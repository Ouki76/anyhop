use std::collections::HashSet;
use std::sync::{Arc, RwLockReadGuard, RwLockWriteGuard};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use super::persist::persist_disabled_models;
use super::{ApiResult, ok_json};
use crate::proxy::AppState;

#[derive(Serialize, Deserialize, Clone)]
pub struct ModelItemDto {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct ModelAction {
    pub model: String,
}

// Poison-recovering guards (same policy as `pool::lock`): the set holds plain
// strings with no invariant a panic could corrupt, so a poisoned lock must not
// make every model toggle fail for the rest of the process.
fn dm_read(state: &AppState) -> RwLockReadGuard<'_, HashSet<String>> {
    state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner())
}

fn dm_write(state: &AppState) -> RwLockWriteGuard<'_, HashSet<String>> {
    state
        .disabled_models
        .write()
        .unwrap_or_else(|e| e.into_inner())
}

/// Persist the disabled set: storage feed first (fast, survives restarts even if
/// the TOML rewrite fails), then the TOML file. Every mutating handler did this.
async fn save_disabled(state: &Arc<AppState>) {
    state.invalidate_catalog();
    let all: Vec<_> = dm_read(state).iter().cloned().collect();
    if let Some(s) = &state.storage {
        s.save_feed("disabled_models", &all);
    }
    persist_disabled_models(state).await;
}

/// `combo/flash` and `flash` name the same model; also drop the bare half of a
/// `provider/model` id so both spellings agree.
fn normalize(a: &ModelAction) -> &str {
    a.model
        .trim()
        .strip_prefix("combo/")
        .unwrap_or(a.model.trim())
}

/// Is `model` disabled under either spelling?
///
/// Matches `proxy::access::model_disabled` exactly: the request path blocks a
/// `provider/model` id when either the qualified id or its bare model name is in
/// the set. The toggle has to use the same predicate — it used to test the
/// qualified id only, so a model disabled by its bare name showed as disabled
/// while the toggle kept inserting the qualified id (still disabled, and one more
/// entry every click).
fn is_disabled(dm: &HashSet<String>, model: &str) -> bool {
    if dm.contains(model) {
        return true;
    }
    match model.split_once('/') {
        // "provider/model": the bare model name disables it everywhere.
        Some((_, rest)) => dm.contains(rest),
        // A bare name may also be stored as "combo/<name>".
        None => dm.contains(&format!("combo/{model}")),
    }
}

/// Clear every spelling `is_disabled` recognises — the exact inverse of it.
fn clear_model(dm: &mut HashSet<String>, model: &str) {
    dm.remove(model);
    match model.split_once('/') {
        Some((_, rest)) => {
            dm.remove(rest);
        }
        None => {
            dm.remove(&format!("combo/{model}"));
        }
    }
}

pub async fn models_list(State(state): State<Arc<AppState>>) -> ApiResult {
    let router = state.router.load();
    let disabled = dm_read(&state).clone();
    let mut list = Vec::new();

    for p in &router.providers {
        for m in p.effective_models().await.iter() {
            let id = format!("{}/{}", p.name, m);
            let enabled = !is_disabled(&disabled, &id);
            list.push(ModelItemDto {
                id,
                name: m.to_string(),
                provider: p.name.clone(),
                enabled,
            });
        }
    }
    for c in &router.combos {
        // Mirrors the request path: "combo/x" and bare "x" both disable a combo.
        let enabled = !is_disabled(&disabled, &c.name);
        list.push(ModelItemDto {
            id: c.name.clone(),
            name: c.name.clone(),
            provider: "combo".into(),
            enabled,
        });
    }

    ok_json(list)
}

pub async fn models_refresh(State(state): State<Arc<AppState>>) -> ApiResult {
    refresh_all_providers(&state).await;
    state.invalidate_catalog();
    state.events.emit_simple(
        "models",
        "",
        "backoff",
        "refreshed models from all providers".into(),
    );
    models_list(State(state)).await
}

/// Fetch model lists from all providers in parallel (10s timeout per provider inside).
pub async fn refresh_all_providers(state: &Arc<AppState>) {
    let router = state.router.load();
    futures::future::join_all(router.providers.iter().map(|p| p.refresh_models())).await;
    // Covers the background refresh task as well as the manual endpoint.
    state.invalidate_catalog();
}

pub async fn model_enable(
    State(state): State<Arc<AppState>>,
    Json(a): Json<ModelAction>,
) -> ApiResult {
    let model = normalize(&a).to_string();
    clear_model(&mut dm_write(&state), &model);
    save_disabled(&state).await;

    state.events.emit_simple(
        "models",
        &model,
        "backoff",
        format!("model '{model}' enabled"),
    );

    ok_json(serde_json::json!({ "model": model, "enabled": true }))
}

pub async fn model_disable(
    State(state): State<Arc<AppState>>,
    Json(a): Json<ModelAction>,
) -> ApiResult {
    let model = normalize(&a).to_string();
    dm_write(&state).insert(model.clone());
    save_disabled(&state).await;

    state.events.emit_simple(
        "models",
        &model,
        "dead",
        format!("model '{model}' disabled"),
    );

    ok_json(serde_json::json!({ "model": model, "enabled": false }))
}

pub async fn model_toggle(
    State(state): State<Arc<AppState>>,
    Json(a): Json<ModelAction>,
) -> ApiResult {
    let model = normalize(&a).to_string();
    let new_enabled = {
        let mut dm = dm_write(&state);
        // Toggle must agree with `models_list`/the request path: an entry in any
        // spelling counts as disabled, and enabling clears all of them.
        if is_disabled(&dm, &model) {
            clear_model(&mut dm, &model);
            true
        } else {
            dm.insert(model.clone());
            false
        }
    };
    save_disabled(&state).await;

    let kind = if new_enabled { "backoff" } else { "dead" };
    state.events.emit_simple(
        "models",
        &model,
        kind,
        format!(
            "model '{model}' {}",
            if new_enabled { "enabled" } else { "disabled" }
        ),
    );

    ok_json(serde_json::json!({ "model": model, "enabled": new_enabled }))
}

pub async fn models_enable_all(State(state): State<Arc<AppState>>) -> ApiResult {
    dm_write(&state).clear();
    save_disabled(&state).await;
    state
        .events
        .emit_simple("models", "", "backoff", "all models enabled".into());
    Ok(StatusCode::OK.into_response())
}

pub async fn models_disable_all(State(state): State<Arc<AppState>>) -> ApiResult {
    let router = state.router.load();
    let mut all_ids = Vec::new();
    for p in &router.providers {
        for m in p.effective_models().await.iter() {
            all_ids.push(format!("{}/{}", p.name, m));
        }
    }
    for c in &router.combos {
        all_ids.push(c.name.clone());
    }

    {
        let mut dm = dm_write(&state);
        for id in all_ids {
            dm.insert(id);
        }
    }
    save_disabled(&state).await;

    state
        .events
        .emit_simple("models", "", "dead", "all models disabled".into());
    Ok(StatusCode::OK.into_response())
}
