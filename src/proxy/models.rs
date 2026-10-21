use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};

use super::access::{combo_allowed, model_allowed};
use super::{AppState, KeyPermissions};

pub async fn list_models(
    State(state): State<Arc<AppState>>,
    key_perm: Option<axum::extract::Extension<KeyPermissions>>,
) -> Response {
    let router = state.router.load();
    let allowed = key_perm.and_then(|p| p.0.allowed_models);

    // Unfiltered requests (the common case) are served from a cached body: the
    // response is identical until the catalogue changes, and rebuilding 124 JSON
    // objects per scrape/request was the dominant cost of this endpoint.
    if allowed.is_none() {
        let epoch = state
            .catalog_epoch
            .load(std::sync::atomic::Ordering::Relaxed);
        {
            let cache = state.models_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((cached_epoch, body)) = cache.as_ref()
                && *cached_epoch == epoch
            {
                return ([("content-type", "application/json")], body.clone()).into_response();
            }
        }
        // Miss: build below, then store. A concurrent builder may win the race —
        // both bodies are identical for the same epoch, so last-writer-wins is fine.
    }

    // Snapshot once: a read-guard cannot be held across .await (not Send).
    let disabled = state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut data = Vec::new();
    for p in &router.providers {
        for m in p.effective_models().await.iter() {
            let id = format!("{}/{}", p.name, m);
            if disabled.contains(&id) || disabled.contains(m.as_str()) {
                continue;
            }
            if let Some(allowed_list) = &allowed
                && !model_allowed(allowed_list, &id, &id, m)
            {
                continue;
            }
            data.push(serde_json::json!({
                "id": id,
                "object": "model",
                "owned_by": p.name,
            }));
        }
    }
    for c in &router.combos {
        // match the request path: both "combo/x" and bare "x" disable a combo
        let bare = c.name.strip_prefix("combo/").unwrap_or(&c.name);
        if disabled.contains(&c.name) || disabled.contains(bare) {
            continue;
        }
        if let Some(allowed_list) = &allowed
            && !combo_allowed(allowed_list, &c.name)
        {
            continue;
        }
        data.push(serde_json::json!({
            "id": c.name,
            "object": "model",
            "owned_by": "combo",
        }));
    }
    let body = serde_json::json!({ "object": "list", "data": data }).to_string();
    if allowed.is_none() {
        let epoch = state
            .catalog_epoch
            .load(std::sync::atomic::Ordering::Relaxed);
        *state.models_cache.lock().unwrap_or_else(|e| e.into_inner()) = Some((epoch, body.clone()));
    }
    ([("content-type", "application/json")], body).into_response()
}

/// GET /v1/models/{id} — the single-model variant of `list_models`.
///
/// Served from the same catalogue (and the same epoch cache), so it cannot drift
/// from the list endpoint; unknown or disabled ids are a 404.
pub async fn get_model(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let router = state.router.load();
    let disabled = state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if disabled.contains(&id) {
        return super::error_response(
            axum::http::StatusCode::NOT_FOUND,
            format!("model '{id}' is disabled"),
            "not_found_error",
        );
    }
    let (bare, explicit_provider) = match id.split_once('/') {
        Some((p, m)) if p != "combo" => (p, Some(m)),
        _ => ("", None),
    };
    for p in &router.providers {
        // Combos are not provider/model pairs and are handled below.
        if let Some(model) = explicit_provider {
            if p.name != bare {
                continue;
            }
            if p.effective_models().await.iter().any(|m| m == model) {
                return Json(serde_json::json!({
                    "id": id,
                    "object": "model",
                    "owned_by": p.name,
                }))
                .into_response();
            }
        }
    }
    for c in &router.combos {
        if c.name == id {
            return Json(serde_json::json!({
                "id": c.name,
                "object": "model",
                "owned_by": "combo",
            }))
            .into_response();
        }
    }
    super::error_response(
        axum::http::StatusCode::NOT_FOUND,
        format!("model '{id}' not found"),
        "not_found_error",
    )
}
