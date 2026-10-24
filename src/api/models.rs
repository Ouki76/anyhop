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

/// Longest accepted model id.
///
/// Every `disabled_models` entry ends up in the TOML file, which is rewritten in
/// full on every toggle, and in the event feed. An unbounded id (the field is a
/// bare `String`) meant one request could add a multi-megabyte entry that every
/// later config write had to fsync.
const MAX_MODEL_ID_LEN: usize = 256;

/// Reject model ids that cannot be real catalogue entries.
fn validate_model_action(a: &ModelAction) -> Result<(), super::ApiError> {
    let m = a.model.trim();
    if m.is_empty() {
        return Err(super::ApiError::BadRequest("model is required".into()));
    }
    if m.chars().count() > MAX_MODEL_ID_LEN {
        return Err(super::ApiError::BadRequest(format!(
            "model id is too long (max {MAX_MODEL_ID_LEN} characters)"
        )));
    }
    // Reject control characters: they corrupt the log line, the event payload and
    // (via the TOML writer) make the config file unreadable.
    if m.chars().any(|c| c.is_control()) {
        return Err(super::ApiError::BadRequest(
            "model id must not contain control characters".into(),
        ));
    }
    Ok(())
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
    validate_model_action(&a)?;
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
    validate_model_action(&a)?;
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
    validate_model_action(&a)?;
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

/// The `disabled_models` set has three spellings in play (`m`, `provider/m`,
/// `combo/m`). Listing, toggling and the request path must agree, or a toggle
/// inserts a second entry that is already disabled and never undoes the first.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::test_support::{MINIMAL, json, state, temp_config};
    use crate::config::{ComboConfig, ProviderConfig};

    fn action(model: &str) -> Json<ModelAction> {
        json(&serde_json::json!({ "model": model }).to_string())
    }

    /// A state with one provider serving `mock/m` and one combo `combo/x`.
    fn state_with_catalogue() -> (std::sync::Arc<AppState>, std::path::PathBuf) {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let pcfg: ProviderConfig = toml::from_str(
            r#"
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:1/v1"
            keys = ["sk-test"]
            models = ["m", "m2"]
            "#,
        )
        .expect("provider config");
        let provider = crate::providers::Provider::from_config(
            &pcfg,
            None,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
            std::time::Duration::from_secs(5),
            1,
        )
        .expect("builds offline");
        st.router
            .store(std::sync::Arc::new(crate::providers::ProviderRouter {
                providers: vec![provider],
                combos: vec![ComboConfig {
                    name: "x".to_string(),
                    chain: vec!["mock/m".to_string()],
                }],
            }));
        (st, path)
    }

    // ----- the predicates -----

    #[test]
    fn a_disabled_spelling_matches_every_other_spelling_of_the_same_model() {
        let mut dm = HashSet::new();
        // A bare model name disables it under every provider and as a combo.
        dm.insert("flash".to_string());
        assert!(is_disabled(&dm, "flash"));
        assert!(is_disabled(&dm, "combo/flash"));
        assert!(is_disabled(&dm, "openrouter/flash"));
        assert!(!is_disabled(&dm, "flash-lite"));

        // A combo name stored with the prefix is the same model as the bare one.
        let mut dm = HashSet::new();
        dm.insert("combo/flash".to_string());
        assert!(is_disabled(&dm, "flash"));
        assert!(is_disabled(&dm, "combo/flash"));
        assert!(!is_disabled(&dm, "other"));

        // A qualified id disables exactly the id the listing passes around
        // (`provider/model`); another provider's identically named model is a
        // different entry. (The request path additionally consults the canonical
        // and upstream ids — see the `proxy::access` tests.)
        let mut dm = HashSet::new();
        dm.insert("mock/m".to_string());
        assert!(is_disabled(&dm, "mock/m"));
        assert!(!is_disabled(&dm, "other/m"));
    }

    /// `clear_model` has to be the exact inverse of `is_disabled`: an enable that
    /// leaves one spelling behind leaves the model disabled.
    #[test]
    fn enabling_clears_every_spelling_the_predicate_recognises() {
        for (model, seeded) in [
            ("mock/m", vec!["mock/m", "m"]),
            ("flash", vec!["flash", "combo/flash"]),
            ("combo/flash", vec!["flash", "combo/flash"]),
        ] {
            let mut dm: HashSet<String> = seeded.iter().map(|s| s.to_string()).collect();
            assert!(is_disabled(&dm, model), "{model} must start disabled");
            clear_model(&mut dm, model);
            assert!(
                !is_disabled(&dm, model),
                "enabling {model} left {dm:?} behind"
            );
        }
    }

    #[test]
    fn the_combo_prefix_is_normalised_away() {
        assert_eq!(
            normalize(&ModelAction {
                model: "  combo/x  ".into()
            }),
            "x"
        );
        assert_eq!(
            normalize(&ModelAction {
                model: "mock/m".into()
            }),
            "mock/m"
        );
        assert_eq!(
            normalize(&ModelAction {
                model: " x ".into()
            }),
            "x"
        );
    }

    // ----- the handlers: state, file and idempotence -----

    /// Every toggle rewrites the config. Two toggles must return to the starting
    /// point — the old code inserted a second spelling instead, so the model
    /// stayed disabled and the file grew on every click.
    #[tokio::test]
    async fn toggling_twice_restores_the_model_and_leaves_no_stale_entry() {
        let (st, path) = state_with_catalogue();

        model_toggle(State(st.clone()), action("mock/m"))
            .await
            .expect("disable");
        assert!(is_disabled(&dm_read(&st), "mock/m"));
        model_toggle(State(st.clone()), action("mock/m"))
            .await
            .expect("enable");
        assert!(
            !is_disabled(&dm_read(&st), "mock/m"),
            "the second toggle must re-enable the model"
        );
        assert!(
            dm_read(&st).is_empty(),
            "a stale spelling survived: {:?}",
            dm_read(&st)
        );

        // Disabling by the bare name and toggling by the qualified id must still
        // reach the enabled state (they are the same model).
        model_disable(State(st.clone()), action("m"))
            .await
            .expect("disable by bare name");
        assert!(is_disabled(&dm_read(&st), "mock/m"));
        let resp = model_toggle(State(st.clone()), action("mock/m"))
            .await
            .expect("toggle the qualified id");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["enabled"], true, "{body}");

        // The file agrees with the live set: empty, and still a valid config.
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("valid config");
        assert!(parsed.disabled_models.is_empty(), "{raw}");
        let _ = std::fs::remove_file(&path);
    }

    /// `disable-all` must cover provider models *and* combos; `enable-all` must
    /// clear everything again.
    #[tokio::test]
    async fn disable_all_covers_models_and_combos_and_enable_all_clears_them() {
        let (st, path) = state_with_catalogue();

        models_disable_all(State(st.clone()))
            .await
            .expect("disable all");
        let dm = dm_read(&st).clone();
        assert!(dm.contains("mock/m"), "{dm:?}");
        assert!(dm.contains("mock/m2"), "{dm:?}");
        assert!(dm.contains("x"), "{dm:?}");
        assert!(is_disabled(&dm, "combo/x"));

        // The listing reflects it.
        let listed = models_list(State(st.clone())).await.expect("list");
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(listed.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .all(|m| m["enabled"] == false),
            "{listed}"
        );

        models_enable_all(State(st.clone()))
            .await
            .expect("enable all");
        assert!(dm_read(&st).is_empty());
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("valid config");
        assert!(parsed.disabled_models.is_empty(), "{raw}");
        let _ = std::fs::remove_file(&path);
    }
}
