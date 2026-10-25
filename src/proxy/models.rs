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
    let limits = state
        .model_limits
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
            data.push(model_json(&limits, &id, &p.name));
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
        data.push(model_json(&limits, &c.name, "combo"));
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
/// from the list endpoint; unknown or disabled ids are a 404. It applies the same
/// two filters as the list — the client-key allowlist and both spellings of a
/// disabled entry — otherwise a restricted key could probe the catalogue one id at
/// a time (200 vs 404) and `disabled_models = ["beta"]` would still resolve
/// `/v1/models/provider/beta`.
pub async fn get_model(
    State(state): State<Arc<AppState>>,
    key_perm: Option<axum::extract::Extension<KeyPermissions>>,
    Path(id): Path<String>,
) -> Response {
    let router = state.router.load();
    let allowed = key_perm.and_then(|p| p.0.allowed_models);
    let disabled = state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let limits = state
        .model_limits
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (bare_kind, explicit_provider) = match id.split_once('/') {
        Some((p, m)) if p != "combo" => (p, Some(m)),
        _ => ("", None),
    };
    // Both spellings, exactly like `list_models` and the request path.
    let model_part = explicit_provider.unwrap_or(id.as_str());
    if disabled.contains(&id) || disabled.contains(model_part) {
        return super::error_response(
            axum::http::StatusCode::NOT_FOUND,
            format!("model '{id}' is disabled"),
            "not_found_error",
        );
    }
    for p in &router.providers {
        // Combos are not provider/model pairs and are handled below.
        if let Some(model) = explicit_provider {
            if p.name != bare_kind {
                continue;
            }
            if p.effective_models().await.iter().any(|m| m == model) {
                if let Some(allowed_list) = &allowed
                    && !model_allowed(allowed_list, &id, &id, model)
                {
                    break;
                }
                return Json(model_json(&limits, &id, &p.name)).into_response();
            }
        }
    }
    for c in &router.combos {
        let bare = c.name.strip_prefix("combo/").unwrap_or(&c.name);
        if c.name == id || bare == model_part {
            if let Some(allowed_list) = &allowed
                && !combo_allowed(allowed_list, &c.name)
            {
                break;
            }
            return Json(model_json(&limits, &c.name, "combo")).into_response();
        }
    }
    super::error_response(
        axum::http::StatusCode::NOT_FOUND,
        format!("model '{id}' not found"),
        "not_found_error",
    )
}

/// The wire object for one model.
///
/// OpenAI's shape is `id`/`object`/`created`/`owned_by`; the token limits are extra
/// fields in the spelling the wider ecosystem already uses (OpenRouter's
/// `context_length`, OpenAI's `max_completion_tokens`). They are only emitted when
/// the operator set them — inventing a number for an unknown model would be worse
/// than saying nothing.
fn model_json(limits: &crate::config::ModelLimits, id: &str, owner: &str) -> serde_json::Value {
    let mut v = serde_json::json!({
        "id": id,
        "object": "model",
        "owned_by": owner,
    });
    if let Some(l) = limits.get(id) {
        if l.context_window > 0 {
            v["context_length"] = serde_json::json!(l.context_window);
        }
        if l.max_output_tokens > 0 {
            v["max_completion_tokens"] = serde_json::json!(l.max_output_tokens);
        }
        if l.max_input_tokens > 0 {
            v["max_input_tokens"] = serde_json::json!(l.max_input_tokens);
        }
    }
    v
}

/// `GET /v1/models` is cached per catalogue epoch and filtered twice (disabled
/// set, client-key allowlist). Both behaviours are invisible until they are
/// wrong: a stale cache keeps serving a model the admin just disabled, and a
/// missing filter hands a restricted key a catalogue it may not use.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::test_support::{MINIMAL, state, temp_config};
    use crate::config::{ComboConfig, ProviderConfig};

    fn state_with_catalogue() -> (Arc<AppState>, std::path::PathBuf) {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let pcfg: ProviderConfig = toml::from_str(
            r#"
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:1/v1"
            keys = ["sk-test"]
            models = ["alpha", "beta"]
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
                    name: "fast".to_string(),
                    chain: vec!["mock/alpha".to_string()],
                }],
            }));
        (st, path)
    }

    async fn ids(resp: Response) -> Vec<String> {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        v["data"]
            .as_array()
            .expect("data array")
            .iter()
            .map(|m| m["id"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[tokio::test]
    async fn the_catalogue_lists_provider_models_and_combos() {
        let (st, path) = state_with_catalogue();
        let list = ids(list_models(State(st.clone()), None).await).await;
        assert_eq!(list, vec!["mock/alpha", "mock/beta", "fast"], "{list:?}");

        // A single model resolves, with the provider that owns it.
        let one = get_model(State(st.clone()), None, Path("mock/alpha".to_string())).await;
        assert_eq!(one.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(one.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["id"], "mock/alpha");
        assert_eq!(v["owned_by"], "mock");

        // A combo resolves too, under its bare name.
        assert_eq!(
            get_model(State(st.clone()), None, Path("fast".to_string()))
                .await
                .status(),
            axum::http::StatusCode::OK
        );

        // Unknown models and unknown providers are a 404, not an empty 200.
        for bad in ["mock/nope", "other/alpha", "nope"] {
            assert_eq!(
                get_model(State(st.clone()), None, Path(bad.to_string()))
                    .await
                    .status(),
                axum::http::StatusCode::NOT_FOUND,
                "{bad}"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A disabled model must disappear from the list *and* from the single-model
    /// endpoint — even though the cached body already exists. The catalogue
    /// epoch is what makes the cache safe to keep.
    #[tokio::test]
    async fn disabling_a_model_invalidates_the_cached_catalogue() {
        let (st, path) = state_with_catalogue();

        let before = ids(list_models(State(st.clone()), None).await).await;
        assert!(before.contains(&"mock/beta".to_string()));
        assert!(
            st.models_cache.lock().unwrap().is_some(),
            "the unfiltered catalogue is cached"
        );

        // What the admin handler does: mutate the set, then bump the epoch.
        st.disabled_models
            .write()
            .unwrap()
            .insert("mock/beta".to_string());
        st.invalidate_catalog();

        let after = ids(list_models(State(st.clone()), None).await).await;
        assert_eq!(after, vec!["mock/alpha", "fast"], "{after:?}");
        assert_eq!(
            get_model(State(st.clone()), None, Path("mock/beta".to_string()))
                .await
                .status(),
            axum::http::StatusCode::NOT_FOUND,
            "a disabled model must not be resolvable by id"
        );

        // Disabling the combo removes it from the listing as well. The admin API
        // stores combo names bare (it strips the `combo/` prefix), so that is the
        // spelling the catalogue has to match.
        st.disabled_models
            .write()
            .unwrap()
            .insert("fast".to_string());
        st.invalidate_catalog();
        assert_eq!(
            ids(list_models(State(st.clone()), None).await).await,
            vec!["mock/alpha"]
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A client key's allowlist filters the catalogue, and that path must bypass
    /// the cache (the same epoch serves different bodies per key).
    #[tokio::test]
    async fn a_client_key_only_sees_its_allowlist() {
        let (st, path) = state_with_catalogue();
        let perm = KeyPermissions {
            allowed_models: Some(vec!["alpha".to_string()]),
            key_name: Some("tenant".to_string()),
        };
        let list =
            ids(list_models(State(st.clone()), Some(axum::extract::Extension(perm))).await).await;
        assert_eq!(list, vec!["mock/alpha"], "{list:?}");
        assert!(
            st.models_cache.lock().unwrap().is_none(),
            "a filtered catalogue must never be cached for everyone else"
        );

        // Only the combo is allowed: the provider models disappear.
        let perm = KeyPermissions {
            allowed_models: Some(vec!["combo/fast".to_string()]),
            key_name: Some("tenant".to_string()),
        };
        assert_eq!(
            ids(list_models(State(st.clone()), Some(axum::extract::Extension(perm))).await).await,
            vec!["fast"]
        );
        let _ = std::fs::remove_file(&path);
    }
}
