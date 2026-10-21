use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

use super::access::{combo_allowed, model_allowed};
use super::{AppState, KeyPermissions};

pub async fn list_models(
    State(state): State<Arc<AppState>>,
    key_perm: Option<axum::extract::Extension<KeyPermissions>>,
) -> Response {
    let router = state.router.load();
    let allowed = key_perm.and_then(|p| p.0.allowed_models);
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
                && !model_allowed(allowed_list, &id, &id, &m)
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
    Json(serde_json::json!({ "object": "list", "data": data })).into_response()
}
