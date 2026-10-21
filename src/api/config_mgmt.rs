use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::proxy::AppState;

/// GET /api/config — raw TOML.
pub async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    match std::fs::read_to_string(&state.config_path) {
        Ok(toml) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], toml).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, format!("cannot read config: {e}")).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ConfigUpdate {
    toml: String,
}

/// PUT /api/config — validate, write, hot-reload.
pub async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ConfigUpdate>,
) -> Response {
    // Validate through the SAME rules as startup load — a saved config must
    // never brick the next process start.
    let parsed: crate::config::Config = match toml::from_str(&body.toml) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response(),
    };
    if let Err(e) = parsed.validate() {
        return (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response();
    }
    {
        // Don't interleave with other config writers mid-write.
        let _guard = state.config_lock.lock().await;
        if let Err(e) = crate::config::write_atomic(&state.config_path, &body.toml) {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("cannot write config: {e}"))
                .into_response();
        }
    }
    match crate::reload_config(&state) {
        Ok(n) => {
            state
                .events
                .emit_simple("config", "", "backoff", format!("config saved, {n} providers reloaded"));
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("config saved but reload failed: {e}"))
            .into_response(),
    }
}

/// POST /api/reload — re-read config from disk.
pub async fn reload(State(state): State<Arc<AppState>>) -> Response {
    match crate::reload_config(&state) {
        Ok(n) => (StatusCode::OK, format!("reloaded {n} providers")).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("reload failed: {e}")).into_response(),
    }
}
