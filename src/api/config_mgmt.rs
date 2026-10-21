use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::proxy::AppState;

use super::{ApiError, ApiResult};

/// GET /api/config — raw TOML.
///
/// The success body is the config file itself (`text/plain`), so this one stays
/// `-> Response`; only the error path uses the typed error.
pub async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    match std::fs::read_to_string(&state.config_path) {
        Ok(toml) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], toml).into_response(),
        Err(e) => ApiError::not_found(format!("cannot read config: {e}")).into_response(),
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
) -> ApiResult {
    // Validate through the SAME rules as startup load — a saved config must
    // never brick the next process start.
    let parsed: crate::config::Config = match toml::from_str(&body.toml) {
        Ok(c) => c,
        Err(e) => return Err(ApiError::bad_request(format!("invalid config: {e}"))),
    };
    if let Err(e) = parsed.validate() {
        return Err(ApiError::bad_request(format!("invalid config: {e}")));
    }
    {
        // Don't interleave with other config writers mid-write.
        let _guard = state.config_lock.lock().await;
        if let Err(e) = crate::config::write_atomic(&state.config_path, &body.toml) {
            return Err(ApiError::internal(format!("cannot write config: {e}")));
        }
    }
    match crate::reload_config(&state) {
        Ok(n) => {
            state.events.emit_simple(
                "config",
                "",
                "backoff",
                format!("config saved, {n} providers reloaded"),
            );
            Ok(StatusCode::OK.into_response())
        }
        Err(e) => Err(ApiError::bad_request(format!(
            "config saved but reload failed: {e}"
        ))),
    }
}

/// POST /api/reload — re-read config from disk.
///
/// The success body is the plain-text `reloaded N providers`, so the signature
/// stays `-> Response`; a failed reload is still an [`ApiError`].
pub async fn reload(State(state): State<Arc<AppState>>) -> Response {
    match crate::reload_config(&state) {
        Ok(n) => (StatusCode::OK, format!("reloaded {n} providers")).into_response(),
        Err(e) => ApiError::bad_request(format!("reload failed: {e}")).into_response(),
    }
}
