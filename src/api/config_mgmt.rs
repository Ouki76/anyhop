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
    // Don't interleave with other config writers mid-write. Validate, build the
    // router, write and swap all happen inside `commit_config_text` (in that
    // order): a config that validates but cannot be built is refused while the
    // previous file is still the one on disk.
    let result = {
        let _guard = state.config_lock.lock().await;
        super::persist::commit_config_text(&state, &body.toml).await
    };
    match result {
        Ok(n) => {
            state.events.emit_simple(
                "config",
                "",
                "backoff",
                format!("config saved, {n} providers reloaded"),
            );
            Ok(StatusCode::OK.into_response())
        }
        // The response already carries the right status (400 / 500) and message.
        Err(resp) => Ok(*resp),
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
