use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use tracing::{info, warn};

use crate::pool::FailKind;
use crate::providers::{Provider, ProviderRouter};

pub struct AppState {
    pub router: ProviderRouter,
    pub http: reqwest::Client,
    pub max_retries: usize,
    pub attempt_timeout: Duration,
}

fn error_response(status: StatusCode, message: impl Into<String>, ty: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": message.into(),
            "type": ty,
            "code": status.as_u16(),
        }
    });
    (status, Json(body)).into_response()
}

pub async fn list_models(State(state): State<Arc<AppState>>) -> Response {
    let mut data = Vec::new();
    for p in &state.router.providers {
        for m in &p.models {
            data.push(serde_json::json!({
                "id": format!("{}/{}", p.name, m),
                "object": "model",
                "owned_by": p.name,
            }));
        }
    }
    Json(serde_json::json!({ "object": "list", "data": data })).into_response()
}

pub async fn chat_completions(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let mut payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON body: {e}"),
                "invalid_request_error",
            );
        }
    };

    let model = payload
        .get("model")
        .and_then(|m| m.as_str())
        .map(str::to_string);
    let Some(model) = model else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing or invalid 'model' field",
            "invalid_request_error",
        );
    };

    let Some((provider, upstream_model)) = state.router.resolve(&model) else {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("no provider serves model '{model}'"),
            "model_not_found",
        );
    };
    payload["model"] = serde_json::Value::String(upstream_model.clone());

    let mut last_err: Option<(StatusCode, String)> = None;

    for _ in 0..state.max_retries.max(1) {
        let Some(key) = provider.pool.pick() else {
            warn!(provider = %provider.name, model = %upstream_model, "no available keys (all cooling down or dead)");
            break;
        };

        let url = format!("{}/chat/completions", provider.base_url);
        let mut req = state
            .http
            .post(&url)
            .bearer_auth(&key.secret)
            .json(&payload);
        for (k, v) in &provider.extra_headers {
            req = req.header(k, v);
        }

        let result = tokio::time::timeout(state.attempt_timeout, req.send()).await;
        let resp = match result {
            Err(_) => {
                provider.pool.report_failure(&key, FailKind::Network);
                warn!(provider = %provider.name, key = %key.masked(), "attempt timed out");
                last_err = Some((StatusCode::GATEWAY_TIMEOUT, "upstream timeout".into()));
                continue;
            }
            Ok(Err(e)) => {
                provider.pool.report_failure(&key, FailKind::Network);
                warn!(provider = %provider.name, key = %key.masked(), error = %e, "network error");
                last_err = Some((StatusCode::BAD_GATEWAY, format!("upstream network error: {e}")));
                continue;
            }
            Ok(Ok(resp)) => resp,
        };

        let status = resp.status();
        if status.is_success() {
            provider.pool.report_success(&key);
            info!(provider = %provider.name, key = %key.masked(), model = %upstream_model, "ok");
            return stream_upstream(resp);
        }

        let status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let retry_after_secs = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let text = resp.text().await.unwrap_or_default();
        let snippet: String = text.chars().take(1000).collect();

        match status.as_u16() {
            429 => {
                provider
                    .pool
                    .report_failure(&key, FailKind::RateLimited { retry_after_secs });
                warn!(provider = %provider.name, key = %key.masked(), retry_after = ?retry_after_secs, "rate limited, key on cooldown");
            }
            401 | 403 => {
                provider.pool.report_failure(&key, FailKind::Auth);
                warn!(provider = %provider.name, key = %key.masked(), "auth failed, key marked dead");
            }
            s if s >= 500 => {
                provider.pool.report_failure(&key, FailKind::Server);
                warn!(provider = %provider.name, key = %key.masked(), status = s, "upstream 5xx, key on cooldown");
            }
            _ => {
                // Client error (400 etc.) — not the key's fault, pass through as-is.
                info!(provider = %provider.name, key = %key.masked(), status = %status.as_u16(), "upstream 4xx, passing through");
                return error_response(status, snippet, "upstream_error");
            }
        }
        last_err = Some((status, snippet));
    }

    let (code, detail) = last_err.unwrap_or((StatusCode::SERVICE_UNAVAILABLE, String::new()));
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!(
            "provider '{}' unavailable after {} attempts (last upstream status {}): {}",
            provider.name,
            state.max_retries,
            code.as_u16(),
            detail
        ),
        "provider_unavailable",
    )
}

/// Pass an upstream 2xx response through to the client with zero buffering.
fn stream_upstream(resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
    let content_type = resp.headers().get(header::CONTENT_TYPE).cloned();
    let stream = resp.bytes_stream().map(|chunk| {
        chunk.map_err(|e| std::io::Error::other(format!("upstream stream error: {e}")))
    });
    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Used by the Gemini adapter in step 2.
#[allow(dead_code)]
pub fn provider_of<'a>(state: &'a AppState, name: &str) -> Option<&'a Provider> {
    state.router.providers.iter().find(|p| p.name == name)
}
