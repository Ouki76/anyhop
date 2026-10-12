//! Fill-in-the-middle endpoint: wraps chat models (e.g. antigravity tab_*)
//! into an IDE-friendly autocomplete API.
//!
//! POST /v1/fim/completions {model, prompt, suffix?, max_tokens?}
//! → legacy-completions-style {"choices": [{"text": ...}]}

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::proxy::AppState;
use crate::providers::Resolved;

const FIM_SYSTEM: &str = "You are a code completion engine. \
The user gives you a code file with a <FILL_HERE> marker. \
Output ONLY the code that belongs at the marker position. \
Never repeat surrounding code. No explanations. No markdown fences.";

pub async fn fim_completions(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return crate::proxy::error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON body: {e}"),
                "invalid_request_error",
            );
        }
    };

    let model = req.get("model").and_then(|m| m.as_str()).unwrap_or("");
    let prompt = req.get("prompt").and_then(|p| p.as_str()).unwrap_or("");
    let suffix = req.get("suffix").and_then(|s| s.as_str()).unwrap_or("");
    if model.is_empty() || prompt.is_empty() {
        return crate::proxy::error_response(
            StatusCode::BAD_REQUEST,
            "missing 'model' or 'prompt'",
            "invalid_request_error",
        );
    }

    let max_tokens = req
        .get("max_tokens")
        .and_then(|t| t.as_u64())
        .unwrap_or(256);

    let synthetic = json!({
        "model": model,
        "stream": false,
        "temperature": req.get("temperature").cloned().unwrap_or(json!(0.0)),
        "max_tokens": max_tokens,
        // NB: "```" must NOT be a stop sequence — models love to open with a fence,
        // which would yield an empty completion. Fences are stripped post-hoc.
        "stop": ["\n\n\n"],
        "messages": [
            {"role": "system", "content": FIM_SYSTEM},
            {"role": "user", "content": format!("```{}\n{}<FILL_HERE>\n{}\n```",
                req.get("language").and_then(|l| l.as_str()).unwrap_or(""),
                prompt, suffix)},
        ],
    });

    let router = state.router.load();
    let Some(resolved) = router.resolve(model) else {
        return crate::proxy::error_response(
            StatusCode::NOT_FOUND,
            format!("no provider serves model '{model}'"),
            "model_not_found",
        );
    };

    // FIM is single-shot: one provider target, full key retry loop.
    let (provider, upstream_model) = match &resolved {
        Resolved::One(p, m) => (*p, m.clone()),
        Resolved::Chain(chain) => match chain.first() {
            Some((p, m)) => (*p, m.clone()),
            None => {
                return crate::proxy::error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "empty combo chain",
                    "provider_unavailable",
                );
            }
        },
    };

    let resp = crate::proxy::run_target_pub(&state, provider, &upstream_model, &synthetic, false).await;
    let Some(resp) = resp else {
        return crate::proxy::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("provider '{}' unavailable", provider.name),
            "provider_unavailable",
        );
    };

    let status = resp.status();
    let bytes = match axum::body::to_bytes(resp.into_body(), 1 << 20).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if !status.is_success() {
        return Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let Ok(chat) = serde_json::from_slice::<Value>(&bytes) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let raw = chat
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("");
    let text = trim_prefix_overlap(&trim_suffix_overlap(&strip_fences(raw), suffix), prompt);
    let finish = chat
        .pointer("/choices/0/finish_reason")
        .and_then(|f| f.as_str())
        .unwrap_or("stop");

    Json(json!({
        "id": chat.get("id").cloned().unwrap_or(json!("fcmpl-anyhop")),
        "object": "text_completion",
        "created": chat.get("created").cloned().unwrap_or(json!(0)),
        "model": model,
        "choices": [{"index": 0, "text": text, "finish_reason": finish}],
        "usage": chat.get("usage").cloned().unwrap_or(json!({})),
    }))
    .into_response()
}

/// Cut the head where the completion repeats the end of the prefix.
/// Only overlaps >= 12 chars are trimmed — shorter matches are too ambiguous
/// (indentation, brackets) to safely treat as an echo.
fn trim_prefix_overlap(text: &str, prefix: &str) -> String {
    let pre = prefix.trim_end_matches('\n');
    if pre.is_empty() {
        return text.to_string();
    }
    let max = pre.len().min(text.len());
    for k in (12..=max).rev() {
        if text.starts_with(&pre[pre.len() - k..]) {
            return text[k..].trim_start_matches('\n').to_string();
        }
    }
    text.to_string()
}

/// Cut the tail where the completion starts echoing the suffix.
fn trim_suffix_overlap(text: &str, suffix: &str) -> String {
    let suf = suffix.trim_start_matches('\n');
    if suf.is_empty() {
        return text.to_string();
    }
    let max = suf.len().min(text.len());
    for k in (1..=max).rev() {
        if text.ends_with(&suf[..k]) {
            return text[..text.len() - k].trim_end_matches('\n').to_string();
        }
    }
    text.to_string()
}

/// Remove a markdown fence wrapper if the model added one despite instructions.
fn strip_fences(s: &str) -> String {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        // drop the language tag line
        let rest = match rest.find('\n') {
            Some(i) => &rest[i + 1..],
            None => rest,
        };
        let rest = rest.strip_suffix("```").unwrap_or(rest);
        return rest.trim_end_matches('\n').to_string();
    }
    s.to_string()
}
