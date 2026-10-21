//! Successful-upstream responses: buffering, translation, and zero-copy streaming.

use std::sync::Arc;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde_json::Value;

use crate::anthropic;
use crate::antigravity;
use crate::codex;
use crate::config::ProviderKind;
use crate::gemini;
use crate::pool::{KeyGuard, KeyState};
use crate::providers::Provider;

use super::error_response;

/// Build the client response for a successful upstream call.
pub(super) async fn success_response(
    provider: &Provider,
    model: &str,
    resp: reqwest::Response,
    is_stream: bool,
    key: Arc<KeyState>,
    guard: KeyGuard,
) -> Response {
    match provider.kind {
        ProviderKind::OpenaiCompat => {
            if is_stream {
                stream_upstream(resp, guard)
            } else {
                // Buffer small JSON responses to capture usage stats.
                let status = resp.status();
                let content_type = resp.headers().get(header::CONTENT_TYPE).cloned();
                drop(guard);
                match resp.bytes().await {
                    Ok(bytes) => {
                        if let Ok(v) = serde_json::from_slice::<Value>(&bytes)
                            && let Some(u) = v.get("usage")
                        {
                            add_usage(
                                &key,
                                u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                                u.get("completion_tokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0),
                            );
                        }
                        let mut b = Response::builder().status(
                            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
                        );
                        if let Some(ct) = content_type {
                            b = b.header(header::CONTENT_TYPE, ct);
                        }
                        b.body(Body::from(bytes))
                            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                    Err(_) => StatusCode::BAD_GATEWAY.into_response(),
                }
            }
        }
        ProviderKind::Gemini
        | ProviderKind::Antigravity
        | ProviderKind::Anthropic
        | ProviderKind::Codex => {
            let envelope = matches!(provider.kind, ProviderKind::Antigravity);
            if is_stream {
                let stream: std::pin::Pin<
                    Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send>,
                > = match provider.kind {
                    ProviderKind::Anthropic => {
                        Box::pin(anthropic::translate_sse_stream(resp, model, Some(key)))
                    }
                    ProviderKind::Codex => {
                        Box::pin(codex::translate_sse_stream(resp, model, Some(key)))
                    }
                    _ => Box::pin(gemini::translate_sse_stream(
                        resp,
                        model,
                        envelope,
                        Some(key),
                    )),
                };
                let stream = stream.map(move |item| {
                    let _ = &guard; // keep the in-flight slot until the stream ends
                    item
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from_stream(stream))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            } else {
                drop(guard);
                if matches!(provider.kind, ProviderKind::Codex) {
                    // Codex backend is stream-only; collect the SSE stream.
                    return match codex::collect_non_stream(resp, model).await {
                        Ok(v) => {
                            if let Some(u) = v.get("usage") {
                                add_usage(
                                    &key,
                                    u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                                    u.get("completion_tokens")
                                        .and_then(|x| x.as_u64())
                                        .unwrap_or(0),
                                );
                            }
                            Json(v).into_response()
                        }
                        Err(e) => error_response(
                            StatusCode::BAD_GATEWAY,
                            format!("codex stream collect failed: {e}"),
                            "upstream_error",
                        ),
                    };
                }
                match resp.json::<Value>().await {
                    Ok(v) => {
                        if matches!(provider.kind, ProviderKind::Anthropic) {
                            let u = v.get("usage").cloned().unwrap_or(Value::Null);
                            add_usage(
                                &key,
                                u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                                u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                            );
                            Json(anthropic::translate_response(model, &v)).into_response()
                        } else {
                            let v = if envelope {
                                antigravity::unwrap_response(v)
                            } else {
                                v
                            };
                            let (p, c) = gemini::usage_pair(&v);
                            add_usage(&key, p, c);
                            Json(gemini::translate_response(model, &v)).into_response()
                        }
                    }
                    Err(e) => error_response(
                        StatusCode::BAD_GATEWAY,
                        format!("invalid upstream JSON: {e}"),
                        "upstream_error",
                    ),
                }
            }
        }
    }
}

fn add_usage(key: &KeyState, prompt: u64, completion: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    key.prompt_tokens.fetch_add(prompt, Relaxed);
    key.completion_tokens.fetch_add(completion, Relaxed);
}

/// Upstream response headers worth relaying on a pass-through. Deliberately an
/// allowlist: hop-by-hop headers (content-length, transfer-encoding, connection)
/// describe the upstream framing, not ours, and must never be copied.
fn forward_header(name: &reqwest::header::HeaderName) -> bool {
    use reqwest::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, RETRY_AFTER};
    matches!(*name, CONTENT_TYPE | CACHE_CONTROL | ETAG | RETRY_AFTER)
        || name.as_str().starts_with("x-ratelimit-")
        || name.as_str() == "x-request-id"
        || name.as_str() == "openai-processing-ms"
        || name.as_str() == "openai-version"
}

/// Pass an upstream 2xx response through to the client with zero buffering.
/// The guard keeps the key's in-flight slot until the stream ends.
fn stream_upstream(resp: reqwest::Response, guard: KeyGuard) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
    let headers: Vec<_> = resp
        .headers()
        .iter()
        .filter(|(n, _)| forward_header(n))
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    let stream = resp.bytes_stream().map(move |chunk| {
        let _ = &guard;
        chunk.map_err(|e| std::io::Error::other(format!("upstream stream error: {e}")))
    });
    let mut builder = Response::builder().status(status);
    for (n, v) in headers {
        builder = builder.header(n, v);
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- response header allowlist -----

    #[test]
    fn only_safe_upstream_headers_are_relayed() {
        use reqwest::header::{CONNECTION, CONTENT_LENGTH, HeaderName, TRANSFER_ENCODING};
        for ok in [
            "content-type",
            "cache-control",
            "etag",
            "retry-after",
            "x-request-id",
        ] {
            assert!(
                forward_header(&HeaderName::from_static(ok)),
                "{ok} should be relayed"
            );
        }
        assert!(forward_header(
            &HeaderName::from_bytes(b"x-ratelimit-remaining-requests").unwrap()
        ));
        // Hop-by-hop / framing headers describe the upstream connection, not ours.
        for bad in [CONTENT_LENGTH, TRANSFER_ENCODING, CONNECTION] {
            assert!(!forward_header(&bad), "{bad} must never be copied");
        }
        assert!(!forward_header(&HeaderName::from_static("set-cookie")));
        assert!(!forward_header(&HeaderName::from_static("authorization")));
    }
}
