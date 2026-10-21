//! `POST /v1/embeddings` — OpenAI-compatible embeddings across providers.
//!
//! Two kinds are supported today:
//! - `openai_compat` — passed through byte-for-byte (only the model name is
//!   spliced), so provider-specific fields like `dimensions` keep working;
//! - `gemini` — translated to `:batchEmbedContents` and back.
//!
//! OAuth kinds (Antigravity/Codex) and Anthropic have no embeddings endpoint, so
//! a combo chain skips them instead of failing the whole request.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::config::ProviderKind;
use crate::pool::FailKind;
use crate::providers::{Provider, Resolved};

use super::access::{combo_allowed, model_allowed, model_disabled};
use super::{AppState, KeyPermissions, error_response};

pub async fn embeddings(
    State(state): State<Arc<AppState>>,
    key_perm: Option<axum::extract::Extension<KeyPermissions>>,
    body: Bytes,
) -> Response {
    let key_models = key_perm.as_ref().and_then(|e| e.0.allowed_models.as_ref());
    let client_key_owned = key_perm.as_ref().and_then(|e| e.0.key_name.clone());
    let client_key = client_key_owned.as_deref();

    // Only `model` is needed to route; the body is forwarded (or translated) as is.
    let Some(span) = crate::scan::string_field_span(&body, b"model") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing or invalid 'model' field",
            "invalid_request_error",
        );
    };
    let model = String::from_utf8_lossy(&body[span.clone()]).into_owned();

    let router = state.router.load();
    let Some(resolved) = router.resolve(&model) else {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("no provider serves model '{model}'"),
            "model_not_found",
        );
    };

    // Same policy checks as chat: disabled models and the client-key allowlist.
    let targets: Vec<(&Provider, String)> = {
        let disabled = state
            .disabled_models
            .read()
            .unwrap_or_else(|e| e.into_inner());
        match &resolved {
            Resolved::One(p, m) => {
                let canonical = format!("{}/{}", p.name, m);
                if model_disabled(&disabled, &model, &canonical, m) {
                    return error_response(
                        StatusCode::NOT_FOUND,
                        format!("model '{model}' is disabled"),
                        "model_not_found",
                    );
                }
                if let Some(allowed) = key_models
                    && !model_allowed(allowed, &model, &canonical, m)
                {
                    return error_response(
                        StatusCode::FORBIDDEN,
                        format!("model '{model}' is not allowed for this API key"),
                        "model_not_allowed",
                    );
                }
                vec![(*p, m.clone())]
            }
            Resolved::Chain(c) => {
                if let Some(allowed) = key_models
                    && !combo_allowed(allowed, &model)
                {
                    return error_response(
                        StatusCode::FORBIDDEN,
                        format!("model '{model}' is not allowed for this API key"),
                        "model_not_allowed",
                    );
                }
                c.iter()
                    .filter(|(p, m)| {
                        !disabled.contains(&format!("{}/{}", p.name, m))
                            && !disabled.contains(m.as_str())
                    })
                    .cloned()
                    .collect()
            }
        }
    };

    if targets.is_empty() {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("all targets in combo '{model}' are disabled"),
            "model_not_found",
        );
    }

    let max_retries = state.rt().max_retries;
    let mut unsupported: Vec<String> = Vec::new();
    let mut attempts = 0usize;

    for (provider, upstream_model) in &targets {
        if !supports_embeddings(provider.kind) {
            unsupported.push(provider.name.clone());
            continue;
        }
        for _ in 0..max_retries {
            attempts += 1;
            let Some(key) = provider.pool.pick(upstream_model, None) else {
                break; // pool exhausted for this model — try the next target
            };
            let Some(guard) = key.try_acquire() else {
                continue; // saturated: try another key without penalising it
            };

            let req = match provider.kind {
                ProviderKind::OpenaiCompat => {
                    let out = rewrite_model(&body, &span, upstream_model);
                    provider
                        .client
                        .post(format!("{}/embeddings", provider.base_url))
                        .bearer_auth(&key.secret)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(out)
                }
                ProviderKind::Gemini => {
                    let Some(payload) = gemini_request(&body, upstream_model) else {
                        drop(guard);
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid embeddings request body",
                            "invalid_request_error",
                        );
                    };
                    provider
                        .client
                        .post(format!(
                            "{}/models/{}:batchEmbedContents",
                            provider.base_url, upstream_model
                        ))
                        .header("x-goog-api-key", &key.secret)
                        .json(&payload)
                }
                // Guarded by `supports_embeddings` above.
                _ => unreachable!("provider kind filtered by supports_embeddings"),
            };
            let mut req = req;
            for (k, v) in &provider.extra_headers {
                req = req.header(k, v);
            }

            let started = std::time::Instant::now();
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    drop(guard);
                    provider
                        .pool
                        .report_failure(&key, FailKind::Network, upstream_model);
                    tracing::warn!(provider = %provider.name, error = %e, "embeddings: request failed");
                    log_attempt(
                        &state,
                        provider,
                        upstream_model,
                        &key,
                        started,
                        AttemptLog {
                            status: "network",
                            stream: false,
                            client_key,
                        },
                    );
                    continue;
                }
            };
            drop(guard);

            let status = resp.status();
            if status.is_success() {
                provider.pool.report_success(&key);
                log_attempt(
                    &state,
                    provider,
                    upstream_model,
                    &key,
                    started,
                    AttemptLog {
                        status: status.as_str(),
                        stream: false,
                        client_key,
                    },
                );
                return match provider.kind {
                    ProviderKind::Gemini => match resp.json::<Value>().await {
                        Ok(v) => match gemini_response(&v, &model) {
                            Some(out) => Json(out).into_response(),
                            None => error_response(
                                StatusCode::BAD_GATEWAY,
                                "upstream returned an unexpected embeddings payload",
                                "upstream_error",
                            ),
                        },
                        Err(e) => error_response(
                            StatusCode::BAD_GATEWAY,
                            format!("cannot decode upstream response: {e}"),
                            "upstream_error",
                        ),
                    },
                    // Pass-through keeps the provider's exact JSON (usage included).
                    _ => {
                        let bytes = resp.bytes().await.unwrap_or_default();
                        ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
                    }
                };
            }

            // Failure: classify exactly like chat so key health stays consistent.
            let retry_after_secs = resp
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let text = resp.text().await.unwrap_or_default();
            let snippet: String = text.chars().take(500).collect();
            log_attempt(
                &state,
                provider,
                upstream_model,
                &key,
                started,
                AttemptLog {
                    status: status.as_str(),
                    stream: false,
                    client_key,
                },
            );

            match status.as_u16() {
                429 => {
                    provider.pool.report_failure(
                        &key,
                        FailKind::RateLimited { retry_after_secs },
                        upstream_model,
                    );
                }
                401 | 403 => {
                    provider
                        .pool
                        .report_failure(&key, FailKind::Auth, upstream_model);
                }
                s if s >= 500 => {
                    provider
                        .pool
                        .report_failure(&key, FailKind::Server, upstream_model);
                }
                _ => {
                    // A client-side error is the caller's problem: pass it through
                    // instead of burning keys on retries.
                    return error_response(
                        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_REQUEST),
                        snippet,
                        "upstream_error",
                    );
                }
            }
        }
    }

    if targets.iter().all(|(p, _)| !supports_embeddings(p.kind)) {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "model '{model}' is served by {} which does not support embeddings",
                unsupported.join(", ")
            ),
            "invalid_request_error",
        );
    }
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!(
            "no available key could serve embeddings for '{model}' after {attempts} attempt(s)"
        ),
        "provider_unavailable",
    )
}

/// Which providers have an embeddings API at all.
fn supports_embeddings(kind: ProviderKind) -> bool {
    matches!(kind, ProviderKind::OpenaiCompat | ProviderKind::Gemini)
}

/// Replace the model name in the raw body (one allocation, no JSON round-trip).
fn rewrite_model(body: &Bytes, span: &std::ops::Range<usize>, model: &str) -> Bytes {
    if body.get(span.clone()) == Some(model.as_bytes()) {
        return body.clone();
    }
    let mut out = Vec::with_capacity(body.len() - span.len() + model.len());
    out.extend_from_slice(&body[..span.start]);
    out.extend_from_slice(model.as_bytes());
    out.extend_from_slice(&body[span.end..]);
    Bytes::from(out)
}

/// Collect `input` (string or array of strings) from an embeddings request.
fn gemini_inputs(body: &[u8]) -> Option<Vec<String>> {
    let v: Value = serde_json::from_slice(body).ok()?;
    match v.get("input")? {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                // Token-id arrays are not representable in Gemini's API.
                out.push(it.as_str()?.to_string());
            }
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    }
}

/// OpenAI embeddings request → Gemini `batchEmbedContents`.
fn gemini_request(body: &[u8], model: &str) -> Option<Value> {
    let inputs = gemini_inputs(body)?;
    let requests: Vec<Value> = inputs
        .iter()
        .map(|text| {
            json!({
                "model": format!("models/{model}"),
                "content": {"parts": [{"text": text}]}
            })
        })
        .collect();
    Some(json!({ "requests": requests }))
}

/// Gemini `batchEmbedContents` response → OpenAI embeddings response.
fn gemini_response(v: &Value, model: &str) -> Option<Value> {
    let arr = v.get("embeddings")?.as_array()?;
    let mut data = Vec::with_capacity(arr.len());
    for (i, e) in arr.iter().enumerate() {
        let values = e.get("values")?.as_array()?;
        data.push(json!({
            "object": "embedding",
            "index": i,
            "embedding": values,
        }));
    }
    Some(json!({
        "object": "list",
        "data": data,
        "model": model,
        // Gemini does not report token usage for embeddings; zeros are honest
        // ("unknown") whereas an estimate would silently corrupt billing stats.
        "usage": {"prompt_tokens": 0, "total_tokens": 0},
    }))
}

/// One attempted upstream call, as recorded in the Requests tab.
struct AttemptLog<'a> {
    status: &'a str,
    stream: bool,
    client_key: Option<&'a str>,
}

fn log_attempt(
    state: &Arc<AppState>,
    provider: &Provider,
    model: &str,
    key: &crate::pool::KeyState,
    started: std::time::Instant,
    attempt: AttemptLog<'_>,
) {
    let AttemptLog {
        status,
        stream,
        client_key,
    } = attempt;
    state.log_request(crate::events::RequestRecord {
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        provider: provider.name.clone(),
        model: model.to_string(),
        key: key.masked(),
        status: status.to_string(),
        latency_ms: started.elapsed().as_millis() as u64,
        stream,
        client_key: client_key.map(str::to_string),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_kinds() {
        assert!(supports_embeddings(ProviderKind::OpenaiCompat));
        assert!(supports_embeddings(ProviderKind::Gemini));
        for k in [
            ProviderKind::Anthropic,
            ProviderKind::Codex,
            ProviderKind::Antigravity,
        ] {
            assert!(!supports_embeddings(k), "{k:?} has no embeddings API");
        }
    }

    #[test]
    fn model_rewrite_is_a_byte_splice() {
        let body = Bytes::from_static(br#"{"model":"a/b","input":"hi"}"#);
        let span = crate::scan::string_field_span(&body, b"model").unwrap();
        let out = rewrite_model(&body, &span, "plain");
        assert_eq!(&out[..], br#"{"model":"plain","input":"hi"}"#);
        // A longer name grows the buffer correctly.
        let out = rewrite_model(&body, &span, "a-much-longer-model-name");
        assert!(out.windows(22).any(|w| w == b"a-much-longer-model-na"));
        // Identical name: no rewrite, and the body is shared, not copied.
        let same = rewrite_model(&body, &span, "a/b");
        assert_eq!(same, body);
    }

    #[test]
    fn single_and_batch_inputs_are_both_accepted() {
        let one = gemini_request(br#"{"model":"m","input":"hello"}"#, "m").unwrap();
        assert_eq!(one["requests"].as_array().unwrap().len(), 1);
        assert_eq!(one["requests"][0]["content"]["parts"][0]["text"], "hello");

        let many = gemini_request(br#"{"model":"m","input":["a","b","c"]}"#, "m").unwrap();
        assert_eq!(many["requests"].as_array().unwrap().len(), 3);
        // Gemini wants the "models/" prefix on the per-request model.
        assert_eq!(many["requests"][2]["model"], "models/m");
    }

    #[test]
    fn token_id_inputs_are_rejected_not_silently_dropped() {
        assert!(gemini_request(br#"{"model":"m","input":[1,2,3]}"#, "m").is_none());
        assert!(gemini_request(br#"{"model":"m","input":[]}"#, "m").is_none());
        assert!(gemini_request(br#"{"model":"m"}"#, "m").is_none());
        assert!(gemini_request(b"not json", "m").is_none());
    }

    #[test]
    fn gemini_response_is_translated_to_the_openai_shape() {
        let upstream = json!({
            "embeddings": [
                {"values": [0.1, 0.2]},
                {"values": [0.3, 0.4]}
            ]
        });
        let out = gemini_response(&upstream, "gemini/embed").unwrap();
        assert_eq!(out["object"], "list");
        assert_eq!(out["model"], "gemini/embed");
        let data = out["data"].as_array().unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[1]["index"], 1);
        assert_eq!(data[1]["embedding"][0], 0.3);
        assert_eq!(out["usage"]["prompt_tokens"], 0);
    }

    #[test]
    fn malformed_upstream_payload_is_an_error_not_a_panic() {
        for bad in [
            json!({}),
            json!({"embeddings": "nope"}),
            json!({"embeddings": [{"values": "nope"}]}),
        ] {
            assert!(gemini_response(&bad, "m").is_none(), "{bad}");
        }
    }
}
