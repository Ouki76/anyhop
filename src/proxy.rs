use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde_json::Value;
use tracing::{info, warn};

use crate::anthropic::{self};
use crate::antigravity::{self, AuthError};
use crate::codex;
use crate::config::ProviderKind;
use crate::gemini;
use crate::pool::{FailKind, KeyState};
use crate::providers::{Provider, ProviderRouter, Resolved};

/// Hot-reloadable server settings.
#[derive(Clone)]
pub struct RtConfig {
    pub max_retries: usize,
    pub attempt_timeout: Duration,
    pub api_key: Option<String>,
}

pub struct AppState {
    pub router: arc_swap::ArcSwap<ProviderRouter>,
    pub cfg: std::sync::RwLock<RtConfig>,
    pub storage: Option<crate::storage::Storage>,
    pub config_path: String,
    pub events: crate::events::EventBus,
    /// Ongoing dashboard-triggered OAuth flow (single at a time).
    pub auth_state: std::sync::Mutex<Option<crate::api::AuthStateDto>>,
}

impl AppState {
    pub fn rt(&self) -> RtConfig {
        self.cfg.read().unwrap().clone()
    }
}

pub fn error_response(status: StatusCode, message: impl Into<String>, ty: &str) -> Response {
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
    let router = state.router.load();
    let mut data = Vec::new();
    for p in &router.providers {
        for m in p.effective_models().await {
            data.push(serde_json::json!({
                "id": format!("{}/{}", p.name, m),
                "object": "model",
                "owned_by": p.name,
            }));
        }
    }
    for c in &router.combos {
        data.push(serde_json::json!({
            "id": c.name,
            "object": "model",
            "owned_by": "combo",
        }));
    }
    Json(serde_json::json!({ "object": "list", "data": data })).into_response()
}

pub async fn chat_completions(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    // Fast path: byte-level peek of model/stream; Value DOM only when a
    // translating provider actually needs it.
    let (model, is_stream, model_span, mut json) = match crate::scan::peek_request(&body) {
        Some((m, s)) => (m, s, crate::scan::string_field_span(&body, b"model"), None),
        None => {
            let v: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        format!("invalid JSON body: {e}"),
                        "invalid_request_error",
                    );
                }
            };
            let m = v
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string);
            let Some(m) = m else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "missing or invalid 'model' field",
                    "invalid_request_error",
                );
            };
            let s = v.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
            (m, s, None, Some(v))
        }
    };

    let router = state.router.load();
    let Some(resolved) = router.resolve(&model) else {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("no provider serves model '{model}'"),
            "model_not_found",
        );
    };

    let targets: Vec<(&Provider, String)> = match &resolved {
        Resolved::One(p, m) => vec![(*p, m.clone())],
        Resolved::Chain(c) => c.clone(),
    };

    // Parse the Value DOM only when a target needs translation or the byte splice
    // failed (non-string model value etc.).
    if json.is_none()
        && (model_span.is_none()
            || targets.iter().any(|(p, _)| p.kind != ProviderKind::OpenaiCompat))
    {
        json = match serde_json::from_slice(&body) {
            Ok(v) => Some(v),
            Err(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid JSON body: {e}"),
                    "invalid_request_error",
                );
            }
        };
    }

    let max_retries = state.rt().max_retries;
    let total = targets.len();
    for (i, (provider, upstream_model)) in targets.iter().enumerate() {
        let result = run_target(&state, provider, upstream_model, &body, model_span.clone(), json.as_ref(), is_stream).await;
        if let Some(resp) = result {
            if total > 1 && i > 0 {
                info!(combo = %model, fallback = i + 1, of = total, "combo fallback succeeded");
            }
            return resp;
        }
        if total > 1 {
            state.events.emit(crate::events::DashEvent::new(
                "combo",
                &model,
                "backoff",
                format!("target '{}/{}' exhausted, trying next", provider.name, upstream_model),
            ));
        } else {
            return exhausted_response(&provider.name, max_retries);
        }
    }
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("combo '{model}': all {total} targets exhausted"),
        "provider_unavailable",
    )
}

fn exhausted_response(provider: &str, attempts: usize) -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("provider '{provider}' unavailable after {attempts} attempts"),
        "provider_unavailable",
    )
}

/// Public wrapper for the FIM endpoint.
pub async fn run_target_pub(
    state: &AppState,
    provider: &Provider,
    model: &str,
    payload: &Value,
    is_stream: bool,
) -> Option<Response> {
    let body = Bytes::from(serde_json::to_vec(payload).unwrap_or_default());
    let span = crate::scan::string_field_span(&body, b"model");
    run_target(state, provider, model, &body, span, Some(payload), is_stream).await
}

/// Run the retry loop for one provider/model target.
/// Some(resp) = definitive answer (success or client error), None = try next target.
///
/// `raw`/`model_span` drive the zero-copy pass-through path; `payload` is the
/// lazily-parsed DOM for translating providers (None-safe: present whenever needed).
async fn run_target(
    state: &AppState,
    provider: &Provider,
    model: &str,
    raw: &Bytes,
    model_span: Option<std::ops::Range<usize>>,
    payload: Option<&Value>,
    is_stream: bool,
) -> Option<Response> {
    // Translated payloads are prebuilt once, before the retry loop
    // (the antigravity envelope additionally needs a per-account project id).
    let translated = match provider.kind {
        ProviderKind::Gemini | ProviderKind::Antigravity => {
            Some(gemini::translate_request(payload.expect("json dom")))
        }
        ProviderKind::Anthropic => {
            let mut p = payload.expect("json dom").clone();
            p["model"] = Value::String(model.to_string());
            Some(anthropic::translate_request(&p))
        }
        ProviderKind::Codex => Some(codex::translate_request(model, payload.expect("json dom"))),
        _ => None,
    };
    let translated = match translated {
        Some(Ok(b)) => Some(b),
        Some(Err(e)) => {
            return Some(error_response(StatusCode::BAD_REQUEST, e, "invalid_request_error"));
        }
        None => None,
    };

    for _ in 0..state.rt().max_retries.max(1) {
        let Some(key) = provider.pool.pick(model) else {
            warn!(provider = %provider.name, model, "no available keys (all busy/cooling down/dead)");
            break;
        };
        let Some(guard) = key.try_acquire() else {
            // Saturated — try another key without penalizing this one.
            continue;
        };

        let mut req = match provider.kind {
            ProviderKind::OpenaiCompat => {
                // Zero-copy splice: swap the model name directly in the body bytes.
                let mut bytes = raw.to_vec();
                if let Some(span) = &model_span {
                    bytes.splice(span.clone(), model.as_bytes().iter().copied());
                }
                provider
                    .client
                    .post(format!("{}/chat/completions", provider.base_url))
                    .bearer_auth(&key.secret)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes)
            }
            ProviderKind::Gemini => provider
                .client
                .post(gemini::endpoint(&provider.base_url, model, is_stream))
                .header("x-goog-api-key", &key.secret)
                .json(translated.as_ref().expect("gemini body")),
            ProviderKind::Anthropic => {
                let mut body = translated.as_ref().expect("anthropic body").clone();
                if is_stream {
                    body["stream"] = Value::Bool(true);
                }
                provider
                    .client
                    .post(format!("{}/v1/messages", provider.base_url))
                    .header("x-api-key", &key.secret)
                    .header("anthropic-version", anthropic::API_VERSION)
                    .json(&body)
            }
            ProviderKind::Codex => {
                let Some(account) = provider.codex_account(&key.secret) else {
                    provider.pool.report_failure(&key, FailKind::Auth, model);
                    continue;
                };
                let token = match account.ensure_access_token().await {
                    Ok(t) => t,
                    Err(e) => {
                        let kind = match &e {
                            AuthError::Permanent(_) => FailKind::Auth,
                            AuthError::Transient(_) => FailKind::Network,
                        };
                        warn!(provider = %provider.name, account = %account.label(), error = %e, "codex token refresh failed");
                        provider.pool.report_failure(&key, kind, model);
                        continue;
                    }
                };
                let mut r = account
                    .client()
                    .post(format!("{}/responses", provider.base_url))
                    .bearer_auth(token)
                    .header("originator", "codex_cli_rs")
                    .header("OpenAI-Beta", "responses=experimental")
                    .header(header::ACCEPT, "text/event-stream")
                    .json(translated.as_ref().expect("codex body"));
                if let Some(acc_id) = &account.account_id {
                    r = r.header("Chatgpt-Account-Id", acc_id);
                }
                r
            }
            ProviderKind::Antigravity => {
                let Some(account) = provider.ag_account(&key.secret) else {
                    provider.pool.report_failure(&key, FailKind::Auth, model);
                    continue;
                };
                let token = match account.ensure_access_token().await {
                    Ok(t) => t,
                    Err(e) => {
                        let kind = match &e {
                            AuthError::Permanent(_) => FailKind::Auth,
                            AuthError::Transient(_) => FailKind::Network,
                        };
                        warn!(provider = %provider.name, account = %account.label(), error = %e, "token refresh failed");
                        provider.pool.report_failure(&key, kind, model);
                        continue;
                    }
                };
                let project = match account.ensure_project_id(&token).await {
                    Ok(p) => p,
                    Err(e) => {
                        let kind = match &e {
                            AuthError::Permanent(_) => FailKind::Auth,
                            AuthError::Transient(_) => FailKind::Network,
                        };
                        warn!(provider = %provider.name, account = %account.label(), error = %e, "project resolution failed");
                        provider.pool.report_failure(&key, kind, model);
                        continue;
                    }
                };
                let inner = translated.as_ref().expect("gemini body").clone();
                let envelope = match antigravity::translate_request_envelope(model, inner, &project)
                {
                    Ok(v) => v,
                    Err(e) => {
                        return Some(error_response(
                            StatusCode::BAD_REQUEST,
                            e,
                            "invalid_request_error",
                        ));
                    }
                };
                account
                    .client()
                    .post(antigravity::endpoint(&provider.base_url, is_stream))
                    .bearer_auth(token)
                    .header(header::USER_AGENT, antigravity::USER_AGENT)
                    .json(&envelope)
            }
        };
        for (k, v) in &provider.extra_headers {
            req = req.header(k, v);
        }

        let result = tokio::time::timeout(state.rt().attempt_timeout, req.send()).await;
        let resp = match result {
            Err(_) => {
                provider.pool.report_failure(&key, FailKind::Network, model);
                warn!(provider = %provider.name, key = %key.masked(), "attempt timed out");
                continue;
            }
            Ok(Err(e)) => {
                provider.pool.report_failure(&key, FailKind::Network, model);
                warn!(provider = %provider.name, key = %key.masked(), error = %e, "network error");
                continue;
            }
            Ok(Ok(resp)) => resp,
        };

        let status = resp.status();
        if status.is_success() {
            provider.pool.report_success(&key);
            info!(provider = %provider.name, key = %key.masked(), model, "ok");
            if provider.drain_below_pct > 0 {
                check_drain_headers(provider, &key, &resp);
            }
            return Some(success_response(provider, model, resp, is_stream, key, guard).await);
        }
        drop(guard);

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
                // Antigravity quotas are per-model: parse exact reset time,
                // fallback to a short per-model cooldown when absent.
                if matches!(provider.kind, ProviderKind::Antigravity) {
                    let until_ms = antigravity::parse_quota_reset_ms(&text).unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64
                            + 60_000
                    });
                    provider
                        .pool
                        .report_failure(&key, FailKind::ModelQuota { until_ms }, model);
                    warn!(provider = %provider.name, key = %key.masked(), model, "model quota exhausted");
                } else {
                    provider
                        .pool
                        .report_failure(&key, FailKind::RateLimited { retry_after_secs }, model);
                    warn!(provider = %provider.name, key = %key.masked(), retry_after = ?retry_after_secs, "rate limited, key on cooldown");
                }
            }
            401 | 403 => {
                provider.pool.report_failure(&key, FailKind::Auth, model);
                warn!(provider = %provider.name, key = %key.masked(), "auth failed, key marked dead");
            }
            // Gemini returns 400 INVALID_ARGUMENT for invalid API keys.
            400 if matches!(provider.kind, ProviderKind::Gemini)
                && snippet.contains("API key not valid") =>
            {
                provider.pool.report_failure(&key, FailKind::Auth, model);
                warn!(provider = %provider.name, key = %key.masked(), "gemini key invalid, marked dead");
            }
            s if s >= 500 => {
                provider.pool.report_failure(&key, FailKind::Server, model);
                warn!(provider = %provider.name, key = %key.masked(), status = s, "upstream 5xx, key on cooldown");
            }
            _ => {
                // Client error (400 etc.) — not the key's fault, pass through as-is.
                info!(provider = %provider.name, key = %key.masked(), status = %status.as_u16(), "upstream 4xx, passing through");
                return Some(error_response(status, snippet, "upstream_error"));
            }
        }
    }
    None
}

/// Proactive drain: cool the key down before it hits the rate limit,
/// based on x-ratelimit-remaining/limit/reset headers.
fn check_drain_headers(provider: &Provider, key: &Arc<KeyState>, resp: &reqwest::Response) {
    let h = resp.headers();
    let get_u64 = |name: &str| {
        h.get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
    };
    let (Some(remaining), Some(limit)) = (
        get_u64("x-ratelimit-remaining-requests"),
        get_u64("x-ratelimit-limit-requests"),
    ) else {
        return;
    };
    if limit == 0 || remaining * 100 >= limit * provider.drain_below_pct as u64 {
        return;
    }
    let reset = h
        .get("x-ratelimit-reset-requests")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_reset_duration)
        .unwrap_or(Duration::from_secs(60));
    provider.pool.drain(key, reset);
}

/// Parse OpenAI-style reset durations: "500ms", "1s", "1m30s", "2h5m".
fn parse_reset_duration(s: &str) -> Option<Duration> {
    let mut total = Duration::ZERO;
    let mut num = String::new();
    let mut unit = String::new();
    let mut flush = |num: &mut String, unit: &mut String| -> Option<()> {
        if num.is_empty() {
            unit.clear();
            return Some(());
        }
        let v: f64 = num.parse().ok()?;
        let d = match unit.as_str() {
            "ms" => Duration::from_secs_f64(v / 1000.0),
            "s" => Duration::from_secs_f64(v),
            "m" => Duration::from_secs_f64(v * 60.0),
            "h" => Duration::from_secs_f64(v * 3600.0),
            _ => return None,
        };
        total += d;
        num.clear();
        unit.clear();
        Some(())
    };
    for c in s.trim().chars() {
        if c.is_ascii_digit() || c == '.' {
            if !unit.is_empty() {
                flush(&mut num, &mut unit)?;
            }
            num.push(c);
        } else if !c.is_whitespace() {
            unit.push(c);
        }
    }
    flush(&mut num, &mut unit)?;
    (total > Duration::ZERO).then_some(total)
}

/// Build the client response for a successful upstream call.
async fn success_response(
    provider: &Provider,
    model: &str,
    resp: reqwest::Response,
    is_stream: bool,
    key: Arc<KeyState>,
    guard: crate::pool::KeyGuard,
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
                                u.get("completion_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                            );
                        }
                        let mut b = Response::builder()
                            .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));
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
        ProviderKind::Gemini | ProviderKind::Antigravity | ProviderKind::Anthropic
        | ProviderKind::Codex => {
            let envelope = matches!(provider.kind, ProviderKind::Antigravity);
            if is_stream {
                let stream: std::pin::Pin<Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
                    match provider.kind {
                        ProviderKind::Anthropic => {
                            Box::pin(anthropic::translate_sse_stream(resp, model, Some(key)))
                        }
                        ProviderKind::Codex => {
                            Box::pin(codex::translate_sse_stream(resp, model, Some(key)))
                        }
                        _ => Box::pin(gemini::translate_sse_stream(resp, model, envelope, Some(key))),
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
                                    u.get("completion_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
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
                            let v = if envelope { antigravity::unwrap_response(v) } else { v };
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

/// Pass an upstream 2xx response through to the client with zero buffering.
/// The guard keeps the key's in-flight slot until the stream ends.
fn stream_upstream(resp: reqwest::Response, guard: crate::pool::KeyGuard) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
    let content_type = resp.headers().get(header::CONTENT_TYPE).cloned();
    let stream = resp.bytes_stream().map(move |chunk| {
        let _ = &guard;
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
