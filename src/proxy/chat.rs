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
use crate::providers::{Provider, Resolved};

use super::access::{combo_allowed, model_allowed, model_disabled};
use super::{AppState, KeyPermissions, error_response};

pub async fn chat_completions(
    State(state): State<Arc<AppState>>,
    key_perm: Option<axum::extract::Extension<KeyPermissions>>,
    body: Bytes,
) -> Response {
    let key_models = key_perm.as_ref().and_then(|e| e.0.allowed_models.as_ref());
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

    // Hold the read guard for the checks instead of cloning the whole set
    // (one String alloc per disabled model per request). The guard is dropped
    // at the end of this block — before the first .await, keeping the handler Send.
    let targets: Vec<(&Provider, String)> = {
        let disabled = state.disabled_models.read().unwrap_or_else(|e| e.into_inner());
        // The requested name may be bare (disabled) or "combo/name" — check both.
        {
            let bare = model.strip_prefix("combo/").unwrap_or(&model);
            if disabled.contains(&model) || disabled.contains(bare) {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("model '{model}' is disabled"),
                    "model_not_found",
                );
            }
        }
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
            let active: Vec<_> = c
                .iter()
                .filter(|(p, m)| {
                    !disabled.contains(&format!("{}/{}", p.name, m)) && !disabled.contains(m.as_str())
                })
                .cloned()
                .collect();
            if active.is_empty() {
                return error_response(
                    StatusCode::NOT_FOUND,
                    format!("all targets in combo '{model}' are disabled"),
                    "model_not_found",
                );
            }
            active
        }
        }
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

    // Sticky sessions: hash (model + body prefix) → the same key for a conversation,
    // to hit the provider's KV cache. Only for chats with messages.
    // Sticky sessions: hash (model + body prefix) → the same key for a conversation,
    // to hit the provider's KV cache. Only for chats with messages, and only when
    // stickiness can actually influence the pick (single-key or fill_first pools
    // ignore it, so hashing would be pure waste).
    // memmem instead of `body.windows(8).any(...)`: the naive version compares
    // 8 bytes at every offset, which is millions of comparisons on a large body.
    let session = if targets.iter().any(|(p, _)| p.pool.sticky_enabled())
        && memchr::memmem::find(&body, b"messages").is_some()
    {
        Some(session_key_with(
            &model,
            &body,
            state.tuning.session_prefix_bytes,
        ))
    } else {
        None
    };

    let client_key = key_perm
        .as_ref()
        .and_then(|e| e.0.key_name.clone());
    let client_key = client_key.as_deref();
    let max_retries = state.rt().max_retries;
    let total = targets.len();
    for (i, (provider, upstream_model)) in targets.iter().enumerate() {
        let result = run_target(
            &state,
            provider,
            upstream_model,
            &body,
            model_span.clone(),
            json.as_ref(),
            is_stream,
            session,
            client_key,
        )
        .await;
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
            let wake = provider.pool.wake_after(&model);
            tracing::debug!(
                provider = %provider.name, model = %upstream_model, ?wake,
                "all attempts failed, reporting exhaustion"
            );
            return exhausted_response(&provider.name, max_retries, wake);
        }
    }
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("combo '{model}': all {total} targets exhausted"),
        "provider_unavailable",
    )
}

/// Sticky session hash: model + the first `tuning.session_prefix_bytes` of the body
/// (covers system + first messages; 4 KB by default).
///
/// `pub` only so `cargo bench` can measure it — it is not part of the HTTP surface.
pub fn session_key(model: &str, body: &Bytes) -> u64 {
    session_key_with(model, body, 4096)
}

pub fn session_key_with(model: &str, body: &Bytes, prefix_bytes: usize) -> u64 {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(model.as_bytes());
    h.update(&body[..body.len().min(prefix_bytes.max(1))]);
    let d = h.finalize();
    // sha256 always yields 32 bytes; slice to 8 for the hash map key.
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    u64::from_le_bytes(out)
}

/// A translating provider was reached without a parsed body — a bug in the
/// caller, not a client error. Report it as a 500 instead of panicking the task.
fn internal_body_error() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal: request body was not parsed for a translating provider",
        "internal_error",
    )
}

fn exhausted_response(provider: &str, attempts: usize, retry_after: Option<Duration>) -> Response {
    let mut resp = error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("provider '{provider}' unavailable after {attempts} attempts"),
        "provider_unavailable",
    );
    // Tell the client when it is worth retrying: without this a single-key
    // provider that just went into a 5s cooldown looks permanently down.
    if let Some(d) = retry_after
        && let Ok(v) = header::HeaderValue::from_str(&d.as_secs().max(1).to_string())
    {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
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
    run_target(state, provider, model, &body, span, Some(payload), is_stream, None, None).await
}

/// Run the retry loop for one provider/model target.
/// Some(resp) = definitive answer (success or client error), None = try next target.
///
/// `raw`/`model_span` drive the zero-copy pass-through path; `payload` is the
/// lazily-parsed DOM for translating providers (None-safe: present whenever needed).
#[allow(clippy::too_many_arguments)] // cohesive hot-path call; grouping would add noise
async fn run_target(
    state: &AppState,
    provider: &Provider,
    model: &str,
    raw: &Bytes,
    model_span: Option<std::ops::Range<usize>>,
    payload: Option<&Value>,
    is_stream: bool,
    session: Option<u64>,
    client_key: Option<&str>,
) -> Option<Response> {
    // Translated payloads are prebuilt once, before the retry loop
    // (the antigravity envelope additionally needs a per-account project id).
    // The caller guarantees a DOM whenever a non-pass-through target is present;
    // fall through as "nothing to translate" rather than panicking if that ever
    // stops holding.
    let translated = match (provider.kind, payload) {
        (ProviderKind::OpenaiCompat, _) => None,
        (_, None) => {
            warn!(provider = %provider.name, model, "no JSON DOM for a translating provider");
            return Some(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal: request body was not parsed",
                "internal_error",
            ));
        }
        (ProviderKind::Gemini | ProviderKind::Antigravity, Some(p)) => {
            Some(gemini::translate_request(p))
        }
        (ProviderKind::Anthropic, Some(p)) => {
            let mut p = p.clone();
            p["model"] = Value::String(model.to_string());
            Some(anthropic::translate_request(&p))
        }
        (ProviderKind::Codex, Some(p)) => Some(codex::translate_request(model, p)),
    };
    let translated = match translated {
        Some(Ok(b)) => Some(b),
        Some(Err(e)) => {
            return Some(error_response(StatusCode::BAD_REQUEST, e, "invalid_request_error"));
        }
        None => None,
    };

    // Snapshot runtime config once per target, not per attempt.
    let rt = state.rt();
    // Per-provider overrides win over the global budget: a slow upstream may need
    // minutes while a fast one should fail over in seconds.
    let attempts = if provider.max_retries > 0 {
        provider.max_retries
    } else {
        rt.max_retries
    };
    let attempt_timeout = provider.timeout;
    for _ in 0..attempts.max(1) {
        let Some(key) = provider.pool.pick(model, session) else {
            warn!(provider = %provider.name, model, "no available keys (all busy/cooling down/dead)");
            break;
        };
        let Some(guard) = key.try_acquire() else {
            // Saturated — try another key without penalizing this one.
            continue;
        };

        let mut req = match provider.kind {
            ProviderKind::OpenaiCompat => {
                // Rewrite the model name in place, but never copy the body unless
                // the value really differs: a bare model name (the common case)
                // used to cost a full body copy — up to 32 MiB per request.
                let bytes: Bytes = match &model_span {
                    Some(span) if raw.get(span.clone()) != Some(model.as_bytes()) => {
                        // One allocation, two memcpys (instead of to_vec + splice).
                        let prefix = &raw[..span.start];
                        let suffix = &raw[span.end..];
                        let mut v = Vec::with_capacity(prefix.len() + model.len() + suffix.len());
                        v.extend_from_slice(prefix);
                        v.extend_from_slice(model.as_bytes());
                        v.extend_from_slice(suffix);
                        Bytes::from(v)
                    }
                    _ => raw.clone(), // Bytes::clone is a refcount bump, no copy
                };
                provider
                    .client
                    .post(format!("{}/chat/completions", provider.base_url))
                    .bearer_auth(&key.secret)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes)
            }
            ProviderKind::Gemini => {
                let Some(t) = translated.as_ref() else {
                    return Some(internal_body_error());
                };
                provider
                    .client
                    .post(gemini::endpoint(&provider.base_url, model, is_stream))
                    .header("x-goog-api-key", &key.secret)
                    .json(t)
            }
            ProviderKind::Anthropic => {
                let Some(t) = translated.as_ref() else {
                    return Some(internal_body_error());
                };
                let mut body = t.clone();
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
                let Some(t) = translated.as_ref() else {
                    return Some(internal_body_error());
                };
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
                    .json(t);
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
                let Some(inner) = translated.as_ref().cloned() else {
                    return Some(internal_body_error());
                };
                let envelope =
                    match antigravity::translate_request_envelope(model, inner, &project) {
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

        let t0 = std::time::Instant::now();
        let result = tokio::time::timeout(attempt_timeout, req.send()).await;
        let latency_ms = t0.elapsed().as_millis() as u64;
        let log_req = |status: &str| {
            state.log_request(crate::events::RequestRecord {
                ts: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                provider: provider.name.clone(),
                model: model.to_string(),
                key: key.masked(),
                status: status.to_string(),
                latency_ms,
                stream: is_stream,
                client_key: client_key.map(str::to_string),
            });
        };
        let resp = match result {
            Err(_) => {
                log_req("timeout");
                provider.pool.report_failure(&key, FailKind::Network, model);
                warn!(provider = %provider.name, key = %key.masked(), "attempt timed out");
                continue;
            }
            Ok(Err(e)) => {
                log_req("network");
                provider.pool.report_failure(&key, FailKind::Network, model);
                warn!(provider = %provider.name, key = %key.masked(), error = %e, "network error");
                continue;
            }
            Ok(Ok(resp)) => resp,
        };

        let status = resp.status();
        log_req(status.as_str());
        if status.is_success() {
            provider.pool.report_success(&key);
            // debug!: one line per request at info level is log amplification —
            // at 5k rps that is 5k writes/s and the log becomes useless. The
            // dashboard's Requests tab is the per-request view instead.
            tracing::debug!(provider = %provider.name, key = %key.masked(), model, "ok");
            if provider.drain_below_pct > 0 {
                check_drain_headers(provider, &key, &resp, state.tuning.as_ref());
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

        match classify_error_status(provider.kind, status.as_u16(), &snippet) {
            ErrorAction::ModelQuota => {
                // Antigravity quotas are per-model: parse exact reset time,
                // fallback to a short per-model cooldown when absent.
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
            }
            ErrorAction::RateLimited => {
                provider
                    .pool
                    .report_failure(&key, FailKind::RateLimited { retry_after_secs }, model);
                warn!(provider = %provider.name, key = %key.masked(), retry_after = ?retry_after_secs, "rate limited, key on cooldown");
            }
            ErrorAction::Auth => {
                provider.pool.report_failure(&key, FailKind::Auth, model);
                warn!(provider = %provider.name, key = %key.masked(), "auth failed, key marked dead");
            }
            ErrorAction::Server => {
                provider.pool.report_failure(&key, FailKind::Server, model);
                warn!(provider = %provider.name, key = %key.masked(), status = %status.as_u16(), "upstream 5xx, key on cooldown");
            }
            ErrorAction::PassThrough => {
                // Client error (400 etc.) — not the key's fault, pass through as-is.
                tracing::debug!(provider = %provider.name, key = %key.masked(), status = %status.as_u16(), "upstream 4xx, passing through");
                return Some(error_response(status, snippet, "upstream_error"));
            }
        }
    }
    None
}

/// Proactive drain: cool the key down before it hits the rate limit,
/// based on x-ratelimit-remaining/limit/reset headers.
fn check_drain_headers(
    provider: &Provider,
    key: &Arc<KeyState>,
    resp: &reqwest::Response,
    tuning: &crate::config::Tuning,
) {
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
    // u128: header values come from the upstream — remaining*100 must not overflow
    if limit == 0 || remaining as u128 * 100 >= limit as u128 * provider.drain_below_pct as u128 {
        return;
    }
    let reset = h
        .get("x-ratelimit-reset-requests")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_reset_duration)
        .unwrap_or_else(|| tuning.drain_fallback());
    provider.pool.drain(key, reset);
}

/// Parse OpenAI-style reset durations: "500ms", "1s", "1m30s", "2h5m".
fn parse_reset_duration(s: &str) -> Option<Duration> {
    let mut total = Duration::ZERO;
    let mut num = String::new();
    let mut unit = String::new();
    let mut flush = |num: &mut String, unit: &mut String| -> Option<()> {
        if num.is_empty() {
            // Nothing buffered at all is fine (start/end of the string), but a
            // unit without a number is junk — accepting it silently would turn
            // "-5s" into a 5s cooldown.
            if unit.is_empty() {
                return Some(());
            }
            return None;
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

/// How a non-2xx upstream status maps onto key-pool bookkeeping.
///
/// Extracted from the retry loop so the mapping is unit-testable: getting it
/// wrong is expensive (a 429 classified as Auth kills a healthy key forever).
#[derive(Debug, PartialEq, Eq)]
enum ErrorAction {
    /// 429 from Antigravity — quota is per model, needs the parsed reset time.
    ModelQuota,
    /// 429 elsewhere — cool the whole key down, honouring Retry-After.
    RateLimited,
    /// 401/403, plus Gemini's 400 "API key not valid": never retry this key.
    Auth,
    /// 5xx — transient, back off and try another key.
    Server,
    /// The client's fault — relay the upstream error untouched.
    PassThrough,
}

fn classify_error_status(kind: ProviderKind, status: u16, body: &str) -> ErrorAction {
    match status {
        429 => {
            if matches!(kind, ProviderKind::Antigravity) {
                ErrorAction::ModelQuota
            } else {
                ErrorAction::RateLimited
            }
        }
        401 | 403 => ErrorAction::Auth,
        // Gemini reports an invalid key as 400 INVALID_ARGUMENT, not 401.
        400 if matches!(kind, ProviderKind::Gemini) && body.contains("API key not valid") => {
            ErrorAction::Auth
        }
        s if s >= 500 => ErrorAction::Server,
        _ => ErrorAction::PassThrough,
    }
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
fn stream_upstream(resp: reqwest::Response, guard: crate::pool::KeyGuard) -> Response {
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

    // ----- upstream error classification -----

    #[test]
    fn rate_limit_cools_the_key_except_for_antigravity() {
        // Antigravity reports per-model quota as 429; everything else is per key.
        assert_eq!(
            classify_error_status(ProviderKind::Antigravity, 429, ""),
            ErrorAction::ModelQuota
        );
        for kind in [
            ProviderKind::OpenaiCompat,
            ProviderKind::Gemini,
            ProviderKind::Anthropic,
            ProviderKind::Codex,
        ] {
            assert_eq!(
                classify_error_status(kind, 429, ""),
                ErrorAction::RateLimited,
                "{kind:?} 429 must cool the whole key"
            );
        }
    }

    #[test]
    fn auth_statuses_kill_the_key() {
        for status in [401, 403] {
            assert_eq!(
                classify_error_status(ProviderKind::OpenaiCompat, status, ""),
                ErrorAction::Auth
            );
        }
    }

    #[test]
    fn gemini_invalid_key_is_detected_by_body() {
        // Gemini answers 400 INVALID_ARGUMENT instead of 401 for a bad key.
        assert_eq!(
            classify_error_status(ProviderKind::Gemini, 400, r#"{"error":"API key not valid. Please pass a valid API key."}"#),
            ErrorAction::Auth
        );
        // The same body from another provider must NOT kill the key — their 400s
        // are request errors.
        assert_eq!(
            classify_error_status(ProviderKind::OpenaiCompat, 400, "API key not valid"),
            ErrorAction::PassThrough
        );
        // A Gemini 400 for a genuinely bad request stays a client error.
        assert_eq!(
            classify_error_status(ProviderKind::Gemini, 400, r#"{"error":"invalid contents"}"#),
            ErrorAction::PassThrough
        );
    }

    #[test]
    fn server_and_client_errors_are_separated() {
        for status in [500, 502, 503, 504, 529] {
            assert_eq!(
                classify_error_status(ProviderKind::OpenaiCompat, status, ""),
                ErrorAction::Server,
                "{status} must be retried on another key"
            );
        }
        for status in [400, 404, 422] {
            assert_eq!(
                classify_error_status(ProviderKind::OpenaiCompat, status, ""),
                ErrorAction::PassThrough,
                "{status} must reach the client unchanged"
            );
        }
    }

    // ----- Retry-After / x-ratelimit-reset parsing -----

    #[test]
    fn reset_durations_parse_the_openai_style_formats() {
        assert_eq!(parse_reset_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_reset_duration("1s"), Some(Duration::from_secs(1)));
        assert_eq!(parse_reset_duration("1m30s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_reset_duration("2h5m"), Some(Duration::from_secs(2 * 3600 + 5 * 60)));
        assert_eq!(parse_reset_duration("  7s  "), Some(Duration::from_secs(7)));
        assert_eq!(parse_reset_duration("1.5s"), Some(Duration::from_millis(1500)));
    }

    #[test]
    fn garbage_reset_durations_are_rejected_not_guessed() {
        // Returning Some(0) would pin a key into an endless zero-length cooldown
        // loop; returning None makes the caller use its documented fallback.
        assert_eq!(parse_reset_duration(""), None);
        assert_eq!(parse_reset_duration("soon"), None);
        assert_eq!(parse_reset_duration("5x"), None);
        assert_eq!(parse_reset_duration("0s"), None);
        assert_eq!(parse_reset_duration("-5s"), None);
    }

    // ----- response header allowlist -----

    #[test]
    fn only_safe_upstream_headers_are_relayed() {
        use reqwest::header::{HeaderName, CONTENT_LENGTH, TRANSFER_ENCODING, CONNECTION};
        for ok in ["content-type", "cache-control", "etag", "retry-after", "x-request-id"] {
            assert!(forward_header(&HeaderName::from_static(ok)), "{ok} should be relayed");
        }
        assert!(forward_header(&HeaderName::from_bytes(b"x-ratelimit-remaining-requests").unwrap()));
        // Hop-by-hop / framing headers describe the upstream connection, not ours.
        for bad in [CONTENT_LENGTH, TRANSFER_ENCODING, CONNECTION] {
            assert!(!forward_header(&bad), "{bad} must never be copied");
        }
        assert!(!forward_header(&HeaderName::from_static("set-cookie")));
        assert!(!forward_header(&HeaderName::from_static("authorization")));
    }

    // ----- sticky session key -----

    #[test]
    fn session_key_is_stable_per_conversation_and_differs_per_model() {
        let body = Bytes::from_static(br#"{"messages":[{"role":"user","content":"hi"}]}"#);
        assert_eq!(session_key("a/model", &body), session_key("a/model", &body));
        assert_ne!(session_key("a/model", &body), session_key("b/model", &body));
        // Same prefix but different tail must not collide (only the first 4KB is
        // hashed, so the payload beyond that is intentionally ignored).
        let other = Bytes::from_static(br#"{"messages":[{"role":"user","content":"yo"}]}"#);
        assert_ne!(session_key("a/model", &body), session_key("a/model", &other));
    }

    #[test]
    fn session_key_handles_short_and_huge_bodies() {
        // Empty body must not panic (slice of 0 bytes is fine).
        let _ = session_key("m", &Bytes::new());
        // >4KB: only the first 4KB is hashed, and it must not slice out of range.
        let big = Bytes::from(vec![b'x'; 9000]);
        let a = session_key("m", &big);
        let mut almost = vec![b'x'; 4096];
        almost.extend_from_slice(b"tail");
        assert_eq!(a, session_key("m", &Bytes::from(almost)), "only the first 4KB may matter");
    }
}
