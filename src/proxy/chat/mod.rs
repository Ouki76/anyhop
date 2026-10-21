//! POST /v1/chat/completions and the per-target retry loop shared with FIM.
//!
//! - `errors`  — upstream status classification, exhaustion bodies, Retry-After parsing
//! - `retry`   — proactive drain from x-ratelimit headers
//! - `session` — sticky-session hashing
//! - `stream`  — pass-through, buffering and translated responses

mod errors;
mod retry;
mod session;
mod stream;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::Response;
use serde_json::Value;
use tracing::{info, warn};

use crate::anthropic::{self};
use crate::antigravity::{self, AuthError};
use crate::codex;
use crate::config::ProviderKind;
use crate::gemini;
use crate::pool::FailKind;
use crate::providers::{Provider, Resolved};

use super::access::{combo_allowed, model_allowed, model_disabled};
use super::{AppState, KeyPermissions, error_response};

use self::errors::{ErrorAction, classify_error_status, exhausted_response, internal_body_error};
use self::retry::check_drain_headers;
use self::session::session_key_with;
use self::stream::success_response;

pub use self::session::session_key;

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
            let m = v.get("model").and_then(|m| m.as_str()).map(str::to_string);
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
        let disabled = state
            .disabled_models
            .read()
            .unwrap_or_else(|e| e.into_inner());
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
                        !disabled.contains(&format!("{}/{}", p.name, m))
                            && !disabled.contains(m.as_str())
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
            || targets
                .iter()
                .any(|(p, _)| p.kind != ProviderKind::OpenaiCompat))
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

    let client_key = key_perm.as_ref().and_then(|e| e.0.key_name.clone());
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
                format!(
                    "target '{}/{}' exhausted, trying next",
                    provider.name, upstream_model
                ),
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
    run_target(
        state,
        provider,
        model,
        &body,
        span,
        Some(payload),
        is_stream,
        None,
        None,
    )
    .await
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
            return Some(error_response(
                StatusCode::BAD_REQUEST,
                e,
                "invalid_request_error",
            ));
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
                provider.pool.report_failure(
                    &key,
                    FailKind::RateLimited { retry_after_secs },
                    model,
                );
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
