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

use self::errors::{
    ErrorAction, TargetFailure, classify_error_status, failure_response, internal_body_error,
};
use self::retry::check_drain_headers;
use self::session::session_key_with;
use self::stream::{Accepted, success_response};

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
            state.tuning().session_prefix_bytes,
        ))
    } else {
        None
    };

    let client_key = key_perm.as_ref().and_then(|e| e.0.key_name.clone());
    let client_key = client_key.as_deref();
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
        match result {
            Ok(resp) => {
                if total > 1 && i > 0 {
                    info!(combo = %model, fallback = i + 1, of = total, "combo fallback succeeded");
                }
                return resp;
            }
            Err(failure) if total > 1 => {
                state.events.emit(crate::events::DashEvent::new(
                    "combo",
                    &model,
                    "backoff",
                    format!(
                        "target '{}/{}' exhausted, trying next",
                        provider.name, upstream_model
                    ),
                ));
                tracing::debug!(
                    provider = %provider.name, model = %upstream_model, ?failure,
                    "combo target failed, trying the next one"
                );
            }
            Err(failure) => {
                tracing::debug!(
                    provider = %provider.name, model = %upstream_model, ?failure,
                    "all attempts failed, reporting exhaustion"
                );
                return failure_response(&provider.name, failure);
            }
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
    .ok()
}

/// Replace the value at `span` with `model`, escaped as a JSON string body.
///
/// The span covers the *raw bytes* between the quotes, so the replacement must be
/// JSON-escaped: a resolved model containing `"` or `\` used to be copied in
/// verbatim and turned the body into invalid JSON (or into a different request).
fn splice_model(raw: &Bytes, span: &std::ops::Range<usize>, model: &str) -> Bytes {
    let prefix = &raw[..span.start];
    let suffix = &raw[span.end..];
    let mut out = Vec::with_capacity(prefix.len() + model.len() + suffix.len() + 8);
    out.extend_from_slice(prefix);
    match serde_json::to_vec(model) {
        // `to_vec` yields `"escaped"`; the surrounding quotes are already there.
        Ok(encoded) if encoded.len() >= 2 => {
            out.extend_from_slice(&encoded[1..encoded.len() - 1]);
        }
        _ => out.extend_from_slice(model.as_bytes()),
    }
    out.extend_from_slice(suffix);
    Bytes::from(out)
}

/// Run the retry loop for one provider/model target.
///
/// `Ok(resp)` is a definitive answer (success or client error); `Err(_)` says
/// *why* nothing worked, so the caller can answer a saturated gateway
/// differently from a provider that is down.
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
) -> Result<Response, TargetFailure> {
    // Translated payloads are prebuilt once, before the retry loop
    // (the antigravity envelope additionally needs a per-account project id).
    // The caller guarantees a DOM whenever a non-pass-through target is present;
    // fall through as "nothing to translate" rather than panicking if that ever
    // stops holding.
    let translated = match (provider.kind, payload) {
        (ProviderKind::OpenaiCompat, _) => None,
        (_, None) => {
            warn!(provider = %provider.name, model, "no JSON DOM for a translating provider");
            return Ok(error_response(
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
            return Ok(error_response(
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
    // Attempts are counted where they are really sent: reporting
    // "unavailable after 4 attempts" when the pool never handed out a key is a lie
    // that sends operators looking in the wrong place.
    let mut made = 0usize;
    let mut last: Option<TargetFailure> = None;
    for _ in 0..attempts.max(1) {
        let Some(key) = provider.pool.pick(model, session) else {
            warn!(provider = %provider.name, model, "no available key (empty pool, cooling down, or saturated)");
            keep_specific(
                &mut last,
                empty_pool_failure(&provider.pool, model, provider.max_concurrent, made),
            );
            break;
        };
        let Some(guard) = key.try_acquire() else {
            // Saturated — try another key without penalizing this one.
            last = Some(TargetFailure::Capacity { attempts: made });
            continue;
        };

        let mut req = match provider.kind {
            ProviderKind::OpenaiCompat => {
                // Rewrite the model name in place, but never copy the body unless
                // the value really differs: a bare model name (the common case)
                // used to cost a full body copy — up to 32 MiB per request.
                let bytes: Bytes = match &model_span {
                    Some(span) if raw.get(span.clone()) != Some(model.as_bytes()) => {
                        splice_model(raw, span, model)
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
                    return Ok(internal_body_error());
                };
                provider
                    .client
                    .post(gemini::endpoint(&provider.base_url, model, is_stream))
                    .header("x-goog-api-key", &key.secret)
                    .json(t)
            }
            ProviderKind::Anthropic => {
                let Some(t) = translated.as_ref() else {
                    return Ok(internal_body_error());
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
                    return Ok(internal_body_error());
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
                    return Ok(internal_body_error());
                };
                let envelope = match antigravity::translate_request_envelope(model, inner, &project)
                {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok(error_response(
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
        made += 1;
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
            // A 2xx is not a completion yet. An upstream error page
            // (`200 text/html` from nginx) used to be relayed as a successful
            // answer: `report_success` ran and the health counters never moved.
            let ct = stream::content_type_of(&resp);
            if let Accepted::WrongContentType(ct) =
                stream::accept_2xx(provider.kind, is_stream, &ct)
            {
                log_req("bad_content_type");
                provider.pool.report_failure(&key, FailKind::Server, model);
                warn!(provider = %provider.name, model, content_type = %ct, "upstream 2xx is not a completion, benching the key");
                last = Some(TargetFailure::BadBody {
                    attempts: made,
                    content_type: ct,
                });
                continue;
            }
            if provider.drain_below_pct > 0 {
                check_drain_headers(provider, &key, &resp, state.tuning().as_ref());
            }
            // Nor is it a body: an upstream that sends headers and then goes
            // silent must not hold the client (or the key slot) forever.
            let body = if matches!(provider.kind, ProviderKind::Codex) {
                // The codex parser owns the whole exchange, body included.
                stream::Upstream::Attached(resp)
            } else {
                match stream::open_body(resp, attempt_timeout).await {
                    Ok(body) => body,
                    Err(e) => {
                        log_req("body_timeout");
                        provider.pool.report_failure(&key, FailKind::Server, model);
                        warn!(provider = %provider.name, model, error = %e, "upstream 2xx without a body, benching the key");
                        last = Some(TargetFailure::Unavailable {
                            attempts: made,
                            wake: None,
                        });
                        continue;
                    }
                }
            };
            provider.pool.report_success(&key);
            // debug!: one line per request at info level is log amplification —
            // at 5k rps that is 5k writes/s and the log becomes useless. The
            // dashboard's Requests tab is the per-request view instead.
            tracing::debug!(provider = %provider.name, key = %key.masked(), model, "ok");
            return Ok(success_response(provider, model, body, is_stream, key, guard).await);
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
                return Ok(error_response(status, snippet, "upstream_error"));
            }
        }
    }
    // Report the real cause: a saturated gateway is a 429 with a Retry-After, a
    // provider that is down is a 503 carrying its wake time.
    Err(match last {
        Some(TargetFailure::Capacity { .. }) => TargetFailure::Capacity { attempts: made },
        Some(TargetFailure::BadBody { content_type, .. }) => TargetFailure::BadBody {
            attempts: made,
            content_type,
        },
        _ => TargetFailure::Unavailable {
            attempts: made,
            // Cooldowns are keyed by the *upstream* model; `wake_after_any` also
            // tolerates the qualified/bare spellings, so a naming mismatch can
            // never silence the Retry-After.
            wake: provider.pool.wake_after_any(model),
        },
    })
}

/// Record `fallback` only when nothing more specific is already known.
///
/// "no key left" is a *consequence* of the failure that benched the last one, so
/// it must not overwrite the explanation: an upstream serving HTML used to end up
/// reported as a generic 503 instead of a 502 naming the content type.
fn keep_specific(last: &mut Option<TargetFailure>, fallback: TargetFailure) {
    if last.is_none() {
        *last = Some(fallback);
    }
}

/// Why the pool handed out no key.
///
/// `pick` returns `None` both when every key is momentarily at its in-flight cap
/// and when no key can serve the model at all; the answers differ (429 "retry in
/// a moment" vs 503 "provider unavailable"). `snapshot()` tells them apart, and
/// this only runs on a request that is already failing.
fn empty_pool_failure(
    pool: &crate::pool::KeyPool,
    model: &str,
    max_concurrent: u32,
    made: usize,
) -> TargetFailure {
    let snapshot = pool.snapshot();
    let usable: Vec<_> = snapshot
        .iter()
        .filter(|k| k.status != "dead" && k.status != "cooldown")
        .collect();
    let saturated = max_concurrent > 0
        && !usable.is_empty()
        && usable.iter().all(|k| k.in_flight >= max_concurrent);
    if saturated {
        return TargetFailure::Capacity { attempts: made };
    }
    TargetFailure::Unavailable {
        attempts: made,
        // Cooldowns are recorded per *upstream* model, which is what `model` is
        // here; `wake_after_any` tolerates the other spellings too.
        wake: pool.wake_after_any(model),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- pass-through model splice -----

    /// A resolved model is spliced into the client's raw JSON body. Anything that
    /// needs escaping (`"`, `\`, control bytes) used to be copied in verbatim,
    /// which corrupted the request instead of reaching the upstream.
    #[test]
    fn a_model_that_needs_escaping_cannot_corrupt_the_passthrough_body() {
        let raw =
            Bytes::from_static(br#"{"model":"alias","messages":[{"role":"user","content":"hi"}]}"#);
        let span = crate::scan::string_field_span(&raw, b"model").expect("the body has a model");
        for model in ["we\"ird", "back\\slash", "line\nbreak", "tab\there"] {
            let out = splice_model(&raw, &span, model);
            let v: Value = serde_json::from_slice(&out)
                .unwrap_or_else(|e| panic!("splicing {model:?} produced invalid JSON: {e}"));
            assert_eq!(v["model"], model);
            // The rest of the body is untouched.
            assert_eq!(v["messages"][0]["content"], "hi");
        }
    }

    #[test]
    fn an_ordinary_model_splice_keeps_the_body_byte_for_byte() {
        let raw = Bytes::from_static(br#"{"model":"alias","temperature":0.5}"#);
        let span = crate::scan::string_field_span(&raw, b"model").expect("the body has a model");
        let out = splice_model(&raw, &span, "upstream-model");
        assert_eq!(
            std::str::from_utf8(&out).expect("spliced bodies are UTF-8"),
            r#"{"model":"upstream-model","temperature":0.5}"#
        );
    }

    // ----- saturation vs exhaustion -----

    /// `pick()` returning `None` means two different things. All keys at their
    /// in-flight cap is "retry in a moment" (429), not "provider down" (503) —
    /// and 200 parallel requests used to get 196 bare 503s for it.
    #[test]
    fn all_keys_at_their_cap_is_capacity_not_exhaustion() {
        let pool = crate::pool::KeyPool::new(
            "p".into(),
            vec!["k".into()],
            crate::config::Strategy::FillFirst,
            1,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
        );
        let key = pool.pick("m", None).expect("one key");
        let slot = key.try_acquire().expect("a free slot");

        assert_eq!(
            empty_pool_failure(&pool, "m", 1, 7),
            TargetFailure::Capacity { attempts: 7 }
        );

        // Once the slot is free again it is no longer a capacity problem.
        drop(slot);
        assert!(matches!(
            empty_pool_failure(&pool, "m", 1, 7),
            TargetFailure::Unavailable { attempts: 7, .. }
        ));
    }

    /// A dead key is not "capacity": nothing is going to free up.
    #[test]
    fn a_pool_of_dead_keys_is_unavailable_not_capacity() {
        let pool = crate::pool::KeyPool::new(
            "p".into(),
            vec!["k".into()],
            crate::config::Strategy::FillFirst,
            1,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
        );
        let key = pool.pick("m", None).expect("one key");
        pool.report_failure(&key, FailKind::Auth, "m");
        assert!(matches!(
            empty_pool_failure(&pool, "m", 1, 2),
            TargetFailure::Unavailable { attempts: 2, .. }
        ));
    }

    /// The specific reason must survive the pool becoming empty because of it.
    #[test]
    fn the_most_specific_failure_reason_wins() {
        let mut last = None;
        keep_specific(
            &mut last,
            TargetFailure::Unavailable {
                attempts: 1,
                wake: None,
            },
        );
        assert!(matches!(last, Some(TargetFailure::Unavailable { .. })));

        let mut last = Some(TargetFailure::BadBody {
            attempts: 1,
            content_type: "text/html".into(),
        });
        keep_specific(
            &mut last,
            TargetFailure::Unavailable {
                attempts: 1,
                wake: None,
            },
        );
        assert_eq!(
            last,
            Some(TargetFailure::BadBody {
                attempts: 1,
                content_type: "text/html".into()
            })
        );
    }

    // ----- exhaustion retry-after -----

    /// Cooldowns are recorded per *upstream* model, so `wake_after` has to be
    /// asked with that name: asking with the client-facing alias found nothing
    /// and dropped the Retry-After from the 503.
    #[test]
    fn a_model_cooldown_is_reported_under_the_upstream_model_only() {
        let cfg: crate::config::ProviderConfig = toml::from_str(
            r#"
            name = "up"
            type = "openai_compat"
            base_url = "http://127.0.0.1:1/v1"
            keys = ["sk-test"]
            models = ["upstream-model"]
            "#,
        )
        .expect("test provider config");
        let provider = crate::providers::Provider::from_config(
            &cfg,
            None,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
            std::time::Duration::from_secs(5),
            1,
        )
        .expect("the provider builds offline");

        let key = provider.pool.pick("upstream-model", None).expect("one key");
        let until_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            + 5_000;
        provider
            .pool
            .report_failure(&key, FailKind::ModelQuota { until_ms }, "upstream-model");

        assert!(
            provider.pool.wake_after("upstream-model").is_some(),
            "the upstream name must report the cooldown"
        );
        assert_eq!(
            provider.pool.wake_after("client-alias"),
            None,
            "the client-facing alias knows nothing about the cooldown — this is \
             exactly why the exhaustion path must pass the upstream model"
        );
    }
}
