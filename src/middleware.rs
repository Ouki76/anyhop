//! HTTP middleware: authentication for /v1/* (gateway key + client keys) and /api/* (admin).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::proxy;

/// Constant-time token comparison (auth checks shouldn't leak length-prefix
/// timing via early-exit string equality).
fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decode `%XX` escapes in a query value.
///
/// The dashboard builds the EventSource URL with `encodeURIComponent`, so any
/// key containing characters outside the unreserved set arrives escaped. Without
/// this, a custom key like `my key&more` could never authenticate.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `?key=` from the URL — only for GET requests (EventSource can't set headers).
/// Keys in URLs leak via logs/history, so POST never takes this path.
fn query_key(req: &Request) -> Option<String> {
    if req.method() != axum::http::Method::GET {
        return None;
    }
    req.uri()
        .query()
        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("key=")))
        .map(percent_decode)
}

fn bearer_ok(req: &Request, expected: &str) -> bool {
    let header_ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| token_eq(t, expected))
        .unwrap_or(false);
    // EventSource cannot send headers — allow ?key= on GET requests
    let query_ok = query_key(req)
        .map(|k| token_eq(&k, expected))
        .unwrap_or(false);
    header_ok || query_ok
}

fn extract_bearer(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .or_else(|| query_key(req))
}

/// Gateway auth: /v1/* requires Bearer <api_key> or a valid client key when configured.
pub async fn require_api_key(
    State(state): State<Arc<proxy::AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let rt = state.rt();
    let token = extract_bearer(&req);
    let ip = client_ip(&req);

    // Locked out after repeated failures? Refuse before touching the keys.
    {
        let burst = rt.auth_fail_burst;
        let window = rt.auth_fail_window;
        let mut fails = state.auth_fails.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(retry) = fails.blocked(&ip, burst, window) {
            let mut resp = proxy::error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed authentication attempts from this address",
                "rate_limit_exceeded",
            );
            if let Ok(v) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return resp;
        }
    }

    let (auth_needed, client_key_info) = {
        // Poisoning-recoverable read: a panicking writer must not wedge all /v1 traffic.
        let client_keys = state.client_keys.read().unwrap_or_else(|e| e.into_inner());
        let auth_needed = rt.api_key.is_some() || !client_keys.is_empty();
        let ck = token.as_ref().and_then(|t| client_keys.get(t).cloned());
        (auth_needed, ck)
    };

    if !auth_needed {
        req.extensions_mut().insert(proxy::KeyPermissions {
            allowed_models: None,
            key_name: None,
        });
        return next.run(req).await;
    }

    let Some(t) = token else {
        return proxy::error_response(
            StatusCode::UNAUTHORIZED,
            "missing gateway API key",
            "authentication_error",
        );
    };

    if let Some(expected) = &rt.api_key
        && token_eq(&t, expected)
    {
        state
            .auth_fails
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear(&ip);
        req.extensions_mut().insert(proxy::KeyPermissions {
            allowed_models: None,
            key_name: Some("master".into()),
        });
        return next.run(req).await;
    }

    if let Some(ck) = client_key_info {
        // Per-key rate limit. Enforced after authentication (so an unauthorised
        // caller cannot probe limits) and before the request touches an upstream.
        if let Some(limiter) = &ck.limiter
            && let Err(retry_after) = limiter.try_take()
        {
            ck.limited
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let secs = retry_after.as_secs().max(1);
            tracing::debug!(
                key = %ck.cfg.name.as_deref().unwrap_or("client key"),
                "rate limited, retry in {secs}s"
            );
            let mut resp = proxy::error_response(
                StatusCode::TOO_MANY_REQUESTS,
                format!("rate limit exceeded for this API key (retry in {secs}s)"),
                "rate_limit_exceeded",
            );
            if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return resp;
        }
        state
            .auth_fails
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear(&ip);
        // Concurrency cap: the key's own limit, else the server-wide default.
        let limit = if ck.max_concurrent > 0 {
            ck.max_concurrent
        } else {
            rt.client_key_max_concurrent
        };
        if limit > 0 {
            let cur = ck
                .in_flight
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if cur >= limit {
                ck.in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                ck.saturated
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return proxy::error_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("too many concurrent requests for this API key (limit {limit})"),
                    "rate_limit_exceeded",
                );
            }
        }
        let allowed = if ck.cfg.models.is_empty() {
            None
        } else {
            Some(ck.cfg.models.clone())
        };
        req.extensions_mut().insert(proxy::KeyPermissions {
            allowed_models: allowed,
            key_name: ck.cfg.name.clone().or_else(|| Some(ck.cfg.key.clone())),
        });
        let mut resp = next.run(req).await;
        if limit > 0 {
            // Dropped with the response — i.e. after a streamed body completes.
            resp.extensions_mut().insert(ClientKeyGuard(ck));
        }
        return resp;
    }

    {
        let burst = rt.auth_fail_burst;
        let window = rt.auth_fail_window;
        state
            .auth_fails
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .note(&ip, burst, window);
    }
    proxy::error_response(
        StatusCode::UNAUTHORIZED,
        "invalid gateway API key",
        "authentication_error",
    )
}

/// Admin auth: `/api/*` requires `Bearer <admin_key>` (or `api_key`) when set.
///
/// `/dashboard` itself is deliberately NOT behind this: those are static,
/// unprivileged assets (an empty SPA that prompts for the key and then calls
/// `/api/*`), so auth here would only replace the login modal with a 401 page.
pub async fn require_admin_key(
    State(state): State<Arc<proxy::AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let rt = state.rt();
    let ip = client_ip(&req);
    let burst = rt.auth_fail_burst;
    let window = rt.auth_fail_window;
    // Same lockout as /v1: the admin surface is the more valuable target.
    {
        let mut fails = state.auth_fails.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(retry) = fails.blocked(&ip, burst, window) {
            let mut resp = proxy::error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed authentication attempts from this address",
                "rate_limit_exceeded",
            );
            if let Ok(v) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return resp;
        }
    }
    if let Some(expected) = rt.admin_key.or(rt.api_key) {
        if !bearer_ok(&req, &expected) {
            state
                .auth_fails
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .note(&ip, burst, window);
            return proxy::error_response(
                StatusCode::UNAUTHORIZED,
                "invalid or missing admin key",
                "authentication_error",
            );
        }
        state
            .auth_fails
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear(&ip);
    }
    next.run(req).await
}

/// Response hardening applied to every route.
///
/// The admin UI keeps its key in `localStorage`, so an injected script would own
/// Failed-auth counter per client IP.
///
/// A wrong key costs one comparison; without a limit an attacker can try
/// millions per minute. After `burst` failures inside `window`, further attempts
/// from that IP get 429 before the key is even compared.
#[derive(Default)]
pub struct AuthFailures {
    seen: std::collections::HashMap<String, (u32, std::time::Instant)>,
}

impl AuthFailures {
    /// Count one failure; returns true when this IP is now locked out.
    pub fn note(&mut self, ip: &str, burst: u32, window: std::time::Duration) -> bool {
        let now = std::time::Instant::now();
        // Keep the map from growing without bound when someone sprays spoofed IPs.
        if self.seen.len() > 10_000 {
            self.seen
                .retain(|_, (_, t)| now.duration_since(*t) < window);
        }
        let e = self.seen.entry(ip.to_string()).or_insert((0, now));
        if now.duration_since(e.1) > window {
            *e = (0, now);
        }
        e.0 = e.0.saturating_add(1);
        e.0 >= burst
    }

    /// Whether this IP is currently locked out (without counting an attempt).
    pub fn blocked(&mut self, ip: &str, burst: u32, window: std::time::Duration) -> Option<u64> {
        let now = std::time::Instant::now();
        let (count, first) = self.seen.get(ip).copied()?;
        let elapsed = now.duration_since(first);
        if elapsed > window {
            self.seen.remove(ip);
            return None;
        }
        if count >= burst {
            return Some((window - elapsed).as_secs().max(1));
        }
        None
    }

    /// Clear the counter for an IP after a successful authentication.
    pub fn clear(&mut self, ip: &str) {
        self.seen.remove(ip);
    }
}

/// Decrements the key's in-flight counter when the response (including a streamed
/// body) is dropped, so the cap tracks real concurrency rather than handler time.
#[derive(Clone)]
pub struct ClientKeyGuard(pub std::sync::Arc<proxy::ClientKeyRuntime>);

impl Drop for ClientKeyGuard {
    fn drop(&mut self) {
        self.0
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Where the request came from: the socket peer, else the first X-Forwarded-For
/// hop (reverse proxies), else "unknown" so the guard still has a bucket.
fn client_ip(req: &Request) -> String {
    if let Some(axum::extract::ConnectInfo(addr)) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return addr.ip().to_string();
    }
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Record request latency for `/metrics` (histograms, not just counters).
pub async fn record_metrics(req: Request, next: Next) -> Response {
    let started = std::time::Instant::now();
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let resp = next.run(req).await;
    crate::api::histograms::record(
        &crate::api::histograms::route_label(&path),
        &method,
        resp.status().as_u16(),
        started.elapsed().as_secs_f64(),
    );
    resp
}

/// Every API error should look the same to a client. Axum's built-in rejections
/// (bad JSON, missing field, wrong method) answer with `text/plain`, which breaks
/// clients that parse the `{"error": {...}}` envelope everywhere else.
///
/// Rewrites non-JSON error bodies under `/api/*` and `/v1/*` into that envelope;
/// successful responses and streams pass through untouched.
pub async fn json_errors(req: Request, next: Next) -> Response {
    use axum::response::IntoResponse as _;

    let path = req.uri().path().to_string();
    let resp = next.run(req).await;
    let is_api = path.starts_with("/api/") || path.starts_with("/v1/");
    if !is_api || !(resp.status().is_client_error() || resp.status().is_server_error()) {
        return resp;
    }
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if is_json {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, 64 * 1024).await else {
        // Body unreadable: keep the status, do not manufacture a payload.
        return (parts.status, "").into_response();
    };
    let message = String::from_utf8_lossy(&bytes).trim().to_string();
    let message = if message.is_empty() {
        parts
            .status
            .canonical_reason()
            .unwrap_or("error")
            .to_string()
    } else {
        message
    };
    let body = serde_json::json!({
        "error": {
            "code": parts.status.as_u16(),
            "message": message,
            "type": error_type(parts.status),
        }
    });
    let keep: Vec<(axum::http::HeaderName, axum::http::HeaderValue)> = parts
        .headers
        .iter()
        .filter(|(k, _)| *k != header::CONTENT_TYPE && *k != header::CONTENT_LENGTH)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut out = (parts.status, axum::Json(body)).into_response();
    for (k, v) in keep {
        out.headers_mut().insert(k, v);
    }
    out
}

/// OpenAI-style error type for an HTTP status.
pub fn error_type(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 | 422 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        405 => "method_not_allowed",
        408 => "timeout_error",
        409 => "conflict_error",
        413 => "payload_too_large",
        429 => "rate_limit_error",
        500..=599 => "api_error",
        _ => "invalid_request_error",
    }
}

/// the whole gateway. These headers are cheap and stop the classic vectors:
/// MIME sniffing (`nosniff`), clickjacking/framing (`DENY`), and leaking the
/// `?key=` query to third parties via the `Referer` header (`no-referrer`).
/// The dashboard document additionally gets a strict CSP (see `dashboard::csp`).
pub async fn security_headers(
    State(state): State<Arc<proxy::AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // Our own listener serving TLS counts too — nobody sets X-Forwarded-Proto then.
    let served_over_tls = state.rt().tls_enabled;
    let req_is_https = served_over_tls || {
        // A TLS-terminating proxy tells us via X-Forwarded-Proto.
        req.headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("https"))
    };
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    // HSTS only where it means something: over our own TLS, or when a proxy says
    // the browser is already on HTTPS. Sending it on plain HTTP is ignored by
    // browsers but confuses operators reading curl output.
    if req_is_https {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    resp
}

#[cfg(test)]
mod json_error_tests {
    use super::*;

    #[test]
    fn error_types_match_the_openai_vocabulary() {
        assert_eq!(error_type(StatusCode::BAD_REQUEST), "invalid_request_error");
        assert_eq!(
            error_type(StatusCode::UNPROCESSABLE_ENTITY),
            "invalid_request_error"
        );
        assert_eq!(error_type(StatusCode::UNAUTHORIZED), "authentication_error");
        assert_eq!(error_type(StatusCode::FORBIDDEN), "permission_error");
        assert_eq!(error_type(StatusCode::NOT_FOUND), "not_found_error");
        assert_eq!(
            error_type(StatusCode::TOO_MANY_REQUESTS),
            "rate_limit_error"
        );
        assert_eq!(error_type(StatusCode::BAD_GATEWAY), "api_error");
        assert_eq!(error_type(StatusCode::INTERNAL_SERVER_ERROR), "api_error");
    }
}
