//! HTTP middleware: authentication for /v1/* (gateway key + client keys) and /api/* (admin).

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::proxy;

/// Constant-time token comparison (auth checks shouldn't leak length-prefix
/// timing via early-exit string equality).
///
/// `pub(crate)` because the OAuth callback compares its `state` with it too: a
/// byte-by-byte early exit would leak the prefix of a live state token.
pub(crate) fn token_eq(a: &str, b: &str) -> bool {
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

    // An upgrade is served by a task that outlives the response, so the
    // concurrency slot must follow the request rather than the response.
    let upgrade = if req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
    {
        Upgrade::WebSocket
    } else {
        Upgrade::Normal
    };

    if let Some(ck) = client_key_info {
        // Per-key rate limit. Enforced after authentication (so an unauthorised
        // caller cannot probe limits) and before the request touches an upstream.
        // `shared` is the configured backend (`local` bucket or Redis, so N
        // instances share one budget); the per-process bucket stays as the
        // fallback when no shared limiter could be built.
        let limited: Option<u64> = match (&ck.shared, &ck.limiter) {
            (Some(shared), _) => shared.try_acquire().await.err(),
            (None, Some(local)) => local.try_take().err().map(retry_after_secs_of),
            (None, None) => None,
        };
        if let Some(secs) = limited {
            ck.limited
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            key_name: Some(proxy::client_key_label(&ck.cfg.key, ck.cfg.name.as_deref())),
        });
        // A websocket upgrade returns its 101 immediately and then lives in a
        // separate task, so for those the slot travels with the *request* and is
        // taken by the handler that owns the session.
        if limit > 0 && upgrade == Upgrade::WebSocket {
            req.extensions_mut().insert(ClientKeyGuard(ck.clone()));
        }
        let mut resp = next.run(req).await;
        if limit > 0 && upgrade == Upgrade::Normal {
            // Dropped with the response — i.e. after a streamed body completes.
            resp.extensions_mut().insert(ClientKeyGuard(ck));
        }
        return resp;
    }

    // The lockout is a *response to a failed credential*, never a pre-filter: a
    // pre-check would let anyone holding a socket lock every legitimate caller
    // out (behind a reverse proxy all of them share the proxy's address). The
    // cost of the check is one constant-time comparison, which is cheap enough
    // that an attacker gains nothing by hammering it.
    if let Some(resp) = gate_failed_credential(&state, &ip) {
        return resp;
    }
    proxy::error_response(
        StatusCode::UNAUTHORIZED,
        "invalid gateway API key",
        "authentication_error",
    )
}

/// Record one failed authentication and report whether the address is now over
/// its budget. Totals ride the same counter the admin path uses.
fn failed_attempt(state: &Arc<proxy::AppState>, ip: &str) -> bool {
    let (burst, window) = {
        let rt = state.rt();
        (rt.auth_fail_burst, rt.auth_fail_window)
    };
    state
        .auth_fails
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .note(ip, burst, window)
}

/// The shared "a credential was wrong" gate: count the failure and hand back the
/// 429 to send once the address has used up its budget.
///
/// Every surface that compares a secret uses this — the gateway and admin
/// middlewares below, and the OAuth callback (whose `state` is a bearer secret in
/// a URL an attacker can sweep).
pub(crate) fn gate_failed_credential(state: &Arc<proxy::AppState>, ip: &str) -> Option<Response> {
    if failed_attempt(state, ip) {
        Some(too_many_failures(state, ip))
    } else {
        None
    }
}

/// Forget an address's failures after a successful authentication.
pub(crate) fn clear_failures(state: &Arc<proxy::AppState>, ip: &str) {
    state
        .auth_fails
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear(ip);
}

/// 429 for an address that is over its failure budget.
///
/// `Retry-After` is the *remaining* window: a static value shorter than the
/// window makes an obedient client retry straight back into another 429 (the
/// block lasts up to `auth_fail_window_secs`, default 60).
fn too_many_failures(state: &Arc<proxy::AppState>, ip: &str) -> Response {
    let secs = {
        let window = state.rt().auth_fail_window;
        state
            .auth_fails
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retry_after_secs(ip, window)
    };
    let mut resp = proxy::error_response(
        StatusCode::TOO_MANY_REQUESTS,
        format!("too many failed authentication attempts from this address (retry in {secs}s)"),
        "rate_limit_exceeded",
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
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
    if let Some(expected) = rt.admin_key.or(rt.api_key) {
        if !bearer_ok(&req, &expected) {
            // Same rule as /v1: count the failure, throttle only the failures.
            if let Some(resp) = gate_failed_credential(&state, &ip) {
                return resp;
            }
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

/// RFC 7235 requires a `WWW-Authenticate` challenge on every 401, and the
/// dashboard/CLI clients use it to tell "wrong key" from "no key at all".
///
/// Applied here, in the outermost layer, so it also covers the 401s that
/// `proxy::error_response` produces all over the gateway — that helper sets no
/// header of its own, and touching it is another file's change; the challenge
/// belongs on the response either way.
fn add_bearer_challenge(resp: &mut Response) {
    if resp.status() != StatusCode::UNAUTHORIZED {
        return;
    }
    if resp.headers().contains_key(header::WWW_AUTHENTICATE) {
        return;
    }
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
}

/// Response hardening applied to every route.
///
/// The admin UI keeps its key in `localStorage`, so an injected script would own
/// Seconds to advertise in `Retry-After` for a wait of `d`.
///
/// Rounds **up** and never returns 0: a client that sleeps exactly the advertised
/// time must find the limit cleared, and `Duration::as_secs()` truncation makes
/// 2.4 s look like 2 s — retry at 2 s, get 429 again.
pub fn retry_after_secs_of(d: std::time::Duration) -> u64 {
    let ms = d.as_millis();
    u64::try_from(ms.div_ceil(1000)).unwrap_or(u64::MAX).max(1)
}

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

    /// Clear the counter for an IP after a successful authentication.
    pub fn clear(&mut self, ip: &str) {
        self.seen.remove(ip);
    }

    /// Seconds left in the current lockout window for `ip`, rounded up.
    ///
    /// `Retry-After` used to be a hard-coded 5 s while the block lasts the whole
    /// `auth_fail_window_secs`: a client that obeyed the header retried into
    /// another ~55 s of 429s. 1 is the floor — "retry now" would be a lie.
    pub fn retry_after_secs(&self, ip: &str, window: std::time::Duration) -> u64 {
        let Some((_, first)) = self.seen.get(ip) else {
            return retry_after_secs_of(window);
        };
        let left = window.saturating_sub(std::time::Instant::now().duration_since(*first));
        ((left.as_millis() as u64).div_ceil(1000)).max(1)
    }
}

/// Whether the request asks for a connection upgrade (websocket) or is a plain
/// HTTP request. Upgrade sessions outlive their response, so their concurrency
/// slot is handed over differently.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Upgrade {
    Normal,
    WebSocket,
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
fn ip_of(headers: &axum::http::HeaderMap, extensions: &axum::http::Extensions) -> String {
    if let Some(axum::extract::ConnectInfo(addr)) =
        extensions.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return addr.ip().to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn client_ip(req: &Request) -> String {
    ip_of(req.headers(), req.extensions())
}

/// The same address as [`client_ip`], as an extractor, for handlers whose
/// signature has no `Request` (the OAuth callback needs the peer address for the
/// shared failure limiter).
///
/// Never rejects: without `ConnectInfo` (and without a forwarding header) the
/// bucket is "unknown", exactly like the middlewares.
pub struct ClientIp(pub String);

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(ip_of(&parts.headers, &parts.extensions)))
    }
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

/// Should `json_errors` replace this response body with the JSON envelope?
///
/// Only error responses under `/api/*` \/ `/v1/*` whose body is not already JSON
/// and not an HTML page: the OAuth callback answers the *browser* with
/// `text/html`, and rewriting that into JSON turned "you can close this tab" into
/// a wall of JSON for the one flow that is meant to be read by a human.
fn should_rewrite_json_errors(path: &str, status: StatusCode, content_type: Option<&str>) -> bool {
    let is_api = path.starts_with("/api/") || path.starts_with("/v1/");
    if !is_api || !(status.is_client_error() || status.is_server_error()) {
        return false;
    }
    match content_type {
        Some(v) if v.starts_with("application/json") => false,
        Some(v) if v.starts_with("text/html") => false,
        _ => true,
    }
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
    if !should_rewrite_json_errors(
        &path,
        resp.status(),
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
    ) {
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
    let served_over_tls = state
        .tls_enabled_flag
        .load(std::sync::atomic::Ordering::Relaxed);
    let req_is_https = served_over_tls || {
        // A TLS-terminating proxy tells us via X-Forwarded-Proto.
        req.headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("https"))
    };
    let mut resp = next.run(req).await;
    add_bearer_challenge(&mut resp);
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

    /// The lockout used to answer a static `Retry-After: 5` while the block
    /// lasts `auth_fail_window_secs` (60 by default): a client that obeyed it
    /// walked straight back into another 55 s of 429s.
    #[test]
    fn retry_after_reports_the_rest_of_the_window() {
        let window = std::time::Duration::from_secs(60);
        let mut fails = AuthFailures::default();
        assert!(!fails.note("10.0.0.1", 2, window), "first failure");
        assert!(fails.note("10.0.0.1", 2, window), "second locks out");
        let secs = fails.retry_after_secs("10.0.0.1", window);
        assert!(
            (59..=60).contains(&secs),
            "Retry-After must be the remaining window, got {secs}"
        );
        // A different address is not locked out and may retry at once.
        assert_eq!(fails.retry_after_secs("10.0.0.2", window), 60);
        // Clearing (a successful auth) resets it to the full window.
        fails.clear("10.0.0.1");
        assert_eq!(fails.retry_after_secs("10.0.0.1", window), 60);
    }

    /// The 429 a locked-out client actually receives must carry the *remaining*
    /// window, not a static value that sends it straight back into a 429.
    #[tokio::test]
    async fn the_lockout_response_reports_the_remaining_window() {
        let st = crate::api::server::test_support::state(std::path::Path::new(
            "/tmp/anyhop-middleware-test-not-a-file.toml",
        ));
        let ip = "198.51.100.7";
        // `test_support` sets burst = 3.
        assert!(gate_failed_credential(&st, ip).is_none(), "1st failure");
        assert!(gate_failed_credential(&st, ip).is_none(), "2nd failure");
        let resp = gate_failed_credential(&st, ip).expect("the 3rd locks out");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let secs: u64 = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("Retry-After");
        assert!(
            (55..=60).contains(&secs),
            "Retry-After must be the remaining window (60 s), got {secs}"
        );
        // The envelope is unchanged: clients parse it.
        let bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"]["type"], "rate_limit_exceeded", "{v}");
        assert_eq!(v["error"]["code"], 429, "{v}");
    }

    /// The OAuth callback answers the browser with an HTML page. `json_errors`
    /// used to rewrite it into the JSON envelope because it only exempted
    /// `application/json`.
    #[test]
    fn html_error_pages_are_left_alone() {
        let s = StatusCode::BAD_REQUEST;
        assert!(!should_rewrite_json_errors(
            "/api/auth/callback",
            s,
            Some("text/html; charset=utf-8")
        ));
        assert!(!should_rewrite_json_errors(
            "/api/providers",
            s,
            Some("application/json")
        ));
        assert!(
            should_rewrite_json_errors("/api/providers", s, Some("text/plain; charset=utf-8")),
            "axum's plain-text rejections still become the envelope"
        );
        assert!(
            should_rewrite_json_errors("/api/providers", s, None),
            "a body with no content type is still rewritten"
        );
        // Successes and non-API paths are never touched.
        assert!(!should_rewrite_json_errors(
            "/api/providers",
            StatusCode::OK,
            Some("text/plain")
        ));
        assert!(!should_rewrite_json_errors(
            "/dashboard",
            s,
            Some("text/plain")
        ));
    }

    /// RFC 7235: a 401 must carry a challenge. The gateway's 401s all come from
    /// `proxy::error_response`, which sets no header.
    #[test]
    fn unauthorized_responses_get_a_bearer_challenge() {
        let mut resp = proxy::error_response(
            StatusCode::UNAUTHORIZED,
            "missing gateway API key",
            "authentication_error",
        );
        add_bearer_challenge(&mut resp);
        assert_eq!(
            resp.headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer")
        );

        // A handler that sets its own challenge keeps it.
        let mut resp = proxy::error_response(StatusCode::UNAUTHORIZED, "x", "authentication_error");
        resp.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Basic realm=\"x\""),
        );
        add_bearer_challenge(&mut resp);
        assert_eq!(
            resp.headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Basic realm=\"x\"")
        );

        // Other statuses are untouched.
        let mut resp = proxy::error_response(StatusCode::NOT_FOUND, "x", "not_found_error");
        add_bearer_challenge(&mut resp);
        assert!(!resp.headers().contains_key(header::WWW_AUTHENTICATE));
    }

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
