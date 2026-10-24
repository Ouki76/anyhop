//! HTTP middleware: authentication for /v1/* (gateway key + client keys) and /api/* (admin).

use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use futures::StreamExt;

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
    // Split on commas: `Upgrade` is a list-valued header, and the realtime
    // handler accepts `websocket` anywhere in it.
    //
    // …but the slot handoff (guard travels with the *request*, the session task
    // takes it) only applies to the one route that really upgrades. Keying it on
    // the header alone was a cap bypass: `Upgrade: websocket` on a normal
    // POST /v1/chat/completions parked the guard in the request extensions, that
    // handler never takes it, and the guard died with the request parts *before*
    // the handler body ran — so `max_concurrent` bounded nothing while the SSE
    // stream kept holding a provider slot.
    let wants_upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
        });
    let upgrade = if wants_upgrade && req.uri().path() == "/v1/realtime" {
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
        // NOTE: a successful client-key request deliberately does *not* clear the
        // per-IP failure budget. Clearing it on success let anyone holding one
        // valid key interleave 1 good request with `burst-1` guesses at other
        // tenants' keys and never be locked out — and with 4-char keys allowed the
        // search space is small enough to walk. Entries expire with the window
        // instead (the master key still clears: it is the operator's credential).
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
        let resp = next.run(req).await;
        if limit > 0 && upgrade == Upgrade::Normal {
            return hold_slot_until_body_ends(resp, ck);
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

/// Hard cap on the distinct source addresses the failed-auth limiter tracks.
///
/// The map is keyed by client IP, whose *breadth* the attacker controls; without a
/// hard cap a spray inside one window grew it without bound.
const MAX_FAIL_ENTRIES: usize = 10_000;

impl AuthFailures {
    /// Count one failure; returns true when this IP is now locked out.
    pub fn note(&mut self, ip: &str, burst: u32, window: std::time::Duration) -> bool {
        let now = std::time::Instant::now();
        // Bound the map for real. `retain` alone only drops *expired* entries, so a
        // spray inside one window (an IPv6 /64 supplies the addresses cheaply) grew
        // it without limit and made every `note` O(n). Sweep first, then evict the
        // oldest quarter if it is still at the cap.
        if self.seen.len() >= MAX_FAIL_ENTRIES {
            self.seen
                .retain(|_, (_, t)| now.duration_since(*t) < window);
            if self.seen.len() >= MAX_FAIL_ENTRIES {
                let mut ages: Vec<(std::time::Instant, String)> = self
                    .seen
                    .iter()
                    .map(|(k, (_, t))| (*t, k.clone()))
                    .collect();
                ages.sort_unstable_by_key(|(t, _)| *t);
                for (_, k) in ages.into_iter().take(MAX_FAIL_ENTRIES / 4) {
                    self.seen.remove(&k);
                }
            }
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

/// Keep a client key's in-flight slot until its **body** is finished.
///
/// The slot used to be parked in the response's extensions. hyper encodes the
/// response head and drops it (extensions included) before it starts polling the
/// body, so a streamed response released the slot at the first byte: a key with
/// `max_concurrent = 1` could hold unlimited SSE streams, each of which also
/// pins an upstream `KeyGuard` — one tenant could exhaust the whole pool. The
/// chat path already holds its provider guard inside the body stream; this does
/// the same for the tenant's slot.
fn hold_slot_until_body_ends(
    resp: Response,
    ck: std::sync::Arc<proxy::ClientKeyRuntime>,
) -> Response {
    let guard = ClientKeyGuard(ck);
    let (parts, body) = resp.into_parts();
    let stream = body.into_data_stream().map(move |chunk| {
        // The closure owns the guard: it is dropped with the last chunk, or with
        // the response if the client disconnects first.
        let _ = &guard;
        chunk
    });
    Response::from_parts(parts, axum::body::Body::from_stream(stream))
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
        // Body unreadable or over the rewrite cap: keep the status *and the
        // headers*. Dropping them lost `Retry-After` / `x-ratelimit-*` /
        // `x-request-id` on relayed upstream errors (>64 KiB text bodies).
        return (parts.status, parts.headers, "").into_response();
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

/// Credential handling: the comparison itself, where the credential may come
/// from, and the failed-attempt budget. All of it is pure enough to test
/// without a socket — except the two request-level guarantees (per-key
/// admission and the upgrade handoff), which need a real router.
#[cfg(test)]
mod auth_tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::http::Request;

    fn req(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    // ----- the comparison -----

    /// `token_eq` is the one function every credential check goes through. If it
    /// ever reported equality for a prefix or for a different-length string, any
    /// key that shares a prefix would authenticate.
    #[test]
    fn credentials_compare_exactly() {
        assert!(token_eq("sk-secret", "sk-secret"));
        assert!(token_eq("", ""), "two empty strings are equal");
        assert!(!token_eq("", "a"), "empty is not a prefix match");
        assert!(!token_eq("sk-secret", "sk-secreT"), "one flipped byte");
        assert!(
            !token_eq("sk-secret", "sk-secre"),
            "a prefix is not a match"
        );
        assert!(
            !token_eq("sk-secret", "sk-secrets"),
            "a longer string is not"
        );
        assert!(
            !token_eq("sk-secret", "sk-secret "),
            "trailing whitespace must not be ignored"
        );
        // Multi-byte secrets are compared byte-wise; this must neither panic nor
        // report a split character as equal.
        assert!(token_eq("ключ-1", "ключ-1"));
        assert!(!token_eq("ключ-1", "ключ-2"));
        assert!(!token_eq("ключ", "ключ-"));
    }

    // ----- where a credential may come from -----

    /// EventSource cannot set headers, so `?key=` is accepted — but only for GET:
    /// a key in a URL ends up in logs and history, which is bad enough for a
    /// long-lived connection and unacceptable for a state-changing request.
    #[test]
    fn a_query_key_only_authenticates_get_requests() {
        assert!(bearer_ok(
            &req("GET", "/v1/models?key=sk-query"),
            "sk-query"
        ));
        assert!(
            !bearer_ok(
                &req("POST", "/v1/chat/completions?key=sk-query"),
                "sk-query"
            ),
            "POST must not authenticate from the query"
        );
        assert!(
            !bearer_ok(&req("GET", "/v1/models?key=sk-wrong"), "sk-query"),
            "a wrong query key is still wrong"
        );
        // The header path works for every method and keeps working alongside it.
        let with_header = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer sk-header")
            .body(Body::empty())
            .expect("request builds");
        assert!(bearer_ok(&with_header, "sk-header"));
        assert!(!bearer_ok(&with_header, "sk-other"));
        // A different scheme is not a bearer token.
        let basic = Request::builder()
            .method("GET")
            .uri("/v1/models")
            .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .expect("request builds");
        assert!(!bearer_ok(&basic, "dXNlcjpwYXNz"));
    }

    /// The dashboard percent-encodes the key before putting it in the EventSource
    /// URL, so a key with reserved characters must authenticate. A malformed
    /// escape must be kept literally rather than truncating or panicking.
    #[test]
    fn percent_escapes_in_the_query_key_are_decoded() {
        assert_eq!(
            extract_bearer(&req("GET", "/api/events?key=a%2Fb%20c%26d")).as_deref(),
            Some("a/b c&d")
        );
        assert_eq!(
            extract_bearer(&req("GET", "/api/events?key=100%zz")).as_deref(),
            Some("100%zz"),
            "a malformed escape is not silently dropped"
        );
        // `key=` may follow other parameters, and other parameters are ignored.
        assert_eq!(
            extract_bearer(&req("GET", "/api/events?since=4&key=sk-x")).as_deref(),
            Some("sk-x")
        );
        // No credential at all.
        assert_eq!(extract_bearer(&req("GET", "/api/events")), None);
    }

    /// The lockout is a counter with a window. A lapsed window must hand out a
    /// fresh budget (otherwise one bad password bans the address forever).
    #[test]
    fn a_lapsed_window_starts_a_fresh_budget() {
        let lapsed = std::time::Duration::from_nanos(1);
        let mut fails = AuthFailures::default();
        assert!(!fails.note("198.51.100.1", 2, lapsed), "first failure");
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(
            !fails.note("198.51.100.1", 2, lapsed),
            "a lapsed window must restart the count, not lock the address out"
        );

        // Inside one window the budget still trips, and only for that address.
        let window = std::time::Duration::from_secs(60);
        let mut fails = AuthFailures::default();
        assert!(!fails.note("198.51.100.2", 2, window));
        assert!(fails.note("198.51.100.2", 2, window));
        assert!(!fails.note("198.51.100.3", 2, window));
        // A zero-length window is meaningless but must not panic or report 0.
        assert!(fails.retry_after_secs("198.51.100.9", std::time::Duration::ZERO) >= 1);
    }

    /// The socket peer is authoritative; X-Forwarded-For is the fallback for
    /// setups where a reverse proxy terminates the connection. Without either
    /// there is still a bucket ("unknown") so the guard cannot be skipped.
    #[test]
    fn the_peer_address_wins_over_a_forwarding_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        let mut ext = axum::http::Extensions::new();
        assert_eq!(ip_of(&headers, &ext), "203.0.113.9", "the first hop");
        ext.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            4242,
        ))));
        assert_eq!(
            ip_of(&headers, &ext),
            "127.0.0.1",
            "a forwarded header cannot override the real peer"
        );
        assert_eq!(
            ip_of(
                &axum::http::HeaderMap::new(),
                &axum::http::Extensions::new()
            ),
            "unknown"
        );
    }

    // ----- per-key admission and the upgrade handoff (needs a live router) -----

    /// One request that the probe route holds open until the test releases it.
    #[derive(Clone)]
    struct Gate(std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>);

    async fn probe(
        axum::extract::Extension(gate): axum::extract::Extension<Gate>,
        req: axum::extract::Request,
    ) -> String {
        let handed_over = req.extensions().get::<ClientKeyGuard>().is_some();
        // Take the receiver out under a short lock, then await it *outside* the
        // guard: holding the mutex across the await would serialise the probe and
        // turn "the cap is missing" into a hang instead of a failed assertion.
        let held = { gate.0.lock().await.take() };
        if let Some(rx) = held {
            let _ = rx.await;
        }
        if handed_over {
            "handoff".to_string()
        } else {
            "guard-on-response".to_string()
        }
    }

    fn router(state: std::sync::Arc<proxy::AppState>, gate: Gate) -> axum::Router {
        use axum::routing::get;
        axum::Router::new()
            .route("/probe", get(probe))
            // The handoff is only wired for the route that really upgrades.
            .route("/v1/realtime", get(probe))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_api_key,
            ))
            .layer(axum::extract::Extension(gate))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                security_headers,
            ))
            .with_state(state)
    }

    async fn serve(app: axum::Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        for _ in 0..300 {
            if cond() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    fn key_runtime(max_concurrent: u32) -> std::sync::Arc<proxy::ClientKeyRuntime> {
        std::sync::Arc::new(proxy::ClientKeyRuntime::new_with(
            crate::config::ClientKeyConfig {
                key: "ck-tenant".to_string(),
                name: Some("tenant".to_string()),
                models: Vec::new(),
                created_at: None,
                rpm: None,
                burst: None,
                max_concurrent: Some(max_concurrent),
            },
            &crate::config::RateLimitConfig::default(),
        ))
    }

    fn state_with_key(
        rt: std::sync::Arc<proxy::ClientKeyRuntime>,
    ) -> std::sync::Arc<proxy::AppState> {
        let path = crate::api::server::test_support::temp_config(
            crate::api::server::test_support::MINIMAL,
        );
        let st = crate::api::server::test_support::state(&path);
        st.client_keys
            .write()
            .unwrap()
            .insert("ck-tenant".to_string(), rt);
        st
    }

    /// The per-key in-flight cap is what stops one tenant from eating the whole
    /// gateway. It must be enforced during the handler (not only per response),
    /// count rejections, and release the slot when the request really ends —
    /// including for a request whose body the client is still reading.
    #[tokio::test]
    async fn a_client_keys_concurrency_cap_holds_until_the_request_ends() {
        let rt = key_runtime(1);
        let st = state_with_key(rt.clone());
        let (release, held) = tokio::sync::oneshot::channel();
        let gate = Gate(std::sync::Arc::new(tokio::sync::Mutex::new(Some(held))));
        let addr = serve(router(st, gate)).await;
        let url = format!("http://{addr}/probe");
        let client = reqwest::Client::new();

        // The first request takes the only slot and stays inside the handler.
        let first = {
            let client = client.clone();
            let url = url.clone();
            tokio::spawn(async move { client.get(url).bearer_auth("ck-tenant").send().await })
        };
        wait_until("the first request to take its slot", || {
            rt.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 1
        })
        .await;

        let second = client
            .get(&url)
            .bearer_auth("ck-tenant")
            .send()
            .await
            .expect("second request");
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a second concurrent request must not be admitted"
        );
        assert_eq!(
            rt.saturated.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the rejection must be counted for /metrics"
        );
        let body: serde_json::Value = second.json().await.expect("json envelope");
        assert_eq!(body["error"]["type"], "rate_limit_exceeded", "{body}");

        release.send(()).expect("release the first request");
        let first = first.await.expect("join").expect("first response");
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.text().await.expect("body"), "guard-on-response");

        // The slot follows the response, so it is back once the first request is
        // done — a leaked permit would 429 this key forever.
        wait_until("the slot to come back", || {
            rt.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 0
        })
        .await;
        let third = client
            .get(&url)
            .bearer_auth("ck-tenant")
            .send()
            .await
            .expect("third request");
        assert_eq!(third.status(), StatusCode::OK, "the slot must be reusable");
    }

    /// A streamed body must hold the slot for as long as the client is reading.
    ///
    /// The permit used to live in the response extensions; hyper encodes the head
    /// and drops them before it starts polling the body, so a tenant with
    /// `max_concurrent = 1` could open unlimited SSE streams (each also pinning a
    /// provider key). This test keeps the body undrained and asserts the slot is
    /// still taken.
    #[tokio::test]
    async fn a_streamed_body_holds_the_slot_until_it_is_dropped() {
        let rt = key_runtime(1);
        let st = state_with_key(rt.clone());
        let addr = stream_router(st).await;
        let url = format!("http://{addr}/stream");
        let client = reqwest::Client::new();

        let resp = client
            .get(&url)
            .bearer_auth("ck-tenant")
            .send()
            .await
            .expect("streamed response head");
        assert_eq!(resp.status(), StatusCode::OK);
        // The head is in, the body is not: the slot must still be held.
        wait_until("the streaming request to hold its slot", || {
            rt.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 1
        })
        .await;

        let second = client
            .get(&url)
            .bearer_auth("ck-tenant")
            .send()
            .await
            .expect("second request");
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a live stream must keep the only slot busy"
        );

        drop(resp);
        wait_until("the slot to come back when the stream is dropped", || {
            rt.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 0
        })
        .await;
        let third = client
            .get(&url)
            .bearer_auth("ck-tenant")
            .send()
            .await
            .expect("third request");
        assert_eq!(third.status(), StatusCode::OK, "the slot must be reusable");
    }

    /// A route answering with an endless stream of tiny chunks.
    async fn endless() -> axum::response::Response {
        // One chunk, then a stream that never ends: the body stays "in progress"
        // for as long as the test keeps the response alive.
        let stream = futures::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from_static(
            b"data: x\n\n",
        ))])
        .chain(futures::stream::pending());
        axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(axum::body::Body::from_stream(stream))
            .expect("response builds")
    }

    async fn stream_router(state: std::sync::Arc<proxy::AppState>) -> std::net::SocketAddr {
        use axum::routing::get;
        let app = axum::Router::new()
            .route("/stream", get(endless))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_api_key,
            ))
            .with_state(state);
        serve(app).await
    }

    /// An upgrade outlives its response, so its slot cannot ride on the response:
    /// the middleware parks the guard in the request extensions and the handler
    /// that owns the session takes it. (A normal request gets the guard on the
    /// response instead — see the test above.)
    #[tokio::test]
    async fn a_websocket_upgrade_receives_its_slot_in_the_request() {
        let rt = key_runtime(1);
        let st = state_with_key(rt.clone());
        let gate = Gate(std::sync::Arc::new(tokio::sync::Mutex::new(None)));
        let addr = serve(router(st, gate)).await;

        let resp = reqwest::Client::new()
            .get(format!("http://{addr}/v1/realtime"))
            .bearer_auth("ck-tenant")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .send()
            .await
            .expect("upgrade probe");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.text().await.expect("body"),
            "handoff",
            "a websocket request must receive the slot in its extensions"
        );
        wait_until("the upgrade slot to be released", || {
            rt.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 0
        })
        .await;
    }

    /// A fake `Upgrade` header on a normal route must NOT hand the slot to the
    /// request.
    ///
    /// The handoff exists because a 101 leaves the response behind; on any other
    /// route nothing removes the guard from the request extensions, so it died with
    /// the request parts *before* the handler ran — `max_concurrent` bounded nothing
    /// while the stream went on holding a provider slot.
    #[tokio::test]
    async fn an_upgrade_header_on_a_normal_route_does_not_skip_the_slot() {
        let rt = key_runtime(1);
        let st = state_with_key(rt.clone());
        let (release, held) = tokio::sync::oneshot::channel();
        let gate = Gate(std::sync::Arc::new(tokio::sync::Mutex::new(Some(held))));
        let addr = serve(router(st, gate)).await;

        let client = reqwest::Client::new();
        let url = format!("http://{addr}/probe");
        let first = {
            let client = client.clone();
            let url = url.clone();
            tokio::spawn(async move {
                client
                    .get(url)
                    .bearer_auth("ck-tenant")
                    .header("connection", "upgrade")
                    .header("upgrade", "websocket")
                    .send()
                    .await
            })
        };
        wait_until("the fake-upgrade request to take its slot", || {
            rt.in_flight.load(std::sync::atomic::Ordering::Relaxed) == 1
        })
        .await;
        let second = client
            .get(&url)
            .bearer_auth("ck-tenant")
            .send()
            .await
            .expect("second request");
        assert_eq!(
            second.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the header must not release the slot early"
        );
        release.send(()).expect("release");
        let first = first.await.expect("join").expect("response");
        assert_eq!(
            first.text().await.expect("body"),
            "guard-on-response",
            "a normal route must keep the guard on the response"
        );
    }

    /// Hardening headers are applied by the outermost layer, so they are present
    /// on error responses too; HSTS is only sent where it can be honoured.
    #[tokio::test]
    async fn hardening_headers_cover_401s_and_hsts_needs_tls() {
        let st = state_with_key(key_runtime(0));
        let addr = serve(router(
            st.clone(),
            Gate(std::sync::Arc::new(tokio::sync::Mutex::new(None))),
        ))
        .await;
        let client = reqwest::Client::new();

        let unauth = client
            .get(format!("http://{addr}/probe"))
            .send()
            .await
            .expect("request");
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
        let h = unauth.headers();
        assert_eq!(h.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");
        assert_eq!(h.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(h.get(header::REFERRER_POLICY).unwrap(), "no-referrer");
        assert_eq!(h.get(header::WWW_AUTHENTICATE).unwrap(), "Bearer");
        assert!(
            !h.contains_key(header::STRICT_TRANSPORT_SECURITY),
            "HSTS on plain HTTP is a lie to the browser"
        );

        // Behind a TLS-terminating proxy the browser is on HTTPS, so HSTS applies.
        let proxied = client
            .get(format!("http://{addr}/probe"))
            .header("x-forwarded-proto", "https")
            .send()
            .await
            .expect("request");
        assert!(
            proxied
                .headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .is_some(),
            "X-Forwarded-Proto: https must turn HSTS on"
        );

        // ... and so does our own listener when it serves TLS.
        st.tls_enabled_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let own_tls = client
            .get(format!("http://{addr}/probe"))
            .send()
            .await
            .expect("request");
        assert!(
            own_tls
                .headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .is_some(),
            "a TLS listener advertises HSTS without any header from a proxy"
        );
    }
}
