//! `GET /v1/realtime` — WebSocket pass-through to an OpenAI-compatible
//! realtime provider.
//!
//! # What this endpoint is
//!
//! The client opens a WebSocket to the gateway (`wss://gateway/v1/realtime`),
//! the gateway opens a second WebSocket to the provider (`wss://provider/v1/
//! realtime`), and the two are relayed frame by frame. The gateway terminates
//! both connections: it is not a byte tunnel, so masking, keepalives and the
//! closing handshake are handled correctly on each hop.
//!
//! ```text
//! client ⇄ [masked frames] ⇄ gateway ⇄ [masked frames] ⇄ provider
//! ```
//!
//! # Which provider serves the request
//!
//! The model arrives either as `?model=provider/model` (what OpenAI's clients
//! send) or in the client's first JSON message (`{"type":"session.update",
//! "session":{"model":"…"}}`). Either way it must resolve to an `openai_compat`
//! provider whose config *declares*
//! `capabilities = ["realtime"]`. Reusing chat's "any provider that lists the
//! model, or any wildcard provider" rule would send a websocket to a
//! chat-only endpoint that happens to share the model name; the failure would
//! happen after the 101, leaving the client with a socket that never speaks.
//! A provider that does not declare the capability is therefore refused with
//! `400 unsupported_capability`, naming the capability and the config snippet
//! that enables it.
//!
//! Client-key rules are chat's, unchanged: `disabled_models` (404
//! `model_not_found`) and the key's model allowlist (403 `model_not_allowed`),
//! matched through [`crate::proxy::access`] so the two endpoints cannot drift.
//!
//! # Auth and quotas
//!
//! * The *client* presents a gateway/client key to the normal `/v1/*` auth
//!   middleware; this handler only sees the resulting [`KeyPermissions`].
//! * The *provider* key is picked from the provider's pool with
//!   [`crate::pool::KeyPool::pick_ready`], and its in-flight slot ([`KeyGuard`]) is
//!   held for the whole session, so `max_concurrent` counts websockets the same
//!   way it counts requests. The secret is only ever sent upstream in an
//!   `Authorization: Bearer` header — never logged, never in a URL.
//!
//! # Limits
//!
//! A session is bounded by [`IDLE_TIMEOUT`] (no frame in *either* direction),
//! [`MAX_SESSION_LIFETIME`] (an absolute ceiling, because pings refresh the idle
//! timer), [`MAX_SESSION_BYTES`] per direction, the per-write [`WRITE_TIMEOUT`],
//! and the frame/message caps in [`crate::ws`]. The number of sessions in the
//! process is bounded too ([`MAX_SESSIONS`]). Realtime audio is a few KiB per
//! event, so these limits are generous for real clients and useless as an
//! amplifier for hostile ones.
//!
//! # Known limitations
//!
//! * The provider's `proxy` setting is ignored: the raw socket is opened
//!   directly (there is no SOCKS client available offline here, and the
//!   reqwest client cannot hand out an upgraded socket).
//! * `wss://` verifies the certificate against the *system* CA bundle
//!   ([`CA_BUNDLES`]); `webpki-roots` is not a direct dependency, so a host
//!   without a CA bundle cannot reach `wss://` providers and is told so.
//! * Only text/binary messages, ping/pong and close are relayed; WebSocket
//!   extensions (permessage-deflate) are not negotiated, so neither side
//!   compresses — the upstream offer is not forwarded.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::api::ApiError;
use crate::pool::{FailKind, KeyGuard, KeyState};
use crate::providers::{Provider, ProviderRouter};
use crate::ws::{self, Frame, FrameReader, OpCode};

use super::access::{combo_allowed, model_allowed, model_disabled};
use super::{AppState, KeyPermissions, error_response};

/// The capability a provider must declare to receive realtime traffic.
const CAPABILITY: &str = "realtime";

/// Provider path appended to `base_url` (OpenAI: `…/v1` + `/realtime`).
const UPSTREAM_PATH: &str = "/realtime";

/// Cap on the provider's handshake response head (a header bomb is not a session).
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// How long a client may take to send a `session.update` when `?model=` is absent.
const MODEL_WAIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Messages buffered while waiting for that model (they are replayed upstream).
const MAX_PENDING_FRAMES: usize = 8;

/// Total payload buffered while waiting for the model.
///
/// Without this cap a client could park [`MAX_PENDING_FRAMES`] × one full-size
/// frame per connection before ever naming a model, which is exactly the sort of
/// pre-session memory amplification the frame caps exist to prevent.
const MAX_PENDING_BYTES: usize = 1024 * 1024;

/// Connect (TCP + TLS) budget for the provider.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Close a session that has carried no frame in *either* direction for this long.
///
/// Realtime sessions are interactive: minutes of silence mean the client is
/// gone, and an idle websocket still costs a provider key slot.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Per-direction byte budget for one session (payload bytes, both ways).
const MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024;

/// Deadline for a single frame write to either peer.
///
/// Every write happens **inside** a `select!` arm body, not as a select branch.
/// A peer that stops reading drives its receive window to zero, `write_all` then
/// pends forever, and the relay never gets back to `select!` — so the idle timer
/// (and every other deadline) is never polled again and the task, both sockets and
/// the provider key slot stay pinned by a client that simply does not read. That
/// is a cheap resource-exhaustion attack, so each write carries a deadline and
/// expiry is a session error (close 1011) instead of a stall. 10 s is far beyond
/// what any working peer needs to drain a frame, and short enough that a stalled
/// session gives its slots back promptly.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many realtime sessions this process may run at once.
///
/// One session costs a client socket, an upstream socket, a provider key slot and
/// a task; without a budget a client opens sockets until the process runs out of
/// descriptors, and each of them also holds a provider key (starving every other
/// endpoint). 512 is far above what a single process serves comfortably in
/// practice, so a real deployment never notices the cap while the hostile case is
/// bounded. Kept as a constant rather than configuration: it describes what one
/// process can hold, not an operator policy.
const MAX_SESSIONS: usize = 512;

/// Hard ceiling on how long one session may live.
///
/// The idle timer is refreshed by *any* frame, pings included, so a peer that
/// pings on schedule can keep a session (and its provider key slot) forever.
/// Realtime sessions are interactive: a client reconnects and resumes, so an hour
/// is far beyond any legitimate session. The close code is 1001 ("going away"),
/// which tells the client to reconnect rather than to treat it as an error.
const MAX_SESSION_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// Running sessions, kept honest by [`SessionSlot`].
static ACTIVE_SESSIONS: LazyLock<Arc<AtomicUsize>> =
    LazyLock::new(|| Arc::new(AtomicUsize::new(0)));

/// A reserved session slot: the process-wide budget is held as long as this lives.
///
/// Acquired before the 101 and released by `Drop`, so *every* way a session can
/// end — a normal close, a protocol error, a write timeout, an upgrade that never
/// completes — returns the slot. Nothing else decrements the counter.
struct SessionSlot {
    active: Arc<AtomicUsize>,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Reserve one slot, or `None` when `cap` sessions are already running.
///
/// Compare-and-increment in one atomic step: a `load() < cap` check followed by a
/// separate increment would let two upgrades both take the last slot. The cap is a
/// parameter (rather than only the global) so the limit itself is testable.
fn acquire_session_slot(active: &Arc<AtomicUsize>, cap: usize) -> Option<SessionSlot> {
    let mut running = active.load(Ordering::Relaxed);
    loop {
        if running >= cap {
            return None;
        }
        match active.compare_exchange_weak(
            running,
            running + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                return Some(SessionSlot {
                    active: Arc::clone(active),
                });
            }
            // Somebody else took/released a slot: retry against the new value.
            Err(current) => running = current,
        }
    }
}

/// Where to look for the system trust anchors used by `wss://` targets.
const CA_BUNDLES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /v1/realtime`.
///
/// Takes the raw [`Request`] because the upgrade future (`hyper::upgrade::on`)
/// can only be taken from it before the 101 is returned.
pub async fn realtime(
    State(state): State<Arc<AppState>>,
    key_perm: Option<Extension<KeyPermissions>>,
    headers: HeaderMap,
    mut req: Request,
) -> Response {
    let client_key = key_perm.as_ref().and_then(|e| e.0.key_name.clone());
    let allowed = key_perm.as_ref().and_then(|e| e.0.allowed_models.clone());

    // The per-client-key concurrency slot for an upgrade arrives in the *request*
    // extensions, unlike every other request, where the middleware attaches it to
    // the response. A websocket answers its 101 from here and then lives on in a
    // spawned task, so a response-attached guard would be dropped the instant the
    // 101 was returned: the key's `max_concurrent` counter would fall back to zero
    // while the session (and its provider key slot) is still in use, which is
    // precisely the concurrency the guard exists to cap. Taking it out of the
    // request and keeping it in `SessionCtx` releases it when the session ends.
    let client_slot = req
        .extensions_mut()
        .remove::<crate::middleware::ClientKeyGuard>();

    // Everything that can fail *before* the upgrade is answered with a normal
    // HTTP error, so the client never has to guess why its socket closed.
    let handshake = match validate_handshake(&headers) {
        Ok(h) => h,
        Err(err) => return err.into_response(),
    };
    let model_hint = query_param(req.uri().query(), "model");
    let router = state.router.load_full();
    let target = match &model_hint {
        Some(model) => match plan_target(&state, &router, model, allowed.as_deref()) {
            Ok(target) => Some(target),
            Err(reject) => return reject.into_response(),
        },
        // The model will arrive in the first websocket message; the provider is
        // resolved (and refused) after the upgrade, in `run_session`.
        None => None,
    };

    let on_upgrade = hyper::upgrade::on(&mut req);

    // Capacity, not policy: refused before the upgrade so the client gets a real
    // HTTP error instead of a socket that is closed right after its 101. The slot
    // is dropped with `session_slot` when the session ends (or immediately, if the
    // builder below fails).
    let Some(session_slot) = acquire_session_slot(&ACTIVE_SESSIONS, MAX_SESSIONS) else {
        warn!("realtime: refusing a session, {MAX_SESSIONS} already running");
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "the gateway is already running {MAX_SESSIONS} realtime sessions; retry shortly"
            ),
            "overloaded",
        );
    };

    let mut builder = axum::http::Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .header("Sec-WebSocket-Accept", ws::accept_key(&handshake.key));
    if let Some(protocol) = &handshake.subprotocol {
        builder = builder.header("Sec-WebSocket-Protocol", protocol);
    }
    let response = match builder.body(axum::body::Body::empty()) {
        Ok(response) => response,
        Err(e) => {
            return ApiError::internal(format!("cannot build the 101 response: {e}"))
                .into_response();
        }
    };

    let ctx = SessionCtx {
        state: Arc::clone(&state),
        router,
        target,
        allowed,
        client_key,
        subprotocol: handshake.subprotocol,
        model_hint,
        started: Instant::now(),
        _client_slot: client_slot,
        _session_slot: session_slot,
    };
    tokio::spawn(async move { run_session(ctx, on_upgrade).await });
    response
}

// ---------------------------------------------------------------------------
// Opening handshake (client side)
// ---------------------------------------------------------------------------

/// The parts of the client's opening handshake the endpoint needs.
#[derive(Debug)]
struct Handshake {
    /// `Sec-WebSocket-Key`, verbatim (input to `Sec-WebSocket-Accept`).
    key: String,
    /// The subprotocol we echo back, if the client offered any.
    subprotocol: Option<String>,
}

/// Validate the client's opening handshake (RFC 6455 §4.2.1).
///
/// `Connection`/`Upgrade` are token lists, so they are matched token by token
/// and case-insensitively; a client that sends `keep-alive, Upgrade` is fine.
fn validate_handshake(headers: &HeaderMap) -> Result<Handshake, ApiError> {
    let upgrade = header_str(headers, "upgrade")
        .ok_or_else(|| ApiError::bad_request("missing 'Upgrade' header"))?;
    if !upgrade
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
    {
        return Err(ApiError::bad_request(format!(
            "'Upgrade' must offer 'websocket' (got '{upgrade}')"
        )));
    }
    let connection = header_str(headers, "connection")
        .ok_or_else(|| ApiError::bad_request("missing 'Connection' header"))?;
    if !connection
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    {
        return Err(ApiError::bad_request(format!(
            "'Connection' must include 'Upgrade' (got '{connection}')"
        )));
    }
    match header_str(headers, "sec-websocket-version") {
        Some("13") => {}
        Some(other) => {
            return Err(ApiError::bad_request(format!(
                "unsupported 'Sec-WebSocket-Version' '{other}' (only 13 is supported)"
            )));
        }
        None => {
            return Err(ApiError::bad_request(
                "missing 'Sec-WebSocket-Version' header (expected 13)",
            ));
        }
    }

    let key = header_str(headers, "sec-websocket-key")
        .ok_or_else(|| ApiError::bad_request("missing 'Sec-WebSocket-Key' header"))?;
    // RFC 6455 §4.2.1 requires the key to be base64 of exactly 16 random bytes.
    // Checking it turns a sloppy client into a clear 400 instead of a 101 the
    // peer cannot validate, and keeps control bytes out of the accept value.
    if !valid_key(key) {
        return Err(ApiError::bad_request(
            "'Sec-WebSocket-Key' must be the base64 encoding of 16 bytes",
        ));
    }

    Ok(Handshake {
        key: key.to_string(),
        subprotocol: choose_subprotocol(headers),
    })
}

/// A `Sec-WebSocket-Key` is base64 of 16 bytes: 22 chars + "==".
fn valid_key(key: &str) -> bool {
    if key.len() != 24 || !key.ends_with("==") {
        return false;
    }
    key[..22]
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Pick the subprotocol to echo.
///
/// OpenAI's browser clients pass `Sec-WebSocket-Protocol: realtime`; a browser
/// *fails* the connection when the server does not select one of the offered
/// protocols, so echoing is not cosmetic. Only token characters are accepted —
/// the value is copied into a response header, and a raw `\r\n` there would be
/// a header injection.
fn choose_subprotocol(headers: &HeaderMap) -> Option<String> {
    let offered = header_str(headers, "sec-websocket-protocol")?;
    let mut first: Option<&str> = None;
    for token in offered.split(',') {
        let token = token.trim();
        if token.is_empty() || token.len() > 128 {
            continue;
        }
        if !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'!'))
        {
            continue;
        }
        if token.eq_ignore_ascii_case("realtime") {
            return Some(token.to_string());
        }
        first.get_or_insert(token);
    }
    first.map(str::to_string)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

// ---------------------------------------------------------------------------
// Query string
// ---------------------------------------------------------------------------

/// Decoded value of `name` in a raw query string.
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            let decoded = percent_decode(value);
            let trimmed = decoded.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Decode `%XX` escapes (the model id may arrive as `provider%2Fmodel`).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push(high << 4 | low);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|d| d as u8)
}

/// Percent-encode a model id for the upstream query string.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Routing and gating
// ---------------------------------------------------------------------------

/// A refusal rendered as the gateway's JSON error envelope.
///
/// Not [`ApiError`] for the routing variants on purpose: `ApiError` derives its
/// `type` string from the status, and `unsupported_capability` /
/// `model_not_found` / `model_not_allowed` are the vocabulary `chat` and
/// `media` already ship (clients branch on them), so the envelope is built with
/// [`error_response`]. Transport-level misuse (a malformed handshake) does use
/// `ApiError`, where the status-derived type is the right one.
struct Reject {
    status: StatusCode,
    message: String,
    kind: &'static str,
}

impl Reject {
    fn into_response(self) -> Response {
        error_response(self.status, self.message, self.kind)
    }

    /// 404 — same wording as chat, so a client sees one vocabulary.
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
            kind: "model_not_found",
        }
    }

    /// 403 — the client key may not use this model.
    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
            kind: "model_not_allowed",
        }
    }

    /// 400 — nothing can serve realtime for this model.
    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            kind: "unsupported_capability",
        }
    }

    /// 400 — the request is malformed (bad query, no frame, bad frame).
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            kind: "invalid_request_error",
        }
    }

    /// 503 — the provider has no usable key right now.
    fn unavailable(provider: &str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: format!(
                "provider '{provider}' has no available key (busy, cooling down or disabled); \
                 retry shortly"
            ),
            kind: "provider_unavailable",
        }
    }

    fn unsupported_provider(provider: &Provider) -> Self {
        // Only `openai_compat` providers can declare capabilities (the config
        // validator rejects the rest), so a gemini/anthropic/codex provider is a
        // different kind of "no" and deserves a different sentence.
        if provider.kind != crate::config::ProviderKind::OpenaiCompat {
            return Self::unsupported(format!(
                "provider '{}' is a {} provider; /v1/realtime only relays to openai_compat \
                 providers, which are the only kind that can declare capabilities",
                provider.name,
                format!("{:?}", provider.kind).to_ascii_lowercase()
            ));
        }
        Self::unsupported(format!(
            "provider '{}' does not declare the '{CAPABILITY}' capability, so it cannot serve \
             /v1/realtime; add capabilities = [\"{CAPABILITY}\"] to it in the config to enable it",
            provider.name
        ))
    }

    fn unsupported_combo(model: &str, targets: &[(&Provider, String)]) -> Self {
        let detail = if targets.is_empty() {
            "it has no resolvable target".to_string()
        } else {
            format!(
                "its targets are {}",
                targets
                    .iter()
                    .map(|(p, m)| format!("{}/{}", p.name, m))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        Self::unsupported(format!(
            "combo '{model}' has no target that declares the '{CAPABILITY}' capability ({detail})"
        ))
    }
}

/// Resolve `model` and apply every gate, exactly as chat does, plus the
/// capability requirement.
///
/// Order matters: "disabled" and "not allowed for this key" are answered before
/// the capability, so a key that cannot use the model learns nothing about
/// which providers would have accepted it.
fn gate<'a>(
    router: &'a ProviderRouter,
    model: &str,
    allowed: Option<&[String]>,
    disabled: &std::collections::HashSet<String>,
) -> Result<(&'a Provider, String), Reject> {
    let Some(resolved) = router.resolve(model) else {
        return Err(Reject::not_found(format!(
            "no provider serves model '{model}'"
        )));
    };

    // A combo may be addressed as "name" or "combo/name"; chat rejects either.
    let bare = model.strip_prefix("combo/").unwrap_or(model);
    if disabled.contains(model) || disabled.contains(bare) {
        return Err(Reject::not_found(format!("model '{model}' is disabled")));
    }

    match resolved {
        crate::providers::Resolved::One(provider, upstream) => {
            // Chat resolution stops at the first provider that lists the model,
            // which may be a chat-only one. Prefer a provider that declares the
            // capability *before* gating, so a key allowlisted for
            // "rt/gpt-realtime" is not refused because a chat provider happens to
            // list the same model first.
            let (provider, upstream) = match provider.has_capability(CAPABILITY) {
                true => (provider, upstream),
                false => match capability_fallback(router, model, disabled) {
                    Some((provider, upstream)) => (provider, upstream),
                    None => return Err(Reject::unsupported_provider(provider)),
                },
            };
            let canonical = format!("{}/{}", provider.name, upstream);
            if model_disabled(disabled, model, &canonical, &upstream) {
                return Err(Reject::not_found(format!("model '{model}' is disabled")));
            }
            if let Some(allowed) = allowed
                && !model_allowed(allowed, model, &canonical, &upstream)
            {
                return Err(Reject::forbidden(format!(
                    "model '{model}' is not allowed for this API key"
                )));
            }
            Ok((provider, upstream))
        }
        crate::providers::Resolved::Chain(chain) => {
            if let Some(allowed) = allowed
                && !combo_allowed(allowed, model)
            {
                return Err(Reject::forbidden(format!(
                    "model '{model}' is not allowed for this API key"
                )));
            }
            let active: Vec<(&Provider, String)> = chain
                .iter()
                .filter(|(provider, upstream)| {
                    provider.has_capability(CAPABILITY)
                        && !disabled.contains(&format!("{}/{}", provider.name, upstream))
                        && !disabled.contains(upstream.as_str())
                })
                .cloned()
                .collect();
            match active.first() {
                Some((provider, upstream)) => Ok((*provider, upstream.clone())),
                None => Err(Reject::unsupported_combo(model, &chain)),
            }
        }
    }
}

/// A capable provider that serves a bare model, when chat's first match is not
/// capable.
fn capability_fallback<'a>(
    router: &'a ProviderRouter,
    model: &str,
    disabled: &std::collections::HashSet<String>,
) -> Option<(&'a Provider, String)> {
    if model.contains('/') {
        // An explicit "provider/model" must not be silently re-routed.
        return None;
    }
    // The allowlist is applied to the chosen target by the caller: filtering here
    // too would turn "this provider is not yours" into "no provider can serve you".
    let capable = |provider: &&Provider| {
        provider.has_capability(CAPABILITY)
            && !model_disabled(
                disabled,
                model,
                &format!("{}/{}", provider.name, model),
                model,
            )
    };
    // Explicit model lists first (chat's precedence), then wildcard providers.
    if let Some(provider) = router
        .providers
        .iter()
        .filter(capable)
        .find(|p| p.models.iter().any(|m| m == model))
    {
        return Some((provider, model.to_string()));
    }
    router
        .providers
        .iter()
        .filter(capable)
        .find(|p| p.models.is_empty())
        .map(|p| (p, model.to_string()))
}

/// One resolved session target: provider, upstream model, and the key slot the
/// session holds.
struct Target {
    provider_name: String,
    base_url: String,
    extra_headers: Vec<(String, String)>,
    /// Model name to send upstream (the provider's, not the client's).
    upstream_model: String,
    /// Model as the client asked for it, for logs.
    requested_model: String,
    key: Arc<KeyState>,
    /// Held for the whole session so `max_concurrent` counts websockets too.
    _guard: KeyGuard,
}

/// Resolve + gate + pick a key, all before any await (the `disabled_models`
/// guard must not be held across one).
fn plan_target(
    state: &AppState,
    router: &ProviderRouter,
    model: &str,
    allowed: Option<&[String]>,
) -> Result<Target, Reject> {
    let disabled = state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let (provider, upstream_model) = gate(router, model, allowed, &disabled)?;
    drop(disabled);

    let key = provider
        .pool
        .pick_ready(&upstream_model, None)
        .ok_or_else(|| Reject::unavailable(&provider.name))?;
    let guard = key
        .try_acquire()
        .ok_or_else(|| Reject::unavailable(&provider.name))?;
    Ok(Target {
        provider_name: provider.name.clone(),
        base_url: provider.base_url.clone(),
        extra_headers: provider.extra_headers.clone(),
        upstream_model,
        requested_model: model.to_string(),
        key,
        _guard: guard,
    })
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Everything the spawned session task needs.
struct SessionCtx {
    state: Arc<AppState>,
    router: Arc<ProviderRouter>,
    /// Resolved from `?model=`; `None` means the client sends the model first.
    target: Option<Target>,
    allowed: Option<Vec<String>>,
    client_key: Option<String>,
    /// Subprotocol to offer upstream (the one we echoed to the client).
    subprotocol: Option<String>,
    model_hint: Option<String>,
    started: Instant,
    /// The client key's concurrency slot, held (never read) until this context is
    /// dropped at the end of the session task.
    ///
    /// `None` when the key has no concurrency cap, when no client keys are
    /// configured, or when the middleware took the response path.
    _client_slot: Option<crate::middleware::ClientKeyGuard>,
    /// The process-wide session budget slot, held for the same reason.
    _session_slot: SessionSlot,
}

/// Drive one websocket session: upgrade, resolve, connect upstream, relay, log.
async fn run_session(ctx: SessionCtx, on_upgrade: hyper::upgrade::OnUpgrade) {
    let SessionCtx {
        state,
        router,
        target,
        allowed,
        client_key,
        subprotocol,
        model_hint,
        started,
        // Both guards are bound (not read) for the whole function: they release
        // the per-key concurrency counter and the session budget only when this
        // task ends, whatever ended it.
        _client_slot,
        _session_slot,
    } = ctx;

    // A peer that accepts the 101 and then never lets the upgrade complete would
    // otherwise hold a session slot forever, so the handover is bounded too.
    let upgraded = match tokio::time::timeout(CONNECT_TIMEOUT, on_upgrade).await {
        Err(_) => {
            warn!(model = ?model_hint, "realtime: the connection did not upgrade in time");
            return;
        }
        Ok(Err(e)) => {
            // The client vanished (or the transport was not upgradeable, e.g.
            // HTTP/2) before hyper could hand the socket over.
            warn!(model = ?model_hint, error = %e, "realtime: the connection could not be upgraded");
            return;
        }
        Ok(Ok(upgraded)) => upgraded,
    };

    let (client_reader, mut client_writer) = tokio::io::split(HyperIo::new(upgraded));
    let mut client = FrameReader::server_side(client_reader);

    // Resolve the provider: from the query string, or from the first message.
    let mut initial: Vec<Frame> = Vec::new();
    let target = match target {
        Some(target) => target,
        None => match await_target(
            &state,
            &router,
            allowed.as_deref(),
            &mut client,
            &mut client_writer,
        )
        .await
        {
            Ok((target, buffered)) => {
                initial = buffered;
                target
            }
            Err(reject) => {
                fail_session(
                    &mut client_writer,
                    reject.kind,
                    &reject.message,
                    &state,
                    model_hint.as_deref().unwrap_or(""),
                    None,
                    client_key.as_deref(),
                    started,
                )
                .await;
                return;
            }
        },
    };

    debug!(
        provider = %target.provider_name,
        model = %target.upstream_model,
        "realtime: relaying"
    );

    let (upstream, pending) = match open_upstream(
        &target.provider_name,
        &target.base_url,
        &target.key.secret,
        &target.upstream_model,
        subprotocol.as_deref(),
        &target.extra_headers,
    )
    .await
    {
        Ok((io, leftover)) => {
            if let Some(provider) = provider_of(&router, &target.provider_name) {
                provider.pool.report_success(&target.key);
            }
            // Bytes that arrived together with the 101 are already the
            // provider's first frames; they must not be dropped.
            (io, leftover)
        }
        Err(e) => {
            warn!(
                provider = %target.provider_name,
                model = %target.upstream_model,
                error = %e,
                "realtime: upstream handshake failed"
            );
            if let Some(provider) = provider_of(&router, &target.provider_name) {
                provider
                    .pool
                    .report_failure(&target.key, e.fail_kind(), &target.upstream_model);
            }
            // The 101 is already on the wire, so the failure has to be reported
            // in-band: an OpenAI-shaped error event, then a close frame.
            fail_session(
                &mut client_writer,
                "upstream_unavailable",
                &e.to_string(),
                &state,
                &target.requested_model,
                Some(&target),
                client_key.as_deref(),
                started,
            )
            .await;
            return;
        }
    };

    let outcome = relay_io(
        client,
        client_writer,
        initial,
        upstream,
        pending,
        Limits::default(),
        &target.upstream_model,
    )
    .await;
    debug!(
        provider = %target.provider_name,
        model = %target.upstream_model,
        ?outcome,
        "realtime: session ended"
    );
    state.log_request(crate::events::RequestRecord {
        ts: unix_now(),
        provider: target.provider_name.clone(),
        model: target.requested_model.clone(),
        key: target.key.masked(),
        // The endpoint's status: the upstream upgraded successfully.
        status: "101".to_string(),
        latency_ms: started.elapsed().as_millis() as u64,
        // A websocket session is streaming by definition.
        stream: true,
        client_key,
    });
}

/// Read frames until one carries a model, buffering them for replay.
async fn await_target<R, W>(
    state: &AppState,
    router: &ProviderRouter,
    allowed: Option<&[String]>,
    client: &mut FrameReader<R>,
    writer: &mut W,
) -> Result<(Target, Vec<Frame>), Reject>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let deadline = tokio::time::Instant::now() + MODEL_WAIT_TIMEOUT;
    let mut buffered: Vec<Frame> = Vec::new();
    let mut buffered_bytes = 0usize;
    let model = loop {
        let frame = match tokio::time::timeout_at(deadline, client.next_message()).await {
            Err(_) => {
                return Err(Reject::bad_request(format!(
                    "no 'model' in the query string and no model in the first message within \
                     {}s; send '/v1/realtime?model=<provider>/<model>' or a session.update \
                     message, or use another provider",
                    MODEL_WAIT_TIMEOUT.as_secs()
                )));
            }
            Ok(Err(e)) => {
                return Err(Reject::bad_request(format!(
                    "invalid WebSocket frame from the client: {e}"
                )));
            }
            Ok(Ok(None)) => {
                return Err(Reject::bad_request(
                    "the client closed the connection before naming a model",
                ));
            }
            Ok(Ok(Some(frame))) => frame,
        };

        match frame.opcode {
            // Keepalives are answered on this hop; they are not part of the
            // session and must not be replayed upstream.
            OpCode::Ping => {
                // Deadline here too: this runs before the relay loop exists, and a
                // client with a zero receive window would otherwise pin the task
                // (and the session budget slot) in a write that never completes.
                let pong = Frame::pong(frame.payload);
                write_within(
                    WRITE_TIMEOUT,
                    "pong to the client",
                    ws::write_frame(writer, &pong),
                )
                .await
                .map_err(|e| Reject::bad_request(format!("cannot answer a ping: {e}")))?;
                continue;
            }
            OpCode::Pong => continue,
            // No echo here: `fail_session` answers with an error event and a
            // close frame, which completes the handshake without sending data
            // after a close.
            OpCode::Close => {
                return Err(Reject::bad_request(
                    "the client closed the connection before naming a model",
                ));
            }
            OpCode::Text | OpCode::Binary => {}
            OpCode::Continuation => {}
        }

        if buffered.len() >= MAX_PENDING_FRAMES {
            return Err(Reject::bad_request(format!(
                "no model in the first {MAX_PENDING_FRAMES} messages; send the model in the \
                 query string (?model=<provider>/<model>) or a session.update message"
            )));
        }
        if buffered_bytes + frame.len() > MAX_PENDING_BYTES {
            return Err(Reject::bad_request(format!(
                "no model in the first {MAX_PENDING_BYTES} bytes of messages; send the model in \
                 the query string (?model=<provider>/<model>) or a session.update first"
            )));
        }
        buffered_bytes += frame.len();
        if let Some(model) = model_from_message(&frame.payload) {
            buffered.push(frame);
            break model;
        }
        buffered.push(frame);
    };

    let target = plan_target(state, router, &model, allowed)?;
    Ok((target, buffered))
}

/// Extract a model id from a client message.
///
/// Both shapes are in the wild: a top-level `"model"` and the documented
/// `{"type":"session.update","session":{"model":"…"}}`. Anything else (audio
/// buffers, conversation items) is the session's business and is replayed
/// upstream untouched.
fn model_from_message(payload: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let model = value
        .get("model")
        .and_then(|m| m.as_str())
        .or_else(|| {
            value
                .get("session")
                .and_then(|s| s.get("model"))
                .and_then(|m| m.as_str())
        })?
        .trim();
    if model.is_empty() {
        None
    } else {
        Some(model.to_string())
    }
}

/// Report a pre-relay failure to the client and record it.
///
/// Used only after the 101: the client sees an OpenAI-shaped error event and a
/// close frame instead of a hanging socket.
#[allow(clippy::too_many_arguments)] // one call site each; a struct would only move the noise
async fn fail_session<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: &str,
    message: &str,
    state: &AppState,
    model: &str,
    target: Option<&Target>,
    client_key: Option<&str>,
    started: Instant,
) {
    let event = serde_json::json!({
        "type": "error",
        "error": {"type": kind, "message": message},
    });
    // Both writes carry the write deadline: a client that stopped reading must
    // not be able to pin this task (and the session slot it holds) here either.
    let _ = write_within(
        WRITE_TIMEOUT,
        "error event to the client",
        ws::write_frame(writer, &Frame::text(event.to_string())),
    )
    .await;
    let _ = write_within(
        WRITE_TIMEOUT,
        "close to the client",
        ws::write_frame(writer, &Frame::close(1011, "gateway: upstream unavailable")),
    )
    .await;
    state.log_request(crate::events::RequestRecord {
        ts: unix_now(),
        provider: target.map_or_else(|| "realtime".to_string(), |t| t.provider_name.clone()),
        model: model.to_string(),
        key: target.map_or_else(|| "-".to_string(), |t| t.key.masked()),
        status: "error".to_string(),
        latency_ms: started.elapsed().as_millis() as u64,
        stream: true,
        client_key: client_key.map(str::to_string),
    });
}

// ---------------------------------------------------------------------------
// Upstream connection
// ---------------------------------------------------------------------------

/// The provider with this name, if it is still in the router.
///
/// The session task holds an `Arc<ProviderRouter>` snapshot rather than a
/// `&Provider` (the router is swapped on reload, and a reference cannot live in
/// a spawned task), so pool book-keeping looks the provider up again.
fn provider_of<'a>(router: &'a ProviderRouter, name: &str) -> Option<&'a Provider> {
    router.providers.iter().find(|p| p.name == name)
}

/// The provider endpoint derived from `base_url`.
#[derive(Debug, PartialEq, Eq)]
struct Endpoint {
    tls: bool,
    /// Host without brackets, for TLS SNI / DNS.
    host: String,
    /// Host with brackets for IPv6, for the `Host:` header.
    host_header: String,
    port: u16,
    /// Path *and* query of the upstream handshake request.
    path: String,
}

/// Derive the websocket endpoint for `model` from a provider `base_url`.
///
/// `https://` becomes `wss://` and `http://` becomes `ws://` (a provider is
/// configured once, for both HTTP and websocket traffic); an explicit `ws://` /
/// `wss://` base URL is accepted as-is. The configured path is extended with
/// `/realtime` unless it already points there, so both
/// `https://api.openai.com/v1` and `wss://api.openai.com/v1/realtime` work.
fn upstream_endpoint(base_url: &str, model: &str) -> Result<Endpoint, String> {
    let base = base_url.trim();
    if base.is_empty() {
        return Err("provider has no base_url, so its websocket endpoint is unknown".to_string());
    }
    let (scheme, rest) = base.split_once("://").ok_or_else(|| {
        format!("base_url '{base}' has no scheme (expected http, https, ws or wss)")
    })?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => false,
        "https" | "wss" => true,
        other => {
            return Err(format!(
                "base_url scheme '{other}' is not supported for realtime (expected http, https, \
                 ws or wss)"
            ));
        }
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if authority.contains('@') {
        return Err(format!(
            "base_url '{base}' embeds credentials; provider keys belong in 'keys'"
        ));
    }
    let (host, host_header, port) = split_authority(authority, if tls { 443 } else { 80 })?;

    let mut path = path
        .split('?')
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();
    if !path.ends_with(UPSTREAM_PATH) {
        path.push_str(UPSTREAM_PATH);
    }
    Ok(Endpoint {
        tls,
        host,
        host_header,
        port,
        path: format!("{path}?model={}", percent_encode(model)),
    })
}

/// Split `host[:port]`, handling bracketed IPv6 literals.
fn split_authority(authority: &str, default_port: u16) -> Result<(String, String, u16), String> {
    if authority.is_empty() {
        return Err("base_url has an empty host".to_string());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (inner, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("base_url host '{authority}' has an unterminated '['"))?;
        let port = match tail {
            "" => default_port,
            _ => {
                let raw = tail
                    .strip_prefix(':')
                    .ok_or_else(|| format!("base_url host '{authority}' is malformed"))?;
                parse_port(raw, authority)?
            }
        };
        return Ok((inner.to_string(), format!("[{inner}]"), port));
    }
    match authority.rsplit_once(':') {
        Some((host, raw)) if !host.is_empty() => Ok((
            host.to_string(),
            host.to_string(),
            parse_port(raw, authority)?,
        )),
        _ => Ok((authority.to_string(), authority.to_string(), default_port)),
    }
}

fn parse_port(raw: &str, authority: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|_| format!("base_url host '{authority}' has an invalid port '{raw}'"))
}

/// The upstream opening handshake.
///
/// Built as a string because there is no client HTTP stack here that can hand
/// out an upgraded socket; the request is fixed, so the only variable parts are
/// validated first (`key`/`accept` are base64, the subprotocol and the extra
/// headers are checked for CR/LF).
fn handshake_request(
    endpoint: &Endpoint,
    key: &str,
    auth: &str,
    subprotocol: Option<&str>,
    extra: &[(String, String)],
) -> Result<String, String> {
    if auth.contains(['\r', '\n']) {
        return Err("provider key contains a line break".to_string());
    }
    let mut request = String::with_capacity(256);
    request.push_str(&format!("GET {} HTTP/1.1\r\n", endpoint.path));
    request.push_str(&format!("Host: {}\r\n", endpoint.host_header));
    request.push_str("Upgrade: websocket\r\n");
    request.push_str("Connection: Upgrade\r\n");
    request.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    request.push_str("Sec-WebSocket-Version: 13\r\n");
    request.push_str(&format!("Authorization: Bearer {auth}\r\n"));
    if let Some(protocol) = subprotocol {
        request.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
    }
    for (name, value) in extra {
        // Operator-configured headers, but a line break in one would split the
        // request; skip it instead of forwarding a crafted one.
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            continue;
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    Ok(request)
}

/// Verify the provider's `101`: status, the two upgrade tokens, no body, and the
/// `Sec-WebSocket-Accept` value.
///
/// The accept check proves the peer actually understood the websocket handshake
/// (and is not a caching proxy replaying someone else's 101), which is why it is
/// not optional. It is not sufficient on its own either:
///
/// * A `101` must also confirm the switch with `Upgrade: websocket` **and**
///   `Connection: Upgrade` (RFC 6455 §4.1 — the client has to see both to switch
///   protocols). A response that merely happens to carry the right accept could
///   be a plain `200`-style reply from something that is not a websocket gateway,
///   and treating it as a socket would relay HTTP bytes as frames.
/// * A `101` declares the connection is now a websocket, so it cannot have a
///   body. `Content-Length: 5` (or any `Transfer-Encoding`) means the peer is
///   about to send bytes that *are not frames*; they would be replayed into the
///   frame reader, which is precisely the request-smuggling shape: one peer's
///   framing becoming another's payload. Both are refused instead.
fn verify_handshake_response(head: &str, expected_accept: &str) -> Result<(), String> {
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "the provider sent an empty handshake response".to_string())?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(format!("not an HTTP response: '{status_line}'"));
    }
    if code != "101" {
        return Err(format!(
            "the provider answered '{status_line}' instead of 101"
        ));
    }
    let mut accept = None;
    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut declares_body = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            // A token list: `Upgrade: websocket` (anything else listed with it is
            // ignored, the token is what matters).
            upgrade |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("websocket"));
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // Any transfer coding means a body follows.
            declares_body = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            // `Content-Length: 0` is harmless and some servers send it; anything
            // else (including an unparsable value) promises body bytes.
            declares_body |= match value.parse::<u64>() {
                Ok(len) => len != 0,
                Err(_) => true,
            };
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
            accept = Some(value.to_string());
        }
    }
    // Checked in this order so the message names the first thing that is wrong;
    // all four properties are required.
    if !upgrade {
        return Err(
            "the provider's 101 has no 'Upgrade: websocket' header (RFC 6455 §4.1)".to_string(),
        );
    }
    if !connection_upgrade {
        return Err(
            "the provider's 101 has no 'Connection: Upgrade' token (RFC 6455 §4.1)".to_string(),
        );
    }
    if declares_body {
        return Err(
            "the provider's 101 declares a body (Content-Length/Transfer-Encoding); those \
             bytes would not be websocket frames"
                .to_string(),
        );
    }
    match accept {
        Some(value) if value == expected_accept => Ok(()),
        Some(value) => Err(format!(
            "the provider's Sec-WebSocket-Accept '{value}' does not match the expected \
             '{expected_accept}'"
        )),
        None => Err("the provider's 101 has no Sec-WebSocket-Accept header".to_string()),
    }
}

/// Read an HTTP response head, returning the leftover bytes (which already
/// belong to the websocket stream) separately.
async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = memchr::memmem::find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            return Ok((head, buf[end + 4..].to_vec()));
        }
        if buf.len() > MAX_HTTP_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the provider's handshake response head exceeds {MAX_HTTP_HEAD} bytes"),
            ));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the provider closed the connection during the handshake",
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Why the upstream connection could not be established.
#[derive(Debug)]
enum UpstreamError {
    /// TCP connect or TLS handshake failed.
    Network(String),
    /// The provider answered with a non-101 status.
    Status(u16, String),
    /// The 101 was malformed (bad accept, missing header).
    Protocol(String),
}

impl UpstreamError {
    /// Map the failure onto the pool's health model so a dead key is benched and
    /// a rate-limited one cools down, exactly like chat does.
    fn fail_kind(&self) -> FailKind {
        match self {
            Self::Status(401 | 403, _) => FailKind::Auth,
            Self::Status(429, _) => FailKind::RateLimited {
                retry_after_secs: None,
            },
            Self::Status(code, _) if (500..600).contains(code) => FailKind::Server,
            Self::Status(_, _) | Self::Protocol(_) | Self::Network(_) => FailKind::Network,
        }
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(message) | Self::Protocol(message) => f.write_str(message),
            Self::Status(code, message) => write!(f, "HTTP {code}: {message}"),
        }
    }
}

/// A provider websocket connection: plain TCP or TLS.
enum UpstreamIo {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for UpstreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Open the provider websocket: connect, handshake, verify the 101.
///
/// Returns the connection plus any bytes that arrived together with the response
/// head (they are already websocket frames and are replayed into the reader).
#[allow(clippy::too_many_arguments)] // flat parameters keep the call site self-documenting
async fn open_upstream(
    provider_name: &str,
    base_url: &str,
    auth: &str,
    model: &str,
    subprotocol: Option<&str>,
    extra: &[(String, String)],
) -> Result<(UpstreamIo, Vec<u8>), UpstreamError> {
    let endpoint = upstream_endpoint(base_url, model)
        .map_err(|e| UpstreamError::Protocol(format!("provider '{provider_name}': {e}")))?;
    let key = ws::random_key().map_err(|e| UpstreamError::Network(e.to_string()))?;
    let accept = ws::accept_key(&key);
    let request = handshake_request(&endpoint, &key, auth, subprotocol, extra)
        .map_err(|e| UpstreamError::Protocol(format!("provider '{provider_name}': {e}")))?;

    let connect = TcpStream::connect((endpoint.host.as_str(), endpoint.port));
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Err(_) => {
            return Err(UpstreamError::Network(format!(
                "provider '{provider_name}': timed out connecting to {}:{}",
                endpoint.host, endpoint.port
            )));
        }
        Ok(Err(e)) => {
            return Err(UpstreamError::Network(format!(
                "provider '{provider_name}': cannot connect to {}:{}: {e}",
                endpoint.host, endpoint.port
            )));
        }
        Ok(Ok(tcp)) => tcp,
    };
    // Small writes (handshake then frames) should go out immediately rather than
    // wait for Nagle to batch them.
    let _ = tcp.set_nodelay(true);

    let mut io = if endpoint.tls {
        let stream = tls_connect(&endpoint.host, tcp)
            .await
            .map_err(|e| UpstreamError::Network(format!("provider '{provider_name}': {e}")))?;
        UpstreamIo::Tls(Box::new(stream))
    } else {
        UpstreamIo::Plain(tcp)
    };

    let write = async {
        io.write_all(request.as_bytes()).await?;
        io.flush().await
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, write).await {
        Err(_) => {
            return Err(UpstreamError::Network(format!(
                "provider '{provider_name}': timed out sending the handshake"
            )));
        }
        Ok(Err(e)) => {
            return Err(UpstreamError::Network(format!(
                "provider '{provider_name}': cannot send the handshake: {e}"
            )));
        }
        Ok(Ok(())) => {}
    }

    let head = tokio::time::timeout(CONNECT_TIMEOUT, read_http_head(&mut io)).await;
    let (head, leftover) = match head {
        Err(_) => {
            return Err(UpstreamError::Network(format!(
                "provider '{provider_name}': timed out waiting for the handshake response"
            )));
        }
        Ok(Err(e)) => {
            return Err(UpstreamError::Network(format!(
                "provider '{provider_name}': {e}"
            )));
        }
        Ok(Ok(head)) => head,
    };

    if let Err(e) = verify_handshake_response(&head, &accept) {
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok());
        // Keep the first line only: response headers can carry cookies/tokens.
        let first_line = head.lines().next().unwrap_or_default().to_string();
        return Err(match status {
            Some(code) => UpstreamError::Status(code, first_line),
            None => UpstreamError::Protocol(format!("provider '{provider_name}': {e}")),
        });
    }
    Ok((io, leftover))
}

/// TLS connector built once per process from the system trust anchors.
async fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    static CONFIG: tokio::sync::OnceCell<Result<Arc<rustls::ClientConfig>, String>> =
        tokio::sync::OnceCell::const_new();
    let config = CONFIG.get_or_init(build_tls_config).await;
    match config {
        Ok(config) => Ok(tokio_rustls::TlsConnector::from(Arc::clone(config))),
        Err(e) => Err(e.clone()),
    }
}

async fn build_tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let roots = load_ca_roots().await?;
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Load the system CA bundle into a rustls root store.
///
/// Certificate verification is *not* optional for `wss://`: without roots there
/// is nothing to verify against, so this fails loudly instead of connecting
/// insecurely.
async fn load_ca_roots() -> Result<rustls::RootCertStore, String> {
    let mut tried = Vec::new();
    for path in CA_BUNDLES {
        let pem = match tokio::fs::read_to_string(path).await {
            Ok(pem) => pem,
            Err(e) => {
                tried.push(format!("{path} ({e})"));
                continue;
            }
        };
        let certificates = pem_certificates(&pem);
        if certificates.is_empty() {
            tried.push(format!("{path} (no CERTIFICATE block)"));
            continue;
        }
        let mut roots = rustls::RootCertStore::empty();
        let mut added = 0usize;
        for der in certificates {
            if roots
                .add(rustls::pki_types::CertificateDer::from(der))
                .is_ok()
            {
                added += 1;
            }
        }
        if added > 0 {
            debug!(path, added, "realtime: loaded system trust anchors");
            return Ok(roots);
        }
        tried.push(format!("{path} (no usable certificate)"));
    }
    Err(format!(
        "wss:// targets need a system CA bundle, but none could be read: {}",
        tried.join(", ")
    ))
}

/// Every `CERTIFICATE` block in a PEM file, as DER.
fn pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body = String::new();
    let mut collecting = false;
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            body.clear();
            collecting = true;
        } else if line == "-----END CERTIFICATE-----" {
            if collecting
                && let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body.as_bytes())
            {
                out.push(der);
            }
            body.clear();
            collecting = false;
        } else if collecting {
            body.push_str(line);
        }
    }
    out
}

async fn tls_connect(
    host: &str,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let connector = tls_connector().await?;
    // `ServerName` accepts both DNS names and IP literals (as `IpAddress`), so a
    // provider configured with a bare IP still verifies its certificate.
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid TLS server name '{host}': {e}"))?;
    connector
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS handshake with '{host}' failed: {e}"))
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

/// Session bounds for [`relay_io`].
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Close the session when no frame arrives in either direction for this long.
    idle: Duration,
    /// Per-direction payload budget for the whole session.
    max_bytes: u64,
    /// Deadline for one frame write (see [`WRITE_TIMEOUT`]).
    write_timeout: Duration,
    /// Absolute session lifetime (see [`MAX_SESSION_LIFETIME`]).
    lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            idle: IDLE_TIMEOUT,
            max_bytes: MAX_SESSION_BYTES,
            write_timeout: WRITE_TIMEOUT,
            lifetime: MAX_SESSION_LIFETIME,
        }
    }
}

/// How a relayed session ended (logged, and asserted by the relay test).
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The client sent a close frame; it was forwarded upstream.
    ClientClosed,
    /// The provider sent a close frame; it was forwarded to the client.
    UpstreamClosed,
    /// Neither direction carried a frame for [`Limits::idle`].
    Idle,
    /// A per-direction byte budget was exceeded.
    Budget,
    /// [`Limits::lifetime`] elapsed (pings kept the idle timer alive).
    Lifetime,
    /// Framing or transport failure (the message says which).
    Error(String),
}

/// Rewrite the client-facing model id in a frame headed upstream.
///
/// The gateway accepts `provider/model`, aliases and combo ids, but the provider
/// only understands its own model name. Only the URL query was rewritten, so a
/// `session.update` still carried `"session":{"model":"openai/gpt-realtime"}` —
/// and `session.model` takes precedence over `?model=`, so the provider saw an
/// unknown model. `session.update` is atomic on the provider side, which meant the
/// instructions/voice/VAD sent in the same message were never applied either.
fn rewrite_outbound_model(frame: &mut Frame, upstream_model: &str) {
    if frame.opcode != OpCode::Text {
        return;
    }
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&frame.payload) else {
        return;
    };
    let mut changed = false;
    if let Some(m) = v.get("model").and_then(|m| m.as_str())
        && m != upstream_model
    {
        v["model"] = serde_json::Value::String(upstream_model.to_string());
        changed = true;
    }
    if let Some(m) = v.pointer("/session/model").and_then(|m| m.as_str())
        && m != upstream_model
    {
        v["session"]["model"] = serde_json::Value::String(upstream_model.to_string());
        changed = true;
    }
    if changed && let Ok(out) = serde_json::to_vec(&v) {
        frame.payload = out;
    }
}

/// Relay frames between an already-upgraded client and the provider.
///
/// Both hops are terminated here, so:
/// * data frames are re-encoded for the destination hop (masked upstream,
///   unmasked towards the client) instead of being copied verbatim;
/// * pings are answered on the hop that asked (RFC 6455 §5.5.2) so a provider
///   keepalive never depends on the client implementation;
/// * a close frame is forwarded and ends the session.
///
/// Reads are cancel-safe (see [`crate::ws::FrameReader`]), which is what allows
/// both directions to be watched from one `select!` without spawning a task per
/// direction.
async fn relay_io<R, W, U>(
    mut client: FrameReader<R>,
    mut to_client: W,
    mut initial: Vec<Frame>,
    upstream: U,
    pending: Vec<u8>,
    limits: Limits,
    upstream_model: &str,
) -> Outcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (upstream_reader, mut to_upstream) = tokio::io::split(upstream);
    let mut from_upstream = FrameReader::client_side(upstream_reader);
    // Frames the provider sent along with its 101 (read in the same syscall as
    // the response head) are replayed into the reader before any socket read.
    from_upstream.prepend(&pending);

    let mut sent_up: u64 = 0;
    let mut sent_down: u64 = 0;
    let mut last_frame = Instant::now();
    // Absolute, not refreshed by traffic: this is what bounds a session whose
    // peer keeps it alive with pings.
    let lifetime_deadline = tokio::time::Instant::now() + limits.lifetime;

    // Frames the client sent before it named a model are replayed first.
    for mut frame in initial.drain(..) {
        // The buffered frames are exactly the ones that carried the client's model
        // id, so this is where the rewrite matters most.
        rewrite_outbound_model(&mut frame, upstream_model);
        sent_up += frame.len() as u64;
        // By value: masking is done in place instead of cloning the payload.
        if let Err(e) = write_within(
            limits.write_timeout,
            "write to the provider",
            ws::write_frame_with(&mut to_upstream, frame, true),
        )
        .await
        {
            close_both(
                &mut to_client,
                &mut to_upstream,
                1011,
                "relay write failed",
                limits.write_timeout,
            )
            .await;
            return Outcome::Error(format!("cannot write to the provider: {e}"));
        }
    }

    loop {
        let idle_deadline = last_frame + limits.idle;
        tokio::select! {
            incoming = client.next_message() => match incoming {
                Err(e) => {
                    close_both(
                        &mut to_client,
                        &mut to_upstream,
                        1002,
                        "protocol error",
                        limits.write_timeout,
                    )
                    .await;
                    return Outcome::Error(format!("client framing error: {e}"));
                }
                Ok(None) => {
                    // Clean close between messages: close the upstream hop too,
                    // under the write deadline (a provider that stopped reading
                    // must not pin the task on the way out).
                    let _ = write_within(
                        limits.write_timeout,
                        "close to the provider",
                        ws::write_frame(&mut to_upstream, &Frame::close(1000, "")),
                    )
                    .await;
                    return Outcome::ClientClosed;
                }
                Ok(Some(mut frame)) => match frame.opcode {
                    OpCode::Close => {
                        // Complete the closing handshake on both hops: the client
                        // gets its close echoed, the provider is told the session
                        // is over. The frame is only a few bytes, so lending it to
                        // both hops is cheaper than cloning it for the masked one.
                        let _ = write_within(
                            limits.write_timeout,
                            "close to the client",
                            ws::write_frame(&mut to_client, &frame),
                        )
                        .await;
                        let _ = write_within(
                            limits.write_timeout,
                            "close to the provider",
                            ws::write_frame_masked(&mut to_upstream, &frame),
                        )
                        .await;
                        return Outcome::ClientClosed;
                    }
                    OpCode::Ping => {
                        last_frame = Instant::now();
                        let pong = Frame::pong(frame.payload);
                        if let Err(e) = write_within(
                            limits.write_timeout,
                            "pong to the client",
                            ws::write_frame(&mut to_client, &pong),
                        )
                        .await
                        {
                            close_both(
                                &mut to_client,
                                &mut to_upstream,
                                1011,
                                "relay write failed",
                                limits.write_timeout,
                            )
                            .await;
                            return Outcome::Error(format!("cannot answer a ping: {e}"));
                        }
                    }
                    OpCode::Pong => {
                        last_frame = Instant::now();
                    }
                    OpCode::Text | OpCode::Binary | OpCode::Continuation => {
                        last_frame = Instant::now();
                        rewrite_outbound_model(&mut frame, upstream_model);
                        sent_up += frame.len() as u64;
                        if sent_up > limits.max_bytes {
                            close_both(
                                &mut to_client,
                                &mut to_upstream,
                                1008,
                                "byte budget exceeded",
                                limits.write_timeout,
                            )
                            .await;
                            return Outcome::Budget;
                        }
                        // By value: the relay owns this frame, so the mask is
                        // applied in place instead of on a clone.
                        if let Err(e) = write_within(
                            limits.write_timeout,
                            "write to the provider",
                            ws::write_frame_with(&mut to_upstream, frame, true),
                        )
                        .await
                        {
                            close_both(
                                &mut to_client,
                                &mut to_upstream,
                                1011,
                                "relay write failed",
                                limits.write_timeout,
                            )
                            .await;
                            return Outcome::Error(format!("cannot write to the provider: {e}"));
                        }
                    }
                },
            },
            incoming = from_upstream.next_message() => match incoming {
                Err(e) => {
                    close_both(
                        &mut to_client,
                        &mut to_upstream,
                        1002,
                        "upstream protocol error",
                        limits.write_timeout,
                    )
                    .await;
                    return Outcome::Error(format!("provider framing error: {e}"));
                }
                Ok(None) => {
                    let _ = write_within(
                        limits.write_timeout,
                        "close to the client",
                        ws::write_frame(&mut to_client, &Frame::close(1000, "")),
                    )
                    .await;
                    return Outcome::UpstreamClosed;
                }
                Ok(Some(frame)) => match frame.opcode {
                    OpCode::Close => {
                        let _ = write_within(
                            limits.write_timeout,
                            "close to the client",
                            ws::write_frame(&mut to_client, &frame),
                        )
                        .await;
                        let _ = write_within(
                            limits.write_timeout,
                            "close to the provider",
                            ws::write_frame_masked(&mut to_upstream, &frame),
                        )
                        .await;
                        return Outcome::UpstreamClosed;
                    }
                    OpCode::Ping => {
                        last_frame = Instant::now();
                        let pong = Frame::pong(frame.payload);
                        if let Err(e) = write_within(
                            limits.write_timeout,
                            "pong to the provider",
                            ws::write_frame_with(&mut to_upstream, pong, true),
                        )
                        .await
                        {
                            close_both(
                                &mut to_client,
                                &mut to_upstream,
                                1011,
                                "relay write failed",
                                limits.write_timeout,
                            )
                            .await;
                            return Outcome::Error(format!(
                                "cannot answer an upstream ping: {e}"
                            ));
                        }
                    }
                    OpCode::Pong => {
                        last_frame = Instant::now();
                    }
                    OpCode::Text | OpCode::Binary | OpCode::Continuation => {
                        last_frame = Instant::now();
                        sent_down += frame.len() as u64;
                        if sent_down > limits.max_bytes {
                            close_both(
                                &mut to_client,
                                &mut to_upstream,
                                1008,
                                "byte budget exceeded",
                                limits.write_timeout,
                            )
                            .await;
                            return Outcome::Budget;
                        }
                        if let Err(e) = write_within(
                            limits.write_timeout,
                            "write to the client",
                            ws::write_frame(&mut to_client, &frame),
                        )
                        .await
                        {
                            close_both(
                                &mut to_client,
                                &mut to_upstream,
                                1011,
                                "relay write failed",
                                limits.write_timeout,
                            )
                            .await;
                            return Outcome::Error(format!("cannot write to the client: {e}"));
                        }
                    }
                },
            },
            _ = tokio::time::sleep_until(idle_deadline.into()) => {
                // Re-read the clock: the other direction may have carried a frame
                // while this timer was pending, in which case the next iteration
                // arms a later deadline.
                if last_frame.elapsed() >= limits.idle {
                    close_both(
                        &mut to_client,
                        &mut to_upstream,
                        1001,
                        "idle timeout",
                        limits.write_timeout,
                    )
                    .await;
                    return Outcome::Idle;
                }
            }
            _ = tokio::time::sleep_until(lifetime_deadline) => {
                // Absolute: pings cannot extend this one. 1001 tells the client to
                // reconnect (and it can resume the conversation), which is the
                // honest answer for "this session lived long enough".
                close_both(
                    &mut to_client,
                    &mut to_upstream,
                    1001,
                    "maximum session lifetime reached",
                    limits.write_timeout,
                )
                .await;
                return Outcome::Lifetime;
            }
        }
    }
}

/// Run one frame write under a deadline, turning expiry into a distinct error.
///
/// Every write in the session goes through this: see [`WRITE_TIMEOUT`] for why a
/// write with no deadline is a denial of service. `what` names the hop so the
/// session log says which peer stopped reading.
async fn write_within<F>(timeout: Duration, what: &str, write: F) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
{
    match tokio::time::timeout(timeout, write).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{what} timed out after {timeout:?}: the peer is not reading"),
        )),
    }
}

/// Best-effort close on both hops, so neither peer is left waiting.
///
/// Both writes carry the session's write deadline: a close to a peer that is not
/// reading must not pin the task either, and the result is deliberately ignored —
/// the session is over either way.
async fn close_both<W1, W2>(
    client: &mut W1,
    upstream: &mut W2,
    code: u16,
    reason: &str,
    write_timeout: Duration,
) where
    W1: AsyncWrite + Unpin,
    W2: AsyncWrite + Unpin,
{
    let frame = Frame::close(code, reason);
    let _ = write_within(
        write_timeout,
        "close to the client",
        ws::write_frame(client, &frame),
    )
    .await;
    let _ = write_within(
        write_timeout,
        "close to the provider",
        ws::write_frame_masked(upstream, &frame),
    )
    .await;
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// hyper ⇄ tokio bridge
// ---------------------------------------------------------------------------

/// Bridges hyper's runtime-agnostic `rt::Read`/`rt::Write` to tokio's
/// `AsyncRead`/`AsyncWrite`, so the frame codec can drive an upgraded connection
/// without `hyper-util`'s `TokioIo` (not a direct dependency here).
struct HyperIo<T> {
    inner: T,
}

impl<T> HyperIo<T> {
    fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: hyper::rt::Read + Unpin> AsyncRead for HyperIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // `initialize_unfilled` returns the unfilled region as `&mut [u8]` and
        // marks it initialized, so the bytes hyper fills are already valid for
        // tokio and `advance` can record them without a copy. `filled` is taken
        // inside the block so the buffer borrow ends before `advance`.
        let filled = {
            let unfilled = buf.initialize_unfilled();
            let mut target = hyper::rt::ReadBuf::new(unfilled);
            let polled = {
                let cursor = target.unfilled();
                Pin::new(&mut this.inner).poll_read(cx, cursor)
            };
            match polled {
                Poll::Ready(Ok(())) => Some(target.filled().len()),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => None,
            }
        };
        match filled {
            Some(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            None => Poll::Pending,
        }
    }
}

impl<T: hyper::rt::Write + Unpin> AsyncWrite for HyperIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ComboConfig, ProviderConfig, Tuning};
    use std::collections::HashSet;
    use tokio::net::TcpListener;

    // ----- fixtures -----

    /// The provider realtime traffic is meant for.
    const REALTIME: &str = r#"
        name = "rt"
        type = "openai_compat"
        base_url = "http://127.0.0.1:1/v1"
        keys = ["sk-rt"]
        models = ["gpt-realtime"]
        capabilities = ["realtime"]
    "#;

    /// A chat provider that *also* lists the realtime model, and comes first in
    /// the router: capability gating, not list order, must decide.
    const CHAT: &str = r#"
        name = "chat"
        type = "openai_compat"
        base_url = "http://127.0.0.1:2/v1"
        keys = ["sk-chat"]
        models = ["gpt-realtime", "gpt-4o"]
    "#;

    /// Declares the capability but lists no models: a realtime wildcard.
    const WILDCARD: &str = r#"
        name = "rtwild"
        type = "openai_compat"
        base_url = "http://127.0.0.1:3/v1"
        keys = ["sk-wild"]
        capabilities = ["realtime"]
    "#;

    /// Not openai_compat, so it cannot declare capabilities at all.
    const GEMINI: &str = r#"
        name = "gem"
        type = "gemini"
        base_url = "http://127.0.0.1:4"
        keys = ["sk-gem"]
        models = ["gpt-realtime"]
    "#;

    fn provider(source: &str) -> Provider {
        let cfg: ProviderConfig = toml::from_str(source).expect("test provider config");
        Provider::from_config(
            &cfg,
            None,
            None,
            None,
            Arc::new(Tuning::default()),
            Duration::from_secs(30),
            2,
        )
        .expect("provider builds offline")
    }

    fn router(providers: Vec<Provider>, combos: &[(&str, &[&str])]) -> ProviderRouter {
        ProviderRouter {
            providers,
            combos: combos
                .iter()
                .map(|(name, chain)| ComboConfig {
                    name: (*name).to_string(),
                    chain: chain.iter().map(|c| (*c).to_string()).collect(),
                })
                .collect(),
        }
    }

    fn no_disabled() -> HashSet<String> {
        HashSet::new()
    }

    fn disabled(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    fn expect_target(result: Result<(&Provider, String), Reject>) -> (&Provider, String) {
        match result {
            Ok(target) => target,
            Err(reject) => panic!("unexpected rejection: {} ({})", reject.message, reject.kind),
        }
    }

    fn expect_reject(result: Result<(&Provider, String), Reject>) -> Reject {
        match result {
            Ok((provider, model)) => {
                panic!("expected a rejection, got {}/{}", provider.name, model)
            }
            Err(reject) => reject,
        }
    }

    // ----- model resolution and capability gating -----

    #[test]
    fn explicit_provider_model_routes_to_that_provider() {
        let r = router(vec![provider(REALTIME), provider(CHAT)], &[]);
        let (provider, model) = expect_target(gate(&r, "rt/gpt-realtime", None, &no_disabled()));
        assert_eq!(provider.name, "rt");
        assert_eq!(model, "gpt-realtime");
    }

    #[test]
    fn bare_model_picks_the_capable_provider_not_the_chat_one() {
        let r = router(vec![provider(CHAT), provider(REALTIME)], &[]);
        let (provider, model) = expect_target(gate(&r, "gpt-realtime", None, &no_disabled()));
        assert_eq!(provider.name, "rt");
        assert_eq!(model, "gpt-realtime");
    }

    #[test]
    fn a_capable_wildcard_provider_accepts_any_model() {
        let r = router(vec![provider(WILDCARD)], &[]);
        let (provider, model) = expect_target(gate(&r, "some-new-model", None, &no_disabled()));
        assert_eq!(provider.name, "rtwild");
        assert_eq!(model, "some-new-model");
    }

    #[test]
    fn a_chat_only_provider_is_400_unsupported_capability() {
        let r = router(vec![provider(CHAT)], &[]);
        let reject = expect_reject(gate(&r, "gpt-realtime", None, &no_disabled()));
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.kind, "unsupported_capability");
        // The message names the capability and the config line that enables it.
        assert!(reject.message.contains("'realtime'"), "{}", reject.message);
        assert!(
            reject.message.contains(r#"capabilities = ["realtime"]"#),
            "{}",
            reject.message
        );
    }

    #[test]
    fn a_non_openai_compat_provider_gets_its_own_message() {
        let r = router(vec![provider(GEMINI)], &[]);
        let reject = expect_reject(gate(&r, "gem/gpt-realtime", None, &no_disabled()));
        assert_eq!(reject.kind, "unsupported_capability");
        assert!(
            reject.message.contains("openai_compat"),
            "{}",
            reject.message
        );
    }

    #[test]
    fn no_provider_at_all_is_404_model_not_found() {
        // Every provider lists models, so a bare unknown model is not a wildcard
        // match: chat returns the same 404.
        let r = router(vec![provider(CHAT)], &[]);
        let reject = expect_reject(gate(&r, "unknown-model", None, &no_disabled()));
        assert_eq!(reject.status, StatusCode::NOT_FOUND);
        assert_eq!(reject.kind, "model_not_found");
        assert_eq!(reject.message, "no provider serves model 'unknown-model'");
    }

    #[test]
    fn a_disabled_model_is_404_with_chats_message() {
        let r = router(vec![provider(REALTIME)], &[]);
        let reject = expect_reject(gate(
            &r,
            "rt/gpt-realtime",
            None,
            &disabled(&["rt/gpt-realtime"]),
        ));
        assert_eq!(reject.status, StatusCode::NOT_FOUND);
        assert_eq!(reject.kind, "model_not_found");
        assert_eq!(reject.message, "model 'rt/gpt-realtime' is disabled");

        // The bare-model name counts as disabled too.
        let reject = expect_reject(gate(&r, "gpt-realtime", None, &disabled(&["gpt-realtime"])));
        assert_eq!(reject.status, StatusCode::NOT_FOUND);
    }

    // ----- client-key allowlist -----

    #[test]
    fn a_model_outside_the_keys_allowlist_is_403() {
        let r = router(vec![provider(REALTIME)], &[]);
        let allowed = vec!["gpt-4o".to_string()];
        let reject = expect_reject(gate(&r, "gpt-realtime", Some(&allowed), &no_disabled()));
        assert_eq!(reject.status, StatusCode::FORBIDDEN);
        assert_eq!(reject.kind, "model_not_allowed");
        assert_eq!(
            reject.message,
            "model 'gpt-realtime' is not allowed for this API key"
        );
    }

    #[test]
    fn an_allowlist_entry_may_name_the_bare_or_provider_qualified_model() {
        let r = router(vec![provider(CHAT), provider(REALTIME)], &[]);
        for entry in ["gpt-realtime", "rt/gpt-realtime"] {
            let allowed = vec![entry.to_string()];
            let (provider, model) =
                expect_target(gate(&r, "gpt-realtime", Some(&allowed), &no_disabled()));
            assert_eq!(provider.name, "rt", "allowlist entry {entry}");
            assert_eq!(model, "gpt-realtime");
        }
    }

    #[test]
    fn a_combo_routes_to_its_first_capable_target() {
        let r = router(
            vec![provider(CHAT), provider(REALTIME)],
            &[("fast", &["chat/gpt-realtime", "rt/gpt-realtime"])],
        );
        let (provider, model) = expect_target(gate(&r, "fast", None, &no_disabled()));
        assert_eq!(provider.name, "rt");
        assert_eq!(model, "gpt-realtime");
        // And through the explicit "combo/" prefix.
        let (provider, _) = expect_target(gate(&r, "combo/fast", None, &no_disabled()));
        assert_eq!(provider.name, "rt");
    }

    #[test]
    fn a_combo_without_a_capable_target_is_400() {
        let r = router(
            vec![provider(CHAT)],
            &[("fast", &["chat/gpt-realtime", "chat/gpt-4o"])],
        );
        let reject = expect_reject(gate(&r, "fast", None, &no_disabled()));
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.kind, "unsupported_capability");
        assert!(
            reject.message.contains("combo 'fast'"),
            "{}",
            reject.message
        );
    }

    #[test]
    fn a_combo_uses_the_combo_allowlist_rule() {
        let r = router(vec![provider(REALTIME)], &[("fast", &["rt/gpt-realtime"])]);
        let allowed = vec!["combo/fast".to_string()];
        assert!(gate(&r, "fast", Some(&allowed), &no_disabled()).is_ok());
        let allowed = vec!["combo/other".to_string()];
        let reject = expect_reject(gate(&r, "fast", Some(&allowed), &no_disabled()));
        assert_eq!(reject.status, StatusCode::FORBIDDEN);
    }

    // ----- query string -----

    #[test]
    fn the_model_query_parameter_is_decoded() {
        assert_eq!(
            query_param(Some("model=rt%2Fgpt-realtime"), "model"),
            Some("rt/gpt-realtime".to_string())
        );
        assert_eq!(
            query_param(Some("api-version=1&model=rt/gpt-realtime&x=2"), "model"),
            Some("rt/gpt-realtime".to_string())
        );
        assert_eq!(query_param(Some("model="), "model"), None);
        assert_eq!(query_param(Some("other=1"), "model"), None);
        assert_eq!(query_param(None, "model"), None);
        // Trimming keeps a stray space out of the model id.
        assert_eq!(
            query_param(Some("model=%20rt%2Fm%20"), "model"),
            Some("rt/m".to_string())
        );
    }

    #[test]
    fn upstream_model_ids_are_percent_encoded() {
        assert_eq!(
            percent_encode("gpt-4o-realtime-preview"),
            "gpt-4o-realtime-preview"
        );
        assert_eq!(percent_encode("a b&c=d"), "a%20b%26c%3Dd");
    }

    // ----- client handshake -----

    fn client_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().expect("header"));
        headers.insert("connection", "keep-alive, Upgrade".parse().expect("header"));
        headers.insert("sec-websocket-version", "13".parse().expect("header"));
        headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().expect("header"),
        );
        headers
    }

    #[test]
    fn a_valid_handshake_yields_the_accept_value() {
        let handshake = validate_handshake(&client_headers()).expect("valid handshake");
        assert_eq!(handshake.key, "dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(
            ws::accept_key(&handshake.key),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(handshake.subprotocol, None);
    }

    #[test]
    fn handshake_headers_are_required_and_validated() {
        for missing in [
            "upgrade",
            "connection",
            "sec-websocket-version",
            "sec-websocket-key",
        ] {
            let mut headers = client_headers();
            headers.remove(missing);
            let err = validate_handshake(&headers).expect_err(missing);
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "{missing}");
        }

        let mut headers = client_headers();
        headers.insert("sec-websocket-version", "8".parse().expect("header"));
        let err = validate_handshake(&headers).expect_err("old version");
        assert!(err.message().contains("only 13"), "{}", err.message());

        let mut headers = client_headers();
        headers.insert("sec-websocket-key", "short".parse().expect("header"));
        let err = validate_handshake(&headers).expect_err("bad key");
        assert!(err.message().contains("16 bytes"), "{}", err.message());

        let mut headers = client_headers();
        headers.insert("upgrade", "h2c".parse().expect("header"));
        let err = validate_handshake(&headers).expect_err("wrong upgrade");
        assert!(err.message().contains("websocket"), "{}", err.message());
    }

    #[test]
    fn the_realtime_subprotocol_is_preferred_when_echoed() {
        let mut headers = client_headers();
        headers.insert(
            "sec-websocket-protocol",
            "chat, realtime".parse().expect("header"),
        );
        assert_eq!(choose_subprotocol(&headers), Some("realtime".to_string()));

        let mut headers = client_headers();
        headers.insert(
            "sec-websocket-protocol",
            "chat, binary".parse().expect("header"),
        );
        assert_eq!(choose_subprotocol(&headers), Some("chat".to_string()));

        // A value that is not a token list (spaces, CR/LF) is never echoed back:
        // it would be header injection.
        let mut headers = client_headers();
        headers.insert(
            "sec-websocket-protocol",
            "not a token".parse().expect("header"),
        );
        assert_eq!(choose_subprotocol(&headers), None);
    }

    // ----- upstream endpoint derivation -----

    #[test]
    fn https_becomes_wss_and_keeps_the_configured_path() {
        let endpoint = upstream_endpoint("https://api.openai.com/v1", "gpt-4o-realtime-preview")
            .expect("endpoint");
        assert_eq!(
            endpoint,
            Endpoint {
                tls: true,
                host: "api.openai.com".to_string(),
                host_header: "api.openai.com".to_string(),
                port: 443,
                path: "/v1/realtime?model=gpt-4o-realtime-preview".to_string(),
            }
        );
    }

    #[test]
    fn a_bare_host_gets_the_realtime_path_and_the_default_port() {
        let endpoint = upstream_endpoint("http://127.0.0.1", "m").expect("endpoint");
        assert!(!endpoint.tls);
        assert_eq!(endpoint.port, 80);
        assert_eq!(endpoint.path, "/realtime?model=m");
        let endpoint = upstream_endpoint("wss://example.test:8443", "m").expect("endpoint");
        assert!(endpoint.tls);
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.path, "/realtime?model=m");
    }

    #[test]
    fn a_path_that_already_ends_in_realtime_is_not_duplicated() {
        let endpoint = upstream_endpoint("ws://127.0.0.1:9000/v1/realtime", "m").expect("endpoint");
        assert_eq!(endpoint.path, "/v1/realtime?model=m");
    }

    #[test]
    fn ipv6_literals_keep_their_brackets_in_the_host_header() {
        let endpoint = upstream_endpoint("ws://[::1]:9000/v1", "m").expect("endpoint");
        assert_eq!(endpoint.host, "::1");
        assert_eq!(endpoint.host_header, "[::1]");
        assert_eq!(endpoint.port, 9000);
    }

    #[test]
    fn unsupported_base_urls_are_refused_not_guessed() {
        assert!(upstream_endpoint("", "m").is_err());
        assert!(upstream_endpoint("api.openai.com/v1", "m").is_err());
        assert!(upstream_endpoint("ftp://api.openai.com/v1", "m").is_err());
        assert!(upstream_endpoint("https://user:pw@api.openai.com/v1", "m").is_err());
        assert!(upstream_endpoint("https://api.openai.com:99999/v1", "m").is_err());
        assert!(upstream_endpoint("https://[::1/v1", "m").is_err());
    }

    // ----- upstream handshake bytes -----

    #[test]
    fn the_upstream_handshake_carries_the_key_and_the_model() {
        let endpoint =
            upstream_endpoint("https://api.openai.com/v1", "rt-model").expect("endpoint");
        let request = handshake_request(
            &endpoint,
            "dGhlIHNhbXBsZSBub25jZQ==",
            "sk-secret",
            Some("realtime"),
            &[("OpenAI-Beta".to_string(), "realtime=v1".to_string())],
        )
        .expect("request");
        assert!(request.starts_with("GET /v1/realtime?model=rt-model HTTP/1.1\r\n"));
        assert!(request.contains("\r\nHost: api.openai.com\r\n"));
        assert!(request.contains("\r\nUpgrade: websocket\r\n"));
        assert!(request.contains("\r\nConnection: Upgrade\r\n"));
        assert!(request.contains("\r\nAuthorization: Bearer sk-secret\r\n"));
        assert!(request.contains("\r\nSec-WebSocket-Version: 13\r\n"));
        assert!(request.contains("\r\nSec-WebSocket-Protocol: realtime\r\n"));
        assert!(request.contains("\r\nOpenAI-Beta: realtime=v1\r\n"));
        assert!(request.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_header_injection_cannot_be_built_into_the_handshake() {
        let endpoint = upstream_endpoint("ws://127.0.0.1:1/v1", "m").expect("endpoint");
        // A key with a line break is refused outright.
        assert!(handshake_request(&endpoint, "k", "sk\r\nX-Evil: 1", None, &[]).is_err());
        // Extra headers carrying a line break are dropped, not forwarded.
        let request = handshake_request(
            &endpoint,
            "k",
            "sk",
            None,
            &[("X-Evil".to_string(), "a\r\nX-Other: b".to_string())],
        )
        .expect("request");
        assert!(!request.contains("X-Evil"), "{request}");
    }

    #[test]
    fn only_a_101_with_the_right_accept_is_accepted() {
        let accept = ws::accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        let good = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}"
        );
        assert!(verify_handshake_response(&good, &accept).is_ok());

        let wrong = good.replace(&accept, "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        let err = verify_handshake_response(&wrong, &accept).expect_err("wrong accept");
        assert!(err.contains("does not match"), "{err}");

        // Both tokens present, but no accept: the accept is what proves the peer
        // understood the handshake.
        let missing =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade"
                .to_string();
        let err = verify_handshake_response(&missing, &accept).expect_err("missing accept");
        assert!(err.contains("no Sec-WebSocket-Accept"), "{err}");

        // Both tokens are matched case-insensitively and as list members.
        let cased = format!(
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\n\
             connection: keep-alive, UPGRADE\r\nSec-WebSocket-Accept: {accept}"
        );
        assert!(
            verify_handshake_response(&cased, &accept).is_ok(),
            "header names and tokens are case-insensitive"
        );

        let refused = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0";
        let err = verify_handshake_response(refused, &accept).expect_err("401");
        assert!(err.contains("401"), "{err}");

        let garbage = "SSH-2.0-OpenSSH";
        let err = verify_handshake_response(garbage, &accept).expect_err("not http");
        assert!(err.contains("not an HTTP response"), "{err}");
    }

    /// A 101 that does not actually confirm the protocol switch, or that promises
    /// body bytes, must be refused: those bytes would be parsed as frames.
    #[test]
    fn a_101_that_is_not_a_clean_upgrade_is_refused() {
        let accept = ws::accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        let make = |extra: &str| {
            format!("HTTP/1.1 101 Switching Protocols\r\n{extra}Sec-WebSocket-Accept: {accept}")
        };

        // Missing `Upgrade: websocket`.
        let err = verify_handshake_response(&make("Connection: Upgrade\r\n"), &accept)
            .expect_err("no Upgrade header");
        assert!(err.contains("Upgrade: websocket"), "{err}");

        // Missing `Connection: Upgrade`.
        let err = verify_handshake_response(&make("Upgrade: websocket\r\n"), &accept)
            .expect_err("no Connection token");
        assert!(err.contains("Connection: Upgrade"), "{err}");

        // `Connection: keep-alive` on its own does not switch protocols.
        let err = verify_handshake_response(
            &make("Upgrade: websocket\r\nConnection: keep-alive\r\n"),
            &accept,
        )
        .expect_err("connection is not an upgrade");
        assert!(err.contains("Connection: Upgrade"), "{err}");

        // A 101 that declares a body: those five bytes would be replayed as frames.
        let err = verify_handshake_response(
            &make("Upgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 5\r\n"),
            &accept,
        )
        .expect_err("a 101 cannot have a body");
        assert!(err.contains("declares a body"), "{err}");

        // Any transfer coding is a body too, with or without a length.
        let err = verify_handshake_response(
            &make("Upgrade: websocket\r\nConnection: Upgrade\r\nTransfer-Encoding: chunked\r\n"),
            &accept,
        )
        .expect_err("chunked is still a body");
        assert!(err.contains("declares a body"), "{err}");

        // `Content-Length: 0` (and 00) are harmless and still accepted.
        for zero in ["0", "00"] {
            let head = make(&format!(
                "Upgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: {zero}\r\n"
            ));
            assert!(
                verify_handshake_response(&head, &accept).is_ok(),
                "Content-Length: {zero} declares no body"
            );
        }
    }

    #[test]
    fn a_failed_handshake_maps_onto_the_key_health_model() {
        assert!(matches!(
            UpstreamError::Status(401, String::new()).fail_kind(),
            FailKind::Auth
        ));
        assert!(matches!(
            UpstreamError::Status(429, String::new()).fail_kind(),
            FailKind::RateLimited { .. }
        ));
        assert!(matches!(
            UpstreamError::Status(503, String::new()).fail_kind(),
            FailKind::Server
        ));
        assert!(matches!(
            UpstreamError::Status(400, String::new()).fail_kind(),
            FailKind::Network
        ));
        assert!(matches!(
            UpstreamError::Network(String::new()).fail_kind(),
            FailKind::Network
        ));
    }

    #[test]
    fn pem_certificates_are_extracted() {
        let der = b"not really a certificate".to_vec();
        let body = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!(
            "# a comment\n-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n\
             -----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        );
        let certificates = pem_certificates(&pem);
        assert_eq!(certificates, vec![der]);
        assert!(pem_certificates("no pem here").is_empty());
    }

    #[test]
    fn the_model_is_read_from_the_first_message() {
        assert_eq!(
            model_from_message(
                br#"{"type":"session.update","session":{"model":"rt/gpt-realtime"}}"#
            ),
            Some("rt/gpt-realtime".to_string())
        );
        assert_eq!(
            model_from_message(br#"{"model":"rt/gpt-realtime","type":"session.update"}"#),
            Some("rt/gpt-realtime".to_string())
        );
        assert_eq!(
            model_from_message(br#"{"type":"input_audio_buffer.append","audio":"AAAA"}"#),
            None
        );
        assert_eq!(model_from_message(b"not json"), None);
        assert_eq!(model_from_message(br#"{"session":{"model":"   "}}"#), None);
    }

    // ----- relay -----

    /// A fake provider that completes our handshake and echoes data messages.
    async fn fake_echo_provider(listener: TcpListener, expected_path: &'static str) {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let (head, leftover) = read_http_head(&mut socket).await.expect("handshake head");
        assert!(leftover.is_empty(), "no frame may precede our 101");
        assert!(
            head.starts_with(&format!("GET {expected_path} HTTP/1.1")),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("authorization: bearer sk-echo"),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("sec-websocket-protocol: realtime"),
            "{head}"
        );
        let key = head
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .expect("key")
            .trim()
            .to_string();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            ws::accept_key(&key)
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("write 101");

        let (reader, mut writer) = tokio::io::split(socket);
        let mut frames = FrameReader::server_side(reader);
        while let Ok(Some(frame)) = frames.next_message().await {
            if frame.opcode == OpCode::Close {
                break;
            }
            if ws::write_frame(&mut writer, &frame).await.is_err() {
                break;
            }
        }
    }

    #[tokio::test]
    async fn relays_frames_through_a_real_socket_and_echoes_them_back() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(fake_echo_provider(
            listener,
            "/v1/realtime?model=echo-model",
        ));

        // The gateway side of the client connection.
        let (client_io, relay_client) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move {
            let (upstream, pending) = open_upstream(
                "fake",
                &format!("http://{addr}/v1"),
                "sk-echo",
                "echo-model",
                Some("realtime"),
                &[],
            )
            .await
            .expect("upstream handshake");
            let (reader, writer) = tokio::io::split(relay_client);
            relay_io(
                FrameReader::server_side(reader),
                writer,
                Vec::new(),
                upstream,
                pending,
                Limits::default(),
                "test-model",
            )
            .await
        });

        // The test plays the client: masked frames out, unmasked frames in.
        let (client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut client = FrameReader::client_side(client_reader);
        ws::write_frame_masked(
            &mut client_writer,
            &Frame::text(r#"{"type":"response.create"}"#),
        )
        .await
        .expect("send text");
        let echoed = client.next_message().await.expect("read").expect("echo");
        assert_eq!(echoed.opcode, OpCode::Text);
        assert_eq!(echoed.payload, br#"{"type":"response.create"}"#);

        // A ping is answered by the gateway on this hop, not forwarded.
        ws::write_frame_masked(&mut client_writer, &Frame::ping(b"k".to_vec()))
            .await
            .expect("send ping");
        let pong = client.next_message().await.expect("read").expect("pong");
        assert_eq!(pong.opcode, OpCode::Pong);
        assert_eq!(pong.payload, b"k");

        // Closing from the client ends the session and is echoed back.
        ws::write_frame_masked(&mut client_writer, &Frame::close(1000, "bye"))
            .await
            .expect("send close");
        let close = client.next_message().await.expect("read").expect("close");
        assert_eq!(close.opcode, OpCode::Close);
        assert_eq!(close.close_code(), Some(1000));

        assert_eq!(relay.await.expect("relay task"), Outcome::ClientClosed);
        server.await.expect("fake provider");
    }

    #[tokio::test]
    async fn handshake_leftover_bytes_become_the_first_frames() {
        // A provider may send its first event in the same segment as the 101.
        // Those bytes must not be dropped with the response head.
        let mut frame_bytes = Vec::new();
        ws::write_frame(&mut frame_bytes, &Frame::text("welcome"))
            .await
            .expect("encode");
        let mut wire = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".to_vec();
        wire.extend_from_slice(&frame_bytes);

        let mut cursor: &[u8] = &wire;
        let (head, leftover) = read_http_head(&mut cursor).await.expect("head");
        assert!(head.starts_with("HTTP/1.1 101"));
        assert!(!leftover.is_empty(), "the frame arrived with the head");

        let mut reader = FrameReader::client_side(&mut cursor);
        reader.prepend(&leftover);
        let frame = reader.next_message().await.expect("read").expect("frame");
        assert_eq!(frame.opcode, OpCode::Text);
        assert_eq!(frame.payload, b"welcome");
    }

    // ----- end to end: axum server, hyper upgrade, provider, relay -----

    /// Minimal `AppState` for the end-to-end test: a router and defaults.
    fn test_state(router: ProviderRouter) -> Arc<AppState> {
        use std::collections::{HashMap, VecDeque};
        use std::sync::atomic::AtomicU64;
        use std::sync::{Mutex, RwLock};

        Arc::new(AppState {
            router: arc_swap::ArcSwap::from_pointee(router),
            cfg: RwLock::new(super::super::RtConfig {
                max_retries: 2,
                attempt_timeout: Duration::from_secs(30),
                api_key: None,
                admin_key: None,
                events_history: 8,
                requests_history: 8,
                auth_fail_burst: 5,
                auth_fail_window: Duration::from_secs(60),
                client_key_max_concurrent: 0,
                tls_enabled: false,
                ratelimit: crate::config::RateLimitConfig::default(),
                cors_origins: std::sync::Arc::new(Vec::new()),
            }),
            storage: None,
            config_path: String::new(),
            events: crate::events::EventBus::new(8),
            auth_state: Mutex::new(None),
            auth_task: Mutex::new(None),
            auth_code_tx: Mutex::new(None),
            auth_start_lock: tokio::sync::Mutex::new(()),
            auth_fails: Mutex::new(crate::middleware::AuthFailures::default()),
            catalog_epoch: AtomicU64::new(0),
            tls_enabled_flag: std::sync::atomic::AtomicBool::new(false),
            models_cache: Mutex::new(None),
            request_log: Mutex::new(VecDeque::new()),
            client_keys: RwLock::new(HashMap::new()),
            disabled_models: RwLock::new(HashSet::new()),
            model_limits: RwLock::new(crate::config::ModelLimits::default()),
            config_lock: tokio::sync::Mutex::new(()),
            tuning: arc_swap::ArcSwap::from_pointee(Tuning::default()),
        })
    }

    /// End to end: a real axum server, the real handler, hyper's upgrade, the
    /// HyperIo bridge, a real TCP provider, and a hand-written websocket client.
    ///
    /// This is the only test that proves the *upgrade* half works: everything
    /// else exercises the codec and the relay in isolation.
    #[tokio::test]
    async fn the_whole_path_works_through_axum_and_hyper_upgrade() {
        let provider_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let provider_addr = provider_listener.local_addr().expect("addr");
        let provider_task = tokio::spawn(fake_echo_provider(
            provider_listener,
            "/v1/realtime?model=echo-model",
        ));

        let source = format!(
            r#"
            name = "rt"
            type = "openai_compat"
            base_url = "http://{provider_addr}/v1"
            keys = ["sk-echo"]
            models = ["echo-model"]
            capabilities = ["realtime"]
            "#
        );
        let state = test_state(router(vec![provider(&source)], &[]));
        let app = axum::Router::new()
            .route("/v1/realtime", axum::routing::get(realtime))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway_addr = listener.local_addr().expect("addr");
        let gateway = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let socket = TcpStream::connect(gateway_addr).await.expect("connect");
        let mut socket = socket;
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let request = format!(
            "GET /v1/realtime?model=rt/echo-model HTTP/1.1\r\nHost: localhost\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Protocol: realtime\r\n\r\n"
        );
        socket
            .write_all(request.as_bytes())
            .await
            .expect("write handshake");

        let (head, leftover) = tokio::time::timeout(CONNECT_TIMEOUT, read_http_head(&mut socket))
            .await
            .expect("the gateway answered the upgrade")
            .expect("readable head");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        let expected_accept = ws::accept_key(key).to_ascii_lowercase();
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("sec-websocket-accept: {expected_accept}")),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("sec-websocket-protocol: realtime"),
            "the client's subprotocol must be echoed: {head}"
        );

        let (reader, mut writer) = tokio::io::split(socket);
        let mut client = FrameReader::client_side(reader);
        client.prepend(&leftover);

        ws::write_frame_masked(&mut writer, &Frame::text(r#"{"type":"response.create"}"#))
            .await
            .expect("send");
        let echoed = tokio::time::timeout(Duration::from_secs(10), client.next_message())
            .await
            .expect("the provider's echo came back")
            .expect("read")
            .expect("frame");
        assert_eq!(echoed.opcode, OpCode::Text);
        assert_eq!(echoed.payload, br#"{"type":"response.create"}"#);

        ws::write_frame_masked(&mut writer, &Frame::close(1000, "bye"))
            .await
            .expect("close");
        let closed = tokio::time::timeout(Duration::from_secs(10), client.next_message())
            .await
            .expect("the close was echoed")
            .expect("read")
            .expect("frame");
        assert_eq!(closed.opcode, OpCode::Close);
        assert_eq!(closed.close_code(), Some(1000));

        provider_task.await.expect("fake provider");
        gateway.abort();
    }

    /// The same path, but the model arrives in the first message instead of the
    /// query string (the shape some clients use). The buffered message must be
    /// replayed upstream once the provider is known.
    #[tokio::test]
    async fn the_model_may_arrive_in_the_first_message() {
        let provider_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let provider_addr = provider_listener.local_addr().expect("addr");
        let provider_task = tokio::spawn(fake_echo_provider(
            provider_listener,
            "/v1/realtime?model=echo-model",
        ));

        let source = format!(
            r#"
            name = "rt"
            type = "openai_compat"
            base_url = "http://{provider_addr}/v1"
            keys = ["sk-echo"]
            models = ["echo-model"]
            capabilities = ["realtime"]
            "#
        );
        let state = test_state(router(vec![provider(&source)], &[]));
        let app = axum::Router::new()
            .route("/v1/realtime", axum::routing::get(realtime))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway_addr = listener.local_addr().expect("addr");
        let gateway = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let socket = TcpStream::connect(gateway_addr).await.expect("connect");
        let mut socket = socket;
        let request = "GET /v1/realtime HTTP/1.1\r\nHost: localhost\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Protocol: realtime\r\n\r\n";
        socket.write_all(request.as_bytes()).await.expect("write");

        let (head, leftover) = tokio::time::timeout(CONNECT_TIMEOUT, read_http_head(&mut socket))
            .await
            .expect("the gateway answered the upgrade")
            .expect("readable head");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");

        let (reader, mut writer) = tokio::io::split(socket);
        let mut client = FrameReader::client_side(reader);
        client.prepend(&leftover);

        let update = r#"{"type":"session.update","session":{"model":"rt/echo-model"}}"#;
        ws::write_frame_masked(&mut writer, &Frame::text(update))
            .await
            .expect("send session.update");
        let echoed = tokio::time::timeout(Duration::from_secs(10), client.next_message())
            .await
            .expect("the update was relayed and echoed")
            .expect("read")
            .expect("frame");
        // The provider only knows its own model name. Relaying the client's
        // `rt/echo-model` verbatim made `session.model` (which wins over `?model=`)
        // an unknown model for the provider — and `session.update` is atomic, so
        // the rest of the message was dropped with it.
        let echoed: serde_json::Value =
            serde_json::from_slice(&echoed.payload).expect("the relayed frame is JSON");
        assert_eq!(echoed["type"], "session.update");
        assert_eq!(
            echoed.pointer("/session/model").and_then(|m| m.as_str()),
            Some("echo-model"),
            "the upstream model id replaces the client-facing one: {echoed}"
        );

        ws::write_frame_masked(&mut writer, &Frame::close(1000, ""))
            .await
            .expect("close");
        provider_task.await.expect("fake provider");
        gateway.abort();
    }

    /// Status code of one plain GET through the gateway.
    ///
    /// The concurrency check needs a second request while a websocket is open, and
    /// a raw request keeps the test free of a client dependency.
    async fn http_status(addr: std::net::SocketAddr, path: &str) -> u16 {
        let mut sock = TcpStream::connect(addr).await.expect("connect");
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer sk-ws\r\n\
             Connection: close\r\n\r\n"
        );
        sock.write_all(request.as_bytes()).await.expect("write");
        let mut head = Vec::new();
        let mut chunk = [0u8; 512];
        while head.len() < 64 {
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&head)
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    /// The per-client-key concurrency slot must survive the 101.
    ///
    /// `require_api_key` puts the guard in the *request* extensions for an upgrade,
    /// so the handler has to take it and keep it in the session context. Left on
    /// the (already returned) response instead, the key's counter would drop back
    /// to zero the moment the 101 left the handler and a second request from the
    /// same key would be let in while this socket is still live — exactly the cap
    /// `max_concurrent` exists to enforce. With `max_concurrent = 1` that is the
    /// difference between 429 and 200 below.
    #[tokio::test]
    async fn the_client_key_concurrency_slot_is_held_for_the_whole_session() {
        let provider_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let provider_addr = provider_listener.local_addr().expect("addr");
        let provider_task = tokio::spawn(fake_echo_provider(
            provider_listener,
            "/v1/realtime?model=echo-model",
        ));

        let source = format!(
            r#"
            name = "rt"
            type = "openai_compat"
            base_url = "http://{provider_addr}/v1"
            keys = ["sk-echo"]
            models = ["echo-model"]
            capabilities = ["realtime"]
            "#
        );
        let state = test_state(router(vec![provider(&source)], &[]));
        state
            .client_keys
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                "sk-ws".to_string(),
                Arc::new(crate::proxy::ClientKeyRuntime::new(
                    crate::config::ClientKeyConfig {
                        key: "sk-ws".to_string(),
                        name: Some("ws-key".to_string()),
                        models: Vec::new(),
                        created_at: None,
                        rpm: None,
                        burst: None,
                        max_concurrent: Some(1),
                    },
                )),
            );
        let app = axum::Router::new()
            .route("/v1/realtime", axum::routing::get(realtime))
            .route("/v1/ping", axum::routing::get(|| async { "pong" }))
            .with_state(state.clone())
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::require_api_key,
            ));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway_addr = listener.local_addr().expect("addr");
        let gateway = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut socket = TcpStream::connect(gateway_addr).await.expect("connect");
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let request = format!(
            "GET /v1/realtime?model=rt/echo-model HTTP/1.1\r\nHost: localhost\r\n\
             Authorization: Bearer sk-ws\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: realtime\r\n\r\n"
        );
        socket
            .write_all(request.as_bytes())
            .await
            .expect("write handshake");
        let (head, leftover) = tokio::time::timeout(CONNECT_TIMEOUT, read_http_head(&mut socket))
            .await
            .expect("the gateway answered the upgrade")
            .expect("readable head");
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");

        // The socket is open and nothing has closed it: the key's only slot is
        // still taken, so the same key cannot start another request.
        assert_eq!(
            http_status(gateway_addr, "/v1/ping").await,
            429,
            "the concurrency slot must still be held after the 101 was returned"
        );

        // Closing the websocket ends the session, which must give the slot back.
        let (reader, mut writer) = tokio::io::split(socket);
        let mut client = FrameReader::client_side(reader);
        client.prepend(&leftover);
        ws::write_frame_masked(&mut writer, &Frame::close(1000, "bye"))
            .await
            .expect("send close");
        let closed = tokio::time::timeout(Duration::from_secs(10), client.next_message())
            .await
            .expect("the close was echoed")
            .expect("read")
            .expect("frame");
        assert_eq!(closed.close_code(), Some(1000));

        let mut released = false;
        for _ in 0..100 {
            if http_status(gateway_addr, "/v1/ping").await == 200 {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(released, "the slot must be released when the session ends");

        provider_task.await.expect("fake provider");
        gateway.abort();
    }

    #[tokio::test]
    async fn a_silent_session_hits_the_idle_timeout() {
        let (_client_io, relay_client) = tokio::io::duplex(1024);
        let (upstream_io, _upstream_peer) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(relay_client);
        let outcome = relay_io(
            FrameReader::server_side(reader),
            writer,
            Vec::new(),
            upstream_io,
            Vec::new(),
            Limits {
                idle: Duration::from_millis(20),
                max_bytes: 1024,
                ..Limits::default()
            },
            "test-model",
        )
        .await;
        assert_eq!(outcome, Outcome::Idle);
    }

    /// A peer that stops reading used to pin the relay forever: `write_all` sat
    /// inside a `select!` arm body, so the idle timer was never polled again and
    /// the task, both sockets and the provider key slot stayed allocated. The write
    /// deadline turns that into an ordinary session error.
    #[tokio::test]
    async fn a_client_that_stops_reading_cannot_pin_the_session() {
        // 1 KiB window, and nobody ever reads the far end.
        let (_stuck_client, relay_client) = tokio::io::duplex(1024);
        let (upstream_io, mut upstream_peer) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(relay_client);
        let relay = tokio::spawn(relay_io(
            FrameReader::server_side(reader),
            writer,
            Vec::new(),
            upstream_io,
            Vec::new(),
            Limits {
                idle: Duration::from_secs(30),
                max_bytes: MAX_SESSION_BYTES,
                write_timeout: Duration::from_millis(20),
                lifetime: Duration::from_secs(30),
            },
            "test-model",
        ));

        // The provider sends one frame far larger than the client's window.
        ws::write_frame(&mut upstream_peer, &Frame::binary(vec![9u8; 32 * 1024]))
            .await
            .expect("the provider's frame is buffered");

        let outcome = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("a peer that does not read must not pin the relay task")
            .expect("relay task");
        match outcome {
            Outcome::Error(message) => {
                assert!(message.contains("timed out"), "{message}");
            }
            other => panic!("expected a write timeout, got {other:?}"),
        }
    }

    /// Pings refresh the idle timer, so without an absolute lifetime a peer could
    /// hold a session (and a provider key slot) forever. The close code is 1001:
    /// "going away", i.e. reconnect, not "you did something wrong".
    #[tokio::test]
    async fn a_session_kept_alive_with_pings_still_ends_at_its_lifetime() {
        let (client_peer, relay_client) = tokio::io::duplex(8192);
        let (peer_reader, mut peer_writer) = tokio::io::split(client_peer);
        let (upstream_io, _upstream_peer) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(relay_client);
        let relay = tokio::spawn(relay_io(
            FrameReader::server_side(reader),
            writer,
            Vec::new(),
            upstream_io,
            Vec::new(),
            Limits {
                // Idle is far away: only the absolute lifetime can end this.
                idle: Duration::from_secs(30),
                max_bytes: MAX_SESSION_BYTES,
                write_timeout: Duration::from_millis(200),
                lifetime: Duration::from_millis(50),
            },
            "test-model",
        ));
        let pinger = tokio::spawn(async move {
            loop {
                if ws::write_frame_masked(&mut peer_writer, &Frame::ping(b"k".to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let outcome = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("the lifetime must end the session")
            .expect("relay task");
        assert_eq!(outcome, Outcome::Lifetime);
        pinger.abort();

        // Every ping was answered before the close, so the close is at the end.
        let mut peer = FrameReader::client_side(peer_reader);
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(5), peer.next_message())
                .await
                .expect("a frame before the close")
                .expect("readable")
                .expect("frame");
            if frame.opcode == OpCode::Close {
                assert_eq!(
                    frame.close_code(),
                    Some(1001),
                    "1001 tells the client to reconnect"
                );
                break;
            }
            assert_eq!(frame.opcode, OpCode::Pong);
        }
    }

    /// The session budget is a hard cap: it refuses at the limit, does not count a
    /// refused attempt, and a dropped slot is immediately reusable.
    #[test]
    fn the_session_budget_refuses_at_the_cap_and_releases_on_drop() {
        // A build-time check of the number itself, not of runtime behaviour.
        const { assert!(MAX_SESSIONS >= 64, "the budget must fit a real deployment") };
        let active = Arc::new(AtomicUsize::new(0));
        let cap = 3;
        let mut held: Vec<SessionSlot> = Vec::new();
        for _ in 0..cap {
            held.push(acquire_session_slot(&active, cap).expect("a slot under the cap"));
        }
        assert_eq!(active.load(Ordering::Relaxed), cap);
        assert!(
            acquire_session_slot(&active, cap).is_none(),
            "the cap must refuse"
        );
        assert_eq!(
            active.load(Ordering::Relaxed),
            cap,
            "a refused acquire must not be counted"
        );
        held.pop();
        assert_eq!(active.load(Ordering::Relaxed), cap - 1);
        let again = acquire_session_slot(&active, cap).expect("the freed slot is reusable");
        assert_eq!(active.load(Ordering::Relaxed), cap);
        drop(again);
        assert_eq!(active.load(Ordering::Relaxed), cap - 1);
        // Dropping the rest returns to zero, so nothing leaks per session.
        drop(held);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn the_per_direction_byte_budget_ends_the_session() {
        let (mut client_io, relay_client) = tokio::io::duplex(8192);
        let (upstream_io, _upstream_peer) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(relay_client);
        let relay = tokio::spawn(relay_io(
            FrameReader::server_side(reader),
            writer,
            Vec::new(),
            upstream_io,
            Vec::new(),
            Limits {
                idle: Duration::from_secs(5),
                max_bytes: 4,
                ..Limits::default()
            },
            "test-model",
        ));
        ws::write_frame_masked(&mut client_io, &Frame::text("far more than four bytes"))
            .await
            .expect("send");
        let mut client = FrameReader::client_side(&mut client_io);
        let close = client.next_message().await.expect("read").expect("close");
        assert_eq!(close.opcode, OpCode::Close);
        assert_eq!(close.close_code(), Some(1008));
        assert_eq!(relay.await.expect("relay task"), Outcome::Budget);
    }
}
