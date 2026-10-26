//! Proxy core: application state, access control, and /v1/* handlers.
//!
//! - `access` — client-key allowlist and disabled_models matching
//! - `models` — GET /v1/models
//! - `chat`   — POST /v1/chat/completions (+ retry/fallback core shared with FIM)
//! - `embeddings` — POST /v1/embeddings (pass-through or Gemini translation)
//! - `media`  — POST /v1/images/* and /v1/audio/* (binary pass-through)
//! - `realtime` — GET /v1/realtime (WebSocket pass-through, capability gated)
//! - `responses` — POST /v1/responses (OpenAI Responses API over the same pipeline)

mod access;
mod chat;
mod embeddings;
pub mod media;
mod models;
pub mod realtime;
pub mod responses;

pub use access::{combo_allowed, model_allowed, model_disabled};
pub(crate) use chat::errors::{ensure_no_hosted_tools, parse_retry_after};
pub use chat::{chat_completions, run_target_pub};
// Exposed for `cargo bench` only (hot-path measurement), not part of the HTTP surface.
pub use chat::session_key;
pub use embeddings::embeddings;
pub use models::{get_model, list_models};
pub use responses::responses;

use std::time::Duration;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::providers::ProviderRouter;

/// Hot-reloadable server settings.
#[derive(Clone)]
pub struct RtConfig {
    pub max_retries: usize,
    pub attempt_timeout: Duration,
    pub api_key: Option<String>,
    /// Admin key for /api/* and /dashboard (falls back to api_key).
    pub admin_key: Option<String>,
    pub events_history: usize,
    pub requests_history: usize,
    /// Failed-auth attempts per IP before lockout, and the window.
    pub auth_fail_burst: u32,
    pub auth_fail_window: std::time::Duration,
    /// Default in-flight cap for client keys that do not set their own (0 = off).
    pub client_key_max_concurrent: u32,
    /// True when this process serves TLS itself (drives HSTS).
    pub tls_enabled: bool,
    /// Client-key rate-limit backend (`local` or `redis`), see
    /// [`crate::distributed`]. Cloned per key on construction/rebind.
    pub ratelimit: crate::config::RateLimitConfig,
    /// Browser origins allowed cross-origin access (`[server] cors_origins`).
    /// Shared as an `Arc`: the CORS middleware reads it on every request and a
    /// reload swaps the whole vector.
    pub cors_origins: std::sync::Arc<Vec<String>>,
}

pub struct AppState {
    pub router: arc_swap::ArcSwap<ProviderRouter>,
    /// Hot-reloadable server settings, published atomically.
    ///
    /// `ArcSwap` rather than `RwLock<RtConfig>`: `rt()` is read on *every*
    /// `/v1/*` and `/api/*` request, and cloning the whole struct there copied
    /// `api_key`, `admin_key` and a `RateLimitConfig` of four `String`s per
    /// request — ~25k avoidable allocations/s at 5k rps. A reload now stores a new
    /// `Arc`, and readers clone the pointer.
    pub cfg: arc_swap::ArcSwap<RtConfig>,
    pub storage: Option<crate::storage::Storage>,
    pub config_path: String,
    pub events: crate::events::EventBus,
    /// Ongoing dashboard-triggered OAuth flow (single at a time).
    pub auth_state: std::sync::Mutex<Option<crate::api::AuthStateDto>>,
    /// Handle of the task serving that flow, so it can be aborted (frees the
    /// local callback port when the operator switches provider or cancels).
    pub auth_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Channel the authorization code is delivered through (loopback socket,
    /// public callback route or a pasted URL).
    pub auth_code_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<(String, String)>>>,
    /// Serialises OAuth flow setup: snapshot → channel → state → spawn must be one
    /// critical section, or two concurrent `POST /api/auth/start` calls clobber
    /// each other's code channel and neither flow can finish.
    pub auth_start_lock: tokio::sync::Mutex<()>,
    /// Failed authentication attempts per client IP (window + count), so a
    /// credential-stuffing loop cannot hammer the key comparison for free.
    pub auth_fails: std::sync::Mutex<crate::middleware::AuthFailures>,
    /// Bumped whenever the model catalogue can change (reload, enable/disable,
    /// refresh). `/v1/models` caches its serialized body per epoch.
    pub catalog_epoch: std::sync::atomic::AtomicU64,
    /// When each model id was first served by this process, for the `created`
    /// field OpenAI requires in a model object.
    ///
    /// A stable stamp, not `now()` per request: `created` means "when this model
    /// became available", and a value that moved on every call would break any
    /// client diffing catalogues. It is populated on first sight and kept for the
    /// life of the process; a restart re-stamps, which is the honest answer for a
    /// process-local catalogue.
    pub model_first_seen: std::sync::Mutex<std::collections::HashMap<String, u64>>,
    /// Bytes of request bodies currently being held in memory.
    ///
    /// `[server] max_body_bytes` caps ONE request; `max_concurrent` caps the number
    /// of requests. Nothing capped the product, so N concurrent 32 MiB requests
    /// could hold N x 32 MiB — the memory limit was reached before any single limit
    /// was exceeded. This counter bounds the sum: a request that would push it over
    /// the budget is refused with 503 and a `Retry-After`, before it is buffered.
    pub inflight_bytes: InflightBytes,
    /// Lock-free mirror of `RtConfig::tls_enabled` for the per-request hardening
    /// layer, which must not clone the whole config to read one bool.
    pub tls_enabled_flag: std::sync::atomic::AtomicBool,
    /// (epoch, full body) of the unfiltered catalogue. Client-key allowlists
    /// bypass it — that is the only per-request variable.
    pub models_cache: std::sync::Mutex<Option<(u64, String)>>,
    /// Ring buffer of recent upstream attempts for the Requests tab.
    pub request_log: std::sync::Mutex<std::collections::VecDeque<crate::events::RequestRecord>>,
    /// Client API keys: key -> ClientKeyConfig.
    pub client_keys:
        std::sync::RwLock<std::collections::HashMap<String, std::sync::Arc<ClientKeyRuntime>>>,
    /// Disabled models (client-facing ids: "provider/model" or combo name).
    pub disabled_models: std::sync::RwLock<std::collections::HashSet<String>>,
    /// Per-model limits (context window and token caps), with a lookup index that
    /// also answers to the bare model name.
    pub model_limits: std::sync::RwLock<crate::config::ModelLimits>,
    /// Serializes read-modify-write cycles on the TOML config file
    /// (dashboard handlers + the OAuth callback all rewrite it).
    pub config_lock: tokio::sync::Mutex<()>,
    /// Configurable timings/limits (see `config::Tuning`).
    ///
    /// Swappable in place: `POST /api/server/update` reports a `[tuning]` change
    /// as applied (no restart), so a reload has to publish a new value here —
    /// while pools, OAuth accounts and request handlers keep their handles.
    /// Read it through [`AppState::tuning`].
    pub tuning: arc_swap::ArcSwap<crate::config::Tuning>,
}

/// A client key at runtime: its config plus the live rate-limiter bucket.
///
/// The limiter and the rejection counter are `Arc`s so a config reload can keep
/// them when the limits did not change — otherwise editing an unrelated setting
/// (or adding another key) would hand every tenant a fresh quota.
pub struct ClientKeyRuntime {
    pub cfg: crate::config::ClientKeyConfig,
    pub limiter: Option<std::sync::Arc<crate::ratelimit::KeyRateLimit>>,
    /// The configured enforcement path for this key: the local bucket, or a
    /// bucket shared with every instance through Redis. `None` = unlimited
    /// (or no bucket could be built, in which case `limiter` is used).
    pub shared: Option<std::sync::Arc<crate::distributed::SharedLimiter>>,
    /// Requests rejected by the rate limiter (exposed via /metrics).
    pub limited: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// In-flight requests for this key, and the cap (0 = unlimited).
    ///
    /// Shared across [`ClientKeyRuntime::rebind`]: the guards of requests already
    /// in progress hold the old `Arc` and decrement *it* on drop, so replacing
    /// the counter with a copy of its value leaked one permit per reload — a key
    /// under load went permanently over its cap and got 429 forever.
    pub in_flight: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// Per-key override. `None` = inherit `[server] client_key_max_concurrent`;
    /// `Some(0)` = unlimited for this key (the explicit opt-out), which is why
    /// this must stay an `Option`: collapsing it to `u32` made `0` indistinguishable
    /// from "unset" and the opt-out silently impossible.
    pub max_concurrent: Option<u32>,
    /// Requests rejected because the key was already at its concurrency cap.
    pub saturated: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ClientKeyRuntime {
    /// Local-backend constructor: the per-process bucket only.
    pub fn new(cfg: crate::config::ClientKeyConfig) -> Self {
        Self::new_with(cfg, &crate::config::RateLimitConfig::default())
    }

    /// Constructor that honours `[ratelimit]`: with `backend = "redis"` the
    /// key's tokens live in Redis, so every gateway instance shares one budget.
    pub fn new_with(
        cfg: crate::config::ClientKeyConfig,
        rl: &crate::config::RateLimitConfig,
    ) -> Self {
        let limiter = local_bucket(&cfg);
        let shared = crate::distributed::SharedLimiter::for_key(&cfg, limiter.clone(), rl);
        let max_concurrent = cfg.max_concurrent;
        Self {
            cfg,
            limiter,
            shared,
            limited: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            in_flight: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_concurrent,
            saturated: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Rebuild for a (possibly edited) config, keeping the live bucket and the
    /// counter when the limits themselves did not change.
    pub fn rebind(
        &self,
        cfg: crate::config::ClientKeyConfig,
        rl: &crate::config::RateLimitConfig,
    ) -> Self {
        if self.cfg.rpm == cfg.rpm && self.cfg.burst == cfg.burst {
            let max_concurrent = cfg.max_concurrent;
            let limiter = self.limiter.clone();
            // Reuse the live limiter when the backend is unchanged, so a reload
            // keeps the (already connected) Redis pool.
            let fresh = crate::distributed::SharedLimiter::for_key(&cfg, limiter.clone(), rl);
            let shared = match (&self.shared, &fresh) {
                (Some(old), Some(new)) if old.same_config(new) => Some(old.clone()),
                _ => fresh,
            };
            Self {
                cfg,
                limiter,
                shared,
                limited: self.limited.clone(),
                // Share the live counter, do not copy its value: the guards of
                // requests in progress decrement the old one when they finish, so
                // a copy would keep the reloaded key permanently "busy".
                in_flight: self.in_flight.clone(),
                max_concurrent,
                saturated: self.saturated.clone(),
            }
        } else {
            // The limits changed, so a fresh bucket is correct — but the *live
            // counters* must still be carried over. `new_with` starts `in_flight`
            // at 0, while the guards of requests already in flight hold the old
            // `Arc` and will decrement *it* on drop. Handing out a zeroed counter
            // therefore leaks one permit per in-flight request on every reload:
            // a tenant under load ends up permanently over its cap and is 429'd
            // forever. This was fixed for the "limits unchanged" branch above; it
            // is the invariant for *every* construct-and-replace path.
            let mut fresh = Self::new_with(cfg, rl);
            fresh.in_flight = self.in_flight.clone();
            fresh.limited = self.limited.clone();
            fresh.saturated = self.saturated.clone();
            fresh
        }
    }
}

/// The per-process bucket for a key (`rpm` 0/None = unlimited).
fn local_bucket(
    cfg: &crate::config::ClientKeyConfig,
) -> Option<std::sync::Arc<crate::ratelimit::KeyRateLimit>> {
    cfg.rpm
        .and_then(|rpm| crate::ratelimit::KeyRateLimit::new(rpm, cfg.burst.unwrap_or(0)))
        .map(std::sync::Arc::new)
}

/// A client-key name safe to put in a label: the configured name, else a short
/// digest of the key. The secret itself must never reach metrics, logs or the
/// request feed — a Prometheus label is copied into a TSDB and kept forever.
pub fn client_key_label(key: &str, name: Option<&str>) -> String {
    name.map(str::to_string).unwrap_or_else(|| {
        let digest = crate::storage::secret_hash(key);
        format!("key-{}", &digest[..8.min(digest.len())])
    })
}

/// Client key permissions, populated by the auth middleware.
#[derive(Debug, Clone)]
pub struct KeyPermissions {
    /// None = all models allowed. Some(list) = allowlist.
    pub allowed_models: Option<Vec<String>>,
    #[allow(dead_code)]
    pub key_name: Option<String>,
}

impl AppState {
    /// The model catalogue may have changed: drop the cached `/v1/models` body.
    pub fn invalidate_catalog(&self) {
        self.catalog_epoch
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn log_request(&self, rec: crate::events::RequestRecord) {
        // One pointer load for one integer. Config: 0 means "in-memory default
        // (200), no persistence".
        let raw = self.cfg.load().requests_history;
        let cap = if raw == 0 { 200 } else { raw }.max(1);
        let mut log = self.request_log.lock().unwrap_or_else(|e| e.into_inner());
        while log.len() >= cap {
            log.pop_front();
        }
        log.push_back(rec);
    }

    /// The tuning every component must honour right now.
    ///
    /// Hands out a shared handle so a caller can use several values
    /// consistently even if a reload swaps the cell in between.
    pub fn tuning(&self) -> std::sync::Arc<crate::config::Tuning> {
        self.tuning.load_full()
    }

    /// The settings in force right now, as a shared handle.
    ///
    /// Callers that need one or two fields should read them straight off this;
    /// it is a pointer clone, not a deep copy.
    pub fn rt(&self) -> std::sync::Arc<RtConfig> {
        self.cfg.load_full()
    }
}

/// `error.code`: OpenAI declares it `string | null`, never a number.
///
/// The concrete token is what a client branches on (`insufficient_quota` means
/// "do not retry", `model_not_found` means "pick another model"), while the HTTP
/// number already lives in the status line. Deriving it from `type` keeps the two
/// in lock-step without threading an optional argument through 90 call sites.
pub fn error_code_for(ty: &str) -> &'static str {
    match ty {
        "invalid_request_error" => "invalid_request_error",
        "authentication_error" => "invalid_api_key",
        "permission_error" => "permission_denied",
        "not_found_error" => "not_found",
        "method_not_allowed" => "method_not_allowed",
        "timeout_error" => "timeout",
        "conflict_error" => "conflict",
        "payload_too_large" => "payload_too_large",
        // Both spellings exist in the wild (and in this tree's own call sites);
        // OpenAI calls the type `rate_limit_error` and the code
        // `rate_limit_exceeded`.
        "rate_limit_error" | "rate_limit_exceeded" => "rate_limit_exceeded",
        "insufficient_quota" => "insufficient_quota",
        _ => "api_error",
    }
}

/// The one error envelope every `/v1/*` and `/api/*` rejection goes through.
///
/// Shape per the OpenAI `Error` schema: `type` and `message` and `param` are
/// required, `code` is a string or null. `code` used to be the HTTP status as an
/// **integer**, which typed SDKs (`openai-python`'s `APIError.code: Optional[str]`)
/// reject, and `param` was missing entirely.
pub fn error_response(status: StatusCode, message: impl Into<String>, ty: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "message": message.into(),
            "type": ty,
            "code": error_code_for(ty),
            // Always present (required by the schema): non-field errors send
            // `null`, exactly like OpenAI. No call site names a field today, so
            // there is nothing to thread through.
            "param": serde_json::Value::Null,
        }
    });
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(rpm: Option<u32>, burst: Option<u32>) -> crate::config::ClientKeyConfig {
        crate::config::ClientKeyConfig {
            key: "sk-wiring".to_string(),
            name: Some("wiring".to_string()),
            models: Vec::new(),
            created_at: None,
            rpm,
            burst,
            max_concurrent: None,
        }
    }

    /// A reload that *changes* a key's limits must still keep its live counters.
    ///
    /// `rebind` used to fall back to a plain `new_with` when `rpm`/`burst`
    /// changed, and `new_with` starts `in_flight` at 0 — while the guards of
    /// requests already in flight hold the old `Arc` and decrement *it* on drop.
    /// Every such reload therefore leaked one permit per in-flight request, and a
    /// tenant under load drifted permanently over its cap and was 429'd forever.
    #[test]
    fn rebind_keeps_the_live_counters_when_the_limits_change() {
        let before = ClientKeyRuntime::new(key(Some(60), Some(2)));
        // Simulate three requests in flight, plus the rejection counters.
        for _ in 0..3 {
            before
                .in_flight
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        before
            .limited
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        before
            .saturated
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);

        // An edit that changes the limits takes the `new_with` branch.
        let after = before.rebind(
            key(Some(120), Some(5)),
            &crate::config::RateLimitConfig::default(),
        );
        assert_eq!(after.cfg.rpm, Some(120), "the new limits must apply");
        assert_eq!(
            after.in_flight.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "in-flight requests must survive a limits change"
        );
        assert_eq!(
            after.limited.load(std::sync::atomic::Ordering::Relaxed),
            7,
            "the rejection counter must survive too"
        );
        assert_eq!(
            after.saturated.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        // It must be the *same* allocation, or a finishing guard decrements a
        // counter nobody reads any more.
        assert!(
            std::sync::Arc::ptr_eq(&before.in_flight, &after.in_flight),
            "the counter must be shared, not copied"
        );
    }

    /// The `[ratelimit]` snapshot must reach every key's runtime, and the local
    /// backend must keep using the very same per-process bucket.
    #[test]
    fn client_keys_follow_the_ratelimit_backend() {
        let local_cfg = crate::config::RateLimitConfig::default();
        assert_eq!(local_cfg.backend, "local");

        let local = ClientKeyRuntime::new(key(Some(60), Some(2)));
        assert!(
            matches!(
                local.shared.as_deref(),
                Some(crate::distributed::SharedLimiter::Local(_))
            ),
            "the local backend must expose the local bucket"
        );

        let redis_cfg = crate::config::RateLimitConfig {
            backend: "redis".to_string(),
            redis_url: "redis://127.0.0.1:6379/0".to_string(),
            ..crate::config::RateLimitConfig::default()
        };
        let shared = ClientKeyRuntime::new_with(key(Some(60), Some(2)), &redis_cfg);
        match shared.shared.as_deref() {
            Some(crate::distributed::SharedLimiter::Redis(l)) => {
                // The bucket name is a digest: the client's bearer token must never
                // reach Redis, where it would sit in KEYS/MONITOR/RDB/backups.
                assert_eq!(
                    l.key(),
                    format!(
                        "anyhop:rl:{}:60:2",
                        crate::distributed::redis::digest("sk-wiring", 16)
                    )
                );
                assert!(
                    !l.key().contains("sk-wiring"),
                    "the secret must not appear in the bucket name"
                );
            }
            other => panic!("expected a redis limiter, got {other:?}"),
        }
    }

    /// E: `rebind` used to copy `in_flight` into a *new* counter, while the
    /// guards of live requests kept decrementing the old one. A handful of
    /// reloads under load left the live counter permanently above the cap, so the
    /// tenant got 429 forever.
    #[test]
    fn rebind_shares_the_live_in_flight_counter() {
        let before = ClientKeyRuntime::new(key(Some(60), Some(2)));
        let after = before.rebind(
            key(Some(60), Some(2)),
            &crate::config::RateLimitConfig::default(),
        );
        assert!(
            std::sync::Arc::ptr_eq(&before.in_flight, &after.in_flight),
            "a reload must keep one counter, not copy its value"
        );

        // A request in progress across two reloads: two permits are taken, the
        // key is reloaded twice, then the requests finish — the counter must be
        // back at zero rather than stuck at two.
        let live = std::sync::Arc::new(before);
        // Two requests in flight (what ClientKeyGuard does on the way in).
        let order = std::sync::atomic::Ordering::Relaxed;
        live.in_flight.fetch_add(1, order);
        live.in_flight.fetch_add(1, order);
        let reloaded1 = std::sync::Arc::new(live.rebind(
            key(Some(60), Some(2)),
            &crate::config::RateLimitConfig::default(),
        ));
        let reloaded2 = std::sync::Arc::new(reloaded1.rebind(
            key(Some(60), Some(2)),
            &crate::config::RateLimitConfig::default(),
        ));
        assert_eq!(
            reloaded2.in_flight.load(order),
            2,
            "the live count must be visible through the reloaded runtime"
        );
        // …and finishing (what the guard does on drop) via the *old* handle.
        live.in_flight.fetch_sub(1, order);
        live.in_flight.fetch_sub(1, order);
        assert_eq!(
            reloaded2.in_flight.load(order),
            0,
            "guards dropped the old counter while the live one stayed above the cap"
        );
    }

    #[test]
    fn unlimited_keys_carry_no_limiter() {
        let rt =
            ClientKeyRuntime::new_with(key(None, None), &crate::config::RateLimitConfig::default());
        assert!(rt.limiter.is_none());
        assert!(rt.shared.is_none());
    }

    #[test]
    fn rebind_keeps_the_live_bucket_when_the_limits_do_not_change() {
        let before = ClientKeyRuntime::new(key(Some(60), Some(2)));
        let after = before.rebind(
            key(Some(60), Some(2)),
            &crate::config::RateLimitConfig::default(),
        );
        let (a, b) = (
            before.limiter.clone().expect("bucket"),
            after.limiter.clone().expect("bucket"),
        );
        assert!(
            std::sync::Arc::ptr_eq(&a, &b),
            "a reload handed out a fresh quota"
        );
        // A changed limit does reset it.
        let changed = before.rebind(
            key(Some(30), Some(1)),
            &crate::config::RateLimitConfig::default(),
        );
        let c = changed.limiter.clone().expect("bucket");
        assert!(!std::sync::Arc::ptr_eq(&a, &c));
    }
}

/// The request feed and the label helper: what the dashboard shows *about* a
/// credential without ever holding the credential.
#[cfg(test)]
mod feed_tests {
    use super::*;

    /// A Prometheus label, a log line and the Requests tab all show this string.
    /// It must identify the key and never contain it.
    #[test]
    fn a_client_key_label_never_carries_the_secret() {
        let name = client_key_label("sk-hop-super-secret", Some("tenant-a"));
        assert_eq!(name, "tenant-a", "a configured name is used verbatim");

        let derived = client_key_label("sk-hop-super-secret", None);
        assert!(derived.starts_with("key-"), "{derived}");
        assert_eq!(derived.len(), "key-".len() + 8);
        assert_ne!(derived, "sk-hop-super-secret");
        assert!(
            !derived.contains("super-secret"),
            "the label leaked the secret: {derived}"
        );
        // Stable for the same key, different for another one.
        assert_eq!(derived, client_key_label("sk-hop-super-secret", None));
        assert_ne!(derived, client_key_label("sk-hop-other-secret", None));
    }

    /// The Requests feed is a bounded ring; a long-running gateway must not grow
    /// it without limit, and the newest attempt must be the one kept.
    #[tokio::test]
    async fn the_request_feed_is_a_bounded_ring_keeping_the_newest() {
        let path = crate::api::server::test_support::temp_config(
            crate::api::server::test_support::MINIMAL,
        );
        let st = crate::api::server::test_support::state(&path);
        let cap = st.rt().requests_history;
        assert!(cap > 0, "the fixture keeps a history");

        for i in 0..(cap + 5) {
            st.log_request(crate::events::RequestRecord {
                ts: i as u64,
                provider: "p".into(),
                model: "m".into(),
                key: "k".into(),
                status: "200".into(),
                latency_ms: i as u64,
                stream: false,
                client_key: None,
            });
        }
        let log = st.request_log.lock().unwrap();
        assert_eq!(log.len(), cap, "the feed must stay at its cap");
        assert_eq!(log.front().expect("non-empty").ts, 5, "oldest dropped");
        assert_eq!(
            log.back().expect("non-empty").ts,
            (cap + 4) as u64,
            "the newest attempt is kept"
        );
        drop(log);
        let _ = std::fs::remove_file(&path);
    }

    /// Every error path in the gateway builds its body here. The envelope is a
    /// client contract: status, `type`, human message and numeric `code`.
    #[tokio::test]
    async fn the_error_envelope_is_uniform() {
        let resp = error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "slow down",
            "rate_limit_error",
        );
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["message"], "slow down");
        assert_eq!(v["error"]["type"], "rate_limit_error");
        // The OpenAI `Error` schema types `code` as string|null and requires
        // `param`; an integer code breaks typed SDKs.
        assert_eq!(v["error"]["code"], "rate_limit_exceeded");
        assert!(v["error"]["param"].is_null(), "param must be present: {v}");
    }
}

/// A byte budget shared by every request in flight.
///
/// Counts **reserved** bytes rather than measured ones: the size is taken from
/// `Content-Length` at admission, so the decision happens before the body is read
/// into memory. A request without `Content-Length` (chunked) reserves a
/// configurable guess and settles up afterwards, so a chunked upload cannot slip
/// past the budget entirely.
///
/// The awkward cases are handled rather than ignored:
/// * a reservation is released exactly once, by a guard dropped at the end of the
///   request — including on error and cancellation paths;
/// * `settle` adjusts the reservation to the real size, so a client that
///   under-declares cannot hold less than it uses;
/// * a zero budget means "no accounting", preserving the old behaviour for
///   operators who set it to 0 deliberately.
#[derive(Debug, Default)]
pub struct InflightBytes {
    used: std::sync::atomic::AtomicU64,
    limit: std::sync::atomic::AtomicU64,
}

impl InflightBytes {
    pub fn new(limit: u64) -> Self {
        Self {
            used: std::sync::atomic::AtomicU64::new(0),
            limit: std::sync::atomic::AtomicU64::new(limit),
        }
    }

    /// Replace the budget (hot reload).
    pub fn set_limit(&self, limit: u64) {
        self.limit
            .store(limit, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn limit(&self) -> u64 {
        self.limit.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn used(&self) -> u64 {
        self.used.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reserve `want` bytes, or refuse without reserving anything.
    ///
    /// Compare-and-swap in a loop rather than fetch_add-then-check: the latter
    /// briefly overshoots the budget under a concurrent burst, which is exactly
    /// when the budget matters.
    pub fn try_reserve(&self, want: u64) -> Option<BytesGuard<'_>> {
        let limit = self.limit();
        if limit == 0 {
            return Some(BytesGuard {
                budget: self,
                held: 0,
            });
        }
        let want = want.min(limit);
        let mut current = self.used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            if current.saturating_add(want) > limit {
                return None;
            }
            match self.used.compare_exchange_weak(
                current,
                current + want,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(BytesGuard {
                        budget: self,
                        held: want,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }
}

/// Holds a reservation until dropped.
pub struct BytesGuard<'a> {
    budget: &'a InflightBytes,
    held: u64,
}

impl BytesGuard<'_> {
    /// Adjust the reservation to the bytes actually used.
    ///
    /// Under-declaring a `Content-Length` is the only way to beat an admission
    /// check, so a body that turns out larger than reserved extends the hold. If
    /// no room is left the reservation stops at the limit — the request still runs
    /// (it has already been read), but the budget stays honest about being full.
    pub fn settle(&mut self, actual: u64) {
        if actual <= self.held {
            return;
        }
        let budget = self.budget;
        let mut current = budget.used.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let extra = actual - self.held;
            let limit = budget.limit();
            let next = current.saturating_add(extra);
            let next = if limit != 0 && next > limit {
                limit
            } else {
                next
            };
            match budget.used.compare_exchange_weak(
                current,
                next,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.held = self.held.saturating_add(next - current);
                    return;
                }
                Err(actual_used) => current = actual_used,
            }
        }
    }
}

impl Drop for BytesGuard<'_> {
    fn drop(&mut self) {
        if self.held > 0 {
            self.budget
                .used
                .fetch_sub(self.held, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
mod inflight_bytes_tests {
    use super::InflightBytes;

    /// Running out of budget refuses the request *without* reserving anything.
    #[test]
    fn a_full_budget_refuses_and_holds_nothing() {
        let b = InflightBytes::new(100);
        let g1 = b.try_reserve(60).expect("60 of 100 fits");
        assert_eq!(b.used(), 60);
        assert!(
            b.try_reserve(60).is_none(),
            "60 + 60 exceeds the budget and must be refused"
        );
        assert_eq!(b.used(), 60, "a refused reservation must not be counted");
        drop(g1);
        assert_eq!(b.used(), 0, "the guard releases on drop");
        assert!(b.try_reserve(100).is_some(), "the whole budget fits again");
    }

    /// A reservation larger than the budget is clamped, not rejected outright —
    /// otherwise one oversized request would be a permanent denial of service
    /// against a small budget.
    #[test]
    fn an_oversized_reservation_is_clamped_to_the_budget() {
        let b = InflightBytes::new(100);
        let _g = b.try_reserve(10_000).expect("clamped, not refused");
        assert_eq!(b.used(), 100);
        assert!(b.try_reserve(1).is_none(), "the budget is fully held");
    }

    /// `settle` extends the hold when the real body is bigger than declared.
    #[test]
    fn settling_a_larger_body_extends_the_hold() {
        let b = InflightBytes::new(1000);
        let mut g = b.try_reserve(100).expect("fits");
        assert_eq!(b.used(), 100);
        g.settle(400);
        assert_eq!(b.used(), 400, "the hold grows to the real size");
        g.settle(50);
        assert_eq!(b.used(), 400, "settling smaller never shrinks the hold");
        drop(g);
        assert_eq!(b.used(), 0);
    }

    /// Settling past the budget stops at the limit and stays consistent on drop.
    #[test]
    fn settling_past_the_budget_does_not_underflow() {
        let b = InflightBytes::new(500);
        let mut g = b.try_reserve(100).expect("fits");
        g.settle(10_000);
        assert_eq!(b.used(), 500, "clamped to the limit");
        drop(g);
        assert_eq!(b.used(), 0, "drop releases exactly what was taken");
    }

    /// A zero budget means "no accounting", and the guard is still drop-safe.
    #[test]
    fn a_zero_budget_disables_accounting() {
        let b = InflightBytes::new(0);
        let g = b.try_reserve(u64::MAX).expect("no limit");
        assert_eq!(b.used(), 0, "nothing is counted when the budget is off");
        drop(g);
        assert_eq!(b.used(), 0);
    }

    /// Reservations from many threads never overshoot, and all are released.
    #[test]
    fn a_concurrent_burst_never_overshoots() {
        let b = std::sync::Arc::new(InflightBytes::new(1000));
        let live = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..64 {
            let b = b.clone();
            let live = live.clone();
            let peak = peak.clone();
            handles.push(std::thread::spawn(move || {
                if let Some(g) = b.try_reserve(100) {
                    let now = live.fetch_add(100, std::sync::atomic::Ordering::AcqRel) + 100;
                    peak.fetch_max(now, std::sync::atomic::Ordering::AcqRel);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    live.fetch_sub(100, std::sync::atomic::Ordering::AcqRel);
                    drop(g);
                }
            }));
        }
        for h in handles {
            h.join().expect("no panic");
        }
        assert!(
            peak.load(std::sync::atomic::Ordering::Relaxed) <= 1000,
            "live bytes must never exceed the budget, peak was {}",
            peak.load(std::sync::atomic::Ordering::Relaxed)
        );
        assert_eq!(b.used(), 0, "every reservation was released");
    }
}
