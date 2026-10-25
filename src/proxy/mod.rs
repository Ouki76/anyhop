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
pub(crate) use chat::errors::parse_retry_after;
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
    pub cfg: std::sync::RwLock<RtConfig>,
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
    pub max_concurrent: u32,
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
        let max_concurrent = cfg.max_concurrent.unwrap_or(0);
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
            let max_concurrent = cfg.max_concurrent.unwrap_or(0);
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
            Self::new_with(cfg, rl)
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
        // Short read guard for one integer instead of cloning the whole RtConfig.
        // Config: 0 means "in-memory default (200), no persistence".
        let raw = self
            .cfg
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .requests_history;
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

    pub fn rt(&self) -> RtConfig {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
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
        assert_eq!(v["error"]["code"], 429);
    }
}
