//! Proxy core: application state, access control, and /v1/* handlers.
//!
//! - `access` — client-key allowlist and disabled_models matching
//! - `models` — GET /v1/models
//! - `chat`   — POST /v1/chat/completions (+ retry/fallback core shared with FIM)
//! - `embeddings` — POST /v1/embeddings (pass-through or Gemini translation)

mod access;
mod chat;
mod embeddings;
mod models;

pub use access::{combo_allowed, model_allowed, model_disabled};
pub use chat::{chat_completions, run_target_pub};
// Exposed for `cargo bench` only (hot-path measurement), not part of the HTTP surface.
pub use chat::session_key;
pub use embeddings::embeddings;
pub use models::list_models;

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
    /// Ring buffer of recent upstream attempts for the Requests tab.
    pub request_log: std::sync::Mutex<std::collections::VecDeque<crate::events::RequestRecord>>,
    /// Client API keys: key -> ClientKeyConfig.
    pub client_keys: std::sync::RwLock<std::collections::HashMap<String, std::sync::Arc<ClientKeyRuntime>>>,
    /// Disabled models (client-facing ids: "provider/model" or combo name).
    pub disabled_models: std::sync::RwLock<std::collections::HashSet<String>>,
    /// Serializes read-modify-write cycles on the TOML config file
    /// (dashboard handlers + the OAuth callback all rewrite it).
    pub config_lock: tokio::sync::Mutex<()>,
    /// Configurable timings/limits (see `config::Tuning`).
    pub tuning: std::sync::Arc<crate::config::Tuning>,
}

/// A client key at runtime: its config plus the live rate-limiter bucket.
///
/// The limiter and the rejection counter are `Arc`s so a config reload can keep
/// them when the limits did not change — otherwise editing an unrelated setting
/// (or adding another key) would hand every tenant a fresh quota.
pub struct ClientKeyRuntime {
    pub cfg: crate::config::ClientKeyConfig,
    pub limiter: Option<std::sync::Arc<crate::ratelimit::KeyRateLimit>>,
    /// Requests rejected by the rate limiter (exposed via /metrics).
    pub limited: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ClientKeyRuntime {
    pub fn new(cfg: crate::config::ClientKeyConfig) -> Self {
        let limiter = cfg
            .rpm
            .and_then(|rpm| crate::ratelimit::KeyRateLimit::new(rpm, cfg.burst.unwrap_or(0)))
            .map(std::sync::Arc::new);
        Self {
            cfg,
            limiter,
            limited: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Rebuild for a (possibly edited) config, keeping the live bucket and the
    /// counter when the limits themselves did not change.
    pub fn rebind(&self, cfg: crate::config::ClientKeyConfig) -> Self {
        if self.cfg.rpm == cfg.rpm && self.cfg.burst == cfg.burst {
            Self {
                cfg,
                limiter: self.limiter.clone(),
                limited: self.limited.clone(),
            }
        } else {
            Self::new(cfg)
        }
    }
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
