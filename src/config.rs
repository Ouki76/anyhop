use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub combos: Vec<ComboConfig>,
    #[serde(default)]
    pub client_keys: Vec<ClientKeyConfig>,
    #[serde(default)]
    pub disabled_models: Vec<String>,
    /// Runtime knobs that used to be hardcoded constants.
    #[serde(default)]
    pub tuning: Tuning,
    /// Where client-key limits are enforced.
    #[serde(default)]
    pub ratelimit: RateLimitConfig,
}

/// Client-key rate limiting backend.
///
/// `local` keeps token buckets in this process (single instance). `redis` shares
/// them through Redis over RESP, so N instances enforce one budget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RateLimitConfig {
    pub backend: String,
    /// `redis://[user:pass@]host:port/db` (redis:// only; TLS via stunnel).
    pub redis_url: String,
    /// Prefix for every key written to Redis.
    pub key_prefix: String,
    /// Fail open (allow) or closed (deny) when Redis is unreachable.
    pub fail_open: bool,
    /// Per-command timeout.
    pub timeout_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            backend: "local".to_string(),
            redis_url: "redis://127.0.0.1:6379/0".to_string(),
            key_prefix: "anyhop".to_string(),
            fail_open: true,
            timeout_ms: 50,
        }
    }
}

/// Operationally interesting timings and limits.
///
/// Every field is a value that used to be a `const` in the code; they are exposed
/// so an operator can tune behaviour per deployment instead of recompiling.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Tuning {
    /// Cap on how long a failed key can stay benched.
    pub max_cooldown_secs: u64,
    /// Backoff base for 5xx / network failures (grows with consecutive failures).
    pub base_backoff_secs: u64,
    /// Cooldown for a 429 that arrives without a Retry-After header.
    pub rate_limit_cooldown_secs: u64,
    /// Fallback cooldown when a provider reports an unknown reset window.
    pub drain_fallback_secs: u64,
    /// How long a fetched upstream model list stays fresh.
    pub models_cache_ttl_secs: u64,
    /// Connect timeout for upstream calls.
    pub connect_timeout_secs: u64,
    /// Timeout for side calls (model listing, quota probes).
    pub meta_timeout_secs: u64,
    /// Sticky routing mode:
    /// * `hash` (default) — rendezvous hashing over the live key set. No shared
    ///   state, so N instances route the same conversation to the same key.
    /// * `map` — per-process session→key map with the TTL below; only correct
    ///   with a single instance.
    pub sticky_mode: String,
    /// Sticky sessions: how long a conversation stays on one key (`map` mode).
    pub sticky_ttl_secs: u64,
    /// Sticky session map size before eviction.
    pub sticky_max_entries: usize,
    /// Bytes of the request body inspected to derive the sticky session id.
    pub session_prefix_bytes: usize,
    /// Broadcast buffer for the SSE event stream.
    pub event_channel_capacity: usize,
    /// Persist interval for events/request history.
    pub persist_interval_secs: u64,
    /// HTTP timeout for OAuth token refresh calls.
    pub oauth_http_timeout_secs: u64,
    /// Refresh an OAuth token this long before it expires.
    pub token_refresh_window_secs: u64,
    /// Poll interval for the dashboard's live views.
    pub ui_refresh_secs: u64,
    /// Keep-alive ping interval on the SSE stream (proxies drop idle streams).
    pub sse_keepalive_secs: u64,
    /// How long a graceful shutdown waits for in-flight responses before it
    /// gives up on them (they are aborted) and flushes state.
    pub shutdown_grace_secs: u64,
    /// How long a client may take to send (each chunk of) a request body.
    /// Bounds slowloris; 0 is not allowed because it would disable the guard.
    pub client_body_timeout_secs: u64,
    /// How long the per-account quota snapshot is reused.
    pub quota_cache_ttl_secs: u64,
    /// Responses API store size: how many `resp_*` records are kept so a
    /// follow-up can chain with `previous_response_id`. The oldest are evicted
    /// first; 0 disables the store (and `previous_response_id` is refused).
    pub response_store_max: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            max_cooldown_secs: 3600,
            base_backoff_secs: 5,
            rate_limit_cooldown_secs: 60,
            drain_fallback_secs: 60,
            models_cache_ttl_secs: 600,
            connect_timeout_secs: 10,
            meta_timeout_secs: 10,
            sticky_mode: "hash".to_string(),
            sticky_ttl_secs: 1800,
            sticky_max_entries: 10_000,
            session_prefix_bytes: 4096,
            event_channel_capacity: 256,
            persist_interval_secs: 30,
            oauth_http_timeout_secs: 30,
            token_refresh_window_secs: 300,
            ui_refresh_secs: 3,
            sse_keepalive_secs: 15,
            shutdown_grace_secs: 10,
            client_body_timeout_secs: 30,
            quota_cache_ttl_secs: 60,
            response_store_max: 1000,
        }
    }
}

impl Tuning {
    pub fn max_cooldown(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.max_cooldown_secs.max(1))
    }
    pub fn base_backoff(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.base_backoff_secs.max(1))
    }
    pub fn rate_limit_cooldown(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.rate_limit_cooldown_secs.max(1))
    }
    pub fn drain_fallback(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.drain_fallback_secs.max(1))
    }
    pub fn models_cache_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.models_cache_ttl_secs.max(1))
    }
    pub fn connect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.connect_timeout_secs.max(1))
    }
    pub fn meta_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.meta_timeout_secs.max(1))
    }
    pub fn sticky_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.sticky_ttl_secs.max(1))
    }
    pub fn sse_keepalive(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.sse_keepalive_secs.max(1))
    }
    /// How long a graceful shutdown may wait for open responses.
    pub fn shutdown_grace(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.shutdown_grace_secs.clamp(1, 120))
    }
    /// Per-chunk request-body read deadline (slowloris guard).
    pub fn client_body_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.client_body_timeout_secs.clamp(1, 300))
    }
    pub fn quota_cache_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.quota_cache_ttl_secs.max(1))
    }
    pub fn persist_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.persist_interval_secs.max(1))
    }
    pub fn oauth_http_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.oauth_http_timeout_secs.max(1))
    }
    pub fn token_refresh_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.token_refresh_window_secs.max(1))
    }

    /// Reject values that would make the gateway unusable rather than merely odd
    /// (a zero cooldown turns a rate-limited key into a hot loop).
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=86_400).contains(&self.max_cooldown_secs),
            "tuning.max_cooldown_secs must be between 1 and 86400"
        );
        anyhow::ensure!(
            (1..=600).contains(&self.base_backoff_secs),
            "tuning.base_backoff_secs must be between 1 and 600"
        );
        anyhow::ensure!(
            (1..=86_400).contains(&self.rate_limit_cooldown_secs),
            "tuning.rate_limit_cooldown_secs must be between 1 and 86400"
        );
        anyhow::ensure!(
            (1..=3600).contains(&self.drain_fallback_secs),
            "tuning.drain_fallback_secs must be between 1 and 3600"
        );
        anyhow::ensure!(
            (1..=86_400).contains(&self.models_cache_ttl_secs),
            "tuning.models_cache_ttl_secs must be between 1 and 86400"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.connect_timeout_secs),
            "tuning.connect_timeout_secs must be between 1 and 300"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.meta_timeout_secs),
            "tuning.meta_timeout_secs must be between 1 and 300"
        );
        anyhow::ensure!(
            matches!(self.sticky_mode.as_str(), "hash" | "map"),
            "tuning.sticky_mode must be \"hash\" or \"map\""
        );
        anyhow::ensure!(
            (1..=120).contains(&self.shutdown_grace_secs),
            "tuning.shutdown_grace_secs must be between 1 and 120"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.client_body_timeout_secs),
            "tuning.client_body_timeout_secs must be between 1 and 300"
        );
        anyhow::ensure!(
            (1..=86_400).contains(&self.sticky_ttl_secs),
            "tuning.sticky_ttl_secs must be between 1 and 86400"
        );
        anyhow::ensure!(
            (16..=1_000_000).contains(&self.sticky_max_entries),
            "tuning.sticky_max_entries must be between 16 and 1000000"
        );
        anyhow::ensure!(
            (256..=1_048_576).contains(&self.session_prefix_bytes),
            "tuning.session_prefix_bytes must be between 256 and 1048576"
        );
        anyhow::ensure!(
            (1..=65_536).contains(&self.event_channel_capacity),
            "tuning.event_channel_capacity must be between 1 and 65536"
        );
        anyhow::ensure!(
            (1..=3600).contains(&self.persist_interval_secs),
            "tuning.persist_interval_secs must be between 1 and 3600"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.oauth_http_timeout_secs),
            "tuning.oauth_http_timeout_secs must be between 1 and 300"
        );
        anyhow::ensure!(
            (0..=3600).contains(&self.token_refresh_window_secs),
            "tuning.token_refresh_window_secs must be between 0 and 3600"
        );
        anyhow::ensure!(
            (1..=600).contains(&self.ui_refresh_secs),
            "tuning.ui_refresh_secs must be between 1 and 600"
        );
        anyhow::ensure!(
            (1..=300).contains(&self.sse_keepalive_secs),
            "tuning.sse_keepalive_secs must be between 1 and 300"
        );
        anyhow::ensure!(
            (1..=86_400).contains(&self.quota_cache_ttl_secs),
            "tuning.quota_cache_ttl_secs must be between 1 and 86400"
        );
        anyhow::ensure!(
            self.response_store_max <= 100_000,
            "tuning.response_store_max must be between 0 and 100000"
        );
        Ok(())
    }
}

/// A virtual model: ordered fallback chain across providers.
/// Referenced as the combo name (or `combo/<name>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComboConfig {
    pub name: String,
    /// Entries like "provider/model".
    pub chain: Vec<String>,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(Path::new(path))
            .map_err(|e| anyhow::anyhow!("cannot read config {path}: {e}"))?;
        let cfg: Config =
            toml::from_str(&raw).map_err(|e| anyhow::anyhow!("invalid config {path}: {e}"))?;
        cfg.validate()
            .map_err(|e| anyhow::anyhow!("invalid config {path}: {e}"))?;
        Ok(cfg)
    }

    /// Invariants the rest of the code relies on. PUT /api/config validates
    /// through the same path so a saved config can never fail the next startup.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.providers.is_empty(), "config has no [[providers]]");
        if let Some(u) = self
            .server
            .public_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            anyhow::ensure!(
                u.starts_with("http://") || u.starts_with("https://"),
                "server.public_url must start with http:// or https://"
            );
            anyhow::ensure!(
                !u.ends_with('/'),
                "server.public_url must not end with '/' (got '{u}')"
            );
            anyhow::ensure!(
                u.len() <= 512,
                "server.public_url must be at most 512 characters"
            );
        }
        self.tuning.validate()?;
        // A one-character master key is a typo, not a key: the dashboard path
        // already requires 8, so the TOML path must agree or the API is
        // "protected" by something guessable.
        for (name, value) in [
            ("api_key", self.server.api_key.as_deref()),
            ("admin_key", self.server.admin_key.as_deref()),
        ] {
            if let Some(secret) = value {
                anyhow::ensure!(
                    !secret.trim().is_empty(),
                    "server.{name} must not be blank (remove the field to disable it)"
                );
                anyhow::ensure!(
                    secret.trim().len() >= 8,
                    "server.{name} must be at least 8 characters"
                );
            }
        }
        self.tuning.validate()?;
        anyhow::ensure!(
            matches!(self.ratelimit.backend.as_str(), "local" | "redis"),
            "ratelimit.backend must be \"local\" or \"redis\""
        );
        if self.ratelimit.backend == "redis" {
            anyhow::ensure!(
                self.ratelimit.redis_url.starts_with("redis://"),
                "ratelimit.redis_url must start with redis://"
            );
            anyhow::ensure!(
                (1..=5_000).contains(&self.ratelimit.timeout_ms),
                "ratelimit.timeout_ms must be between 1 and 5000"
            );
        }
        for p in &self.providers {
            for cap in &p.capabilities {
                anyhow::ensure!(
                    matches!(cap.as_str(), "images" | "audio" | "realtime"),
                    "provider '{}': unknown capability '{cap}' (images|audio|realtime)",
                    p.name
                );
            }
            anyhow::ensure!(
                p.capabilities.is_empty() || matches!(p.kind, ProviderKind::OpenaiCompat),
                "provider '{}': capabilities are only supported for openai_compat providers",
                p.name
            );
        }
        anyhow::ensure!(
            !self.server.listen.trim().is_empty(),
            "server.listen is empty"
        );
        // A listener without a port cannot be bound.
        anyhow::ensure!(
            self.server.listen.contains(':'),
            "server.listen must look like host:port (got '{}')",
            self.server.listen
        );
        // Ranges, not just types — the same ones POST /api/server/update
        // enforces. Out-of-range values are accepted by serde but break the
        // gateway in ways that are hard to diagnose afterwards.
        //
        // run_target() would silently clamp 0 to 1; a config that cannot be
        // served as written should be rejected instead.
        anyhow::ensure!(
            (1..=32).contains(&self.server.max_retries),
            "server.max_retries must be between 1 and 32"
        );
        anyhow::ensure!(
            (1..=3600).contains(&self.server.attempt_timeout_secs),
            "server.attempt_timeout_secs must be between 1 and 3600"
        );
        // The body limit is a layer installed at startup; 0 would turn every
        // POST into an immediate 413, while an unbounded value lets one upload
        // eat the process's memory.
        anyhow::ensure!(
            (1024..=256 * 1024 * 1024).contains(&self.server.max_body_bytes),
            "server.max_body_bytes must be between 1024 and 268435456"
        );
        anyhow::ensure!(
            self.server.events_history <= 100_000,
            "server.events_history must be <= 100000"
        );
        anyhow::ensure!(
            self.server.requests_history <= 100_000,
            "server.requests_history must be <= 100000"
        );
        anyhow::ensure!(
            self.server.models_refresh_secs <= 86_400,
            "server.models_refresh_secs must be <= 86400"
        );
        // A zero window makes the brute-force guard forget every attempt as it
        // is counted, which silently disables the lockout entirely.
        anyhow::ensure!(
            (1..=10_000).contains(&self.server.auth_fail_burst),
            "server.auth_fail_burst must be between 1 and 10000"
        );
        anyhow::ensure!(
            (1..=3600).contains(&self.server.auth_fail_window_secs),
            "server.auth_fail_window_secs must be between 1 and 3600"
        );
        anyhow::ensure!(
            self.server.client_key_max_concurrent <= 10_000,
            "server.client_key_max_concurrent must be <= 10000"
        );
        anyhow::ensure!(
            matches!(self.server.log_format.as_str(), "text" | "json"),
            "server.log_format must be \"text\" or \"json\""
        );

        let mut names = std::collections::HashSet::new();
        for p in &self.providers {
            // All name-based lookups use find() — a duplicate name would make
            // the second provider unreachable through the API.
            anyhow::ensure!(!p.name.trim().is_empty(), "provider with an empty name");
            anyhow::ensure!(
                names.insert(p.name.as_str()),
                "duplicate provider name '{}'",
                p.name
            );
            anyhow::ensure!(
                p.drain_below_pct <= 100,
                "provider '{}': drain_below_pct must be <= 100",
                p.name
            );
            // A provider with no credentials can never serve a request. The
            // per-kind check below mirrors `Provider::from_config` exactly:
            // validate() is what guards the config file, so anything it accepts
            // and the runtime rejects would brick the next start.
            match p.kind {
                ProviderKind::OpenaiCompat | ProviderKind::Gemini | ProviderKind::Anthropic => {
                    anyhow::ensure!(
                        !p.keys.is_empty(),
                        "provider '{}': no keys configured",
                        p.name
                    );
                    // anthropic has a built-in default endpoint; the other two
                    // must say where to send the request.
                    anyhow::ensure!(
                        !p.base_url.trim_end_matches('/').is_empty()
                            || matches!(p.kind, ProviderKind::Anthropic),
                        "provider '{}': base_url is required",
                        p.name
                    );
                }
                ProviderKind::Antigravity | ProviderKind::Codex => {
                    let auth_cmd = if matches!(p.kind, ProviderKind::Antigravity) {
                        "anyhop auth antigravity"
                    } else {
                        "anyhop auth codex"
                    };
                    anyhow::ensure!(
                        !p.accounts.is_empty(),
                        "provider '{}': no accounts configured (run `{auth_cmd}`)",
                        p.name
                    );
                }
            }
            // A repeated secret is counted twice in rotation and in the stats
            // (the dashboard "add key" path already rejects duplicates).
            let mut seen = std::collections::HashSet::new();
            for k in &p.keys {
                anyhow::ensure!(
                    !k.trim().is_empty(),
                    "provider '{}' has an empty key entry",
                    p.name
                );
                anyhow::ensure!(
                    seen.insert(k.as_str()),
                    "provider '{}' lists the same key twice",
                    p.name
                );
            }
        }

        // Combos: unique names, non-empty chains, and every "provider/model"
        // entry must reference a declared provider — resolve() would otherwise
        // skip it with a warning and quietly degrade the fallback chain.
        let mut combo_names = std::collections::HashSet::new();
        for c in &self.combos {
            anyhow::ensure!(!c.name.trim().is_empty(), "combo with an empty name");
            anyhow::ensure!(
                combo_names.insert(c.name.as_str()),
                "duplicate combo name '{}'",
                c.name
            );
            anyhow::ensure!(!c.chain.is_empty(), "combo '{}' has an empty chain", c.name);
            for entry in &c.chain {
                if let Some((prefix, rest)) = entry.split_once('/') {
                    anyhow::ensure!(
                        !rest.is_empty(),
                        "combo '{}': chain entry '{entry}' has an empty model",
                        c.name
                    );
                    anyhow::ensure!(
                        names.contains(prefix),
                        "combo '{}': chain entry '{entry}' references unknown provider '{prefix}'",
                        c.name
                    );
                }
            }
        }

        let mut key_values = std::collections::HashSet::new();
        for (i, k) in self.client_keys.iter().enumerate() {
            // An empty key would be matched by an empty bearer token.
            anyhow::ensure!(!k.key.is_empty(), "client_keys[{i}] has an empty key");
            anyhow::ensure!(
                key_values.insert(k.key.as_str()),
                "client_keys[{i}] duplicates another key's value"
            );
            // A zero rpm is "unlimited"; a burst below the sustained rate would
            // make the limit meaningless, so reject the contradictory combination
            // instead of silently ignoring it at runtime.
            if let (Some(rpm), Some(burst)) = (k.rpm, k.burst) {
                anyhow::ensure!(
                    rpm > 0 || burst == 0,
                    "client_keys[{i}]: 'burst' set without 'rpm' (add rpm = <requests per minute>)"
                );
            }
        }
        Ok(())
    }
}

/// Client API key with a model allowlist ([] = all models).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientKeyConfig {
    pub key: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub created_at: Option<u64>,
    /// Sustained requests per minute for this key (None/0 = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpm: Option<u32>,
    /// Spike allowance; defaults to `rpm` when unset or 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    /// In-flight requests allowed for this key (None = `[server] client_key_max_concurrent`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Max upstream attempts per incoming request (each attempt uses a different key).
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// Timeout for a single upstream attempt.
    #[serde(default = "default_attempt_timeout_secs")]
    pub attempt_timeout_secs: u64,
    /// redb state file (key health, OAuth tokens, stats). Empty = disabled.
    #[serde(default = "default_state_file")]
    pub state_file: String,
    /// Global upstream proxy (http/https/socks5). Overridden per provider/account.
    #[serde(default)]
    pub proxy: Option<String>,
    /// If set, /v1/* endpoints require `Authorization: Bearer <api_key>`.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Admin key for /api/* and /dashboard. Defaults to api_key when unset.
    #[serde(default)]
    pub admin_key: Option<String>,
    /// Public base URL of this gateway (e.g. `https://gateway.example.com`).
    ///
    /// When set, OAuth sign-in uses `<public_url>/api/auth/callback` as the
    /// redirect URI, so a dashboard opened on another machine (or a phone) can
    /// finish the flow. Unset = the classic loopback listener on 127.0.0.1.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Max request body size (bytes).
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    /// Serve the web dashboard at /dashboard (the JSON API stays on regardless).
    #[cfg_attr(not(feature = "dashboard"), allow(dead_code))]
    #[serde(default = "default_true")]
    pub dashboard: bool,
    /// Serve HTTPS directly from this process (PEM files). Both must be set.
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    /// Log format: "text" (default) or "json" for log shippers.
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Per-client-key concurrency cap (0 = unlimited) unless the key overrides it.
    #[serde(default)]
    pub client_key_max_concurrent: u32,
    /// Failed-auth attempts from one IP before it is throttled.
    #[serde(default = "default_auth_fail_burst")]
    pub auth_fail_burst: u32,
    /// How long the failure counter is remembered.
    #[serde(default = "default_auth_fail_window_secs")]
    pub auth_fail_window_secs: u64,
    /// Max events kept (and persisted). 0 = in-memory 100, no persistence.
    #[serde(default = "default_events_history")]
    pub events_history: usize,
    /// Max request-log entries kept (and persisted). 0 = in-memory 200, no persistence.
    #[serde(default = "default_requests_history")]
    pub requests_history: usize,
    /// Periodic models refresh interval from providers (secs). Default: 300 (5 min). 0 = disabled.
    #[serde(default = "default_models_refresh_secs")]
    pub models_refresh_secs: u64,
}

fn default_models_refresh_secs() -> u64 {
    300
}

fn default_max_body() -> usize {
    32 * 1024 * 1024 // 32 MiB
}

fn default_log_format() -> String {
    "text".to_string()
}
fn default_auth_fail_burst() -> u32 {
    10
}
fn default_auth_fail_window_secs() -> u64 {
    60
}
fn default_events_history() -> usize {
    100
}
fn default_requests_history() -> usize {
    200
}

fn default_true() -> bool {
    true
}

fn default_state_file() -> String {
    "anyhop.redb".into()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            max_retries: default_max_retries(),
            attempt_timeout_secs: default_attempt_timeout_secs(),
            state_file: default_state_file(),
            proxy: None,
            api_key: None,
            dashboard: true,
            events_history: default_events_history(),
            requests_history: default_requests_history(),
            admin_key: None,
            public_url: None,
            tls_cert: None,
            tls_key: None,
            log_format: default_log_format(),
            client_key_max_concurrent: 0,
            auth_fail_burst: default_auth_fail_burst(),
            auth_fail_window_secs: default_auth_fail_window_secs(),
            max_body_bytes: default_max_body(),
            models_refresh_secs: default_models_refresh_secs(),
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_max_retries() -> usize {
    4
}
fn default_attempt_timeout_secs() -> u64 {
    120
}

/// Atomic config write: temp file + rename — a crash mid-write must not
/// leave a truncated TOML that bricks the next startup.
///
/// The config holds provider API keys and OAuth refresh tokens, so the file must
/// stay owner-only: `fs::write` created the temporary with the process umask
/// (0644) and the rename carried that mode over the 0600 file the operator had.
/// The temporary is created with `create_new` + 0600, which also means a symlink
/// planted at that path cannot redirect the write, and it gets a unique name so
/// two processes sharing a config cannot clobber each other's temporary.
pub fn write_atomic(path: &str, contents: &str) -> std::io::Result<()> {
    let tmp = temp_path(path);
    let write = || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, contents)?;
        }
        Ok(())
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Rename keeps the temporary's 0600 mode, so the config never becomes
    // group/world readable.
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// A unique sibling path for the atomic write: `<path>.tmp.<pid>.<counter>`.
/// Uniqueness only has to survive concurrent writers, so pid + process-local
/// counter is enough and needs no randomness.
fn temp_path(path: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{path}.tmp.{}.{n}", std::process::id())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ProviderKind,
    /// Optional for antigravity (defaults to the daily cloudcode-pa endpoint).
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub keys: Vec<String>,
    /// OAuth accounts (antigravity only).
    #[serde(default)]
    pub accounts: Vec<OAuthAccountConfig>,
    /// Models served by this provider. Empty = wildcard (accept any model).
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub strategy: Strategy,
    /// Extra headers sent to upstream on every request (e.g. OpenRouter referer).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Upstream proxy: http://, https://, socks5://, socks5h://.
    #[serde(default)]
    pub proxy: Option<String>,
    /// Max concurrent in-flight requests per key (0 = unlimited).
    #[serde(default)]
    pub max_concurrent: u32,
    /// Proactively cool a key down when remaining requests fall below this %% of the limit
    /// (OpenAI-compat rate-limit headers). 0 = disabled.
    #[serde(default)]
    pub drain_below_pct: u32,
    /// Per-provider attempt timeout; falls back to `[server] attempt_timeout_secs`.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Per-provider attempt budget; falls back to `[server] max_retries`.
    #[serde(default)]
    pub max_retries: Option<usize>,
    /// Optional pass-through endpoints this provider serves: "images", "audio",
    /// "realtime". Empty = chat/completions/embeddings only.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthAccountConfig {
    /// May be empty when `access_token` is provided (dev/testing shortcut).
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub email: Option<String>,
    /// Antigravity: cloudcode project id.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Codex: chatgpt account id (from id_token claims).
    #[serde(default)]
    pub account_id: Option<String>,
    /// Pre-seeded access token that never refreshes (for tests / imported tokens).
    #[serde(default)]
    pub access_token: Option<String>,
    /// Per-account proxy (overrides provider-level proxy).
    #[serde(default)]
    pub proxy: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    OpenaiCompat,
    Gemini,
    Antigravity,
    Anthropic,
    Codex,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// Rotate keys evenly.
    #[default]
    RoundRobin,
    /// Pick the available key with the fewest total requests.
    LeastUsed,
    /// Stick to the first available key until it gets rate-limited, then the next.
    /// Best for per-key daily quotas (e.g. Gemini free tier).
    FillFirst,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid config: one openai_compat provider with one key.
    const VALID: &str = r#"
        [server]
        listen = "127.0.0.1:8080"

        [[providers]]
        name = "p"
        type = "openai_compat"
        base_url = "http://127.0.0.1:9/v1"
        keys = ["sk-1"]
    "#;

    fn parse(toml_text: &str) -> Config {
        toml::from_str(toml_text).expect("the fixture parses")
    }

    fn error_of(toml_text: &str) -> String {
        parse(toml_text)
            .validate()
            .expect_err("this config must be rejected")
            .to_string()
    }

    // ----- A: validate() mirrors Provider::from_config -----

    #[test]
    fn a_valid_config_still_validates() {
        parse(VALID)
            .validate()
            .expect("the baseline config is valid");
    }

    /// Every shape `Provider::from_config` rejects must be rejected here too:
    /// write_validated() only runs validate(), so an accepted-but-unbuildable
    /// config used to be written to disk and then fail the *next* `anyhop` start.
    #[test]
    fn a_missing_or_empty_base_url_is_rejected_before_the_write() {
        for kind in ["openai_compat", "gemini"] {
            let text = format!(
                r#"
                [[providers]]
                name = "p"
                type = "{kind}"
                keys = ["sk-1"]
                "#
            );
            let e = error_of(&text);
            assert!(
                e.contains("base_url is required"),
                "{kind}: unexpected error: {e}"
            );

            let blank = format!(
                r#"
                [[providers]]
                name = "p"
                type = "{kind}"
                base_url = ""
                keys = ["sk-1"]
                "#
            );
            assert!(
                error_of(&blank).contains("base_url is required"),
                "{kind}: an empty base_url must be rejected"
            );
        }
    }

    /// anthropic has a default endpoint, so an empty base_url stays valid there.
    #[test]
    fn anthropic_needs_no_base_url() {
        let text = r#"
            [[providers]]
            name = "claude"
            type = "anthropic"
            keys = ["sk-ant"]
        "#;
        parse(text)
            .validate()
            .expect("anthropic has a default base_url");
    }

    #[test]
    fn an_oauth_provider_with_keys_but_no_accounts_is_rejected() {
        for kind in ["antigravity", "codex"] {
            let text = format!(
                r#"
                [[providers]]
                name = "p"
                type = "{kind}"
                keys = ["sk-1"]
                "#
            );
            let e = error_of(&text);
            assert!(
                e.contains("no accounts configured"),
                "{kind}: unexpected error: {e}"
            );
        }
    }

    #[test]
    fn a_key_provider_with_accounts_but_no_keys_is_rejected() {
        let text = r#"
            [[providers]]
            name = "g"
            type = "gemini"
            base_url = "http://127.0.0.1:9/v1beta"

            [[providers.accounts]]
            email = "x@example.com"
            access_token = "tok"
        "#;
        let e = error_of(text);
        assert!(e.contains("no keys configured"), "unexpected error: {e}");
    }

    // ----- I: ranges that disable safety features -----

    #[test]
    fn out_of_range_server_values_are_rejected() {
        // (toml body, the fragment the error must name)
        let cases = [
            ("max_retries = 0", "max_retries"),
            ("max_retries = 33", "max_retries"),
            (
                "max_retries = 1000000",
                "max_retries", // a huge value spins the retry loop
            ),
            ("attempt_timeout_secs = 0", "attempt_timeout_secs"),
            ("max_body_bytes = 0", "max_body_bytes"),
            ("events_history = 100001", "events_history"),
            ("requests_history = 100001", "requests_history"),
            ("models_refresh_secs = 86401", "models_refresh_secs"),
            ("auth_fail_burst = 0", "auth_fail_burst"),
            (
                // A zero window made the brute-force lockout forget every
                // attempt: the counter was reset as it was counted.
                "auth_fail_window_secs = 0",
                "auth_fail_window_secs",
            ),
            (
                "client_key_max_concurrent = 10001",
                "client_key_max_concurrent",
            ),
            ("log_format = \"xml\"", "log_format"),
        ];
        for (line, field) in cases {
            let text = format!(
                r#"
                [server]
                {line}

                [[providers]]
                name = "p"
                type = "openai_compat"
                base_url = "http://127.0.0.1:9/v1"
                keys = ["sk-1"]
                "#
            );
            let e = error_of(&text);
            assert!(
                e.contains(field),
                "config with '{line}' must be rejected naming {field}, got: {e}"
            );
        }
    }

    #[test]
    fn the_boundary_values_the_dashboard_accepts_still_validate() {
        let text = r#"
            [server]
            max_retries = 32
            attempt_timeout_secs = 3600
            max_body_bytes = 1024
            events_history = 100000
            requests_history = 100000
            auth_fail_burst = 1
            auth_fail_window_secs = 3600
            models_refresh_secs = 86400

            [[providers]]
            name = "p"
            type = "openai_compat"
            base_url = "http://127.0.0.1:9/v1"
            keys = ["sk-1"]
        "#;
        parse(text)
            .validate()
            .expect("the documented boundary values are valid");
    }

    // ----- M: the config file holds secrets and must stay owner-only -----

    #[cfg(unix)]
    #[test]
    fn write_atomic_leaves_an_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "anyhop-cfg-perm-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("anyhop.toml");
        // Pre-create it world-readable, the way an old `fs::write` would have:
        // the rewrite must not inherit that mode.
        std::fs::write(&path, "listen = \"127.0.0.1:1\"\n").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let p = path.to_str().expect("utf-8 path");

        write_atomic(p, "max_retries = 7\n").expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "the config holds provider keys and OAuth tokens; mode {mode:o} is not owner-only"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "max_retries = 7\n"
        );
        // No temporary left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("list")
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|n| n.to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_uses_a_unique_temp_name_per_call() {
        let dir = std::env::temp_dir().join(format!(
            "anyhop-cfg-tmp-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("anyhop.toml");
        let p = path.to_str().expect("utf-8 path");
        // Two writers sharing the path (a multi-instance deployment points both
        // at the same file) must not race on one fixed ".tmp" name.
        let a = temp_path(p);
        let b = temp_path(p);
        assert_ne!(a, b, "the temporary path must not be shared");
        write_atomic(p, "x = 1\n").expect("write");
        write_atomic(p, "x = 2\n").expect("write");
        assert_eq!(std::fs::read_to_string(p).expect("read"), "x = 2\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
