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
    /// Sticky sessions: how long a conversation stays on one key.
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
    /// How long the per-account quota snapshot is reused.
    pub quota_cache_ttl_secs: u64,
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
            sticky_ttl_secs: 1800,
            sticky_max_entries: 10_000,
            session_prefix_bytes: 4096,
            event_channel_capacity: 256,
            persist_interval_secs: 30,
            oauth_http_timeout_secs: 30,
            token_refresh_window_secs: 300,
            ui_refresh_secs: 3,
            sse_keepalive_secs: 15,
            quota_cache_ttl_secs: 60,
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
        anyhow::ensure!(
            !self.server.listen.trim().is_empty(),
            "server.listen is empty"
        );
        // run_target() would silently clamp 0 to 1; a config that cannot be
        // served as written should be rejected instead.
        anyhow::ensure!(
            self.server.max_retries >= 1,
            "server.max_retries must be >= 1"
        );
        anyhow::ensure!(
            self.server.attempt_timeout_secs >= 1,
            "server.attempt_timeout_secs must be >= 1"
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
            // A provider with no credentials can never serve a request, and the
            // runtime rejects it — so treat it as a config error here, before an
            // edit is written to disk.
            anyhow::ensure!(
                !p.keys.is_empty() || !p.accounts.is_empty(),
                "provider '{}' has no keys or accounts",
                p.name
            );
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
                if rpm > 0 && burst > 0 {
                    anyhow::ensure!(burst >= 1, "client_keys[{i}]: 'burst' must be at least 1");
                }
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
pub fn write_atomic(path: &str, contents: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
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
