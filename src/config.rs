use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Is this an `http(s)://` URL within the length the gateway accepts?
///
/// One rule for both entry points. The dashboard edit path had it; the TOML path
/// did not, so a hand-written `base_url = "file:///etc/passwd"`, a `gopher://` or a
/// link-local metadata address reached `reqwest` verbatim — with the provider key
/// attached, because the runtime builds upstream URLs by concatenation
/// (`format!("{base}/chat/completions")`) and never re-checks the scheme.
pub fn is_http_url(url: &str) -> bool {
    let u = url.trim();
    !u.is_empty()
        && u.len() <= 2048
        && (u.starts_with("http://") || u.starts_with("https://"))
        // `http://` with nothing after it would concatenate into `http:///v1/...`.
        && u.len() > "https://".len()
}

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
    /// Per-model limits (context window and token caps), editable from the
    /// dashboard and published in `/v1/models`.
    ///
    /// ```toml
    /// [[model_limits]]
    /// model = "dashscope/deepseek-v4-pro"
    /// context_window = 131072
    /// max_output_tokens = 8192
    /// ```
    ///
    /// A zero (or absent) value means "not set": the gateway then publishes no
    /// number for that field instead of inventing one.
    #[serde(default)]
    pub model_limits: Vec<ModelLimit>,
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
    /// How long an accepted connection has to send its request **headers**.
    /// The body deadline starts only after the first byte, so without this a
    /// client that opens a socket and never writes holds a file descriptor
    /// (slowloris). Bounds the pre-request phase; 0 is not allowed because it
    /// would disable the guard.
    pub client_header_timeout_secs: u64,
    /// How long a request waits for a free upstream slot when every key is at its
    /// concurrency cap, before the gateway answers `429 + Retry-After: 1`.
    /// Saturation is "come back in a moment", not an outage: failing fast turned
    /// a 100 ms burst into 196 instant 429s. 0 = fail fast (the old behaviour).
    pub capacity_wait_ms: u64,
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
            client_header_timeout_secs: 10,
            capacity_wait_ms: 5000,
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
    /// Deadline for a connection to send its request headers.
    pub fn client_header_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.client_header_timeout_secs.clamp(1, 300))
    }
    /// How long one admission round may wait for a free in-flight slot.
    ///
    /// Zero is meaningful (fail fast) and must survive the conversion, so this is
    /// a clamp on the upper bound only.
    pub fn capacity_wait(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.capacity_wait_ms.min(30_000))
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
        // 0 is a documented value ("refresh only once expired") and the validator
        // accepts it, but `.max(1)` silently turned it into one second — so the
        // setting could not be expressed at all.
        std::time::Duration::from_secs(self.token_refresh_window_secs)
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
            (1..=300).contains(&self.client_header_timeout_secs),
            "tuning.client_header_timeout_secs must be between 1 and 300"
        );
        anyhow::ensure!(
            self.capacity_wait_ms <= 30_000,
            "tuning.capacity_wait_ms must be between 0 and 30000 (0 = fail fast)"
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

/// What the gateway knows about one model's limits.
///
/// Every field is optional and defaults to 0 (= unknown). The rules a value has to
/// satisfy live in [`ModelLimit::check`], so a hand-edited file, `PUT /api/config`
/// and the dashboard accept exactly the same numbers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ModelLimit {
    /// `provider/model`, a bare model name (applies to every provider serving it),
    /// or a combo name.
    pub model: String,
    /// Total tokens the model can hold — prompt plus completion.
    pub context_window: u64,
    /// Cap on the completion; published as `max_completion_tokens` in `/v1/models`.
    pub max_output_tokens: u64,
    /// Cap on the prompt alone, when the provider states one separately.
    pub max_input_tokens: u64,
}

/// Largest accepted values: a wrong number must not turn into an absurd JSON
/// response, and `u64::MAX` in a config file is always a typo.
pub const MAX_CONTEXT_WINDOW: u64 = 10_000_000;
pub const MAX_OUTPUT_TOKENS: u64 = 1_000_000;

impl ModelLimit {
    /// Longest accepted model id — the same bound `disabled_models` uses.
    pub const MAX_MODEL_LEN: usize = 256;

    /// Did the operator set anything at all?
    pub fn is_empty(&self) -> bool {
        self.context_window == 0 && self.max_output_tokens == 0 && self.max_input_tokens == 0
    }

    /// Which fields carry an explicit value ("context_window", …).
    pub fn overridden(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.context_window > 0 {
            out.push("context_window");
        }
        if self.max_output_tokens > 0 {
            out.push("max_output_tokens");
        }
        if self.max_input_tokens > 0 {
            out.push("max_input_tokens");
        }
        out
    }

    /// Validation shared by `Config::validate` and the API handler.
    pub fn check(&self) -> anyhow::Result<()> {
        let m = self.model.trim();
        anyhow::ensure!(!m.is_empty(), "model_limits entry with an empty model id");
        anyhow::ensure!(
            m.chars().count() <= Self::MAX_MODEL_LEN,
            "model_limits: model id is too long (max {} characters)",
            Self::MAX_MODEL_LEN
        );
        anyhow::ensure!(
            !m.chars().any(|c| c.is_control()),
            "model_limits: model id must not contain control characters"
        );
        anyhow::ensure!(
            self.context_window <= MAX_CONTEXT_WINDOW,
            "model_limits '{}': context_window must be 0 (unset) or 1..={MAX_CONTEXT_WINDOW}",
            self.model
        );
        anyhow::ensure!(
            self.max_output_tokens <= MAX_OUTPUT_TOKENS,
            "model_limits '{}': max_output_tokens must be 0 (unset) or 1..={MAX_OUTPUT_TOKENS}",
            self.model
        );
        anyhow::ensure!(
            self.max_input_tokens <= MAX_CONTEXT_WINDOW,
            "model_limits '{}': max_input_tokens must be 0 (unset) or 1..={MAX_CONTEXT_WINDOW}",
            self.model
        );
        // The completion is part of the window: a cap larger than the whole window
        // can never be satisfied, and the dashboard would happily show both.
        if self.context_window > 0 && self.max_output_tokens > 0 {
            anyhow::ensure!(
                self.max_output_tokens <= self.context_window,
                "model_limits '{}': max_output_tokens ({}) cannot exceed context_window ({})",
                self.model,
                self.max_output_tokens,
                self.context_window
            );
        }
        if self.context_window > 0 && self.max_input_tokens > 0 {
            anyhow::ensure!(
                self.max_input_tokens <= self.context_window,
                "model_limits '{}': max_input_tokens ({}) cannot exceed context_window ({})",
                self.model,
                self.max_input_tokens,
                self.context_window
            );
        }
        anyhow::ensure!(
            !self.is_empty(),
            "model_limits '{}': nothing to store (set at least one limit or delete the entry)",
            self.model
        );
        Ok(())
    }
}

/// The installed per-model limits.
///
/// `entries` is exactly what the file holds (canonical model ids, sorted) — the
/// writer and the API need that list. `index` answers a lookup for any spelling
/// (*qualified id*, bare model name, `combo/<name>`) in one hash probe, which is
/// what `/v1/models` does for every model of every provider.
#[derive(Debug, Clone, Default)]
pub struct ModelLimits {
    entries: Vec<ModelLimit>,
    index: std::collections::HashMap<String, ModelLimit>,
}

impl ModelLimits {
    pub fn build(mut entries: Vec<ModelLimit>) -> Self {
        for l in &mut entries {
            l.model = l.model.trim().to_string();
        }
        entries.retain(|l| !l.model.is_empty() && !l.is_empty());
        entries.sort_by(|a, b| a.model.cmp(&b.model));

        let mut index = std::collections::HashMap::new();
        for l in &entries {
            // The entry itself…
            index.insert(l.model.clone(), l.clone());
            // …its bare name (a limit on `beta` applies to every provider serving
            // `beta`), and `combo/<name>` for a bare combo name.
            match l.model.split_once('/') {
                Some((_, bare)) if !bare.is_empty() => {
                    index.entry(bare.to_string()).or_insert_with(|| l.clone());
                }
                _ => {
                    index
                        .entry(format!("combo/{}", l.model))
                        .or_insert_with(|| l.clone());
                }
            }
        }
        Self { entries, index }
    }

    /// The limits that apply to `id`, or `None`.
    pub fn get(&self, id: &str) -> Option<&ModelLimit> {
        if let Some(l) = self.index.get(id) {
            return Some(l);
        }
        // A qualified id whose provider-specific entry is absent still inherits the
        // bare-name entry, which `build` indexed — covered by the lookup above. The
        // remaining case is a bare id asking for a `combo/` spelling.
        match id.split_once('/') {
            Some((_, bare)) => self.index.get(bare),
            None => self.index.get(&format!("combo/{id}")),
        }
    }

    /// What the file holds (canonical ids, sorted).
    pub fn entries(&self) -> &[ModelLimit] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
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
        // A cert without a key (or vice versa) used to validate and then fall
        // through to *plaintext* HTTP while `tls_enabled` stayed true: bearer keys
        // and OAuth callbacks travelled in clear text, HSTS was advertised, and the
        // dashboard reported TLS on. Refuse the half-configuration.
        anyhow::ensure!(
            self.server.tls_cert.is_some() == self.server.tls_key.is_some(),
            "server.tls_cert and server.tls_key must be set together (now: cert {}, key {})",
            if self.server.tls_cert.is_some() {
                "set"
            } else {
                "unset"
            },
            if self.server.tls_key.is_some() {
                "set"
            } else {
                "unset"
            }
        );
        anyhow::ensure!(
            !self.server.listen.trim().is_empty(),
            "server.listen is empty"
        );
        // A listener without a port cannot be bound. `contains(':')` accepted
        // `":"`, `"127.0.0.1:"` and `"127.0.0.1:notaport"`, each of which is written
        // by the settings API, reported as restart_required, and then kills the next
        // start at bind time.
        let listen = self.server.listen.trim();
        let (host, port) = listen.rsplit_once(':').ok_or_else(|| {
            anyhow::anyhow!("server.listen must look like host:port (got '{listen}')")
        })?;
        anyhow::ensure!(
            port.parse::<u16>().map(|p| p > 0).unwrap_or(false),
            "server.listen has an invalid port '{}' (expected 1-65535)",
            port
        );
        anyhow::ensure!(
            !host.trim().is_empty() || listen.starts_with(":["),
            "server.listen has an empty host (use 0.0.0.0 to listen everywhere)"
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
        // 0 disables the accounting (the pre-existing behaviour); otherwise it must
        // be at least one request's worth, or every request would be refused.
        anyhow::ensure!(
            self.server.max_inflight_body_bytes == 0
                || self.server.max_inflight_body_bytes >= self.server.max_body_bytes as u64,
            "server.max_inflight_body_bytes must be 0 (off) or at least max_body_bytes"
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
        // Each CORS entry becomes an `Access-Control-Allow-Origin` value: a bare
        // "*" mixed with real origins is ambiguous, and anything with a space or a
        // newline cannot be a header value at all.
        for o in &self.server.cors_origins {
            let o = o.trim();
            anyhow::ensure!(!o.is_empty(), "server.cors_origins has an empty entry");
            anyhow::ensure!(
                o == "*" || o.starts_with("http://") || o.starts_with("https://"),
                "server.cors_origins entry '{o}' must be '*' or start with http:// or https://"
            );
            anyhow::ensure!(
                !o.chars().any(|c| c.is_control() || c == ' '),
                "server.cors_origins entry '{o}' must not contain spaces or control characters"
            );
        }
        anyhow::ensure!(
            !(self.server.cors_origins.iter().any(|o| o.trim() == "*")
                && self.server.cors_origins.len() > 1),
            "server.cors_origins: \"*\" cannot be combined with other origins"
        );

        let mut names = std::collections::HashSet::new();
        for p in &self.providers {
            // The per-provider override wins over `server.max_retries`, which is
            // range-checked (1..=32) — an unbounded value here turned one client
            // request into a near-endless upstream loop that held a client-key slot
            // and a provider key.
            if let Some(n) = p.max_retries {
                anyhow::ensure!(
                    (1..=32).contains(&n),
                    "provider '{}': max_retries must be between 1 and 32 (got {n})",
                    p.name
                );
            }
            if let Some(t) = p.timeout_secs {
                anyhow::ensure!(
                    (1..=3600).contains(&t),
                    "provider '{}': timeout_secs must be between 1 and 3600 (got {t})",
                    p.name
                );
            }
            // The API handler already bounds this; without the same rule here a
            // hand-edited file (or PUT /api/config) could install a value the
            // dashboard refuses.
            anyhow::ensure!(
                p.max_concurrent <= 10_000,
                "provider '{}': max_concurrent must be 0 (unlimited) or 1..=10000 (got {})",
                p.name,
                p.max_concurrent
            );
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
            if let Some(u) = p
                .limits_url
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty())
            {
                anyhow::ensure!(
                    u.starts_with("http://") || u.starts_with("https://"),
                    "provider '{}': limits_url must start with http:// or https://",
                    p.name
                );
                anyhow::ensure!(
                    !u.chars().any(|c| c.is_control()),
                    "provider '{}': limits_url must not contain control characters",
                    p.name
                );
            }
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
                    // The dashboard edit path already validated the scheme; the
                    // TOML path did not, so `base_url = "file:///etc/passwd"` or a
                    // link-local metadata address reached `reqwest` verbatim — with
                    // the provider key attached. The runtime composes URLs by
                    // concatenation (`format!("{base}/chat/completions")`), so the
                    // scheme is the only thing standing between a config typo and a
                    // request to an unintended host. Same rule, one place.
                    // An empty value stays legal for the kinds that have a
                    // default endpoint (anthropic); anything actually given must
                    // be an http(s) URL.
                    anyhow::ensure!(
                        p.base_url.trim().is_empty() || is_http_url(&p.base_url),
                        "provider '{}': base_url must be an http(s) URL of at most 2048 \
                         characters (got '{}')",
                        p.name,
                        p.base_url
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

        // A client-key deployment is a *shared* gateway by definition, so it must
        // carry an `admin_key`. Two distinct shapes are refused here:
        //
        // 1. no credential at all — historically this produced a file that every
        //    later writer, `POST /api/reload`, SIGHUP and the next start rejected,
        //    i.e. the admin API locked itself out of its own config;
        // 2. `api_key` present but no `admin_key` — `/api/*` used to accept the
        //    gateway key, so this used to pass. It no longer does: that key is
        //    handed to every client and must not reach the control plane
        //    (`middleware::require_admin_key`), so such a gateway would have
        //    settings nobody can open.
        //
        // Configuring `admin_key` is the one extra line this boundary costs.
        anyhow::ensure!(
            self.client_keys.is_empty()
                || self.server.api_key.is_some()
                || self.server.admin_key.is_some(),
            "client_keys are configured but neither server.api_key nor server.admin_key is set: \
             /api/* (raw config editor, provider keys, OAuth) would accept unauthenticated \
             requests. Set [server] admin_key (and api_key for /v1/*) or remove the client keys"
        );
        anyhow::ensure!(
            self.client_keys.is_empty() || self.server.admin_key.is_some(),
            "client_keys are configured but [server] admin_key is not set: /api/* (raw config \
             editor, provider keys, OAuth) accepts only admin_key, because api_key is handed to \
             every client and must not be able to read provider secrets. Set [server] admin_key"
        );

        let mut key_values = std::collections::HashSet::new();
        // Per-model limits: unique ids, bounded numbers, and consistency between
        // the window and the caps (see ModelLimit::check).
        let mut limit_ids = std::collections::HashSet::new();
        for l in &self.model_limits {
            l.check()?;
            anyhow::ensure!(
                limit_ids.insert(l.model.trim().to_string()),
                "duplicate model_limits entry for '{}'",
                l.model
            );
        }

        let mut key_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (i, k) in self.client_keys.iter().enumerate() {
            // An empty key would be matched by an empty bearer token.
            anyhow::ensure!(!k.key.is_empty(), "client_keys[{i}] has an empty key");
            anyhow::ensure!(
                key_values.insert(k.key.as_str()),
                "client_keys[{i}] duplicates another key's value"
            );
            anyhow::ensure!(
                k.max_concurrent.unwrap_or(0) <= 10_000,
                "client_keys[{i}]: max_concurrent must be 0 (server default) or 1..=10000"
            );
            // The name is a Prometheus label value and the Requests-tab identity:
            // two keys sharing one name emit duplicate series, which makes
            // Prometheus reject the *whole* scrape.
            if let Some(name) = k.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
                anyhow::ensure!(
                    key_names.insert(name.to_string()),
                    "client_keys[{i}] duplicates the name '{name}'"
                );
            }
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
    /// Total bytes of request bodies allowed in memory across ALL in-flight
    /// requests. `max_body_bytes` bounds one request and `client_key_max_concurrent`
    /// bounds the count; without this, N concurrent large requests each pass their
    /// own limit while together exceeding the container's memory. 0 = no accounting.
    ///
    /// The default (256 MiB) is deliberately generous: it only bites when many
    /// large requests overlap, which is exactly the case that used to reach the
    /// memory limit. Set it to roughly half the container's memory budget.
    pub max_inflight_body_bytes: u64,
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
    /// Per-client-key concurrency cap unless the key overrides it.
    ///
    /// Defaults to 64 rather than unlimited: an absent cap means the counter at
    /// `middleware.rs` is never even incremented, so a runaway client is invisible
    /// in the metrics *and* can head-of-line-block every other tenant for up to
    /// `capacity_wait_ms` before their requests turn into 429s. 64 is far above any
    /// interactive workload and keeps the 32 MiB × 64 worst case inside a normal
    /// container budget. Set it to 0 to restore the old unlimited behaviour.
    #[serde(default = "default_client_key_max_concurrent")]
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
    /// Browser origins allowed to call `/v1/*` and `/api/*` cross-origin.
    ///
    /// Empty (the default) means same-origin only, which is what the bundled
    /// dashboard needs. A browser-based client (Open WebUI, LobeChat, Chatbox…)
    /// served from another origin sends a preflight `OPTIONS` request and is
    /// refused without an entry here — `"*"` allows any origin (the key is still
    /// required, and `Access-Control-Allow-Credentials` stays off, so a hostile
    /// page cannot borrow a stored credential).
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

fn default_models_refresh_secs() -> u64 {
    300
}

fn default_max_body() -> usize {
    32 * 1024 * 1024 // 32 MiB
}

fn default_client_key_max_concurrent() -> u32 {
    64
}

fn default_max_inflight_body() -> u64 {
    256 * 1024 * 1024 // 256 MiB: 8 concurrent max-size requests
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
            client_key_max_concurrent: default_client_key_max_concurrent(),
            auth_fail_burst: default_auth_fail_burst(),
            auth_fail_window_secs: default_auth_fail_window_secs(),
            max_body_bytes: default_max_body(),
            max_inflight_body_bytes: default_max_inflight_body(),
            models_refresh_secs: default_models_refresh_secs(),
            cors_origins: Vec::new(),
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
    //
    // A single-file bind mount cannot be renamed *onto* (`EBUSY`) — and that is how
    // most container deployments mount the config. Falling back to an in-place copy
    // keeps the dashboard usable there; it is not atomic, so it is logged and only
    // used for this error class (a permission failure still fails loudly instead of
    // truncating the file).
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(16) /* EBUSY */ | Some(18) /* EXDEV */
            ) =>
        {
            tracing::warn!(
                path,
                error = %e,
                "config is a bind mount: rewriting it in place (not atomic)"
            );
            write_in_place(path, contents).inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })?;
            let _ = std::fs::remove_file(&tmp);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Truncate and rewrite `path`, creating it 0600 when it does not exist yet.
fn write_in_place(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::{Seek as _, Write as _};

    // Rewrite the *existing* inode rather than rename over it: a single-file
    // bind mount (the containerised deploy) cannot be replaced by rename, which is
    // exactly why this fallback exists.
    //
    // The bytes are written **over** the current content, never after
    // `truncate(true)`: truncating first meant a crash, ENOSPC or a full disk
    // between the truncate and the write left an **empty** anyhop.toml — the
    // gateway would then fail to start with no way back except a backup. Writing
    // first and truncating to the new length afterwards means a failure leaves the
    // file *longer* than intended, or with a stale tail, but never empty, and the
    // very next successful write repairs it.
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            // Deliberately NOT `truncate(true)`: the new bytes are written over
            // the existing content and the length is fixed afterwards, so a crash
            // or ENOSPC mid-write leaves a stale tail rather than an empty file.
            .truncate(false)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        // See the unix branch: truncating first would risk an empty config.
        .truncate(false)
        .open(path)?;

    f.write_all(contents.as_bytes())?;
    // Drop any tail from a previously longer config, then make the length durable.
    f.set_len(contents.len() as u64)?;
    f.rewind()?;
    f.sync_all()
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
    /// Where to read per-model limits from, when the provider's OpenAI-compatible
    /// `/models` does not carry them.
    ///
    /// Nothing is special-cased in the code: a vendor whose standard endpoint is
    /// bare (DashScope's `compatible-mode/v1/models` returns only
    /// `id/object/created/owned_by`) is described by its operator once, e.g.
    ///
    /// ```toml
    /// limits_url = "https://dashscope-intl.aliyuncs.com/api/v1/models"
    /// ```
    ///
    /// Left empty, no second request is made.
    #[serde(default)]
    pub limits_url: Option<String>,
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

    /// The in-place fallback (single-file bind mounts) must never leave the
    /// config **empty**.
    ///
    /// It used to `truncate(true)` before writing, so a crash or a full disk in
    /// that window produced a zero-byte `anyhop.toml` — a gateway that cannot
    /// start and a config that is gone. Writing over the existing bytes and
    /// truncating to the new length afterwards means the worst case is a stale
    /// tail, which the next successful write repairs.
    ///
    /// This test pins the *observable contract* (no stale tail, valid TOML, 0600).
    /// The crash window itself cannot be reproduced in-process — it needs the
    /// process to die between two syscalls — so the ordering is enforced by the
    /// code shape and this comment, not by the assertion.
    #[test]
    fn writing_in_place_never_truncates_before_the_bytes_are_there() {
        let path = std::env::temp_dir().join(format!(
            "anyhop-inplace-{}-{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let p = path.to_str().expect("utf-8 temp path").to_string();

        // A long config, then a shorter one: the tail must not survive.
        let long = "# a long comment line\n".repeat(50) + "[server]\nlisten = \"127.0.0.1:1\"\n";
        write_in_place(&p, &long).expect("first write");
        assert_eq!(std::fs::read_to_string(&p).expect("read"), long);

        let short = "[server]\nlisten = \"127.0.0.1:2\"\n";
        write_in_place(&p, short).expect("second write");
        let after = std::fs::read_to_string(&p).expect("read");
        assert_eq!(after, short, "a shorter config must not keep the old tail");
        // And it must still parse.
        toml::from_str::<Config>(&after).expect("the file is a valid config");

        // The file is not empty at any point we can observe, and it is 0600.
        assert!(!after.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "secrets file must stay 0600");
        }
        let _ = std::fs::remove_file(&path);
    }

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

    /// TLS is a pair: a cert without a key used to validate and then serve
    /// *plaintext* while `tls_enabled` stayed true (bearer keys in clear text,
    /// HSTS advertised, the dashboard reporting TLS on).
    #[test]
    fn a_half_configured_tls_pair_is_rejected() {
        let cert_only = VALID.replace("[server]", "[server]\ntls_cert = \"/etc/anyhop/tls.crt\"");
        let msg = error_of(&cert_only);
        assert!(msg.contains("set together"), "{msg}");
        let key_only = VALID.replace("[server]", "[server]\ntls_key = \"/etc/anyhop/tls.key\"");
        let msg = error_of(&key_only);
        assert!(msg.contains("set together"), "{msg}");
        // Both together are accepted (the file itself is only opened at startup).
        let both = VALID.replace(
            "[server]",
            "[server]\ntls_cert = \"/etc/anyhop/tls.crt\"\ntls_key = \"/etc/anyhop/tls.key\"",
        );
        parse(&both).validate().expect("a complete pair is valid");
    }

    /// CORS entries become response headers: a wildcard mixed with real origins is
    /// ambiguous, and a value with a space or a control character cannot be a
    /// header at all.
    #[test]
    fn cors_origins_are_validated_as_header_values() {
        let ok = VALID.replace(
            "[server]",
            "[server]\ncors_origins = [\"https://ui.example\", \"http://localhost:3000\"]",
        );
        parse(&ok).validate().expect("listed origins are valid");

        let wildcard = VALID.replace("[server]", "[server]\ncors_origins = [\"*\"]");
        parse(&wildcard)
            .validate()
            .expect("a lone wildcard is valid");

        for (entry, needle) in [
            ("[\"*\", \"https://ui.example\"]", "cannot be combined"),
            ("[\"ui.example\"]", "must be"),
            ("[\"\"]", "empty entry"),
            // Interior whitespace cannot be a header value; a stray
            // leading/trailing space is trimmed instead of refused.
            ("[\"https://ui example\"]", "spaces"),
        ] {
            let cfg = VALID.replace("[server]", &format!("[server]\ncors_origins = {entry}"));
            let msg = error_of(&cfg);
            assert!(msg.contains(needle), "{entry}: {msg}");
        }
    }

    /// Per-model limits: the numbers the dashboard offers are the numbers the
    /// validator accepts, and the runtime index answers every spelling of a model.
    #[test]
    fn model_limits_are_bounded_and_indexed_by_every_spelling() {
        let ok = VALID.to_string()
            + r#"
            [[model_limits]]
            model = "p/alpha"
            context_window = 131072
            max_output_tokens = 8192

            [[model_limits]]
            model = "beta"
            context_window = 32000
            "#;
        let cfg = parse(&ok);
        cfg.validate().expect("valid limits");

        let index = ModelLimits::build(cfg.model_limits.clone());
        // The qualified id and the bare name both resolve…
        assert_eq!(index.get("p/alpha").map(|l| l.context_window), Some(131072));
        assert_eq!(index.get("alpha").map(|l| l.max_output_tokens), Some(8192));
        // …as does a bare entry for a model served by any provider, even when the
        // provider-qualified spelling was never written.
        assert_eq!(index.get("beta").map(|l| l.context_window), Some(32000));
        assert_eq!(
            index.get("other/beta").map(|l| l.context_window),
            Some(32000)
        );
        assert!(index.get("gamma").is_none());

        // Out-of-range and contradictory numbers are refused, so the dashboard
        // cannot store something the next reload rejects.
        for (body, needle) in [
            (
                "model = \"p/a\"\ncontext_window = 100\nmax_output_tokens = 500",
                "cannot exceed",
            ),
            (
                "model = \"p/a\"\nmax_output_tokens = 2000000",
                "max_output_tokens",
            ),
            (
                "model = \"p/a\"\ncontext_window = 99000000",
                "context_window",
            ),
            ("model = \"\"\ncontext_window = 100", "empty model id"),
            ("model = \"p/a\"", "nothing to store"),
        ] {
            let cfg = VALID.to_string() + &format!("\n[[model_limits]]\n{body}\n");
            let msg = error_of(&cfg);
            assert!(msg.contains(needle), "{body}: {msg}");
        }

        // Two entries for the same model are ambiguous — reject instead of letting
        // the index pick one by iteration order.
        let dup = VALID.to_string()
            + "\n[[model_limits]]\nmodel = \"p/a\"\ncontext_window = 1000\n"
            + "\n[[model_limits]]\nmodel = \"p/a\"\ncontext_window = 2000\n";
        let msg = error_of(&dup);
        assert!(msg.contains("duplicate"), "{msg}");
    }

    /// The per-provider override wins over `server.max_retries`, which is bounded —
    /// so an unbounded override turned one request into a near-endless retry loop.
    #[test]
    fn per_provider_retry_and_timeout_bounds_are_enforced() {
        for (field, value) in [
            ("max_retries = 0", "max_retries"),
            ("max_retries = 1000", "max_retries"),
            ("timeout_secs = 0", "timeout_secs"),
            ("timeout_secs = 999999", "timeout_secs"),
        ] {
            let cfg = VALID.replace("keys = [\"sk-1\"]", &format!("keys = [\"sk-1\"]\n{field}"));
            let msg = error_of(&cfg);
            assert!(msg.contains(value), "{field}: {msg}");
        }
        let ok = VALID.replace(
            "keys = [\"sk-1\"]",
            "keys = [\"sk-1\"]\nmax_retries = 2\ntimeout_secs = 60",
        );
        parse(&ok).validate().expect("in-range overrides are valid");
    }

    /// Two client keys with the same name emit duplicate Prometheus series, and a
    /// duplicate sample makes Prometheus reject the whole scrape.
    #[test]
    fn duplicate_client_key_names_are_rejected() {
        let cfg = format!(
            r#"{VALID}
            api_key = "master-key-1"

            [[client_keys]]
            key = "ck-1"
            name = "team"

            [[client_keys]]
            key = "ck-2"
            name = "team"
            "#
        );
        // Admin credentials belong to [server]; splice them there. `admin_key` is
        // required as soon as client keys exist, and a valid document is what lets
        // this test reach the check it is actually about.
        let cfg = cfg.replace(
            "listen = \"127.0.0.1:8080\"",
            "listen = \"127.0.0.1:8080\"\napi_key = \"master-key-1\"\nadmin_key = \"admin-key-1\"",
        );
        let msg = error_of(&cfg);
        assert!(msg.contains("duplicates the name"), "{msg}");
    }

    // ----- A: validate() mirrors Provider::from_config -----

    #[test]
    fn a_valid_config_still_validates() {
        parse(VALID)
            .validate()
            .expect("the baseline config is valid");
    }

    /// `base_url` must be an http(s) URL, from the TOML path too.
    ///
    /// The dashboard edit path validated the scheme; `Config::validate` only
    /// checked "not empty". The runtime concatenates URLs
    /// (`format!("{base}/chat/completions")`) and attaches the provider key, so a
    /// hand-written `file://`, `gopher://` or link-local metadata address reached
    /// `reqwest` verbatim — an SSRF from a config file, reachable through
    /// `PUT /api/config`.
    #[test]
    fn a_base_url_that_is_not_http_is_rejected() {
        for bad in [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://example.com/v1",
            "ws://example.com/v1",
            "javascript:alert(1)",
            "not a url",
            "http://",
        ] {
            let text = format!(
                r#"
                [[providers]]
                name = "p"
                type = "openai_compat"
                base_url = "{bad}"
                keys = ["sk-1"]
                "#
            );
            let e = error_of(&text);
            assert!(
                e.contains("base_url must be an http(s) URL"),
                "{bad:?} must be rejected, got: {e}"
            );
        }

        // A normal endpoint still validates.
        for good in ["https://api.example.com/v1", "http://127.0.0.1:9100/v1"] {
            let text = format!(
                r#"
                [[providers]]
                name = "p"
                type = "openai_compat"
                base_url = "{good}"
                keys = ["sk-1"]
                "#
            );
            parse(&text)
                .validate()
                .unwrap_or_else(|e| panic!("{good:?} should be valid: {e}"));
        }

        // A link-local metadata address is a *valid* http URL: blocking it is a
        // separate policy decision (an operator may legitimately proxy through a
        // cloud metadata-adjacent host), so it validates and is documented as an
        // operator responsibility in RESIDUAL-RISKS.md.
        parse(
            r#"
                [[providers]]
                name = "p"
                type = "openai_compat"
                base_url = "http://169.254.169.254/v1"
                keys = ["sk-1"]
            "#,
        )
        .validate()
        .expect("http is http; the host is the operator's call");

        // And the predicate itself draws the line where the docs say it does.
        assert!(is_http_url("https://a.example/v1"));
        assert!(is_http_url("http://127.0.0.1:1/v1"));
        assert!(!is_http_url(""));
        assert!(!is_http_url("   "));
        assert!(!is_http_url("http://"));
        assert!(!is_http_url(&format!(
            "https://a.example/{}",
            "x".repeat(2048)
        )));
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

    /// Every `[tuning]` knob has a range, and a value outside it has to be
    /// refused *by name*: these numbers reach cooldown maths, timeouts and
    /// allocation sizes, so a silently accepted zero disables a guard (a zero
    /// cooldown turns a rate-limited key into a hot loop; a zero body timeout
    /// disables the slowloris bound).
    #[test]
    fn every_tuning_knob_rejects_out_of_range_values_by_name() {
        let cases = [
            ("max_cooldown_secs = 0", "max_cooldown_secs"),
            ("base_backoff_secs = 601", "base_backoff_secs"),
            ("rate_limit_cooldown_secs = 0", "rate_limit_cooldown_secs"),
            ("drain_fallback_secs = 0", "drain_fallback_secs"),
            ("models_cache_ttl_secs = 0", "models_cache_ttl_secs"),
            ("connect_timeout_secs = 0", "connect_timeout_secs"),
            ("meta_timeout_secs = 301", "meta_timeout_secs"),
            ("sticky_mode = \"rendezvous\"", "sticky_mode"),
            ("shutdown_grace_secs = 0", "shutdown_grace_secs"),
            ("client_body_timeout_secs = 0", "client_body_timeout_secs"),
            ("capacity_wait_ms = 30001", "capacity_wait_ms"),
            ("sticky_ttl_secs = 0", "sticky_ttl_secs"),
            ("sticky_max_entries = 15", "sticky_max_entries"),
            ("session_prefix_bytes = 255", "session_prefix_bytes"),
            ("event_channel_capacity = 0", "event_channel_capacity"),
            ("persist_interval_secs = 0", "persist_interval_secs"),
            ("oauth_http_timeout_secs = 0", "oauth_http_timeout_secs"),
            (
                "token_refresh_window_secs = 3601",
                "token_refresh_window_secs",
            ),
            ("ui_refresh_secs = 0", "ui_refresh_secs"),
            ("sse_keepalive_secs = 0", "sse_keepalive_secs"),
            ("quota_cache_ttl_secs = 0", "quota_cache_ttl_secs"),
            ("response_store_max = 100001", "response_store_max"),
        ];
        for (line, field) in cases {
            let text = format!(
                r#"
                [[providers]]
                name = "p"
                type = "openai_compat"
                base_url = "http://127.0.0.1:9/v1"
                keys = ["sk-1"]

                [tuning]
                {line}
                "#
            );
            let e = error_of(&text);
            assert!(
                e.contains(field),
                "tuning '{line}' must be rejected naming {field}, got: {e}"
            );
        }

        // The documented "off" values are legal: 0 capacity wait (fail fast),
        // 0 refresh window (refresh only on expiry) and 0 store cap (disabled).
        let text = r#"
            [[providers]]
            name = "p"
            type = "openai_compat"
            base_url = "http://127.0.0.1:9/v1"
            keys = ["sk-1"]

            [tuning]
            capacity_wait_ms = 0
            token_refresh_window_secs = 0
            response_store_max = 0
        "#;
        parse(text)
            .validate()
            .expect("the documented zero values are valid");
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
