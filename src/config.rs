use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub combos: Vec<ComboConfig>,
}

/// A virtual model: ordered fallback chain across providers.
/// Referenced as the combo name (or `combo/<name>`).
#[derive(Debug, Clone, Deserialize)]
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
        anyhow::ensure!(!cfg.providers.is_empty(), "config has no [[providers]]");
        Ok(cfg)
    }
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
    pub accounts: Vec<AntigravityAccountConfig>,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct AntigravityAccountConfig {
    /// May be empty when `access_token` is provided (dev/testing shortcut).
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
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
