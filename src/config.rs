use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
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
}

fn default_state_file() -> String {
    "anyhop.redb".into()
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
