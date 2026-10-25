//! DTOs and tab types shared across the UI.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ClientKeyDto {
    #[serde(default)]
    pub max_concurrent: Option<u32>,
    /// Stable public id — the listing never carries the secret itself.
    #[serde(default)]
    pub id: String,
    /// Present only in the response that created the key.
    #[serde(default)]
    pub key: Option<String>,
    pub masked: String,
    pub name: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub created_at: u64,
    /// Sustained requests per minute (0 = unlimited).
    #[serde(default)]
    pub rpm: u32,
    /// Spike allowance (0 = same as rpm).
    #[serde(default)]
    pub burst: u32,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ModelItemDto {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub enabled: bool,
    /// The numbers that apply (override → provider; 0 = unknown).
    #[serde(default)]
    pub limits: ModelLimits,
    /// Where each number came from: override | provider | unknown.
    #[serde(default)]
    pub sources: LimitSources,
    /// The operator's own values (0 = not set) — what the editor's inputs show.
    #[serde(default)]
    pub overrides: ModelLimits,
    /// The config key the overrides live under ("" = none).
    #[serde(default)]
    pub limits_source: String,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct LimitSources {
    #[serde(default)]
    pub context_window: String,
    #[serde(default)]
    pub max_output_tokens: String,
    #[serde(default)]
    pub max_input_tokens: String,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct ModelLimits {
    #[serde(default)]
    pub context_window: u64,
    #[serde(default)]
    pub max_output_tokens: u64,
    #[serde(default)]
    pub max_input_tokens: u64,
}

impl ModelItemDto {
    /// Did the operator set this field? Only then does "Reset" make sense.
    pub fn is_overridden(&self, field: &str) -> bool {
        match field {
            "context_window" => self.overrides.context_window > 0,
            "max_output_tokens" => self.overrides.max_output_tokens > 0,
            _ => self.overrides.max_input_tokens > 0,
        }
    }

    /// The operator's value for a field (0 = not set).
    pub fn override_of(&self, field: &str) -> u64 {
        match field {
            "context_window" => self.overrides.context_window,
            "max_output_tokens" => self.overrides.max_output_tokens,
            _ => self.overrides.max_input_tokens,
        }
    }

    /// Where a field's effective value came from.
    pub fn source_of(&self, field: &str) -> String {
        let s = match field {
            "context_window" => &self.sources.context_window,
            "max_output_tokens" => &self.sources.max_output_tokens,
            _ => &self.sources.max_input_tokens,
        };
        if s.is_empty() { "unknown".to_string() } else { s.clone() }
    }

    /// "128k", "1M", "8192" — compact enough for a row.
    pub fn context_label(&self) -> String {
        fmt_tokens(self.limits.context_window)
    }

    pub fn output_label(&self) -> String {
        fmt_tokens(self.limits.max_output_tokens)
    }

    /// 1048576 -> "1 048 576" (thin thousands groups, readable at a glance).
    pub fn context_exact(&self) -> String {
        fmt_exact(self.limits.context_window)
    }

    pub fn output_exact(&self) -> String {
        fmt_exact(self.limits.max_output_tokens)
    }

    pub fn input_exact(&self) -> String {
        fmt_exact(self.limits.max_input_tokens)
    }
}

/// 0 -> "—", 1048576 -> "1 048 576", 8192 -> "8 192".
pub fn fmt_exact(n: u64) -> String {
    if n == 0 {
        return "—".to_string();
    }
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push('\u{2009}');
        }
        out.push(c);
    }
    out
}

/// 0 -> "—", 1500 -> "1.5k", 131072 -> "131k", 1_048_576 -> "1M".
pub fn fmt_tokens(n: u64) -> String {
    if n == 0 {
        return "—".to_string();
    }
    if n >= 1_000_000 {
        let m = n as f64 / 1_000_000.0;
        return if (m - m.round()).abs() < 0.05 {
            format!("{}M", m.round() as u64)
        } else {
            format!("{m:.1}M")
        };
    }
    if n >= 1000 {
        let k = n as f64 / 1000.0;
        return if (k - k.round()).abs() < 0.05 {
            format!("{}k", k.round() as u64)
        } else {
            format!("{k:.1}k")
        };
    }
    n.to_string()
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ComboDto {
    pub name: String,
    pub chain: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct KeyDto {
    pub id: String,
    pub masked: String,
    pub status: String,
    pub cooldown_remaining_secs: u64,
    pub in_flight: u32,
    pub requests: u64,
    pub failures: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

/// A provider's *structure* — everything except the counters that change with
/// traffic.
///
/// The page re-renders when this tuple changes; the poll loop must not use the full
/// `ProviderDto`, because `in_flight`/`requests`/`failures` move every few seconds
/// and rebuilding the detail page wipes whatever the operator is typing (settings
/// form, a key being pasted).
pub type ProviderShape = (
    String,
    String,
    String,
    String,
    Vec<(String, String, String)>, // (key id, masked, status)
    Vec<String>,
    u32,
    u32,
    Vec<String>,
);

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProviderDto {
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub name: String,
    #[serde(default)]
    pub timeout_secs: u64,
    #[serde(default)]
    pub max_retries: usize,
    pub kind: String,
    pub strategy: String,
    pub base_url: String,
    pub keys: Vec<KeyDto>,
    #[serde(default)]
    pub models: Vec<String>,
    /// Editable settings.
    #[serde(default)]
    pub max_concurrent: u32,
    #[serde(default)]
    pub drain_below_pct: u32,
    #[serde(default)]
    pub proxy: Option<String>,
    /// OAuth providers get accounts, not keys — the UI hides "add key" for them.
    #[serde(default)]
    pub oauth: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct QuotaModelDto {
    pub id: String,
    pub pct: Option<u64>,
    pub low: bool,
    pub reset: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct QuotaDto {
    pub provider: String,
    pub account: String,
    pub models: Vec<QuotaModelDto>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct EventDto {
    pub ts: u64,
    pub provider: String,
    pub key: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Providers,
    Models,
    ApiKeys,
    Quotas,
    Events,
    Requests,
    Settings,
    Config,
}

/// Sidebar navigation: (group label, items), in display order.
pub const NAV: &[(&str, &[(Tab, &str)])] = &[
    ("Main", &[(Tab::Overview, "Overview")]),
    (
        "Manage",
        &[
            (Tab::Providers, "Providers"),
            (Tab::Models, "Models"),
            (Tab::ApiKeys, "API Keys"),
        ],
    ),
    (
        "Observe",
        &[
            (Tab::Quotas, "Quotas"),
            (Tab::Events, "Events"),
            (Tab::Requests, "Requests"),
        ],
    ),
    (
        "System",
        &[(Tab::Settings, "Settings"), (Tab::Config, "Config")],
    ),
];

impl Tab {
    /// URL hash identifying the tab.
    pub fn hash(self) -> &'static str {
        match self {
            Tab::Overview => "overview",
            Tab::Providers => "providers",
            Tab::Models => "models",
            Tab::ApiKeys => "keys",
            Tab::Quotas => "quotas",
            Tab::Events => "events",
            Tab::Requests => "requests",
            Tab::Settings => "settings",
            Tab::Config => "config",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RequestDto {
    pub ts: u64,
    pub provider: String,
    pub model: String,
    pub key: String,
    pub status: String,
    pub latency_ms: u64,
    pub stream: bool,
    #[serde(default)]
    pub client_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct TuningDto {
    #[serde(default)]
    pub client_body_timeout_secs: u64,
    #[serde(default)]
    pub shutdown_grace_secs: u64,
    #[serde(default)]
    pub capacity_wait_ms: u64,
    #[serde(default)]
    pub response_store_max: usize,
    pub max_cooldown_secs: u64,
    pub base_backoff_secs: u64,
    pub rate_limit_cooldown_secs: u64,
    pub drain_fallback_secs: u64,
    pub models_cache_ttl_secs: u64,
    pub connect_timeout_secs: u64,
    pub meta_timeout_secs: u64,
    pub sticky_ttl_secs: u64,
    pub sticky_max_entries: usize,
    pub session_prefix_bytes: usize,
    pub event_channel_capacity: usize,
    pub persist_interval_secs: u64,
    pub oauth_http_timeout_secs: u64,
    pub token_refresh_window_secs: u64,
    pub ui_refresh_secs: u64,
    pub sse_keepalive_secs: u64,
    pub quota_cache_ttl_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServerDto {
    pub listen: String,
    pub max_retries: usize,
    pub attempt_timeout_secs: u64,
    pub max_body_bytes: usize,
    pub events_history: usize,
    pub requests_history: usize,
    pub models_refresh_secs: u64,
    pub dashboard: bool,
    #[serde(default)]
    pub proxy: Option<String>,
    pub state_file: String,
    /// Public base URL used for OAuth redirects (empty = loopback only).
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
    #[serde(default)]
    pub log_format: String,
    #[serde(default)]
    pub client_key_max_concurrent: u32,
    #[serde(default)]
    pub auth_fail_burst: u32,
    #[serde(default)]
    pub auth_fail_window_secs: u64,
    /// Secrets are never returned — only whether they are configured.
    pub api_key_set: bool,
    pub admin_key_set: bool,
    pub tuning: TuningDto,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AuthStateDto {
    pub kind: String,
    #[serde(default)]
    pub provider: String,
    pub status: String,
    pub url: String,
    /// loopback | public
    #[serde(default)]
    pub mode: String,
    pub message: String,
}
