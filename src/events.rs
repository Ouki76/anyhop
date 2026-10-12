//! Failover event feed for the dashboard.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DashEvent {
    pub ts: u64,
    pub provider: String,
    pub key: String,
    pub kind: &'static str,
    pub detail: String,
}

impl DashEvent {
    pub fn new(provider: &str, key: &str, kind: &'static str, detail: String) -> Self {
        Self {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            provider: provider.to_string(),
            key: key.to_string(),
            kind,
            detail,
        }
    }

    pub fn time_hms(&self) -> String {
        let s = self.ts % 86400;
        format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    }

    /// HTML fragment for the htmx SSE feed.
    pub fn to_html(&self) -> String {
        let cls = match self.kind {
            "rate_limited" => "ev-warn",
            "dead" => "ev-err",
            _ => "ev-info",
        };
        format!(
            "<div class=\"ev {cls}\"><span class=\"ev-ts\">{}</span> \
             <b>{}</b> [{}] {} — {}</div>",
            self.time_hms(),
            html_escape(&self.provider),
            self.kind,
            html_escape(&self.key),
            html_escape(&self.detail),
        )
    }
}

pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
