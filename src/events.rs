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
}
