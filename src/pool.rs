use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Strategy;
use crate::storage::{HealthRecord, StatsRecord, Storage};

pub const STATUS_ACTIVE: u8 = 0;
pub const STATUS_COOLDOWN: u8 = 1;
pub const STATUS_DEAD: u8 = 2;

const MAX_COOLDOWN: Duration = Duration::from_secs(300);
const DEFAULT_RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(60);
const BASE_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub enum FailKind {
    /// HTTP 429. Honors Retry-After when present.
    RateLimited { retry_after_secs: Option<u64> },
    /// HTTP 401/403 — key is invalid, never retry it.
    Auth,
    /// HTTP 5xx from upstream.
    Server,
    /// Timeout / connect failure / reset.
    Network,
}

pub struct KeyState {
    pub secret: String,
    status: AtomicU8,
    /// Unix epoch millis until which the key is in cooldown. 0 = none.
    cooldown_until_ms: AtomicU64,
    pub requests: AtomicU64,
    pub failures: AtomicU64,
    consecutive_failures: AtomicU64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl KeyState {
    fn new(secret: String) -> Self {
        Self {
            secret,
            status: AtomicU8::new(STATUS_ACTIVE),
            cooldown_until_ms: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
        }
    }

    pub fn masked(&self) -> String {
        let s = &self.secret;
        if s.len() <= 8 { "****".into() } else { format!("{}…", &s[..8]) }
    }

    fn is_available(&self) -> bool {
        match self.status.load(Ordering::Relaxed) {
            STATUS_ACTIVE => true,
            // Lazy promote back to active once cooldown expires.
            STATUS_COOLDOWN if now_ms() >= self.cooldown_until_ms.load(Ordering::Relaxed) => {
                self.status.store(STATUS_ACTIVE, Ordering::Relaxed);
                self.consecutive_failures.store(0, Ordering::Relaxed);
                true
            }
            STATUS_COOLDOWN => false,
            _ => false,
        }
    }

    fn set_cooldown(&self, d: Duration) {
        let d = d.min(MAX_COOLDOWN);
        self.cooldown_until_ms
            .store(now_ms() + d.as_millis() as u64, Ordering::Relaxed);
        self.status.store(STATUS_COOLDOWN, Ordering::Relaxed);
    }

    fn health(&self) -> HealthRecord {
        HealthRecord {
            status: self.status.load(Ordering::Relaxed),
            cooldown_until_ms: self.cooldown_until_ms.load(Ordering::Relaxed),
        }
    }

    fn restore_health(&self, rec: &HealthRecord) {
        self.status.store(rec.status, Ordering::Relaxed);
        self.cooldown_until_ms
            .store(rec.cooldown_until_ms, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KeySnapshot {
    pub masked: String,
    pub status: String,
    pub cooldown_remaining_secs: u64,
    pub requests: u64,
    pub failures: u64,
}

pub struct KeyPool {
    name: String,
    strategy: Strategy,
    keys: Vec<Arc<KeyState>>,
    cursor: AtomicUsize,
    storage: Option<Storage>,
}

impl KeyPool {
    pub fn new(
        name: String,
        secrets: Vec<String>,
        strategy: Strategy,
        storage: Option<Storage>,
    ) -> Self {
        let pool = Self {
            name,
            strategy,
            keys: secrets.into_iter().map(|s| Arc::new(KeyState::new(s))).collect(),
            cursor: AtomicUsize::new(0),
            storage,
        };
        pool.restore();
        pool
    }

    /// Restore health and stats persisted from previous runs.
    fn restore(&self) {
        let Some(storage) = &self.storage else { return };
        for key in &self.keys {
            if let Some(h) = storage.load_health(&self.name, &key.secret) {
                key.restore_health(&h);
            }
            if let Some(s) = storage.load_stats(&self.name, &key.secret) {
                key.requests.store(s.requests, Ordering::Relaxed);
                key.failures.store(s.failures, Ordering::Relaxed);
            }
        }
    }

    fn persist_health(&self, key: &KeyState) {
        if let Some(storage) = &self.storage {
            storage.save_health(&self.name, &key.secret, key.health());
        }
    }

    /// Snapshot for the dashboard.
    pub fn snapshot(&self) -> Vec<KeySnapshot> {
        let now = now_ms();
        self.keys
            .iter()
            .map(|k| {
                let status = k.status.load(Ordering::Relaxed);
                let until = k.cooldown_until_ms.load(Ordering::Relaxed);
                KeySnapshot {
                    masked: k.masked(),
                    status: match status {
                        STATUS_ACTIVE => "active",
                        STATUS_COOLDOWN if now >= until => "active",
                        STATUS_COOLDOWN => "cooldown",
                        _ => "dead",
                    }
                    .to_string(),
                    cooldown_remaining_secs: if status == STATUS_COOLDOWN && until > now {
                        (until - now) / 1000
                    } else {
                        0
                    },
                    requests: k.requests.load(Ordering::Relaxed),
                    failures: k.failures.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Persist current request/failure counters (called periodically).
    pub fn persist_stats(&self) {
        let Some(storage) = &self.storage else { return };
        for key in &self.keys {
            storage.save_stats(
                &self.name,
                &key.secret,
                StatsRecord {
                    requests: key.requests.load(Ordering::Relaxed),
                    failures: key.failures.load(Ordering::Relaxed),
                },
            );
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Pick the next available key according to the strategy. None = all cooling down/dead.
    pub fn pick(&self) -> Option<Arc<KeyState>> {
        if self.keys.is_empty() {
            return None;
        }
        match self.strategy {
            Strategy::RoundRobin => {
                let n = self.keys.len();
                let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
                (0..n)
                    .map(|i| &self.keys[(start + i) % n])
                    .find(|k| k.is_available())
                    .cloned()
            }
            Strategy::LeastUsed => self
                .keys
                .iter()
                .filter(|k| k.is_available())
                .min_by_key(|k| k.requests.load(Ordering::Relaxed))
                .cloned(),
            Strategy::FillFirst => self.keys.iter().find(|k| k.is_available()).cloned(),
        }
    }

    pub fn report_success(&self, key: &KeyState) {
        key.requests.fetch_add(1, Ordering::Relaxed);
        key.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn report_failure(&self, key: &KeyState, kind: FailKind) {
        key.requests.fetch_add(1, Ordering::Relaxed);
        key.failures.fetch_add(1, Ordering::Relaxed);
        match kind {
            FailKind::Auth => {
                key.status.store(STATUS_DEAD, Ordering::Relaxed);
            }
            FailKind::RateLimited { retry_after_secs } => {
                // Rate limit is a quota signal, not instability — no exponential backoff.
                key.consecutive_failures.store(0, Ordering::Relaxed);
                key.set_cooldown(
                    retry_after_secs
                        .map(Duration::from_secs)
                        .unwrap_or(DEFAULT_RATE_LIMIT_COOLDOWN),
                );
            }
            FailKind::Server | FailKind::Network => {
                let n = key.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                let shift = (n - 1).min(6) as u32;
                key.set_cooldown(BASE_BACKOFF * 2u32.pow(shift));
            }
        }
        self.persist_health(key);
    }
}
