use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Strategy;

const STATUS_ACTIVE: u8 = 0;
const STATUS_COOLDOWN: u8 = 1;
const STATUS_DEAD: u8 = 2;

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
            STATUS_COOLDOWN => {
                if now_ms() >= self.cooldown_until_ms.load(Ordering::Relaxed) {
                    // Lazy promote back to active.
                    self.status.store(STATUS_ACTIVE, Ordering::Relaxed);
                    self.consecutive_failures.store(0, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn set_cooldown(&self, d: Duration) {
        let d = d.min(MAX_COOLDOWN);
        self.cooldown_until_ms
            .store(now_ms() + d.as_millis() as u64, Ordering::Relaxed);
        self.status.store(STATUS_COOLDOWN, Ordering::Relaxed);
    }
}

pub struct KeyPool {
    strategy: Strategy,
    keys: Vec<Arc<KeyState>>,
    cursor: AtomicUsize,
}

impl KeyPool {
    pub fn new(secrets: Vec<String>, strategy: Strategy) -> Self {
        Self {
            strategy,
            keys: secrets.into_iter().map(|s| Arc::new(KeyState::new(s))).collect(),
            cursor: AtomicUsize::new(0),
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
    }
}
