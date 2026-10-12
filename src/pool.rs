use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Strategy;
use crate::storage::{HealthRecord, StatsRecord, Storage};

pub const STATUS_ACTIVE: u8 = 0;
pub const STATUS_COOLDOWN: u8 = 1;
pub const STATUS_DEAD: u8 = 2;

const MAX_COOLDOWN: Duration = Duration::from_secs(3600);
const DEFAULT_RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(60);
const BASE_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub enum FailKind {
    /// HTTP 429, quota is per-key. Honors Retry-After when present.
    RateLimited { retry_after_secs: Option<u64> },
    /// Per-model quota exhausted (Antigravity): only this model cools down,
    /// the key keeps serving other models.
    ModelQuota { until_ms: u64 },
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
    /// Per-model cooldowns (model id -> until unix ms).
    model_cooldowns: Mutex<HashMap<String, u64>>,
    in_flight: AtomicU32,
    max_concurrent: u32,
    pub requests: AtomicU64,
    pub failures: AtomicU64,
    pub prompt_tokens: AtomicU64,
    pub completion_tokens: AtomicU64,
    consecutive_failures: AtomicU64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl KeyState {
    fn new(secret: String, max_concurrent: u32) -> Self {
        Self {
            secret,
            status: AtomicU8::new(STATUS_ACTIVE),
            cooldown_until_ms: AtomicU64::new(0),
            model_cooldowns: Mutex::new(HashMap::new()),
            in_flight: AtomicU32::new(0),
            max_concurrent,
            requests: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            prompt_tokens: AtomicU64::new(0),
            completion_tokens: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
        }
    }

    pub fn masked(&self) -> String {
        let s = &self.secret;
        if s.len() <= 8 { "****".into() } else { format!("{}…", &s[..8]) }
    }

    fn is_available(&self, model: &str) -> bool {
        match self.status.load(Ordering::Relaxed) {
            STATUS_ACTIVE => {}
            // Lazy promote back to active once cooldown expires.
            STATUS_COOLDOWN if now_ms() >= self.cooldown_until_ms.load(Ordering::Relaxed) => {
                self.status.store(STATUS_ACTIVE, Ordering::Relaxed);
                self.consecutive_failures.store(0, Ordering::Relaxed);
            }
            _ => return false,
        }
        // Per-model cooldown?
        let mut mc = self.model_cooldowns.lock().unwrap();
        if let Some(until) = mc.get(model).copied() {
            if now_ms() < until {
                return false;
            }
            mc.remove(model);
        }
        drop(mc);
        // Admission control.
        self.max_concurrent == 0 || self.in_flight.load(Ordering::Relaxed) < self.max_concurrent
    }

    /// Acquire an in-flight slot. Returns None when saturated.
    pub fn try_acquire(self: &Arc<Self>) -> Option<KeyGuard> {
        let limit = self.max_concurrent;
        loop {
            let cur = self.in_flight.load(Ordering::Relaxed);
            if limit > 0 && cur >= limit {
                return None;
            }
            if self
                .in_flight
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(KeyGuard { key: self.clone() });
            }
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

/// RAII in-flight slot; decrements on drop (including dropped streams).
pub struct KeyGuard {
    key: Arc<KeyState>,
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        self.key.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KeySnapshot {
    /// Stable opaque id (hash prefix), used by the dashboard actions.
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

pub struct KeyPool {
    name: String,
    strategy: Strategy,
    max_concurrent: u32,
    keys: Mutex<Vec<Arc<KeyState>>>,
    cursor: AtomicUsize,
    storage: Option<Storage>,
    events: Option<crate::events::EventBus>,
}

impl KeyPool {
    pub fn new(
        name: String,
        secrets: Vec<String>,
        strategy: Strategy,
        max_concurrent: u32,
        storage: Option<Storage>,
        events: Option<crate::events::EventBus>,
    ) -> Self {
        let pool = Self {
            name,
            strategy,
            max_concurrent,
            keys: Mutex::new(
                secrets
                    .into_iter()
                    .map(|s| Arc::new(KeyState::new(s, max_concurrent)))
                    .collect(),
            ),
            cursor: AtomicUsize::new(0),
            storage,
            events,
        };
        pool.restore();
        pool
    }

    /// Restore health and stats persisted from previous runs.
    fn restore(&self) {
        let Some(storage) = &self.storage else { return };
        for key in self.keys.lock().unwrap().iter() {
            Self::restore_key(storage, &self.name, key);
        }
    }

    fn restore_key(storage: &Storage, name: &str, key: &Arc<KeyState>) {
        if let Some(h) = storage.load_health(name, &key.secret) {
            key.restore_health(&h);
        }
        if let Some(s) = storage.load_stats(name, &key.secret) {
            key.requests.store(s.requests, Ordering::Relaxed);
            key.failures.store(s.failures, Ordering::Relaxed);
            key.prompt_tokens.store(s.prompt_tokens, Ordering::Relaxed);
            key.completion_tokens
                .store(s.completion_tokens, Ordering::Relaxed);
        }
    }

    fn persist_health(&self, key: &KeyState) {
        if let Some(storage) = &self.storage {
            storage.save_health(&self.name, &key.secret, key.health());
        }
    }

    /// Persist current counters (called periodically).
    pub fn persist_stats(&self) {
        let Some(storage) = &self.storage else { return };
        for key in self.keys.lock().unwrap().iter() {
            storage.save_stats(
                &self.name,
                &key.secret,
                StatsRecord {
                    requests: key.requests.load(Ordering::Relaxed),
                    failures: key.failures.load(Ordering::Relaxed),
                    prompt_tokens: key.prompt_tokens.load(Ordering::Relaxed),
                    completion_tokens: key.completion_tokens.load(Ordering::Relaxed),
                },
            );
        }
    }

    fn emit(&self, key: &KeyState, kind: &'static str, detail: String) {
        if let Some(bus) = &self.events {
            bus.emit_simple(&self.name, &key.masked(), kind, detail);
        }
    }

    pub fn len(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    /// Pick the next key available for this model according to the strategy.
    pub fn pick(&self, model: &str) -> Option<Arc<KeyState>> {
        let keys = self.keys.lock().unwrap();
        if keys.is_empty() {
            return None;
        }
        match self.strategy {
            Strategy::RoundRobin => {
                let n = keys.len();
                let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
                (0..n)
                    .map(|i| &keys[(start + i) % n])
                    .find(|k| k.is_available(model))
                    .cloned()
            }
            Strategy::LeastUsed => keys
                .iter()
                .filter(|k| k.is_available(model))
                .min_by_key(|k| k.requests.load(Ordering::Relaxed))
                .cloned(),
            Strategy::FillFirst => keys.iter().find(|k| k.is_available(model)).cloned(),
        }
    }

    /// Proactively cool a key down before it hits the limit (rate-limit headers).
    pub fn drain(&self, key: &KeyState, d: Duration) {
        key.set_cooldown(d);
        self.persist_health(key);
        self.emit(key, "drain", format!("proactive cooldown {}s", d.as_secs()));
    }

    pub fn report_success(&self, key: &KeyState) {
        key.requests.fetch_add(1, Ordering::Relaxed);
        key.consecutive_failures.store(0, Ordering::Relaxed);
    }

    pub fn report_failure(&self, key: &KeyState, kind: FailKind, model: &str) {
        key.requests.fetch_add(1, Ordering::Relaxed);
        key.failures.fetch_add(1, Ordering::Relaxed);
        match kind {
            FailKind::Auth => {
                key.status.store(STATUS_DEAD, Ordering::Relaxed);
                self.emit(key, "dead", "auth rejected, key disabled".into());
            }
            FailKind::ModelQuota { until_ms } => {
                key.consecutive_failures.store(0, Ordering::Relaxed);
                let secs = until_ms.saturating_sub(now_ms()) / 1000;
                key.model_cooldowns
                    .lock()
                    .unwrap()
                    .insert(model.to_string(), until_ms);
                self.emit(
                    key,
                    "rate_limited",
                    format!("model '{model}' quota, cooldown {secs}s"),
                );
                return; // per-model only, nothing global to persist
            }
            FailKind::RateLimited { retry_after_secs } => {
                // Rate limit is a quota signal, not instability — no exponential backoff.
                key.consecutive_failures.store(0, Ordering::Relaxed);
                let d = retry_after_secs
                    .map(Duration::from_secs)
                    .unwrap_or(DEFAULT_RATE_LIMIT_COOLDOWN)
                    .min(MAX_COOLDOWN);
                key.set_cooldown(d);
                self.emit(key, "rate_limited", format!("cooldown {}s", d.as_secs()));
            }
            FailKind::Server | FailKind::Network => {
                let n = key.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                let shift = (n - 1).min(6) as u32;
                let d = (BASE_BACKOFF * 2u32.pow(shift)).min(MAX_COOLDOWN);
                key.set_cooldown(d);
                self.emit(key, "backoff", format!("cooldown {}s", d.as_secs()));
            }
        }
        self.persist_health(key);
    }

    // ----- dashboard management -----

    fn key_by_id(&self, id: &str) -> Option<Arc<KeyState>> {
        if id.len() < 8 {
            return None;
        }
        self.keys
            .lock()
            .unwrap()
            .iter()
            .find(|k| crate::storage::key_id(&self.name, &k.secret).ends_with(id))
            .cloned()
    }

    /// Enable (clear dead/cooldown) or disable (dead) a key. Returns false if unknown id.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> bool {
        let Some(key) = self.key_by_id(id) else { return false };
        if enabled {
            key.status.store(STATUS_ACTIVE, Ordering::Relaxed);
            key.cooldown_until_ms.store(0, Ordering::Relaxed);
            key.consecutive_failures.store(0, Ordering::Relaxed);
        } else {
            key.status.store(STATUS_DEAD, Ordering::Relaxed);
        }
        self.persist_health(&key);
        self.emit(
            &key,
            "backoff",
            if enabled { "key enabled manually" } else { "key disabled manually" }.into(),
        );
        true
    }

    pub fn contains(&self, secret: &str) -> bool {
        self.keys.lock().unwrap().iter().any(|k| k.secret == secret)
    }

    /// Add a key at runtime (dashboard). Restores persisted health/stats.
    pub fn add_key(&self, secret: String) {
        let key = Arc::new(KeyState::new(secret, self.max_concurrent));
        if let Some(storage) = &self.storage {
            Self::restore_key(storage, &self.name, &key);
        }
        self.keys.lock().unwrap().push(key);
    }

    /// Snapshot for the dashboard.
    pub fn snapshot(&self) -> Vec<KeySnapshot> {
        let now = now_ms();
        self.keys
            .lock()
            .unwrap()
            .iter()
            .map(|k| {
                let status = k.status.load(Ordering::Relaxed);
                let until = k.cooldown_until_ms.load(Ordering::Relaxed);
                let id = crate::storage::key_id(&self.name, &k.secret);
                KeySnapshot {
                    id: id.rsplit(':').next().unwrap_or(&id).to_string(),
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
                    in_flight: k.in_flight.load(Ordering::Relaxed),
                    requests: k.requests.load(Ordering::Relaxed),
                    failures: k.failures.load(Ordering::Relaxed),
                    prompt_tokens: k.prompt_tokens.load(Ordering::Relaxed),
                    completion_tokens: k.completion_tokens.load(Ordering::Relaxed),
                }
            })
            .collect()
    }
}
