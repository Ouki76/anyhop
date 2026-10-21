use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Strategy;
use crate::storage::{HealthRecord, StatsRecord, Storage};

pub const STATUS_ACTIVE: u8 = 0;
pub const STATUS_COOLDOWN: u8 = 1;
pub const STATUS_DEAD: u8 = 2;

// Cooldown/backoff values are configurable via `[tuning]` — see config::Tuning.

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
    /// Human label used in the dashboard/logs instead of a masked secret
    /// (OAuth accounts: the account e-mail). Set once at construction.
    label: std::sync::OnceLock<String>,
    /// sha256(secret)[..16] hex — computed once; per-request hashing showed up
    /// on the sticky-session hot path.
    id_hash: String,
    status: AtomicU8,
    /// Unix epoch millis until which the key is in cooldown. 0 = none.
    cooldown_until_ms: AtomicU64,
    /// Per-model cooldowns (model id -> until unix ms).
    model_cooldowns: Mutex<HashMap<String, u64>>,
    /// True while `model_cooldowns` is non-empty. Lets the hot path skip the
    /// mutex entirely — it is empty for almost every request.
    has_model_cooldowns: AtomicBool,
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

/// Lock a std Mutex, recovering from poisoning: our guards protect plain data
/// (no invariant a panic could corrupt), so a poisoned lock must not wedge
/// the whole pool.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl KeyState {
    fn new(secret: String, max_concurrent: u32) -> Self {
        // Same id format storage uses for health/stats keys — computed directly
        // instead of slicing a formatted "provider:hash" string.
        let id_hash = crate::storage::secret_hash(&secret);
        Self {
            secret,
            label: std::sync::OnceLock::new(),
            id_hash,
            status: AtomicU8::new(STATUS_ACTIVE),
            cooldown_until_ms: AtomicU64::new(0),
            model_cooldowns: Mutex::new(HashMap::new()),
            has_model_cooldowns: AtomicBool::new(false),
            in_flight: AtomicU32::new(0),
            max_concurrent,
            requests: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            prompt_tokens: AtomicU64::new(0),
            completion_tokens: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
        }
    }

    /// How this credential is shown to an operator: the account label when there
    /// is one, otherwise a short mask of the secret.
    ///
    /// For OAuth providers the "secret" is a refresh token whose first 8 chars are
    /// the same for every Google account (`1//0c…`), so masking it leaked a token
    /// prefix and told the accounts apart badly. The e-mail is both safer and
    /// more useful.
    pub fn masked(&self) -> String {
        if let Some(l) = self.label.get() {
            return l.clone();
        }
        let s = &self.secret;
        // char-safe: &s[..8] panics when byte 8 splits a multi-byte char
        let mut it = s.chars();
        let prefix: String = it.by_ref().take(8).collect();
        if it.next().is_none() {
            "****".into()
        } else {
            format!("{prefix}…")
        }
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
        // Per-model cooldown? Skipped without touching the mutex when the map has
        // never been written (the overwhelmingly common case).
        if self.has_model_cooldowns.load(Ordering::Relaxed) {
            let mut mc = lock(&self.model_cooldowns);
            if let Some(until) = mc.get(model).copied() {
                if now_ms() < until {
                    return false;
                }
                mc.remove(model);
                if mc.is_empty() {
                    self.has_model_cooldowns.store(false, Ordering::Relaxed);
                }
            }
        }
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

    /// Bench this key for `d`, clamped to the configured maximum.
    fn set_cooldown(&self, d: Duration, max: Duration) {
        let d = d.min(max);
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
    /// Sticky sessions: session hash -> (key id hash, last seen unix ms).
    /// Keeps a conversation on one key so the provider-side KV cache hits.
    sticky: Mutex<HashMap<u64, (String, u64)>>,
    tuning: std::sync::Arc<crate::config::Tuning>,
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
        // Tests and simple call sites get the defaults; production goes through
        // `new_with_tuning` so the config file is authoritative.
        Self::new_with_tuning(
            name,
            secrets,
            strategy,
            max_concurrent,
            storage,
            events,
            std::sync::Arc::new(crate::config::Tuning::default()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tuning(
        name: String,
        secrets: Vec<String>,
        strategy: Strategy,
        max_concurrent: u32,
        storage: Option<Storage>,
        events: Option<crate::events::EventBus>,
        tuning: std::sync::Arc<crate::config::Tuning>,
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
            sticky: Mutex::new(HashMap::new()),
            tuning,
        };
        pool.restore();
        pool
    }

    /// Restore health and stats persisted from previous runs.
    fn restore(&self) {
        let Some(storage) = &self.storage else { return };
        for key in lock(&self.keys).iter() {
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
        for key in lock(&self.keys).iter() {
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
        lock(&self.keys).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether sticky routing can change the outcome for this pool.
    ///
    /// With a single key, or with `fill_first` (which is sticky by construction),
    /// the session hash is computed and thrown away — skipping it saves a SHA-256
    /// over the body prefix on every request.
    pub fn sticky_enabled(&self) -> bool {
        !matches!(self.strategy, Strategy::FillFirst) && self.len() > 1
    }

    /// Pick the next key available for this model according to the strategy.
    /// `session` enables sticky routing: the same session hash sticks to one key.
    pub fn pick(&self, model: &str, session: Option<u64>) -> Option<Arc<KeyState>> {
        // Sticky lookup first (round_robin/least_used; fill_first is sticky by design).
        if let Some(s) = session
            && !matches!(self.strategy, Strategy::FillFirst)
        {
            let now = now_ms();
            {
                // Per-entry TTL check instead of a full-map retain sweep on every
                // pick; saturating_sub survives wall-clock steps backward.
                let kid = {
                    let mut map = lock(&self.sticky);
                    match map.get_mut(&s) {
                        Some((kid, seen))
                            if now.saturating_sub(*seen)
                                < self.tuning.sticky_ttl().as_millis() as u64 =>
                        {
                            *seen = now;
                            Some(kid.clone())
                        }
                        Some(_) => {
                            map.remove(&s);
                            None
                        }
                        None => None,
                    }
                };
                if let Some(kid) = kid {
                    let keys = lock(&self.keys);
                    if let Some(k) = keys
                        .iter()
                        .find(|k| k.id_hash == kid && k.is_available(model))
                    {
                        return Some(k.clone());
                    }
                    // The key went into cooldown/died — repick below.
                }
            }
            let picked = self.pick_inner(model);
            if let Some(k) = &picked {
                let mut map = lock(&self.sticky);
                if map.len() >= self.tuning.sticky_max_entries {
                    map.clear(); // coarse eviction on overflow
                }
                map.insert(s, (k.id_hash.clone(), now));
            }
            return picked;
        }
        self.pick_inner(model)
    }

    fn pick_inner(&self, model: &str) -> Option<Arc<KeyState>> {
        let keys = lock(&self.keys);
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
        let max = self.tuning.max_cooldown();
        key.set_cooldown(d, max);
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
                lock(&key.model_cooldowns).insert(model.to_string(), until_ms);
                key.has_model_cooldowns.store(true, Ordering::Relaxed);
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
                    .unwrap_or_else(|| self.tuning.rate_limit_cooldown())
                    .min(self.tuning.max_cooldown());
                let max = self.tuning.max_cooldown();
                key.set_cooldown(d, max);
                self.emit(key, "rate_limited", format!("cooldown {}s", d.as_secs()));
            }
            FailKind::Server | FailKind::Network => {
                let n = key.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                let shift = (n - 1).min(6) as u32;
                let max = self.tuning.max_cooldown();
                let d = (self.tuning.base_backoff() * 2u32.pow(shift)).min(max);
                key.set_cooldown(d, max);
                self.emit(key, "backoff", format!("cooldown {}s", d.as_secs()));
            }
        }
        self.persist_health(key);
    }

    // ----- dashboard management -----

    fn key_by_id(&self, id: &str) -> Option<Arc<KeyState>> {
        let id = id.trim();
        if id.len() < 8 {
            return None;
        }
        let keys = lock(&self.keys);
        // Exact id first (what `snapshot()` hands the dashboard).
        if let Some(k) = keys.iter().find(|k| k.id_hash == id) {
            return Some(k.clone());
        }
        // Tolerate a shortened suffix, but only when it is unambiguous: a
        // partial match against several credentials must not pick one blindly.
        let mut hits = keys.iter().filter(|k| k.id_hash.ends_with(id));
        match (hits.next(), hits.next()) {
            (Some(k), None) => Some(k.clone()),
            _ => None,
        }
    }

    /// Enable (clear dead/cooldown) or disable (dead) a key. Returns false if unknown id.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> bool {
        let Some(key) = self.key_by_id(id) else {
            return false;
        };
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
            if enabled {
                "key enabled manually"
            } else {
                "key disabled manually"
            }
            .into(),
        );
        true
    }

    /// The secret behind a snapshot id. Used only by the config-rewriting paths
    /// (key deletion) — everything else must keep using the hashed id.
    pub fn secret_by_id(&self, id: &str) -> Option<String> {
        self.key_by_id(id).map(|k| k.secret.clone())
    }

    /// Attach a display label to the key holding `secret`.
    pub fn set_label(&self, secret: &str, label: &str) {
        if let Some(k) = lock(&self.keys).iter().find(|k| k.secret == secret) {
            let _ = k.label.set(label.to_string());
        }
    }

    pub fn contains(&self, secret: &str) -> bool {
        lock(&self.keys).iter().any(|k| k.secret == secret)
    }

    /// Add a key at runtime (dashboard). Restores persisted health/stats.
    pub fn add_key(&self, secret: String) {
        let key = Arc::new(KeyState::new(secret, self.max_concurrent));
        if let Some(storage) = &self.storage {
            Self::restore_key(storage, &self.name, &key);
        }
        lock(&self.keys).push(key);
    }

    /// How long until at least one key could serve `model` again.
    ///
    /// Used for `Retry-After` when every key is cooling down: a cooldown is a
    /// temporary state, and telling the client "503 forever" would be a lie.
    /// Returns None when no key will ever recover (all dead / pool empty).
    pub fn wake_after(&self, model: &str) -> Option<Duration> {
        let keys = lock(&self.keys);
        let now = now_ms();
        let mut best: Option<u64> = None;
        for k in keys.iter() {
            match k.status.load(Ordering::Relaxed) {
                STATUS_DEAD => continue, // never recovers on its own
                STATUS_COOLDOWN => {
                    let until = k.cooldown_until_ms.load(Ordering::Relaxed);
                    if until > now {
                        best = Some(best.map_or(until, |b: u64| b.min(until)));
                        continue;
                    }
                }
                _ => {}
            }
            // Per-model cooldown is the only thing left that could block it.
            let until = lock(&k.model_cooldowns).get(model).copied().unwrap_or(0);
            if until > now {
                best = Some(best.map_or(until, |b: u64| b.min(until)));
            } else {
                return None; // a healthy key exists but was busy — retry immediately
            }
        }
        best.map(|until| Duration::from_millis(until.saturating_sub(now)))
    }

    /// Snapshot for the dashboard.
    pub fn snapshot(&self) -> Vec<KeySnapshot> {
        let now = now_ms();
        lock(&self.keys)
            .iter()
            .map(|k| {
                let status = k.status.load(Ordering::Relaxed);
                let until = k.cooldown_until_ms.load(Ordering::Relaxed);
                KeySnapshot {
                    id: k.id_hash.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(strategy: Strategy, secrets: &[&str]) -> KeyPool {
        KeyPool::new(
            "test".into(),
            secrets.iter().map(|s| s.to_string()).collect(),
            strategy,
            0,
            None,
            None,
        )
    }

    #[allow(dead_code)] // used by the id-based tests below
    fn id_of(pool: &KeyPool, index: usize) -> String {
        pool.snapshot()[index].id.clone()
    }

    // ----- rotation strategies -----

    #[test]
    fn round_robin_reaches_every_key() {
        let p = pool(Strategy::RoundRobin, &["a", "b", "c"]);
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(p.pick("m", None).unwrap().secret.clone());
        }
        // Three consecutive picks of two rounds must cover all three keys.
        let first: std::collections::HashSet<_> = seen[..3].iter().cloned().collect();
        let second: std::collections::HashSet<_> = seen[3..].iter().cloned().collect();
        assert_eq!(first.len(), 3, "round_robin skipped a key: {seen:?}");
        assert_eq!(second.len(), 3, "round_robin skipped a key: {seen:?}");
    }

    #[test]
    fn fill_first_exhausts_one_key_before_the_next() {
        let p = pool(Strategy::FillFirst, &["first", "second"]);
        for _ in 0..5 {
            assert_eq!(p.pick("m", None).unwrap().secret, "first");
        }
        // Put the first key in cooldown: the next pick must move on.
        let first = p.pick("m", None).unwrap();
        p.report_failure(
            &first,
            FailKind::RateLimited {
                retry_after_secs: Some(60),
            },
            "m",
        );
        assert_eq!(p.pick("m", None).unwrap().secret, "second");
    }

    #[test]
    fn least_used_prefers_the_lowest_request_count() {
        let p = pool(Strategy::LeastUsed, &["busy", "idle"]);
        let busy = p.pick("m", None).unwrap();
        // Same tie both times → `min_by_key` keeps the first; force a difference.
        busy.requests.store(10, Ordering::Relaxed);
        let other = p
            .snapshot()
            .iter()
            .find(|k| k.id != busy.id_hash)
            .unwrap()
            .id
            .clone();
        assert!(p.set_enabled(&other, true));
        let picked = p.pick("m", None).unwrap();
        assert_eq!(
            picked.requests.load(Ordering::Relaxed),
            0,
            "least_used picked the busy key"
        );
    }

    // ----- failure classification -----

    #[test]
    fn auth_failure_kills_the_key_but_not_the_pool() {
        let p = pool(Strategy::RoundRobin, &["dead", "alive"]);
        let k = p.pick("m", None).unwrap();
        p.report_failure(&k, FailKind::Auth, "m");
        assert_eq!(k.status.load(Ordering::Relaxed), STATUS_DEAD);
        // A dead key must never be picked again, the healthy one must still serve.
        for _ in 0..10 {
            let next = p.pick("m", None).expect("healthy key still available");
            assert_ne!(next.secret, "dead");
        }
    }

    #[test]
    fn rate_limit_sets_a_cooldown_of_the_requested_length() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m", None).unwrap();
        p.report_failure(
            &k,
            FailKind::RateLimited {
                retry_after_secs: Some(120),
            },
            "m",
        );
        assert_eq!(k.status.load(Ordering::Relaxed), STATUS_COOLDOWN);
        let snap = p.snapshot();
        // 120s requested; allow a second of drift and enforce the upper clamp.
        assert!(
            (118..=120).contains(&snap[0].cooldown_remaining_secs),
            "unexpected cooldown {}s",
            snap[0].cooldown_remaining_secs
        );
        assert_eq!(snap[0].status, "cooldown");
        // Nothing else can serve → pick must report unavailability.
        assert!(p.pick("m", None).is_none());
    }

    #[test]
    fn server_errors_back_off_exponentially_and_are_capped() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m", None).unwrap();
        p.report_failure(&k, FailKind::Server, "m"); // 5s
        let first = p.snapshot()[0].cooldown_remaining_secs;
        p.report_failure(&k, FailKind::Server, "m"); // 10s
        let second = p.snapshot()[0].cooldown_remaining_secs;
        assert!(
            second > first,
            "expected exponential growth: {first}s → {second}s"
        );
        for _ in 0..20 {
            p.report_failure(&k, FailKind::Server, "m");
        }
        assert!(
            p.snapshot()[0].cooldown_remaining_secs <= 3600,
            "cooldown must be clamped to the default max_cooldown"
        );
    }

    #[test]
    fn model_quota_cools_only_that_model() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m1", None).unwrap();
        let until = now_ms() + 60_000;
        p.report_failure(&k, FailKind::ModelQuota { until_ms: until }, "m1");
        // The key itself stays active…
        assert_eq!(k.status.load(Ordering::Relaxed), STATUS_ACTIVE);
        // …but is unavailable for the exhausted model only.
        assert!(p.pick("m1", None).is_none());
        assert!(
            p.pick("m2", None).is_some(),
            "sibling model must keep working"
        );
    }

    #[test]
    fn success_resets_the_consecutive_failure_counter() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m", None).unwrap();
        p.report_failure(&k, FailKind::Server, "m");
        assert_eq!(k.consecutive_failures.load(Ordering::Relaxed), 1);
        p.report_success(&k);
        assert_eq!(k.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    // ----- admission control -----

    #[test]
    fn max_concurrent_is_enforced_and_slots_are_released() {
        let p = KeyPool::new(
            "t".into(),
            vec!["k1".into()],
            Strategy::RoundRobin,
            1,
            None,
            None,
        );
        let k = p.pick("m", None).unwrap();
        let guard = k.try_acquire().expect("first slot");
        assert!(
            k.try_acquire().is_none(),
            "limit 1 must not hand out a second slot"
        );
        assert!(
            p.pick("m", None).is_none(),
            "saturated key must not be picked"
        );
        drop(guard);
        assert!(
            k.try_acquire().is_some(),
            "dropping the guard must free the slot"
        );
    }

    #[test]
    fn unlimited_concurrency_always_grants() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m", None).unwrap();
        let guards: Vec<_> = (0..100)
            .map(|_| k.try_acquire().expect("unlimited"))
            .collect();
        assert_eq!(k.in_flight.load(Ordering::Relaxed), 100);
        drop(guards);
        assert_eq!(k.in_flight.load(Ordering::Relaxed), 0);
    }

    // ----- sticky sessions -----

    #[test]
    fn sticky_session_keeps_a_conversation_on_one_key() {
        let p = pool(Strategy::RoundRobin, &["a", "b", "c"]);
        let first = p.pick("m", Some(42)).unwrap().secret.clone();
        for _ in 0..10 {
            assert_eq!(p.pick("m", Some(42)).unwrap().secret, first);
        }
        // Different sessions may move (round_robin advances the cursor).
        let _ = p.pick("m", Some(7)).unwrap();
    }

    #[test]
    fn sticky_session_is_not_used_for_fill_first() {
        // fill_first is sticky by design; the session map must not interfere.
        let p = pool(Strategy::FillFirst, &["a", "b"]);
        assert_eq!(p.pick("m", Some(1)).unwrap().secret, "a");
        assert_eq!(p.pick("m", Some(2)).unwrap().secret, "a");
    }

    // ----- dashboard management -----

    #[test]
    fn key_lookup_requires_an_exact_or_unambiguous_id() {
        let p = pool(Strategy::RoundRobin, &["secret-one", "secret-two"]);
        let snap = p.snapshot();
        assert!(p.key_by_id(&snap[0].id).is_some(), "exact id must resolve");
        // Tolerated shortened form is a *suffix* (see key_by_id): a prefix is not
        // a valid handle and must be rejected rather than silently mis-matched.
        let tail = &snap[0].id[snap[0].id.len() - 8..];
        assert!(p.key_by_id(tail).is_some(), "unique suffix must resolve");
        assert!(
            p.key_by_id("short").is_none(),
            "too-short ids must be rejected"
        );
        assert!(
            p.key_by_id("00000000not-a-real-id").is_none(),
            "unknown id must be rejected"
        );
    }

    #[test]
    fn disabled_key_can_be_revived() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let id = p.snapshot()[0].id.clone();
        assert!(p.set_enabled(&id, false));
        assert_eq!(p.snapshot()[0].status, "dead");
        assert!(p.pick("m", None).is_none());
        assert!(p.set_enabled(&id, true));
        assert_eq!(p.snapshot()[0].status, "active");
        assert!(p.pick("m", None).is_some());
    }

    #[test]
    fn add_key_extends_the_pool_without_duplicating() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        assert!(p.contains("k1"));
        p.add_key("k2".into());
        assert_eq!(p.len(), 2);
        assert!(p.contains("k2"));
        assert!(!p.contains("k3"));
    }

    #[test]
    fn masked_never_leaks_and_survives_multibyte() {
        let k = KeyState::new("ключ-с-кириллицей-и-длиной".into(), 0);
        let m = k.masked();
        assert!(m.ends_with('…'), "long secret must be truncated: {m}");
        assert!(
            !m.contains("длиной"),
            "masked form must not contain the tail: {m}"
        );
        // Short secrets collapse to a constant, never the value itself.
        let short = KeyState::new("abc".into(), 0);
        assert_eq!(short.masked(), "****");
    }

    #[test]
    fn wake_after_reports_the_soonest_recovery() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m", None).unwrap();
        p.report_failure(
            &k,
            FailKind::RateLimited {
                retry_after_secs: Some(30),
            },
            "m",
        );
        let d = p.wake_after("m").expect("cooldown must be reportable");
        assert!(
            (28..=30).contains(&d.as_secs()),
            "unexpected wake_after {d:?}"
        );
    }

    #[test]
    fn wake_after_is_none_when_nothing_can_recover() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m", None).unwrap();
        // A dead key never comes back on its own → no Retry-After to promise.
        p.report_failure(&k, FailKind::Auth, "m");
        assert!(p.wake_after("m").is_none());
    }

    #[test]
    fn wake_after_is_none_when_a_key_is_merely_busy() {
        let p = KeyPool::new(
            "t".into(),
            vec!["k1".into()],
            Strategy::RoundRobin,
            1,
            None,
            None,
        );
        let k = p.pick("m", None).unwrap();
        let _busy = k.try_acquire().expect("slot");
        // Busy is not cooling: the client should retry immediately, so no header.
        assert!(p.wake_after("m").is_none());
    }

    #[test]
    fn ids_are_stable_and_secret_derived() {
        let a = KeyState::new("same-secret".into(), 0);
        let b = KeyState::new("same-secret".into(), 0);
        let c = KeyState::new("other-secret".into(), 0);
        assert_eq!(a.id_hash, b.id_hash);
        assert_ne!(a.id_hash, c.id_hash);
        assert!(
            !a.id_hash.contains("secret"),
            "id must be a hash, not the secret"
        );
    }
}
