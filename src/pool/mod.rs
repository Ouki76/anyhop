//! Key pool: strategy-based key selection, sticky sessions, cooldowns and persistence.

mod key;
mod sticky;

pub use key::{FailKind, KeyGuard, KeyState, STATUS_ACTIVE, STATUS_COOLDOWN, STATUS_DEAD};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Strategy;
use crate::storage::{StatsRecord, Storage};

use sticky::StickySessions;

/// Largest number of per-model cooldowns kept for one key.
///
/// The model name comes from the client on a wildcard provider, so an attacker (or
/// a busy multi-model client) could grow this map — and the health record written on
/// every failure — without bound.
const MAX_MODEL_COOLDOWNS: usize = 256;

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
    sticky: StickySessions,
    /// Shared with the sticky sessions and swappable in place: `[tuning]` edits
    /// are hot-reloaded, and a pool that a reload reused keeps serving with the
    /// new values instead of the ones it was built with.
    tuning: std::sync::Arc<arc_swap::ArcSwap<crate::config::Tuning>>,
}

impl KeyPool {
    /// The one and only constructor: it always takes the tuning the pool must
    /// honour. (There used to be a `new` that silently substituted
    /// `Tuning::default()`, which made every `[tuning]` knob dead config for
    /// the production call site.)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        secrets: Vec<String>,
        strategy: Strategy,
        max_concurrent: u32,
        storage: Option<Storage>,
        events: Option<crate::events::EventBus>,
        tuning: std::sync::Arc<crate::config::Tuning>,
    ) -> Self {
        let live = std::sync::Arc::new(arc_swap::ArcSwap::from(tuning));
        let sticky = StickySessions::new(live.clone());
        // Two identical secrets would share an id_hash: stats count them twice
        // while rendezvous hashing can only ever score one of them.
        let mut seen = std::collections::HashSet::new();
        let keys = secrets
            .into_iter()
            .filter(|s| seen.insert(s.clone()))
            .map(|s| Arc::new(KeyState::new(s, max_concurrent)))
            .collect();
        let pool = Self {
            name,
            strategy,
            max_concurrent,
            keys: Mutex::new(keys),
            cursor: AtomicUsize::new(0),
            storage,
            events,
            sticky,
            tuning: live,
        };
        pool.restore();
        pool
    }

    /// The tuning this pool currently honours.
    pub fn tuning(&self) -> std::sync::Arc<crate::config::Tuning> {
        self.tuning.load_full()
    }

    /// Apply a hot `[tuning]` reload to this pool.
    pub fn set_tuning(&self, tuning: std::sync::Arc<crate::config::Tuning>) {
        self.sticky.set_tuning(tuning.clone());
        self.tuning.store(tuning);
    }

    /// Everything that makes two pools interchangeable: the credential set (by
    /// hashed id), the strategy and the admission limit.
    ///
    /// A config reload compares this with the live pool's signature and reuses
    /// the pool when they match — rebuilding it would throw away cooldowns,
    /// per-model quotas and counters that have nothing to do with the edit.
    pub fn signature(&self) -> (Vec<String>, Strategy, u32) {
        let mut ids: Vec<String> = lock(&self.keys).iter().map(|k| k.id_hash.clone()).collect();
        ids.sort();
        (ids, self.strategy, self.max_concurrent)
    }

    /// Restore health and stats persisted from previous runs.
    ///
    /// One read transaction for the whole pool: this runs for every key of every
    /// provider on every reload.
    fn restore(&self) {
        let Some(storage) = &self.storage else { return };
        let keys = lock(&self.keys);
        if keys.is_empty() {
            return;
        }
        let secrets: Vec<String> = keys.iter().map(|k| k.secret.clone()).collect();
        let records = storage.load_pool_records(&self.name, &secrets);
        let max = self.tuning().max_cooldown();
        for (key, rec) in keys.iter().zip(records) {
            if let Some(h) = rec.health {
                key.restore_health(&h, max);
            }
            if let Some(s) = rec.stats {
                key.requests.store(s.requests, Ordering::Relaxed);
                key.failures.store(s.failures, Ordering::Relaxed);
                key.prompt_tokens.store(s.prompt_tokens, Ordering::Relaxed);
                key.completion_tokens
                    .store(s.completion_tokens, Ordering::Relaxed);
            }
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
    ///
    /// Health only — used by callers that do not consume an in-flight slot (model
    /// listing, quota probes). Request paths want [`KeyPool::pick_ready`].
    pub fn pick(&self, model: &str, session: Option<u64>) -> Option<Arc<KeyState>> {
        self.pick_where(model, session, |_| true)
    }

    /// Admission-aware [`KeyPool::pick`]: the key must also have a free in-flight
    /// slot.
    ///
    /// Returning a saturated key wasted the admission loop — every 25 ms poll
    /// handed back the same one, `try_acquire` failed again, and the other keys
    /// were never considered. With `fill_first` (the default for OAuth providers)
    /// that made the pool's effective concurrency one key's `max_concurrent`:
    /// under a 200-request storm a 2x2 pool served ~54 % of what it should.
    pub fn pick_ready(&self, model: &str, session: Option<u64>) -> Option<Arc<KeyState>> {
        self.pick_where(model, session, KeyState::has_capacity)
    }

    fn pick_where(
        &self,
        model: &str,
        session: Option<u64>,
        ready: impl Fn(&KeyState) -> bool + Copy,
    ) -> Option<Arc<KeyState>> {
        // Sticky routing (round_robin/least_used; fill_first is sticky by design).
        if let Some(s) = session
            && !matches!(self.strategy, Strategy::FillFirst)
        {
            if self.sticky.is_hashed() {
                // Rendezvous hashing: the same conversation lands on the same key
                // in every instance, with no shared state to keep in sync.
                let keys = lock(&self.keys);
                return self
                    .sticky
                    .rendezvous(s, &keys, |k| k.is_available(model) && ready(k))
                    .map(|i| keys[i].clone());
            }
            let now = now_ms();
            if let Some(kid) = self.sticky.lookup(s, now) {
                let keys = lock(&self.keys);
                if let Some(k) = keys
                    .iter()
                    .find(|k| k.id_hash == kid && k.is_available(model) && ready(k))
                {
                    return Some(k.clone());
                }
                // The key went into cooldown/died/became busy — repick below.
            }
            let picked = self.pick_inner(model, ready);
            if let Some(k) = &picked {
                self.sticky.bind(s, &k.id_hash, now);
            }
            return picked;
        }
        self.pick_inner(model, ready)
    }

    fn pick_inner(&self, model: &str, ready: impl Fn(&KeyState) -> bool) -> Option<Arc<KeyState>> {
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
                    .find(|k| k.is_available(model) && ready(k))
                    .cloned()
            }
            Strategy::LeastUsed => keys
                .iter()
                .filter(|k| k.is_available(model) && ready(k))
                // Live load first: in-flight requests are what a concurrent burst
                // competes over, while `requests` only moves after a round trip —
                // ranking on it alone made this strategy behave like `fill_first`
                // under exactly the load it exists for. Lifetime count breaks ties
                // so sustained traffic still spreads evenly.
                .min_by_key(|k| (k.in_flight(), k.requests.load(Ordering::Relaxed)))
                .cloned(),
            Strategy::FillFirst => keys
                .iter()
                .find(|k| k.is_available(model) && ready(k))
                .cloned(),
        }
    }

    /// Proactively cool a key down before it hits the limit (rate-limit headers).
    pub fn drain(&self, key: &KeyState, d: Duration) {
        let max = self.tuning().max_cooldown();
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
                let max = self.tuning().max_cooldown();
                // A reset time from upstream is a hint, not a promise: clamp it to
                // the configured maximum like every other cooldown.
                let until_ms = until_ms.min(now_ms().saturating_add(max.as_millis() as u64));
                let secs = until_ms.saturating_sub(now_ms()) / 1000;
                {
                    let mut cooldowns = lock(&key.model_cooldowns);
                    // Prune expired entries and cap the map: the model name is
                    // client-chosen on a wildcard provider, every 429 inserts one,
                    // and nothing ever removed them — so the map (and the health
                    // record persisted on each failure) grew without bound.
                    let now = now_ms();
                    cooldowns.retain(|_, until| *until > now);
                    if cooldowns.len() >= MAX_MODEL_COOLDOWNS {
                        // Drop the entry closest to expiring: cheapest to lose and
                        // the least likely to still be needed.
                        if let Some(oldest) = cooldowns
                            .iter()
                            .min_by_key(|(_, until)| **until)
                            .map(|(m, _)| m.clone())
                        {
                            cooldowns.remove(&oldest);
                        }
                    }
                    cooldowns.insert(model.to_string(), until_ms);
                }
                key.has_model_cooldowns.store(true, Ordering::Relaxed);
                self.emit(
                    key,
                    "rate_limited",
                    format!("model '{model}' quota, cooldown {secs}s"),
                );
                // Persist it: a reload that rebuilds this pool must not forget
                // that this model is exhausted (it did — that is how a reload
                // turned a per-model 429 into another doomed attempt).
            }
            FailKind::RateLimited { retry_after_secs } => {
                // Rate limit is a quota signal, not instability — no exponential backoff.
                key.consecutive_failures.store(0, Ordering::Relaxed);
                let tuning = self.tuning();
                let max = tuning.max_cooldown();
                let d = retry_after_secs
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| tuning.rate_limit_cooldown())
                    .min(max);
                key.set_cooldown(d, max);
                self.emit(key, "rate_limited", format!("cooldown {}s", d.as_secs()));
            }
            FailKind::Server | FailKind::Network => {
                let n = key.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                let shift = (n - 1).min(6) as u32;
                let tuning = self.tuning();
                let max = tuning.max_cooldown();
                let d = (tuning.base_backoff() * 2u32.pow(shift)).min(max);
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
    ///
    /// A credential already in the pool is a no-op: two `KeyState`s for the same
    /// secret share an id hash, so rotation would count it twice while sticky
    /// rendezvous could only ever score one of them.
    pub fn add_key(&self, secret: String) {
        let mut keys = lock(&self.keys);
        if keys.iter().any(|k| k.secret == secret) {
            return;
        }
        let key = Arc::new(KeyState::new(secret, self.max_concurrent));
        if let Some(storage) = &self.storage {
            let recs = storage.load_pool_records(&self.name, std::slice::from_ref(&key.secret));
            if let Some(rec) = recs.into_iter().next() {
                let max = self.tuning().max_cooldown();
                if let Some(h) = rec.health {
                    key.restore_health(&h, max);
                }
                if let Some(s) = rec.stats {
                    key.requests.store(s.requests, Ordering::Relaxed);
                    key.failures.store(s.failures, Ordering::Relaxed);
                    key.prompt_tokens.store(s.prompt_tokens, Ordering::Relaxed);
                    key.completion_tokens
                        .store(s.completion_tokens, Ordering::Relaxed);
                }
            }
        }
        keys.push(key);
    }

    /// How long until at least one key could serve `model` again.
    ///
    /// Used for `Retry-After` when every key is cooling down: a cooldown is a
    /// temporary state, and telling the client "503 forever" would be a lie.
    /// Returns None when no key will ever recover (all dead / pool empty).
    ///
    /// `model` must be the *upstream* model id, because that is how cooldowns are
    /// keyed. Callers that only know the client-facing name should use
    /// [`KeyPool::wake_after_any`].
    pub fn wake_after(&self, model: &str) -> Option<Duration> {
        self.wake_after_names(&[model])
    }

    /// Like [`KeyPool::wake_after`], but tolerant of the caller's naming.
    ///
    /// A 503 handler usually has the client-facing model id: `provider/model` for
    /// a routed model, a bare id, or a combo name. Cooldowns are recorded under
    /// the upstream id, so this looks up every plausible spelling (the name as
    /// given, its bare form, and this provider's `<provider>/<bare>` form) — a
    /// naming mismatch must not silence `Retry-After`.
    pub fn wake_after_any(&self, model: &str) -> Option<Duration> {
        let bare = model.rsplit_once('/').map_or(model, |(_, rest)| rest);
        let qualified = format!("{}/{}", self.name, bare);
        let mut names: Vec<&str> = vec![model, bare];
        if names.iter().all(|n| *n != qualified) {
            names.push(&qualified);
        }
        self.wake_after_names(&names)
    }

    fn wake_after_names(&self, names: &[&str]) -> Option<Duration> {
        let keys = lock(&self.keys);
        let now = now_ms();
        let mut best: Option<u64> = None;
        for k in keys.iter() {
            // Dead never recovers on its own — nothing to promise for it.
            if k.status.load(Ordering::Relaxed) == STATUS_DEAD {
                continue;
            }
            // A key can be blocked by its global cooldown *and* a per-model one:
            // the real wait is the later of the two. Reporting only the global
            // one told the client to retry straight into the model quota.
            let mut blocker = 0u64;
            if k.status.load(Ordering::Relaxed) == STATUS_COOLDOWN {
                blocker = blocker.max(k.cooldown_until_ms.load(Ordering::Relaxed));
            }
            if k.has_model_cooldowns.load(Ordering::Relaxed) {
                let mc = lock(&k.model_cooldowns);
                for name in names {
                    if let Some(until) = mc.get(*name) {
                        blocker = blocker.max(*until);
                    }
                }
            }
            if blocker <= now {
                // This key can serve the model right now; the 503 was a busy
                // pool, not a cooldown — retry immediately.
                return None;
            }
            best = Some(best.map_or(blocker, |b: u64| b.min(blocker)));
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
        pooled(
            strategy,
            secrets,
            Arc::new(crate::config::Tuning::default()),
        )
    }

    fn pooled(strategy: Strategy, secrets: &[&str], tuning: Arc<crate::config::Tuning>) -> KeyPool {
        KeyPool::new(
            "test".into(),
            secrets.iter().map(|s| s.to_string()).collect(),
            strategy,
            0,
            None,
            None,
            tuning,
        )
    }

    /// A pool where every key admits exactly `per_key` concurrent requests.
    fn pool_with_capacity(strategy: Strategy, secrets: &[&str], per_key: u32) -> KeyPool {
        KeyPool::new(
            "test".into(),
            secrets.iter().map(|s| s.to_string()).collect(),
            strategy,
            per_key,
            None,
            None,
            Arc::new(crate::config::Tuning::default()),
        )
    }

    /// A saturated key must not shadow the rest of the pool.
    ///
    /// `pick` returns key 1 until it is *benched*, so with `fill_first` the
    /// admission loop kept getting the same saturated key back: a 2x2 pool served
    /// at half its capacity and the overflow was rejected.
    #[test]
    fn a_saturated_key_does_not_hide_the_others() {
        let p = pool_with_capacity(Strategy::FillFirst, &["k1", "k2"], 1);
        let first = p.pick_ready("m", None).expect("a ready key");
        let held = first.try_acquire().expect("its only slot");
        let second = p
            .pick_ready("m", None)
            .expect("the second key still has a slot");
        assert_ne!(
            first.id_hash, second.id_hash,
            "pick_ready repeated the saturated key"
        );
        let held2 = second.try_acquire().expect("its slot");
        assert!(
            p.pick_ready("m", None).is_none(),
            "both keys are at their cap, so nothing is ready"
        );
        // `pick` (health + capacity) is the same predicate here: model listing
        // simply sees an empty pool while every key is busy, which is honest.
        assert!(p.pick("m", None).is_none());
        drop(held);
        assert!(p.pick_ready("m", None).is_some(), "the slot was returned");
        drop(held2);
    }

    /// `least_used` must also skip a key that has no room, not just the busiest one.
    #[test]
    fn least_used_skips_a_full_key() {
        let p = pool_with_capacity(Strategy::LeastUsed, &["k1", "k2"], 1);
        let a = p.pick_ready("m", None).expect("a key");
        let guard = a.try_acquire().expect("slot");
        let b = p.pick_ready("m", None).expect("the other key");
        assert_ne!(a.id_hash, b.id_hash);
        drop(guard);
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

    /// `least_used` must spread a *concurrent* burst, not just sequential calls.
    ///
    /// It ranked on `requests`, which increments only after a round trip: every
    /// request in a burst read the same counts, picked the same key, and the
    /// strategy degenerated into `fill_first` — pinning one key while the rest
    /// sat idle, exactly the pattern `has_capacity` was added to fix.
    #[test]
    fn least_used_spreads_a_concurrent_burst() {
        // Unlimited concurrency, so admission never masks the choice.
        let p = pool_with_capacity(Strategy::LeastUsed, &["a", "b", "c"], 0);
        // Simulate a burst: five picks taken *before* any of them reports back.
        let mut guards = Vec::new();
        for _ in 0..3 {
            let key = p.pick("m", None).expect("a key");
            guards.push(key.try_acquire().expect("a slot"));
        }
        let in_flight: Vec<u32> = p.snapshot().iter().map(|k| k.in_flight).collect();
        assert_eq!(
            in_flight.iter().filter(|n| **n == 0).count(),
            0,
            "every key should have taken one request, got {in_flight:?}"
        );
        assert!(
            in_flight.iter().all(|n| *n == 1),
            "the burst must spread one per key, got {in_flight:?}"
        );
        // A sixth request still gets a key (unlimited capacity) — and it lands on
        // the least loaded one rather than stacking on the first.
        let extra = p.pick("m", None).expect("a key");
        assert_eq!(extra.in_flight(), 1);
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
            Arc::new(crate::config::Tuning::default()),
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
            Arc::new(crate::config::Tuning::default()),
        );
        let k = p.pick("m", None).unwrap();
        let _busy = k.try_acquire().expect("slot");
        // Busy is not cooling: the client should retry immediately, so no header.
        assert!(p.wake_after("m").is_none());
    }

    // ----- B: the pool must honour the tuning it is given -----

    /// `KeyPool::new` used to substitute `Tuning::default()` for the tuning it
    /// was handed, so every `[tuning]` value was dead config: a configured 1 s
    /// cooldown still benched the key for the default 60 s.
    #[test]
    fn the_configured_rate_limit_cooldown_is_used() {
        let tuning = Arc::new(crate::config::Tuning {
            rate_limit_cooldown_secs: 1,
            ..crate::config::Tuning::default()
        });
        let p = pooled(Strategy::RoundRobin, &["k1"], tuning);
        let k = p.pick("m", None).unwrap();
        p.report_failure(
            &k,
            FailKind::RateLimited {
                retry_after_secs: None,
            },
            "m",
        );
        let secs = p.snapshot()[0].cooldown_remaining_secs;
        assert!(
            secs <= 1,
            "configured rate_limit_cooldown_secs = 1, pool benched for {secs}s"
        );

        // base_backoff_secs drives the 5xx path the same way.
        let tuning = Arc::new(crate::config::Tuning {
            base_backoff_secs: 1,
            max_cooldown_secs: 2,
            ..crate::config::Tuning::default()
        });
        let p = pooled(Strategy::RoundRobin, &["k1"], tuning);
        let k = p.pick("m", None).unwrap();
        p.report_failure(&k, FailKind::Server, "m");
        assert!(
            p.snapshot()[0].cooldown_remaining_secs <= 2,
            "base_backoff/max_cooldown from the config were ignored"
        );
    }

    /// The same for `sticky_mode`: `map` used to be ignored (the pool always
    /// built its session map with the default `hash` tuning).
    #[test]
    fn the_configured_sticky_mode_is_used() {
        let map = Arc::new(crate::config::Tuning {
            sticky_mode: "map".to_string(),
            ..crate::config::Tuning::default()
        });
        let p = pooled(Strategy::RoundRobin, &["a", "b"], map);
        assert!(
            !p.sticky.is_hashed(),
            "sticky_mode = \"map\" must be honoured"
        );
        assert!(p.sticky_enabled());
        // map mode really binds: the same session keeps the same key even after
        // the round-robin cursor moved on.
        let first = p.pick("m", Some(5)).unwrap().secret.clone();
        for _ in 0..5 {
            assert_eq!(p.pick("m", Some(5)).unwrap().secret, first);
        }

        let hash = Arc::new(crate::config::Tuning::default());
        let p = pooled(Strategy::RoundRobin, &["a", "b"], hash);
        assert!(p.sticky.is_hashed(), "hash is the default mode");
    }

    /// A `[tuning]` reload must reach a pool that was reused rather than rebuilt.
    #[test]
    fn set_tuning_changes_the_live_behaviour() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        p.set_tuning(Arc::new(crate::config::Tuning {
            max_cooldown_secs: 2,
            base_backoff_secs: 1,
            ..crate::config::Tuning::default()
        }));
        assert_eq!(p.tuning().max_cooldown_secs, 2);
        let k = p.pick("m", None).unwrap();
        for _ in 0..5 {
            p.report_failure(&k, FailKind::Server, "m");
        }
        assert!(
            p.snapshot()[0].cooldown_remaining_secs <= 2,
            "the swapped-in max_cooldown must cap the backoff"
        );
    }

    // ----- G: wake_after must report the real block -----

    /// A model cooldown and a global cooldown can overlap; the honest answer is
    /// the later of the two. This used to report only the global one.
    #[test]
    fn wake_after_reports_the_longer_of_global_and_model_cooldown() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m1", None).unwrap();
        // 10 s global, then a 120 s per-model quota.
        p.report_failure(
            &k,
            FailKind::RateLimited {
                retry_after_secs: Some(10),
            },
            "m1",
        );
        p.report_failure(
            &k,
            FailKind::ModelQuota {
                until_ms: now_ms() + 120_000,
            },
            "m1",
        );
        let d = p
            .wake_after("m1")
            .expect("a blocked pool must report a wait");
        assert!(
            d.as_secs() >= 100,
            "reported {d:?}: the model quota outlasts the global cooldown"
        );
    }

    /// The caller often has the client-facing name (`provider/model`) while the
    /// cooldown is keyed by the upstream id — `wake_after_any` must see both.
    #[test]
    fn wake_after_any_matches_the_callers_naming() {
        let p = pool(Strategy::RoundRobin, &["k1"]);
        let k = p.pick("m1", None).unwrap();
        p.report_failure(
            &k,
            FailKind::ModelQuota {
                until_ms: now_ms() + 60_000,
            },
            "test/m1",
        );
        assert!(
            p.wake_after("m1").is_none(),
            "the plain name does not match a prefixed cooldown key"
        );
        let d = p
            .wake_after_any("m1")
            .expect("the provider-qualified name must be found");
        assert!((50..=60).contains(&d.as_secs()), "unexpected {d:?}");
        // The already-qualified spelling works too.
        assert!(p.wake_after_any("test/m1").is_some());
        // And a bare upstream id stays a match for the qualified call.
        assert!(p.wake_after("test/m1").is_some());
    }

    // ----- H: a restored cooldown is clamped -----

    #[test]
    fn a_restored_cooldown_is_clamped_and_expired_ones_are_dropped() {
        let max = Duration::from_secs(60);
        let k = KeyState::new("k1".into(), 0);
        // A state file written with a wildly wrong clock: ~10 years out.
        let absurd = now_ms() + 10 * 365 * 24 * 3600 * 1000;
        k.restore_health(
            &crate::storage::HealthRecord {
                status: STATUS_COOLDOWN,
                cooldown_until_ms: absurd,
                ..Default::default()
            },
            max,
        );
        let until = k.cooldown_until_ms.load(Ordering::Relaxed);
        assert!(
            until <= now_ms() + 60_000 + 1_000,
            "restored cooldown was not clamped to max_cooldown"
        );

        // Already expired (or a forward clock step) means "active", not "cooldown".
        let k = KeyState::new("k2".into(), 0);
        k.restore_health(
            &crate::storage::HealthRecord {
                status: STATUS_COOLDOWN,
                cooldown_until_ms: now_ms().saturating_sub(5_000),
                ..Default::default()
            },
            max,
        );
        assert_eq!(
            k.status.load(Ordering::Relaxed),
            STATUS_ACTIVE,
            "an expired cooldown must not bench the key"
        );
        assert_eq!(k.cooldown_until_ms.load(Ordering::Relaxed), 0);

        // A dead key stays dead: no deadline can undo an auth rejection.
        let k = KeyState::new("k3".into(), 0);
        k.restore_health(
            &crate::storage::HealthRecord {
                status: STATUS_DEAD,
                cooldown_until_ms: 0,
                ..Default::default()
            },
            max,
        );
        assert_eq!(k.status.load(Ordering::Relaxed), STATUS_DEAD);
    }

    #[test]
    fn restored_per_model_cooldowns_are_kept_and_clamped() {
        let max = Duration::from_secs(60);
        let k = KeyState::new("k1".into(), 0);
        let mut record = crate::storage::HealthRecord {
            status: STATUS_ACTIVE,
            cooldown_until_ms: 0,
            ..Default::default()
        };
        record
            .model_cooldowns
            .insert("m1".into(), now_ms() + 30_000);
        record
            .model_cooldowns
            .insert("m2".into(), now_ms() + 10 * 365 * 24 * 3600 * 1000);
        record
            .model_cooldowns
            .insert("m3".into(), now_ms().saturating_sub(1_000));
        k.restore_health(&record, max);

        let mc = lock(&k.model_cooldowns);
        assert!(mc.contains_key("m1"), "a live model cooldown must survive");
        assert!(
            mc.get("m2").is_some_and(|u| *u <= now_ms() + 61_000),
            "an absurd model cooldown must be clamped"
        );
        assert!(
            !mc.contains_key("m3"),
            "an expired model cooldown must be dropped"
        );
    }

    // ----- L: duplicate credentials -----

    #[test]
    fn duplicate_secrets_never_enter_the_pool() {
        // add_key had no dedupe: the second copy shared an id hash with the
        // first, so rendezvous hashing could only ever pick one of them.
        let p = pool(Strategy::RoundRobin, &["k1"]);
        p.add_key("k1".into());
        assert_eq!(p.len(), 1, "add_key duplicated an existing credential");
        assert_eq!(p.signature().0.len(), 1);

        // The constructor dedupes as well (a config file can list one twice —
        // validate() rejects it, a hand-built pool does not go through validate).
        let p = KeyPool::new(
            "test".into(),
            vec!["k1".into(), "k1".into(), "k2".into()],
            Strategy::RoundRobin,
            0,
            None,
            None,
            Arc::new(crate::config::Tuning::default()),
        );
        assert_eq!(p.len(), 2);
    }

    // ----- D: the pool identity a reload compares -----

    #[test]
    fn the_signature_tracks_credentials_strategy_and_limit() {
        let a = pool(Strategy::RoundRobin, &["k1", "k2"]);
        let b = pool(Strategy::RoundRobin, &["k2", "k1"]);
        assert_eq!(a.signature(), b.signature(), "order must not matter");

        let changed = pool(Strategy::LeastUsed, &["k1", "k2"]);
        assert_ne!(a.signature(), changed.signature(), "strategy is part of it");

        let more = pool(Strategy::RoundRobin, &["k1", "k2", "k3"]);
        assert_ne!(a.signature(), more.signature(), "keys are part of it");

        let limited = KeyPool::new(
            "test".into(),
            vec!["k1".into(), "k2".into()],
            Strategy::RoundRobin,
            3,
            None,
            None,
            Arc::new(crate::config::Tuning::default()),
        );
        assert_ne!(
            a.signature(),
            limited.signature(),
            "the concurrency limit is part of it"
        );
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

    // ----- proactive drain (x-ratelimit headers) -----

    /// `drain` is the proactive path: it benches a key *before* the upstream
    /// returns 429, for exactly the advertised reset. It must not take the pool
    /// down with it.
    #[test]
    fn a_proactive_drain_benches_only_the_advertised_key() {
        let p = pool(Strategy::RoundRobin, &["a", "b"]);
        let drained = p.pick("m", None).expect("a key");
        let drained_id = drained.id_hash.clone();

        p.drain(&drained, Duration::from_secs(45));

        let snap = p.snapshot();
        let row = snap
            .iter()
            .find(|k| k.id == drained_id)
            .expect("the drained key is in the snapshot");
        assert_eq!(row.status, "cooldown", "the drained key must be benched");
        assert!(
            (44..=45).contains(&row.cooldown_remaining_secs),
            "the cooldown must be the advertised reset, got {}s",
            row.cooldown_remaining_secs
        );
        // The other key still serves the model.
        for _ in 0..4 {
            let next = p.pick("m", None).expect("the healthy key still serves");
            assert_ne!(
                next.id_hash, drained_id,
                "a cooled key must not be handed out"
            );
        }
        // The pool is not "unavailable": a healthy key can serve right now, so a
        // 503 would be a lie (nothing to wait for).
        assert!(
            p.wake_after("m").is_none(),
            "one healthy key means the client does not have to wait"
        );
        // Once every key is drained the pool does report a wake time.
        let other = p.pick("m", None).expect("the healthy key");
        p.drain(&other, Duration::from_secs(30));
        assert!(
            p.wake_after("m").is_some(),
            "a fully drained pool must tell the client when to come back"
        );
    }

    /// The upstream can advertise an hour; `max_cooldown_secs` still bounds how
    /// long a key is unusable (a hostile header must not disable a key all day).
    #[test]
    fn a_drain_is_clamped_to_the_configured_maximum() {
        let tuning = crate::config::Tuning {
            max_cooldown_secs: 120,
            ..Default::default()
        };
        let p = pooled(Strategy::RoundRobin, &["a"], Arc::new(tuning));
        let key = p.pick("m", None).expect("a key");
        p.drain(&key, Duration::from_secs(6 * 3600));
        let remaining = p.snapshot()[0].cooldown_remaining_secs;
        assert!(
            remaining <= 120,
            "a drain longer than max_cooldown must be clamped, got {remaining}s"
        );
    }

    /// A proactive drain is a health decision like any other: it has to be in the
    /// state file before a config reload rebuilds the pool, or the dashboard save
    /// that follows a drain resurrects exactly the key we benched.
    #[tokio::test]
    async fn a_drain_survives_a_pool_rebuild() {
        let dir = scratch_dir("drain-persist");
        let path = dir.join("state.redb");
        let store = crate::storage::Storage::open(path.to_str().expect("utf-8")).expect("open");
        let tuning = Arc::new(crate::config::Tuning::default());

        let p = KeyPool::new(
            "test".into(),
            vec!["sk-drain".into()],
            Strategy::RoundRobin,
            0,
            Some(store.clone()),
            None,
            tuning.clone(),
        );
        let key = p.pick("m", None).expect("a key");
        p.drain(&key, Duration::from_secs(30));
        assert_eq!(p.snapshot()[0].status, "cooldown");

        // What a reload does for a provider whose credentials changed.
        let rebuilt = KeyPool::new(
            "test".into(),
            vec!["sk-drain".into()],
            Strategy::RoundRobin,
            0,
            Some(store),
            None,
            tuning,
        );
        assert_eq!(
            rebuilt.snapshot()[0].status,
            "cooldown",
            "the rebuilt pool lost the drain (health was not persisted)"
        );
        assert!(
            rebuilt.pick("m", None).is_none(),
            "a drained key must not be handed out after a reload"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scratch directory for tests that need a state file.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anyhop-pool-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }
}
