//! Per-key state: credential, health/cooldown flags, counters, and the in-flight guard.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::storage::HealthRecord;

use super::{lock, now_ms};

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
    pub(super) label: std::sync::OnceLock<String>,
    /// sha256(secret)[..16] hex — computed once; per-request hashing showed up
    /// on the sticky-session hot path.
    pub(super) id_hash: String,
    pub(super) status: AtomicU8,
    /// Unix epoch millis until which the key is in cooldown. 0 = none.
    pub(super) cooldown_until_ms: AtomicU64,
    /// Per-model cooldowns (model id -> until unix ms).
    pub(super) model_cooldowns: Mutex<HashMap<String, u64>>,
    /// True while `model_cooldowns` is non-empty. Lets the hot path skip the
    /// mutex entirely — it is empty for almost every request.
    pub(super) has_model_cooldowns: AtomicBool,
    pub(super) in_flight: AtomicU32,
    max_concurrent: u32,
    pub requests: AtomicU64,
    pub failures: AtomicU64,
    pub prompt_tokens: AtomicU64,
    pub completion_tokens: AtomicU64,
    pub(super) consecutive_failures: AtomicU64,
}

impl KeyState {
    pub(super) fn new(secret: String, max_concurrent: u32) -> Self {
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

    pub(super) fn is_available(&self, model: &str) -> bool {
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
    pub(super) fn set_cooldown(&self, d: Duration, max: Duration) {
        let d = d.min(max);
        self.cooldown_until_ms
            .store(now_ms() + d.as_millis() as u64, Ordering::Relaxed);
        self.status.store(STATUS_COOLDOWN, Ordering::Relaxed);
    }

    /// Everything about this key that must survive a restart or a config reload.
    pub(super) fn health(&self) -> HealthRecord {
        // The map is empty for almost every key, so the common case costs one
        // relaxed load and no lock.
        let model_cooldowns = if self.has_model_cooldowns.load(Ordering::Relaxed) {
            lock(&self.model_cooldowns).clone()
        } else {
            HashMap::new()
        };
        HealthRecord {
            status: self.status.load(Ordering::Relaxed),
            cooldown_until_ms: self.cooldown_until_ms.load(Ordering::Relaxed),
            model_cooldowns,
        }
    }

    /// Restore a persisted record, clamped to the configured maximum cooldown.
    ///
    /// The record was written by another process at another time: a state file
    /// with a wrong clock used to bench a key for ~10 years (`u64` epoch millis
    /// from a bad clock), and a forward clock step silently wiped every cooldown.
    /// Anything already expired is active — never "cooldown until 1970".
    pub(super) fn restore_health(&self, rec: &HealthRecord, max: Duration) {
        let now = now_ms();
        let horizon = now.saturating_add(max.as_millis() as u64);
        let until = rec.cooldown_until_ms.min(horizon);
        let status = match rec.status {
            // A dead key stays dead regardless of the clock: it was disabled or
            // rejected, which no deadline can undo.
            STATUS_DEAD => STATUS_DEAD,
            STATUS_COOLDOWN if until > now => STATUS_COOLDOWN,
            // Unknown status values, and cooldowns that already ran out, mean
            // "active" — the bytes on disk must not invent a longer outage.
            _ => STATUS_ACTIVE,
        };
        self.status.store(status, Ordering::Relaxed);
        self.cooldown_until_ms.store(
            if status == STATUS_COOLDOWN { until } else { 0 },
            Ordering::Relaxed,
        );

        if !rec.model_cooldowns.is_empty() {
            let mut mc = lock(&self.model_cooldowns);
            for (model, &until) in &rec.model_cooldowns {
                let until = until.min(horizon);
                if until > now {
                    mc.insert(model.clone(), until);
                }
            }
            self.has_model_cooldowns
                .store(!mc.is_empty(), Ordering::Relaxed);
        }
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
