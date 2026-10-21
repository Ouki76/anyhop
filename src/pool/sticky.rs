//! Sticky-session map: session hash → key id, with TTL refresh and coarse eviction.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::config::Tuning;

use super::lock;

/// Sticky sessions: session hash -> (key id hash, last seen unix ms).
/// Keeps a conversation on one key so the provider-side KV cache hits.
pub(super) struct StickySessions {
    map: Mutex<HashMap<u64, (String, u64)>>,
    tuning: Arc<Tuning>,
}

impl StickySessions {
    pub(super) fn new(tuning: Arc<Tuning>) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            tuning,
        }
    }

    /// Key id bound to `session` when the binding is still fresh, refreshing its
    /// timestamp. An expired entry is dropped so the caller repicks.
    pub(super) fn lookup(&self, session: u64, now: u64) -> Option<String> {
        // Per-entry TTL check instead of a full-map retain sweep on every
        // pick; saturating_sub survives wall-clock steps backward.
        let mut map = lock(&self.map);
        match map.get_mut(&session) {
            Some((kid, seen))
                if now.saturating_sub(*seen) < self.tuning.sticky_ttl().as_millis() as u64 =>
            {
                *seen = now;
                Some(kid.clone())
            }
            Some(_) => {
                map.remove(&session);
                None
            }
            None => None,
        }
    }

    /// Remember that `session` is served by the key whose id hash is `kid`.
    pub(super) fn bind(&self, session: u64, kid: &str, now: u64) {
        let mut map = lock(&self.map);
        if map.len() >= self.tuning.sticky_max_entries {
            map.clear(); // coarse eviction on overflow
        }
        map.insert(session, (kid.to_string(), now));
    }
}
