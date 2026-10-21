//! Sticky routing: keep a conversation on one key so the provider-side prompt
//! cache hits.
//!
//! Two modes, both behind `[tuning] sticky_mode`:
//!
//! * `hash` (default) — **rendezvous hashing** over the currently available keys.
//!   The winner depends only on (session, key id), so every instance picks the
//!   same key for the same conversation without sharing any state. That is what
//!   makes the gateway safe to run behind a load balancer, and it needs no TTL:
//!   when a key disappears its sessions move to the next-highest score and move
//!   back when it returns (minimal disruption).
//! * `map` — the historical per-process map (session → key, TTL, coarse
//!   eviction). Kept for single-instance deployments that prefer "whatever
//!   worked last" over a deterministic rule.
//!
//! Both modes are cheap: `hash` walks the key list once (≤ pool size) with a
//! multiply-xor mix, no allocation; `map` is a hash-map lookup.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::config::Tuning;

use super::lock;

/// Rendezvous score for (session, key id). Deterministic across processes and
/// architectures: integer mix, no floats, no hashing seed.
fn score(session: u64, key_id: &str) -> u64 {
    // FNV-1a over the id, then a 64-bit finaliser mixed with the session.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key_id.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    let mut x = session ^ h.rotate_left(17);
    // splitmix64 finaliser: good avalanche, all-integer.
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

/// Sticky-session state for one pool.
pub(super) struct StickySessions {
    map: Mutex<HashMap<u64, (String, u64)>>,
    tuning: Arc<Tuning>,
    hashed: bool,
}

impl StickySessions {
    pub(super) fn new(tuning: Arc<Tuning>) -> Self {
        let hashed = tuning.sticky_mode != "map";
        Self {
            map: Mutex::new(HashMap::new()),
            tuning,
            hashed,
        }
    }

    /// Whether this pool routes by rendezvous hashing (no shared state).
    pub(super) fn is_hashed(&self) -> bool {
        self.hashed
    }

    /// Index of the highest-scoring available key, or None when none is available.
    ///
    /// `available` is evaluated through the caller's closure so this module stays
    /// free of model-cooldown knowledge.
    pub(super) fn rendezvous(
        &self,
        session: u64,
        keys: &[Arc<super::KeyState>],
        is_available: impl Fn(&super::KeyState) -> bool,
    ) -> Option<usize> {
        let mut best: Option<(u64, usize)> = None;
        for (i, k) in keys.iter().enumerate() {
            if !is_available(k) {
                continue;
            }
            let s = score(session, &k.id_hash);
            if best.is_none_or(|(bs, _)| s > bs) {
                best = Some((s, i));
            }
        }
        best.map(|(_, i)| i)
    }

    /// `map` mode: key id bound to `session` while the binding is fresh.
    pub(super) fn lookup(&self, session: u64, now: u64) -> Option<String> {
        if self.hashed {
            return None;
        }
        // Per-entry TTL check instead of a full-map retain sweep on every pick;
        // saturating_sub survives wall-clock steps backward.
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

    /// `map` mode: remember that `session` is served by the key `kid`.
    pub(super) fn bind(&self, session: u64, kid: &str, now: u64) {
        if self.hashed {
            return;
        }
        let mut map = lock(&self.map);
        if map.len() >= self.tuning.sticky_max_entries {
            map.clear(); // coarse eviction on overflow
        }
        map.insert(session, (kid.to_string(), now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun(mode: &str) -> Arc<Tuning> {
        Arc::new(Tuning {
            sticky_mode: mode.to_string(),
            ..Tuning::default()
        })
    }

    #[test]
    fn score_is_stable_and_well_spread() {
        // Deterministic across calls (and therefore across processes).
        assert_eq!(score(42, "abc"), score(42, "abc"));
        assert_ne!(score(42, "abc"), score(43, "abc"));
        assert_ne!(score(42, "abc"), score(42, "abd"));
        // Sanity: 1000 distinct keys should not collapse onto one value.
        let distinct: std::collections::HashSet<u64> =
            (0..1000).map(|i| score(7, &i.to_string())).collect();
        assert!(distinct.len() > 990, "poor spread: {}", distinct.len());
    }

    /// The point of the hashed mode: two independent "instances" (no shared
    /// state) agree on the key for the same session.
    #[test]
    fn two_instances_agree_without_sharing_state() {
        let a = StickySessions::new(tun("hash"));
        let b = StickySessions::new(tun("hash"));
        let keys: Vec<Arc<super::super::KeyState>> = ["k1", "k2", "k3"]
            .iter()
            .map(|s| Arc::new(super::super::KeyState::new((*s).to_string(), 0)))
            .collect();
        for session in 0..200u64 {
            let pa = a.rendezvous(session, &keys, |_| true);
            let pb = b.rendezvous(session, &keys, |_| true);
            assert_eq!(pa, pb, "instances disagree for session {session}");
        }
    }

    /// Unavailable keys are skipped, and the choice is still deterministic.
    #[test]
    fn unavailable_keys_are_skipped() {
        let s = StickySessions::new(tun("hash"));
        let keys: Vec<Arc<super::super::KeyState>> = ["k1", "k2", "k3"]
            .iter()
            .map(|k| Arc::new(super::super::KeyState::new((*k).to_string(), 0)))
            .collect();
        let pinned = s.rendezvous(1234, &keys, |_| true).expect("a key");
        let without = s
            .rendezvous(1234, &keys, |k| k.id_hash != keys[pinned].id_hash)
            .expect("another key");
        assert_ne!(pinned, without);
        // Everything unavailable -> nothing to pick.
        assert!(s.rendezvous(1234, &keys, |_| false).is_none());
    }

    #[test]
    fn map_mode_still_binds_and_expires() {
        let s = StickySessions::new(tun("map"));
        assert!(s.lookup(9, 0).is_none());
        s.bind(9, "kid", 1_000);
        assert_eq!(s.lookup(9, 1_100).as_deref(), Some("kid"));
        // Beyond the TTL (measured from the *refresh* above) the binding is dropped.
        let late = 1_100 + Tuning::default().sticky_ttl().as_millis() as u64 + 1;
        assert!(s.lookup(9, late).is_none());
    }
}
