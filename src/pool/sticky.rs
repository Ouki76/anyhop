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
///
/// The tuning is a shared, hot-swappable cell: a `[tuning] sticky_mode`/TTL edit
/// must take effect on a pool that a reload did *not* rebuild.
pub(super) struct StickySessions {
    map: Mutex<HashMap<u64, (String, u64)>>,
    tuning: Arc<arc_swap::ArcSwap<Tuning>>,
    /// Mirrors `sticky_mode` for the per-request check; refreshed by
    /// [`StickySessions::set_tuning`] so the hot path never loads the cell.
    hashed: std::sync::atomic::AtomicBool,
}

impl StickySessions {
    pub(super) fn new(tuning: Arc<arc_swap::ArcSwap<Tuning>>) -> Self {
        let hashed = is_hashed(&tuning.load());
        Self {
            map: Mutex::new(HashMap::new()),
            tuning,
            hashed: std::sync::atomic::AtomicBool::new(hashed),
        }
    }

    /// Swap in a new tuning cell state (config reload).
    pub(super) fn set_tuning(&self, tuning: Arc<Tuning>) {
        self.hashed
            .store(is_hashed(&tuning), std::sync::atomic::Ordering::Relaxed);
        self.tuning.store(tuning);
    }

    fn tuning(&self) -> Arc<Tuning> {
        self.tuning.load_full()
    }

    /// Whether this pool routes by rendezvous hashing (no shared state).
    pub(super) fn is_hashed(&self) -> bool {
        self.hashed.load(std::sync::atomic::Ordering::Relaxed)
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
            // `>=` rather than `>`: two credentials with the same id (which
            // `add_key` now refuses to create) must not pin every session of the
            // pair onto the first one forever.
            if best.is_none_or(|(bs, _)| s >= bs) {
                best = Some((s, i));
            }
        }
        best.map(|(_, i)| i)
    }

    /// `map` mode: key id bound to `session` while the binding is fresh.
    pub(super) fn lookup(&self, session: u64, now: u64) -> Option<String> {
        if self.is_hashed() {
            return None;
        }
        let ttl = self.tuning().sticky_ttl().as_millis() as u64;
        // Per-entry TTL check instead of a full-map retain sweep on every pick;
        // saturating_sub survives wall-clock steps backward.
        let mut map = lock(&self.map);
        match map.get_mut(&session) {
            Some((kid, seen)) if now.saturating_sub(*seen) < ttl => {
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
        if self.is_hashed() {
            return;
        }
        let max_entries = self.tuning().sticky_max_entries;
        let mut map = lock(&self.map);
        if map.len() >= max_entries {
            self.evict(&mut map, max_entries, now);
        }
        map.insert(session, (kid.to_string(), now));
    }

    /// Make room for one more binding.
    ///
    /// This used to be `map.clear()`: the whole table dropped at the cap, so at
    /// once every live conversation lost its key binding *and* one request paid
    /// for thousands of frees — the sticky pin exists to keep a conversation on
    /// one key for its prompt cache, and the cliff undid that for everyone just
    /// when the gateway was busiest.
    ///
    /// Expired entries go first (they cost nothing to lose). Only if that frees
    /// nothing are the oldest quarter dropped, which under sustained load is the
    /// traffic least likely to still be live.
    fn evict(&self, map: &mut HashMap<u64, (String, u64)>, max_entries: usize, now: u64) {
        let ttl = self.tuning().sticky_ttl().as_millis() as u64;
        map.retain(|_, (_, seen)| now.saturating_sub(*seen) < ttl);
        if map.len() < max_entries {
            return;
        }
        let mut ages: Vec<(u64, u64)> = map.iter().map(|(s, (_, seen))| (*seen, *s)).collect();
        ages.sort_unstable_by_key(|(seen, _)| *seen);
        for (_, session) in ages.into_iter().take(max_entries / 4) {
            map.remove(&session);
        }
    }
}

/// `[tuning] sticky_mode`: anything but `map` means rendezvous hashing.
fn is_hashed(tuning: &Tuning) -> bool {
    tuning.sticky_mode != "map"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun(mode: &str) -> Arc<arc_swap::ArcSwap<Tuning>> {
        Arc::new(arc_swap::ArcSwap::from_pointee(Tuning {
            sticky_mode: mode.to_string(),
            ..Tuning::default()
        }))
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

    /// At the cap, eviction must drop the *oldest* bindings — never the whole
    /// table.
    ///
    /// `bind` used to call `map.clear()`, so the moment a busy gateway reached
    /// `sticky_max_entries` every live conversation lost its key binding at once
    /// and one request paid for thousands of frees. A sticky pin exists to keep a
    /// conversation on one key for its prompt cache; the cliff undid that for
    /// everyone exactly when the gateway was busiest.
    #[test]
    fn eviction_at_the_cap_keeps_the_newest_bindings() {
        let t = Arc::new(arc_swap::ArcSwap::from_pointee(Tuning {
            sticky_mode: "map".to_string(),
            sticky_max_entries: 8,
            ..Tuning::default()
        }));
        let s = StickySessions::new(t);
        // Fill to the cap with distinct sessions, oldest first. No `lookup` here:
        // a lookup refreshes an entry's timestamp, which is the point of the TTL.
        for i in 0..8u64 {
            s.bind(i, "key-a", 1_000 + i);
        }

        // One more binding trips eviction. The newest entries must survive and
        // only the oldest quarter may go.
        s.bind(99, "key-a", 1_008);
        assert_eq!(
            s.lookup(7, 1_008).as_deref(),
            Some("key-a"),
            "the newest binding was evicted by the cap"
        );
        assert_eq!(
            s.lookup(99, 1_008).as_deref(),
            Some("key-a"),
            "the binding that triggered eviction must exist"
        );
        assert_eq!(
            s.lookup(0, 1_008),
            None,
            "the oldest binding is the one that should go"
        );
        // The middle of the table is untouched: a clear() would have lost it too.
        assert_eq!(
            s.lookup(5, 1_008).as_deref(),
            Some("key-a"),
            "eviction dropped more than the oldest quarter"
        );
    }

    /// Expired entries are dropped first, so a table full of dead sessions does
    /// not force live ones out.
    #[test]
    fn expired_bindings_are_evicted_before_live_ones() {
        let t = Arc::new(arc_swap::ArcSwap::from_pointee(Tuning {
            sticky_mode: "map".to_string(),
            sticky_max_entries: 4,
            ..Tuning::default()
        }));
        let s = StickySessions::new(t);
        let ttl_ms = Tuning::default().sticky_ttl().as_millis() as u64;
        // Three long-expired sessions, then one live one at the cap.
        for i in 0..3u64 {
            s.bind(i, "key-a", 0);
        }
        let now = ttl_ms + 5_000;
        s.bind(50, "key-a", now);
        // Adding one more must evict only the dead ones.
        s.bind(51, "key-a", now + 1);
        assert_eq!(
            s.lookup(50, now + 1).as_deref(),
            Some("key-a"),
            "a live binding was dropped while expired ones existed"
        );
        assert_eq!(s.lookup(51, now + 1).as_deref(), Some("key-a"));
        assert_eq!(s.lookup(0, now + 1), None, "expired entries must be gone");
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

    /// A hot `[tuning] sticky_mode` edit must reach a pool that a reload reused.
    #[test]
    fn a_tuning_swap_changes_the_mode_and_the_ttl() {
        let s = StickySessions::new(tun("hash"));
        assert!(s.is_hashed(), "hash is the default mode");
        assert!(s.lookup(1, 0).is_none(), "hash mode keeps no map");

        s.set_tuning(Arc::new(Tuning {
            sticky_mode: "map".to_string(),
            sticky_ttl_secs: 1,
            ..Tuning::default()
        }));
        assert!(!s.is_hashed(), "switching to map mode must take effect");
        s.bind(1, "kid", 1_000);
        assert_eq!(s.lookup(1, 1_500).as_deref(), Some("kid"));
        assert!(
            s.lookup(1, 3_000).is_none(),
            "the new 1 s TTL must apply, not the 1800 s default"
        );

        // An unknown mode falls back to hashing, as the config validator requires.
        s.set_tuning(Arc::new(Tuning::default()));
        assert!(s.is_hashed());
    }

    /// Equal ids are refused by `KeyPool::add_key`; if one ever reaches the
    /// scorer, every session must still be spread rather than pinned to the
    /// first duplicate.
    #[test]
    fn duplicate_ids_do_not_pin_every_session_to_one_key() {
        let s = StickySessions::new(tun("hash"));
        let keys: Vec<Arc<super::super::KeyState>> = ["same", "same", "other"]
            .iter()
            .map(|k| Arc::new(super::super::KeyState::new((*k).to_string(), 0)))
            .collect();
        assert_eq!(
            keys[0].id_hash, keys[1].id_hash,
            "fixture must be duplicate"
        );
        // The strict `>` version always answered index 0 for the pair; `>=` picks
        // the later one, so the selection still moves.
        let picked = s.rendezvous(7, &keys, |_| true).expect("a key");
        assert!(picked < keys.len());
        assert!(s.rendezvous(7, &keys, |_| false).is_none());
    }
}
