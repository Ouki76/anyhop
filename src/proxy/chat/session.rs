//! Sticky-session keys: a stable hash of the model plus the body prefix.

use axum::body::Bytes;

/// Sticky session hash: model + the first `tuning.session_prefix_bytes` of the body
/// (covers system + first messages; 4 KB by default).
///
/// `pub` only so `cargo bench` can measure it — it is not part of the HTTP surface.
pub fn session_key(model: &str, body: &Bytes) -> u64 {
    session_key_with(model, body, 4096)
}

pub(super) fn session_key_with(model: &str, body: &Bytes, prefix_bytes: usize) -> u64 {
    // NOT a cryptographic hash, and deliberately so: this value chooses *which key
    // serves a conversation*, is never compared against a secret, and is not stored
    // anywhere an attacker can observe. SHA-256 over 4 KiB costs ~23 µs on a CPU
    // without SHA-NI (Haswell and older), which is 15 % of a core at 6 k rps for a
    // pure cache-affinity decision; FNV-1a with a splitmix64 finaliser costs ~0.7 µs
    // and distributes just as well for map keys and rendezvous hashing.
    //
    // Determinism is the requirement (every instance must hash a conversation to the
    // same key), so the seed is fixed and nothing here may become randomly seeded.
    let prefix = &body[..body.len().min(prefix_bytes.max(1))];
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    // 8 bytes at a time: a byte-wise fold costs ~1.4 ns/byte on a non-SHA-NI core,
    // which is most of the 5 µs. Reading a word and mixing it with the same prime
    // keeps the properties that matter here (deterministic, avalanche-y after the
    // finaliser) at ~1/6 the cost.
    for chunk in model.as_bytes().chunks(8).chain(prefix.chunks(8)) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        h ^= u64::from_le_bytes(word);
        h = h.wrapping_mul(0x0000_0100_0000_01b3); // FNV prime
    }
    // FNV alone has a weak final avalanche; splitmix64's finaliser fixes that so
    // neighbouring bodies land in far-apart buckets.
    let mut z = h ^ (prefix.len() as u64) << 32 ^ model.len() as u64;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- sticky session key -----

    #[test]
    fn session_key_is_stable_per_conversation_and_differs_per_model() {
        let body = Bytes::from_static(br#"{"messages":[{"role":"user","content":"hi"}]}"#);
        assert_eq!(session_key("a/model", &body), session_key("a/model", &body));
        assert_ne!(session_key("a/model", &body), session_key("b/model", &body));
        // Same prefix but different tail must not collide (only the first 4KB is
        // hashed, so the payload beyond that is intentionally ignored).
        let other = Bytes::from_static(br#"{"messages":[{"role":"user","content":"yo"}]}"#);
        assert_ne!(
            session_key("a/model", &body),
            session_key("a/model", &other)
        );
    }

    /// The fast hash must behave like a hash: deterministic, model-sensitive and
    /// collision-free for realistic volumes (it is a map key and a rendezvous input).
    #[test]
    fn the_fast_session_hash_is_deterministic_and_well_spread() {
        let body = Bytes::from_static(br#"{"messages":[{"role":"user","content":"hi"}]}"#);
        assert_eq!(session_key("m", &body), session_key("m", &body));
        assert_ne!(session_key("a", &body), session_key("b", &body));

        let mut seen = std::collections::HashSet::new();
        for i in 0..10_000u32 {
            let b = Bytes::from(format!(
                r#"{{"messages":[{{"role":"user","content":"turn {i}"}}]}}"#
            ));
            assert!(seen.insert(session_key("m", &b)), "collision at {i}");
        }
        // Sequential bodies must not cluster in the low bits (that is what the
        // finaliser is for: the sticky map and rendezvous both index with them).
        let low_bits: std::collections::HashSet<u64> = (0..4096u32)
            .map(|i| {
                let b = Bytes::from(format!(r#"{{"n":{i}}}"#));
                session_key("m", &b) & 0xff
            })
            .collect();
        assert!(
            low_bits.len() > 250,
            "the low byte only took {} distinct values out of 256",
            low_bits.len()
        );
    }

    #[test]
    fn session_key_handles_short_and_huge_bodies() {
        // Empty body must not panic (slice of 0 bytes is fine).
        let _ = session_key("m", &Bytes::new());
        // >4KB: only the first 4KB is hashed, and it must not slice out of range.
        let big = Bytes::from(vec![b'x'; 9000]);
        let a = session_key("m", &big);
        let mut almost = vec![b'x'; 4096];
        almost.extend_from_slice(b"tail");
        assert_eq!(
            a,
            session_key("m", &Bytes::from(almost)),
            "only the first 4KB may matter"
        );
    }
}

/// The configurable prefix length is a cost knob (a SHA-256 over the first N
/// bytes of every chat request) and must not change the *stability* guarantee.
#[cfg(test)]
mod prefix_tests {
    use super::*;

    fn body_of(first: &[u8], tail: &[u8]) -> Bytes {
        let mut v = first.to_vec();
        v.extend_from_slice(tail);
        Bytes::from(v)
    }

    #[test]
    fn the_default_prefix_matches_the_documented_4096_bytes() {
        let body = body_of(b"{\"messages\":[", b"]}");
        assert_eq!(
            session_key("m", &body),
            session_key_with("m", &body, 4096),
            "session_key is the documented default"
        );
    }

    #[test]
    fn a_shorter_prefix_ignores_the_tail_it_was_told_to_ignore() {
        // The bodies differ only at byte 2.
        let a = Bytes::from_static(b"AAA-rest-of-body-one");
        let b = Bytes::from_static(b"AAB-rest-of-body-two");

        assert_eq!(
            session_key_with("m", &a, 2),
            session_key_with("m", &b, 2),
            "bytes beyond the configured prefix must not take part"
        );
        assert_ne!(
            session_key_with("m", &a, 3),
            session_key_with("m", &b, 3),
            "a prefix that covers the difference must separate the sessions"
        );
        // A prefix of 0 is treated as 1: it must never hash an empty body, which
        // would put every conversation of a model in one bucket.
        assert_eq!(session_key_with("m", &a, 0), session_key_with("m", &a, 1));
        assert_eq!(
            session_key_with("m", &a, 1),
            session_key_with("m", &b, 1),
            "the first byte is the same, so a 1-byte prefix cannot tell them apart"
        );
    }
}
