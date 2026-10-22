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
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(model.as_bytes());
    h.update(&body[..body.len().min(prefix_bytes.max(1))]);
    let d = h.finalize();
    // sha256 always yields 32 bytes; slice to 8 for the hash map key.
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    u64::from_le_bytes(out)
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
