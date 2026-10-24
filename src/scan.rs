//! Byte-level JSON field scanner for the hot path.
//!
//! For pass-through providers we avoid a full `serde_json::Value` round-trip:
//! peek the `model`/`stream` fields and splice the upstream model name directly
//! into the request body bytes. Falls back to Value parsing on any ambiguity.
//!
//! Performance notes (measured by `cargo bench`, benches/hot_paths.rs):
//! - one walk extracts both fields (it used to walk the body twice);
//! - bytes that cannot matter are skipped with `memchr`, so string *contents*
//!   are never inspected one byte at a time. Together this is ~10x on a 64 KiB
//!   body and matters for the largest payloads (32 MiB body limit).

use std::ops::Range;

/// Peek top-level "model" (string) and "stream" (bool) fields without building a DOM.
/// Returns None if the body isn't a flat-enough JSON object — caller falls back to Value.
pub fn peek_request(body: &[u8]) -> Option<(String, bool)> {
    let mut model: Option<String> = None;
    let mut stream: Option<bool> = None;
    // A duplicate or escaped key is ambiguous: the caller must fall back to a real
    // parse, otherwise authorization and the upstream would disagree (see
    // `string_field_span`).
    let mut model_seen = 0u32;
    let mut stream_seen = 0u32;
    let mut bail = false;

    walk_top_level(body, |key, content_end| {
        // A key written with a JSON escape ("mod\u0065l") is the same key to
        // serde but different bytes to us, so decode before comparing. This only
        // allocates when the key actually contains a backslash.
        let escaped = key.contains(&b'\\');
        let is_model = key == b"model" || (escaped && decode_json_string(key) == "model");
        if escaped && is_model {
            // An escaped spelling of the field: the caller must fall back to a real
            // parse (we cannot splice a span in a key we cannot match byte-for-byte,
            // and the upstream decides by decoded name).
            model = None;
            stream = None;
            bail = true;
            return Some(true);
        }
        let is_stream =
            key == b"stream" || (key.contains(&b'\\') && decode_json_string(key) == "stream");
        if is_model {
            model_seen += 1;
            if model_seen > 1 {
                return Some(true);
            }
            let span = string_value_span(body, content_end)?;
            model = Some(decode_json_string(&body[span]));
        } else if is_stream {
            stream_seen += 1;
            if stream_seen > 1 {
                return Some(true);
            }
            match bool_value(body, content_end) {
                // `"stream": 1` (a Python-ish truthy value) is not the JSON the
                // spec allows: the fast path used to read it as `false`, forward the
                // body verbatim, and then mishandle a streamed reply. Bail out so the
                // DOM path can reject it.
                None => {
                    bail = true;
                    return Some(true);
                }
                value => stream = value,
            }
        }
        // Stop as soon as both fields are known — the tail of a large body is
        // usually the message history, which we do not need.
        Some(model.is_some() && stream.is_some())
    });

    if bail || model_seen > 1 || stream_seen > 1 {
        return None;
    }
    Some((model?, stream.unwrap_or(false)))
}

/// Span of a top-level string field's value (without quotes) for in-place splicing.
///
/// Returns `None` when the field is **ambiguous**: it appears more than once, or
/// its key is written with a JSON escape (`"mod\u0065l"`). Both cases are
/// security-relevant — an upstream JSON parser resolves duplicates as
/// *last-one-wins* and decodes escapes, so a body like
/// `{"model":"allowed","model":"disabled"}` would be authorized and routed as
/// `allowed` here while the upstream executes `disabled`. Bailing out makes the
/// caller fall back to a real `serde_json` parse, which agrees with the upstream.
pub fn string_field_span(body: &[u8], key: &[u8]) -> Option<Range<usize>> {
    match scan_key(body, key) {
        KeyScan::Unique(span) => span,
        KeyScan::Absent | KeyScan::Ambiguous => None,
    }
}

/// Result of looking up one top-level key.
enum KeyScan {
    Unique(Option<Range<usize>>),
    Absent,
    Ambiguous,
}

/// Find a top-level key exactly once, refusing duplicates and escaped spellings.
fn scan_key(body: &[u8], key: &[u8]) -> KeyScan {
    let mut found: Option<Option<Range<usize>>> = None;
    let mut ambiguous = false;
    walk_top_level(body, |k, content_end| {
        // An escaped key cannot be compared byte-for-byte against `key`: "A"
        // and "A" are the same key to serde but different bytes to us.
        let escaped = k.contains(&b'\\');
        let matches = k == key || (escaped && decode_json_string(k).as_bytes() == key);
        if matches {
            if found.is_some() {
                ambiguous = true;
                return Some(true);
            }
            found = Some(string_value_span(body, content_end));
        }
        Some(false)
    });
    if ambiguous {
        return KeyScan::Ambiguous;
    }
    match found {
        Some(span) => KeyScan::Unique(span),
        None => KeyScan::Absent,
    }
}

/// Walk the body once, calling `f(key, index_after_key_string)` for every
/// top-level (depth 1) object key. `f` returns `true` to stop the walk.
fn walk_top_level<F>(body: &[u8], mut f: F)
where
    F: FnMut(&[u8], usize) -> Option<bool>,
{
    let mut i = 0usize;
    let mut depth = 0i32;
    while i < body.len() {
        match body[i] {
            b'"' => {
                let Some((content, next)) = scan_string(body, i) else {
                    return;
                };
                // Only a *key* may be reported: a string at depth 1 is a key only
                // when the next structural byte is ':'. Without this check every
                // depth-1 *value* was treated as a key, so a body carrying the
                // literal "model" as a value (e.g. `"content":"model"` at top level)
                // looked like a duplicate key and lost the byte fast path — and on
                // malformed input (`{"a":"model":"evil"}`) the value was spliced as
                // the model.
                if depth == 1 && is_key_at(body, next) && f(&body[content], next) == Some(true) {
                    return;
                }
                i = next;
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                if depth < 0 {
                    return; // malformed: let the caller fall back to Value parsing
                }
                i += 1;
            }
            // Nothing interesting in this byte: jump to the next structural one.
            _ => i = next_structural(body, i),
        }
    }
}

/// Is the string that ends at `after` followed by `:` (i.e. is it an object key)?
#[inline]
fn is_key_at(body: &[u8], after: usize) -> bool {
    body.get(skip_ws(body, after)) == Some(&b':')
}

/// Index of the next `"`, `{`, `}`, `[` or `]` at or after `i` (or `body.len()`).
///
/// Two SIMD scans instead of five byte comparisons per byte: this is what turns
/// the scanner from memory-bandwidth-bound into effectively free.
#[inline]
fn next_structural(body: &[u8], i: usize) -> usize {
    let rest = &body[i..];
    // memchr has a fixed setup cost that dominates a short remainder — for small
    // bodies (the common case: a few hundred bytes) a plain scan is faster.
    if rest.len() <= 96 {
        for (k, &b) in rest.iter().enumerate() {
            if matches!(b, b'"' | b'{' | b'}' | b'[' | b']') {
                // Always advances: the caller only lands here on a non-structural byte.
                return i + k.max(1);
            }
        }
        return body.len();
    }
    let a = memchr::memchr3(b'"', b'{', b'}', rest).unwrap_or(rest.len());
    let b = memchr::memchr2(b'[', b']', rest).unwrap_or(rest.len());
    i + a.min(b).max(1)
}

/// Given the index right after a key string, parse `: "value"` and return the
/// span of the value content (without quotes).
fn string_value_span(body: &[u8], after_key: usize) -> Option<Range<usize>> {
    let j = skip_ws(body, after_key);
    if body.get(j) != Some(&b':') {
        return None;
    }
    let j = skip_ws(body, j + 1);
    if body.get(j) != Some(&b'"') {
        return None; // non-string value — caller falls back to the Value path
    }
    scan_string(body, j).map(|(span, _)| span)
}

/// Parse `: true|false` after a key. Returns None when the value isn't a bool
/// literal (the walk then keeps looking for a later occurrence of the key).
fn bool_value(body: &[u8], after_key: usize) -> Option<bool> {
    let j = skip_ws(body, after_key);
    if body.get(j) != Some(&b':') {
        return None;
    }
    let j = skip_ws(body, j + 1);
    let rest = &body[j..];
    if rest.starts_with(b"true") {
        Some(true)
    } else if rest.starts_with(b"false") {
        Some(false)
    } else {
        None
    }
}

#[inline]
fn skip_ws(body: &[u8], mut i: usize) -> usize {
    while i < body.len() && body[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Decode a JSON string body into a `String`.
fn decode_json_string(raw: &[u8]) -> String {
    // Fast path: no escapes and no control characters (the overwhelmingly common
    // case for model ids). The old code always allocated a quoted copy and ran a
    // full JSON parse per request just to unescape a name like "gpt-4o-mini".
    if !raw.iter().any(|&b| b == b'\\' || b < 0x20)
        && let Ok(s) = std::str::from_utf8(raw)
    {
        return s.to_string();
    }
    // Slow path: real escapes — let serde unescape them.
    let raw = String::from_utf8_lossy(raw);
    match serde_json::from_str::<String>(&format!("\"{raw}\"")) {
        Ok(s) => s,
        // Invalid UTF-8 in a model id is a client error; keep the raw text so the
        // request fails later with a clear "unknown model" instead of a panic.
        Err(_) => raw.into_owned(),
    }
}

/// Given the index of an opening quote, return (content range, index after closing quote).
fn scan_string(body: &[u8], start: usize) -> Option<(Range<usize>, usize)> {
    debug_assert_eq!(body[start], b'"');
    let mut i = start + 1;
    loop {
        // Jump to the next quote or escape instead of walking byte by byte: for a
        // 1 MiB message history this is the difference between µs and ns.
        let rel = memchr::memchr2(b'"', b'\\', body.get(i..)?)?;
        match body[i + rel] {
            b'"' => return Some((start + 1..i + rel, i + rel + 1)),
            _ => i += rel + 2, // skip the escaped character
        }
    }
}

#[cfg(test)]
mod tests {
    /// A depth-1 string *value* is not a key, even when it spells "model".
    ///
    /// The walk reported every depth-1 string to its callback, so a body carrying
    /// the literal `"model"` as a value looked like a duplicate key: the fast path
    /// was abandoned (full DOM parse per request) and, on malformed input, a value
    /// could be spliced as the model.
    #[test]
    fn a_value_that_spells_a_field_name_is_not_a_key() {
        let body = br#"{"note":"model","model":"gpt-x","stream":false}"#;
        assert_eq!(
            peek_request(body),
            Some(("gpt-x".to_string(), false)),
            "the value 'model' must not count as the model key"
        );
        let span = string_field_span(body, b"model").expect("the real key has a unique span");
        assert_eq!(&body[span], b"gpt-x");
        // Same for a value that spells "stream".
        let body = br#"{"note":"stream","model":"m","stream":true}"#;
        assert_eq!(peek_request(body), Some(("m".to_string(), true)));
    }

    use super::*;

    #[test]
    fn peek_basic() {
        let body = br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi \"model\": x"}]}"#;
        let (model, stream) = peek_request(body).unwrap();
        assert_eq!(model, "gpt-4o");
        assert!(stream);
    }

    #[test]
    fn peek_no_stream() {
        let body = br#"{"messages":[],"model":"m"}"#;
        let (model, stream) = peek_request(body).unwrap();
        assert_eq!(model, "m");
        assert!(!stream);
    }

    #[test]
    fn splice_span() {
        let body = br#"{"model":"old/name","messages":[]}"#;
        let span = string_field_span(body, b"model").unwrap();
        assert_eq!(&body[span], b"old/name");
    }

    #[test]
    fn escaped_model() {
        let body = br#"{"model":"a\"b","stream":false}"#;
        let (model, stream) = peek_request(body).unwrap();
        assert_eq!(model, "a\"b");
        assert!(!stream);
    }

    #[test]
    fn model_prefix_field_does_not_match() {
        let body = br#"{"model_id":"nope","model":"yes","stream":true}"#;
        assert_eq!(peek_request(body).unwrap().0, "yes");
    }

    #[test]
    fn stream_options_does_not_shadow_stream() {
        // "stream_options" must not be read as "stream"
        let body = br#"{"model":"m","stream_options":{"include_usage":true},"stream":false}"#;
        let (_, stream) = peek_request(body).unwrap();
        assert!(!stream, "stream_options must not be mistaken for stream");
    }

    #[test]
    fn stream_before_model_is_found() {
        // The single walk must handle any field order.
        let body = br#"{"stream":true,"temperature":0.5,"model":"m2"}"#;
        let (model, stream) = peek_request(body).unwrap();
        assert_eq!(model, "m2");
        assert!(stream);
    }

    #[test]
    fn nested_model_is_ignored() {
        // A nested "model" (e.g. inside tools) is not the top-level one.
        let body = br#"{"tools":[{"function":{"model":"nested"}}],"model":"top"}"#;
        assert_eq!(peek_request(body).unwrap().0, "top");
    }

    #[test]
    fn model_as_text_inside_a_message_is_ignored() {
        // The literal text `"model":"fake"` inside a string value must not match.
        let body =
            br#"{"messages":[{"role":"user","content":"{\"model\":\"fake\"}"}],"model":"real"}"#;
        assert_eq!(peek_request(body).unwrap().0, "real");
    }

    #[test]
    fn whitespace_around_colon_is_tolerated() {
        let body = br#"{ "model" : "m" , "stream" : true }"#;
        let (model, stream) = peek_request(body).unwrap();
        assert_eq!(model, "m");
        assert!(stream);
    }

    #[test]
    fn non_string_model_falls_back() {
        let body = br#"{"model":123,"messages":[]}"#;
        assert!(peek_request(body).is_none());
    }

    #[test]
    fn missing_model_falls_back() {
        assert!(peek_request(br#"{"messages":[]}"#).is_none());
    }

    #[test]
    fn unbalanced_body_does_not_panic() {
        for body in [
            &b"}"[..],
            &b"{"[..],
            &b"\"model\":"[..],
            &b""[..],
            &b"{\"model\":\"m\""[..],
        ] {
            let _ = peek_request(body);
            let _ = string_field_span(body, b"model");
        }
    }

    #[test]
    fn multibyte_content_does_not_split_chars() {
        // A 2-byte UTF-8 char right after a backslash must not cause a byte slice
        // panic inside scan_string.
        let body = "{\"model\":\"m\",\"messages\":[{\"content\":\"\\\\ü\"}],\"stream\":true}";
        let (model, stream) = peek_request(body.as_bytes()).unwrap();
        assert_eq!(model, "m");
        assert!(stream);
    }

    #[test]
    fn htmlish_payload_without_model_is_scanned_fully() {
        // Worst case: no model → full walk, must terminate and return None.
        let body = format!(r#"{{"messages":[{{"content":"{}"}}]}}"#, "x".repeat(1000));
        assert!(peek_request(body.as_bytes()).is_none());
    }

    /// An authorization bypass, found by fuzzing: `{"model":"allowed","model":
    /// "disabled"}` was routed and authorized as *allowed* while the upstream
    /// (serde, last-wins) executed *disabled*. The scanner must refuse to answer.
    #[test]
    fn a_duplicate_model_key_is_refused() {
        let body = br#"{"model":"allowed","messages":[],"model":"disabled"}"#;
        assert!(
            string_field_span(body, b"model").is_none(),
            "a duplicate model key must fall back to a real parse"
        );
        assert!(peek_request(body).is_none(), "peek must bail as well");
    }

    /// The same bypass with an escape in the key: `"mod\u0065l"` decodes to
    /// "model" for serde but not for a byte comparison.
    #[test]
    fn an_escaped_model_key_is_refused() {
        let body = br#"{"model":"allowed","mod\u0065l":"disabled"}"#;
        assert!(string_field_span(body, b"model").is_none());
        assert!(peek_request(body).is_none(), "peek must bail on escapes");
    }

    /// A single, plain key still takes the fast path (no behaviour change).
    #[test]
    fn a_single_model_key_still_scans() {
        let body = br#"{"model":"mock/test-model","stream":true,"messages":[]}"#;
        let span = string_field_span(body, b"model").expect("span");
        assert_eq!(&body[span], b"mock/test-model");
        assert_eq!(
            peek_request(body),
            Some(("mock/test-model".to_string(), true))
        );
    }
}
