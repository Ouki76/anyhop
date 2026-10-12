//! Byte-level JSON field scanner for the hot path.
//!
//! For pass-through providers we avoid a full `serde_json::Value` round-trip:
//! peek the `model`/`stream` fields and splice the upstream model name directly
//! into the request body bytes. Falls back to Value parsing on any ambiguity.

use std::ops::Range;

/// Peek top-level "model" (string) and "stream" (bool) fields without building a DOM.
/// Returns None if the body isn't a flat-enough JSON object — caller falls back to Value.
pub fn peek_request(body: &[u8]) -> Option<(String, bool)> {
    let model = find_string_field(body, b"model")?;
    let stream = find_bool_field(body, b"stream").unwrap_or(false);
    Some((model, stream))
}

/// Span of a top-level string field's value (without quotes) for in-place splicing.
pub fn string_field_span(body: &[u8], key: &[u8]) -> Option<Range<usize>> {
    let mut i = 0usize;
    let mut depth = 0i32;
    while i < body.len() {
        match body[i] {
            b'"' => {
                let (_content, next) = scan_string(body, i)?;
                if depth == 1
                    && i + 1 + key.len() <= body.len()
                    && &body[i + 1..i + 1 + key.len()] == key
                {
                    // expect ':'
                    let mut j = next;
                    while j < body.len() && body[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j >= body.len() || body[j] != b':' {
                        return None;
                    }
                    j += 1;
                    while j < body.len() && body[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j >= body.len() || body[j] != b'"' {
                        return None; // non-string value — bail to Value path
                    }
                    let (vspan, _) = scan_string(body, j)?;
                    return Some(vspan);
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
                    return None;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn find_string_field(body: &[u8], key: &[u8]) -> Option<String> {
    let span = string_field_span(body, key)?;
    // Value contains raw JSON string content (may include escapes).
    let raw = std::str::from_utf8(&body[span]).ok()?;
    serde_json::from_str::<String>(&format!("\"{raw}\"")).ok()
}

fn find_bool_field(body: &[u8], key: &[u8]) -> Option<bool> {
    let mut i = 0usize;
    let mut depth = 0i32;
    while i < body.len() {
        match body[i] {
            b'"' => {
                let (_, next) = scan_string(body, i)?;
                if depth == 1
                    && i + 1 + key.len() <= body.len()
                    && &body[i + 1..i + 1 + key.len()] == key
                {
                    let mut j = next;
                    while j < body.len() && body[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j >= body.len() || body[j] != b':' {
                        return None;
                    }
                    j += 1;
                    while j < body.len() && body[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if body[j..].starts_with(b"true") {
                        return Some(true);
                    }
                    if body[j..].starts_with(b"false") {
                        return Some(false);
                    }
                    return None;
                }
                i = next;
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Given the index of an opening quote, return (content range, index after closing quote).
fn scan_string(body: &[u8], start: usize) -> Option<(Range<usize>, usize)> {
    debug_assert_eq!(body[start], b'"');
    let mut i = start + 1;
    while i < body.len() {
        match body[i] {
            b'\\' => i += 2,
            b'"' => return Some((start + 1..i, i + 1)),
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
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
        let mut v = body.to_vec();
        v.splice(span, b"new".iter().copied());
        assert_eq!(v, br#"{"model":"new","messages":[]}"#);
    }

    #[test]
    fn escaped_model() {
        let body = br#"{"model":"a\"b","stream":false}"#;
        let (model, stream) = peek_request(body).unwrap();
        assert_eq!(model, "a\"b");
        assert!(!stream);
    }
}
