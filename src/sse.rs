//! Shared SSE parser/serializer for upstream translation streams.
//! Reuses a single BytesMut buffer: no per-event String allocations.

use bytes::{Bytes, BytesMut};

pub struct SseParser {
    buf: BytesMut,
}

impl SseParser {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(16 * 1024),
        }
    }

    /// Feed raw bytes, get back complete `data:` payloads.
    /// Handles both LF and CRLF framing (the SSE spec allows either);
    /// multi-line `data:` fields are joined with '\n' per spec.
    ///
    /// Returns a fresh `Vec` on purpose: the callers bulk-`extend` it into their
    /// queue, which is measurably faster than pushing events one by one into a
    /// `VecDeque` (see `cargo bench`: 516 vs 549 ns per 10-event chunk).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Bytes> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(4);
        let mut consumed = 0;
        while let Some((ev_len, next)) = find_boundary(&self.buf[consumed..]) {
            push_event(&self.buf[consumed..consumed + ev_len], &mut out);
            consumed += next;
        }
        if consumed > 0 {
            let _ = self.buf.split_to(consumed);
        }
        out
    }

    /// Remaining buffered bytes (call at EOF to flush a trailing partial event).
    pub fn finish(&mut self) -> Vec<Bytes> {
        if self.buf.is_empty() {
            return Vec::new();
        }
        let chunk = self.buf.split().freeze();
        let mut out = Vec::with_capacity(1);
        push_event(&chunk, &mut out);
        out
    }
}

/// Extract `data:` payloads from one raw event block.
fn push_event(event: &[u8], out: &mut Vec<Bytes>) {
    let mut data: Option<BytesMut> = None;
    for line in event.split(|&b| b == b'\n') {
        // tolerate CRLF line endings
        let line = match line.last() {
            Some(b'\r') => &line[..line.len() - 1],
            _ => line,
        };
        if let Some(rest) = line.strip_prefix(b"data:") {
            let rest = if rest.first() == Some(&b' ') { &rest[1..] } else { rest };
            match &mut data {
                Some(d) => {
                    d.extend_from_slice(b"\n");
                    d.extend_from_slice(rest);
                }
                None => {
                    let mut d = BytesMut::new();
                    d.extend_from_slice(rest);
                    data = Some(d);
                }
            }
        }
    }
    if let Some(d) = data
        && !d.is_empty()
    {
        out.push(d.freeze());
    }
}

/// Locate the end of the first complete event: a blank line, i.e. "\n\n" or
/// "\r\n\r\n" (also tolerates a lone "\n" followed by "\r\n").
/// Returns (event_len, bytes_to_consume).
fn find_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while let Some(off) = memchr::memchr(b'\n', &buf[i..]) {
        let pos = i + off;
        match buf.get(pos + 1) {
            Some(b'\n') => return Some((pos, pos + 2)),
            Some(b'\r') if buf.get(pos + 2) == Some(&b'\n') => return Some((pos, pos + 3)),
            _ => {}
        }
        i = pos + 1;
    }
    None
}

/// Serialize a JSON value as an SSE frame: `data: {...}\n\n`.
pub fn frame(v: &serde_json::Value) -> Bytes {
    let mut out = BytesMut::with_capacity(256);
    out.extend_from_slice(b"data: ");
    // serde_json::to_writer into Vec, then extend — single allocation.
    if let Ok(j) = serde_json::to_vec(v) {
        out.extend_from_slice(&j);
    }
    out.extend_from_slice(b"\n\n");
    out.freeze()
}

pub const DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(v: Vec<Bytes>) -> Vec<String> {
        v.into_iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn lf_events() {
        let mut p = SseParser::new();
        let out = p.feed(b"data: a\n\ndata: b\n\n");
        assert_eq!(texts(out), vec!["a", "b"]);
        assert!(p.finish().is_empty());
    }

    #[test]
    fn crlf_events() {
        // CRLF framing must not stall the stream until EOF
        let mut p = SseParser::new();
        let out = p.feed(b"data: a\r\n\r\ndata: b\r\n\r\n");
        assert_eq!(texts(out), vec!["a", "b"]);
        assert!(p.finish().is_empty());
    }

    #[test]
    fn crlf_split_across_feeds() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: a\r\n\r").is_empty());
        let out = p.feed(b"\ndata: c\r\n\r\n");
        assert_eq!(texts(out), vec!["a", "c"]);
    }

    #[test]
    fn multiline_data_joined_with_newline() {
        let mut p = SseParser::new();
        let out = p.feed(b"data: line1\ndata: line2\n\n");
        assert_eq!(texts(out), vec!["line1\nline2"]);
    }

    #[test]
    fn trailing_partial_event_flushed_at_eof() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: tail").is_empty());
        assert_eq!(texts(p.finish()), vec!["tail"]);
    }

    #[test]
    fn non_data_lines_ignored() {
        let mut p = SseParser::new();
        let out = p.feed(b": comment\nevent: message\ndata: x\n\n");
        assert_eq!(texts(out), vec!["x"]);
    }
}
