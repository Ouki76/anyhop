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

    /// Feed raw bytes, get back complete `data:` payloads (concatenated multiline).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Bytes> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut consumed = 0;
        while let Some(pos) = find_subslice(&self.buf[consumed..], b"\n\n") {
            let event = &self.buf[consumed..consumed + pos];
            let mut data = BytesMut::new();
            for line in event.split(|&b| b == b'\n') {
                if let Some(rest) = line.strip_prefix(b"data:") {
                    let rest = if rest.first() == Some(&b' ') { &rest[1..] } else { rest };
                    data.extend_from_slice(rest);
                }
            }
            if !data.is_empty() {
                out.push(data.freeze());
            }
            consumed += pos + 2;
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
        self.feed_owned(&chunk)
    }

    fn feed_owned(&mut self, chunk: &Bytes) -> Vec<Bytes> {
        // Treat the remainder as one final event even without the \n\n terminator.
        let mut data = BytesMut::new();
        for line in chunk.split(|&b| b == b'\n') {
            if let Some(rest) = line.strip_prefix(b"data:") {
                let rest = if rest.first() == Some(&b' ') { &rest[1..] } else { rest };
                data.extend_from_slice(rest);
            }
        }
        if data.is_empty() {
            Vec::new()
        } else {
            vec![data.freeze()]
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
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
