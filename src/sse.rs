//! Shared SSE parser/serializer for upstream translation streams.
//! Reuses a single BytesMut buffer: no per-event String allocations.

use std::fmt;

use bytes::{Bytes, BytesMut};

/// Largest partial event the parser will buffer, in bytes.
///
/// `feed` copies every chunk it is given into `buf` and only releases the
/// *complete* prefix, so a provider that never sends a blank line (an endless
/// `data:` line, or a body that is simply one long line) grows that buffer
/// without bound. That is an allocation paid for by whoever can make us read such
/// an upstream — one connection per stalled stream, unbounded bytes each. A real
/// event is a few hundred bytes (a chat delta, a usage chunk), so 1 MiB is far
/// above any working provider and small enough to be irrelevant when a stream
/// does stall. Same reasoning as the WebSocket frame cap in [`crate::ws`].
const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// Reported when the buffered partial event exceeds [`MAX_EVENT_BYTES`].
///
/// The parser stays failed after this: the bytes that were buffered have been
/// released, so there is no state left to resume from, and pretending a stream
/// is healthy after dropping its tail would hand the client a truncated message
/// as if it were complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventTooLarge {
    /// Bytes that had accumulated for one event when the cap was hit.
    pub buffered: usize,
}

impl fmt::Display for EventTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upstream SSE event exceeded the {MAX_EVENT_BYTES} byte cap: {} bytes buffered \
             without a blank line",
            self.buffered
        )
    }
}

impl std::error::Error for EventTooLarge {}

pub struct SseParser {
    buf: BytesMut,
    /// Set when an event overran [`MAX_EVENT_BYTES`]; sticky, see
    /// [`EventTooLarge`].
    failed: bool,
}

impl SseParser {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(16 * 1024),
            failed: false,
        }
    }

    /// Feed raw bytes, get back complete `data:` payloads.
    /// Handles both LF and CRLF framing (the SSE spec allows either);
    /// multi-line `data:` fields are joined with '\n' per spec.
    ///
    /// Returns a fresh `Vec` on purpose: the callers bulk-`extend` it into their
    /// queue, which is measurably faster than pushing events one by one into a
    /// `VecDeque` (see `cargo bench`: 516 vs 549 ns per 10-event chunk).
    ///
    /// This is the infallible wrapper for translators whose response has already
    /// started (they can only stop producing events, not fail the stream). On
    /// overflow the buffered event is dropped and the parse ends, which keeps the
    /// memory bounded; [`SseParser::feed_checked`] is the same parse with the
    /// error handed back, for callers that can fail cleanly.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Bytes> {
        self.feed_checked(chunk).unwrap_or_default()
    }

    /// Feed raw bytes, get back complete `data:` payloads, or the error that says
    /// the upstream is not framing events at all.
    pub fn feed_checked(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, EventTooLarge> {
        if self.failed {
            // The stream is already abandoned; reporting it again keeps every
            // later caller on the same error path instead of silently resuming.
            return Err(EventTooLarge { buffered: 0 });
        }
        // A single chunk larger than the whole cap can never become a legal
        // event, so fail before copying it in: there is no point allocating a
        // buffer we would immediately abandon.
        if chunk.len() > MAX_EVENT_BYTES {
            self.failed = true;
            return Err(EventTooLarge {
                buffered: chunk.len(),
            });
        }
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
        // Everything left is one *incomplete* event: cap it, and release it when
        // it overruns rather than keeping the bytes around for a parse that can
        // no longer succeed.
        if self.buf.len() > MAX_EVENT_BYTES {
            let buffered = self.buf.len();
            self.failed = true;
            self.buf = BytesMut::new();
            return Err(EventTooLarge { buffered });
        }
        Ok(out)
    }

    /// Remaining buffered bytes (call at EOF to flush a trailing partial event).
    pub fn finish(&mut self) -> Vec<Bytes> {
        if self.failed || self.buf.is_empty() {
            // A failed parse has no trustworthy tail to flush.
            return Vec::new();
        }
        let chunk = self.buf.split().freeze();
        let mut out = Vec::with_capacity(1);
        push_event(&chunk, &mut out);
        out
    }

    /// Bytes currently held for a partial event (test-only).
    #[cfg(test)]
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
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
            let rest = if rest.first() == Some(&b' ') {
                &rest[1..]
            } else {
                rest
            };
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

/// Test plumbing that drives the real streaming translators.
///
/// The translators take a `reqwest::Response` — the only way to exercise the
/// production path (and the only way to see how the bytes are *framed*, which is
/// where the interesting bugs live) is to speak HTTP to a loopback socket. Each
/// `Vec<u8>` in `chunks` is written as its own TCP write, so tests can split one
/// event across reads on purpose.
#[cfg(test)]
pub(crate) mod test_support {
    use std::io;
    use std::time::Duration;

    use bytes::Bytes;
    use futures::{Stream, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve `chunks` as one `text/event-stream` response on a loopback port and
    /// return the client-side response.
    pub(crate) async fn sse_response(chunks: Vec<Vec<u8>>) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local address");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // The request head is irrelevant; the body never is (all GET).
            let mut head = [0u8; 2048];
            let _ = sock.read(&mut head).await;
            let header =
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
            if sock.write_all(header).await.is_err() {
                return;
            }
            for chunk in chunks {
                if sock.write_all(&chunk).await.is_err() {
                    return;
                }
                let _ = sock.flush().await;
                // Let the client read this write as a chunk of its own: the
                // fragmentation tests depend on the split being observable.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = sock.shutdown().await;
        });
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build a test client")
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("the loopback upstream answers")
    }

    /// Drain a translated stream into its raw frames.
    pub(crate) async fn frames<S>(stream: S) -> Vec<String>
    where
        S: Stream<Item = Result<Bytes, io::Error>>,
    {
        futures::pin_mut!(stream);
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            let bytes = item.expect("a translated frame");
            out.push(String::from_utf8(bytes.to_vec()).expect("frames are UTF-8"));
        }
        out
    }

    /// Drain frames until the stream ends *or fails*: the error is returned
    /// instead of panicking, for the tests that expect a stall.
    pub(crate) async fn frames_or_error<S>(stream: S) -> (Vec<String>, Option<String>)
    where
        S: Stream<Item = Result<Bytes, io::Error>>,
    {
        futures::pin_mut!(stream);
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(bytes) => out.push(String::from_utf8(bytes.to_vec()).expect("frames are UTF-8")),
                Err(e) => return (out, Some(e.to_string())),
            }
        }
        (out, None)
    }

    /// Parse one frame's JSON body; `[DONE]` (and anything unparsable) is None.
    pub(crate) fn data(frame: &str) -> Option<serde_json::Value> {
        let body = frame.trim().strip_prefix("data:")?.trim();
        if body == "[DONE]" {
            return None;
        }
        serde_json::from_str(body).ok()
    }

    /// Headers arrive, the body never does: the "200 then silence" upstream the
    /// first-byte deadline exists for. The socket stays open for `hold`.
    pub(crate) async fn silent_body(content_type: &str, hold: Duration) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local address");
        let content_type = content_type.to_string();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut head = [0u8; 2048];
            let _ = sock.read(&mut head).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\nconnection: close\r\n\r\n"
            );
            if sock.write_all(header.as_bytes()).await.is_err() {
                return;
            }
            let _ = sock.flush().await;
            // Silence, on purpose.
            tokio::time::sleep(hold).await;
            let _ = sock.shutdown().await;
        });
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build a test client")
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("the loopback upstream answers the headers")
    }

    /// A one-key pool entry, for the per-key usage counters.
    pub(crate) fn key_state() -> std::sync::Arc<crate::pool::KeyState> {
        let pool = crate::pool::KeyPool::new(
            "test".into(),
            vec!["k-test".into()],
            crate::config::Strategy::FillFirst,
            4,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
        );
        pool.pick("m", None).expect("the pool holds one key")
    }
}

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

    // ----- the buffer cap -----

    /// A provider that never sends a blank line must not be able to grow the
    /// buffer forever: the parse fails, the buffer is released, and it stays
    /// failed instead of resuming on a torn event.
    #[test]
    fn an_event_without_a_blank_line_is_refused_at_the_cap() {
        let mut p = SseParser::new();
        // 64 KiB of `data: aaaa…` per chunk, no newline anywhere: every chunk is
        // one more swallow for a buffer that can never complete an event.
        let chunk = vec![b'a'; 64 * 1024];
        let mut fed = 0usize;
        let err = loop {
            match p.feed_checked(&chunk) {
                Ok(out) => {
                    assert!(out.is_empty(), "no event can complete without a newline");
                    fed += chunk.len();
                    assert!(
                        p.buffered_len() <= MAX_EVENT_BYTES,
                        "the buffer grew to {} bytes",
                        p.buffered_len()
                    );
                    assert!(fed <= MAX_EVENT_BYTES + chunk.len(), "the cap never bit");
                }
                Err(e) => break e,
            }
        };
        assert!(err.buffered > MAX_EVENT_BYTES, "{err}");
        assert!(err.to_string().contains("cap"), "{err}");
        assert_eq!(p.buffered_len(), 0, "the overrun buffer is released");
        // Sticky: the stream is over, not just this event.
        assert!(p.feed_checked(b"data: ok\n\n").is_err());
        assert!(
            p.finish().is_empty(),
            "no tail may be flushed after a failure"
        );
    }

    /// One chunk that is larger than the cap is refused without being copied.
    #[test]
    fn a_single_oversized_chunk_is_refused_before_it_is_buffered() {
        let mut p = SseParser::new();
        let chunk = vec![b'x'; MAX_EVENT_BYTES + 1];
        let err = p
            .feed_checked(&chunk)
            .expect_err("a whole chunk over the cap cannot become an event");
        assert_eq!(err.buffered, MAX_EVENT_BYTES + 1);
        assert!(p.buffered_len() <= MAX_EVENT_BYTES);
    }

    /// The infallible wrapper stays bounded too (it is what the streaming
    /// translators use), and a healthy stream still parses after a huge *event*,
    /// because events are released as they complete.
    #[test]
    fn the_infallible_wrapper_stops_instead_of_growing() {
        let mut p = SseParser::new();
        let chunk = vec![b'b'; 64 * 1024];
        for _ in 0..40 {
            assert!(p.feed(&chunk).is_empty());
        }
        assert!(p.buffered_len() <= MAX_EVENT_BYTES);

        // Ordinary traffic is unaffected: many complete events in one feed.
        let mut p = SseParser::new();
        let mut body = Vec::new();
        for i in 0..100 {
            body.extend_from_slice(format!("data: {i}\n\n").as_bytes());
        }
        assert_eq!(p.feed(&body).len(), 100);
        assert_eq!(p.buffered_len(), 0);
    }
}
