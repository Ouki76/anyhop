//! Minimal server/client WebSocket (RFC 6455) framing for `GET /v1/realtime`.
//!
//! The crate builds offline and axum is compiled *without* its `ws` feature, so
//! there is no `tokio-tungstenite`/`tungstenite` to lean on. This module is the
//! small, self-contained piece the realtime proxy needs: the opening-handshake
//! key derivation ([`accept_key`]) and a frame codec
//! ([`read_frame`]/[`write_frame`] and the buffered [`FrameReader`]).
//!
//! What is implemented: FIN, text/binary/close/ping/pong, `continuation`
//! reassembly, 7/16/64-bit payload lengths, client→server masking, and the frame
//! and message size caps the proxy relies on. What is deliberately *not*
//! implemented: extensions (permessage-deflate), the client-side handshake
//! response validation (that lives in `proxy::realtime`, where the upstream
//! headers are), and anything stateful beyond one connection.
//!
//! # Security-relevant decisions
//!
//! * **Masking is a per-direction policy, not a suggestion.** RFC 6455 §5.1
//!   requires every client frame to be masked and every server frame not to be
//!   masked; the mask exists to stop a hostile page from reusing a connection to
//!   a non-WebSocket server by forging a byte stream that server would parse as
//!   HTTP. A gateway that accepts unmasked client frames re-opens exactly that
//!   hole, and one that forwards masked frames to a real client is equally
//!   broken, so [`FrameReader::server_side`] (peer is a client → masking
//!   required) and [`FrameReader::client_side`] (peer is a server → masking
//!   forbidden) are the only readers the relay uses. [`FrameReader::new`] with
//!   [`Mask::Any`] exists for tests and for callers that genuinely do not know
//!   which side they are.
//! * **Caps are enforced from the length prefix, before allocating.** A peer that
//!   announces a 2^63-byte payload must not make us reserve it: the length is
//!   checked against [`MAX_FRAME_BYTES`] as soon as the header is parsed, and the
//!   buffer only grows when real bytes arrive. Fragmented messages are capped in
//!   total by [`MAX_MESSAGE_BYTES`], so unlimited fragmentation cannot be used to
//!   assemble a giant message out of small frames.
//! * **Control frames are checked strictly** (FIN set, payload ≤ 125 bytes): a
//!   fragmented or oversized ping/close is a protocol error, not something to
//!   tolerate, because both are used by the closing handshake.
//! * **Text payloads are validated as UTF-8 on completion** (RFC 6455 §5.6). The
//!   codec does not otherwise interpret payloads — the gateway relays bytes.
//! * **[`FrameReader`] is cancel-safe**: bytes read from the socket are kept in an
//!   internal buffer, so a `next_message()` future may be dropped at any await
//!   point (e.g. by `tokio::select!`) without losing framing state. The relay
//!   depends on this to watch both directions in one task.

use std::io;

use base64::Engine as _;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// RFC 6455 §1.3: the GUID concatenated with `Sec-WebSocket-Key` before hashing.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Largest single frame accepted. 16 MiB is far above any realtime audio event
/// (base64 audio deltas are a few KiB) while still bounding one allocation.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Largest reassembled message accepted (fragments included).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// How much we try to read per syscall; also the buffer growth step.
const READ_CHUNK: usize = 16 * 1024;

/// WebSocket opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// 0x0 — a fragment continuing the previous data frame.
    Continuation,
    /// 0x1 — UTF-8 text.
    Text,
    /// 0x2 — arbitrary bytes.
    Binary,
    /// 0x8 — closing handshake.
    Close,
    /// 0x9 — keepalive request.
    Ping,
    /// 0xA — keepalive answer.
    Pong,
}

impl OpCode {
    /// Decode the low nibble of the first header byte.
    ///
    /// Reserved opcodes (0x3–0x7, 0xB–0xF) are rejected by the caller: without a
    /// negotiated extension they have no defined meaning.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Continuation,
            1 => Self::Text,
            2 => Self::Binary,
            8 => Self::Close,
            9 => Self::Ping,
            10 => Self::Pong,
            _ => return None,
        })
    }

    /// The wire value of this opcode.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Continuation => 0,
            Self::Text => 1,
            Self::Binary => 2,
            Self::Close => 8,
            Self::Ping => 9,
            Self::Pong => 10,
        }
    }

    /// Control frames (close/ping/pong) may interleave a fragmented message and
    /// have their own length/FIN rules.
    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// One WebSocket frame as it appears on the wire (after unmasking).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// FIN bit: the last fragment of a message.
    pub fin: bool,
    /// Frame opcode.
    pub opcode: OpCode,
    /// Payload bytes (already unmasked).
    pub payload: Vec<u8>,
}

impl Frame {
    /// A complete text frame.
    pub fn text(payload: impl Into<String>) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Text,
            payload: payload.into().into_bytes(),
        }
    }

    /// A complete binary frame.
    pub fn binary(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Binary,
            payload,
        }
    }

    /// A ping carrying the application's opaque payload (≤ 125 bytes).
    pub fn ping(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Ping,
            payload,
        }
    }

    /// A pong answering a ping (same payload, ≤ 125 bytes).
    pub fn pong(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: OpCode::Pong,
            payload,
        }
    }

    /// A close frame with a status code and a reason.
    ///
    /// The reason is truncated to the 123 bytes a control frame has left after
    /// the 2-byte code, on a `char` boundary so the payload stays valid UTF-8.
    pub fn close(code: u16, reason: &str) -> Self {
        let mut payload = Vec::with_capacity(2 + reason.len().min(123));
        payload.extend_from_slice(&code.to_be_bytes());
        let mut end = reason.len().min(123);
        while end > 0 && !reason.is_char_boundary(end) {
            end -= 1;
        }
        payload.extend_from_slice(&reason.as_bytes()[..end]);
        Self {
            fin: true,
            opcode: OpCode::Close,
            payload,
        }
    }

    /// The close status code, if this is a close frame that carries one.
    pub fn close_code(&self) -> Option<u16> {
        if self.opcode != OpCode::Close || self.payload.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
    }

    /// The close reason, if this is a close frame with a valid UTF-8 reason.
    pub fn close_reason(&self) -> Option<&str> {
        if self.opcode != OpCode::Close || self.payload.len() < 2 {
            return None;
        }
        std::str::from_utf8(&self.payload[2..]).ok()
    }

    /// Number of payload bytes (used for the relay's byte budget).
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// True when the frame carries no payload.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Which masking the peer is allowed (or required) to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mask {
    /// Accept either form (tests, and callers that do not know their role).
    Any,
    /// The peer is a client: frames must be masked (RFC 6455 §5.1).
    Required,
    /// The peer is a server: frames must not be masked (RFC 6455 §5.1).
    Forbidden,
}

/// Compute the `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`.
///
/// `base64(sha1(key + GUID))`, exactly RFC 6455 §4.2.2 step 5.4. The key is
/// client-controlled, which is safe: its only use is as SHA-1 input, and the
/// output is base64, so no header-splitting can be induced through it.
pub fn accept_key(client_key: &str) -> String {
    let mut input = Vec::with_capacity(client_key.len() + WS_GUID.len());
    input.extend_from_slice(client_key.as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sha1(&input))
}

/// A fresh `Sec-WebSocket-Key`: 16 random bytes from the OS CSPRNG, base64.
///
/// The key is an anti-cache/nonce value, but it must still be unpredictable
/// enough that a cached 101 from a shared proxy cannot be replayed, so it comes
/// from `getrandom` rather than a clock or a counter.
pub fn random_key() -> io::Result<String> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| io::Error::other(format!("CSPRNG unavailable: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

/// SHA-1 of `data` (RFC 3174).
///
/// Only the WebSocket handshake needs a hash here, and the handshake fixes it
/// to SHA-1, which `sha2` (already a dependency) cannot provide. It is used as
/// a *handshake checksum*, never for authentication, so the algorithm's
/// collision weaknesses do not matter; what matters is that it is exactly right,
/// which the RFC's own test vector in this module's tests pins down.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    // Full blocks are hashed straight out of `data`; only the padded tail is
    // copied, so a large input never costs a second full-size buffer.
    let (blocks, rest) = data.as_chunks::<64>();
    for block in blocks {
        sha1_compress(&mut state, block);
    }
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    // 56 mod 64 is where the 8-byte big-endian bit length goes; if the 0x80 does
    // not fit before that, one more block is needed.
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].as_chunks::<64>().0 {
        sha1_compress(&mut state, block);
    }

    let mut out = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// One SHA-1 compression step over a 64-byte block.
fn sha1_compress(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        let at = i * 4;
        *word = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, &word) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// Read exactly one frame from `r`.
///
/// Masking is honoured in either direction (`Mask::Any`): a masked frame is
/// unmasked, an unmasked one is returned as-is. Use [`FrameReader`] when the
/// side is known and masking must be enforced.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    FrameReader::new(r, Mask::Any).next_frame().await
}

/// Write one unmasked frame (the server→client direction) and flush it.
///
/// Frames are never fragmented on write: every message this gateway produces is
/// a single frame, so there is no interleaving to get wrong.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    write_frame_with(w, frame, false).await
}

/// Write one masked frame (the client→server direction) and flush it.
///
/// A fresh unpredictable mask key per frame is what RFC 6455 §5.3 asks for; it
/// stops the payload bytes from being guessable by an intermediary that can
/// predict them.
pub async fn write_frame_masked<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    write_frame_with(w, frame, true).await
}

/// Write one frame, optionally masked.
pub async fn write_frame_with<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &Frame,
    mask: bool,
) -> io::Result<()> {
    if frame.payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to send a {} byte frame (cap is {MAX_FRAME_BYTES})",
                frame.payload.len()
            ),
        ));
    }
    if frame.opcode.is_control() && (!frame.fin || frame.payload.len() > 125) {
        return Err(protocol(
            "a control frame must be final and carry at most 125 bytes",
        ));
    }

    let mut header = [0u8; 14];
    header[0] = if frame.fin { 0x80 } else { 0 } | frame.opcode.as_u8();
    let mask_bit = if mask { 0x80u8 } else { 0 };
    let payload_len = frame.payload.len();
    let mut header_len = 2;
    if payload_len < 126 {
        header[1] = mask_bit | payload_len as u8;
    } else if payload_len <= usize::from(u16::MAX) {
        header[1] = mask_bit | 126;
        header[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        header_len = 4;
    } else {
        header[1] = mask_bit | 127;
        header[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
        header_len = 10;
    }

    if mask {
        let mut key = [0u8; 4];
        getrandom::fill(&mut key)
            .map_err(|e| io::Error::other(format!("CSPRNG unavailable: {e}")))?;
        header[header_len..header_len + 4].copy_from_slice(&key);
        header_len += 4;
        w.write_all(&header[..header_len]).await?;
        // `write_frame` takes `&Frame`, so the masked copy is unavoidable here;
        // a caller that owns the payload could mask in place with `write_frame_with`
        // by building the frame itself.
        let mut payload = frame.payload.clone();
        apply_mask(&mut payload, key);
        w.write_all(&payload).await?;
    } else {
        w.write_all(&header[..header_len]).await?;
        w.write_all(&frame.payload).await?;
    }
    w.flush().await?;
    Ok(())
}

/// A buffered, cancel-safe frame/message reader.
///
/// Reads are buffered in `buf`, so dropping a `next_*` future mid-frame keeps the
/// connection in sync. That property is what lets the relay watch both
/// directions from one `tokio::select!` loop instead of spawning a task per
/// direction.
pub struct FrameReader<R> {
    io: R,
    buf: BytesMut,
    mask: Mask,
    max_frame: usize,
    max_message: usize,
    /// Opcode and payload of the message being reassembled, if any.
    fragment: Option<(OpCode, Vec<u8>)>,
}

impl<R> FrameReader<R> {
    /// Build a reader with an explicit masking policy and the default caps.
    pub fn new(io: R, mask: Mask) -> Self {
        Self::with_limits(io, mask, MAX_FRAME_BYTES, MAX_MESSAGE_BYTES)
    }

    /// We are the *server* end: the peer is a client, so masked frames are
    /// required (and their payload is always unmasked before returning).
    pub fn server_side(io: R) -> Self {
        Self::new(io, Mask::Required)
    }

    /// We are the *client* end: the peer is a server, so masked frames are a
    /// protocol violation.
    pub fn client_side(io: R) -> Self {
        Self::new(io, Mask::Forbidden)
    }

    /// Build a reader with explicit caps (used by tests).
    pub fn with_limits(io: R, mask: Mask, max_frame: usize, max_message: usize) -> Self {
        Self {
            io,
            buf: BytesMut::with_capacity(READ_CHUNK),
            mask,
            max_frame,
            max_message,
            fragment: None,
        }
    }

    /// Recover the underlying stream (any buffered bytes are dropped with it).
    pub fn into_inner(self) -> R {
        self.io
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Push bytes that were already read off the socket back in front of the
    /// buffer. The upstream handshake reader uses this when a single read
    /// returns headers *and* the first frames.
    pub fn prepend(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut merged = BytesMut::with_capacity(bytes.len() + self.buf.len());
        merged.extend_from_slice(bytes);
        merged.extend_from_slice(&self.buf);
        self.buf = merged;
    }

    /// Read the next frame off the wire (control frames included).
    pub async fn next_frame(&mut self) -> io::Result<Frame> {
        self.next_wire_frame().await?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed the connection before sending a frame",
            )
        })
    }

    /// Read the next *message*: complete text/binary frames come back whole, and
    /// control frames (close/ping/pong) are returned as they arrive, even
    /// between the fragments of a message.
    ///
    /// `Ok(None)` means the peer closed the connection cleanly between messages.
    pub async fn next_message(&mut self) -> io::Result<Option<Frame>> {
        loop {
            let Some(frame) = self.next_wire_frame().await? else {
                if self.fragment.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed the connection in the middle of a fragmented message",
                    ));
                }
                return Ok(None);
            };

            // Control frames are never fragments and may interleave a fragmented
            // message, so they are delivered immediately; the reassembly state is
            // untouched.
            if frame.opcode.is_control() {
                return Ok(Some(frame));
            }

            match frame.opcode {
                OpCode::Continuation => {
                    let Some((opcode, mut data)) = self.fragment.take() else {
                        return Err(protocol(
                            "continuation frame without a message to continue (RFC 6455 §5.4)",
                        ));
                    };
                    if data.len() + frame.payload.len() > self.max_message {
                        return Err(too_large(
                            data.len() + frame.payload.len(),
                            self.max_message,
                            "message",
                        ));
                    }
                    data.extend_from_slice(&frame.payload);
                    if frame.fin {
                        validate_text(opcode, &data)?;
                        return Ok(Some(Frame {
                            fin: true,
                            opcode,
                            payload: data,
                        }));
                    }
                    self.fragment = Some((opcode, data));
                }
                OpCode::Text | OpCode::Binary => {
                    if self.fragment.is_some() {
                        return Err(protocol(
                            "a new data frame started while a message was still fragmented \
                             (RFC 6455 §5.4)",
                        ));
                    }
                    if frame.fin {
                        validate_text(frame.opcode, &frame.payload)?;
                        return Ok(Some(frame));
                    }
                    if frame.payload.len() > self.max_message {
                        return Err(too_large(frame.payload.len(), self.max_message, "message"));
                    }
                    self.fragment = Some((frame.opcode, frame.payload));
                }
                // `is_control()` above already handled every other opcode.
                OpCode::Close | OpCode::Ping | OpCode::Pong => {}
            }
        }
    }

    /// One wire frame, or `None` on a clean end of stream between frames.
    async fn next_wire_frame(&mut self) -> io::Result<Option<Frame>> {
        loop {
            if let Some(frame) = parse_frame(&mut self.buf, self.mask, self.max_frame)? {
                return Ok(Some(frame));
            }
            if !self.fill().await? {
                return Ok(None);
            }
        }
    }

    /// Read more bytes into the buffer.
    ///
    /// `Ok(false)` is a *clean* end of stream (the peer closed between frames);
    /// EOF in the middle of a frame is an error, because silently truncating a
    /// frame would hand the peer a partial message as if it were complete.
    async fn fill(&mut self) -> io::Result<bool> {
        // BytesMut's `BufMut` impl grows 64 bytes at a time; reserving a read
        // chunk keeps a 1 MiB frame from costing thousands of reallocations.
        self.buf.reserve(READ_CHUNK);
        loop {
            match self.io.read_buf(&mut self.buf).await {
                Ok(0) => {
                    if self.buf.is_empty() {
                        return Ok(false);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed in the middle of a frame",
                    ));
                }
                Ok(_) => return Ok(true),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Parse one frame out of `buf`, consuming it only when it is complete.
///
/// `Ok(None)` means "not enough bytes yet" — the caller reads more. Any other
/// outcome either consumes one frame or fails the connection.
fn parse_frame(buf: &mut BytesMut, mask: Mask, max_frame: usize) -> io::Result<Option<Frame>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    if b0 & 0x70 != 0 {
        return Err(protocol(
            "reserved header bits are set but no extension was negotiated",
        ));
    }
    let opcode = match OpCode::from_u8(b0 & 0x0f) {
        Some(op) => op,
        None => {
            return Err(protocol(format!("unknown opcode 0x{:02x}", b0 & 0x0f)));
        }
    };
    let masked = b1 & 0x80 != 0;
    let len7 = (b1 & 0x7f) as usize;

    let mut offset = 2;
    let payload_len = match len7 {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            offset = 4;
            usize::from(u16::from_be_bytes([buf[2], buf[3]]))
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            offset = 10;
            let raw = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            if raw & (1 << 63) != 0 {
                return Err(protocol(
                    "64-bit payload length has the most significant bit set",
                ));
            }
            match usize::try_from(raw) {
                Ok(v) => v,
                Err(_) => {
                    return Err(too_large_usize(raw, max_frame));
                }
            }
        }
        n => n,
    };

    if opcode.is_control() {
        if !fin {
            return Err(protocol("control frames must not be fragmented"));
        }
        if payload_len > 125 {
            return Err(protocol("control frame payload exceeds 125 bytes"));
        }
    }
    // Checked *before* waiting for (or allocating) the payload: a hostile peer
    // must not be able to ask for a giant buffer by announcing a length.
    if payload_len > max_frame {
        return Err(too_large(payload_len, max_frame, "frame"));
    }

    match mask {
        Mask::Required if !masked => {
            return Err(protocol("client frames must be masked (RFC 6455 §5.1)"));
        }
        Mask::Forbidden if masked => {
            return Err(protocol("server frames must not be masked (RFC 6455 §5.1)"));
        }
        _ => {}
    }

    let mask_len = if masked { 4 } else { 0 };
    let total = offset + mask_len + payload_len;
    if buf.len() < total {
        return Ok(None);
    }

    let start = offset + mask_len;
    let mut payload = buf[start..start + payload_len].to_vec();
    if masked {
        apply_mask(
            &mut payload,
            [
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ],
        );
    }
    buf.advance(total);
    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}

/// XOR the payload with the repeating 4-byte mask key.
fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[i & 3];
    }
}

/// Text messages must be valid UTF-8 once complete (RFC 6455 §5.6).
fn validate_text(opcode: OpCode, payload: &[u8]) -> io::Result<()> {
    if opcode == OpCode::Text && std::str::from_utf8(payload).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "text message is not valid UTF-8",
        ));
    }
    Ok(())
}

/// A protocol violation (RFC 6455 §7.1.7 "fail the WebSocket connection").
fn protocol(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// An oversized frame/message: still a protocol error, but a distinct message.
fn too_large(got: usize, cap: usize, what: &str) -> io::Error {
    protocol(format!("{what} of {got} bytes exceeds the {cap} byte cap"))
}

fn too_large_usize(got: u64, cap: usize) -> io::Error {
    protocol(format!("frame of {got} bytes exceeds the {cap} byte cap"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    async fn read_bytes(data: &[u8]) -> io::Result<Frame> {
        let mut cursor: &[u8] = data;
        read_frame(&mut cursor).await
    }

    /// Build a frame the way a client would: masked, with a known key.
    fn masked_wire_frame(fin: bool, opcode: OpCode, payload: &[u8], key: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if fin { 0x80 } else { 0 } | opcode.as_u8());
        if payload.len() < 126 {
            out.push(0x80 | payload.len() as u8);
        } else {
            out.push(0x80 | 126);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&key);
        let mut data = payload.to_vec();
        apply_mask(&mut data, key);
        out.extend_from_slice(&data);
        out
    }

    // ----- handshake -----

    #[test]
    fn sha1_matches_known_vectors() {
        // FIPS 180-1 / RFC 3174 examples.
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        // Longer than one block, so the multi-block path is covered too.
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // 120 bytes of 'a' exercises the branch where 0x80 and the length do not
        // both fit in the final block (a second block is hashed).
        assert_eq!(
            hex(&sha1(&[b'a'; 120])),
            "f34c1488385346a55709ba056ddd08280dd4c6d6"
        );
    }

    #[test]
    fn accept_key_matches_the_rfc_test_vector() {
        // RFC 6455 §1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        // A different key must not collide with it.
        assert_ne!(
            accept_key("AAAAAAAAAAAAAAAAAAAAAA=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn random_key_is_16_base64_bytes_and_unique() {
        let a = random_key().expect("CSPRNG");
        let b = random_key().expect("CSPRNG");
        assert_ne!(a, b);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(a.as_bytes())
            .expect("valid base64");
        assert_eq!(raw.len(), 16);
    }

    // ----- frame encoding -----

    #[tokio::test]
    async fn masking_round_trip() {
        let payload = b"hello realtime".to_vec();
        let frame = Frame::text("hello realtime");
        let mut wire = Vec::new();
        write_frame_masked(&mut wire, &frame).await.expect("write");
        // The mask bit must be set and the payload on the wire must not equal the
        // plaintext (with this key it never can, but the bit is the contract).
        assert_eq!(wire[1] & 0x80, 0x80, "client frames are masked");
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let got = reader.next_message().await.expect("read").expect("frame");
        assert_eq!(got.opcode, OpCode::Text);
        assert!(got.fin);
        assert_eq!(got.payload, payload);
    }

    #[tokio::test]
    async fn server_writes_are_unmasked() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &Frame::binary(vec![1, 2, 3, 4]))
            .await
            .expect("write");
        assert_eq!(wire[1] & 0x80, 0, "server frames are not masked");
        assert_eq!(&wire[2..], &[1, 2, 3, 4]);
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::client_side(&mut cursor);
        let got = reader.next_frame().await.expect("read");
        assert_eq!(got.opcode, OpCode::Binary);
        assert_eq!(got.payload, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn sixteen_bit_length_round_trip() {
        let payload = vec![0xABu8; 300];
        let mut wire = Vec::new();
        write_frame(&mut wire, &Frame::binary(payload.clone()))
            .await
            .expect("write");
        assert_eq!(wire[1], 126, "300 bytes uses the 16-bit form");
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 300);
        let mut cursor: &[u8] = &wire;
        let got = read_frame(&mut cursor).await.expect("read");
        assert_eq!(got.payload, payload);
    }

    #[tokio::test]
    async fn sixty_four_bit_length_round_trip() {
        let payload = vec![0x5Au8; 70_000];
        let mut wire = Vec::new();
        write_frame(&mut wire, &Frame::binary(payload.clone()))
            .await
            .expect("write");
        assert_eq!(wire[1], 127, "70k bytes uses the 64-bit form");
        let declared = u64::from_be_bytes(wire[2..10].try_into().expect("8 bytes"));
        assert_eq!(declared, 70_000);
        let mut cursor: &[u8] = &wire;
        let got = read_frame(&mut cursor).await.expect("read");
        assert_eq!(got.payload.len(), 70_000);
        assert_eq!(got.payload, payload);
    }

    #[tokio::test]
    async fn ping_and_pong_payloads_are_echoed() {
        let ping = Frame::ping(b"ka".to_vec());
        let mut wire = Vec::new();
        write_frame_masked(&mut wire, &ping).await.expect("write");
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let got = reader.next_message().await.expect("read").expect("frame");
        assert_eq!(got.opcode, OpCode::Ping);
        assert_eq!(got.payload, b"ka");
        // The answer is a pong with the same application payload.
        let mut reply = Vec::new();
        write_frame(&mut reply, &Frame::pong(got.payload.clone()))
            .await
            .expect("write");
        let mut cursor: &[u8] = &reply;
        let pong = read_frame(&mut cursor).await.expect("read");
        assert_eq!(pong.opcode, OpCode::Pong);
        assert_eq!(pong.payload, b"ka");
    }

    #[tokio::test]
    async fn close_frame_carries_code_and_reason() {
        let frame = Frame::close(1008, "policy violation");
        let mut wire = Vec::new();
        write_frame_masked(&mut wire, &frame).await.expect("write");
        let mut cursor: &[u8] = &wire;
        let got = read_frame(&mut cursor).await.expect("read");
        assert_eq!(got.opcode, OpCode::Close);
        assert_eq!(got.close_code(), Some(1008));
        assert_eq!(got.close_reason(), Some("policy violation"));
        // An empty close payload is legal and means "no code".
        let bare = Frame {
            fin: true,
            opcode: OpCode::Close,
            payload: Vec::new(),
        };
        assert_eq!(bare.close_code(), None);
        let mut wire = Vec::new();
        write_frame(&mut wire, &bare).await.expect("write");
        let mut cursor: &[u8] = &wire;
        let got = read_frame(&mut cursor).await.expect("read");
        assert_eq!(got.opcode, OpCode::Close);
        assert_eq!(got.close_code(), None);
    }

    #[test]
    fn close_reason_is_truncated_to_123_bytes_on_a_char_boundary() {
        let reason = "é".repeat(100); // 200 bytes of 2-byte chars
        let frame = Frame::close(1011, &reason);
        assert!(frame.payload.len() <= 125, "control frame cap");
        assert_eq!(frame.payload.len(), 2 + 122, "whole chars only");
        assert!(std::str::from_utf8(&frame.payload[2..]).is_ok());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocating_the_payload() {
        // Only the header arrives: the length is enough to fail the connection.
        let mut wire = Vec::new();
        wire.push(0x81); // FIN + text
        wire.push(0x80 | 127); // masked + 64-bit length
        let declared = (MAX_FRAME_BYTES as u64) + 1;
        wire.extend_from_slice(&declared.to_be_bytes());
        wire.extend_from_slice(&[0, 0, 0, 0]); // mask key
        let err = read_bytes(&wire).await.expect_err("must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn fragmented_message_is_reassembled() {
        let key = [1, 2, 3, 4];
        let mut wire = Vec::new();
        wire.extend_from_slice(&masked_wire_frame(false, OpCode::Text, b"Hel", key));
        wire.extend_from_slice(&masked_wire_frame(
            false,
            OpCode::Continuation,
            b"lo, ",
            key,
        ));
        wire.extend_from_slice(&masked_wire_frame(
            true,
            OpCode::Continuation,
            b"world",
            key,
        ));
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let message = reader.next_message().await.expect("read").expect("message");
        assert_eq!(message.opcode, OpCode::Text);
        assert!(message.fin, "a reassembled message is always FIN");
        assert_eq!(message.payload, b"Hello, world");
        // Everything was consumed; the next read is a clean EOF.
        assert!(reader.next_message().await.expect("eof").is_none());
    }

    #[tokio::test]
    async fn control_frame_may_interleave_a_fragmented_message() {
        let key = [9, 8, 7, 6];
        let mut wire = Vec::new();
        wire.extend_from_slice(&masked_wire_frame(false, OpCode::Text, b"a", key));
        wire.extend_from_slice(&masked_wire_frame(true, OpCode::Ping, b"p", key));
        wire.extend_from_slice(&masked_wire_frame(true, OpCode::Continuation, b"b", key));
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let ping = reader.next_message().await.expect("read").expect("ping");
        assert_eq!(ping.opcode, OpCode::Ping, "control frames are not buffered");
        let message = reader.next_message().await.expect("read").expect("message");
        assert_eq!(message.payload, b"ab");
    }

    #[tokio::test]
    async fn oversized_fragmented_message_is_rejected() {
        let mut wire = Vec::new();
        let reader_bytes = {
            // Two fragments that each fit the frame cap but together do not fit
            // the (deliberately tiny) message cap.
            let mut out = Vec::new();
            out.extend_from_slice(&masked_wire_frame(
                false,
                OpCode::Text,
                b"aaaa",
                [1, 1, 1, 1],
            ));
            out.extend_from_slice(&masked_wire_frame(
                true,
                OpCode::Continuation,
                b"bbbb",
                [1, 1, 1, 1],
            ));
            out
        };
        wire.extend_from_slice(&reader_bytes);
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::with_limits(&mut cursor, Mask::Required, 1024, 6);
        let err = reader
            .next_message()
            .await
            .expect_err("message cap must bite");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn masking_policy_is_enforced_in_both_directions() {
        // An unmasked frame from a peer that must mask (a client).
        let mut wire = Vec::new();
        write_frame(&mut wire, &Frame::text("nope"))
            .await
            .expect("write");
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let err = reader
            .next_frame()
            .await
            .expect_err("unmasked client frame");
        assert!(err.to_string().contains("must be masked"), "{err}");

        // A masked frame from a peer that must not mask (a server).
        let mut wire = Vec::new();
        write_frame_masked(&mut wire, &Frame::text("nope"))
            .await
            .expect("write");
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::client_side(&mut cursor);
        let err = reader.next_frame().await.expect_err("masked server frame");
        assert!(err.to_string().contains("must not be masked"), "{err}");
    }

    #[tokio::test]
    async fn fragmented_and_oversized_control_frames_are_rejected() {
        // A ping with FIN=0.
        let wire = masked_wire_frame(false, OpCode::Ping, b"p", [0, 0, 0, 0]);
        let err = read_bytes(&wire).await.expect_err("fragmented ping");
        assert!(err.to_string().contains("must not be fragmented"), "{err}");

        // A ping of 126 bytes.
        let wire = masked_wire_frame(true, OpCode::Ping, &[0u8; 126], [0, 0, 0, 0]);
        let err = read_bytes(&wire).await.expect_err("oversized ping");
        assert!(err.to_string().contains("125"), "{err}");
    }

    #[tokio::test]
    async fn continuation_without_a_start_is_a_protocol_error() {
        let wire = masked_wire_frame(true, OpCode::Continuation, b"x", [0, 0, 0, 0]);
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let err = reader
            .next_message()
            .await
            .expect_err("orphan continuation");
        assert!(err.to_string().contains("continuation"), "{err}");
    }

    #[tokio::test]
    async fn invalid_utf8_text_is_rejected() {
        let wire = masked_wire_frame(true, OpCode::Text, &[0xFF, 0xFE], [0, 0, 0, 0]);
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let err = reader.next_message().await.expect_err("invalid utf-8");
        assert!(err.to_string().contains("UTF-8"), "{err}");
        // The same bytes are fine as binary.
        let wire = masked_wire_frame(true, OpCode::Binary, &[0xFF, 0xFE], [0, 0, 0, 0]);
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        assert!(reader.next_message().await.expect("binary").is_some());
    }

    #[tokio::test]
    async fn reserved_bits_and_unknown_opcodes_are_rejected() {
        // RSV1 set.
        let mut wire = masked_wire_frame(true, OpCode::Text, b"x", [0; 4]);
        wire[0] |= 0x40;
        let err = read_bytes(&wire).await.expect_err("rsv bit");
        assert!(err.to_string().contains("reserved"), "{err}");

        // Opcode 0x3.
        let mut wire = masked_wire_frame(true, OpCode::Text, b"x", [0; 4]);
        wire[0] = (wire[0] & 0xF0) | 0x03;
        let err = read_bytes(&wire).await.expect_err("unknown opcode");
        assert!(err.to_string().contains("opcode"), "{err}");
    }

    #[tokio::test]
    async fn clean_eof_between_frames_and_truncation_are_distinguished() {
        let mut cursor: &[u8] = &[];
        let mut reader = FrameReader::server_side(&mut cursor);
        assert!(reader.next_message().await.expect("clean eof").is_none());

        // A truncated frame is an error, not an end of stream.
        let mut wire = masked_wire_frame(true, OpCode::Text, b"truncated", [0; 4]);
        wire.truncate(wire.len() - 2);
        let mut cursor: &[u8] = &wire;
        let mut reader = FrameReader::server_side(&mut cursor);
        let err = reader.next_message().await.expect_err("truncated");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn prepended_bytes_are_parsed_first() {
        // Simulates the upstream handshake read returning headers + first frame.
        let mut wire = Vec::new();
        write_frame(&mut wire, &Frame::text("first"))
            .await
            .expect("write");
        let mut cursor: &[u8] = &[];
        let mut reader = FrameReader::client_side(&mut cursor);
        reader.prepend(&wire);
        let got = reader.next_message().await.expect("read").expect("frame");
        assert_eq!(got.payload, b"first");
    }

    #[test]
    fn frame_helpers() {
        assert!(OpCode::Close.is_control());
        assert!(OpCode::Ping.is_control());
        assert!(OpCode::Pong.is_control());
        assert!(!OpCode::Text.is_control());
        for op in [
            OpCode::Continuation,
            OpCode::Text,
            OpCode::Binary,
            OpCode::Close,
            OpCode::Ping,
            OpCode::Pong,
        ] {
            assert_eq!(OpCode::from_u8(op.as_u8()), Some(op));
        }
        assert_eq!(OpCode::from_u8(3), None);
        assert_eq!(Frame::text("abc").len(), 3);
        assert!(Frame::binary(vec![]).is_empty());
    }
}
