//! Minimal RESP2 client — hand-written over [`tokio::net::TcpStream`].
//!
//! The gateway must build with `cargo --offline` against the crates already in
//! `Cargo.lock`, so a `redis`/`fred` dependency is not an option. Only a very
//! small slice of the protocol is needed, and RESP2 is simple enough to own:
//!
//! - one command writer (`*N` array of `$len` bulk strings),
//! - one reply parser (`+`, `-`, `:`, `$`, `*`, plus the `$-1` / `*-1` nils),
//! - a lazy pool of at most [`MAX_POOL_CONNS`] sockets with a per-command
//!   timeout, so a stuck Redis cannot pin gateway tasks.
//!
//! Transport is plain TCP (`redis://`); TLS is expected to be terminated by
//! stunnel/a sidecar, which is what the config documents.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, Semaphore};

/// Maximum sockets a pool opens to one Redis server (created lazily).
pub const MAX_POOL_CONNS: usize = 4;

/// Longest protocol line (status, error, header) accepted.
const MAX_LINE: usize = 64 * 1024;
/// Largest bulk string accepted (a rate-limiter value is a handful of bytes).
const MAX_BULK: usize = 8 * 1024 * 1024;
/// Largest array length accepted.
///
/// A per-frame cap alone is not a bound on memory (see [`MAX_REPLY_BYTES`]), so
/// this is deliberately far below the ~1M that RESP would allow: the only array
/// reply this client consumes is the token-bucket script's `{allowed,
/// retry_ms}`, and nothing in the gateway asks Redis for a wide result. 1024
/// leaves room for a diagnostic reply (e.g. a future `KEYS`-free probe) while
/// keeping one malicious header from costing a megabyte of `Vec` capacity.
const MAX_ARRAY: usize = 1024;
/// Nesting limit for arrays of arrays.
const MAX_DEPTH: usize = 8;
/// Total bytes a single reply may cost, across every element and every level.
///
/// Every field is bounded on its own (line, bulk, array count, depth), but a
/// peer that is hostile or buggy can stay inside each limit while blowing up
/// their product: `*1000000` of 8 MiB bulks is ~8 TB, and nesting multiplies
/// even tiny frames. The parser therefore charges a budget as it goes and
/// refuses the reply once the sum exceeds this cap. 32 MiB is far above any
/// legitimate reply here (a token bucket answers with two integers) and small
/// enough that a stuck reply cannot exhaust the gateway's memory.
const MAX_REPLY_BYTES: usize = 32 << 20;
/// Budget charged for each parsed node, on top of any payload bytes: this is
/// what one `Resp` value costs before its data is counted, and it is what makes
/// deeply nested arrays of empty frames pay for the tree they build.
const NODE_COST: usize = std::mem::size_of::<Resp>();

/// A failed Redis operation.
///
/// Variants are meaningful to the caller: [`RedisError::keeps_connection`]
/// decides whether a pooled socket can be reused or must be dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisError {
    /// The URL could not be parsed.
    Url(String),
    /// Connect/write/read failure — the socket state is unknown.
    Io(String),
    /// Bytes we cannot decode as RESP.
    Protocol(String),
    /// `-ERR …` (or `-WRONGPASS …`) reply. The socket is still in sync.
    Server(String),
    /// No complete reply within the configured timeout.
    Timeout(String),
}

impl RedisError {
    /// Whether the stream is still usable after this error.
    pub fn keeps_connection(&self) -> bool {
        matches!(self, Self::Server(_))
    }

    /// A failure that says "the peer/socket is gone", not "the server refused us".
    ///
    /// Used to decide whether replaying an idempotent command on a fresh
    /// connection is worthwhile: a reused socket whose peer restarted fails here,
    /// while `-WRONGPASS`/`-MOVED`/timeouts (a genuinely overloaded server) do not.
    pub fn is_transport(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Protocol(_))
    }
}

impl fmt::Display for RedisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(m) => write!(f, "redis url: {m}"),
            Self::Io(m) => write!(f, "redis io: {m}"),
            Self::Protocol(m) => write!(f, "redis protocol: {m}"),
            Self::Server(m) => write!(f, "redis error reply: {}", for_log(m)),
            Self::Timeout(m) => write!(f, "redis timeout: {m}"),
        }
    }
}

impl std::error::Error for RedisError {}

fn io_err(what: &str, e: std::io::Error) -> RedisError {
    RedisError::Io(format!("{what}: {e}"))
}

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------

/// `redis://[user:pass@]host:port[/db]` with credentials percent-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisUrl {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub db: u32,
}

impl RedisUrl {
    /// Parse a `redis://` URL. `db` defaults to 0 and the port to 6379.
    pub fn parse(raw: &str) -> Result<Self, RedisError> {
        let whole = raw.trim();
        let rest = whole
            .strip_prefix("redis://")
            .ok_or_else(|| RedisError::Url(format!("'{whole}' must start with redis://")))?;
        // `authority` runs to the first '/', the rest is the (optional) db index.
        let (authority, tail) = match rest.split_once('/') {
            Some((a, t)) => (a, t),
            None => (rest, ""),
        };
        // Trailing query/fragment (`?x=y`) is not part of the db index.
        let tail = tail.split(['?', '#']).next().unwrap_or("");
        if authority.is_empty() {
            return Err(RedisError::Url("missing host".into()));
        }

        // rsplit: passwords may legally contain '@' once percent-encoded, but a
        // stray one must not swallow the host.
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        if hostport.is_empty() {
            return Err(RedisError::Url("missing host".into()));
        }

        let (host, port) = split_host_port(hostport)?;
        if host.is_empty() {
            return Err(RedisError::Url("missing host".into()));
        }

        // `redis://:pass@h`, `redis://user:pass@h` and `redis://pass@h` are all
        // accepted by common clients; the last form has no username.
        let (username, password) = match userinfo {
            None => (None, None),
            Some(u) => match u.split_once(':') {
                Some((user, pass)) => (
                    non_empty(percent_decode(user)),
                    non_empty(percent_decode(pass)),
                ),
                None => (None, non_empty(percent_decode(u))),
            },
        };

        let db = if tail.is_empty() {
            0
        } else {
            tail.parse::<u32>()
                .map_err(|_| RedisError::Url(format!("'{tail}' is not a database index")))?
        };

        Ok(Self {
            host,
            port,
            username,
            password,
            db,
        })
    }

    /// Identity for the process-wide pool registry. The password is reduced to a
    /// digest so the secret never lives in a map key or a log line.
    fn identity(&self) -> String {
        let user = self.username.as_deref().unwrap_or("");
        let pass = self
            .password
            .as_deref()
            .map(|p| digest(p, IDENTITY_DIGEST_BYTES))
            .unwrap_or_default();
        format!("{}:{}:{}:{user}:{pass}", self.host, self.port, self.db)
    }

    /// Loggable form — never includes the password.
    pub fn redacted(&self) -> String {
        format!("redis://{}:{}/{}", self.host, self.port, self.db)
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

fn split_host_port(hostport: &str) -> Result<(String, u16), RedisError> {
    let port = |p: &str| -> Result<u16, RedisError> {
        p.parse::<u16>()
            .map_err(|_| RedisError::Url(format!("'{p}' is not a TCP port")))
    };
    if let Some(rest) = hostport.strip_prefix('[') {
        // Bracketed IPv6 literal.
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| RedisError::Url("unterminated '[ipv6]' host".into()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => port(p)?,
            None if tail.is_empty() => 6379,
            None => return Err(RedisError::Url(format!("unexpected '{tail}' after host"))),
        };
        return Ok((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), port(p)?)),
        None => Ok((hostport.to_string(), 6379)),
    }
}

/// Decode `%XX` escapes (credentials may contain reserved characters).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h as u8) << 4 | l as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Digest bytes kept in the pool-registry key: 128 bits, so two different
/// passwords cannot share a pool by collision, while the key stays short.
const IDENTITY_DIGEST_BYTES: usize = 16;

/// Hex SHA-256 of `s`, truncated to `bytes` digest bytes.
///
/// This is how a secret is *referred to* without being stored: the Redis
/// password in a pool identity, and a client's API key in its bucket name. The
/// hash is unsalted and deterministic on purpose — every instance must derive
/// the same name for the same key, across restarts — so the output is a name,
/// not a password substitute for anything but lookup.
pub fn digest(s: &str, bytes: usize) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(s.as_bytes());
    hex::encode(&d[..bytes.min(d.len())])
}

// ---------------------------------------------------------------------------
// RESP2 values
// ---------------------------------------------------------------------------

/// One RESP2 reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resp {
    /// `+OK`
    Simple(String),
    /// `-ERR …`
    Error(String),
    /// `:123`
    Integer(i64),
    /// `$3\r\nfoo`; `None` is the `$-1` nil bulk.
    Bulk(Option<Vec<u8>>),
    /// `*2\r\n…`; `None` is the `*-1` nil array.
    Array(Option<Vec<Resp>>),
}

impl Resp {
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Simple(s) | Self::Error(s) => Some(s),
            Self::Bulk(Some(b)) => std::str::from_utf8(b).ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Resp]> {
        match self {
            Self::Array(Some(items)) => Some(items),
            _ => None,
        }
    }

    /// Bulk bytes, regardless of whether they are valid UTF-8.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bulk(Some(b)) => Some(b),
            _ => None,
        }
    }

    /// Compact rendering for logs and error messages: the type tag and the
    /// size, never the payload.
    ///
    /// `{reply:?}` is wrong for anything that came off the wire: a reply can
    /// carry an 8 MiB bulk, and `Debug` would turn one unexpected reply into a
    /// ~32 MB log line (the `Debug` of a `Vec<u8>` is decimal ASCII), i.e. a
    /// memory spike and log flooding for whoever sent it. Everything here is a
    /// handful of bytes regardless of the reply, so a hostile or broken server
    /// cannot choose the size of what the gateway writes to its log.
    pub fn summary(&self) -> String {
        match self {
            Self::Simple(s) => format!("simple({})", s.len()),
            Self::Error(s) => format!("error({})", s.len()),
            // Bounded by construction, so the value itself is safe to print.
            Self::Integer(i) => format!("integer({i})"),
            Self::Bulk(Some(b)) => format!("bulk({})", b.len()),
            Self::Bulk(None) => "bulk(nil)".to_string(),
            Self::Array(Some(items)) => format!("array({})", items.len()),
            Self::Array(None) => "array(nil)".to_string(),
        }
    }
}

/// Longest server-supplied text kept when it is rendered for a log line. A
/// `-ERR …` reply can be 64 KiB, and it is only ever wanted as a hint.
const MAX_LOG_TEXT: usize = 200;

/// Shorten `s` to [`MAX_LOG_TEXT`] characters (at a UTF-8 boundary) for
/// logging, keeping a note of the original size when it was cut.
fn for_log(s: &str) -> std::borrow::Cow<'_, str> {
    if s.len() <= MAX_LOG_TEXT {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut end = MAX_LOG_TEXT;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}… ({} bytes)", &s[..end], s.len()))
}

/// Encode a command as a RESP array of bulk strings.
pub fn encode_command(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + args.iter().map(|a| a.len() + 16).sum::<usize>());
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Read one `\r\n`-terminated line (the terminator is stripped).
///
/// Two properties matter here, because the peer is a server that may be hostile
/// or simply broken:
///
/// * **the line is buffered at most [`MAX_LINE`] bytes.** `read_until` would
///   happily grow its `Vec` for a megabyte-long "line" and only then let us look
///   at the result, so a server that never sends `\n` could make the parser hold
///   an arbitrarily large buffer. Scanning with `fill_buf`/`consume` lets the cap
///   fire while the line is still arriving.
/// * **a line that ends at EOF without a `\n` is an error, not a short reply.**
///   `+O` followed by a closed socket is not `+OK`, and `:1` is not `:12`; the
///   truncated reply would otherwise be handed to the caller as a success.
async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<String, RedisError> {
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    loop {
        // The borrow of `r` from `fill_buf` must end before `consume`, hence the
        // block: `(terminated, consumed)` carries everything out of it.
        let (terminated, used) = {
            let available = r.fill_buf().await.map_err(|e| io_err("read", e))?;
            if available.is_empty() {
                return Err(RedisError::Io(if buf.is_empty() {
                    "connection closed by server".into()
                } else {
                    "connection closed in the middle of a protocol line".into()
                }));
            }
            match memchr::memchr(b'\n', available) {
                Some(i) => {
                    if buf.len() + i + 1 > MAX_LINE {
                        return Err(line_too_long());
                    }
                    buf.extend_from_slice(&available[..=i]);
                    (true, i + 1)
                }
                None => {
                    if buf.len() + available.len() > MAX_LINE {
                        return Err(line_too_long());
                    }
                    buf.extend_from_slice(available);
                    (false, available.len())
                }
            }
        };
        r.consume(used);
        if terminated {
            break;
        }
    }
    // Exactly one terminator is stripped: the `\n`, plus the `\r` that precedes
    // it. Anything else is content (a bare `\r` inside a status line is).
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| RedisError::Protocol("non-UTF-8 protocol line".into()))
}

fn line_too_long() -> RedisError {
    RedisError::Protocol(format!("line exceeds {MAX_LINE} bytes"))
}

/// Parse one reply. `$-1` / `*-1` become `Bulk(None)` / `Array(None)`.
///
/// Bounds are enforced at every level: the line, the bulk, the array count, the
/// nesting depth, and — through [`Budget`] — the reply as a whole.
async fn parse_reply<R: AsyncBufRead + Unpin>(r: &mut R, depth: usize) -> Result<Resp, RedisError> {
    let mut budget = Budget::new();
    parse_bounded(r, depth, &mut budget).await
}

/// Parse one complete reply out of a byte slice.
///
/// Thin wrapper over [`parse_reply`] for `tests/fuzz_parsers.rs`: the caps, the
/// [`Budget`] and the error types are the ones the pool sees, so a hostile reply
/// behaves here exactly as it does on a socket.
#[doc(hidden)]
pub async fn reply_from_slice(bytes: &[u8]) -> Result<Resp, RedisError> {
    let mut r = tokio::io::BufReader::new(bytes);
    parse_reply(&mut r, 0).await
}

/// One reply within a shared byte budget.
async fn parse_bounded<R: AsyncBufRead + Unpin>(
    r: &mut R,
    depth: usize,
    budget: &mut Budget,
) -> Result<Resp, RedisError> {
    if depth > MAX_DEPTH {
        return Err(RedisError::Protocol("arrays nested too deeply".into()));
    }
    let line = read_line(r).await?;
    let (tag, rest) = match line.split_at_checked(1) {
        Some((tag, rest)) => (tag, rest),
        None => return Err(RedisError::Protocol("empty reply line".into())),
    };
    // Every node costs its own `Resp` value; payloads are charged on top.
    budget.charge(NODE_COST)?;
    match tag {
        "+" => {
            budget.charge(rest.len())?;
            Ok(Resp::Simple(rest.to_string()))
        }
        "-" => {
            budget.charge(rest.len())?;
            Ok(Resp::Error(rest.to_string()))
        }
        ":" => rest
            .parse::<i64>()
            .map(Resp::Integer)
            .map_err(|_| RedisError::Protocol(format!("invalid integer '{rest}'"))),
        "$" => {
            let len: i64 = rest
                .parse()
                .map_err(|_| RedisError::Protocol(format!("invalid bulk length '{rest}'")))?;
            if len == -1 {
                return Ok(Resp::Bulk(None));
            }
            let len = useful_len(len, MAX_BULK, "bulk")?;
            // Charged from the header, before the allocation it describes.
            budget.charge(len + 2)?;
            let mut data = vec![0u8; len + 2];
            r.read_exact(&mut data)
                .await
                .map_err(|e| io_err("read bulk", e))?;
            if &data[len..] != b"\r\n" {
                return Err(RedisError::Protocol("bulk not terminated by CRLF".into()));
            }
            data.truncate(len);
            Ok(Resp::Bulk(Some(data)))
        }
        "*" => {
            let n: i64 = rest
                .parse()
                .map_err(|_| RedisError::Protocol(format!("invalid array length '{rest}'")))?;
            if n == -1 {
                return Ok(Resp::Array(None));
            }
            let n = useful_len(n, MAX_ARRAY, "array")?;
            // The items vector is allocated up front at the *claimed* count, so
            // it is charged from the header as well.
            budget.charge(n.saturating_mul(NODE_COST))?;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(Box::pin(parse_bounded(r, depth + 1, budget)).await?);
            }
            Ok(Resp::Array(Some(items)))
        }
        other => Err(RedisError::Protocol(format!(
            "unknown reply type '{other}'"
        ))),
    }
}

/// The byte budget for one reply, threaded through the recursion.
///
/// Per-field caps bound each frame; this bounds the *sum*. It is charged before
/// every allocation, so a peer cannot make the parser hold more than
/// [`MAX_REPLY_BYTES`] however it slices the frames: one big bulk, a million
/// small ones, or a tree of nested arrays all pay for what they will occupy.
struct Budget {
    left: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            left: MAX_REPLY_BYTES,
        }
    }

    /// Charge `n` bytes, or refuse the reply once the budget is spent.
    fn charge(&mut self, n: usize) -> Result<(), RedisError> {
        match self.left.checked_sub(n) {
            Some(left) => {
                self.left = left;
                Ok(())
            }
            None => Err(RedisError::Protocol(format!(
                "reply exceeds {MAX_REPLY_BYTES} bytes"
            ))),
        }
    }
}

fn useful_len(len: i64, max: usize, what: &str) -> Result<usize, RedisError> {
    if len < 0 {
        return Err(RedisError::Protocol(format!(
            "negative {what} length {len}"
        )));
    }
    let len = len as usize;
    if len > max {
        return Err(RedisError::Protocol(format!(
            "{what} length {len} exceeds {max}"
        )));
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// One socket with its own read buffer.
struct Conn {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
}

impl Conn {
    async fn connect(url: &RedisUrl, timeout: Duration) -> Result<Self, RedisError> {
        let addr = url.authority();
        let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| RedisError::Timeout(format!("connect to {addr}")))?
            .map_err(|e| RedisError::Io(format!("connect to {addr}: {e}")))?;
        // Nagle would add up to ~40 ms to these tiny request/response pairs.
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!("redis {}: cannot set TCP_NODELAY: {e}", url.redacted());
        }
        let (read, write) = stream.into_split();
        let mut conn = Self {
            read: BufReader::new(read),
            write,
        };
        if let Some(pass) = &url.password {
            let mut args: Vec<&[u8]> = vec![b"AUTH"];
            if let Some(user) = &url.username {
                args.push(user.as_bytes());
            }
            args.push(pass.as_bytes());
            conn.call(timeout, &args).await?;
        }
        if url.db != 0 {
            let db = url.db.to_string();
            conn.call(timeout, &[b"SELECT", db.as_bytes()]).await?;
        }
        Ok(conn)
    }

    /// Send one command and read one reply. `-ERR` becomes [`RedisError::Server`].
    ///
    /// Write and read share one deadline: a server that accepts bytes but never
    /// answers must not hold a gateway task (or a pool slot) indefinitely.
    async fn call(&mut self, timeout: Duration, args: &[&[u8]]) -> Result<Resp, RedisError> {
        let frame = encode_command(args);
        let cmd = String::from_utf8_lossy(args.first().copied().unwrap_or(b"?")).into_owned();
        let reply = tokio::time::timeout(timeout, async {
            self.write
                .write_all(&frame)
                .await
                .map_err(|e| io_err("write", e))?;
            self.write.flush().await.map_err(|e| io_err("flush", e))?;
            parse_reply(&mut self.read, 0).await
        })
        .await
        .map_err(|_| RedisError::Timeout(format!("{cmd} after {timeout:?}")))??;
        match reply {
            Resp::Error(msg) => Err(RedisError::Server(msg)),
            other => Ok(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/// A lazy pool of up to [`MAX_POOL_CONNS`] connections to one Redis server.
///
/// - Sockets are opened on demand and kept for reuse;
/// - a command that fails with an IO/protocol error drops its socket (its state
///   is unknown), the next command transparently opens a fresh one;
/// - a `-ERR` reply keeps the socket, because the stream is still in sync;
/// - a semaphore caps concurrency at the pool size, and every command is
///   bounded by `timeout`.
pub struct RedisPool {
    url: RedisUrl,
    timeout: Duration,
    slots: Semaphore,
    idle: Mutex<Vec<Conn>>,
}

impl fmt::Debug for RedisPool {
    /// Sockets hold no printable state; the URL (redacted) and timeout do.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisPool")
            .field("server", &self.redacted())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl RedisPool {
    pub fn new(url: RedisUrl, timeout: Duration) -> Self {
        Self {
            url,
            timeout: if timeout.is_zero() {
                Duration::from_millis(50)
            } else {
                timeout
            },
            slots: Semaphore::new(MAX_POOL_CONNS),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Pool identity (host/port/db/credentials digest) for sharing decisions.
    /// Everything that changes how the pool behaves — the URL *and* the timeout.
    ///
    /// The timeout used to be missing, so `rebind` treated a limiter built with a
    /// new `[ratelimit] timeout_ms` as identical, kept the old pool, and silently
    /// ignored the setting until a restart (while a second, unused pool with the
    /// new timeout was left behind).
    pub fn identity(&self) -> String {
        format!("{}@{}ms", self.url.identity(), self.timeout.as_millis())
    }

    pub fn redacted(&self) -> String {
        self.url.redacted()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Run one command, borrowing a pooled connection for its duration.
    async fn call(&self, args: &[&[u8]]) -> Result<Resp, RedisError> {
        self.call_with(args, true).await
    }

    /// `replay_on_reconnect` decides what happens when a *reused* socket fails at
    /// the IO level (a peer that restarted or failed over while the socket sat
    /// idle).
    ///
    /// Replaying is only safe for a command that does not mutate state. The
    /// token-bucket `EVAL` does: if Redis executed the script and the socket died
    /// before the reply arrived, a replay consumes a **second** token, so after any
    /// restart the shared bucket drained at up to 2× `rpm` and a client running at
    /// exactly `rpm` saw spurious 429s. It therefore passes `false`: the caller
    /// gets the transport error, and the limiter's own policy decides (`fail_open`,
    /// or a 429 with `Retry-After` — the client's retry is the natural replay unit).
    async fn call_with(
        &self,
        args: &[&[u8]],
        replay_on_reconnect: bool,
    ) -> Result<Resp, RedisError> {
        // Held for the whole command: it is this call's slot in the pool.
        let _permit = match tokio::time::timeout(self.timeout, self.slots.acquire()).await {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(RedisError::Protocol("pool closed".into())),
            Err(_) => {
                return Err(RedisError::Timeout(format!(
                    "no free connection within {:?}",
                    self.timeout
                )));
            }
        };
        // Holding the idle lock across `connect` would serialize every new
        // connection (and worse, across an await); pop and release instead.
        let pooled = self.idle.lock().await.pop();
        let reuse = pooled.is_some();
        let mut conn = match pooled {
            Some(c) => c,
            None => Conn::connect(&self.url, self.timeout).await?,
        };
        let outcome = conn.call(self.timeout, args).await;
        match outcome {
            Ok(reply) => {
                self.release(conn).await;
                Ok(reply)
            }
            Err(e) if e.keeps_connection() => {
                self.release(conn).await;
                Err(e)
            }
            // A *reused* socket that fails at the IO level is almost always a peer
            // that restarted or failed over while the socket sat idle: it is not
            // evidence that Redis is unavailable. For a read-only command,
            // reconnect once and replay it. Without this, the first requests after
            // a Redis restart got a spurious 429 (`fail_open = false`) even though
            // the server was healthy again.
            //
            // A state-mutating command is never replayed (see `call_with`).
            Err(e) if replay_on_reconnect && reuse && e.is_transport() => {
                drop(conn);
                let mut fresh = Conn::connect(&self.url, self.timeout).await?;
                let retry = fresh.call(self.timeout, args).await;
                match retry {
                    Ok(reply) => {
                        self.release(fresh).await;
                        Ok(reply)
                    }
                    Err(e) if e.keeps_connection() => {
                        self.release(fresh).await;
                        Err(e)
                    }
                    Err(e) => Err(e),
                }
            }
            // Unknown socket state: drop the connection (closing the socket).
            Err(e) => Err(e),
        }
    }

    async fn release(&self, conn: Conn) {
        let mut idle = self.idle.lock().await;
        if idle.len() < MAX_POOL_CONNS {
            idle.push(conn);
        }
    }

    pub async fn ping(&self) -> Result<(), RedisError> {
        self.call(&[b"PING"]).await.map(|_| ())
    }

    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, RedisError> {
        match self.call(&[b"GET", key.as_bytes()]).await? {
            Resp::Bulk(b) => Ok(b),
            other => Err(unexpected("GET", &other)),
        }
    }

    /// `SET key value EX seconds`.
    pub async fn set_ex(&self, key: &str, value: &[u8], secs: u64) -> Result<(), RedisError> {
        let secs = secs.to_string();
        self.call(&[b"SET", key.as_bytes(), value, b"EX", secs.as_bytes()])
            .await
            .map(|_| ())
    }

    pub async fn incr(&self, key: &str) -> Result<i64, RedisError> {
        match self.call(&[b"INCR", key.as_bytes()]).await? {
            Resp::Integer(i) => Ok(i),
            other => Err(unexpected("INCR", &other)),
        }
    }

    pub async fn expire(&self, key: &str, secs: u64) -> Result<bool, RedisError> {
        let secs = secs.to_string();
        match self
            .call(&[b"EXPIRE", key.as_bytes(), secs.as_bytes()])
            .await?
        {
            Resp::Integer(i) => Ok(i == 1),
            other => Err(unexpected("EXPIRE", &other)),
        }
    }

    /// Remaining TTL in seconds (`-1` = no expiry, `-2` = missing key).
    pub async fn ttl(&self, key: &str) -> Result<i64, RedisError> {
        match self.call(&[b"TTL", key.as_bytes()]).await? {
            Resp::Integer(i) => Ok(i),
            other => Err(unexpected("TTL", &other)),
        }
    }

    pub async fn del(&self, keys: &[&str]) -> Result<i64, RedisError> {
        let mut args: Vec<&[u8]> = Vec::with_capacity(keys.len() + 1);
        args.push(b"DEL");
        args.extend(keys.iter().map(|k| k.as_bytes()));
        match self.call(&args).await? {
            Resp::Integer(i) => Ok(i),
            other => Err(unexpected("DEL", &other)),
        }
    }

    /// `EVAL script numkeys key… arg…` — the script travels as a bulk string.
    pub async fn eval(
        &self,
        script: &str,
        keys: &[&str],
        args: &[&[u8]],
    ) -> Result<Resp, RedisError> {
        let numkeys = keys.len().to_string();
        let mut frame: Vec<&[u8]> = Vec::with_capacity(3 + keys.len() + args.len());
        frame.push(b"EVAL");
        frame.push(script.as_bytes());
        frame.push(numkeys.as_bytes());
        frame.extend(keys.iter().map(|k| k.as_bytes()));
        frame.extend_from_slice(args);
        // Not replayable: a replay of a read-modify-write charges the bucket twice.
        self.call_with(&frame, false).await
    }
}

/// "Wrong reply type for this command" — with a bounded rendering of the reply,
/// never its payload (see [`Resp::summary`]).
fn unexpected(cmd: &str, got: &Resp) -> RedisError {
    RedisError::Protocol(format!("{cmd}: unexpected reply {}", got.summary()))
}

/// One pool per (server, credentials, timeout) for the whole process: N client
/// keys must not mean N×4 sockets. Entries are weak, so a pool dies with its
/// last limiter.
pub fn shared_pool(url: &RedisUrl, timeout: Duration) -> Arc<RedisPool> {
    static REGISTRY: OnceLock<StdMutex<HashMap<String, Weak<RedisPool>>>> = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let timeout = if timeout.is_zero() {
        Duration::from_millis(50)
    } else {
        timeout
    };
    let id = format!("{}|{}", url.identity(), timeout.as_millis());
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pool) = guard.get(&id).and_then(Weak::upgrade) {
        return pool;
    }
    let pool = Arc::new(RedisPool::new(url.clone(), timeout));
    // Bound the registry: drop entries whose last limiter is gone.
    if guard.len() > 64 {
        guard.retain(|_, w| w.strong_count() > 0);
    }
    guard.insert(id, Arc::downgrade(&pool));
    pool
}
// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

/// An in-process Redis that speaks just enough RESP2 for these tests.
///
/// It is *not* a Redis emulator: it serves `PING`, `AUTH`, `SELECT`, `GET`,
/// `SET … EX`, `INCR`, `EXPIRE`, `TTL`, `DEL` and `EVAL`, and for `EVAL` it
/// reproduces the token-bucket semantics of
/// [`crate::distributed::limiter::TOKEN_BUCKET_LUA`] (recognised by the
/// `-- anyhop:token-bucket` marker) rather than interpreting Lua.
///
/// It also provides the failure modes the pool must survive: closing a
/// connection instead of replying, replying slowly, and `-ERR` replies.
#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[derive(Default)]
    struct State {
        /// key -> (value, expiry)
        values: HashMap<String, (String, Option<Instant>)>,
        /// Every command received, in order (command name first).
        log: Vec<Vec<String>>,
    }

    #[derive(Clone)]
    struct Ctx {
        state: Arc<StdMutex<State>>,
        conns: Arc<AtomicUsize>,
        drop_after: Arc<AtomicUsize>,
        delay: Arc<StdMutex<Duration>>,
        password: Option<String>,
    }

    /// Handle of a running fake server. Dropping it leaves the socket open for
    /// the rest of the test binary; ports are ephemeral, so that is harmless.
    pub struct FakeRedis {
        addr: SocketAddr,
        ctx: Ctx,
    }

    impl FakeRedis {
        pub async fn start() -> Self {
            Self::start_auth(None).await
        }

        /// A server that requires `AUTH <password>`.
        pub async fn start_with_password(pw: &str) -> Self {
            Self::start_auth(Some(pw.to_string())).await
        }

        async fn start_auth(password: Option<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake redis");
            let addr = listener.local_addr().expect("fake redis addr");
            let ctx = Ctx {
                state: Arc::new(StdMutex::new(State::default())),
                conns: Arc::new(AtomicUsize::new(0)),
                drop_after: Arc::new(AtomicUsize::new(0)),
                delay: Arc::new(StdMutex::new(Duration::ZERO)),
                password,
            };
            let shared = ctx.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    shared.conns.fetch_add(1, AtomicOrdering::SeqCst);
                    let per_conn = shared.clone();
                    tokio::spawn(async move { serve(stream, per_conn).await });
                }
            });
            Self { addr, ctx }
        }

        pub fn port(&self) -> u16 {
            self.addr.port()
        }

        pub fn url(&self) -> String {
            self.url_full(0, None)
        }

        pub fn url_full(&self, db: u32, pw: Option<&str>) -> String {
            match pw {
                Some(p) => format!("redis://:{p}@127.0.0.1:{}/{db}", self.port()),
                None => format!("redis://127.0.0.1:{}/{db}", self.port()),
            }
        }

        /// Every command received so far, in order.
        pub fn commands(&self) -> Vec<Vec<String>> {
            lock(&self.ctx.state).log.clone()
        }

        /// Commands whose name (case-insensitive) matches.
        pub fn commands_named(&self, name: &str) -> Vec<Vec<String>> {
            self.commands()
                .into_iter()
                .filter(|c| c.first().is_some_and(|n| n.eq_ignore_ascii_case(name)))
                .collect()
        }

        pub fn connections(&self) -> usize {
            self.ctx.conns.load(AtomicOrdering::SeqCst)
        }

        /// Raw value stored at `key` (`None` = missing).
        pub fn value(&self, key: &str) -> Option<String> {
            lock(&self.ctx.state)
                .values
                .get(key)
                .map(|(v, _)| v.clone())
        }

        /// Remaining TTL of `key` in seconds, as the real server would report it.
        pub fn ttl(&self, key: &str) -> i64 {
            match lock(&self.ctx.state).values.get(key) {
                None => -2,
                Some((_, None)) => -1,
                Some((_, Some(at))) => {
                    at.saturating_duration_since(Instant::now()).as_secs() as i64
                }
            }
        }

        /// The next `n` commands get **no reply** and close the socket, which is
        /// how a real connection dies behind a proxy or a restart.
        pub fn drop_after(&self, n: usize) {
            self.ctx.drop_after.store(n, AtomicOrdering::SeqCst);
        }

        /// Delay every reply (for concurrency/timeout tests).
        pub fn set_delay(&self, d: Duration) {
            *lock(&self.ctx.delay) = d;
        }
    }

    fn lock<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn serve(stream: TcpStream, ctx: Ctx) {
        let (rd, mut wr) = stream.into_split();
        let mut rd = BufReader::new(rd);
        let mut authed = ctx.password.is_none();
        loop {
            // Client commands are arrays of bulk strings.
            let frame = match super::parse_reply(&mut rd, 0).await {
                Ok(f) => f,
                Err(_) => return, // client went away or sent garbage
            };
            let Resp::Array(Some(items)) = frame else {
                let _ = wr
                    .write_all(&resp_error("ERR expected an array of bulk strings"))
                    .await;
                return;
            };
            let mut args = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Resp::Bulk(Some(b)) => args.push(String::from_utf8_lossy(&b).into_owned()),
                    _ => return,
                }
            }
            lock(&ctx.state).log.push(args.clone());

            // "Connection died" mode: consume the command, send nothing, close.
            if ctx.drop_after.load(AtomicOrdering::SeqCst) > 0
                && ctx.drop_after.fetch_sub(1, AtomicOrdering::SeqCst) <= 1
            {
                return;
            }

            let delay = *lock(&ctx.delay);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            let reply = dispatch(&ctx, &args, &mut authed);
            if wr.write_all(&reply).await.is_err() {
                return;
            }
        }
    }

    fn dispatch(ctx: &Ctx, args: &[String], authed: &mut bool) -> Vec<u8> {
        let cmd = args
            .first()
            .map(|c| c.to_ascii_uppercase())
            .unwrap_or_default();
        if let Some(expected) = &ctx.password {
            if cmd == "AUTH" {
                let pass = args.last().cloned().unwrap_or_default();
                return if &pass == expected {
                    *authed = true;
                    resp_simple("OK")
                } else {
                    resp_error("WRONGPASS invalid username-password pair")
                };
            }
            if !*authed {
                return resp_error("NOAUTH Authentication required.");
            }
        } else if cmd == "AUTH" {
            *authed = true;
            return resp_simple("OK");
        }
        match cmd.as_str() {
            "PING" => match args.get(1) {
                Some(msg) => resp_bulk(msg),
                None => resp_simple("PONG"),
            },
            "SELECT" => resp_simple("OK"),
            "GET" => {
                let Some(key) = args.get(1) else {
                    return resp_error("ERR wrong number of arguments for 'get'");
                };
                // Test hook: keys starting with `boom:` answer with an error
                // reply, to prove `-ERR` does not cost a connection.
                if key.starts_with("boom:") {
                    return resp_error("ERR simulated failure");
                }
                match lock(&ctx.state).values.get(key).map(|(v, _)| v.clone()) {
                    Some(v) => resp_bulk(&v),
                    None => resp_nil(),
                }
            }
            "SET" => {
                let (Some(key), Some(val)) = (args.get(1), args.get(2)) else {
                    return resp_error("ERR wrong number of arguments for 'set'");
                };
                let expiry = match args.get(3).map(|s| s.to_ascii_uppercase()) {
                    Some(opt) if opt == "EX" => {
                        match args.get(4).and_then(|s| s.parse::<u64>().ok()) {
                            Some(secs) => Some(Instant::now() + Duration::from_secs(secs)),
                            None => return resp_error("ERR invalid expire time in 'set'"),
                        }
                    }
                    Some(opt) => return resp_error(&format!("ERR unsupported SET option '{opt}'")),
                    None => None,
                };
                lock(&ctx.state)
                    .values
                    .insert(key.clone(), (val.clone(), expiry));
                resp_simple("OK")
            }
            "INCR" => {
                let Some(key) = args.get(1) else {
                    return resp_error("ERR wrong number of arguments for 'incr'");
                };
                let mut st = lock(&ctx.state);
                let cur = st
                    .values
                    .get(key)
                    .and_then(|(v, _)| v.parse::<i64>().ok())
                    .unwrap_or(0);
                let next = cur + 1;
                st.values.insert(key.clone(), (next.to_string(), None));
                resp_int(next)
            }
            "EXPIRE" => {
                let (Some(key), Some(secs)) = (args.get(1), args.get(2)) else {
                    return resp_error("ERR wrong number of arguments for 'expire'");
                };
                let secs = secs.parse::<u64>().unwrap_or(0);
                let mut st = lock(&ctx.state);
                match st.values.get_mut(key) {
                    Some((_, at)) => {
                        *at = Some(Instant::now() + Duration::from_secs(secs));
                        resp_int(1)
                    }
                    None => resp_int(0),
                }
            }
            "TTL" => {
                let Some(key) = args.get(1) else {
                    return resp_error("ERR wrong number of arguments for 'ttl'");
                };
                let st = lock(&ctx.state);
                match st.values.get(key) {
                    None => resp_int(-2),
                    Some((_, None)) => resp_int(-1),
                    Some((_, Some(at))) => {
                        resp_int(at.saturating_duration_since(Instant::now()).as_secs() as i64)
                    }
                }
            }
            "DEL" => {
                let mut st = lock(&ctx.state);
                let mut n = 0;
                for key in &args[1..] {
                    if st.values.remove(key).is_some() {
                        n += 1;
                    }
                }
                resp_int(n)
            }
            "EVAL" => eval(ctx, args),
            other => resp_error(&format!("ERR unknown command '{other}'")),
        }
    }

    /// Token-bucket semantics of `TOKEN_BUCKET_LUA`, in Rust.
    ///
    /// Argument layout mirrors the script: `KEYS[1]`, then ARGV = capacity,
    /// rate_per_sec, now_ms, ttl_secs.
    fn eval(ctx: &Ctx, args: &[String]) -> Vec<u8> {
        if args.len() < 4 {
            return resp_error("ERR wrong number of arguments for 'eval'");
        }
        if !args[1].contains("-- anyhop:token-bucket") {
            return resp_error("ERR this test double only emulates the anyhop token-bucket script");
        }
        let numkeys: usize = args[2].parse().unwrap_or(0);
        if numkeys != 1 {
            return resp_error("ERR exactly one key");
        }
        let key = args[3].clone();
        let argv = &args[3 + numkeys..];
        if argv.len() < 4 {
            return resp_error("ERR wrong number of script arguments");
        }
        let parse = |v: &str, what: &str| -> Result<f64, Vec<u8>> {
            v.parse::<f64>()
                .map_err(|_| resp_error(&format!("ERR bad {what} '{v}'")))
        };
        let cap = match parse(&argv[0], "capacity") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let rate = match parse(&argv[1], "rate") {
            Ok(v) if v > 0.0 => v,
            Ok(_) => return resp_error("ERR rate must be positive"),
            Err(e) => return e,
        };
        let now = match parse(&argv[2], "now") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ttl: u64 = argv[3].parse().unwrap_or(60);

        let mut st = lock(&ctx.state);
        let raw = st.values.get(&key).map(|(v, _)| v.clone());
        let (mut tokens, last) = match raw.as_deref().and_then(parse_bucket) {
            Some((t, l)) => (t, l),
            None => (cap, now),
        };
        let elapsed = ((now - last) / 1000.0).max(0.0);
        tokens = (tokens + elapsed * rate).min(cap);
        let (allowed, retry) = if tokens >= 1.0 {
            tokens -= 1.0;
            (1i64, 0i64)
        } else {
            (0i64, (((1.0 - tokens) / rate) * 1000.0).ceil() as i64)
        };
        let value = format!("{tokens:.6}:{now:.0}");
        st.values.insert(
            key,
            (value, Some(Instant::now() + Duration::from_secs(ttl))),
        );
        resp_array_ints(&[allowed, retry.max(0)])
    }

    fn parse_bucket(raw: &str) -> Option<(f64, f64)> {
        let (tokens, last) = raw.split_once(':')?;
        Some((tokens.parse().ok()?, last.parse().ok()?))
    }

    fn resp_simple(s: &str) -> Vec<u8> {
        format!("+{s}\r\n").into_bytes()
    }

    fn resp_error(s: &str) -> Vec<u8> {
        format!("-{s}\r\n").into_bytes()
    }

    fn resp_bulk(s: &str) -> Vec<u8> {
        format!("${}\r\n{s}\r\n", s.len()).into_bytes()
    }

    fn resp_nil() -> Vec<u8> {
        b"$-1\r\n".to_vec()
    }

    fn resp_int(i: i64) -> Vec<u8> {
        format!(":{i}\r\n").into_bytes()
    }

    fn resp_array_ints(v: &[i64]) -> Vec<u8> {
        let mut out = format!("*{}\r\n", v.len()).into_bytes();
        for i in v {
            out.extend_from_slice(format!(":{i}\r\n").as_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::fake::FakeRedis;
    use super::*;

    /// Parse a single reply out of a byte slice.
    async fn parse(bytes: &[u8]) -> Result<Resp, RedisError> {
        parse_reply(&mut BufReader::new(bytes), 0).await
    }

    fn pool(fake: &FakeRedis, timeout_ms: u64) -> RedisPool {
        let url = RedisUrl::parse(&fake.url()).expect("url");
        RedisPool::new(url, Duration::from_millis(timeout_ms))
    }

    // --- URL parsing -------------------------------------------------------

    #[test]
    fn parses_url_without_credentials() {
        let u = RedisUrl::parse("redis://cache.internal:6380").expect("url");
        assert_eq!(u.host, "cache.internal");
        assert_eq!(u.port, 6380);
        assert_eq!(u.db, 0);
        assert_eq!(u.username, None);
        assert_eq!(u.password, None);
        assert_eq!(u.redacted(), "redis://cache.internal:6380/0");
    }

    #[test]
    fn parses_url_with_user_password_and_db() {
        let u = RedisUrl::parse("redis://gateway:hunter2@127.0.0.1:6379/3").expect("url");
        assert_eq!(u.host, "127.0.0.1");
        assert_eq!(u.port, 6379);
        assert_eq!(u.db, 3);
        assert_eq!(u.username.as_deref(), Some("gateway"));
        assert_eq!(u.password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn percent_decodes_credentials_and_defaults_port() {
        // `p@ss word` and a username that needs escaping.
        let u = RedisUrl::parse("redis://us%65r:p%40ss%20word@cache/7").expect("url");
        assert_eq!(u.username.as_deref(), Some("user"));
        assert_eq!(u.password.as_deref(), Some("p@ss word"));
        assert_eq!(u.port, 6379, "port defaults to 6379");
        assert_eq!(u.db, 7);
        // Password only (`redis://:pass@host`), and the older `redis://pass@host`.
        let u = RedisUrl::parse("redis://:s3cr3t@h:1").expect("url");
        assert_eq!((u.username, u.password.as_deref()), (None, Some("s3cr3t")));
        let u = RedisUrl::parse("redis://s3cr3t@h:1").expect("url");
        assert_eq!((u.username, u.password.as_deref()), (None, Some("s3cr3t")));
        // Bracketed IPv6.
        let u = RedisUrl::parse("redis://[::1]:6390/1").expect("url");
        assert_eq!((u.host.as_str(), u.port, u.db), ("::1", 6390, 1));
    }

    #[test]
    fn rejects_malformed_urls() {
        for bad in [
            "http://127.0.0.1:6379",
            "127.0.0.1:6379",
            "redis://",
            "redis://:6379",
            "redis://host:notaport",
            "redis://host:70000",
            "redis://host/notadb",
            "redis://[::1:6379",
        ] {
            assert!(RedisUrl::parse(bad).is_err(), "'{bad}' must be rejected");
        }
    }

    #[test]
    fn redacted_url_never_leaks_the_password() {
        let u = RedisUrl::parse("redis://gw:topsecret@h:6379/2").expect("url");
        assert!(!u.redacted().contains("topsecret"), "{}", u.redacted());
        assert!(u.redacted().contains("h:6379"));
    }

    #[test]
    fn pool_identity_is_a_wide_digest_of_the_password() {
        // The identity names a pool in a process-wide map, so it must separate
        // servers *and* credentials without ever holding the password. 16 digest
        // bytes (32 hex) — 8 was small enough that two passwords could plausibly
        // share a pool by accident, and that pool would send the *wrong*
        // credentials.
        let a = RedisUrl::parse("redis://gw:hunter2@h:6379/0").expect("url");
        let b = RedisUrl::parse("redis://gw:other@h:6379/0").expect("url");
        let anonymous = RedisUrl::parse("redis://h:6379/0").expect("url");
        assert!(!a.identity().contains("hunter2"), "{}", a.identity());
        assert_ne!(a.identity(), b.identity(), "another password, another pool");
        assert_ne!(a.identity(), anonymous.identity(), "credentials matter");
        assert_eq!(
            a.identity(),
            RedisUrl::parse("redis://gw:hunter2@h:6379/0")
                .expect("url")
                .identity(),
            "the name must be stable, not salted"
        );
        let identity = a.identity();
        let tag = identity.rsplit(':').next().expect("digest");
        assert_eq!(tag.len(), 32, "16 digest bytes as hex: {tag}");
    }

    // --- RESP parsing ------------------------------------------------------

    #[tokio::test]
    async fn parses_every_resp_reply_type() {
        assert_eq!(
            parse(b"+OK\r\n").await.expect("simple"),
            Resp::Simple("OK".into())
        );
        assert_eq!(
            parse(b"-ERR nope\r\n").await.expect("error"),
            Resp::Error("ERR nope".into())
        );
        assert_eq!(parse(b":123\r\n").await.expect("int"), Resp::Integer(123));
        assert_eq!(
            parse(b"$5\r\nhello\r\n").await.expect("bulk"),
            Resp::Bulk(Some(b"hello".to_vec()))
        );
        assert_eq!(parse(b"$-1\r\n").await.expect("nil bulk"), Resp::Bulk(None));
        assert_eq!(
            parse(b"*-1\r\n").await.expect("nil array"),
            Resp::Array(None)
        );
        assert_eq!(
            parse(b"*3\r\n:1\r\n$3\r\nfoo\r\n+OK\r\n")
                .await
                .expect("array"),
            Resp::Array(Some(vec![
                Resp::Integer(1),
                Resp::Bulk(Some(b"foo".to_vec())),
                Resp::Simple("OK".into()),
            ]))
        );
        assert_eq!(
            parse(b"*1\r\n*2\r\n:1\r\n:2\r\n").await.expect("nested"),
            Resp::Array(Some(vec![Resp::Array(Some(vec![
                Resp::Integer(1),
                Resp::Integer(2)
            ]))]))
        );
        // Empty bulk and empty array are legal.
        assert_eq!(
            parse(b"$0\r\n\r\n").await.expect("empty bulk"),
            Resp::Bulk(Some(Vec::new()))
        );
        assert_eq!(
            parse(b"*0\r\n").await.expect("empty array"),
            Resp::Array(Some(Vec::new()))
        );
    }

    #[tokio::test]
    async fn accessors_read_the_value_they_name() {
        let arr = parse(b"*2\r\n:7\r\n$2\r\nhi\r\n").await.expect("array");
        let items = arr.as_array().expect("array");
        assert_eq!(items[0].as_integer(), Some(7));
        assert_eq!(items[1].as_str(), Some("hi"));
        assert_eq!(items[1].as_bytes(), Some(&b"hi"[..]));
        assert_eq!(Resp::Bulk(None).as_str(), None);
    }

    #[tokio::test]
    async fn rejects_malformed_frames() {
        // Unknown type byte.
        assert!(matches!(
            parse(b"?what\r\n").await,
            Err(RedisError::Protocol(_))
        ));
        // Non-numeric lengths.
        assert!(matches!(
            parse(b"$abc\r\n").await,
            Err(RedisError::Protocol(_))
        ));
        assert!(matches!(
            parse(b"*abc\r\n").await,
            Err(RedisError::Protocol(_))
        ));
        // Negative bulk length that is not the -1 nil.
        assert!(matches!(
            parse(b"$-5\r\n").await,
            Err(RedisError::Protocol(_))
        ));
        // Bulk that claims more bytes than it carries.
        assert!(matches!(parse(b"$5\r\nab").await, Err(RedisError::Io(_))));
        // Bulk not terminated by CRLF.
        assert!(matches!(
            parse(b"$2\r\nabXX").await,
            Err(RedisError::Protocol(_))
        ));
        // Empty input: the peer closed mid-frame.
        assert!(matches!(parse(b"").await, Err(RedisError::Io(_))));
    }

    #[test]
    fn encodes_commands_as_resp_arrays() {
        assert_eq!(
            encode_command(&[b"SET", b"k", b"v"]),
            b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n".to_vec()
        );
    }

    // --- Pool behaviour ----------------------------------------------------

    #[tokio::test]
    async fn pool_reuses_one_connection() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 500);
        p.ping().await.expect("ping 1");
        p.ping().await.expect("ping 2");
        assert_eq!(p.get("missing").await.expect("get"), None);
        assert_eq!(fake.connections(), 1, "one socket must serve every command");
    }

    #[tokio::test]
    async fn basic_commands_round_trip() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 500);
        p.set_ex("k", b"v1", 90).await.expect("set");
        assert_eq!(p.get("k").await.expect("get"), Some(b"v1".to_vec()));
        let ttl = p.ttl("k").await.expect("ttl");
        assert!((1..=90).contains(&ttl), "ttl {ttl} must be the EX value");
        assert_eq!(p.ttl("nope").await.expect("ttl missing"), -2);
        assert_eq!(p.incr("n").await.expect("incr"), 1);
        assert_eq!(p.incr("n").await.expect("incr"), 2);
        assert!(p.expire("k", 30).await.expect("expire"));
        assert!(!p.expire("nope", 30).await.expect("expire missing"));
        assert_eq!(p.del(&["k", "n", "nope"]).await.expect("del"), 2);
        assert_eq!(p.get("k").await.expect("get deleted"), None);
    }

    /// A reused socket whose peer went away is repaired transparently: the command
    /// is replayed once on a fresh connection.
    ///
    /// This used to surface as an error to the caller. With `fail_open = false`
    /// that meant the first requests after a Redis restart were answered `429`
    /// although Redis was healthy again; with `fail_open = true` it silently
    /// over-granted.
    #[tokio::test]
    async fn pool_replays_a_command_on_a_dead_reused_socket() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 500);
        p.ping().await.expect("warm up");
        fake.drop_after(1);
        // The command still succeeds (one transparent reconnect + replay)…
        p.ping().await.expect("replayed on a fresh connection");
        assert!(
            fake.connections() >= 2,
            "the dead socket must be replaced ({} connections)",
            fake.connections()
        );
        // …and the classification the retry depends on: a transport failure is
        // retryable and drops the socket, a server reply is neither.
        assert!(!RedisError::Io("reset".into()).keeps_connection());
        assert!(RedisError::Io("reset".into()).is_transport());
        assert!(!RedisError::Protocol("junk".into()).keeps_connection());
        assert!(RedisError::Server("ERR bad".into()).keeps_connection());
        assert!(!RedisError::Server("ERR bad".into()).is_transport());
        assert!(!RedisError::Timeout("slow".into()).is_transport());
    }

    /// A state-mutating command must **not** be replayed on a dead reused socket.
    ///
    /// The token-bucket `EVAL` is a read-modify-write. If Redis executes it and the
    /// socket dies before the reply arrives, replaying charges the bucket a second
    /// time: after any restart/failover the shared budget drains at up to 2× `rpm`,
    /// so a client running at exactly `rpm` starts getting 429s. The caller must see
    /// the transport error and let the limiter's policy decide.
    #[tokio::test]
    async fn a_state_mutating_command_is_not_replayed_on_a_dead_socket() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 500);
        p.ping().await.expect("warm up");
        fake.drop_after(1);
        let err = p
            .eval("return 1", &["anyhop:rl:k"], &[b"1", b"1", b"1", b"1"])
            .await
            .expect_err("a non-idempotent command must surface the transport error");
        assert!(
            err.is_transport(),
            "the caller must be able to fall back to its own policy: {err:?}"
        );

        // A read-only command on the same dead socket *is* repaired, so the pool
        // still recovers rather than staying broken.
        p.ping().await.expect("the next command reconnects");
        assert!(fake.connections() >= 2, "the dead socket must be replaced");
    }

    #[tokio::test]
    async fn server_errors_keep_the_connection() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 500);
        p.ping().await.expect("warm up");
        let err = p.get("boom:1").await.expect_err("-ERR reply");
        assert!(matches!(err, RedisError::Server(_)), "{err:?}");
        assert!(err.keeps_connection(), "-ERR leaves the stream in sync");
        p.ping().await.expect("still usable");
        assert_eq!(fake.connections(), 1, "-ERR must not cost a socket");
    }

    #[tokio::test]
    async fn a_stalled_server_times_out_and_the_socket_is_dropped() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 60);
        fake.set_delay(Duration::from_millis(400));
        let err = p.ping().await.expect_err("must not hang");
        assert!(matches!(err, RedisError::Timeout(_)), "{err:?}");
        fake.set_delay(Duration::ZERO);
        p.ping().await.expect("recovers on a fresh socket");
    }

    #[tokio::test]
    async fn the_pool_never_exceeds_four_connections() {
        let fake = FakeRedis::start().await;
        fake.set_delay(Duration::from_millis(25));
        let p = Arc::new(pool(&fake, 5_000));
        let mut tasks = Vec::new();
        for _ in 0..12 {
            let p = p.clone();
            tasks.push(tokio::spawn(async move { p.ping().await }));
        }
        for t in tasks {
            t.await.expect("join").expect("concurrent ping");
        }
        let conns = fake.connections();
        assert!(conns > 1, "concurrent commands must use several sockets");
        assert!(conns <= MAX_POOL_CONNS, "opened {conns} sockets");
    }

    #[tokio::test]
    async fn auth_and_select_are_sent_before_the_first_command() {
        let fake = FakeRedis::start_with_password("s3cr3t").await;
        let url = RedisUrl::parse(&fake.url_full(3, Some("s3cr3t"))).expect("url");
        let p = RedisPool::new(url, Duration::from_millis(500));
        p.ping().await.expect("ping");
        let names: Vec<String> = fake
            .commands()
            .iter()
            .map(|c| c[0].to_ascii_uppercase())
            .collect();
        assert_eq!(names, vec!["AUTH", "SELECT", "PING"]);
        let commands = fake.commands();
        assert_eq!(commands[0][1], "s3cr3t", "password must be sent decoded");
        assert_eq!(commands[1][1], "3", "db index from the URL");
    }

    #[tokio::test]
    async fn a_wrong_password_fails_the_connection() {
        let fake = FakeRedis::start_with_password("right").await;
        let url = RedisUrl::parse(&fake.url_full(0, Some("wrong"))).expect("url");
        let p = RedisPool::new(url, Duration::from_millis(500));
        let err = p.ping().await.expect_err("AUTH must fail");
        assert!(matches!(err, RedisError::Server(_)), "{err:?}");
        assert_eq!(fake.connections(), 1);
        assert!(
            fake.commands_named("PING").is_empty(),
            "PING must not be sent"
        );
    }

    #[tokio::test]
    async fn eval_sends_the_script_numkeys_key_and_args() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 500);
        let reply = p
            .eval(
                crate::distributed::limiter::TOKEN_BUCKET_LUA,
                &["anyhop:rl:k:60:2"],
                &[b"2", b"1", b"0", b"60"],
            )
            .await
            .expect("eval");
        assert_eq!(reply.as_array().expect("array")[0].as_integer(), Some(1));
        let evals = fake.commands_named("EVAL");
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0][2], "1", "numkeys");
        assert_eq!(evals[0][3], "anyhop:rl:k:60:2");
        assert_eq!(&evals[0][4..], &["2", "1", "0", "60"]);
        assert!(evals[0][1].contains("-- anyhop:token-bucket"));
    }

    #[tokio::test]
    async fn an_unknown_command_is_an_error_reply() {
        let fake = FakeRedis::start().await;
        let p = pool(&fake, 500);
        let err = p.call(&[b"FROBNICATE"]).await.expect_err("unknown");
        assert!(matches!(err, RedisError::Server(ref m) if m.starts_with("ERR unknown command")));
    }

    #[tokio::test]
    async fn one_pool_is_shared_per_server_and_timeout() {
        let fake = FakeRedis::start().await;
        let url = RedisUrl::parse(&fake.url()).expect("url");
        let a = shared_pool(&url, Duration::from_millis(100));
        let b = shared_pool(&url, Duration::from_millis(100));
        assert!(Arc::ptr_eq(&a, &b), "same server must reuse one pool");
        let c = shared_pool(&url, Duration::from_millis(250));
        assert!(
            !Arc::ptr_eq(&a, &c),
            "a different timeout is a different pool"
        );
    }

    // --- hostile / broken servers ------------------------------------------
    //
    // The peer here is the *server*, so every one of these is something a
    // compromised or malfunctioning Redis (or a MITM in front of it) can send.
    // Each test asserts an `Err` — never a panic — and, where allocation is the
    // risk, that the parser refused from the header instead of buffering the
    // payload.

    #[tokio::test]
    async fn negative_lengths_other_than_the_nil_forms_are_rejected() {
        for bad in [
            "$-2\r\n",
            "$-3\r\n",
            "$-9223372036854775807\r\n",
            "*-2\r\n",
            "*-10\r\n",
        ] {
            let err = parse(bad.as_bytes())
                .await
                .expect_err("only -1 is a nil length");
            assert!(
                matches!(err, RedisError::Protocol(ref m) if m.contains("negative")),
                "{bad}: {err}"
            );
        }
        // The two legal nils still parse.
        assert_eq!(parse(b"$-1\r\n").await.expect("nil bulk"), Resp::Bulk(None));
        assert_eq!(
            parse(b"*-1\r\n").await.expect("nil array"),
            Resp::Array(None)
        );
    }

    #[tokio::test]
    async fn array_counts_over_the_cap_are_refused_from_the_header() {
        for bad in [
            "*2000000\r\n",
            "*1000000\r\n",
            "*1000000000\r\n",
            "*9223372036854775807\r\n",
        ] {
            let err = parse(bad.as_bytes()).await.expect_err("array cap");
            assert!(
                matches!(err, RedisError::Protocol(ref m) if m.contains("array length")),
                "{bad}: {err}"
            );
        }
        // The widest legal array is not preallocated beyond the cap either: the
        // first missing element is what fails, so a claimed MAX_ARRAY-element
        // reply costs one read, not a MAX_ARRAY-entry allocation.
        let wire = format!("*{MAX_ARRAY}\r\n");
        let err = parse(wire.as_bytes()).await.expect_err("elements missing");
        assert!(matches!(err, RedisError::Io(_)), "{err:?}");
        // One element over the cap is refused without reading any of them.
        let wire = format!("*{}\r\n", MAX_ARRAY + 1);
        let err = parse(wire.as_bytes()).await.expect_err("over the cap");
        assert!(
            matches!(err, RedisError::Protocol(ref m) if m.contains("exceeds")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_total_reply_budget_stops_nested_but_individually_legal_frames() {
        // Every frame here is legal on its own: arrays of exactly MAX_ARRAY
        // elements, depth 2, four-byte integers. Their *sum* is not: it is ~1M
        // nodes, which is the shape a hostile server uses to make the parser
        // hold gigabytes through frames that each pass the per-field caps.
        // Nothing about a token bucket needs it, so the byte budget refuses it.
        let mut wire = Vec::with_capacity(4 << 20);
        wire.extend_from_slice(format!("*{MAX_ARRAY}\r\n").as_bytes());
        for _ in 0..MAX_ARRAY {
            wire.extend_from_slice(format!("*{MAX_ARRAY}\r\n").as_bytes());
            for _ in 0..MAX_ARRAY {
                wire.extend_from_slice(b":0\r\n");
            }
        }
        let err = parse(&wire)
            .await
            .expect_err("the reply as a whole is over the budget");
        assert!(
            matches!(err, RedisError::Protocol(ref m) if m.contains("exceeds")),
            "{err}"
        );

        // The same shape, but a reply the gateway could plausibly get — the
        // token-bucket script's `{allowed, retry_ms}` — still parses, as does a
        // bulk sitting at the per-field cap.
        assert_eq!(
            parse(b"*2\r\n:1\r\n:0\r\n")
                .await
                .expect("token bucket reply"),
            Resp::Array(Some(vec![Resp::Integer(1), Resp::Integer(0)]))
        );
        let mut max_bulk = format!("${MAX_BULK}\r\n").into_bytes();
        max_bulk.resize(max_bulk.len() + MAX_BULK, b'x');
        max_bulk.extend_from_slice(b"\r\n");
        let got = parse(&max_bulk)
            .await
            .expect("MAX_BULK is under the budget");
        assert_eq!(got.as_bytes().map(<[u8]>::len), Some(MAX_BULK));
    }

    #[tokio::test]
    async fn a_huge_reply_is_summarised_in_a_short_message() {
        // Finding 3: `{reply:?}` on a reply with an 8 MiB sibling bulk is a
        // ~32 MB log line — one unexpected reply, a memory spike and a flooded
        // log. The message must describe the reply, not reproduce it.
        let huge = Resp::Array(Some(vec![
            Resp::Bulk(Some(vec![b'x'; MAX_BULK])),
            Resp::Integer(1),
        ]));
        let msg = unexpected("GET", &huge).to_string();
        assert!(
            msg.len() < 200,
            "the log line is {} bytes, not a summary: {msg}",
            msg.len()
        );
        assert!(msg.contains("array(2)"), "{msg}");
        assert!(!msg.contains("xxxx"), "the payload must not be printed");
        // Children are not walked: the summary is O(1) in the reply, so a
        // sibling bulk cannot choose even the length of the description.
        let bulk = Resp::Bulk(Some(vec![b'x'; MAX_BULK]));
        let msg = unexpected("GET", &bulk).to_string();
        assert!(msg.contains(&format!("bulk({MAX_BULK})")), "{msg}");
        assert!(msg.len() < 200, "{msg}");

        // A `-ERR …` reply may be 64 KiB of server-chosen text; it is truncated
        // the same way when it is formatted for a log.
        let msg = RedisError::Server("E".repeat(MAX_LINE)).to_string();
        assert!(msg.len() < 300, "server text is {} bytes: {msg}", msg.len());
        assert!(msg.contains(&format!("{} bytes", MAX_LINE)), "{msg}");
        // Short text is passed through untouched.
        assert_eq!(
            RedisError::Server("ERR nope".into()).to_string(),
            "redis error reply: ERR nope"
        );
    }

    #[test]
    fn every_reply_summarises_to_a_tag_and_a_length() {
        assert_eq!(Resp::Simple("OK".into()).summary(), "simple(2)");
        assert_eq!(Resp::Error("ERR no".into()).summary(), "error(6)");
        assert_eq!(Resp::Integer(-7).summary(), "integer(-7)");
        assert_eq!(Resp::Bulk(Some(vec![0; 4096])).summary(), "bulk(4096)");
        assert_eq!(Resp::Bulk(None).summary(), "bulk(nil)");
        assert_eq!(
            Resp::Array(Some(vec![Resp::Integer(1); 3])).summary(),
            "array(3)"
        );
        assert_eq!(Resp::Array(None).summary(), "array(nil)");
    }

    #[tokio::test]
    async fn the_pool_reports_a_huge_wrong_reply_in_a_few_bytes() {
        // The same guarantee through the real path: a server that answers GET
        // with a megabyte of payload must not make the gateway log it.
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut scratch = [0u8; 256];
            let _ = sock.read(&mut scratch).await;
            let payload = vec![b'y'; 1 << 20];
            let _ = sock
                .write_all(format!("*1\r\n${}\r\n", payload.len()).as_bytes())
                .await;
            let _ = sock.write_all(&payload).await;
            let _ = sock.write_all(b"\r\n").await;
            let _ = sock.flush().await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let url = RedisUrl::parse(&format!("redis://127.0.0.1:{}/0", addr.port())).expect("url");
        let p = RedisPool::new(url, Duration::from_millis(1_000));
        let err = p.get("k").await.expect_err("an array is not a GET reply");
        let msg = err.to_string();
        assert!(msg.len() < 200, "{} bytes: {msg}", msg.len());
        assert!(msg.contains("array(1)"), "{msg}");
        assert!(!msg.contains("yyy"), "the payload must not be printed");
        server.abort();
    }

    #[tokio::test]
    async fn nested_arrays_hit_a_depth_cap_instead_of_the_stack() {
        // MAX_DEPTH levels fit …
        let mut ok = Vec::new();
        for _ in 0..MAX_DEPTH {
            ok.extend_from_slice(b"*1\r\n");
        }
        ok.extend_from_slice(b":1\r\n");
        assert!(parse(&ok).await.is_ok(), "MAX_DEPTH levels must parse");

        // … one more does not, and neither does a thousand: the error comes from
        // the counter, so the recursion never grows past the cap.
        for levels in [MAX_DEPTH + 1, 1000] {
            let mut bad = Vec::new();
            for _ in 0..levels {
                bad.extend_from_slice(b"*1\r\n");
            }
            bad.extend_from_slice(b":1\r\n");
            let err = parse(&bad).await.expect_err("depth cap must bite");
            assert!(
                matches!(err, RedisError::Protocol(ref m) if m.contains("too deeply")),
                "{levels} levels: {err}"
            );
        }
    }

    #[tokio::test]
    async fn bulk_headers_over_the_cap_are_refused_before_allocating() {
        // Not even an integer.
        for bad in ["$99999999999999999999\r\n", "$ 5\r\n", "$0x10\r\n", "$\r\n"] {
            let err = parse(bad.as_bytes()).await.expect_err("bad bulk length");
            assert!(
                matches!(err, RedisError::Protocol(ref m) if m.contains("bulk length")),
                "{bad}: {err}"
            );
        }
        // An integer, but larger than MAX_BULK: refused from the header, so the
        // 8 MiB+2 allocation in the `$` branch never happens.
        for declared in [MAX_BULK + 1, i64::MAX as usize] {
            let header = format!("${declared}\r\n");
            let err = parse(header.as_bytes())
                .await
                .expect_err("over the bulk cap");
            assert!(
                matches!(err, RedisError::Protocol(ref m) if m.contains("exceeds")),
                "{declared}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_integers_are_rejected() {
        for bad in [
            ":abc\r\n",
            ":1.5\r\n",
            ":\r\n",
            ": 1\r\n",
            ":99999999999999999999\r\n",
            ":1e3\r\n",
        ] {
            let err = parse(bad.as_bytes()).await.expect_err("not an integer");
            assert!(
                matches!(err, RedisError::Protocol(ref m) if m.contains("integer")),
                "{bad}: {err}"
            );
        }
        assert_eq!(
            parse(b":-7\r\n").await.expect("negative"),
            Resp::Integer(-7)
        );
    }

    #[tokio::test]
    async fn a_line_that_ends_at_eof_is_not_a_reply() {
        // A truncated reply must fail the connection: `+O` is not `+OK`, and
        // handing the caller `Simple("O")` would make a broken socket look like a
        // successful command.
        for truncated in ["+OK", ":42", "-ERR no", "$3", "*2"] {
            let err = parse(truncated.as_bytes())
                .await
                .expect_err("no terminator, no reply");
            assert!(
                matches!(err, RedisError::Io(ref m) if m.contains("closed")),
                "{truncated:?}: {err}"
            );
        }
        // Garbage that is not even a reply type, and an empty line.
        for bad in ["?what\r\n", "\r\n", "\n", "hello world\r\n"] {
            let err = parse(bad.as_bytes()).await.expect_err("not RESP");
            assert!(matches!(err, RedisError::Protocol(_)), "{bad:?}: {err}");
        }
    }

    #[tokio::test]
    async fn a_very_long_line_is_refused_without_buffering_it() {
        // 1 MiB of `+aaa…` with no terminator. The error must come from the
        // first MAX_LINE bytes, so the rest of the stream stays unread: a server
        // cannot use one endless "line" to make the parser hold an unbounded
        // buffer for as long as the socket stays open.
        let mut wire = vec![b'+'];
        wire.resize(1024 * 1024, b'a');
        let mut cursor: &[u8] = &wire;
        let err = {
            let mut buffered = BufReader::new(&mut cursor);
            parse_reply(&mut buffered, 0)
                .await
                .expect_err("unterminated megabyte line")
        };
        assert!(
            matches!(err, RedisError::Protocol(ref m) if m.contains("line exceeds")),
            "{err}"
        );
        assert!(
            cursor.len() > wire.len() / 2,
            "only ~MAX_LINE bytes may be consumed, {} of {} were",
            wire.len() - cursor.len(),
            wire.len()
        );
    }

    /// An `AsyncRead` that hands out one byte per poll, the way a TCP connection
    /// that fragments a reply into tiny segments would.
    struct Trickle<'a> {
        data: &'a [u8],
    }

    impl tokio::io::AsyncRead for Trickle<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.data.is_empty() || buf.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            let (head, tail) = self.data.split_at(1);
            buf.put_slice(head);
            self.data = tail;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_reply_split_across_packets_still_parses() {
        // Every byte arrives in its own "packet": headers, bulk bodies and
        // nested arrays must all survive being fragmented at arbitrary points.
        for (wire, expected) in [
            (&b"$5\r\nhello\r\n"[..], Resp::Bulk(Some(b"hello".to_vec()))),
            (&b"+OK\r\n"[..], Resp::Simple("OK".into())),
            (
                &b"*2\r\n$3\r\nfoo\r\n:7\r\n"[..],
                Resp::Array(Some(vec![
                    Resp::Bulk(Some(b"foo".to_vec())),
                    Resp::Integer(7),
                ])),
            ),
            (&b"$-1\r\n"[..], Resp::Bulk(None)),
        ] {
            let mut reader = BufReader::new(Trickle { data: wire });
            let got = parse_reply(&mut reader, 0)
                .await
                .expect("a fragmented reply is still one reply");
            assert_eq!(got, expected, "{:?}", String::from_utf8_lossy(wire));
        }
    }

    #[tokio::test]
    async fn a_ten_megabyte_bulk_is_refused_by_the_pool() {
        // The question the pool has to answer: a server that promises a 10 MiB
        // value for a GET must not be able to make the gateway allocate it.
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut scratch = [0u8; 256];
            let _ = sock.read(&mut scratch).await;
            let _ = sock.write_all(b"$10485760\r\n").await;
            let _ = sock.write_all(&[b'x'; 64]).await;
            let _ = sock.flush().await;
            // Hold the socket open, so a parser that waited for the body would
            // time out instead of seeing a clean EOF.
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let url = RedisUrl::parse(&format!("redis://127.0.0.1:{}/0", addr.port())).expect("url");
        let p = RedisPool::new(url, Duration::from_millis(1_000));
        let err = p
            .get("k")
            .await
            .expect_err("a 10 MiB GET reply is over MAX_BULK");
        assert!(
            matches!(err, RedisError::Protocol(ref m) if m.contains("exceeds")),
            "{err:?}"
        );
        assert!(
            !err.keeps_connection(),
            "an oversized reply leaves the stream at an unknown offset"
        );
        server.abort();
    }

    #[tokio::test]
    async fn deterministic_garbage_never_panics() {
        // xorshift64 seeded with a constant: an unknown reply type followed by
        // random bytes. Always an error, and always one of the defined variants.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..500 {
            let mut wire = vec![b'?'];
            for _ in 0..(state as usize % 64) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                wire.push((state >> 32) as u8);
            }
            let err = parse(&wire).await.expect_err("unknown reply type");
            // Either the unknown type byte or an unterminated line: both are
            // defined errors, which is the whole point.
            assert!(
                matches!(err, RedisError::Protocol(_) | RedisError::Io(_)),
                "{err:?}"
            );
        }
    }
}
