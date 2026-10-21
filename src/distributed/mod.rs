//! Shared (multi-instance) client-key rate limiting.
//!
//! Two pieces, both written from scratch because this crate may only use crates
//! that are already in `Cargo.lock` (no `redis` client, no TLS client):
//!
//! - [`redis`] — a minimal RESP2 client over `tokio::net::TcpStream`, with a
//!   small lazy connection pool and per-command timeouts.
//! - [`limiter`] — [`SharedLimiter`], which picks between the existing
//!   per-process token bucket and an atomic Redis token bucket (one `EVAL`), so
//!   N gateway instances enforce a single budget per client key.
//!
//! With `[ratelimit] backend = "local"` nothing new is on the request path: the
//! limiter wraps the very same [`crate::ratelimit::KeyRateLimit`] used before.

pub mod limiter;
pub mod redis;

pub use limiter::{RedisLimiter, SharedLimiter, TOKEN_BUCKET_LUA};
pub use redis::{RedisError, RedisPool, RedisUrl, Resp};
