//! Client-key token bucket, either in this process or shared through Redis.
//!
//! The local backend is exactly [`crate::ratelimit::KeyRateLimit`] — the same
//! `Mutex<TokenBucket>` the gateway always used. The Redis backend runs the
//! bucket as one Lua script so the read-modify-write of `tokens`/`last` is
//! atomic inside Redis: two instances that share a server therefore share one
//! budget, with no `INCR`-based approximation to drift apart.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::RateLimitConfig;
use crate::distributed::redis::{self, RedisError, RedisPool, RedisUrl, Resp};
use crate::ratelimit::KeyRateLimit;

/// Warn at most this often while Redis is failing (per key).
const WARN_EVERY: Duration = Duration::from_secs(60);

/// Digest bytes in a bucket name: 128 bits, i.e. a collision needs ~2^64 keys.
/// Shorter would make the name prettier for no benefit; longer would only make
/// every `MONITOR` line noisier.
const CLIENT_KEY_DIGEST_BYTES: usize = 16;

/// Atomic token bucket. One `EVAL`, one round trip, exact across instances.
///
/// State is a single string `"<tokens>:<last_ms>"`: one `GET` + one `SET` inside
/// one script keeps the whole read-modify-write atomic, and the key carries both
/// numbers a token bucket needs. `INCR` (a counter with a separate `EXPIRE`)
/// cannot express a continuously refilling bucket, so it is deliberately not
/// used.
///
/// - `KEYS[1]` bucket key
/// - `ARGV[1]` capacity (`burst`, already defaulted to `rpm`)
/// - `ARGV[2]` refill rate per second (`rpm / 60`)
/// - `ARGV[3]` `now_ms` — the caller's clock, see [`RedisLimiter::try_acquire`]
/// - `ARGV[4]` TTL seconds, always ≥ 60
///
/// Returns `{allowed, retry_after_ms}`; `allowed` is 1/0.
///
/// The `-- anyhop:token-bucket` marker is what the test double keys on to
/// emulate these semantics instead of interpreting Lua.
pub const TOKEN_BUCKET_LUA: &str = r"-- anyhop:token-bucket: atomic token bucket, returns {allowed, retry_after_ms}
local cap = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local raw = redis.call('GET', KEYS[1])
local tokens = cap
local last = now
if raw then
  local sep = string.find(raw, ':')
  if sep then
    tokens = tonumber(string.sub(raw, 1, sep - 1)) or cap
    last = tonumber(string.sub(raw, sep + 1)) or now
  end
end
-- A caller clock that jumped backwards must not hand out extra credit, and one
-- that jumped forwards must not mint a full bucket out of thin air: clamp the
-- observation to [last, last + one full refill]. (The comment below used to claim
-- skew could not do this; a forward jump used to refill to `cap` instantly.)
local elapsed = (now - last) / 1000
if elapsed < 0 then elapsed = 0 end
if cap > 0 and elapsed * rate > cap then elapsed = cap / rate end
tokens = tokens + elapsed * rate
if tokens > cap then tokens = cap end
local allowed = 0
local retry_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  retry_ms = math.ceil((1 - tokens) / rate * 1000)
  if retry_ms < 1 then retry_ms = 1 end
end
redis.call('SET', KEYS[1], string.format('%.6f:%.0f', tokens, now), 'EX', ttl)
return {allowed, retry_ms}";

/// A client key's limiter: whichever backend `[ratelimit] backend` selects.
#[derive(Debug)]
pub enum SharedLimiter {
    /// Per-process bucket (single instance, and the fallback when Redis is
    /// unusable). Holds the same `Arc` as `ClientKeyRuntime::limiter`.
    Local(Arc<KeyRateLimit>),
    /// Token bucket shared by every instance behind the same Redis server.
    Redis(Arc<RedisLimiter>),
}

impl SharedLimiter {
    /// Build the limiter for one client key, or `None` when the key is
    /// unlimited (`rpm` unset/0) — in which case no bucket exists at all.
    ///
    /// A `redis` backend with an unusable URL falls back to `local` and says so:
    /// silently dropping the limit, or denying every request, would both be
    /// worse than limiting per process.
    pub fn for_key(
        key: &crate::config::ClientKeyConfig,
        local: Option<Arc<KeyRateLimit>>,
        rl: &RateLimitConfig,
    ) -> Option<Arc<Self>> {
        let rpm = key.rpm.filter(|r| *r > 0)?;
        let burst = key.burst.unwrap_or(0);
        if rl.backend == "redis" {
            match RedisLimiter::new(&key.key, rpm, burst, rl) {
                Ok(l) => return Some(Arc::new(Self::Redis(Arc::new(l)))),
                Err(e) => tracing::warn!(
                    "rate limiting: redis backend unusable ({e}); falling back to local buckets"
                ),
            }
        }
        local.map(|l| Arc::new(Self::Local(l)))
    }

    /// Consume one request. `Err(retry_after_secs)` = limited.
    pub async fn try_acquire(&self) -> Result<(), u64> {
        match self {
            // Round up: a client that sleeps exactly the advertised time must find
            // the bucket refilled (truncating 2.4 s to 2 s answers 429 again).
            Self::Local(l) => l.try_take().map_err(crate::middleware::retry_after_secs_of),
            Self::Redis(r) => r.try_acquire().await,
        }
    }

    /// True when `other` would behave identically, so a config reload can keep
    /// this instance (and with it the connection pool) instead of rebuilding.
    pub fn same_config(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Local(_), Self::Local(_)) => true,
            (Self::Redis(a), Self::Redis(b)) => {
                a.key == b.key
                    && a.capacity == b.capacity
                    && a.rate_per_sec == b.rate_per_sec
                    && a.fail_open == b.fail_open
                    && a.pool.identity() == b.pool.identity()
            }
            _ => false,
        }
    }
}

/// Redis-backed token bucket for one client key.
#[derive(Debug)]
pub struct RedisLimiter {
    pool: Arc<RedisPool>,
    /// `<prefix>:rl:<digest>:<rpm>:<burst>` — the name of the bucket.
    ///
    /// `digest` is the SHA-256 of the client key, **not** the key: the key is
    /// the bearer token clients authenticate with, and a Redis key is anything
    /// but private — it crosses `redis://` in plaintext and lives on in
    /// `KEYS`/`SCAN`/`MONITOR`, in `RDB`/`AOF` files and in every backup that
    /// copies them. A plain, unsalted hash (see [`redis::digest`]) keeps the
    /// name identical on every instance and across restarts while keeping the
    /// secret out of the server entirely.
    ///
    /// The limits are part of the name, so changing a key's limit starts from a
    /// fresh, full bucket.
    key: String,
    capacity: f64,
    rate_per_sec: f64,
    ttl_secs: u64,
    fail_open: bool,
    last_warn: Mutex<Option<Instant>>,
}

impl RedisLimiter {
    pub fn new(
        client_key: &str,
        rpm: u32,
        burst: u32,
        rl: &RateLimitConfig,
    ) -> Result<Self, RedisError> {
        let url = RedisUrl::parse(&rl.redis_url)?;
        let timeout = Duration::from_millis(rl.timeout_ms.clamp(1, 5_000));
        // Same defaulting as `TokenBucket::new`: burst 0 means "rpm".
        let capacity = if burst == 0 { rpm.max(1) } else { burst };
        Ok(Self {
            pool: redis::shared_pool(&url, timeout),
            key: format!(
                "{}:rl:{}:{}:{}",
                rl.key_prefix,
                redis::digest(client_key, CLIENT_KEY_DIGEST_BYTES),
                rpm,
                capacity
            ),
            capacity: capacity as f64,
            rate_per_sec: rpm as f64 / 60.0,
            ttl_secs: bucket_ttl(rpm, capacity),
            fail_open: rl.fail_open,
            last_warn: Mutex::new(None),
        })
    }

    /// The Redis key this limiter writes (exposed for tests/metrics).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Consume one request, or report how long the caller should wait.
    ///
    /// Time comes from this host's clock rather than `redis.call('TIME')`: the
    /// script stays valid on every Redis version and the call needs no extra round
    /// trip. Hosts are expected to be NTP-synced; a skewed clock can shift a bucket
    /// by the skew, and the script clamps a single observation to at most one full
    /// refill so a forward jump cannot mint more than `burst` tokens at once.
    pub async fn try_acquire(&self) -> Result<(), u64> {
        let now = now_ms();
        let cap = format!("{:.6}", self.capacity);
        let rate = format!("{:.6}", self.rate_per_sec);
        let now_s = now.to_string();
        let ttl = self.ttl_secs.to_string();
        let args: [&[u8]; 4] = [
            cap.as_bytes(),
            rate.as_bytes(),
            now_s.as_bytes(),
            ttl.as_bytes(),
        ];
        match self
            .pool
            .eval(TOKEN_BUCKET_LUA, &[self.key.as_str()], &args)
            .await
        {
            Ok(Resp::Array(Some(items))) => {
                let allowed = items.first().and_then(Resp::as_integer).unwrap_or(0);
                let retry_ms = items.get(1).and_then(Resp::as_integer).unwrap_or(0);
                if allowed == 1 {
                    Ok(())
                } else {
                    Err(secs_from_ms(retry_ms))
                }
            }
            // `summary()`, not `{other:?}`: the reply came off the wire, and an
            // 8 MiB sibling bulk would become a ~32 MB log line here.
            Ok(other) => self.degraded(format!("unexpected EVAL reply: {}", other.summary())),
            Err(e) => self.degraded(e.to_string()),
        }
    }

    /// Redis failed. `fail_open` decides the answer; either way the operator
    /// hears about it at most once a minute per key.
    fn degraded(&self, why: String) -> Result<(), u64> {
        let now = Instant::now();
        let due = {
            let mut last = self.last_warn.lock().unwrap_or_else(|e| e.into_inner());
            match *last {
                Some(t) if now.duration_since(t) < WARN_EVERY => false,
                _ => {
                    *last = Some(now);
                    true
                }
            }
        };
        if due {
            let policy = if self.fail_open {
                "allowing"
            } else {
                "denying"
            };
            tracing::warn!(
                "rate limiting: redis {} failed ({why}); {policy} requests \
                 (rpm {} burst {}, fail_open {})",
                self.pool.redacted(),
                self.rate_per_sec * 60.0,
                self.capacity,
                self.fail_open
            );
        }
        if self.fail_open { Ok(()) } else { Err(1) }
    }
}

/// TTL for the bucket key: twice the time a full bucket needs to refill, and
/// never under a minute. A key that expires is equivalent to a full bucket, so
/// eviction is harmless.
fn bucket_ttl(rpm: u32, capacity: u32) -> u64 {
    let rpm = rpm.max(1) as u64;
    let refill_secs = capacity.max(1) as u64 * 60 / rpm;
    (refill_secs * 2).max(60)
}

fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(_) => 0, // clock before the epoch: treat as "no time has passed"
    }
}

/// Redis reports milliseconds; `Retry-After` is whole seconds. Round up so a
/// client never retries into the same rejection, and never answer 0.
fn secs_from_ms(ms: i64) -> u64 {
    (ms.max(0) as u64).div_ceil(1000).max(1)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientKeyConfig;
    use crate::distributed::redis::fake::FakeRedis;

    fn key(rpm: u32, burst: u32) -> ClientKeyConfig {
        ClientKeyConfig {
            key: "sk-test".to_string(),
            name: Some("test".to_string()),
            models: Vec::new(),
            created_at: None,
            rpm: Some(rpm),
            burst: Some(burst),
            max_concurrent: None,
        }
    }

    fn redis_cfg(url: &str, fail_open: bool) -> RateLimitConfig {
        RateLimitConfig {
            backend: "redis".to_string(),
            redis_url: url.to_string(),
            key_prefix: "anyhop".to_string(),
            fail_open,
            timeout_ms: 300,
        }
    }

    fn shared(fake: &FakeRedis, rpm: u32, burst: u32, fail_open: bool) -> Arc<SharedLimiter> {
        SharedLimiter::for_key(&key(rpm, burst), None, &redis_cfg(&fake.url(), fail_open))
            .expect("limiter")
    }

    /// The bucket name the limiter must derive for `key`: the prefix, a **digest**
    /// of the client key, then the limits.
    fn bucket(client_key: &str, rpm: u32, capacity: u32) -> String {
        format!(
            "anyhop:rl:{}:{rpm}:{capacity}",
            redis::digest(client_key, CLIENT_KEY_DIGEST_BYTES)
        )
    }

    /// A port that was just free — the "Redis is down" case.
    async fn dead_redis_url() -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        drop(l);
        format!("redis://127.0.0.1:{port}/0")
    }

    #[tokio::test]
    async fn two_instances_drain_one_shared_budget() {
        let fake = FakeRedis::start().await;
        // Two limiters built independently, as two gateway instances would be.
        let a = shared(&fake, 60, 3, true);
        let b = shared(&fake, 60, 3, true);
        assert!(matches!(&*a, SharedLimiter::Redis(_)));
        assert!(a.try_acquire().await.is_ok());
        assert!(b.try_acquire().await.is_ok());
        assert!(a.try_acquire().await.is_ok());
        let retry = b
            .try_acquire()
            .await
            .expect_err("budget is shared, so this is limited");
        // 60 rpm = 1 token/s, and the bucket is empty.
        assert_eq!(retry, 1, "retry_after must be about a second");
        // One key, named after the prefix, the key's digest and the limits.
        assert!(
            fake.value(&bucket("sk-test", 60, 3)).is_some(),
            "bucket must live under <prefix>:rl:<digest>:<rpm>:<burst>"
        );
        // Refill is continuous, so a later call is allowed again.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(a.try_acquire().await.is_ok(), "one token refilled");
    }

    #[tokio::test]
    async fn every_acquire_is_one_atomic_eval_with_a_ttl() {
        let fake = FakeRedis::start().await;
        let l = shared(&fake, 60, 5, true);
        l.try_acquire().await.expect("first");
        let evals = fake.commands_named("EVAL");
        assert_eq!(evals.len(), 1, "one round trip per request");
        assert_eq!(evals[0][2], "1", "exactly one key");
        assert_eq!(evals[0][3], bucket("sk-test", 60, 5));
        // rpm 60 / burst 5 refills in 5s, so the 60s floor applies.
        assert_eq!(evals[0][7], "60", "ttl is never below 60s");
        // The fake honours `SET … EX`, so the bucket really expires.
        let ttl = fake.ttl(&bucket("sk-test", 60, 5));
        assert!((1..=60).contains(&ttl), "bucket ttl {ttl}");
        // A larger bucket gets 2x its refill time (see bucket_ttl).
        let big = shared(&fake, 60, 60, true);
        big.try_acquire().await.expect("first");
        let evals = fake.commands_named("EVAL");
        assert_eq!(evals.last().expect("eval")[7], "120");
    }

    /// Finding 1: the client key is a bearer token. It must never appear in a
    /// Redis key, because that name travels in plaintext and is persisted by
    /// `KEYS`/`SCAN`/`MONITOR`, `RDB`/`AOF` and every backup of them.
    #[tokio::test]
    async fn the_bucket_name_is_a_digest_and_the_secret_never_reaches_redis() {
        let fake = FakeRedis::start().await;
        let a = shared(&fake, 60, 3, true);
        let SharedLimiter::Redis(a) = &*a else {
            panic!("redis backend expected");
        };
        assert!(a.try_acquire().await.is_ok());

        // Shape: <prefix>:rl:<32 hex>:<rpm>:<burst> — a digest, not the token.
        let name = a.key();
        assert!(name.starts_with("anyhop:rl:"), "{name}");
        assert!(name.ends_with(":60:3"), "{name}");
        assert!(
            !name.contains("sk-test"),
            "the secret is in the key: {name}"
        );
        let tag = name
            .strip_prefix("anyhop:rl:")
            .and_then(|rest| rest.strip_suffix(":60:3"))
            .expect("bucket shape");
        assert_eq!(tag.len(), 32, "16 digest bytes, hex: {tag}");
        assert!(
            tag.bytes().all(|b| b.is_ascii_hexdigit()),
            "bucket tag is not hex: {tag}"
        );

        // Stable: another instance derives the same name, so the budget is
        // shared (a random salt would silently give each instance its own).
        let b = shared(&fake, 60, 3, true);
        let SharedLimiter::Redis(b) = &*b else {
            panic!("redis backend expected");
        };
        assert_eq!(a.key(), b.key(), "the name must be deterministic");

        // …and nothing the client sent names the key: not one command on the
        // wire (script, KEYS or ARGV) mentions the token.
        let wire = format!("{:?}", fake.commands());
        assert!(
            !wire.contains("sk-test"),
            "the client key reached the server: {wire}"
        );
    }

    #[tokio::test]
    async fn a_full_burst_passes_then_the_key_is_limited() {
        let fake = FakeRedis::start().await;
        let l = shared(&fake, 60, 2, true);
        assert!(l.try_acquire().await.is_ok());
        assert!(l.try_acquire().await.is_ok());
        assert_eq!(l.try_acquire().await.expect_err("exhausted"), 1);
    }

    #[tokio::test]
    async fn keys_with_different_limits_do_not_share_a_bucket() {
        let fake = FakeRedis::start().await;
        let a = shared(&fake, 60, 1, true);
        let b = shared(&fake, 60, 2, true);
        assert!(a.try_acquire().await.is_ok());
        // The second key has its own (bigger) bucket: the first exhausted does
        // not affect it.
        assert!(b.try_acquire().await.is_ok());
        assert!(b.try_acquire().await.is_ok());
        assert!(b.try_acquire().await.is_err());
    }

    #[tokio::test]
    async fn fail_open_allows_requests_when_redis_is_down() {
        let url = dead_redis_url().await;
        let l = SharedLimiter::for_key(&key(60, 1), None, &redis_cfg(&url, true)).expect("limiter");
        assert!(
            l.try_acquire().await.is_ok(),
            "fail_open must fall back to allowing traffic"
        );
    }

    #[tokio::test]
    async fn fail_closed_denies_requests_when_redis_is_down() {
        let url = dead_redis_url().await;
        let l =
            SharedLimiter::for_key(&key(60, 1), None, &redis_cfg(&url, false)).expect("limiter");
        let retry = l
            .try_acquire()
            .await
            .expect_err("fail_open = false must deny");
        assert_eq!(retry, 1, "deny with a one second retry");
    }

    #[tokio::test]
    async fn an_unusable_url_falls_back_to_the_local_bucket() {
        let local = Some(Arc::new(KeyRateLimit::new(60, 1).expect("bucket")));
        let cfg = redis_cfg("not-a-redis-url", true);
        let l = SharedLimiter::for_key(&key(60, 1), local, &cfg).expect("limiter");
        assert!(
            matches!(&*l, SharedLimiter::Local(_)),
            "a broken URL must not silently drop the limit"
        );
        assert!(l.try_acquire().await.is_ok());
        assert_eq!(l.try_acquire().await.expect_err("limited locally"), 1);
    }

    #[tokio::test]
    async fn the_local_backend_is_the_same_bucket_as_before() {
        let local = Some(Arc::new(KeyRateLimit::new(60, 2).expect("bucket")));
        let l = SharedLimiter::for_key(&key(60, 2), local, &RateLimitConfig::default())
            .expect("limiter");
        assert!(matches!(&*l, SharedLimiter::Local(_)));
        assert!(l.try_acquire().await.is_ok());
        assert!(l.try_acquire().await.is_ok());
        // Same rounding as `retry_after.as_secs().max(1)` in the middleware.
        assert_eq!(l.try_acquire().await.expect_err("limited"), 1);
    }

    #[tokio::test]
    async fn unlimited_keys_get_no_limiter_at_all() {
        let fake = FakeRedis::start().await;
        let mut cfg = key(60, 0);
        cfg.rpm = None;
        assert!(SharedLimiter::for_key(&cfg, None, &redis_cfg(&fake.url(), true)).is_none());
        cfg.rpm = Some(0);
        assert!(SharedLimiter::for_key(&cfg, None, &redis_cfg(&fake.url(), true)).is_none());
    }

    #[tokio::test]
    async fn reload_reuses_an_identical_redis_limiter() {
        let fake = FakeRedis::start().await;
        let cfg = redis_cfg(&fake.url(), true);
        let a = SharedLimiter::for_key(&key(60, 3), None, &cfg).expect("a");
        let b = SharedLimiter::for_key(&key(60, 3), None, &cfg).expect("b");
        assert!(
            a.same_config(&b),
            "an unrelated reload must keep the limiter"
        );
        let bigger = SharedLimiter::for_key(&key(60, 9), None, &cfg).expect("c");
        assert!(!a.same_config(&bigger));
        let local = SharedLimiter::for_key(
            &key(60, 3),
            Some(Arc::new(KeyRateLimit::new(60, 3).expect("bucket"))),
            &RateLimitConfig::default(),
        )
        .expect("local");
        assert!(!a.same_config(&local), "a backend switch rebuilds it");
    }

    #[test]
    fn bucket_ttl_is_two_refills_and_never_under_a_minute() {
        // 60 rpm, burst 60: a full refill takes 60s.
        assert_eq!(bucket_ttl(60, 60), 120);
        // 1 rpm, burst 1: refill takes 60s → still 120.
        assert_eq!(bucket_ttl(1, 1), 120);
        // A tiny bucket refills in no time; the floor keeps the key alive.
        assert_eq!(bucket_ttl(60, 1), 60);
        assert_eq!(bucket_ttl(600, 600), 120);
    }

    #[test]
    fn retry_seconds_round_up() {
        assert_eq!(secs_from_ms(0), 1);
        assert_eq!(secs_from_ms(1), 1);
        assert_eq!(secs_from_ms(999), 1);
        assert_eq!(secs_from_ms(1_000), 1);
        assert_eq!(secs_from_ms(1_001), 2);
    }

    #[test]
    fn the_lua_script_is_the_documented_one() {
        // Guard rails for the script that runs on every Redis deployment.
        assert!(TOKEN_BUCKET_LUA.contains("-- anyhop:token-bucket"));
        assert!(TOKEN_BUCKET_LUA.contains("redis.call('GET', KEYS[1])"));
        assert!(TOKEN_BUCKET_LUA.contains("redis.call('SET', KEYS[1]"));
        assert!(TOKEN_BUCKET_LUA.contains("'EX', ttl"));
        assert!(TOKEN_BUCKET_LUA.contains("return {allowed, retry_ms}"));
        // `%.0f`, not `tostring`: Lua 5.1 would print 1.7e+12 for a ms clock.
        assert!(TOKEN_BUCKET_LUA.contains("string.format"));
        assert!(!TOKEN_BUCKET_LUA.contains("tostring"));
    }
}
