//! Per-client-key rate limiting: a token bucket per credential.
//!
//! Deliberately *not* a request-per-minute counter reset on a wall-clock minute:
//! that allows a full burst at second 59 and another at second 0. A bucket refills
//! continuously, so `rpm` is a sustained rate and `burst` caps the spike.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One token bucket. `capacity` tokens, refilled at `rate_per_sec`.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    rate_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// `rpm` requests per minute sustained, up to `burst` in a spike
    /// (`burst` defaults to `rpm` when 0).
    pub fn new(rpm: u32, burst: u32) -> Option<Self> {
        if rpm == 0 {
            return None; // unlimited
        }
        let capacity = if burst == 0 { rpm } else { burst.max(1) } as f64;
        Some(Self {
            capacity,
            rate_per_sec: rpm as f64 / 60.0,
            tokens: capacity,
            last: Instant::now(),
        })
    }

    /// Refill by elapsed time, then try to take one token.
    fn try_take_at(&mut self, now: Instant) -> Result<(), Duration> {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
            self.last = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Time until the next whole token is available.
            let missing = 1.0 - self.tokens;
            Err(Duration::from_secs_f64((missing / self.rate_per_sec).max(0.05)))
        }
    }

    /// Take one token, or return how long the caller should wait.
    pub fn try_take(&mut self) -> Result<(), Duration> {
        self.try_take_at(Instant::now())
    }

    /// Tokens currently available (for metrics).
    pub fn available(&self) -> f64 {
        self.tokens
    }
}

/// Rate limiter for one client key, shared across requests.
#[derive(Debug)]
pub struct KeyRateLimit {
    bucket: Mutex<TokenBucket>,
}

impl KeyRateLimit {
    pub fn new(rpm: u32, burst: u32) -> Option<Self> {
        TokenBucket::new(rpm, burst).map(|b| Self {
            bucket: Mutex::new(b),
        })
    }

    /// Try to consume one request. `Err(retry_after)` = limited.
    ///
    /// Poison-recovering: the guard protects plain numbers with no invariant a
    /// panic could corrupt, so a poisoned lock must not disable the limit
    /// (or, worse, permanently block the key).
    pub fn try_take(&self) -> Result<(), Duration> {
        let mut b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        b.try_take()
    }

    pub fn available(&self) -> f64 {
        let b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        b.available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_when_rpm_is_zero() {
        assert!(TokenBucket::new(0, 0).is_none());
    }

    #[test]
    fn allows_a_burst_then_limits() {
        let mut b = TokenBucket::new(60, 3).expect("bucket");
        let now = Instant::now();
        for i in 0..3 {
            assert!(b.try_take_at(now).is_ok(), "burst token {i} must pass");
        }
        let retry = b.try_take_at(now).expect_err("burst exhausted");
        // 60 rpm = 1 token/s, so the next token is ~1s away.
        assert!(retry <= Duration::from_secs(1), "retry_after too large: {retry:?}");
        assert!(retry >= Duration::from_millis(900), "retry_after too small: {retry:?}");
    }

    #[test]
    fn refills_continuously_not_per_calendar_minute() {
        // 1 rpm = one token per 60s, capacity 1.
        let mut b = TokenBucket::new(1, 1).expect("bucket");
        let t0 = Instant::now();
        assert!(b.try_take_at(t0).is_ok());
        assert!(b.try_take_at(t0).is_err());
        // 30s later half a token has accrued — not a full request yet.
        assert!(b.try_take_at(t0 + Duration::from_secs(30)).is_err());
        // 61s later a full token is available again.
        assert!(b.try_take_at(t0 + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn capacity_caps_the_refill() {
        let mut b = TokenBucket::new(60, 2).expect("bucket");
        let t0 = Instant::now();
        // An hour of idle time must not accumulate an hour's worth of requests.
        assert!(b.try_take_at(t0 + Duration::from_secs(3600)).is_ok());
        assert!(b.try_take_at(t0 + Duration::from_secs(3600)).is_ok());
        assert!(b.try_take_at(t0 + Duration::from_secs(3600)).is_err());
    }

    #[test]
    fn burst_defaults_to_rpm() {
        let mut b = TokenBucket::new(5, 0).expect("bucket");
        let now = Instant::now();
        for _ in 0..5 {
            assert!(b.try_take_at(now).is_ok());
        }
        assert!(b.try_take_at(now).is_err());
    }

    #[test]
    fn exhausted_key_reports_a_sane_retry_after() {
        // 1 rpm: the bucket is deep-empty, retry must be ~60s, never hours.
        let mut b = TokenBucket::new(1, 1).expect("bucket");
        let now = Instant::now();
        assert!(b.try_take_at(now).is_ok());
        let retry = b.try_take_at(now).expect_err("limited");
        assert!(retry <= Duration::from_secs(60), "{retry:?}");
        assert!(retry >= Duration::from_secs(59), "{retry:?}");
    }

    #[test]
    fn shared_limiter_counts_across_clones() {
        let limiter = KeyRateLimit::new(60, 2).expect("limiter");
        assert!(limiter.try_take().is_ok());
        assert!(limiter.try_take().is_ok());
        assert!(limiter.try_take().is_err());
        assert!(limiter.available() < 1.0);
    }

    #[test]
    fn a_poisoned_lock_still_enforces_the_limit() {
        let limiter = std::sync::Arc::new(KeyRateLimit::new(60, 1).expect("limiter"));
        // Poison the mutex from another thread.
        let l2 = limiter.clone();
        let _ = std::thread::spawn(move || {
            let _g = l2.bucket.lock().unwrap();
            panic!("poison the bucket");
        })
        .join();
        // The key state must stay usable, and the limiter must keep working.
        assert!(limiter.try_take().is_ok(), "recovered lock must still grant the first token");
        assert!(limiter.try_take().is_err(), "recovered lock must still enforce the limit");
    }
}