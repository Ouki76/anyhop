//! Retry-loop helpers: proactive drain driven by upstream rate-limit headers.

use std::sync::Arc;

use crate::config::Tuning;
use crate::pool::KeyState;
use crate::providers::Provider;

use super::errors::parse_reset_duration;

/// Proactive drain: cool the key down before it hits the rate limit,
/// based on x-ratelimit-remaining/limit/reset headers.
pub(super) fn check_drain_headers(
    provider: &Provider,
    key: &Arc<KeyState>,
    resp: &reqwest::Response,
    tuning: &Tuning,
) {
    let h = resp.headers();
    let get_u64 = |name: &str| {
        h.get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
    };
    let (Some(remaining), Some(limit)) = (
        get_u64("x-ratelimit-remaining-requests"),
        get_u64("x-ratelimit-limit-requests"),
    ) else {
        return;
    };
    // u128: header values come from the upstream — remaining*100 must not overflow
    if limit == 0 || remaining as u128 * 100 >= limit as u128 * provider.drain_below_pct as u128 {
        return;
    }
    let reset = h
        .get("x-ratelimit-reset-requests")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_reset_duration)
        .unwrap_or_else(|| tuning.drain_fallback());
    provider.pool.drain(key, reset);
}
