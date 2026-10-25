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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A provider with the drain knob set, built offline (no upstream is contacted).
    fn drain_provider(drain_below_pct: u32) -> Provider {
        let cfg: crate::config::ProviderConfig = toml::from_str(&format!(
            r#"
            name = "up"
            type = "openai_compat"
            base_url = "http://127.0.0.1:1/v1"
            keys = ["sk-a"]
            models = ["m"]
            drain_below_pct = {drain_below_pct}
            "#
        ))
        .expect("test provider config");
        Provider::from_config(
            &cfg,
            None,
            None,
            None,
            Arc::new(Tuning::default()),
            Duration::from_secs(5),
            2,
        )
        .expect("the provider builds offline")
    }

    /// A real `reqwest::Response` carrying `headers`, served from a loopback
    /// socket. The header logic is what is under test, and that needs a genuine
    /// response object.
    ///
    /// Served by axum rather than by a hand-written socket: `tokio` 1.54 + hyper 1
    /// report a raw "write the response, close immediately" server as
    /// `UnexpectedMessage` (the client sees the connection end mid-exchange), which
    /// says nothing about the code under test.
    async fn response_with(headers: &[(&str, &str)]) -> reqwest::Response {
        let pairs: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let pairs = pairs.clone();
                async move {
                    let mut resp = axum::response::Response::new(axum::body::Body::empty());
                    for (k, v) in pairs {
                        if let (Ok(name), Ok(value)) = (
                            axum::http::HeaderName::from_bytes(k.as_bytes()),
                            axum::http::HeaderValue::from_str(&v),
                        ) {
                            resp.headers_mut().insert(name, value);
                        }
                    }
                    resp
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        let resp = reqwest::get(format!("http://{addr}/"))
            .await
            .expect("the loopback server answers");
        let _ = tx.send(());
        resp
    }

    /// The (single) key's remaining cooldown.
    fn remaining_secs(provider: &Provider) -> u64 {
        provider.pool.snapshot()[0].cooldown_remaining_secs
    }

    /// The whole point of the headers: when the upstream says "10% of the window
    /// is left", cool the key down *before* the next request gets a 429. The
    /// advertised reset is honoured, not a fixed value.
    #[tokio::test]
    async fn a_low_remaining_budget_drains_the_key_for_the_advertised_reset() {
        let provider = drain_provider(10);
        let key = provider.pool.pick("m", None).expect("a key");
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "5"),
            ("x-ratelimit-limit-requests", "100"),
            ("x-ratelimit-reset-requests", "30s"),
        ])
        .await;

        check_drain_headers(&provider, &key, &resp, &Tuning::default());

        let remaining = remaining_secs(&provider);
        assert!(
            (29..=30).contains(&remaining),
            "the key must be benched for the advertised reset, got {remaining}s"
        );
        // The pool immediately stops handing this key out.
        assert!(
            provider.pool.pick("m", None).is_none(),
            "a proactively drained key must not be used again"
        );
    }

    /// At or above the threshold there is nothing to do: benching a healthy key
    /// would take capacity away for no reason.
    #[tokio::test]
    async fn a_budget_at_the_threshold_is_left_alone() {
        let provider = drain_provider(10);
        let key = provider.pool.pick("m", None).expect("a key");
        // remaining*100 == limit*10 exactly: the comparison is ">=" so this is
        // the boundary case that must NOT drain.
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "10"),
            ("x-ratelimit-limit-requests", "100"),
            ("x-ratelimit-reset-requests", "30s"),
        ])
        .await;

        check_drain_headers(&provider, &key, &resp, &Tuning::default());
        assert_eq!(remaining_secs(&provider), 0, "no cooldown expected");

        // Well above the threshold is equally untouched.
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "99"),
            ("x-ratelimit-limit-requests", "100"),
        ])
        .await;
        check_drain_headers(&provider, &key, &resp, &Tuning::default());
        assert_eq!(remaining_secs(&provider), 0);
    }

    /// A provider that only sends the counters, a garbage reset value, or no
    /// counters at all must still end up with a *bounded* cooldown rather than a
    /// panic, an unparseable duration, or a permanently benched key.
    #[tokio::test]
    async fn a_missing_or_garbage_reset_uses_the_configured_fallback() {
        let tuning = Tuning {
            drain_fallback_secs: 20,
            ..Default::default()
        };

        // No reset header at all.
        let provider = drain_provider(50);
        let key = provider.pool.pick("m", None).expect("a key");
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "1"),
            ("x-ratelimit-limit-requests", "100"),
        ])
        .await;
        check_drain_headers(&provider, &key, &resp, &tuning);
        let remaining = remaining_secs(&provider);
        assert!(
            (19..=20).contains(&remaining),
            "the configured fallback must be used, got {remaining}s"
        );

        // A reset the parser rejects takes the same path.
        let provider = drain_provider(50);
        let key = provider.pool.pick("m", None).expect("a key");
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "1"),
            ("x-ratelimit-limit-requests", "100"),
            ("x-ratelimit-reset-requests", "whenever"),
        ])
        .await;
        check_drain_headers(&provider, &key, &resp, &tuning);
        assert!(
            (19..=20).contains(&remaining_secs(&provider)),
            "a garbage reset must fall back instead of benching forever"
        );

        // No counters at all: nothing to decide, nothing benched.
        let provider = drain_provider(50);
        let key = provider.pool.pick("m", None).expect("a key");
        let resp = response_with(&[("x-ratelimit-reset-requests", "30s")]).await;
        check_drain_headers(&provider, &key, &resp, &tuning);
        assert_eq!(remaining_secs(&provider), 0);
    }

    /// Header values come from the upstream. `remaining * 100` overflows u64 for
    /// values near the top of the range, and a panic in the retry loop would take
    /// the whole request down; a zero limit must not divide by anything either.
    #[tokio::test]
    async fn absurd_header_values_are_compared_without_overflowing() {
        let provider = drain_provider(10);
        let key = provider.pool.pick("m", None).expect("a key");

        // remaining * 100 > u64::MAX if computed in u64.
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "18446744073709551615"),
            ("x-ratelimit-limit-requests", "18446744073709551615"),
        ])
        .await;
        check_drain_headers(&provider, &key, &resp, &Tuning::default());
        assert_eq!(
            remaining_secs(&provider),
            0,
            "a full budget is not a drain, and nothing overflowed"
        );

        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "0"),
            ("x-ratelimit-limit-requests", "0"),
        ])
        .await;
        check_drain_headers(&provider, &key, &resp, &Tuning::default());
        assert_eq!(remaining_secs(&provider), 0, "limit 0 means unknown");

        // Non-numeric counters are ignored rather than parsed as 0 (= drain!).
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "lots"),
            ("x-ratelimit-limit-requests", "100"),
        ])
        .await;
        check_drain_headers(&provider, &key, &resp, &Tuning::default());
        assert_eq!(remaining_secs(&provider), 0);
    }

    /// `drain_below_pct = 0` disables the feature: even an exhausted budget must
    /// not bench a key.
    #[tokio::test]
    async fn a_zero_threshold_disables_the_drain() {
        let provider = drain_provider(0);
        let key = provider.pool.pick("m", None).expect("a key");
        let resp = response_with(&[
            ("x-ratelimit-remaining-requests", "0"),
            ("x-ratelimit-limit-requests", "10000"),
            ("x-ratelimit-reset-requests", "120s"),
        ])
        .await;
        check_drain_headers(&provider, &key, &resp, &Tuning::default());
        assert_eq!(remaining_secs(&provider), 0);
    }
}
