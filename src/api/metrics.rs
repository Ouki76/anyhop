//! Prometheus metrics: `/metrics` (admin-authenticated, text exposition format).
//!
//! A rotation gateway's failure mode is silent — every key quietly slips into
//! cooldown and clients see 503s. These series make that visible:
//! `anyhop_key_status{state="dead"}` and `anyhop_keys_available` are the two
//! alerts worth wiring up.
//!
//! Everything is scraped from the live pools (atomics, no I/O), so a scrape is
//! cheap even under load.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Instant;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::proxy::AppState;

/// Process start, used for uptime. Initialised on first use, which happens at
/// the first scrape — so it is the "time since first scrape" floor, not an
/// exact process age. Documented rather than plumbed through every state struct.
static START: LazyLock<Instant> = LazyLock::new(Instant::now);

pub async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let router = state.router.load();
    let mut out = String::with_capacity(4096);

    out.push_str("# HELP anyhop_up Whether the gateway process is serving.\n");
    out.push_str("# TYPE anyhop_up gauge\nanyhop_up 1\n");
    let _ = writeln!(
        out,
        "# HELP anyhop_uptime_seconds Seconds since the first metrics scrape.\n\
         # TYPE anyhop_uptime_seconds counter\nanyhop_uptime_seconds {}",
        START.elapsed().as_secs()
    );
    let _ = writeln!(
        out,
        "# HELP anyhop_providers Configured providers.\n\
         # TYPE anyhop_providers gauge\nanyhop_providers {}",
        router.providers.len()
    );
    let _ = writeln!(
        out,
        "# HELP anyhop_combos Configured virtual models (fallback chains).\n\
         # TYPE anyhop_combos gauge\nanyhop_combos {}",
        router.combos.len()
    );

    // Header block for the per-key families.
    for (name, kind, help) in [
        (
            "anyhop_key_requests_total",
            "counter",
            "Upstream attempts routed through this credential.",
        ),
        (
            "anyhop_key_failures_total",
            "counter",
            "Failed upstream attempts on this credential.",
        ),
        (
            "anyhop_key_tokens_total",
            "counter",
            "Tokens reported by the upstream (label type=prompt|completion).",
        ),
        (
            "anyhop_key_in_flight",
            "gauge",
            "Requests currently executing on this credential.",
        ),
        (
            "anyhop_key_cooldown_seconds",
            "gauge",
            "Remaining cooldown before the credential is retried.",
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }
    let _ = writeln!(
        out,
        "# HELP anyhop_key_status Credential state as a one-hot gauge (state=active|cooldown|dead).\n\
         # TYPE anyhop_key_status gauge"
    );

    let mut available = 0usize;
    let mut total_keys = 0usize;

    for p in &router.providers {
        let provider = esc(&p.name);
        for k in p.pool.snapshot() {
            total_keys += 1;
            let id = esc(&k.id);
            let labels = format!("provider=\"{provider}\",key=\"{id}\"");
            let _ = writeln!(out, "anyhop_key_requests_total{{{labels}}} {}", k.requests);
            let _ = writeln!(out, "anyhop_key_failures_total{{{labels}}} {}", k.failures);
            let _ = writeln!(
                out,
                "anyhop_key_tokens_total{{{labels},type=\"prompt\"}} {}",
                k.prompt_tokens
            );
            let _ = writeln!(
                out,
                "anyhop_key_tokens_total{{{labels},type=\"completion\"}} {}",
                k.completion_tokens
            );
            let _ = writeln!(out, "anyhop_key_in_flight{{{labels}}} {}", k.in_flight);
            let _ = writeln!(
                out,
                "anyhop_key_cooldown_seconds{{{labels}}} {}",
                k.cooldown_remaining_secs
            );
            if k.status == "active" {
                available += 1;
            }
            for s in ["active", "cooldown", "dead"] {
                let one = u8::from(k.status == s);
                let _ = writeln!(out, "anyhop_key_status{{{labels},state=\"{s}\"}} {one}");
            }
        }
    }

    let _ = writeln!(
        out,
        "# HELP anyhop_keys_total Credentials across all providers.\n\
         # TYPE anyhop_keys_total gauge\nanyhop_keys_total {total_keys}"
    );
    let _ = writeln!(
        out,
        "# HELP anyhop_keys_available Credentials currently usable (not dead, not cooling).\n\
         # TYPE anyhop_keys_available gauge\nanyhop_keys_available {available}"
    );

    // Per-client-key rate limiting: the two series worth alerting on are the
    // rejection counter (a tenant is being throttled) and the remaining tokens.
    let keys = state.client_keys.read().unwrap_or_else(|e| e.into_inner());
    if keys.values().any(|r| r.limiter.is_some()) {
        out.push_str(
            "# HELP anyhop_client_key_rate_limited_total Requests rejected by the per-key rate limit.\n\
             # TYPE anyhop_client_key_rate_limited_total counter\n",
        );
        // Both families must be declared before any sample is written: a strict
        // exposition parser (promtool, the Prometheus server itself) rejects a
        // scrape whose # TYPE appears after a sample of that metric.
        out.push_str(
            "# HELP anyhop_client_key_rate_limit_tokens Tokens left in the key's bucket.\n\
             # TYPE anyhop_client_key_rate_limit_tokens gauge\n",
        );
        for rt in keys.values() {
            let Some(limiter) = &rt.limiter else { continue };
            let name = esc(&crate::proxy::client_key_label(
                &rt.cfg.key,
                rt.cfg.name.as_deref(),
            ));
            let n = rt.limited.load(std::sync::atomic::Ordering::Relaxed);
            let _ = writeln!(
                out,
                "anyhop_client_key_rate_limited_total{{key=\"{name}\"}} {n}"
            );
            // The token gauge only describes the *local* bucket. Under the redis
            // backend the bucket lives in Redis and the local one is never drained,
            // so emitting it reported a permanently full bucket.
            if rt.shared.as_ref().is_none_or(|s| s.is_local()) {
                let _ = writeln!(
                    out,
                    "anyhop_client_key_rate_limit_tokens{{key=\"{name}\"}} {:.3}",
                    limiter.available()
                );
            }
        }
    }
    drop(keys);

    if let Some(rss) = rss_bytes() {
        let _ = writeln!(
            out,
            "# HELP anyhop_process_resident_memory_bytes Resident set size.\n\
             # TYPE anyhop_process_resident_memory_bytes gauge\n\
             anyhop_process_resident_memory_bytes {rss}"
        );
    }

    // Latency histograms (recorded by middleware::record_metrics). Empty when
    // nothing has been served yet, so this is safe to append unconditionally.
    out.push_str(&crate::api::histograms::render());
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

/// Escape a Prometheus label value: `\`, `"` and newlines only.
fn esc(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// RSS from /proc/self/statm (Linux only); `None` elsewhere or on parse failure.
fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        // 4 KiB pages on every platform we target; a wrong value here would only
        // skew a monitoring gauge, never behaviour.
        Some(pages * 4096)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(esc("plain"), "plain");
        assert_eq!(esc(r#"a"b"#), r#"a\"b"#);
        assert_eq!(esc("a\\b"), "a\\\\b");
        assert_eq!(esc("a\nb"), "a\\nb");
    }

    /// The exposition body is what a Prometheus scraper parses, and a malformed
    /// one is rejected wholesale — taking every series with it. `run_all.sh`
    /// greps three of these lines; nothing asserted the document as a whole.
    #[tokio::test]
    async fn the_exposition_is_a_well_formed_prometheus_document() {
        // The histogram registry is process-wide and other tests reset it, so the
        // scrape must not interleave with them. A `std::sync` guard may not cross
        // an `.await`, so the lock is held around a `block_on` of the handler
        // rather than across the test's own await points.
        let st = crate::api::server::test_support::state(&std::path::PathBuf::from(
            "/tmp/anyhop-metrics-test-not-a-file.toml",
        ));
        let resp = {
            let _registry = crate::api::histograms::test_guard();
            futures::executor::block_on(metrics(State(st)))
        };
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; version=0.0.4; charset=utf-8"),
            "the Prometheus text format names its version in the content type"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("body");
        let body = String::from_utf8(body.to_vec()).expect("utf-8");

        let mut type_of: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut saw_help: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for line in body.lines() {
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("# HELP ") {
                let name = rest.split_whitespace().next().expect("HELP has a name");
                assert!(saw_help.insert(name), "{name} has a duplicate # HELP line");
            } else if let Some(rest) = line.strip_prefix("# TYPE ") {
                let mut it = rest.split_whitespace();
                let name = it.next().expect("TYPE has a name");
                let kind = it.next().expect("TYPE has a kind");
                assert!(
                    matches!(
                        kind,
                        "counter" | "gauge" | "histogram" | "summary" | "untyped"
                    ),
                    "{name}: unknown metric type {kind}"
                );
                assert!(
                    type_of.insert(name, kind).is_none(),
                    "{name} has a duplicate # TYPE line"
                );
            } else {
                assert!(!line.starts_with('#'), "unexpected comment form: {line}");
                let (sample, value) = line
                    .rsplit_once(' ')
                    .unwrap_or_else(|| panic!("sample line without a value: {line}"));
                let name = sample.split('{').next().unwrap_or(sample);
                // Every sample must belong to a declared family, and a `_total`
                // counter must not claim to be a gauge (Prometheus rejects a
                // counter/gauge name clash).
                // A histogram's samples carry a required suffix that is not part
                // of the family name (`_bucket`, `_sum`, `_count`), and a counter
                // may be written as `_total`. Strip one and look again.
                let family = ["_bucket", "_sum", "_count", "_total"]
                    .iter()
                    .find_map(|suffix| {
                        name.strip_suffix(suffix)
                            .filter(|base| type_of.contains_key(base))
                    })
                    .unwrap_or(name);
                assert!(
                    type_of.contains_key(family),
                    "sample {name} has no # TYPE line (family {family})"
                );
                assert!(
                    value.parse::<f64>().is_ok(),
                    "sample {name} has a non-numeric value {value:?}"
                );
            }
        }

        // The handful of series the runbook relies on must actually be present.
        for required in [
            "anyhop_up 1",
            "anyhop_providers ",
            "anyhop_keys_available ",
            "anyhop_process_resident_memory_bytes ",
        ] {
            assert!(
                body.contains(required),
                "the exposition is missing {required:?}:\n{body}"
            );
        }
        assert!(
            !body.contains("NaN") && !body.contains("inf"),
            "a gauge must never render as NaN/inf: {body}"
        );
    }

    #[test]
    fn rss_lookup_does_not_panic() {
        // Either a plausible number or None — never a panic.
        if let Some(v) = rss_bytes() {
            assert!(v > 0);
        }
    }
}
