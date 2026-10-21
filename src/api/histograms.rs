//! Latency histograms for `/metrics`.
//!
//! `api::metrics` exposes pool state as gauges and counters, which says what is
//! broken but not how slow it is: "p95 of `/v1/chat/completions` is 4.2 s" and
//! "1 % of requests return 503" cannot be derived from its series. This module
//! adds the family that answers both — one `histogram` per
//! `(route, method, status)` triple — in plain `std`, with no protobuf client,
//! no registry crate and no background thread.
//!
//! # Lock strategy (why the hot path is cheap)
//!
//! The series map is `RwLock<HashMap<Key, Arc<Buckets>>>`, and *only the map* is
//! behind the lock. Each `Buckets` is an `Arc` whose counters are atomics, so a
//! scrape and a request can touch the same series without excluding each other:
//!
//! * existing series → `read()` lock for the map lookup, then release it and
//!   bump atomics (any number of request threads proceed in parallel);
//! * new series → one `write()` lock, taken at most once per distinct
//!   `(route, method, status)` for the life of the process.
//!
//! The lock therefore never covers the recording itself, which is why a busy
//! gateway does not serialise on metrics.
//!
//! Sums are stored as `AtomicU64` **nanoseconds**, not as an atomic float: there
//! is no portable `AtomicF64` in `std`, and emulating one with a
//! compare-and-swap loop over the bit pattern would be more code and strictly
//! slower than a single integer `fetch_add`. The division by `1e9` happens once
//! per scrape, in [`render`].
//!
//! # Usage
//!
//! From a `from_fn` middleware, after the response is built:
//!
//! ```text
//! let secs = started.elapsed().as_secs_f64();
//! anyhop::api::histograms::record(
//!     &anyhop::api::histograms::route_label(req.uri().path()),
//!     req.method().as_str(),
//!     status.as_u16(),
//!     secs,
//! );
//! ```
//!
//! and in `api::metrics`, after the existing series:
//!
//! ```text
//! out.push_str(&anyhop::api::histograms::render());
//! ```

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};

/// Series name; the `_bucket`, `_sum` and `_count` suffixes are appended by
/// [`render`], as the Prometheus text format requires.
pub const METRIC_NAME: &str = "anyhop_http_request_duration_seconds";

/// Upper bound on distinct `(route, method, status)` series kept in the map.
///
/// Prometheus series are forever: an unbounded label set (one series per user
/// path, per id, per attacker-chosen URL) is the classic way to blow up both
/// this process's memory and the scraper's TSDB. Overflow is folded into
/// `route="other"` rather than dropped, so totals still add up.
pub const MAX_SERIES: usize = 500;

/// Upper bound of the finite buckets; the histogram carries `FINITE_BUCKETS + 1`
/// slots because `+Inf` is a slot too.
pub const FINITE_BUCKETS: usize = 13;

/// Label emitted for a value above the last finite bucket.
const INF_LABEL: &str = "+Inf";

/// Route label for anything we do not recognise, and the overflow sink.
const OTHER_ROUTE: &str = "other";

/// Finite bucket boundaries in seconds — the Prometheus default bucket set.
///
/// Kept as `f64` for the comparison in [`Buckets::observe`]; the exact strings
/// Prometheus must see live in [`BUCKETS_LE`]. **The two arrays are parallel and
/// must be edited together.**
const BUCKETS: [f64; FINITE_BUCKETS] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// `le` label values, formatted by hand so a scrape diffs cleanly against a
/// rendered template instead of drifting with float formatting.
const BUCKETS_LE: [&str; FINITE_BUCKETS + 1] = [
    "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5",
    "10", INF_LABEL,
];

/// Paths that are emitted verbatim: the real router surface from `build_router`
/// (`/v1/*`, the admin API, health and the dashboard entry point).
///
/// This is an allowlist rather than a regex because the point of the label is to
/// be a *closed* set: anything not in here is either an id or noise.
const STATIC_ROUTES: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/fim/completions",
    "/v1/models",
    "/v1/models/{*id}",
    "/v1/responses",
    "/v1/realtime",
    "/v1/images/generations",
    "/v1/images/edits",
    "/v1/audio/speech",
    "/v1/audio/transcriptions",
    "/v1/audio/translations",
    "/healthz",
    "/metrics",
    "/dashboard",
    "/api/providers",
    "/api/providers/add",
    "/api/providers/update",
    "/api/providers/delete",
    "/api/requests",
    "/api/quotas",
    "/api/events",
    "/api/keys/add",
    "/api/keys/delete",
    "/api/keys/enable",
    "/api/keys/disable",
    "/api/combos",
    "/api/combos/add",
    "/api/combos/update",
    "/api/combos/delete",
    "/api/client-keys",
    "/api/client-keys/add",
    "/api/client-keys/update",
    "/api/client-keys/delete",
    "/api/models",
    "/api/models/refresh",
    "/api/models/enable",
    "/api/models/disable",
    "/api/models/toggle",
    "/api/models/enable-all",
    "/api/models/disable-all",
    "/api/config",
    "/api/reload",
    "/api/server",
    "/api/server/update",
    "/api/auth/start",
    "/api/auth/status",
    "/api/auth/cancel",
    "/api/auth/complete",
    "/api/auth/callback",
];

/// Map key. Ordered so that the same tuple always sorts into the same place,
/// which is what makes [`render`]'s output stable.
type Key = (String, String, u16);

/// One histogram series.
///
/// `counts[i]` holds the observations that fell into slot `i`, i.e.
/// `BUCKETS[i-1] < v <= BUCKETS[i]`, with the last slot reserved for `+Inf`.
/// The `_bucket{le=…}` lines are the cumulative sums of those slots and are
/// computed in [`render`], never stored — otherwise every observation would
/// have to touch all remaining buckets.
struct Buckets {
    /// Per-bucket observation counts (non-cumulative). `AtomicU64` so the
    /// request path never needs the write lock or a mutable borrow.
    counts: [AtomicU64; FINITE_BUCKETS + 1],
    /// Sum of observed durations in **nanoseconds**; see the module docs for why
    /// this is an integer rather than an atomic `f64`.
    sum_ns: AtomicU64,
    /// Number of observations; equals the `+Inf` bucket.
    count: AtomicU64,
}

impl Buckets {
    fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_ns: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record one duration. `Relaxed` everywhere: these counters are monotone and
    /// independent of one another, and a scrape tolerates reading them
    /// mid-flight (a bucket may momentarily disagree with `_count` by one, which
    /// Prometheus handles — it only needs a monotone counter between scrapes).
    fn observe(&self, secs: f64) {
        // Clock skew or a caller bug must not poison the series: NaN and
        // negative values are clamped, infinite ones would overflow the sum.
        let secs = if secs.is_finite() && secs > 0.0 {
            secs
        } else {
            0.0
        };
        let slot = BUCKETS
            .iter()
            .position(|&b| secs <= b)
            .unwrap_or(FINITE_BUCKETS);
        if let Some(c) = self.counts.get(slot) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        let ns = (secs * 1e9) as u64;
        self.sum_ns.fetch_add(ns, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// The process-wide registry.
///
/// `LazyLock` rather than a `OnceLock<Box<…>>`: no `Option` to unwrap, and the
/// map is only allocated on the first request of a build that records metrics at
/// all.
static REGISTRY: LazyLock<RwLock<HashMap<Key, Arc<Buckets>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Record one completed HTTP request.
///
/// `route` is stored **verbatim** as the `route` label, so pass
/// [`route_label`]'s output (call it once per request; it is not free). Passing
/// a raw path also works but bypasses the cardinality reasoning and relies on
/// [`MAX_SERIES`] alone.
///
/// Cost: a read lock plus one `Arc` clone for an existing series — the counters
/// are subsequently bumped on the `Arc` after the guard is dropped. A new series
/// costs one write lock, once ever.
pub fn record(route: &str, method: &str, status: u16, secs: f64) {
    let key: Key = (route.to_owned(), method.to_owned(), status);

    // Poisoning-recoverable read, like the rest of the crate: a panicking
    // registrar must not turn into a panic on every subsequent request.
    let existing = match REGISTRY.read() {
        Ok(map) => map.get(&key).map(Arc::clone),
        Err(poisoned) => poisoned.into_inner().get(&key).map(Arc::clone),
    };

    let buckets = match existing {
        Some(buckets) => buckets,
        None => admit(key),
    };
    buckets.observe(secs);
}

/// Insert-and-return for a series that is not in the map yet.
///
/// This is the only place that takes the write lock, and [`record`] calls it
/// only after a read-locked lookup missed. The map is re-checked under the lock:
/// another thread may have created the same series between our read and our
/// write, and inserting it twice would split one histogram into two.
fn admit(mut key: Key) -> Arc<Buckets> {
    let mut map = match REGISTRY.write() {
        Ok(map) => map,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(buckets) = map.get(&key) {
        return Arc::clone(buckets);
    }

    // Cardinality guard. The scan is O(n) but only runs for a brand-new series
    // (≤ MAX_SERIES times in the life of the process) and `n <= MAX_SERIES`, so
    // it never touches the per-request path.
    if key.0 != OTHER_ROUTE {
        let distinct = map.keys().filter(|k| k.0 != OTHER_ROUTE).count();
        if distinct >= MAX_SERIES {
            key.0 = OTHER_ROUTE.to_owned();
            if let Some(buckets) = map.get(&key) {
                return Arc::clone(buckets);
            }
        }
    }

    let buckets = Arc::new(Buckets::new());
    map.insert(key, Arc::clone(&buckets));
    buckets
}

/// Prometheus text lines for every recorded series (empty when nothing was
/// recorded).
///
/// The `# HELP`/`# TYPE` pair is emitted once per call, never per series, and
/// the series themselves are sorted by `(route, method, status)` so two scrapes
/// of an unchanged gateway produce byte-identical bodies — otherwise every
/// sample looks like churn to a text diff and to `promtool`.
///
/// The read lock is held while formatting, which blocks only the creation of a
/// brand-new series (never an in-flight `record` of a known one) for the
/// duration of one scrape.
pub fn render() -> String {
    let map = match REGISTRY.read() {
        Ok(map) => map,
        Err(poisoned) => poisoned.into_inner(),
    };
    if map.is_empty() {
        return String::new();
    }

    let mut keys: Vec<&Key> = map.keys().collect();
    keys.sort();

    let mut out = String::with_capacity(256 * keys.len());
    let _ = writeln!(
        out,
        "# HELP {METRIC_NAME} HTTP request duration in seconds, by route, method and status.\n\
         # TYPE {METRIC_NAME} histogram"
    );

    for key in keys {
        let Some(buckets) = map.get(key) else {
            // Unreachable while the read guard is held; skipping beats unwrapping.
            continue;
        };
        let (route, method, status) = key;
        let labels = format!(
            "route=\"{}\",method=\"{}\",status=\"{status}\"",
            esc(route),
            esc(method)
        );

        let mut cumulative = 0u64;
        for (le, slot) in BUCKETS_LE.iter().zip(buckets.counts.iter()) {
            cumulative = cumulative.saturating_add(slot.load(Ordering::Relaxed));
            let _ = writeln!(
                out,
                "{METRIC_NAME}_bucket{{{labels},le=\"{le}\"}} {cumulative}"
            );
        }
        let sum = buckets.sum_ns.load(Ordering::Relaxed);
        let _ = writeln!(out, "{METRIC_NAME}_sum{{{labels}}} {}", fmt_secs(sum));
        let _ = writeln!(
            out,
            "{METRIC_NAME}_count{{{labels}}} {}",
            buckets.count.load(Ordering::Relaxed)
        );
    }
    out
}

/// Label used for routes: collapse path parameters so cardinality stays bounded.
///
/// Rules, in order:
///
/// * an exact match against the router's surface (`/v1/chat/completions`,
///   `/api/providers/update`, `/metrics`, …) is kept verbatim;
/// * anything below `/dashboard/` — the SPA's hashed asset names — becomes
///   `/dashboard/*`;
/// * `/api/<resource>/<anything-not-a-known-action>` keeps the resource and
///   hides the parameter: `/api/foo/12345` → `/api/foo/{id}`;
/// * everything else — `/api/<unknown>`, `/v1/<unknown>`, `/` — becomes `other`.
///
/// The result is idempotent, so feeding a label back in is a no-op.
pub fn route_label(path: &str) -> String {
    // Tolerate a query string and trailing slashes: `/dashboard/` is the same
    // route as `/dashboard`.
    let path = path.split('?').next().unwrap_or_default();
    let trimmed = path.trim_end_matches('/');
    let path = if trimmed.is_empty() { "/" } else { trimmed };

    if STATIC_ROUTES.contains(&path) {
        return path.to_owned();
    }
    if path.starts_with("/dashboard/") {
        // Only sub-paths reach here: `/dashboard/` was trimmed to `/dashboard`
        // above, so a bare entry point stays its own series.
        return "/dashboard/*".to_owned();
    }
    if let Some(rest) = path.strip_prefix("/api/") {
        return api_label(rest);
    }
    OTHER_ROUTE.to_owned()
}

/// `/api/*` tail → bounded label. `rest` has no leading slash.
fn api_label(rest: &str) -> String {
    let mut segments = rest.split('/').filter(|s| !s.is_empty());
    let Some(resource) = segments.next() else {
        return OTHER_ROUTE.to_owned();
    };
    // Exact routes are handled by STATIC_ROUTES; a resource that is not even
    // slug-shaped (`%2e%2e`, a 4 KiB injection attempt) is noise, not a route.
    if !is_slug(resource) {
        return OTHER_ROUTE.to_owned();
    }
    match segments.next() {
        // Unknown single-segment resource: nothing to collapse, so do not invent
        // a series for it.
        None => OTHER_ROUTE.to_owned(),
        // Unknown shape under a known-looking resource, or an id under an
        // unknown one: keep the resource, hide the parameter. Deeper paths are
        // folded into the same label.
        Some(_) => format!("/api/{resource}/{{id}}"),
    }
}

/// `[a-z0-9_-]`, at most 32 bytes: enough for every real path segment, short
/// enough that a hostile one cannot become a large label value.
fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Escape a Prometheus label value: `\`, `"` and newlines only.
///
/// Byte-for-byte the same rule as `api::metrics::esc`, which is private to that
/// module. Duplicating twelve lines keeps `/metrics` untouched; the shared rule
/// is pinned by a test here and by `label_values_are_escaped` there.
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

/// Seconds from nanoseconds, without exponent notation and without trailing
/// zeros: `730_500_000` → `0.7305`, `0` → `0`.
fn fmt_secs(ns: u64) -> String {
    let s = format!("{:.9}", ns as f64 / 1e9);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() {
        "0".to_owned()
    } else {
        s.to_owned()
    }
}

/// Drop every recorded series. **Tests only.**
///
/// The registry is process-wide, so a test that asserts on the *whole* body
/// needs a known starting point. Every test that calls this (or reads the
/// registry) holds `tests::TEST_LOCK`, which serialises them regardless of the
/// order the harness runs them in.
#[cfg(test)]
pub fn reset() {
    let mut map = match REGISTRY.write() {
        Ok(map) => map,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises the tests that touch the process-wide registry, because each of
    /// them starts with [`reset`]. Without it a parallel test could wipe the
    /// other's series mid-assertion; with it, every test observes exactly the
    /// series it recorded, in any execution order.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Last field of the first line beginning with `prefix`, as an integer.
    fn int_field(body: &str, prefix: &str) -> Option<u64> {
        body.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
    }

    /// Last field of the first line beginning with `prefix`, as a float.
    fn float_field(body: &str, prefix: &str) -> Option<f64> {
        body.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
    }

    #[test]
    fn route_label_keeps_the_router_surface() {
        for path in [
            "/v1/chat/completions",
            "/v1/embeddings",
            "/v1/fim/completions",
            "/v1/models",
            "/api/providers/update",
            "/api/client-keys",
            "/api/models/enable-all",
            "/metrics",
            "/healthz",
            "/dashboard",
        ] {
            assert_eq!(route_label(path), path, "{path} should be verbatim");
        }
    }

    #[test]
    fn route_label_is_idempotent() {
        for path in [
            "/v1/chat/completions",
            "/api/providers/update",
            "/api/foo/12345",
            "/dashboard/assets/app-1a2b3c.js",
            "/nope",
        ] {
            let once = route_label(path);
            assert_eq!(route_label(&once), once, "{path} is not idempotent");
        }
    }

    #[test]
    fn route_label_collapses_ids_and_assets() {
        // Known resource, unknown action → keep the resource, hide the parameter.
        assert_eq!(route_label("/api/foo/12345"), "/api/foo/{id}");
        assert_eq!(route_label("/api/providers/8675309"), "/api/providers/{id}");
        // Deeper paths collapse into the same series as their two-segment form.
        assert_eq!(route_label("/api/foo/1/2/3"), "/api/foo/{id}");
        // Dashboard assets: bounded by construction.
        assert_eq!(route_label("/dashboard/"), "/dashboard");
        assert_eq!(
            route_label("/dashboard/assets/index-D3adB33f.js"),
            "/dashboard/*"
        );
        // Query strings and trailing slashes are not part of the route.
        assert_eq!(
            route_label("/v1/chat/completions?stream=1"),
            "/v1/chat/completions"
        );
        assert_eq!(route_label("/metrics/"), "/metrics");
    }

    #[test]
    fn route_label_unknown_paths_become_other() {
        for path in [
            "/",
            "",
            "/favicon.ico",
            "/v1/unknown/thing",
            "/api",
            "/api/",
            "/api/12345",
            "/admin",
        ] {
            assert_eq!(route_label(path), "other", "{path} should fold to other");
        }
    }

    #[test]
    fn observations_land_in_the_matching_buckets() {
        let _guard = guard();
        reset();

        let route = "/v1/test/buckets";
        let body_prefix =
            format!("{METRIC_NAME}_bucket{{route=\"{route}\",method=\"POST\",status=\"200\",le=");
        // 0.0005 → le=0.001; 0.03 → le=0.05; 0.7 → le=1.
        for secs in [0.0005, 0.03, 0.7] {
            record(route, "POST", 200, secs);
        }
        let body = render();

        // Cumulative counts: the three observations are in le=0.001, le=0.05 and
        // le=1 respectively, so everything below 0.05 holds 1 (the first one),
        // 0.05..0.5 holds 2, and 1 and +Inf hold all 3.
        let bucket = |le: &str| int_field(&body, &format!("{body_prefix}\"{le}\"}} "));
        assert_eq!(bucket("0.001"), Some(1));
        assert_eq!(bucket("0.0025"), Some(1));
        assert_eq!(bucket("0.01"), Some(1));
        assert_eq!(bucket("0.025"), Some(1));
        assert_eq!(bucket("0.05"), Some(2));
        assert_eq!(bucket("0.25"), Some(2));
        assert_eq!(bucket("0.5"), Some(2));
        assert_eq!(bucket("1"), Some(3));
        assert_eq!(bucket("5"), Some(3));
        assert_eq!(bucket("+Inf"), Some(3));

        let labels = format!("route=\"{route}\",method=\"POST\",status=\"200\"");
        assert_eq!(
            int_field(&body, &format!("{METRIC_NAME}_count{{{labels}}}")),
            Some(3)
        );
        let sum = float_field(&body, &format!("{METRIC_NAME}_sum{{{labels}}}")).unwrap_or_default();
        assert!((sum - 0.7305).abs() < 1e-9, "sum was {sum}");
        // The +Inf bucket must agree with _count, or the scrape is inconsistent.
        assert_eq!(bucket("+Inf"), Some(3));
    }

    #[test]
    fn rendering_twice_does_not_duplicate_headers() {
        let _guard = guard();
        reset();
        record("/v1/test/render-twice", "GET", 200, 0.01);

        let first = render();
        let second = render();
        for body in [&first, &second] {
            assert_eq!(body.matches(&format!("# HELP {METRIC_NAME} ")).count(), 1);
            assert_eq!(
                body.matches(&format!("# TYPE {METRIC_NAME} histogram"))
                    .count(),
                1
            );
        }
        assert_eq!(first, second, "render must be deterministic");
    }

    #[test]
    fn render_is_empty_before_anything_is_recorded() {
        let _guard = guard();
        reset();
        assert_eq!(render(), "");
    }

    #[test]
    fn cardinality_cap_folds_overflow_into_other() {
        let _guard = guard();
        reset();

        // MAX_SERIES distinct routes, plus overflow on top of that.
        for i in 0..MAX_SERIES + 3 {
            record(&format!("/v1/test/cap/{i}"), "GET", 200, 0.002);
        }
        let body = render();

        // Only the fallback series may exist beyond the cap...
        let distinct = body
            .lines()
            .filter(|l| l.contains(&format!("{METRIC_NAME}_count{{")))
            .filter(|l| !l.contains("route=\"other\""))
            .count();
        assert_eq!(distinct, MAX_SERIES, "cap is not enforced");
        // ...and it must have absorbed all three overflow observations.
        let other = format!("{METRIC_NAME}_count{{route=\"other\",method=\"GET\",status=\"200\"}}");
        assert_eq!(int_field(&body, &other), Some(3));
        // Nothing is silently lost: the buckets still sum to every observation.
        assert_eq!(
            int_field(
                &body,
                &format!(
                    "{METRIC_NAME}_bucket{{route=\"other\",method=\"GET\",status=\"200\",le=\"+Inf\"}}"
                )
            ),
            Some(3)
        );
    }

    #[test]
    fn label_values_are_escaped() {
        let _guard = guard();
        reset();
        record("route\"with\\backslash\nand-newline", "GET", 500, 0.25);
        let body = render();
        assert!(
            body.contains(r#"route="route\"with\\backslash\nand-newline""#),
            "labels were not escaped:\n{body}"
        );
        // Every emitted line carries the escaped form: one per bucket plus
        // `_sum` and `_count`.
        let escaped = r#"route="route\"with\\backslash\nand-newline""#;
        assert_eq!(
            body.lines().filter(|l| l.contains(escaped)).count(),
            FINITE_BUCKETS + 3,
            "not every series line carries the escaped label:\n{body}"
        );
    }

    #[test]
    fn bucket_labels_match_the_boundaries() {
        assert_eq!(BUCKETS_LE.len(), BUCKETS.len() + 1);
        for (le, bound) in BUCKETS_LE.iter().zip(BUCKETS.iter()) {
            let parsed: f64 = le.parse().unwrap_or_default();
            assert!((parsed - bound).abs() < f64::EPSILON, "{le} != {bound}");
        }
        assert_eq!(BUCKETS_LE.last(), Some(&"+Inf"));
    }

    #[test]
    fn secs_formatting_has_no_exponent() {
        assert_eq!(fmt_secs(0), "0");
        assert_eq!(fmt_secs(730_500_000), "0.7305");
        assert_eq!(fmt_secs(1_000_000_000), "1");
        assert_eq!(fmt_secs(2_500_000), "0.0025");
    }
}
