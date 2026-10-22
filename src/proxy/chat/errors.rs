//! Upstream error classification, exhaustion responses, and Retry-After parsing.

use std::time::Duration;

use axum::http::{StatusCode, header};
use axum::response::Response;

use crate::config::ProviderKind;

use super::error_response;

/// A translating provider was reached without a parsed body — a bug in the
/// caller, not a client error. Report it as a 500 instead of panicking the task.
pub(super) fn internal_body_error() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal: request body was not parsed for a translating provider",
        "internal_error",
    )
}

/// Why one target produced no answer.
///
/// `KeyPool::pick` returning `None` is ambiguous — "every key is momentarily at
/// its in-flight cap" and "no key can serve this model" are different answers
/// for the client — so the retry loop records what actually happened instead of
/// guessing at the end.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TargetFailure {
    /// Keys are alive but every in-flight slot is taken: retry shortly.
    Capacity { attempts: usize },
    /// No key can serve the model right now (cooling down / dead / empty pool).
    Unavailable {
        attempts: usize,
        wake: Option<Duration>,
    },
    /// The upstream answered 2xx with something that is not a completion.
    BadBody {
        attempts: usize,
        content_type: String,
    },
}

/// Turn a target failure into the client's answer.
pub(super) fn failure_response(provider: &str, failure: TargetFailure) -> Response {
    match failure {
        TargetFailure::Capacity { attempts } => busy_response(provider, attempts),
        TargetFailure::Unavailable { attempts, wake } => {
            exhausted_response(provider, attempts, wake)
        }
        TargetFailure::BadBody {
            attempts,
            content_type,
        } => {
            let got = if content_type.is_empty() {
                "a body with no content type".to_string()
            } else {
                format!("'{content_type}'")
            };
            error_response(
                StatusCode::BAD_GATEWAY,
                format!(
                    "provider '{provider}' answered 2xx with {got} instead of a completion \
                     after {attempts} attempt(s)"
                ),
                "upstream_error",
            )
        }
    }
}

/// The gateway is saturated: the keys are healthy, there is simply no in-flight
/// slot free. That is "come back in a moment", not "this provider is down" — so
/// it is a 429 with a Retry-After instead of a bare 503 (and never a 503 without
/// the header, which leaves the client to guess).
pub(super) fn busy_response(provider: &str, attempts: usize) -> Response {
    let mut resp = error_response(
        StatusCode::TOO_MANY_REQUESTS,
        format!(
            "provider '{provider}' is at its concurrency limit \
             ({attempts} upstream attempt(s) made); retry shortly"
        ),
        "rate_limit_exceeded",
    );
    if let Ok(v) = header::HeaderValue::from_str("1") {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

pub(super) fn exhausted_response(
    provider: &str,
    attempts: usize,
    retry_after: Option<Duration>,
) -> Response {
    let mut resp = error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("provider '{provider}' unavailable after {attempts} attempts"),
        "provider_unavailable",
    );
    // Tell the client when it is worth retrying: without this a single-key
    // provider that just went into a 5s cooldown looks permanently down.
    if let Some(d) = retry_after
        && let Ok(v) =
            header::HeaderValue::from_str(&crate::middleware::retry_after_secs_of(d).to_string())
    {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

/// Longest cooldown a single header may request.
///
/// A reset time is attacker-influenced (it comes from the upstream's response
/// headers), and a cooldown pins keys out of rotation: allowing a day is already
/// generous, allowing a week or a millennium is a self-inflicted outage.
const MAX_RESET: Duration = Duration::from_secs(24 * 3600);

/// Parse OpenAI-style reset durations: "500ms", "1s", "1m30s", "2h5m".
///
/// Every value here is untrusted, so nothing is fed to `Duration::from_secs_f64`
/// before it is proven finite, non-negative and bounded — that constructor panics
/// on NaN/inf/out-of-range, and `"999999999999999999999999999999s"` (1e30) is a
/// perfectly legal header value.
pub(super) fn parse_reset_duration(s: &str) -> Option<Duration> {
    let mut total = Duration::ZERO;
    let mut num = String::new();
    let mut unit = String::new();
    let mut flush = |num: &mut String, unit: &mut String| -> Option<()> {
        if num.is_empty() {
            // Nothing buffered at all is fine (start/end of the string), but a
            // unit without a number is junk — accepting it silently would turn
            // "-5s" into a 5s cooldown.
            if unit.is_empty() {
                return Some(());
            }
            return None;
        }
        let v: f64 = num.parse().ok()?;
        let scale = match unit.as_str() {
            "ms" => 0.001,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        let secs = v * scale;
        if !secs.is_finite() || secs < 0.0 || secs > MAX_RESET.as_secs_f64() {
            return None;
        }
        // checked_add: a header full of components must not wrap the total.
        total = total.checked_add(Duration::from_secs_f64(secs))?;
        // Clamp instead of rejecting a *sum* that adds up to more than a day:
        // "cool down for a long time" is still a meaningful instruction, it just
        // does not get to disable the pool for a week.
        if total > MAX_RESET {
            total = MAX_RESET;
        }
        num.clear();
        unit.clear();
        Some(())
    };
    for c in s.trim().chars() {
        if c.is_ascii_digit() || c == '.' {
            if !unit.is_empty() {
                flush(&mut num, &mut unit)?;
            }
            num.push(c);
        } else if !c.is_whitespace() {
            unit.push(c);
        }
    }
    flush(&mut num, &mut unit)?;
    (total > Duration::ZERO).then_some(total)
}

/// How a non-2xx upstream status maps onto key-pool bookkeeping.
///
/// Extracted from the retry loop so the mapping is unit-testable: getting it
/// wrong is expensive (a 429 classified as Auth kills a healthy key forever).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ErrorAction {
    /// 429 from Antigravity — quota is per model, needs the parsed reset time.
    ModelQuota,
    /// 429 elsewhere — cool the whole key down, honouring Retry-After.
    RateLimited,
    /// 401/403, plus Gemini's 400 "API key not valid": never retry this key.
    Auth,
    /// 5xx — transient, back off and try another key.
    Server,
    /// The client's fault — relay the upstream error untouched.
    PassThrough,
}

pub(super) fn classify_error_status(kind: ProviderKind, status: u16, body: &str) -> ErrorAction {
    match status {
        429 => {
            if matches!(kind, ProviderKind::Antigravity) {
                ErrorAction::ModelQuota
            } else {
                ErrorAction::RateLimited
            }
        }
        401 | 403 => ErrorAction::Auth,
        // Gemini reports an invalid key as 400 INVALID_ARGUMENT, not 401.
        400 if matches!(kind, ProviderKind::Gemini) && body.contains("API key not valid") => {
            ErrorAction::Auth
        }
        s if s >= 500 => ErrorAction::Server,
        _ => ErrorAction::PassThrough,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- upstream error classification -----

    #[test]
    fn rate_limit_cools_the_key_except_for_antigravity() {
        // Antigravity reports per-model quota as 429; everything else is per key.
        assert_eq!(
            classify_error_status(ProviderKind::Antigravity, 429, ""),
            ErrorAction::ModelQuota
        );
        for kind in [
            ProviderKind::OpenaiCompat,
            ProviderKind::Gemini,
            ProviderKind::Anthropic,
            ProviderKind::Codex,
        ] {
            assert_eq!(
                classify_error_status(kind, 429, ""),
                ErrorAction::RateLimited,
                "{kind:?} 429 must cool the whole key"
            );
        }
    }

    #[test]
    fn auth_statuses_kill_the_key() {
        for status in [401, 403] {
            assert_eq!(
                classify_error_status(ProviderKind::OpenaiCompat, status, ""),
                ErrorAction::Auth
            );
        }
    }

    #[test]
    fn gemini_invalid_key_is_detected_by_body() {
        // Gemini answers 400 INVALID_ARGUMENT instead of 401 for a bad key.
        assert_eq!(
            classify_error_status(
                ProviderKind::Gemini,
                400,
                r#"{"error":"API key not valid. Please pass a valid API key."}"#
            ),
            ErrorAction::Auth
        );
        // The same body from another provider must NOT kill the key — their 400s
        // are request errors.
        assert_eq!(
            classify_error_status(ProviderKind::OpenaiCompat, 400, "API key not valid"),
            ErrorAction::PassThrough
        );
        // A Gemini 400 for a genuinely bad request stays a client error.
        assert_eq!(
            classify_error_status(ProviderKind::Gemini, 400, r#"{"error":"invalid contents"}"#),
            ErrorAction::PassThrough
        );
    }

    #[test]
    fn server_and_client_errors_are_separated() {
        for status in [500, 502, 503, 504, 529] {
            assert_eq!(
                classify_error_status(ProviderKind::OpenaiCompat, status, ""),
                ErrorAction::Server,
                "{status} must be retried on another key"
            );
        }
        for status in [400, 404, 422] {
            assert_eq!(
                classify_error_status(ProviderKind::OpenaiCompat, status, ""),
                ErrorAction::PassThrough,
                "{status} must reach the client unchanged"
            );
        }
    }

    // ----- how a target failure is answered -----

    /// A saturated gateway must say "retry shortly" *with* a Retry-After, not
    /// "unavailable after 4 attempts" (which also lied about the attempt count).
    #[test]
    fn a_saturated_gateway_answers_429_with_retry_after() {
        let resp = busy_response("openai", 0);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024);
        let body = futures::executor::block_on(body).expect("the body collects");
        let v: serde_json::Value = serde_json::from_slice(&body).expect("JSON envelope");
        assert_eq!(v["error"]["type"], "rate_limit_exceeded");
        assert_eq!(v["error"]["code"], 429);
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("0 upstream attempt"),
            "{v}"
        );
    }

    /// A 2xx in the wrong protocol is an upstream failure with its own answer.
    #[test]
    fn a_non_completion_body_is_a_502_naming_the_content_type() {
        let resp = failure_response(
            "upstream",
            TargetFailure::BadBody {
                attempts: 2,
                content_type: "text/html".into(),
            },
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// The exhaustion message must carry the attempts that were really made.
    #[test]
    fn exhaustion_reports_the_real_attempt_count() {
        let resp = failure_response(
            "upstream",
            TargetFailure::Unavailable {
                attempts: 0,
                wake: Some(Duration::from_secs(3)),
            },
        );
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = futures::executor::block_on(axum::body::to_bytes(resp.into_body(), 64 * 1024))
            .expect("the body collects");
        let v: serde_json::Value = serde_json::from_slice(&body).expect("JSON envelope");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("after 0 attempts"),
            "{v}"
        );
    }

    // ----- Retry-After / x-ratelimit-reset parsing -----

    #[test]
    fn reset_durations_parse_the_openai_style_formats() {
        assert_eq!(
            parse_reset_duration("500ms"),
            Some(Duration::from_millis(500))
        );
        assert_eq!(parse_reset_duration("1s"), Some(Duration::from_secs(1)));
        assert_eq!(parse_reset_duration("1m30s"), Some(Duration::from_secs(90)));
        assert_eq!(
            parse_reset_duration("2h5m"),
            Some(Duration::from_secs(2 * 3600 + 5 * 60))
        );
        assert_eq!(parse_reset_duration("  7s  "), Some(Duration::from_secs(7)));
        assert_eq!(
            parse_reset_duration("1.5s"),
            Some(Duration::from_millis(1500))
        );
    }

    #[test]
    fn garbage_reset_durations_are_rejected_not_guessed() {
        // Returning Some(0) would pin a key into an endless zero-length cooldown
        // loop; returning None makes the caller use its documented fallback.
        assert_eq!(parse_reset_duration(""), None);
        assert_eq!(parse_reset_duration("soon"), None);
        assert_eq!(parse_reset_duration("5x"), None);
        assert_eq!(parse_reset_duration("0s"), None);
        assert_eq!(parse_reset_duration("-5s"), None);
    }

    /// A hostile header used to reach `Duration::from_secs_f64(1e30)`, which
    /// panics — in the retry loop, so the connection (and the task) died.
    #[test]
    fn an_absurd_reset_header_is_rejected_without_panicking() {
        for hostile in [
            "999999999999999999999999999999s",
            "999999999999999999999999999999999999999999999999ms",
            "999999999999999999999999999999m",
            "999999999999999999999999999999h",
            "1e300s",
            // 25h in one component: beyond the ceiling, refused outright.
            "90000s",
            "25h",
        ] {
            assert_eq!(parse_reset_duration(hostile), None, "{hostile}");
        }
        // ...and a real long cooldown still parses, clamped to the ceiling.
        assert_eq!(parse_reset_duration("24h"), Some(MAX_RESET));
        assert_eq!(
            parse_reset_duration("1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h1h"),
            Some(MAX_RESET),
            "a total over the ceiling is clamped, not wrapped or rejected"
        );
        assert_eq!(
            parse_reset_duration("3h30m"),
            Some(Duration::from_secs(3 * 3600 + 30 * 60))
        );
    }

    /// `total += d` overflowed before; many components now stay bounded.
    #[test]
    fn many_components_cannot_overflow_the_total() {
        let mut s = String::new();
        for _ in 0..100_000 {
            s.push_str("23h59m");
        }
        assert_eq!(parse_reset_duration(&s), Some(MAX_RESET));
    }
}
