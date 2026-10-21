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
        && let Ok(v) = header::HeaderValue::from_str(&d.as_secs().max(1).to_string())
    {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

/// Parse OpenAI-style reset durations: "500ms", "1s", "1m30s", "2h5m".
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
        let d = match unit.as_str() {
            "ms" => Duration::from_secs_f64(v / 1000.0),
            "s" => Duration::from_secs_f64(v),
            "m" => Duration::from_secs_f64(v * 60.0),
            "h" => Duration::from_secs_f64(v * 3600.0),
            _ => return None,
        };
        total += d;
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
}
