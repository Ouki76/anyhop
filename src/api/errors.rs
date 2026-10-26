//! Typed error for the JSON API and gateway handlers.
//!
//! Handlers used to hand-roll `(StatusCode, String).into_response()` pairs,
//! which `json_errors` then re-wrapped into the OpenAI envelope. [`ApiError`]
//! makes the status and the envelope a single value, so a handler can return
//! `Err(ApiError::not_found("unknown provider"))` and stay `-> ApiResult`.
//!
//! The wire format is *identical* to [`crate::proxy::error_response`]:
//!
//! ```json
//! {"error":{"code":404,"message":"…","type":"not_found_error"}}
//! ```
//!
//! and the OpenAI-style `type` strings are taken from
//! [`crate::middleware::error_type`] so there is one mapping in the tree.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// An HTTP error with a client-facing message.
///
/// Pick the variant by *why* the request failed, not by how it is phrased: the
/// variant fixes the status code and therefore the OpenAI error `type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// 400 `invalid_request_error` — the request itself is malformed: a missing
    /// field, an invalid name, a value that cannot be parsed. Prefer this for
    /// anything the caller can fix by resending a corrected body.
    BadRequest(String),
    /// 401 `authentication_error` — no credential, or a credential the server
    /// does not recognise. Use for missing/incorrect master or client keys.
    Unauthorized(String),
    /// 403 `permission_error` — the caller *is* authenticated but the key is not
    /// allowed to do this (model allowlist, admin-only route).
    Forbidden(String),
    /// 404 `not_found_error` — the addressed resource does not exist: unknown
    /// provider, combo, client key or model id.
    NotFound(String),
    /// 409 `conflict_error` — the request is well-formed but clashes with the
    /// current state: duplicate key/name, or an operation already in progress.
    Conflict(String),
    /// 422 `invalid_request_error` — the request is syntactically valid but
    /// semantically rejected (e.g. a combo chain that references itself).
    /// Distinct from [`ApiError::BadRequest`] only in status.
    Unprocessable(String),
    /// 429 `rate_limit_error` — the caller exceeded a quota. Set
    /// `retry_after_secs` whenever the wait is known so a `Retry-After` header
    /// tells the client when retrying is worth it.
    TooManyRequests {
        message: String,
        retry_after_secs: Option<u64>,
    },
    /// 500 `api_error` — a server-side failure the caller cannot fix (I/O on
    /// the config file, a failed key generation). Keep the message free of
    /// secrets and internal paths.
    Internal(String),
}

impl ApiError {
    /// 400 — malformed request body.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    /// 401 — missing or unknown credential.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized(message.into())
    }

    /// 403 — authenticated but not allowed.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    /// 404 — unknown resource.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    /// 409 — conflicts with current state.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    /// 422 — valid syntax, rejected semantics.
    pub fn unprocessable(message: impl Into<String>) -> Self {
        Self::Unprocessable(message.into())
    }

    /// 429 — quota exceeded. `retry_after_secs` becomes a `Retry-After` header.
    pub fn too_many_requests(message: impl Into<String>, retry_after_secs: Option<u64>) -> Self {
        Self::TooManyRequests {
            message: message.into(),
            retry_after_secs,
        }
    }

    /// 500 — internal failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// The HTTP status this error is rendered with.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The client-facing message.
    pub fn message(&self) -> &str {
        match self {
            Self::BadRequest(m)
            | Self::Unauthorized(m)
            | Self::Forbidden(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::Unprocessable(m)
            | Self::Internal(m) => m,
            Self::TooManyRequests { message, .. } => message,
        }
    }

    /// The OpenAI-style error `type`, derived from the status so the vocabulary
    /// lives only in [`crate::middleware::error_type`].
    pub fn kind(&self) -> &'static str {
        crate::middleware::error_type(self.status())
    }

    /// `Retry-After` value for this error, if any.
    fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::TooManyRequests {
                retry_after_secs, ..
            } => *retry_after_secs,
            _ => None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let kind = self.kind();
        // Reuse the single envelope implementation instead of rebuilding the
        // JSON here; the extra header is added afterwards (same as
        // `middleware::auth` and `proxy::chat::exhausted_response` do).
        let mut resp = crate::proxy::error_response(status, self.message(), kind);
        if let Some(secs) = self.retry_after_secs()
            && let Ok(value) = axum::http::HeaderValue::from_str(&secs.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, value);
        }
        resp
    }
}

impl std::fmt::Display for ApiError {
    /// Renders as `status: message`, e.g. `404 Not Found: unknown provider`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status(), self.message())
    }
}

impl std::error::Error for ApiError {}

/// Handler return type: a produced response, or an [`ApiError`] that
/// `IntoResponse` turns into the JSON envelope.
pub type ApiResult = Result<Response, ApiError>;

/// Wrap a serialisable value as a `200 application/json` response, so a handler
/// can end with `ok_json(dto)` instead of `Ok(Json(dto).into_response())`.
pub fn ok_json<T: serde::Serialize>(value: T) -> ApiResult {
    Ok(axum::Json(value).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use serde_json::{Value, json};

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("response body is readable");
        serde_json::from_slice(&bytes).expect("response body is JSON")
    }

    fn content_type(resp: &Response) -> String {
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn every_variant_maps_to_its_status_and_type() {
        let cases = [
            (ApiError::bad_request("m"), 400, "invalid_request_error"),
            (ApiError::unauthorized("m"), 401, "authentication_error"),
            (ApiError::forbidden("m"), 403, "permission_error"),
            (ApiError::not_found("m"), 404, "not_found_error"),
            (ApiError::conflict("m"), 409, "conflict_error"),
            (ApiError::unprocessable("m"), 422, "invalid_request_error"),
            (
                ApiError::too_many_requests("m", Some(7)),
                429,
                "rate_limit_error",
            ),
            (ApiError::internal("m"), 500, "api_error"),
        ];
        for (err, status, kind) in cases {
            assert_eq!(err.status().as_u16(), status, "status for {err:?}");
            assert_eq!(err.kind(), kind, "type for {err:?}");
            // Same vocabulary as the middleware, not a copy that can drift.
            assert_eq!(err.kind(), crate::middleware::error_type(err.status()));
            assert_eq!(err.message(), "m");
        }
    }

    #[tokio::test]
    async fn body_is_the_openai_envelope() {
        let cases = [
            (
                ApiError::bad_request("name is empty"),
                400,
                "invalid_request_error",
            ),
            (
                ApiError::unauthorized("missing API key"),
                401,
                "authentication_error",
            ),
            (
                ApiError::forbidden("model not allowed for this key"),
                403,
                "permission_error",
            ),
            (
                ApiError::not_found("unknown provider"),
                404,
                "not_found_error",
            ),
            (
                ApiError::conflict("API key already exists"),
                409,
                "conflict_error",
            ),
            (
                ApiError::unprocessable("combo chain references itself"),
                422,
                "invalid_request_error",
            ),
            (
                ApiError::too_many_requests("rate limit exceeded", None),
                429,
                "rate_limit_error",
            ),
            (
                ApiError::internal("cannot generate a key"),
                500,
                "api_error",
            ),
        ];
        for (err, code, kind) in cases {
            let message = err.message().to_string();
            let resp = err.into_response();
            assert_eq!(resp.status().as_u16(), code);
            assert!(
                content_type(&resp).starts_with("application/json"),
                "content-type for {code}: {}",
                content_type(&resp)
            );
            let body = body_json(resp).await;
            assert_eq!(
                body,
                json!({"error": {
                    "code": crate::proxy::error_code_for(kind),
                    "message": message,
                    "type": kind,
                    "param": null,
                }}),
                "body for {code}"
            );
        }
    }

    #[tokio::test]
    async fn too_many_requests_sets_retry_after() {
        let resp = ApiError::too_many_requests("slow down", Some(12)).into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("12")
        );
        assert!(content_type(&resp).starts_with("application/json"));
        let body = body_json(resp).await;
        assert_eq!(body["error"]["type"], json!("rate_limit_error"));
    }

    #[tokio::test]
    async fn too_many_requests_without_retry_after_omits_the_header() {
        let resp = ApiError::too_many_requests("slow down", None).into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
        // Other variants never carry it either.
        let resp = ApiError::internal("boom").into_response();
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
    }

    #[tokio::test]
    async fn ok_json_is_200_with_json_content_type() {
        let resp = ok_json(json!({"ok": true})).expect("ok_json never fails");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(content_type(&resp).starts_with("application/json"));
        assert_eq!(body_json(resp).await, json!({"ok": true}));
    }

    #[test]
    fn display_renders_status_and_message() {
        let err = ApiError::not_found("unknown provider");
        assert_eq!(err.to_string(), "404 Not Found: unknown provider");
        // Usable as a boxed error, e.g. with `?` in anyhow-based code.
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert_eq!(boxed.to_string(), "404 Not Found: unknown provider");
    }

    #[test]
    fn constructors_build_the_expected_variants() {
        assert_eq!(ApiError::conflict("dup").to_string(), "409 Conflict: dup");
        assert_eq!(
            ApiError::too_many_requests("later", Some(3)),
            ApiError::TooManyRequests {
                message: "later".to_string(),
                retry_after_secs: Some(3),
            }
        );
    }
}
