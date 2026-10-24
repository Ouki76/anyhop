//! Successful-upstream responses: buffering, translation, and zero-copy streaming.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde_json::Value;

use crate::anthropic;
use crate::antigravity;
use crate::codex;
use crate::config::ProviderKind;
use crate::gemini;
use crate::pool::{KeyGuard, KeyState};
use crate::providers::Provider;

use super::error_response;

/// A translated/pass-through upstream body.
pub(super) type BodyStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// What the retry loop hands over once a 2xx is accepted.
pub(super) enum Upstream {
    /// The body is still attached to its response. Only the codex backend needs
    /// this: its own parser owns the whole exchange.
    Attached(reqwest::Response),
    /// The head is in, and the body stream has already produced its first chunk
    /// under a deadline (see [`open_body`]).
    Opened {
        status: StatusCode,
        /// Upstream headers worth relaying, already filtered (see [`forward_header`]).
        headers: Vec<(header::HeaderName, HeaderValue)>,
        stream: BodyStream,
    },
}

/// Upper bound on a buffered (non-stream) upstream body.
///
/// Only *request* bodies were bounded (`server.max_body_bytes`); a 2xx answer was
/// read into memory with an idle deadline but no size limit, so an upstream (or a
/// proxy in front of one) that slow-drips an endless body made the gateway
/// accumulate gigabytes. 64 MiB is far above any chat completion but leaves room
/// for inline base64 media.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Why a 2xx upstream had no usable body.
#[derive(Debug)]
pub(super) enum BodyError {
    /// The first byte never arrived inside the attempt timeout.
    Idle(Duration),
    /// The connection died while reading.
    Upstream(String),
    /// The body grew past [`MAX_RESPONSE_BYTES`].
    TooLarge(usize),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle(d) => write!(f, "upstream sent no body within {:?}", d),
            Self::Upstream(e) => write!(f, "upstream body failed: {e}"),
            Self::TooLarge(n) => write!(
                f,
                "upstream body exceeds the {MAX_RESPONSE_BYTES}-byte limit ({n} bytes received)"
            ),
        }
    }
}

/// Wait for the first body chunk, then hand the body back as a stream.
///
/// `req.send()` resolving only means the *headers* arrived: an upstream that
/// sends `200 text/event-stream` and then goes silent used to hold the client
/// (0 bytes for as long as the socket lived) and the key's in-flight slot for
/// ever. The first byte is awaited here, inside the retry loop, so a silent
/// upstream can be retried on another key and reported as a server failure.
pub(super) async fn open_body(
    resp: reqwest::Response,
    idle: Duration,
) -> Result<Upstream, BodyError> {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
    let headers: Vec<_> = resp
        .headers()
        .iter()
        .filter(|(n, _)| forward_header(n))
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect();
    let mut body = resp.bytes_stream();
    let first = match tokio::time::timeout(idle, body.next()).await {
        Err(_) => return Err(BodyError::Idle(idle)),
        Ok(None) => None,
        Ok(Some(Ok(chunk))) => Some(chunk),
        Ok(Some(Err(e))) => return Err(BodyError::Upstream(e.to_string())),
    };
    let head = futures::stream::iter(first.map(Ok::<Bytes, std::io::Error>));
    let rest = body.map(|chunk| chunk.map_err(|e| std::io::Error::other(e.to_string())));
    Ok(Upstream::Opened {
        status,
        headers,
        stream: Box::pin(head.chain(rest)),
    })
}

/// Fail the stream when the upstream goes quiet for `idle`, first chunk included.
///
/// The translators turn this into a terminal error frame, so a stalled stream
/// ends with a signal instead of a truncated answer.
pub(super) fn idle_body(stream: BodyStream, idle: Duration) -> BodyStream {
    struct State {
        inner: BodyStream,
        idle: Duration,
        done: bool,
    }
    let state = State {
        inner: stream,
        idle,
        done: false,
    };
    Box::pin(futures::stream::unfold(state, |mut s| async move {
        if s.done {
            return None;
        }
        let item = {
            let next = s.inner.next();
            futures::pin_mut!(next);
            tokio::time::timeout(s.idle, next).await
        };
        match item {
            Ok(Some(Ok(chunk))) => Some((Ok(chunk), s)),
            Ok(Some(Err(e))) => {
                s.done = true;
                Some((Err(e), s))
            }
            Ok(None) => None,
            Err(_) => {
                s.done = true;
                Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("upstream body idle for {:?}", s.idle),
                    )),
                    s,
                ))
            }
        }
    }))
}

/// Read a whole body, with the same idle deadline on every read.
async fn read_all(mut stream: BodyStream, idle: Duration) -> Result<Bytes, BodyError> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(idle, stream.next()).await {
            Err(_) => return Err(BodyError::Idle(idle)),
            Ok(None) => return Ok(Bytes::from(out)),
            Ok(Some(Ok(chunk))) => {
                if out.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                    return Err(BodyError::TooLarge(out.len().saturating_add(chunk.len())));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(Some(Err(e))) => return Err(BodyError::Upstream(e.to_string())),
        }
    }
}

/// `text/HTML; charset=utf-8` -> `text/html`.
fn normalize_content_type(raw: &str) -> String {
    raw.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// The content type of a response head, normalized for [`accept_2xx`].
pub(super) fn content_type_of(resp: &reqwest::Response) -> String {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(normalize_content_type)
        .unwrap_or_default()
}

/// Is a 2xx upstream actually speaking our protocol?
///
/// An upstream error page (`200 text/html` from nginx) used to be relayed as a
/// successful completion: the client parsed garbage, `report_success` ran, and
/// nothing in the health counters noticed. The gateway is a protocol proxy — a
/// body in the wrong protocol is an upstream failure.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Accepted {
    Ok,
    WrongContentType(String),
}

pub(super) fn accept_2xx(kind: ProviderKind, is_stream: bool, raw_content_type: &str) -> Accepted {
    let content_type = normalize_content_type(raw_content_type);
    // Codex's backend answers a stream even for a non-stream client request.
    let wants_sse = is_stream || matches!(kind, ProviderKind::Codex);
    if wants_sse {
        return if content_type == "text/event-stream" {
            Accepted::Ok
        } else {
            Accepted::WrongContentType(content_type.to_string())
        };
    }
    if content_type.is_empty()
        || content_type == "application/json"
        || content_type.ends_with("+json")
    {
        // An absent type is not evidence of an error page; the body still has to
        // parse as JSON below.
        return Accepted::Ok;
    }
    Accepted::WrongContentType(content_type.to_string())
}

/// Is this a JSON content type (`application/json`, `*+json`)?
///
/// Separates "the upstream speaks JSON, not SSE" from "the upstream sent an error
/// page". The first is a shape mismatch a client can trigger at will (send
/// `stream: true` to a compat proxy that ignores it); it must not be booked as a
/// key-health failure, or one client benches the provider for everyone.
pub(super) fn is_json_like(content_type: &str) -> bool {
    content_type == "application/json" || content_type.ends_with("+json")
}

/// Build the client response for a successful upstream call.
///
/// `idle` bounds every read of the upstream body; a translator reports a stall
/// as a terminal error frame, a buffered read as a 502.
pub(super) async fn success_response(
    provider: &Provider,
    model: &str,
    body: Upstream,
    is_stream: bool,
    key: Arc<KeyState>,
    guard: KeyGuard,
) -> Response {
    let idle = provider.timeout;
    match provider.kind {
        ProviderKind::Codex => {
            let Upstream::Attached(resp) = body else {
                drop(guard);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal: the codex body was consumed before its parser ran",
                    "internal_error",
                );
            };
            if is_stream {
                let stream = codex::translate_sse_stream(resp, model, Some(key));
                let stream = stream.map(move |item| {
                    let _ = &guard; // keep the in-flight slot until the stream ends
                    item
                });
                sse_response(stream)
            } else {
                // Codex backend is stream-only; collect the SSE stream.
                let collected = codex::collect_non_stream(resp, model).await;
                drop(guard);
                match collected {
                    Ok(v) => {
                        if let Some(u) = v.get("usage") {
                            add_usage(
                                &key,
                                u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                                u.get("completion_tokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0),
                            );
                        }
                        Json(v).into_response()
                    }
                    Err(e) => error_response(
                        StatusCode::BAD_GATEWAY,
                        format!("codex stream collect failed: {e}"),
                        "upstream_error",
                    ),
                }
            }
        }
        ProviderKind::OpenaiCompat => {
            let Upstream::Opened {
                status,
                headers,
                stream,
            } = body
            else {
                drop(guard);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal: an opened upstream body was expected",
                    "internal_error",
                );
            };
            if is_stream {
                pass_through(status, headers, idle_body(stream, idle), guard)
            } else {
                // Read first, release second: dropping the guard before the read
                // removed the pool's backpressure exactly for the unbounded part.
                let read = read_all(stream, idle).await;
                drop(guard);
                match read {
                    Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(v) => {
                            add_openai_usage(&key, &v);
                            let mut b = Response::builder().status(status);
                            for (n, v) in headers {
                                b = b.header(n, v);
                            }
                            b.body(Body::from(bytes)).unwrap_or_else(|_| {
                                StatusCode::INTERNAL_SERVER_ERROR.into_response()
                            })
                        }
                        // A JSON content type with a non-JSON body is still an
                        // upstream fault: never relay it as a completion.
                        Err(e) => error_response(
                            StatusCode::BAD_GATEWAY,
                            format!("upstream body is not a completion: {e}"),
                            "upstream_error",
                        ),
                    },
                    Err(e) => {
                        error_response(StatusCode::BAD_GATEWAY, format!("{e}"), "upstream_error")
                    }
                }
            }
        }
        ProviderKind::Gemini | ProviderKind::Antigravity | ProviderKind::Anthropic => {
            let Upstream::Opened { stream, .. } = body else {
                drop(guard);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal: an opened upstream body was expected",
                    "internal_error",
                );
            };
            let envelope = matches!(provider.kind, ProviderKind::Antigravity);
            if is_stream {
                let stream = idle_body(stream, idle);
                let stream: BodyStream = match provider.kind {
                    ProviderKind::Anthropic => Box::pin(anthropic::translate_sse_stream_from(
                        stream,
                        model,
                        Some(key),
                    )),
                    _ => Box::pin(gemini::translate_sse_stream_from(
                        stream,
                        model,
                        envelope,
                        Some(key),
                    )),
                };
                let stream = stream.map(move |item| {
                    let _ = &guard; // keep the in-flight slot until the stream ends
                    item
                });
                sse_response(stream)
            } else {
                let read = read_all(stream, idle).await;
                drop(guard);
                match read {
                    Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(v) => {
                            if matches!(provider.kind, ProviderKind::Anthropic) {
                                let u = v.get("usage").cloned().unwrap_or(Value::Null);
                                add_usage(
                                    &key,
                                    u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                                    u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                                );
                                Json(anthropic::translate_response(model, &v)).into_response()
                            } else {
                                let v = if envelope {
                                    antigravity::unwrap_response(v)
                                } else {
                                    v
                                };
                                let (p, c) = gemini::usage_pair(&v);
                                add_usage(&key, p, c);
                                Json(gemini::translate_response(model, &v)).into_response()
                            }
                        }
                        Err(e) => error_response(
                            StatusCode::BAD_GATEWAY,
                            format!("invalid upstream JSON: {e}"),
                            "upstream_error",
                        ),
                    },
                    Err(e) => {
                        error_response(StatusCode::BAD_GATEWAY, format!("{e}"), "upstream_error")
                    }
                }
            }
        }
    }
}

fn sse_response(
    stream: impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn add_usage(key: &KeyState, prompt: u64, completion: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    key.prompt_tokens.fetch_add(prompt, Relaxed);
    key.completion_tokens.fetch_add(completion, Relaxed);
}

/// Pull `usage` out of an OpenAI-compatible completion.
fn add_openai_usage(key: &KeyState, v: &Value) {
    if let Some(u) = v.get("usage") {
        add_usage(
            key,
            u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
            u.get("completion_tokens")
                .and_then(|x| x.as_u64())
                .unwrap_or(0),
        );
    }
}

/// Upstream response headers worth relaying on a pass-through. Deliberately an
/// allowlist: hop-by-hop headers (content-length, transfer-encoding, connection)
/// describe the upstream framing, not ours, and must never be copied.
fn forward_header(name: &reqwest::header::HeaderName) -> bool {
    use reqwest::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, RETRY_AFTER};
    matches!(*name, CONTENT_TYPE | CACHE_CONTROL | ETAG | RETRY_AFTER)
        || name.as_str().starts_with("x-ratelimit-")
        || name.as_str() == "x-request-id"
        || name.as_str() == "openai-processing-ms"
        || name.as_str() == "openai-version"
}

/// Pass an upstream 2xx body through to the client with zero buffering.
/// The guard keeps the key's in-flight slot until the stream ends.
///
/// A failure mid-body (dead connection, idle deadline) must not look like a
/// finished answer: the relay closes with an OpenAI-style error frame followed by
/// `[DONE]`, so the client can tell truncation from success.
fn pass_through(
    status: StatusCode,
    headers: Vec<(header::HeaderName, HeaderValue)>,
    stream: BodyStream,
    guard: KeyGuard,
) -> Response {
    let stream =
        futures::stream::unfold((Some(stream), Some(guard)), |(inner, guard)| async move {
            let mut inner = inner?;
            match inner.next().await {
                Some(Ok(chunk)) => Some((Ok::<Bytes, std::io::Error>(chunk), (Some(inner), guard))),
                Some(Err(e)) => {
                    let frame = crate::sse::frame(&serde_json::json!({
                        "error": {
                            "message": format!("upstream stream error: {e}"),
                            "type": "upstream_error",
                        }
                    }));
                    // Blank line first: terminate any event that was cut in half.
                    let mut out = bytes::BytesMut::from(&b"\n\n"[..]);
                    out.extend_from_slice(&frame);
                    out.extend_from_slice(crate::sse::DONE_FRAME);
                    Some((Ok::<Bytes, std::io::Error>(out.freeze()), (None, guard)))
                }
                None => None,
            }
        });
    let mut builder = Response::builder().status(status);
    for (n, v) in headers {
        builder = builder.header(n, v);
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- response header allowlist -----

    #[test]
    fn only_safe_upstream_headers_are_relayed() {
        use reqwest::header::{CONNECTION, CONTENT_LENGTH, HeaderName, TRANSFER_ENCODING};
        for ok in [
            "content-type",
            "cache-control",
            "etag",
            "retry-after",
            "x-request-id",
        ] {
            assert!(
                forward_header(&HeaderName::from_static(ok)),
                "{ok} should be relayed"
            );
        }
        assert!(forward_header(
            &HeaderName::from_bytes(b"x-ratelimit-remaining-requests").unwrap()
        ));
        // Hop-by-hop / framing headers describe the upstream connection, not ours.
        for bad in [CONTENT_LENGTH, TRANSFER_ENCODING, CONNECTION] {
            assert!(!forward_header(&bad), "{bad} must never be copied");
        }
        assert!(!forward_header(&HeaderName::from_static("set-cookie")));
        assert!(!forward_header(&HeaderName::from_static("authorization")));
    }

    // ----- 2xx bodies that are not completions -----

    /// An nginx error page (`200 text/html`) used to be relayed as a completion.
    #[test]
    fn a_200_html_page_is_not_a_completion() {
        assert_eq!(
            accept_2xx(ProviderKind::OpenaiCompat, false, "text/html"),
            Accepted::WrongContentType("text/html".into())
        );
        assert_eq!(
            accept_2xx(ProviderKind::OpenaiCompat, true, "text/html"),
            Accepted::WrongContentType("text/html".into())
        );
        assert_eq!(
            accept_2xx(ProviderKind::Gemini, false, "text/plain"),
            Accepted::WrongContentType("text/plain".into())
        );
        assert_eq!(
            accept_2xx(ProviderKind::Anthropic, false, "image/png"),
            Accepted::WrongContentType("image/png".into())
        );
    }

    #[test]
    fn real_completions_and_streams_are_accepted() {
        assert_eq!(
            accept_2xx(ProviderKind::OpenaiCompat, false, "application/json"),
            Accepted::Ok
        );
        assert_eq!(
            accept_2xx(
                ProviderKind::Gemini,
                false,
                "application/json; charset=utf-8"
            ),
            Accepted::Ok
        );
        assert_eq!(
            accept_2xx(ProviderKind::Anthropic, true, "text/event-stream"),
            Accepted::Ok
        );
        // Codex streams even when the client asked for a plain completion.
        assert_eq!(
            accept_2xx(ProviderKind::Codex, false, "text/event-stream"),
            Accepted::Ok
        );
        // An untyped body is not evidence of an error page: the JSON parse below
        // is the real gate.
        assert_eq!(
            accept_2xx(ProviderKind::OpenaiCompat, false, ""),
            Accepted::Ok
        );
    }

    // ----- body deadlines -----

    fn provider(source: &str) -> Provider {
        let cfg: crate::config::ProviderConfig =
            toml::from_str(source).expect("test provider config");
        Provider::from_config(
            &cfg,
            None,
            None,
            None,
            Arc::new(crate::config::Tuning::default()),
            Duration::from_secs(30),
            1,
        )
        .expect("the provider builds offline")
    }

    const OPENAI_PROVIDER: &str = r#"
        name = "up"
        type = "openai_compat"
        base_url = "http://127.0.0.1:1/v1"
        keys = ["sk-test"]
        models = ["m"]
    "#;

    /// A translating provider: its stream goes through the SSE parser before it
    /// reaches the client, which is a separate place to lose the slot.
    const ANTHROPIC_PROVIDER: &str = r#"
        name = "up"
        type = "anthropic"
        base_url = "http://127.0.0.1:1"
        keys = ["sk-test"]
        models = ["m"]
    "#;

    /// `200` and then silence: the first-byte deadline must fail the attempt so
    /// the retry loop can bench the key, instead of holding the client forever.
    #[tokio::test]
    async fn a_body_that_never_starts_arrives_is_a_timeout() {
        let resp =
            crate::sse::test_support::silent_body("text/event-stream", Duration::from_secs(2))
                .await;
        let Err(err) = open_body(resp, Duration::from_millis(100)).await else {
            panic!("a silent body must not open");
        };
        assert!(matches!(err, BodyError::Idle(_)), "{err}");
        assert!(err.to_string().contains("no body"), "{err}");
    }

    /// The first chunk must not be lost by watching for it.
    #[tokio::test]
    async fn the_first_chunk_is_replayed_to_the_translator() {
        let resp = crate::sse::test_support::sse_response(vec![
            b"data: a\n\n".to_vec(),
            b"data: b\n\n".to_vec(),
        ])
        .await;
        let Upstream::Opened {
            stream, headers, ..
        } = open_body(resp, Duration::from_secs(5))
            .await
            .expect("body opens")
        else {
            panic!("open_body always yields an opened body");
        };
        assert!(
            headers.iter().any(|(n, _)| *n == header::CONTENT_TYPE),
            "the content type is kept for the relay: {headers:?}"
        );
        let out = crate::sse::test_support::frames(stream).await;
        assert_eq!(out, vec!["data: a\n\n", "data: b\n\n"]);
    }

    /// A stall *between* chunks ends the stream with an error item, which the
    /// translators turn into a terminal error frame.
    #[tokio::test]
    async fn a_stalled_stream_errors_instead_of_hanging() {
        let resp = crate::sse::test_support::sse_response(vec![b"data: a\n\n".to_vec()]).await;
        let Upstream::Opened { stream, .. } = open_body(resp, Duration::from_secs(5))
            .await
            .expect("body opens")
        else {
            panic!("open_body always yields an opened body");
        };
        // The upstream closed after one event, so idle_body sees EOF, not a stall.
        let out =
            crate::sse::test_support::frames(idle_body(stream, Duration::from_millis(50))).await;
        assert_eq!(out.len(), 1);

        // Now a stream that produces one chunk and then never ends.
        let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Bytes, std::io::Error>>();
        tx.unbounded_send(Ok(Bytes::from_static(b"data: a\n\n")))
            .expect("send");
        // Keep `tx` alive but silent: the idle deadline is the only way out.
        let stream: BodyStream = Box::pin(rx);
        let (out, err) =
            crate::sse::test_support::frames_or_error(idle_body(stream, Duration::from_millis(50)))
                .await;
        assert_eq!(out.len(), 1, "the first chunk is delivered");
        assert!(
            err.unwrap_or_default().contains("idle"),
            "the stall must surface as a timed-out item"
        );
        drop(tx);
    }

    // ----- bodies that are not completions (F6) -----

    /// A `200 application/json` whose body is an HTML error page must not be
    /// relayed: the client would parse it as a completion.
    #[tokio::test]
    async fn a_json_content_type_with_an_html_body_is_a_502() {
        let provider = provider(OPENAI_PROVIDER);
        let key = provider.pool.pick("m", None).expect("one key");
        let guard = key.try_acquire().expect("a free slot");
        let body = Upstream::Opened {
            status: StatusCode::OK,
            headers: vec![(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            stream: Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
                b"<html><body>502 Bad Gateway</body></html>",
            ))])),
        };
        let resp = success_response(&provider, "m", body, false, key, guard).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn content_type_parameters_and_case_are_normalized() {
        assert_eq!(
            normalize_content_type("text/HTML; charset=utf-8"),
            "text/html"
        );
        assert_eq!(
            normalize_content_type(" application/json "),
            "application/json"
        );
        assert_eq!(normalize_content_type(""), "");
    }

    // ----- the stream's lifetime is the slot's lifetime (chaos 2.3 / 2.4) -----

    /// The in-flight counters the dashboard shows for a provider.
    fn in_flight(provider: &Provider) -> u32 {
        provider.pool.snapshot().iter().map(|k| k.in_flight).sum()
    }

    /// A body that emits one frame and then never ends, plus a flag that flips
    /// when the stream is really dropped.
    ///
    /// The flag is carried *inside* the stream state, so it proves the body — and
    /// with it the upstream it stands for — was released, not merely stopped
    /// being read.
    fn stalled_body() -> (BodyStream, Arc<std::sync::atomic::AtomicBool>) {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct Probe(Arc<AtomicBool>);
        impl Drop for Probe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let (tx, rx) = futures::channel::mpsc::unbounded::<Result<Bytes, std::io::Error>>();
        tx.unbounded_send(Ok(Bytes::from_static(b"data: a\n\n")))
            .expect("queue the first frame");
        // `tx` rides along in the state, so the stream cannot reach a natural EOF.
        let state = (Probe(dropped.clone()), tx, rx);
        let stream = futures::stream::unfold(state, |(probe, tx, mut rx)| async move {
            let item = rx.next().await?;
            Some((item, (probe, tx, rx)))
        });
        (Box::pin(stream), dropped)
    }

    fn opened(stream: BodyStream) -> Upstream {
        Upstream::Opened {
            status: StatusCode::OK,
            headers: Vec::new(),
            stream,
        }
    }

    /// A loopback upstream that streams events until the connection dies, and
    /// records the moment its peer (the gateway) hung up.
    ///
    /// A client disconnect is invisible to a stream that ends on its own:
    /// something has to keep writing after the gateway is gone. This one writes
    /// every 20 ms for ~20 s, so `peer_gone` flips within one write of the
    /// gateway dropping the upstream body — long before the stream would have
    /// ended by itself.
    async fn endless_stream(peer_gone: Arc<std::sync::atomic::AtomicBool>) -> reqwest::Response {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local address");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut head = [0u8; 2048];
            let _ = sock.read(&mut head).await;
            let header = b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                           connection: close\r\n\r\n";
            if sock.write_all(header).await.is_err() {
                peer_gone.store(true, Ordering::SeqCst);
                return;
            }
            for _ in 0..1000 {
                if sock.write_all(b"data: tick\n\n").await.is_err() {
                    // The gateway is gone: the write went nowhere.
                    peer_gone.store(true, Ordering::SeqCst);
                    return;
                }
                let _ = sock.flush().await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("build a test client")
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("the loopback upstream starts streaming")
    }

    /// 2.3: the in-flight counter is the pool's admission control *and* a
    /// dashboard field. Releasing the `KeyGuard` when the handler returned used to
    /// free the slot while the client was still reading: `/api/providers` showed 0
    /// for a live stream, and the pool believed it had capacity it did not have.
    #[tokio::test]
    async fn a_live_stream_holds_its_key_slot_until_the_body_is_dropped() {
        let provider = provider(OPENAI_PROVIDER);
        let key = provider.pool.pick("m", None).expect("one key");
        let guard = key.try_acquire().expect("a free slot");
        let (body, upstream_dropped) = stalled_body();
        let resp = success_response(&provider, "m", opened(body), true, key, guard).await;

        assert_eq!(
            in_flight(&provider),
            1,
            "an open stream holds exactly one slot"
        );

        // Reading a frame must not release it either.
        let mut frames = resp.into_body().into_data_stream();
        assert!(frames.next().await.is_some(), "the first frame is relayed");
        assert_eq!(in_flight(&provider), 1, "still held while the client reads");

        drop(frames);
        assert_eq!(
            in_flight(&provider),
            0,
            "dropping the body releases the slot"
        );
        assert!(
            upstream_dropped.load(std::sync::atomic::Ordering::SeqCst),
            "dropping the client body must drop the upstream body with it"
        );
    }

    /// 2.4: dropping the client response must close the *upstream connection*, not
    /// just stop reading it. When the upstream lived in a task of its own the
    /// provider kept streaming (and burning quota and a key slot) to the end.
    #[tokio::test]
    async fn dropping_the_client_body_closes_the_upstream_connection() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let provider = provider(OPENAI_PROVIDER);
        let peer_gone = Arc::new(AtomicBool::new(false));
        let upstream = endless_stream(peer_gone.clone()).await;
        let body = open_body(upstream, Duration::from_secs(5))
            .await
            .expect("the body opens");
        let key = provider.pool.pick("m", None).expect("one key");
        let guard = key.try_acquire().expect("a free slot");
        let resp = success_response(&provider, "m", body, true, key, guard).await;

        // A client that reads one frame and vanishes.
        let mut frames = resp.into_body().into_data_stream();
        assert!(frames.next().await.is_some(), "the relay produces a frame");
        assert_eq!(in_flight(&provider), 1, "the live stream holds the slot");
        drop(frames);

        // The upstream writes for ~20 s: "still writing" cannot be a race with a
        // natural end of body, it is the regression.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !peer_gone.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            peer_gone.load(Ordering::SeqCst),
            "the upstream was still streaming 3s after the client-facing body was dropped: \
             nothing ties the upstream connection to the response body any more"
        );
        assert_eq!(in_flight(&provider), 0, "and the slot comes back with it");
    }

    /// The other half of the contract: a stream that ends normally releases the
    /// slot, so a short completion does not leak one either.
    #[tokio::test]
    async fn a_finished_stream_releases_its_slot() {
        let provider = provider(OPENAI_PROVIDER);
        let key = provider.pool.pick("m", None).expect("one key");
        let guard = key.try_acquire().expect("a free slot");
        let body = Upstream::Opened {
            status: StatusCode::OK,
            headers: Vec::new(),
            stream: Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
                b"data: a\n\n",
            ))])),
        };
        let resp = success_response(&provider, "m", body, true, key, guard).await;

        let mut frames = resp.into_body().into_data_stream();
        let mut count = 0;
        while let Some(item) = frames.next().await {
            item.expect("every relayed item is a frame");
            count += 1;
        }
        assert_eq!(
            count, 1,
            "the single frame is relayed before the end of body"
        );
        assert_eq!(
            in_flight(&provider),
            0,
            "a finished stream must not leak a slot"
        );
    }

    /// The translated path (gemini/anthropic) wraps the upstream in a parser
    /// before it reaches the client: the slot has to survive that wrapping too.
    #[tokio::test]
    async fn a_translated_stream_holds_its_key_slot_too() {
        let provider = provider(ANTHROPIC_PROVIDER);
        let key = provider.pool.pick("m", None).expect("one key");
        let guard = key.try_acquire().expect("a free slot");
        let (body, upstream_dropped) = stalled_body();
        let resp = success_response(&provider, "m", opened(body), true, key, guard).await;

        assert_eq!(
            in_flight(&provider),
            1,
            "an open translated stream holds its slot"
        );
        drop(resp);
        assert_eq!(in_flight(&provider), 0, "and releases it with the body");
        assert!(
            upstream_dropped.load(std::sync::atomic::Ordering::SeqCst),
            "the parser must not keep the upstream body alive on its own"
        );
    }
}
