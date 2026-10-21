//! POST /v1/responses — the OpenAI Responses API, served by the chat pipeline.
//!
//! Scope is text in / text out. There is no response store, so
//! `previous_response_id` cannot work, and tool calling / reasoning knobs /
//! structured-output formats are not wired through the translating providers.
//! Those are refused by name instead of dropped: a silently ignored `tools`
//! array looks to the user like a model that decided not to call a function,
//! which is far harder to debug than a 400.
//!
//! The mapping itself is kept in pure functions (`to_chat_request`,
//! `response_object`, `StreamMapper`) so the translation rules and the SSE event
//! sequence are unit-testable without a provider.

use std::collections::VecDeque;
use std::sync::Arc;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::BytesMut;
use futures::StreamExt;
use serde_json::{Value, json};
use tracing::{debug, info};

use crate::providers::{Provider, ProviderRouter, Resolved};
use crate::sse::SseParser;

use super::{
    AppState, KeyPermissions, combo_allowed, error_response, model_allowed, model_disabled,
    run_target_pub,
};

/// Largest upstream body we buffer to build a non-streaming response.
const MAX_UPSTREAM_BODY: usize = 32 << 20;

/// Accept a Responses request and answer it in the Responses shape, using the
/// same provider/retry/fallback pipeline as `/v1/chat/completions`.
pub async fn responses(
    State(state): State<Arc<AppState>>,
    key_perm: Option<Extension<KeyPermissions>>,
    body: Bytes,
) -> Response {
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON body: {e}"),
                "invalid_request_error",
            );
        }
    };
    let chat = match to_chat_request(&req) {
        Ok(v) => v,
        Err((status, message)) => return error_response(status, message, "invalid_request_error"),
    };
    // `to_chat_request` always sets both fields.
    let model = chat
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let is_stream = chat.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let key_models = key_perm
        .as_ref()
        .and_then(|e| e.0.allowed_models.as_deref());

    // The guard pins the provider list for the whole request, exactly as
    // `chat_completions` does; reloads swap a new Arc instead of mutating this one.
    let router = state.router.load();
    let targets = match resolve_targets(&state, &router, &model, key_models) {
        Ok(t) => t,
        Err((status, message, ty)) => return error_response(status, message, ty),
    };

    let resp = serve_targets(&state, &targets, &model, &chat, is_stream).await;
    if !resp.status().is_success() {
        // `run_target`/`error_response` already produced an OpenAI-shaped error.
        return resp;
    }
    if is_stream {
        sse_response(resp, &model)
    } else {
        non_stream_response(resp, &model).await
    }
}

// ---------------------------------------------------------------------------
// target resolution (mirrors the semantics of `chat_completions`)
// ---------------------------------------------------------------------------

/// The three parts `error_response` needs. A tuple instead of a `Response` keeps
/// the `Err` variant small (clippy::result_large_err) and lets the handler own the
/// single place where a response is built.
type ResolveError = (StatusCode, String, &'static str);

/// Resolve the requested model to `(provider, upstream_model)` targets, honouring
/// the global disabled list, combos and the client key's allowlist.
///
/// The status/`type` pairs are copied verbatim from `chat_completions` so a client
/// cannot tell the two endpoints apart by their errors.
fn resolve_targets<'a>(
    state: &AppState,
    router: &'a ProviderRouter,
    model: &str,
    key_models: Option<&[String]>,
) -> Result<Vec<(&'a Provider, String)>, ResolveError> {
    let Some(resolved) = router.resolve(model) else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no provider serves model '{model}'"),
            "model_not_found",
        ));
    };

    // One read guard for the whole check instead of a clone of the set: the
    // disabled list can be long and this runs per request.
    let disabled = state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner());
    // The requested name may be bare (disabled) or "combo/name" — check both.
    let bare = model.strip_prefix("combo/").unwrap_or(model);
    if disabled.contains(model) || disabled.contains(bare) {
        return Err((
            StatusCode::NOT_FOUND,
            format!("model '{model}' is disabled"),
            "model_not_found",
        ));
    }

    match &resolved {
        Resolved::One(p, m) => {
            let canonical = format!("{}/{}", p.name, m);
            if model_disabled(&disabled, model, &canonical, m) {
                return Err((
                    StatusCode::NOT_FOUND,
                    format!("model '{model}' is disabled"),
                    "model_not_found",
                ));
            }
            if let Some(allowed) = key_models
                && !model_allowed(allowed, model, &canonical, m)
            {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("model '{model}' is not allowed for this API key"),
                    "model_not_allowed",
                ));
            }
            Ok(vec![(*p, m.clone())])
        }
        Resolved::Chain(chain) => {
            if let Some(allowed) = key_models
                && !combo_allowed(allowed, model)
            {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("model '{model}' is not allowed for this API key"),
                    "model_not_allowed",
                ));
            }
            let active: Vec<_> = chain
                .iter()
                .filter(|(p, m)| {
                    !disabled.contains(&format!("{}/{}", p.name, m))
                        && !disabled.contains(m.as_str())
                })
                .cloned()
                .collect();
            if active.is_empty() {
                return Err((
                    StatusCode::NOT_FOUND,
                    format!("all targets in combo '{model}' are disabled"),
                    "model_not_found",
                ));
            }
            Ok(active)
        }
    }
}

/// Walk the resolved targets until one answers, with the same combo fallback and
/// 503 semantics as the chat endpoint.
async fn serve_targets(
    state: &AppState,
    targets: &[(&Provider, String)],
    model: &str,
    chat: &Value,
    is_stream: bool,
) -> Response {
    let total = targets.len();
    for (i, (provider, upstream_model)) in targets.iter().enumerate() {
        let result = run_target_pub(state, provider, upstream_model, chat, is_stream).await;
        if let Some(resp) = result {
            if total > 1 && i > 0 {
                info!(combo = %model, fallback = i + 1, of = total, "combo fallback succeeded");
            }
            return resp;
        }
        if total > 1 {
            state.events.emit(crate::events::DashEvent::new(
                "combo",
                model,
                "backoff",
                format!(
                    "target '{}/{}' exhausted, trying next",
                    provider.name, upstream_model
                ),
            ));
        } else {
            return exhausted_response(provider, model, state.rt().max_retries);
        }
    }
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("combo '{model}': all {total} targets exhausted"),
        "provider_unavailable",
    )
}

fn exhausted_response(provider: &Provider, model: &str, attempts: usize) -> Response {
    let mut resp = error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!(
            "provider '{}' unavailable after {attempts} attempts",
            provider.name
        ),
        "provider_unavailable",
    );
    // Same reasoning as the chat endpoint: a provider in a short cooldown is not
    // down forever, and without Retry-After the client cannot tell the difference.
    if let Some(d) = provider.pool.wake_after(model)
        && let Ok(v) = header::HeaderValue::from_str(&d.as_secs().max(1).to_string())
    {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

// ---------------------------------------------------------------------------
// request translation (pure)
// ---------------------------------------------------------------------------

fn bad_request(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.into())
}

fn unsupported(field: &str) -> (StatusCode, String) {
    bad_request(format!("'{field}' is not supported by this gateway"))
}

/// Translate a Responses request into a chat-completions request.
///
/// Pure by design: `Err` carries the exact status and message the client gets,
/// so every acceptance and rejection rule is unit-testable.
fn to_chat_request(v: &Value) -> Result<Value, (StatusCode, String)> {
    let model = v
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| bad_request("missing or invalid 'model' field"))?
        .to_string();

    // Reject what we cannot honour, by name. Dropping `tools` (or accepting
    // `previous_response_id` and answering statelessly) would silently change the
    // meaning of the request.
    if v.get("previous_response_id").is_some_and(|x| !x.is_null()) {
        return Err(bad_request(
            "'previous_response_id' is not supported: this gateway keeps no response store",
        ));
    }
    if let Some(tools) = v.get("tools")
        && !is_inert_array(tools)
    {
        return Err(unsupported("tools"));
    }
    if let Some(choice) = v.get("tool_choice")
        && !is_inert_tool_choice(choice)
    {
        return Err(unsupported("tool_choice"));
    }
    if let Some(reasoning) = v.get("reasoning")
        && reasoning
            .as_object()
            .is_some_and(|o| !o.is_empty() && o.values().any(|x| !x.is_null()))
    {
        return Err(unsupported("reasoning"));
    }
    if let Some(format) = v.pointer("/text/format")
        && !is_plain_text_format(format)
    {
        return Err(unsupported("text.format"));
    }

    let stream = match v.get("stream") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(bad_request("'stream' must be a boolean")),
    };
    let max_tokens = match v.get("max_output_tokens") {
        None | Some(Value::Null) => None,
        Some(x) => Some(
            x.as_u64()
                .filter(|n| *n > 0)
                .ok_or_else(|| bad_request("'max_output_tokens' must be a positive integer"))?,
        ),
    };

    let mut messages = Vec::new();
    match v.get("instructions") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            // An empty instruction adds a system turn that says nothing.
            if !s.is_empty() {
                messages.push(json!({"role": "system", "content": s}));
            }
        }
        Some(_) => return Err(bad_request("'instructions' must be a string")),
    }
    push_input_messages(v.get("input"), &mut messages)?;
    if messages.is_empty() {
        return Err(bad_request("'input' contains no messages"));
    }

    let mut chat = json!({"model": model, "messages": messages});
    if let Some(n) = max_tokens {
        chat["max_tokens"] = json!(n);
    }
    if let Some(t) = v.get("temperature")
        && !t.is_null()
    {
        chat["temperature"] = t.clone();
    }
    if let Some(p) = v.get("top_p")
        && !p.is_null()
    {
        chat["top_p"] = p.clone();
    }
    if stream {
        chat["stream"] = Value::Bool(true);
    }
    Ok(chat)
}

/// A field whose only meaningful value is "nothing": `null` or an empty array.
fn is_inert_array(v: &Value) -> bool {
    v.is_null() || v.as_array().is_some_and(Vec::is_empty)
}

/// `auto`/`none` are what the client sends when it has no tool preference at all.
fn is_inert_tool_choice(v: &Value) -> bool {
    v.is_null() || matches!(v.as_str(), Some("auto" | "none"))
}

/// The default text format carries no constraint; anything else is a request for
/// structured output we cannot forward.
fn is_plain_text_format(v: &Value) -> bool {
    if v.is_null() {
        return true;
    }
    match v.as_object() {
        Some(o) => o
            .get("type")
            .and_then(Value::as_str)
            .is_none_or(|t| t == "text"),
        None => false,
    }
}

fn push_input_messages(
    input: Option<&Value>,
    out: &mut Vec<Value>,
) -> Result<(), (StatusCode, String)> {
    match input {
        None | Some(Value::Null) => Err(bad_request("missing 'input' field")),
        Some(Value::String(s)) => {
            out.push(user_message(s));
            Ok(())
        }
        Some(Value::Array(items)) => {
            for item in items {
                push_input_item(item, out)?;
            }
            Ok(())
        }
        Some(_) => Err(bad_request("'input' must be a string or an array of items")),
    }
}

fn push_input_item(item: &Value, out: &mut Vec<Value>) -> Result<(), (StatusCode, String)> {
    // Bare strings inside the array mean the same as a string `input`.
    if let Some(text) = item.as_str() {
        out.push(user_message(text));
        return Ok(());
    }
    let Some(obj) = item.as_object() else {
        return Err(bad_request(
            "each 'input' item must be an object or a string",
        ));
    };
    // An item without `type` that carries a role is a message by convention.
    let ty = obj.get("type").and_then(Value::as_str).unwrap_or("message");
    match ty {
        "message" => {
            let role = obj.get("role").and_then(Value::as_str).unwrap_or("user");
            let role = match role {
                // Responses' `developer` is chat's `system`.
                "developer" => "system",
                "user" | "assistant" | "system" => role,
                other => {
                    return Err(bad_request(format!("unsupported message role '{other}'")));
                }
            };
            let text = message_text(obj.get("content"))?;
            out.push(json!({"role": role, "content": text}));
            Ok(())
        }
        "input_text" => {
            let text = obj.get("text").and_then(Value::as_str).unwrap_or_default();
            out.push(user_message(text));
            Ok(())
        }
        other => Err(bad_request(format!(
            "'input' item type '{other}' is not supported"
        ))),
    }
}

/// Flatten a message `content` (string or array of parts) to plain text.
fn message_text(content: Option<&Value>) -> Result<String, (StatusCode, String)> {
    match content {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Array(parts)) => {
            let mut text = String::new();
            for part in parts {
                match part {
                    Value::String(s) => text.push_str(s),
                    Value::Object(o) => {
                        let ty = o
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or("input_text");
                        match ty {
                            // `output_text` appears when a client replays a previous
                            // assistant turn back to us.
                            "input_text" | "output_text" | "text" => {
                                text.push_str(
                                    o.get("text").and_then(Value::as_str).unwrap_or_default(),
                                );
                            }
                            other => {
                                return Err(bad_request(format!(
                                    "message content part type '{other}' is not supported"
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(bad_request(
                            "message content parts must be strings or objects",
                        ));
                    }
                }
            }
            Ok(text)
        }
        Some(_) => Err(bad_request(
            "'content' must be a string or an array of parts",
        )),
    }
}

fn user_message(text: &str) -> Value {
    json!({"role": "user", "content": text})
}

// ---------------------------------------------------------------------------
// response shaping
// ---------------------------------------------------------------------------

/// `resp_`/`msg_` ids are cosmetic (no store), but clients do parse them as opaque
/// ids, so keep them unique and hex like the real API.
fn random_id(prefix: &str) -> String {
    let mut raw = [0u8; 16];
    if getrandom::fill(&mut raw).is_err() {
        // CSPRNG failure only costs uniqueness; a clock-derived id still beats
        // panicking inside a request handler.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        return format!("{prefix}{nanos:x}");
    }
    format!("{prefix}{}", hex::encode(raw))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `(input_tokens, output_tokens)` from a chat-completions payload.
fn usage_pair(chat: &Value) -> (u64, u64) {
    let usage = chat.get("usage");
    let pick = |key: &str| {
        usage
            .and_then(|u| u.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    (pick("prompt_tokens"), pick("completion_tokens"))
}

/// Build the `response` object: the non-stream body and the payload of
/// `response.completed` are the same thing on purpose, so a client sees one shape.
fn response_object(
    id: &str,
    created_at: u64,
    model: &str,
    item_id: &str,
    text: &str,
    usage: (u64, u64),
) -> Value {
    let (input_tokens, output_tokens) = usage;
    json!({
        "id": id,
        "object": "response",
        "created_at": created_at,
        "status": "completed",
        "model": model,
        "output": [{
            "type": "message",
            "id": item_id,
            "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}],
        }],
        // Convenience field the official SDK reads without walking `output`.
        "output_text": text,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
    })
}

async fn non_stream_response(resp: Response, model: &str) -> Response {
    let bytes = match axum::body::to_bytes(resp.into_body(), MAX_UPSTREAM_BODY).await {
        Ok(b) => b,
        Err(e) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                format!("upstream body read failed: {e}"),
                "upstream_error",
            );
        }
    };
    let Ok(chat) = serde_json::from_slice::<Value>(&bytes) else {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "invalid upstream JSON",
            "upstream_error",
        );
    };
    let text = chat
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Json(response_object(
        &random_id("resp_"),
        unix_now(),
        model,
        &random_id("msg_"),
        text,
        usage_pair(&chat),
    ))
    .into_response()
}

// ---------------------------------------------------------------------------
// streaming
// ---------------------------------------------------------------------------

/// Serialize one SSE frame with the `event:` name the Responses API requires.
fn event_frame(name: &str, body: &Value) -> Bytes {
    let mut out = BytesMut::with_capacity(256);
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b"\ndata: ");
    if let Ok(json) = serde_json::to_vec(body) {
        out.extend_from_slice(&json);
    }
    out.extend_from_slice(b"\n\n");
    out.freeze()
}

/// Maps chat-completions SSE payloads onto Responses SSE frames.
///
/// No I/O and no clock reads after construction: the async wrapper only feeds it
/// parser output, which makes the whole event sequence assertable offline.
struct StreamMapper {
    resp_id: String,
    item_id: String,
    model: String,
    created_at: u64,
    text: String,
    usage: (u64, u64),
    /// `output_item.added` is emitted lazily, right before the first delta.
    item_added: bool,
    /// Set once the terminal event was sent, so `[DONE]` followed by EOF (the
    /// normal case) cannot complete the response twice.
    completed: bool,
    sequence: u64,
}

impl StreamMapper {
    fn new(model: String) -> Self {
        Self {
            resp_id: random_id("resp_"),
            item_id: random_id("msg_"),
            model,
            created_at: unix_now(),
            text: String::new(),
            usage: (0, 0),
            item_added: false,
            completed: false,
            sequence: 0,
        }
    }

    /// Serialize one event, stamping `type` and the monotonic `sequence_number`
    /// every Responses event carries.
    fn emit(&mut self, name: &str, mut body: Value) -> Bytes {
        if let Value::Object(map) = &mut body {
            map.insert("type".to_string(), Value::String(name.to_string()));
            map.insert("sequence_number".to_string(), json!(self.sequence));
        }
        self.sequence += 1;
        event_frame(name, &body)
    }

    fn snapshot(&self, status: &str, output: Value) -> Value {
        let (input_tokens, output_tokens) = self.usage;
        json!({
            "id": self.resp_id,
            "object": "response",
            "created_at": self.created_at,
            "status": status,
            "model": self.model,
            "output": output,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            },
        })
    }

    fn item_added_event(&mut self) -> Bytes {
        let item_id = self.item_id.clone();
        self.emit(
            "response.output_item.added",
            json!({
                "output_index": 0,
                "item": {
                    "type": "message",
                    "id": item_id,
                    "role": "assistant",
                    "status": "in_progress",
                    "content": [],
                },
            }),
        )
    }

    /// Frames the client must see before the first delta.
    fn start(&mut self) -> Vec<Bytes> {
        let snapshot = self.snapshot("in_progress", json!([]));
        vec![self.emit("response.created", json!({"response": snapshot}))]
    }

    /// Map one upstream `data:` payload to zero or more client frames.
    fn feed(&mut self, data: &[u8]) -> Vec<Bytes> {
        if self.completed {
            return Vec::new();
        }
        let payload = data.trim_ascii();
        if payload == b"[DONE]" {
            return self.finish();
        }
        let Ok(chunk) = serde_json::from_slice::<Value>(payload) else {
            // Keep-alives and provider-specific frames are not our business.
            debug!("ignoring non-JSON chat SSE payload");
            return Vec::new();
        };
        if let Some(err) = chunk.get("error")
            && !err.is_null()
        {
            return self.fail(err);
        }
        if chunk.get("usage").is_some_and(|u| !u.is_null()) {
            self.usage = usage_pair(&chunk);
        }
        let delta = chunk
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if delta.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        if !self.item_added {
            self.item_added = true;
            out.push(self.item_added_event());
        }
        self.text.push_str(delta);
        let item_id = self.item_id.clone();
        out.push(self.emit(
            "response.output_text.delta",
            json!({
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "delta": delta,
            }),
        ));
        out
    }

    /// Terminal frames: `output_text.done` then `response.completed`.
    fn finish(&mut self) -> Vec<Bytes> {
        if self.completed {
            return Vec::new();
        }
        self.completed = true;
        let mut out = Vec::new();
        if !self.item_added {
            // An empty completion still owes one output item, otherwise the
            // events below would reference an item the client never saw.
            self.item_added = true;
            out.push(self.item_added_event());
        }
        let item_id = self.item_id.clone();
        let text = self.text.clone();
        out.push(self.emit(
            "response.output_text.done",
            json!({
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "text": text,
            }),
        ));
        let resp = response_object(
            &self.resp_id,
            self.created_at,
            &self.model,
            &item_id,
            &text,
            self.usage,
        );
        out.push(self.emit("response.completed", json!({"response": resp})));
        out
    }

    /// Upstream failed mid-stream: tell the client instead of leaving it waiting
    /// for a `response.completed` that will never arrive.
    fn fail(&mut self, err: &Value) -> Vec<Bytes> {
        if self.completed {
            return Vec::new();
        }
        self.completed = true;
        let snapshot = self.snapshot("failed", json!([]));
        vec![self.emit(
            "response.failed",
            json!({"response": snapshot, "error": err}),
        )]
    }
}

/// Upstream chat SSE, boxed so the stream state stays a concrete struct.
type UpstreamStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<Bytes, axum::Error>> + Send>>;

struct StreamState {
    upstream: UpstreamStream,
    parser: SseParser,
    mapper: StreamMapper,
    queue: VecDeque<Bytes>,
    ended: bool,
}

/// Relay the upstream chat SSE as Responses SSE.
///
/// The key guard lives inside the upstream body, so it keeps the in-flight slot
/// until this stream is dropped — no extra bookkeeping needed here.
fn sse_response(resp: Response, model: &str) -> Response {
    let mut mapper = StreamMapper::new(model.to_string());
    let queue: VecDeque<Bytes> = mapper.start().into();
    let state = StreamState {
        upstream: Box::pin(resp.into_body().into_data_stream()),
        parser: SseParser::new(),
        mapper,
        queue,
        ended: false,
    };

    // `unfold` with an explicit queue: a single upstream chunk usually yields
    // several events, and a plain `scan` would force one frame per poll.
    let stream = futures::stream::unfold(Some(state), |prev| async move {
        let mut st = prev?;
        loop {
            if let Some(frame) = st.queue.pop_front() {
                return Some((Ok::<Bytes, std::io::Error>(frame), Some(st)));
            }
            if st.ended {
                return None;
            }
            match st.upstream.next().await {
                Some(Ok(chunk)) => {
                    let payloads = st.parser.feed(&chunk);
                    for payload in payloads {
                        let frames = st.mapper.feed(&payload);
                        st.queue.extend(frames);
                    }
                }
                Some(Err(e)) => {
                    debug!(error = %e, "upstream stream error");
                    st.ended = true;
                    let frames = st.mapper.finish();
                    st.queue.extend(frames);
                }
                None => {
                    st.ended = true;
                    for payload in st.parser.finish() {
                        let frames = st.mapper.feed(&payload);
                        st.queue.extend(frames);
                    }
                    // `finish` is idempotent: if the stream ended with `[DONE]`
                    // this is a no-op, otherwise it completes the response.
                    let frames = st.mapper.finish();
                    st.queue.extend(frames);
                }
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_names(frames: &[Bytes]) -> Vec<String> {
        frames
            .iter()
            .map(|f| {
                let s = std::str::from_utf8(f).expect("frames are UTF-8");
                s.lines()
                    .next()
                    .and_then(|l| l.strip_prefix("event: "))
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }

    fn data_of(frame: &Bytes) -> Value {
        let s = std::str::from_utf8(frame).expect("frames are UTF-8");
        let line = s
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("frame has a data line");
        serde_json::from_str(line).expect("data is JSON")
    }

    // ----- request translation -----

    #[test]
    fn string_input_becomes_one_user_message() {
        let chat = to_chat_request(&json!({"model": "openai/gpt-4o", "input": "Hello"}))
            .expect("string input is supported");
        assert_eq!(chat["model"], "openai/gpt-4o");
        assert_eq!(
            chat["messages"],
            json!([{"role": "user", "content": "Hello"}])
        );
        // Nothing to forward: no stream, no max_tokens.
        assert!(chat.get("stream").is_none());
        assert!(chat.get("max_tokens").is_none());
    }

    #[test]
    fn array_input_is_translated_in_order() {
        let chat = to_chat_request(&json!({
            "model": "m",
            "input": [
                {"type": "message", "role": "developer", "content": "be terse"},
                {"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": "Hi "},
                    {"type": "input_text", "text": "there"}
                ]},
                {"type": "message", "role": "assistant", "content": "hello"},
                {"type": "input_text", "text": "again"}
            ]
        }))
        .expect("array input is supported");
        assert_eq!(
            chat["messages"],
            json!([
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "Hi there"},
                {"role": "assistant", "content": "hello"},
                {"role": "user", "content": "again"},
            ])
        );
    }

    #[test]
    fn instructions_are_prepended_as_a_system_message() {
        let chat = to_chat_request(&json!({
            "model": "m",
            "instructions": "You are a poet.",
            "input": "Write one line."
        }))
        .expect("instructions are supported");
        assert_eq!(
            chat["messages"][0],
            json!({"role": "system", "content": "You are a poet."})
        );
        assert_eq!(
            chat["messages"][1],
            json!({"role": "user", "content": "Write one line."})
        );
    }

    #[test]
    fn generation_knobs_are_forwarded() {
        let chat = to_chat_request(&json!({
            "model": "m",
            "input": "hi",
            "max_output_tokens": 256,
            "temperature": 0.2,
            "top_p": 0.9,
            "stream": true
        }))
        .expect("supported knobs");
        assert_eq!(chat["max_tokens"], 256);
        assert_eq!(chat["temperature"], 0.2);
        assert_eq!(chat["top_p"], 0.9);
        assert_eq!(chat["stream"], true);
    }

    #[test]
    fn unsupported_fields_are_rejected_by_name() {
        let cases = [
            (
                json!({"model": "m", "input": "hi", "tools": [{"type": "function", "name": "f"}]}),
                "tools",
            ),
            (
                json!({"model": "m", "input": "hi", "tool_choice": "required"}),
                "tool_choice",
            ),
            (
                json!({"model": "m", "input": "hi", "reasoning": {"effort": "high"}}),
                "reasoning",
            ),
            (
                json!({"model": "m", "input": "hi", "text": {"format": {"type": "json_schema"}}}),
                "text.format",
            ),
            (
                json!({"model": "m", "input": "hi", "previous_response_id": "resp_1"}),
                "previous_response_id",
            ),
        ];
        for (req, field) in cases {
            let (status, message) = to_chat_request(&req).expect_err("must be rejected");
            assert_eq!(status, StatusCode::BAD_REQUEST, "{field}");
            assert!(
                message.contains(field),
                "message '{message}' must name the field '{field}'"
            );
        }
    }

    #[test]
    fn inert_tool_and_format_fields_are_accepted() {
        // Clients send these defaults unconditionally; rejecting them would break
        // ordinary text requests.
        let chat = to_chat_request(&json!({
            "model": "m",
            "input": "hi",
            "tools": [],
            "tool_choice": "auto",
            "reasoning": {},
            "text": {"format": {"type": "text"}}
        }))
        .expect("inert defaults are fine");
        assert_eq!(chat["messages"], json!([{"role": "user", "content": "hi"}]));
    }

    #[test]
    fn missing_model_and_input_are_client_errors() {
        let (status, message) = to_chat_request(&json!({"input": "hi"})).expect_err("no model");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("model"));

        let (status, message) = to_chat_request(&json!({"model": "m"})).expect_err("no input");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("input"));
    }

    // ----- response shaping -----

    #[test]
    fn non_stream_object_matches_the_responses_shape() {
        let chat = json!({
            "choices": [{"message": {"role": "assistant", "content": "Hi there"}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}
        });
        let text = chat
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .expect("assistant text");
        let out = response_object(
            "resp_abc",
            1_700_000_000,
            "m",
            "msg_abc",
            text,
            usage_pair(&chat),
        );

        assert_eq!(out["object"], "response");
        assert_eq!(out["status"], "completed");
        assert_eq!(out["id"], "resp_abc");
        assert_eq!(out["model"], "m");
        assert_eq!(out["output_text"], "Hi there");
        assert_eq!(out["output"][0]["type"], "message");
        assert_eq!(out["output"][0]["role"], "assistant");
        assert_eq!(
            out["output"][0]["content"][0],
            json!({"type": "output_text", "text": "Hi there", "annotations": []})
        );
        // prompt/completion tokens map onto input/output, totals are summed.
        assert_eq!(
            out["usage"],
            json!({"input_tokens": 7, "output_tokens": 3, "total_tokens": 10})
        );
    }

    // ----- streaming -----

    #[test]
    fn chat_deltas_map_to_responses_sse_events() {
        let mut mapper = StreamMapper::new("m".to_string());
        let mut frames = mapper.start();
        // Role-only and empty deltas must not produce text events.
        frames.extend(mapper.feed(br#"{"choices":[{"delta":{"role":"assistant"}}]}"#));
        frames.extend(mapper.feed(br#"{"choices":[{"delta":{"content":"Hel"}}]}"#));
        frames.extend(mapper.feed(br#"{"choices":[{"delta":{"content":"lo"}}]}"#));
        frames.extend(mapper.feed(
            br#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}"#,
        ));
        frames.extend(mapper.feed(b"[DONE]"));
        // After the terminal event nothing else may be emitted.
        assert!(
            mapper
                .feed(br#"{"choices":[{"delta":{"content":"late"}}]}"#)
                .is_empty()
        );

        assert_eq!(
            event_names(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.completed",
            ]
        );

        let deltas: Vec<String> = frames
            .iter()
            .filter_map(|f| {
                data_of(f)
                    .get("delta")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(deltas, vec!["Hel", "lo"]);

        let done = data_of(&frames[4]);
        assert_eq!(done["text"], "Hello");

        let completed = data_of(&frames[5]);
        assert_eq!(completed["response"]["object"], "response");
        assert_eq!(completed["response"]["output_text"], "Hello");
        assert_eq!(
            completed["response"]["usage"],
            json!({"input_tokens": 5, "output_tokens": 2, "total_tokens": 7})
        );
    }

    #[test]
    fn eof_without_done_still_completes_once() {
        let mut mapper = StreamMapper::new("m".to_string());
        let mut frames = mapper.start();
        frames.extend(mapper.feed(br#"{"choices":[{"delta":{"content":"x"}}]}"#));
        frames.extend(mapper.finish());
        assert!(mapper.finish().is_empty(), "completion must not repeat");
        assert_eq!(
            event_names(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.output_text.delta",
                "response.output_text.done",
                "response.completed",
            ]
        );
    }

    #[test]
    fn empty_completion_still_reports_one_item() {
        let mut mapper = StreamMapper::new("m".to_string());
        let mut frames = mapper.start();
        frames.extend(mapper.feed(b"[DONE]"));
        assert_eq!(
            event_names(&frames),
            vec![
                "response.created",
                "response.output_item.added",
                "response.output_text.done",
                "response.completed",
            ]
        );
        assert_eq!(data_of(&frames[1])["item"]["role"], "assistant");
    }

    /// The async relay (parser + queue + `Body::from_stream`), end to end on an
    /// in-memory upstream body — no socket, no provider.
    #[tokio::test]
    async fn sse_relay_maps_an_upstream_body_to_responses_frames() {
        let upstream = futures::stream::iter(vec![
            Ok::<Bytes, std::io::Error>(Bytes::from_static(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\r\n\r\n",
            )),
            // Split mid-frame on purpose: the parser must buffer the remainder.
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: [DO")),
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"NE]\n\n")),
        ]);
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(upstream))
            .expect("in-memory response is well formed");

        let relayed = sse_response(resp, "m");
        let body = axum::body::to_bytes(relayed.into_body(), 1 << 20)
            .await
            .expect("relayed body collects");
        let text = std::str::from_utf8(&body).expect("frames are UTF-8");
        let names: Vec<&str> = text
            .split("\n\n")
            .filter_map(|frame| frame.lines().next())
            .filter_map(|line| line.strip_prefix("event: "))
            .collect();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.output_item.added",
                "response.output_text.delta",
                "response.output_text.done",
                "response.completed",
            ]
        );
        assert!(
            text.contains(r#""output_text":"Hi""#),
            "completed event carries the text: {text}"
        );
    }

    #[test]
    fn upstream_error_frame_ends_the_stream_as_failed() {
        let mut mapper = StreamMapper::new("m".to_string());
        let mut frames = mapper.start();
        frames.extend(mapper.feed(br#"{"error":{"message":"boom","type":"server_error"}}"#));
        assert_eq!(
            event_names(&frames),
            vec!["response.created", "response.failed"]
        );
        assert!(mapper.finish().is_empty(), "failed is terminal too");
        assert_eq!(data_of(&frames[1])["error"]["message"], "boom");
    }
}
