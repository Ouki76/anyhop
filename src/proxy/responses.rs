//! POST /v1/responses — the OpenAI Responses API, served by the chat pipeline.
//!
//! Scope is text in / text out. A small response store (kept in the state file,
//! bounded by `[tuning] response_store_max`) makes `previous_response_id` work:
//! the stored turn's input messages and its assistant reply are prepended to the
//! new conversation. Tool calling / reasoning knobs / structured-output formats
//! are not wired through the translating providers, and are refused by name
//! instead of dropped: a silently ignored `tools` array looks to the user like a
//! model that decided not to call a function, which is far harder to debug than
//! a 400.
//!
//! The mapping itself is kept in pure functions (`to_chat_request`,
//! `replay_history`, `response_object`, `StreamMapper`) so the translation rules
//! and the SSE event sequence are unit-testable without a provider.

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
use crate::storage::{Storage, StoredResponse};

use super::{
    AppState, KeyPermissions, combo_allowed, error_response, model_allowed, model_disabled,
    run_target_pub,
};

/// Largest upstream body we buffer to build a non-streaming response.
const MAX_UPSTREAM_BODY: usize = 32 << 20;

/// Largest flattened input text accepted, in bytes.
///
/// The transport already caps the request body (`[server] max_body_bytes`, 32 MiB
/// by default), but this endpoint cannot relay that body: it flattens it into
/// messages and the pipeline re-serializes them on every attempt, so the text is
/// copied several times and the copies outlive the request body. Capping the
/// flattened text keeps that amplification bounded even if the body limit is
/// raised, and 8 MiB is already far beyond any model's context window.
const MAX_INPUT_BYTES: usize = 8 << 20;

/// Largest number of `input` items accepted.
///
/// A JSON string costs three bytes on the wire but far more as a `Value` plus a
/// translated message, so a body full of empty strings would be amplified tenfold
/// or worse without a count cap. 100 000 items is orders of magnitude beyond any
/// real conversation and still bounds the derived message vector.
const MAX_INPUT_ITEMS: usize = 100_000;

/// Largest assistant text accumulated while streaming, in bytes.
///
/// `StreamMapper` keeps every delta it relays so it can emit
/// `output_text.done` and store the reply, so a provider that streams forever
/// grows a `String` without bound: the same amplification [`MAX_INPUT_BYTES`]
/// bounds on the way in, with no bound at all on the way out. It reuses the same
/// 8 MiB figure (no model's output reaches it) and, unlike the input path,
/// overflow *truncates* instead of failing: the client has already received the
/// deltas, and the event sequence has to stay intact.
const MAX_OUTPUT_TEXT: usize = MAX_INPUT_BYTES;

/// Upper bound on a requested output budget.
///
/// The value is forwarded to the translating providers as `max_tokens`. A caller
/// asking for 2^64-1 tokens would at best be rejected upstream, and a translator
/// that narrows the number (e.g. `as_i64().unwrap_or(…)`) would read it as
/// something else entirely, so it is clamped to a number every provider can at
/// least parse. It is not a promise: each provider still enforces its own cap.
const MAX_OUTPUT_TOKENS: u64 = 1_000_000;

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
    // No state file or a zero cap both mean "off", and `previous_response_id` is
    // then refused rather than ignored (see `resolve_previous`).
    let store_max = state.tuning().response_store_max;
    let storage = state.storage.as_ref().filter(|_| store_max > 0);
    if let Some(s) = storage {
        // The writer task owns eviction but cannot see `Tuning`: hand it the cap
        // (one relaxed store) and let it do the work on its own thread.
        s.set_response_max(store_max);
    }
    // Who owns the stored record. `key_name` is the key's configured name, or a
    // hash-derived label for an unnamed key, so it identifies the key without
    // keeping the secret around.
    let owner = key_perm.as_ref().and_then(|e| e.0.key_name.clone());
    let previous = match resolve_previous(&req, storage, store_max, owner.as_deref()) {
        Ok(p) => p,
        Err((status, message)) => return error_response(status, message, "invalid_request_error"),
    };
    let mut chat = match to_chat_request(&req) {
        Ok(v) => v,
        Err((status, message)) => return error_response(status, message, "invalid_request_error"),
    };
    if let Some(prev) = &previous {
        replay_history(&mut chat, prev);
    }
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

    let (resp, provider) = serve_targets(&state, &targets, &model, &chat, is_stream).await;
    if !resp.status().is_success() {
        // `run_target`/`error_response` already produced an OpenAI-shaped error.
        return resp;
    }
    let ctx = ResponseContext {
        input: chat
            .get("messages")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        model,
        provider,
        previous_response_id: previous.as_ref().map(|p| p.id.clone()),
        storage: storage.cloned(),
        owner,
    };
    if is_stream {
        sse_response(resp, ctx)
    } else {
        non_stream_response(resp, &ctx).await
    }
}

/// What a finished response must remember: the request that produced it, so a
/// follow-up can replay the conversation, plus the store it belongs in.
struct ResponseContext {
    /// The translated chat messages that were sent upstream.
    input: Value,
    model: String,
    /// Provider that answered (combo fallback aware).
    provider: String,
    /// The id this response continues, echoed back to the client.
    previous_response_id: Option<String>,
    /// `None` when the feature is off (no state file, or a zero cap).
    storage: Option<Storage>,
    /// The client key that owns the record this request stores.
    ///
    /// A stored response is replayed as the assistant turn of a later request, so
    /// the id is a capability: without an owner, any key that learns another
    /// key's id could read that conversation back. The label comes from
    /// [`KeyPermissions::key_name`] (configured name, else a hash-derived label),
    /// so the secret itself is never stored.
    owner: Option<String>,
}

impl ResponseContext {
    /// Keep a completed response so the next turn can chain to it. Silent no-op
    /// when the store is off — the client just sees `previous_response_id: null`.
    fn persist(&self, id: &str, created_at: u64, text: &str, usage: (u64, u64)) {
        let Some(storage) = &self.storage else {
            return;
        };
        let (input_tokens, output_tokens) = usage;
        storage.save_response(
            id,
            StoredResponse {
                id: id.to_string(),
                created_at,
                model: self.model.clone(),
                provider: self.provider.clone(),
                input: self.input.clone(),
                output_text: text.to_string(),
                usage: Some(json!({
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    // Saturating: both numbers come from the upstream body, and a
                    // hostile/broken provider must not turn the totals into a
                    // debug-build panic.
                    "total_tokens": input_tokens.saturating_add(output_tokens),
                })),
                owner: self.owner.clone(),
            },
        );
    }
}

/// Resolve `previous_response_id` into the record a follow-up replays.
///
/// `Ok(None)` means "this request starts a conversation". `Err` carries the
/// exact 400 the client gets, so both the "store is off" and the "unknown id"
/// rules are assertable without building an `AppState`.
fn resolve_previous(
    v: &Value,
    storage: Option<&Storage>,
    store_max: usize,
    owner: Option<&str>,
) -> Result<Option<StoredResponse>, (StatusCode, String)> {
    let id = match v.get("previous_response_id") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        Some(_) => return Err(bad_request("'previous_response_id' must be a string")),
    };
    // Answering statelessly instead would hand the client a fresh conversation
    // while it believes it is continuing one.
    let Some(storage) = storage.filter(|_| store_max > 0) else {
        return Err(bad_request(
            "'previous_response_id' is not supported: response storage is disabled \
             (set [server] state_file and a non-zero [tuning] response_store_max)",
        ));
    };
    match storage.load_response(&id) {
        Some(rec) => {
            // Ownership: a record that belongs to another key is answered with the
            // *same* 400 as a record that does not exist. Saying "not yours" would
            // confirm that the id is real, which is exactly what an attacker
            // probing for other keys' conversations wants to know.
            if let Some(stored) = rec.owner.as_deref()
                && Some(stored) != owner
            {
                debug!(
                    id,
                    "rejecting a previous_response_id owned by another client key"
                );
                return Err(bad_request(format!(
                    "'previous_response_id' '{id}' is unknown or expired"
                )));
            }
            Ok(Some(rec))
        }
        None => Err(bad_request(format!(
            "'previous_response_id' '{id}' is unknown or expired"
        ))),
    }
}

/// Prepend a stored turn to a freshly translated chat request: its original
/// input messages, then the assistant reply it ended with, then the new turn.
///
/// The stored input already contains whatever `instructions` the original call
/// carried (they were translated into a system message), so a changed
/// `instructions` on the follow-up arrives as a later system turn — which every
/// translating provider hoists back to a system prompt anyway.
fn replay_history(chat: &mut Value, prev: &StoredResponse) {
    let mut messages: Vec<Value> = Vec::new();
    match &prev.input {
        Value::Array(items) => messages.extend(items.iter().cloned()),
        // Defensive: keeps a record with an unexpected shape replayable.
        Value::String(s) => messages.push(user_message(s)),
        _ => {}
    }
    messages.push(json!({"role": "assistant", "content": prev.output_text}));
    if let Some(new) = chat.get("messages").and_then(Value::as_array) {
        messages.extend(new.iter().cloned());
    }
    chat["messages"] = Value::Array(messages);
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
/// 503 semantics as the chat endpoint. Also reports which provider answered, so
/// the response store can record it.
async fn serve_targets(
    state: &AppState,
    targets: &[(&Provider, String)],
    model: &str,
    chat: &Value,
    is_stream: bool,
) -> (Response, String) {
    let total = targets.len();
    for (i, (provider, upstream_model)) in targets.iter().enumerate() {
        let result = run_target_pub(state, provider, upstream_model, chat, is_stream).await;
        if let Some(resp) = result {
            if total > 1 && i > 0 {
                info!(combo = %model, fallback = i + 1, of = total, "combo fallback succeeded");
            }
            return (resp, provider.name.clone());
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
            let resp = exhausted_response(provider, model, state.rt().max_retries);
            return (resp, provider.name.clone());
        }
    }
    (
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("combo '{model}': all {total} targets exhausted"),
            "provider_unavailable",
        ),
        String::new(),
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

    // Reject what we cannot honour, by name. Dropping `tools` would silently
    // change the meaning of the request; `previous_response_id` is resolved (and
    // replayed) by the handler, so it is not this function's business.
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
                .ok_or_else(|| bad_request("'max_output_tokens' must be a positive integer"))?
                .min(MAX_OUTPUT_TOKENS),
        ),
    };

    let mut messages = Vec::new();
    // Bytes of text flattened so far, against MAX_INPUT_BYTES.
    let mut used = 0usize;
    match v.get("instructions") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            // An empty instruction adds a system turn that says nothing.
            if !s.is_empty() {
                charge_input(&mut used, s.len())?;
                messages.push(json!({"role": "system", "content": s}));
            }
        }
        Some(_) => return Err(bad_request("'instructions' must be a string")),
    }
    push_input_messages(v.get("input"), &mut messages, &mut used)?;
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

/// Account for `n` more bytes of input text.
///
/// Charged while the input is flattened, so an oversized request is refused
/// before the message vector (and the JSON derived from it) is built, instead of
/// after it has already been copied.
fn charge_input(used: &mut usize, n: usize) -> Result<(), (StatusCode, String)> {
    *used = used.saturating_add(n);
    if *used > MAX_INPUT_BYTES {
        return Err(bad_request(format!(
            "'input' is too large: more than {MAX_INPUT_BYTES} bytes of text"
        )));
    }
    Ok(())
}

fn push_input_messages(
    input: Option<&Value>,
    out: &mut Vec<Value>,
    used: &mut usize,
) -> Result<(), (StatusCode, String)> {
    match input {
        None | Some(Value::Null) => Err(bad_request("missing 'input' field")),
        Some(Value::String(s)) => {
            charge_input(used, s.len())?;
            out.push(user_message(s));
            Ok(())
        }
        Some(Value::Array(items)) => {
            // Checked before any message is built, so the bound is on the work
            // done, not just on what is kept.
            if items.len() > MAX_INPUT_ITEMS {
                return Err(bad_request(format!(
                    "'input' has {} items; the cap is {MAX_INPUT_ITEMS}",
                    items.len()
                )));
            }
            for item in items {
                push_input_item(item, out, used)?;
            }
            Ok(())
        }
        Some(_) => Err(bad_request("'input' must be a string or an array of items")),
    }
}

fn push_input_item(
    item: &Value,
    out: &mut Vec<Value>,
    used: &mut usize,
) -> Result<(), (StatusCode, String)> {
    // Bare strings inside the array mean the same as a string `input`.
    if let Some(text) = item.as_str() {
        charge_input(used, text.len())?;
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
            let text = message_text(obj.get("content"), used)?;
            out.push(json!({"role": role, "content": text}));
            Ok(())
        }
        "input_text" => {
            let text = obj.get("text").and_then(Value::as_str).unwrap_or_default();
            charge_input(used, text.len())?;
            out.push(user_message(text));
            Ok(())
        }
        other => Err(bad_request(format!(
            "'input' item type '{other}' is not supported"
        ))),
    }
}

/// Flatten a message `content` (string or array of parts) to plain text.
fn message_text(content: Option<&Value>, used: &mut usize) -> Result<String, (StatusCode, String)> {
    match content {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => {
            charge_input(used, s.len())?;
            Ok(s.clone())
        }
        Some(Value::Array(parts)) => {
            let mut text = String::new();
            for part in parts {
                match part {
                    Value::String(s) => {
                        charge_input(used, s.len())?;
                        text.push_str(s);
                    }
                    Value::Object(o) => {
                        let ty = o
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or("input_text");
                        match ty {
                            // `output_text` appears when a client replays a previous
                            // assistant turn back to us.
                            "input_text" | "output_text" | "text" => {
                                let piece =
                                    o.get("text").and_then(Value::as_str).unwrap_or_default();
                                charge_input(used, piece.len())?;
                                text.push_str(piece);
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
    previous_response_id: Option<&str>,
) -> Value {
    let (input_tokens, output_tokens) = usage;
    json!({
        "id": id,
        "object": "response",
        "created_at": created_at,
        "status": "completed",
        "model": model,
        // The turn this one continues, exactly as the client sent it (null for a
        // fresh conversation), so a client can chain without bookkeeping.
        "previous_response_id": previous_response_id,
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
            "total_tokens": input_tokens.saturating_add(output_tokens),
        },
    })
}

async fn non_stream_response(resp: Response, ctx: &ResponseContext) -> Response {
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
    let id = random_id("resp_");
    let created_at = unix_now();
    let usage = usage_pair(&chat);
    // Batched write: the client is not made to wait for the state file.
    ctx.persist(&id, created_at, text, usage);
    Json(response_object(
        &id,
        created_at,
        &ctx.model,
        &random_id("msg_"),
        text,
        usage,
        ctx.previous_response_id.as_deref(),
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
    /// Echoed in every snapshot of the response object.
    previous_response_id: Option<String>,
    text: String,
    usage: (u64, u64),
    /// `output_item.added` is emitted lazily, right before the first delta.
    item_added: bool,
    /// Set once the terminal event was sent, so `[DONE]` followed by EOF (the
    /// normal case) cannot complete the response twice.
    completed: bool,
    /// True when the terminal event was `response.completed` (not `failed`):
    /// only then is there a response worth storing.
    ok: bool,
    sequence: u64,
}

impl StreamMapper {
    fn new(model: String, previous_response_id: Option<String>) -> Self {
        Self {
            resp_id: random_id("resp_"),
            item_id: random_id("msg_"),
            model,
            created_at: unix_now(),
            previous_response_id,
            text: String::new(),
            usage: (0, 0),
            item_added: false,
            completed: false,
            ok: false,
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
            "previous_response_id": self.previous_response_id.as_deref(),
            "output": output,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens.saturating_add(output_tokens),
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
        self.push_text(delta);
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

    /// Append a delta to the accumulated reply, stopping at [`MAX_OUTPUT_TEXT`].
    ///
    /// Truncating on a `char` boundary keeps the stored/reported text valid
    /// UTF-8 even when the cut lands inside a multi-byte character, and the delta
    /// itself has already gone to the client untouched — only the copy we keep is
    /// bounded.
    fn push_text(&mut self, delta: &str) {
        let remaining = MAX_OUTPUT_TEXT.saturating_sub(self.text.len());
        if remaining == 0 {
            return;
        }
        let mut end = delta.len().min(remaining);
        while end > 0 && !delta.is_char_boundary(end) {
            end -= 1;
        }
        self.text.push_str(&delta[..end]);
    }

    /// Terminal frames: `output_text.done` then `response.completed`.
    fn finish(&mut self) -> Vec<Bytes> {
        if self.completed {
            return Vec::new();
        }
        self.completed = true;
        // From here on the reply is real: the relay stores it.
        self.ok = true;
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
            self.previous_response_id.as_deref(),
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
    /// Where the finished response is stored, and whether that already happened.
    ctx: ResponseContext,
    saved: bool,
}

/// Relay the upstream chat SSE as Responses SSE.
///
/// The key guard lives inside the upstream body, so it keeps the in-flight slot
/// until this stream is dropped — no extra bookkeeping needed here.
fn sse_response(resp: Response, ctx: ResponseContext) -> Response {
    let mut mapper = StreamMapper::new(ctx.model.clone(), ctx.previous_response_id.clone());
    let queue: VecDeque<Bytes> = mapper.start().into();
    let state = StreamState {
        upstream: Box::pin(resp.into_body().into_data_stream()),
        parser: SseParser::new(),
        mapper,
        queue,
        ended: false,
        ctx,
        saved: false,
    };

    // `unfold` with an explicit queue: a single upstream chunk usually yields
    // several events, and a plain `scan` would force one frame per poll.
    let stream = futures::stream::unfold(Some(state), |prev| async move {
        let mut st = prev?;
        loop {
            // Store the reply before its terminal frame leaves: a follow-up may
            // arrive as soon as the client sees `response.completed`.
            if st.mapper.ok && !st.saved {
                st.saved = true;
                st.ctx.persist(
                    &st.mapper.resp_id,
                    st.mapper.created_at,
                    &st.mapper.text,
                    st.mapper.usage,
                );
            }
            if let Some(frame) = st.queue.pop_front() {
                return Some((Ok::<Bytes, std::io::Error>(frame), Some(st)));
            }
            if st.ended {
                return None;
            }
            match st.upstream.next().await {
                Some(Ok(chunk)) => match st.parser.feed_checked(&chunk) {
                    Ok(payloads) => {
                        for payload in payloads {
                            let frames = st.mapper.feed(&payload);
                            st.queue.extend(frames);
                        }
                    }
                    Err(e) => {
                        // The upstream is not framing events at all (an endless
                        // line): end the response with `response.failed` instead of
                        // relaying a truncated conversation as if it had finished.
                        debug!(error = %e, "upstream SSE event exceeded the parser cap");
                        st.ended = true;
                        let frames = st.mapper.fail(&json!({
                            "type": "upstream_error",
                            "message": e.to_string(),
                        }));
                        st.queue.extend(frames);
                    }
                },
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

    /// Context with the store off — what a gateway without a state file builds.
    fn test_ctx(model: &str, previous: Option<&str>) -> ResponseContext {
        ResponseContext {
            input: json!([{"role": "user", "content": "hi"}]),
            model: model.to_string(),
            provider: "test".to_string(),
            previous_response_id: previous.map(str::to_string),
            storage: None,
            owner: None,
        }
    }

    /// Unique scratch state file: redb locks the path, so tests must not share one.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "anyhop-responses-{tag}-{}-{nanos}.redb",
            std::process::id()
        ))
    }

    fn stored(id: &str, created_at: u64) -> StoredResponse {
        StoredResponse {
            id: id.to_string(),
            created_at,
            model: "m".to_string(),
            provider: "mock".to_string(),
            input: json!([
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"}
            ]),
            output_text: "hello".to_string(),
            usage: None,
            owner: None,
        }
    }

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

    // ----- previous_response_id (the response store) -----

    #[test]
    fn replay_prepends_the_original_input_and_the_assistant_output() {
        let prev = stored("resp_1", 1);
        let mut chat = to_chat_request(&json!({"model": "m", "input": "again"}))
            .expect("a plain follow-up translates");
        replay_history(&mut chat, &prev);
        assert_eq!(
            chat["messages"],
            json!([
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"},
                {"role": "user", "content": "again"},
            ])
        );
        // Only the messages are touched.
        assert_eq!(chat["model"], "m");
    }

    #[test]
    fn a_follow_up_keeps_its_own_knobs_after_the_replayed_history() {
        let mut chat = to_chat_request(&json!({
            "model": "m",
            "input": "again",
            "max_output_tokens": 32,
            "stream": true
        }))
        .expect("supported knobs");
        replay_history(&mut chat, &stored("resp_1", 1));
        assert_eq!(chat["max_tokens"], 32);
        assert_eq!(chat["stream"], true);
        assert_eq!(
            chat["messages"].as_array().map(Vec::len),
            Some(4),
            "history is prepended, not merged"
        );
    }

    #[test]
    fn previous_response_id_without_a_store_is_a_400() {
        let (status, message) =
            resolve_previous(&json!({"previous_response_id": "resp_1"}), None, 1000, None)
                .expect_err("no store: the id must be refused, not ignored");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("previous_response_id"), "{message}");
        assert!(
            message.contains("response storage is disabled"),
            "{message}"
        );
    }

    #[test]
    fn a_null_previous_response_id_starts_a_conversation() {
        let prev = resolve_previous(&json!({"previous_response_id": null}), None, 1000, None)
            .expect("null means 'no previous response'");
        assert!(prev.is_none());
    }

    #[test]
    fn a_non_string_previous_response_id_is_a_400() {
        let (status, message) =
            resolve_previous(&json!({"previous_response_id": 7}), None, 1000, None)
                .expect_err("an id must be a string");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("previous_response_id"), "{message}");
    }

    #[tokio::test]
    async fn a_stored_response_resolves_and_an_unknown_id_is_a_400() {
        let path = scratch("resolve");
        let store = Storage::open(path.to_str().expect("temp path is UTF-8"))
            .expect("the state file opens");
        store.set_response_max(10);
        store.save_response("resp_1", stored("resp_1", 1));
        store.flush_async().await;

        let prev = resolve_previous(
            &json!({"previous_response_id": "resp_1"}),
            Some(&store),
            10,
            None,
        )
        .expect("a stored id resolves")
        .expect("the record comes back");
        assert_eq!(prev.output_text, "hello");

        let (status, message) = resolve_previous(
            &json!({"previous_response_id": "resp_gone"}),
            Some(&store),
            10,
            None,
        )
        .expect_err("nothing was stored under that id");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("unknown or expired"), "{message}");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_zero_store_cap_refuses_previous_response_id() {
        let path = scratch("disabled");
        let store = Storage::open(path.to_str().expect("temp path is UTF-8"))
            .expect("the state file opens");
        store.save_response("resp_1", stored("resp_1", 1));
        store.flush_async().await;

        // The record is still on disk, but the feature is off: refusing is the
        // only honest answer (a fresh conversation would look like a replay).
        let (status, message) = resolve_previous(
            &json!({"previous_response_id": "resp_1"}),
            Some(&store),
            0,
            None,
        )
        .expect_err("a zero cap disables the store");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            message.contains("response storage is disabled"),
            "{message}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A record can carry an owner; the base helper stays ownerless so the
    /// upgrade path (records written before ownership) keeps a test too.
    fn owned(id: &str, created_at: u64, owner: &str) -> StoredResponse {
        StoredResponse {
            owner: Some(owner.to_string()),
            ..stored(id, created_at)
        }
    }

    /// The record is bound to the key that produced it: the same key replays it,
    /// another key gets exactly the "unknown or expired" 400 an id that never
    /// existed would get.
    #[tokio::test]
    async fn a_stored_response_only_replays_for_its_own_key() {
        let path = scratch("owner");
        let store = Storage::open(path.to_str().expect("temp path is UTF-8"))
            .expect("the state file opens");
        store.set_response_max(10);
        store.save_response("resp_mine", owned("resp_mine", 1, "key-a"));
        store.flush_async().await;

        let prev = resolve_previous(
            &json!({"previous_response_id": "resp_mine"}),
            Some(&store),
            10,
            Some("key-a"),
        )
        .expect("the owner replays its own turn")
        .expect("the record comes back");
        assert_eq!(prev.output_text, "hello");

        let (status, message) = resolve_previous(
            &json!({"previous_response_id": "resp_mine"}),
            Some(&store),
            10,
            Some("key-b"),
        )
        .expect_err("another key must not read this conversation");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("unknown or expired"), "{message}");
        // Indistinguishable from an id that was never stored: the answer must not
        // confirm that this response id exists. Only the echoed id differs.
        let (_, missing) = resolve_previous(
            &json!({"previous_response_id": "resp_missing"}),
            Some(&store),
            10,
            Some("key-b"),
        )
        .expect_err("unknown id");
        assert_eq!(
            message.replace("resp_mine", "<id>"),
            missing.replace("resp_missing", "<id>")
        );

        // A record with no owner (written before ownership was tracked) still
        // replays: an upgrade must not cut live conversations off.
        store.save_response("resp_legacy", stored("resp_legacy", 2));
        store.flush_async().await;
        assert!(
            resolve_previous(
                &json!({"previous_response_id": "resp_legacy"}),
                Some(&store),
                10,
                Some("key-b"),
            )
            .is_ok(),
            "an unowned record stays replayable"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The non-stream handler path end to end: store the reply, get the id back,
    /// replay it into a follow-up.
    #[tokio::test]
    async fn a_non_stream_completion_is_stored_and_replays() {
        let path = scratch("nonstream");
        let store = Storage::open(path.to_str().expect("temp path is UTF-8"))
            .expect("the state file opens");
        store.set_response_max(10);
        let ctx = ResponseContext {
            input: json!([{"role": "user", "content": "hi"}]),
            model: "m".to_string(),
            provider: "mock".to_string(),
            previous_response_id: Some("resp_prev".to_string()),
            storage: Some(store.clone()),
            owner: None,
        };
        let upstream = json!({
            "choices": [{"message": {"role": "assistant", "content": "hello"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}
        });
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(upstream.to_string()))
            .expect("an in-memory response is well formed");

        let out = non_stream_response(resp, &ctx).await;
        let body = axum::body::to_bytes(out.into_body(), 1 << 20)
            .await
            .expect("the body collects");
        let body: Value = serde_json::from_slice(&body).expect("the body is JSON");
        let id = body["id"]
            .as_str()
            .expect("the response has an id")
            .to_string();
        assert_eq!(body["previous_response_id"], "resp_prev");

        store.flush_async().await;
        let rec = store.load_response(&id).expect("the reply was stored");
        assert_eq!(rec.output_text, "hello");
        assert_eq!(rec.model, "m");
        assert_eq!(rec.provider, "mock");
        assert_eq!(rec.input, json!([{"role": "user", "content": "hi"}]));
        assert_eq!(
            rec.usage,
            Some(json!({"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}))
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Same for the streaming path: the reply is stored by the relay, before the
    /// `response.completed` frame is handed to the client.
    #[tokio::test]
    async fn a_streaming_completion_is_stored() {
        let path = scratch("stream");
        let store = Storage::open(path.to_str().expect("temp path is UTF-8"))
            .expect("the state file opens");
        store.set_response_max(10);
        let ctx = ResponseContext {
            input: json!([{"role": "user", "content": "hi"}]),
            model: "m".to_string(),
            provider: "mock".to_string(),
            previous_response_id: None,
            storage: Some(store.clone()),
            owner: None,
        };
        let upstream = futures::stream::iter(vec![
            Ok::<Bytes, std::io::Error>(Bytes::from_static(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n",
            )),
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: [DONE]\n\n")),
        ]);
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(upstream))
            .expect("an in-memory response is well formed");

        let relayed = sse_response(resp, ctx);
        let body = axum::body::to_bytes(relayed.into_body(), 1 << 20)
            .await
            .expect("the relayed body collects");
        let text = std::str::from_utf8(&body).expect("frames are UTF-8");
        let completed = text
            .split("\n\n")
            .find(|frame| frame.starts_with("event: response.completed"))
            .expect("the stream completed");
        let data = completed
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("the frame carries data");
        let done: Value = serde_json::from_str(data).expect("the payload is JSON");
        let id = done["response"]["id"]
            .as_str()
            .expect("the response has an id")
            .to_string();
        assert_eq!(done["response"]["previous_response_id"], Value::Null);

        store.flush_async().await;
        let rec = store
            .load_response(&id)
            .expect("the streamed reply was stored");
        assert_eq!(rec.output_text, "Hi");

        let _ = std::fs::remove_file(&path);
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
            None,
        );

        assert_eq!(out["object"], "response");
        assert_eq!(out["status"], "completed");
        assert_eq!(out["id"], "resp_abc");
        assert_eq!(out["model"], "m");
        // A fresh conversation says so explicitly rather than omitting the field.
        assert_eq!(out["previous_response_id"], Value::Null);
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
        let mut mapper = StreamMapper::new("m".to_string(), None);
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
        let mut mapper = StreamMapper::new("m".to_string(), None);
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
        let mut mapper = StreamMapper::new("m".to_string(), None);
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

    #[test]
    fn streaming_echoes_previous_response_id_in_every_response_object() {
        let mut mapper = StreamMapper::new("m".to_string(), Some("resp_prev".to_string()));
        let mut frames = mapper.start();
        frames.extend(mapper.feed(br#"{"choices":[{"delta":{"content":"x"}}]}"#));
        frames.extend(mapper.finish());
        assert_eq!(
            data_of(&frames[0])["response"]["previous_response_id"],
            "resp_prev"
        );
        let completed = data_of(frames.last().expect("there is a terminal frame"));
        assert_eq!(completed["response"]["previous_response_id"], "resp_prev");
        assert!(mapper.ok, "a completed stream is worth storing");
    }

    /// A provider streaming forever must not grow the retained reply without
    /// bound: the deltas reach the client, the copy we keep stops at the cap, and
    /// the terminal events still describe valid UTF-8.
    #[test]
    fn the_accumulated_text_stops_at_the_cap_on_a_char_boundary() {
        let mut mapper = StreamMapper::new("m".to_string(), None);
        let _ = mapper.start();
        // "€" is three bytes, so the cap lands inside a character.
        let big = "€".repeat((MAX_OUTPUT_TEXT / 3) + 1000);
        let chunk = json!({"choices": [{"delta": {"content": big}}]}).to_string();
        let frames = mapper.feed(chunk.as_bytes());
        assert_eq!(
            event_names(&frames),
            vec!["response.output_item.added", "response.output_text.delta"]
        );
        assert!(
            mapper.text.len() <= MAX_OUTPUT_TEXT,
            "retained {} bytes, cap is {MAX_OUTPUT_TEXT}",
            mapper.text.len()
        );
        assert!(
            mapper.text.len() > MAX_OUTPUT_TEXT - 3,
            "the cap must be reached, not undershot"
        );
        assert_eq!(
            mapper.text.chars().count() * 3,
            mapper.text.len(),
            "truncation cut through a character"
        );
        // The terminal events report exactly the text that was kept.
        let done = mapper.finish();
        assert_eq!(
            data_of(&done[0])["text"].as_str().map(str::len),
            Some(mapper.text.len())
        );
        assert_eq!(
            data_of(&done[1])["response"]["output_text"]
                .as_str()
                .map(str::len),
            Some(mapper.text.len())
        );
    }

    #[test]
    fn a_failed_stream_is_not_stored() {
        let mut mapper = StreamMapper::new("m".to_string(), None);
        let _ = mapper.start();
        let _ = mapper.feed(br#"{"error":{"message":"boom"}}"#);
        assert!(mapper.completed);
        // `response.failed` is terminal but carries no reply: storing it would let
        // the next turn "continue" a conversation with an empty assistant turn.
        assert!(!mapper.ok);
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

        let relayed = sse_response(resp, test_ctx("m", None));
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

    /// A provider that never sends a blank line is not framing SSE at all: the
    /// response ends with `response.failed` instead of relaying a truncated
    /// conversation as if it had completed.
    #[tokio::test]
    async fn an_endless_upstream_event_fails_the_stream_cleanly() {
        let huge = vec![b'x'; 1536 * 1024]; // > the 1 MiB event cap, no blank line
        let upstream = futures::stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::from(huge))]);
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(upstream))
            .expect("in-memory response is well formed");

        let relayed = sse_response(resp, test_ctx("m", None));
        let body = axum::body::to_bytes(relayed.into_body(), 1 << 20)
            .await
            .expect("the relayed body collects");
        let text = std::str::from_utf8(&body).expect("frames are UTF-8");
        assert!(
            text.contains("event: response.failed"),
            "the stream must fail loudly: {text}"
        );
        assert!(
            !text.contains("event: response.completed"),
            "an unfinished reply must not be reported as complete"
        );
        assert!(text.contains("cap"), "the error names the cap: {text}");
    }

    #[test]
    fn upstream_error_frame_ends_the_stream_as_failed() {
        let mut mapper = StreamMapper::new("m".to_string(), None);
        let mut frames = mapper.start();
        frames.extend(mapper.feed(br#"{"error":{"message":"boom","type":"server_error"}}"#));
        assert_eq!(
            event_names(&frames),
            vec!["response.created", "response.failed"]
        );
        assert!(mapper.finish().is_empty(), "failed is terminal too");
        assert_eq!(data_of(&frames[1])["error"]["message"], "boom");
    }

    // ----- hostile request bodies -----
    //
    // `input` is attacker-controlled and this endpoint cannot relay it verbatim:
    // it flattens it into chat messages, so every test here pins the bound that
    // stops a small body from becoming a large allocation.

    #[test]
    fn deeply_nested_input_is_a_clean_error() {
        // 1000 levels of `[[[…]]]` as an input item. The translator inspects one
        // level only, so there is nothing to recurse into and the answer is a
        // plain 400.
        let mut item = json!("bottom");
        for _ in 0..1000 {
            item = Value::Array(vec![item]);
        }
        let (status, message) =
            to_chat_request(&json!({"model": "m", "input": [item]})).expect_err("not a message");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("object or a string"), "{message}");

        // The same shape inside a message's `content` is refused just as flatly.
        let mut part = json!("bottom");
        for _ in 0..1000 {
            part = Value::Array(vec![part]);
        }
        let (status, message) = to_chat_request(&json!({
            "model": "m",
            "input": [{"type": "message", "role": "user", "content": [part]}]
        }))
        .expect_err("not a content part");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("content parts"), "{message}");
    }

    #[test]
    fn a_thousand_levels_of_json_is_refused_by_the_parser_first() {
        // The handler parses before it translates; serde_json's own recursion
        // limit means such a body never even becomes a `Value`, which is the
        // outermost of the two guards.
        let deep = format!("{}{}", "[".repeat(1000), "]".repeat(1000));
        assert!(
            serde_json::from_slice::<Value>(deep.as_bytes()).is_err(),
            "a 1000-deep body must not deserialize"
        );
        // A depth that really is harmless still parses, so the limit is not
        // rejecting ordinary nesting.
        assert!(serde_json::from_slice::<Value>(b"[[1]]").is_ok());
    }

    #[test]
    fn a_ten_megabyte_input_is_refused_and_a_large_one_still_works() {
        // 10 MiB of text: refused before the message is built.
        let (status, message) = to_chat_request(&json!({
            "model": "m",
            "input": "x".repeat(10 << 20),
        }))
        .expect_err("over the input cap");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("too large"), "{message}");

        // Just under the cap is translated unchanged: ordinary large prompts keep
        // working, so the cap is a bound and not a behaviour change.
        let text = "y".repeat((8 << 20) - 16);
        let chat = to_chat_request(&json!({"model": "m", "input": text}))
            .expect("under the cap is accepted");
        assert_eq!(
            chat["messages"][0]["content"].as_str().map(str::len),
            Some((8 << 20) - 16)
        );
    }

    #[test]
    fn too_many_input_items_are_refused_before_they_become_messages() {
        // Empty strings are three bytes of body each but a whole `Value` plus a
        // whole message each, so the count is capped independently of the bytes.
        let items: Vec<Value> = (0..=MAX_INPUT_ITEMS).map(|_| json!("")).collect();
        let (status, message) = to_chat_request(&json!({"model": "m", "input": items}))
            .expect_err("item cap must bite");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("items"), "{message}");

        // Exactly at the cap is still translated.
        let items: Vec<Value> = (0..MAX_INPUT_ITEMS).map(|_| json!("")).collect();
        let chat =
            to_chat_request(&json!({"model": "m", "input": items})).expect("the cap is inclusive");
        assert_eq!(
            chat["messages"].as_array().map(Vec::len),
            Some(MAX_INPUT_ITEMS)
        );
    }

    #[test]
    fn non_object_input_items_are_rejected() {
        for item in [json!(42), json!(1.5), json!(true), json!(null), json!([])] {
            let (status, _) = to_chat_request(&json!({"model": "m", "input": [item.clone()]}))
                .expect_err("not a message");
            assert_eq!(status, StatusCode::BAD_REQUEST, "{item}");
        }
        // An object with an unsupported item type is refused by name.
        let (status, message) = to_chat_request(&json!({
            "model": "m",
            "input": [{"type": "function_call"}]
        }))
        .expect_err("unsupported item type");
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("function_call"), "{message}");

        // …and `input` itself must be a string or an array.
        for bad in [json!(7), json!(true), json!({"a": 1})] {
            let (status, message) =
                to_chat_request(&json!({"model": "m", "input": bad})).expect_err("not an input");
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(message.contains("string or an array"), "{message}");
        }
    }

    #[test]
    fn null_and_empty_content_become_an_empty_message() {
        // Not an error: a message with no content is a legal (if empty) turn.
        let chat = to_chat_request(&json!({
            "model": "m",
            "input": [{"type": "message", "role": "user", "content": null}]
        }))
        .expect("null content is legal");
        assert_eq!(chat["messages"], json!([{"role": "user", "content": ""}]));

        // An empty part array does the same, and a part with no `text` adds "".
        let chat = to_chat_request(&json!({
            "model": "m",
            "input": [
                {"role": "user", "content": []},
                {"role": "user", "content": [{"type": "input_text"}, {"type": "input_text", "text": "tail"}]}
            ]
        }))
        .expect("empty parts are legal");
        assert_eq!(chat["messages"][0]["content"], "");
        assert_eq!(chat["messages"][1]["content"], "tail");
    }

    #[test]
    fn huge_max_output_tokens_is_clamped_not_overflowed() {
        for asked in [
            u64::MAX,
            u64::MAX / 2,
            MAX_OUTPUT_TOKENS + 1,
            1_000_000_000_000,
        ] {
            let chat = to_chat_request(&json!({
                "model": "m",
                "input": "hi",
                "max_output_tokens": asked,
            }))
            .expect("an over-large budget is clamped, not fatal");
            assert_eq!(
                chat["max_tokens"],
                json!(MAX_OUTPUT_TOKENS),
                "{asked} was not clamped"
            );
            // The clamped value must be readable both ways: the translators use
            // `as_u64` and `as_i64`.
            assert_eq!(chat["max_tokens"].as_u64(), Some(MAX_OUTPUT_TOKENS));
            assert_eq!(chat["max_tokens"].as_i64(), Some(MAX_OUTPUT_TOKENS as i64));
        }
        // A sane budget is forwarded untouched.
        let chat = to_chat_request(&json!({"model": "m", "input": "hi", "max_output_tokens": 256}))
            .expect("sane budget");
        assert_eq!(chat["max_tokens"], 256);
        // Zero, negatives and non-numbers are still refused.
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("256"),
            json!({}),
            json!([]),
        ] {
            let (status, message) = to_chat_request(&json!({
                "model": "m",
                "input": "hi",
                "max_output_tokens": bad,
            }))
            .expect_err("not a positive integer");
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(message.contains("max_output_tokens"), "{bad}: {message}");
        }
    }

    #[test]
    fn a_previous_response_id_chain_grows_linearly_and_cannot_cycle() {
        // Replay is a *flatten*, not a walk: `replay_history` copies the stored
        // messages and never follows `previous_response_id`. A cycle is therefore
        // structurally impossible — there is no pointer to loop on — and the only
        // cost is the linear growth of the flattened history shown here.
        let mut prev = stored("resp_0", 0);
        let mut prev_len = 2; // `stored()` carries two messages
        for turn in 1..=100u64 {
            let mut chat = to_chat_request(&json!({"model": "m", "input": format!("turn {turn}")}))
                .expect("a plain follow-up translates");
            replay_history(&mut chat, &prev);
            let messages = chat["messages"].as_array().expect("messages").clone();
            assert_eq!(messages.len(), prev_len + 2, "turn {turn}");
            assert_eq!(messages[0]["content"], "be terse");
            assert_eq!(messages[prev_len]["role"], "assistant");
            assert_eq!(messages[prev_len]["content"], "hello");
            assert_eq!(messages[prev_len + 1]["content"], format!("turn {turn}"));
            // The next record stores exactly what went upstream — the expansion
            // itself, not a reference — which is what makes the chain terminate.
            prev_len = messages.len();
            prev = StoredResponse {
                id: format!("resp_{turn}"),
                input: Value::Array(messages),
                ..stored("scratch", turn)
            };
        }
        assert_eq!(prev_len, 2 + 2 * 100);

        // Records with an unexpected shape still replay, defensively.
        let mut rec = stored("resp_s", 0);
        rec.input = json!("legacy string input");
        let mut chat = to_chat_request(&json!({"model": "m", "input": "next"})).expect("ok");
        replay_history(&mut chat, &rec);
        assert_eq!(
            chat["messages"],
            json!([
                {"role": "user", "content": "legacy string input"},
                {"role": "assistant", "content": "hello"},
                {"role": "user", "content": "next"},
            ])
        );
        rec.input = Value::Null;
        let mut chat = to_chat_request(&json!({"model": "m", "input": "next"})).expect("ok");
        replay_history(&mut chat, &rec);
        assert_eq!(chat["messages"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn absurd_upstream_usage_saturates_instead_of_overflowing() {
        // `usage` comes from the upstream body, so both numbers are arbitrary
        // u64s. `u64::MAX + 1` must not panic a debug build (or wrap into a tiny
        // total in release).
        let chat = json!({"usage": {"prompt_tokens": u64::MAX, "completion_tokens": 1}});
        let usage = usage_pair(&chat);
        assert_eq!(usage, (u64::MAX, 1));

        let out = response_object("resp_x", 0, "m", "msg_x", "hi", usage, None);
        assert_eq!(out["usage"]["input_tokens"], json!(u64::MAX));
        assert_eq!(out["usage"]["output_tokens"], json!(1));
        assert_eq!(out["usage"]["total_tokens"], json!(u64::MAX));

        // The streaming snapshots sum the same numbers.
        let mut mapper = StreamMapper::new("m".to_string(), None);
        mapper.usage = usage;
        let snapshot = mapper.snapshot("completed", json!([]));
        assert_eq!(snapshot["usage"]["total_tokens"], json!(u64::MAX));
    }

    #[tokio::test]
    async fn storing_absurd_usage_saturates_too() {
        let path = scratch("usage");
        let store = Storage::open(path.to_str().expect("temp path is UTF-8"))
            .expect("the state file opens");
        store.set_response_max(10);
        let ctx = ResponseContext {
            input: json!([{"role": "user", "content": "hi"}]),
            model: "m".to_string(),
            provider: "mock".to_string(),
            previous_response_id: None,
            storage: Some(store.clone()),
            owner: None,
        };
        ctx.persist("resp_huge", 1, "hi", (u64::MAX, 1));
        store.flush_async().await;
        let rec = store
            .load_response("resp_huge")
            .expect("the reply was stored");
        assert_eq!(
            rec.usage.as_ref().and_then(|u| u.get("total_tokens")),
            Some(&json!(u64::MAX))
        );
        let _ = std::fs::remove_file(&path);
    }
}
