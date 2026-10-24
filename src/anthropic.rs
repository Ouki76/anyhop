//! Anthropic (/v1/messages) ⇄ OpenAI (chat/completions) translation layer.

use std::collections::VecDeque;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::{Value, json};

pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
pub const API_VERSION: &str = "2023-06-01";

/// The Messages endpoint for a configured `base_url`.
///
/// A base that already ends in `/v1` is a normal spelling (`https://api.anthropic.com/v1`,
/// the same convention the example config uses for openai_compat) and the model
/// listing already tolerates it. Appending blindly here produced `/v1/v1/messages`
/// → 404 for chat while `/v1/models` worked, which is a confusing pair of symptoms.
pub fn messages_url(base_url: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if base.is_empty() {
        format!("{DEFAULT_BASE_URL}/v1/messages")
    } else if base.ends_with("/v1") {
        format!("{base}/messages")
    } else {
        format!("{base}/v1/messages")
    }
}

/// Anthropic's `content_block.*` events carry a block index. Anything past this
/// is hostile: the index used to be fed straight into a `Vec` resize, so
/// `index: 18446744073709551615` overflowed (panic in debug, out of bounds in
/// release) and `index: 1000000000` asked the allocator for a 16 GB vector.
const MAX_BLOCK_INDEX: u64 = 1024;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn gen_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("chatcmpl-{nanos:x}")
}

// ---------- request translation (OpenAI -> Anthropic) ----------

/// OpenAI content -> Anthropic content blocks.
///
/// A part we cannot translate is an error, not something to drop: dropping it
/// left `content: []`, which the upstream rejects with a confusing 400 about
/// empty content *after* the round trip.
fn content_blocks(content: Option<&Value>) -> Result<Vec<Value>, String> {
    match content {
        None => Ok(vec![json!({"type": "text", "text": ""})]),
        Some(Value::String(s)) => Ok(vec![json!({"type": "text", "text": s})]),
        Some(Value::Array(arr)) => {
            let mut blocks = Vec::new();
            for p in arr {
                match p.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        let mut b = json!({"type": "text", "text": p.get("text").cloned().unwrap_or(json!(""))});
                        // Prompt caching: forward cache_control breakpoints as-is.
                        if let Some(cc) = p.get("cache_control") {
                            b["cache_control"] = cc.clone();
                        }
                        blocks.push(b);
                    }
                    Some("image_url") => {
                        let url = p
                            .pointer("/image_url/url")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        match url
                            .strip_prefix("data:")
                            .and_then(|d| d.split_once(";base64,"))
                        {
                            Some((mime, b64)) => blocks.push(json!({
                                "type": "image",
                                "source": {"type": "base64", "media_type": mime, "data": b64},
                            })),
                            None => {
                                return Err(format!(
                                    "unsupported image_url '{url}': only base64 data: URLs \
                                     can be translated to an Anthropic image block"
                                ));
                            }
                        }
                    }
                    other => {
                        return Err(format!(
                            "unsupported content part type '{}'",
                            other.unwrap_or("<missing>")
                        ));
                    }
                }
            }
            if blocks.is_empty() {
                return Err("message has no translatable content parts".into());
            }
            Ok(blocks)
        }
        _ => Err("unsupported message content type".into()),
    }
}

/// OpenAI content may be a plain string or an array of text parts.
/// (Same helper as gemini.rs — array-form system/assistant/tool messages used
/// to be silently dropped or JSON-dumped into the text.)
fn content_text(content: Option<&Value>) -> Option<String> {
    match content {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(parts)) => {
            let t: String = parts
                .iter()
                .filter(|p| p.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect();
            if t.is_empty() { None } else { Some(t) }
        }
        _ => None,
    }
}

/// Anthropic requires max_tokens. Default must fit every model's output cap:
/// claude-3-haiku caps at 4096, 3.5/3.7 at 8192, 4.x allows far more — but a
/// default that exceeds the cap is a hard 400, so stay conservative.
fn default_max_tokens(model: &str) -> u64 {
    max_output_cap(model).min(8192)
}

/// The model's *maximum* output tokens.
///
/// Used to clamp a `max_tokens` this module inflates to fit a thinking budget:
/// `reasoning_effort = "high"` (24576) on a claude-3.5 (8192 cap) used to become
/// `max_tokens: 24577`, which Anthropic rejects outright — so the feature failed
/// with a 400 on exactly the models that need the smaller budget.
fn max_output_cap(model: &str) -> u64 {
    if model.contains("claude-3-haiku") || model.contains("haiku-3") {
        4096
    } else if model.contains("claude-3") {
        8192
    } else if model.contains("claude-4") || model.contains("sonnet-4") || model.contains("opus-4") {
        // 4.x family allows up to 64k on the long-output variants.
        64000
    } else {
        8192
    }
}

/// Prompt tokens actually billed for a request.
///
/// Anthropic *excludes* `cache_read_input_tokens` and `cache_creation_input_tokens`
/// from `input_tokens`, so a cached conversation reported a `prompt_tokens` far
/// below the real context — clients sizing context windows and the pool's token
/// counters both undercounted. The cached share is also surfaced the way OpenAI
/// does (`prompt_tokens_details.cached_tokens`).
fn prompt_usage(u: &Value) -> (u64, u64) {
    let plain = u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
    let cache_read = u
        .get("cache_read_input_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let cache_write = u
        .get("cache_creation_input_tokens")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    (
        plain.saturating_add(cache_read).saturating_add(cache_write),
        cache_read,
    )
}

/// Replay the thinking blocks we handed the client (text + signature) as the
/// *first* blocks of the assistant turn.
///
/// Anthropic validates the signature, and with thinking enabled it rejects a
/// turn that starts with `tool_use` — which is exactly what a response without
/// the signature collapsed into on the second turn.
fn replay_thinking(msg: &Value, blocks: &mut Vec<Value>) {
    let Some(arr) = msg.get("thinking_blocks").and_then(|b| b.as_array()) else {
        return;
    };
    for b in arr {
        match b.get("type").and_then(|t| t.as_str()) {
            Some("thinking") => {
                let mut block = json!({
                    "type": "thinking",
                    "thinking": b.get("thinking").cloned().unwrap_or(json!("")),
                });
                if let Some(sig) = b
                    .get("signature")
                    .and_then(|s| s.as_str())
                    .filter(|s| !s.is_empty())
                {
                    block["signature"] = json!(sig);
                }
                blocks.push(block);
            }
            Some("redacted_thinking") => {
                if let Some(data) = b.get("data") {
                    blocks.push(json!({"type": "redacted_thinking", "data": data}));
                }
            }
            _ => {}
        }
    }
}

pub fn translate_request(body: &Value) -> Result<Value, String> {
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or("missing 'messages' array")?;

    // Thinking: reasoning_effort / thinking.budget_tokens -> thinking config.
    // Resolved before the message loop because replayed thinking blocks are only
    // legal when thinking is enabled for *this* request.
    let budget = body
        .get("reasoning_effort")
        .and_then(|e| e.as_str())
        .and_then(|e| match e {
            "none" => Some(0),
            "minimal" | "low" => Some(1024),
            "medium" => Some(8192),
            "high" | "xhigh" | "max" => Some(24576),
            _ => None,
        })
        .or_else(|| {
            body.pointer("/thinking/budget_tokens")
                .and_then(|b| b.as_i64())
        });
    let thinking_on = budget.is_some_and(|b| b > 0);

    let mut system_texts: Vec<String> = Vec::new();
    let mut out_msgs: Vec<Value> = Vec::new();

    for msg in messages {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
        match role {
            "system" | "developer" => {
                if let Some(c) = content_text(msg.get("content")) {
                    system_texts.push(c);
                }
            }
            "user" => out_msgs.push(json!({
                "role": "user",
                "content": content_blocks(msg.get("content"))?,
            })),
            "assistant" => {
                let mut blocks = Vec::new();
                if thinking_on {
                    replay_thinking(msg, &mut blocks);
                }
                if let Some(t) = content_text(msg.get("content"))
                    && !t.is_empty()
                {
                    blocks.push(json!({"type": "text", "text": t}));
                }
                if let Some(tcs) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                    for tc in tcs {
                        let input: Value = tc
                            .pointer("/function/arguments")
                            .and_then(|a| a.as_str())
                            .and_then(|s| serde_json::from_str(s).ok())
                            .unwrap_or(json!({}));
                        blocks.push(json!({
                            "type": "tool_use",
                            "id": tc.get("id").cloned().unwrap_or(json!("")),
                            "name": tc.pointer("/function/name").cloned().unwrap_or(json!("")),
                            "input": input,
                        }));
                    }
                }
                if blocks.is_empty() {
                    blocks.push(json!({"type": "text", "text": ""}));
                }
                out_msgs.push(json!({"role": "assistant", "content": blocks}));
            }
            "tool" => {
                let result = content_text(msg.get("content")).unwrap_or_default();
                out_msgs.push(json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id").cloned().unwrap_or(json!("")),
                        "content": result,
                    }],
                }));
            }
            _ => {}
        }
    }

    // Anthropic requires strictly alternating user/assistant — merge same-role runs.
    let mut merged: Vec<Value> = Vec::new();
    for m in out_msgs {
        let role = m
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(last) = merged.last_mut()
            && last.get("role").and_then(|r| r.as_str()) == Some(role.as_str())
        {
            let content = m.get("content").cloned().unwrap_or(json!([]));
            if let Some(arr) = last.pointer_mut("/content").and_then(|c| c.as_array_mut())
                && let Some(add) = content.as_array()
            {
                arr.extend(add.iter().cloned());
            }
            continue;
        }
        merged.push(m);
    }

    let model_name = body.get("model").and_then(|m| m.as_str()).unwrap_or("");
    let mut req = json!({
        "model": body.get("model").cloned().unwrap_or(json!("")),
        // Anthropic requires max_tokens; the default must fit the model's
        // output cap (32000 is rejected outright by claude-3.5/3.7/haiku-3).
        "max_tokens": body
            .get("max_completion_tokens")
            .or_else(|| body.get("max_tokens"))
            .cloned()
            .unwrap_or_else(|| json!(default_max_tokens(model_name))),
        "messages": merged,
    });
    if !system_texts.is_empty() {
        req["system"] = json!(system_texts.join("\n\n"));
    }
    // OpenAI allows temperature/top_p up to 2.0; Anthropic rejects anything above
    // 1.0 with a hard 400. A client that is perfectly valid against an OpenAI model
    // used to fail through the gateway, so clamp (do not drop: the intent survives).
    if let Some(t) = body.get("temperature").and_then(|t| t.as_f64()) {
        req["temperature"] = json!(t.clamp(0.0, 1.0));
    }
    if let Some(t) = body.get("top_p").and_then(|t| t.as_f64())
        && t > 0.0
    {
        req["top_p"] = json!(t.clamp(0.0, 1.0));
    }
    if let Some(stop) = body.get("stop") {
        let seqs = match stop {
            Value::String(s) => vec![json!(s)],
            Value::Array(a) => a.clone(),
            _ => vec![],
        };
        if !seqs.is_empty() {
            req["stop_sequences"] = json!(seqs);
        }
    }
    match budget {
        Some(b) if b > 0 => {
            // Anthropic 400s when max_tokens <= budget_tokens — grow max_tokens
            // to fit the budget (clients rarely set both), but never past the
            // model's own output cap: a 24576-token budget on an 8192-cap model
            // was a guaranteed 400. Shrink the budget instead of the request.
            // saturating: `budget_tokens` is client-supplied, and i64::MAX would
            // otherwise panic on the add (debug) or wrap (release).
            let cap = max_output_cap(model_name);
            let cur = req["max_tokens"].as_i64().unwrap_or(0);
            if cur <= b {
                let new_max = b.saturating_add(1).min(cap as i64).max(1);
                req["max_tokens"] = json!(new_max);
            }
            // A budget at or above max_tokens is invalid: leave room for one token
            // of output so the request stays legal after the clamp.
            let max_tokens = req["max_tokens"].as_i64().unwrap_or(cap as i64);
            let b = b.min(max_tokens.saturating_sub(1)).max(1);
            // ...and rejects temperature/top_p combined with thinking — drop them.
            if let Some(o) = req.as_object_mut() {
                o.remove("temperature");
                o.remove("top_p");
            }
            req["thinking"] = json!({"type": "enabled", "budget_tokens": b});
        }
        Some(_) => {
            req["thinking"] = json!({"type": "disabled"});
        }
        None => {}
    }

    // Anthropic has no JSON mode. Dropping the field silently made a schema request
    // come back as prose with HTTP 200 (the client believed it had JSON); say so
    // instead, so the caller can pick another provider or drop the field.
    if let Some(rf) = body.get("response_format") {
        let kind = rf.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if kind == "json_schema" || kind == "json_object" {
            return Err(format!(
                "response_format '{kind}' is not supported by the anthropic provider (the \
                 Messages API has no JSON mode); use a provider that implements it or omit \
                 the field"
            ));
        }
    }

    if let Some(tools) = body.get("tools").and_then(|t| t.as_array()) {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let f = t.get("function")?;
                Some(json!({
                    "name": f.get("name")?,
                    "description": f.get("description").cloned().unwrap_or(json!("")),
                    "input_schema": f.get("parameters").cloned().unwrap_or(json!({"type": "object", "properties": {}})),
                }))
            })
            .collect();
        if !converted.is_empty() {
            req["tools"] = json!(converted);
        }
    }
    if let Some(tc) = body.get("tool_choice") {
        let choice = match tc {
            Value::String(s) => match s.as_str() {
                "none" => Some(json!({"type": "none"})),
                "required" => Some(json!({"type": "any"})),
                "auto" => Some(json!({"type": "auto"})),
                _ => None,
            },
            Value::Object(o) => o
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(|n| json!({"type": "tool", "name": n})),
            _ => None,
        };
        if let Some(c) = choice {
            req["tool_choice"] = c;
        }
    }

    Ok(req)
}

// ---------- response translation (Anthropic -> OpenAI) ----------

fn map_stop(r: Option<&str>) -> &'static str {
    match r {
        Some("max_tokens") => "length",
        Some("tool_use") => "tool_calls",
        // Safety refusal — let safety-aware clients distinguish it from a normal stop.
        Some("refusal") => "content_filter",
        _ => "stop",
    }
}

/// What one Anthropic message says, in OpenAI terms.
struct Extracted {
    content: String,
    reasoning: String,
    /// `thinking_blocks[]` = `{type: "thinking", thinking, signature}` — the
    /// signature is what makes the block replayable on the next turn.
    thinking_blocks: Vec<Value>,
    tool_calls: Vec<Value>,
}

/// Collect the translatable parts of a list of Anthropic content blocks.
fn extract_blocks(blocks: Option<&Vec<Value>>) -> Extracted {
    let mut out = Extracted {
        content: String::new(),
        reasoning: String::new(),
        thinking_blocks: Vec::new(),
        tool_calls: Vec::new(),
    };
    if let Some(blocks) = blocks {
        for b in blocks {
            match b.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                        out.content.push_str(t);
                    }
                }
                Some("thinking") => {
                    let text = b.get("thinking").and_then(|t| t.as_str()).unwrap_or("");
                    out.reasoning.push_str(text);
                    let mut block = json!({"type": "thinking", "thinking": text});
                    // Keeping only the prose broke the second turn: the signature
                    // that proves the block is unmodified was thrown away.
                    if let Some(sig) = b
                        .get("signature")
                        .and_then(|s| s.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        block["signature"] = json!(sig);
                    }
                    out.thinking_blocks.push(block);
                }
                Some("redacted_thinking") => {
                    let mut block = json!({"type": "redacted_thinking"});
                    if let Some(data) = b.get("data") {
                        block["data"] = data.clone();
                    }
                    out.thinking_blocks.push(block);
                }
                Some("tool_use") => {
                    out.tool_calls.push(json!({
                        "index": out.tool_calls.len(),
                        "id": b.get("id").cloned().unwrap_or(json!("")),
                        "type": "function",
                        "function": {
                            "name": b.get("name").cloned().unwrap_or(json!("")),
                            "arguments": b.get("input").cloned().unwrap_or(json!({})).to_string(),
                        },
                    }));
                }
                _ => {}
            }
        }
    }
    out
}

pub fn translate_response(model: &str, v: &Value) -> Value {
    let e = extract_blocks(v.get("content").and_then(|c| c.as_array()));

    let mut msg = json!({"role": "assistant"});
    if e.tool_calls.is_empty() {
        msg["content"] = json!(e.content);
    } else {
        msg["content"] = if e.content.is_empty() {
            Value::Null
        } else {
            json!(e.content)
        };
        msg["tool_calls"] = json!(e.tool_calls);
    }
    if !e.reasoning.is_empty() {
        msg["reasoning_content"] = json!(e.reasoning);
    }
    if !e.thinking_blocks.is_empty() {
        msg["thinking_blocks"] = json!(e.thinking_blocks);
    }

    let u = v.get("usage").cloned().unwrap_or(json!({}));
    let (prompt_tokens, cached_tokens) = prompt_usage(&u);
    let completion_tokens = u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
    json!({
        "id": v.get("id").cloned().unwrap_or_else(|| json!(gen_id())),
        "object": "chat.completion",
        "created": now_secs(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": msg,
            "finish_reason": map_stop(v.get("stop_reason").and_then(|r| r.as_str())),
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            // Saturating: both numbers are chosen by the upstream stream, and a
            // hostile/broken provider must not turn the total into a debug-build
            // panic (or a wrapped 0 in release). The same rule as the Responses
            // shaping in `proxy::responses`.
            "total_tokens": prompt_tokens.saturating_add(completion_tokens),
            "prompt_tokens_details": {"cached_tokens": cached_tokens},
        },
    })
}

// ---------- SSE stream translation ----------

/// A thinking block being streamed: Anthropic sends the prose in
/// `thinking_delta` and the signature in a separate `signature_delta`, so the
/// signature can only be attached to the block once it closes.
struct ThinkingBuf {
    index: usize,
    text: String,
    signature: Option<String>,
}

struct SseState {
    id: String,
    created: u64,
    model: String,
    sent_role: bool,
    /// Anthropic block index -> OpenAI tool_calls index (for tool_use blocks).
    block_tool_index: Vec<Option<usize>>,
    /// The thinking block currently open, if any.
    thinking: Option<ThinkingBuf>,
    prompt_tokens: u64,
    completion_tokens: u64,
}

impl SseState {
    fn chunk(&self, delta: Value, finish: Value) -> Value {
        json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        })
    }

    /// OpenAI streams emit usage exactly once: a final chunk with empty choices.
    fn usage_chunk(&self) -> Value {
        json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [],
            "usage": {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                // See `translate_response`: the counters come from the upstream
                // stream, so the sum saturates instead of overflowing.
                "total_tokens": self.prompt_tokens.saturating_add(self.completion_tokens),
            },
        })
    }
}

/// The `index` of a content-block event, bounds-checked before it is used as a
/// length (see [`MAX_BLOCK_INDEX`]).
fn block_index(v: &Value) -> Result<usize, String> {
    let idx = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
    if idx > MAX_BLOCK_INDEX {
        return Err(format!(
            "content block index {idx} rejected: the maximum is {MAX_BLOCK_INDEX}"
        ));
    }
    Ok(idx as usize)
}

/// Anthropic reports a mid-stream failure as `{"type":"error","error":{...}}`.
fn error_event(v: &Value) -> Option<String> {
    if v.get("type").and_then(|t| t.as_str()) != Some("error") {
        return None;
    }
    let err = v.get("error")?;
    Some(
        err.get("message")
            .and_then(|m| m.as_str())
            .or_else(|| err.get("type").and_then(|t| t.as_str()))
            .unwrap_or("upstream stream error")
            .to_string(),
    )
}

fn translate_event(v: &Value, st: &mut SseState) -> Result<Option<Value>, String> {
    let Some(ty) = v.get("type").and_then(|t| t.as_str()) else {
        return Ok(None);
    };
    match ty {
        "message_start" => {
            if let Some(u) = v.pointer("/message/usage") {
                // Same accounting as the non-streaming path (cache buckets included).
                let (p, _) = prompt_usage(u);
                st.prompt_tokens = p;
            }
            if st.sent_role {
                Ok(None)
            } else {
                st.sent_role = true;
                Ok(Some(st.chunk(json!({"role": "assistant"}), Value::Null)))
            }
        }
        "content_block_start" => {
            let idx = block_index(v)?;
            if st.block_tool_index.len() <= idx {
                st.block_tool_index.resize(idx + 1, None);
            }
            let Some(block) = v.get("content_block") else {
                return Ok(None);
            };
            match block.get("type").and_then(|t| t.as_str()) {
                Some("tool_use") => {
                    let tool_idx = st.block_tool_index.iter().flatten().count();
                    st.block_tool_index[idx] = Some(tool_idx);
                    Ok(Some(st.chunk(
                        json!({"tool_calls": [{
                            "index": tool_idx,
                            "id": block.get("id").cloned().unwrap_or(json!("")),
                            "type": "function",
                            "function": {
                                "name": block.get("name").cloned().unwrap_or(json!("")),
                                "arguments": "",
                            },
                        }]}),
                        Value::Null,
                    )))
                }
                Some("thinking") => {
                    let text = block
                        .get("thinking")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();
                    st.thinking = Some(ThinkingBuf {
                        index: idx,
                        text: text.clone(),
                        signature: None,
                    });
                    // Some upstreams put the whole thought in the start event.
                    if text.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(
                            st.chunk(json!({"reasoning_content": text}), Value::Null),
                        ))
                    }
                }
                Some("redacted_thinking") => {
                    let mut b = json!({"type": "redacted_thinking"});
                    if let Some(data) = block.get("data") {
                        b["data"] = data.clone();
                    }
                    Ok(Some(st.chunk(json!({"thinking_blocks": [b]}), Value::Null)))
                }
                _ => Ok(None),
            }
        }
        "content_block_delta" => {
            let idx = block_index(v)?;
            let Some(delta) = v.get("delta") else {
                return Ok(None);
            };
            match delta.get("type").and_then(|t| t.as_str()) {
                Some("text_delta") => {
                    let text = delta.get("text").cloned().unwrap_or(json!(""));
                    Ok(Some(st.chunk(json!({"content": text}), Value::Null)))
                }
                Some("thinking_delta") => {
                    let text = delta.get("thinking").cloned().unwrap_or(json!(""));
                    if let Some(t) = st.thinking.as_mut().filter(|t| t.index == idx)
                        && let Some(s) = text.as_str()
                    {
                        t.text.push_str(s);
                    }
                    Ok(Some(
                        st.chunk(json!({"reasoning_content": text}), Value::Null),
                    ))
                }
                Some("signature_delta") => {
                    // Buffered, not forwarded on its own: it belongs to the
                    // thinking block, which is replayed as one unit.
                    if let Some(t) = st.thinking.as_mut().filter(|t| t.index == idx)
                        && let Some(sig) = delta.get("signature").and_then(|s| s.as_str())
                    {
                        t.signature = Some(sig.to_string());
                    }
                    Ok(None)
                }
                Some("input_json_delta") => {
                    let Some(tool_idx) = st.block_tool_index.get(idx).copied().flatten() else {
                        return Ok(None);
                    };
                    let partial = delta.get("partial_json").cloned().unwrap_or(json!(""));
                    Ok(Some(st.chunk(
                        json!({"tool_calls": [{
                            "index": tool_idx,
                            "function": {"arguments": partial},
                        }]}),
                        Value::Null,
                    )))
                }
                _ => Ok(None),
            }
        }
        "content_block_stop" => {
            let idx = block_index(v)?;
            let Some(t) = st.thinking.take().filter(|t| t.index == idx) else {
                return Ok(None);
            };
            // Without a signature the block cannot be replayed, so there is
            // nothing useful to hand over (older models / plain thinking).
            let Some(sig) = t.signature else {
                return Ok(None);
            };
            Ok(Some(st.chunk(
                json!({"thinking_blocks": [{
                    "type": "thinking",
                    "thinking": t.text,
                    "signature": sig,
                }]}),
                Value::Null,
            )))
        }
        "message_delta" => {
            if let Some(o) = v.pointer("/usage/output_tokens").and_then(|x| x.as_u64()) {
                st.completion_tokens = o;
            }
            let finish = v
                .pointer("/delta/stop_reason")
                .and_then(|r| r.as_str())
                .map(|r| json!(map_stop(Some(r))));
            Ok(finish.map(|f| st.chunk(json!({}), f)))
        }
        _ => Ok(None),
    }
}

fn add_usage(key: &crate::pool::KeyState, prompt: u64, completion: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    key.prompt_tokens.fetch_add(prompt, Relaxed);
    key.completion_tokens.fetch_add(completion, Relaxed);
}

/// One upstream stream being translated.
struct Upstream {
    inner: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>,
    parser: crate::sse::SseParser,
    /// Complete `data:` payloads waiting to be translated.
    pending: VecDeque<Bytes>,
    /// Translated frames queued for emission (chunk, usage chunk, DONE).
    out: VecDeque<Bytes>,
    eof: bool,
    /// No more frames will be produced (terminal frame already queued).
    ended: bool,
    usage_added: bool,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
    st: SseState,
}

impl Upstream {
    fn add_usage_once(&mut self) {
        if self.usage_added {
            return;
        }
        self.usage_added = true;
        if let Some(k) = &self.stats {
            add_usage(k, self.st.prompt_tokens, self.st.completion_tokens);
        }
    }

    /// The usage chunk OpenAI clients expect at the end of a stream.
    fn push_usage(&mut self) {
        let (p, c) = (self.st.prompt_tokens, self.st.completion_tokens);
        if p > 0 || c > 0 {
            let chunk = self.st.usage_chunk();
            self.out.push_back(crate::sse::frame(&chunk));
        }
    }

    fn push_done(&mut self) {
        self.out
            .push_back(Bytes::from_static(crate::sse::DONE_FRAME));
        self.ended = true;
    }

    /// End the stream with a terminal error frame, then DONE: a partial answer
    /// followed by a cheerful `[DONE]` is indistinguishable from success.
    fn fail(&mut self, message: &str) {
        self.add_usage_once();
        self.out.push_back(crate::sse::frame(&json!({
            "error": {"message": message, "type": "upstream_error"}
        })));
        self.push_done();
    }
}

/// Convert an Anthropic SSE upstream response into an OpenAI-style SSE byte stream.
pub fn translate_sse_stream(
    resp: reqwest::Response,
    model: &str,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    translate_sse_stream_from(
        resp.bytes_stream().map(|r| r.map_err(io::Error::other)),
        model,
        stats,
    )
}

/// Same translation, over an already-opened body stream (the proxy watches it
/// for the first byte and for stalls, which a `reqwest::Response` cannot express).
pub fn translate_sse_stream_from<S>(
    inner: S,
    model: &str,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    let state = Upstream {
        inner: Box::pin(inner),
        parser: crate::sse::SseParser::new(),
        pending: VecDeque::new(),
        out: VecDeque::new(),
        eof: false,
        ended: false,
        usage_added: false,
        stats,
        st: SseState {
            id: gen_id(),
            created: now_secs(),
            model: model.to_string(),
            sent_role: false,
            block_tool_index: Vec::new(),
            thinking: None,
            prompt_tokens: 0,
            completion_tokens: 0,
        },
    };

    futures::stream::unfold(state, move |mut s| async move {
        loop {
            if s.ended && s.out.is_empty() {
                return None;
            }
            if let Some(frame) = s.out.pop_front() {
                return Some((Ok(frame), s));
            }
            if let Some(data) = s.pending.pop_front() {
                let Ok(v) = serde_json::from_slice::<Value>(&data) else {
                    continue;
                };
                if let Some(msg) = error_event(&v) {
                    s.fail(&msg);
                    continue;
                }
                let is_stop = v.get("type").and_then(|t| t.as_str()) == Some("message_stop");
                match translate_event(&v, &mut s.st) {
                    Ok(Some(chunk)) => s.out.push_back(crate::sse::frame(&chunk)),
                    Ok(None) => {}
                    Err(e) => {
                        // A hostile block index ends the stream as failed rather
                        // than being dropped or resized (see MAX_BLOCK_INDEX).
                        s.fail(&e);
                        continue;
                    }
                }
                if is_stop {
                    s.add_usage_once();
                    s.push_usage();
                    s.push_done();
                }
                continue;
            }

            if s.eof {
                s.add_usage_once();
                if !s.ended {
                    s.push_done();
                }
                continue;
            }

            match s.inner.next().await {
                Some(Ok(b)) => match s.parser.feed_checked(&b) {
                    Ok(events) => s.pending.extend(events),
                    Err(e) => {
                        // The parser cap stops a provider that never frames an
                        // event; the client must see that as a failure.
                        tracing::debug!(error = %e, "upstream SSE event exceeded the parser cap");
                        s.fail(&e.to_string());
                    }
                },
                Some(Err(e)) => {
                    // A read failure (dead connection, idle deadline) is a
                    // truncated answer: say so instead of closing silently.
                    s.fail(&format!("upstream stream error: {e}"));
                }
                None => {
                    s.eof = true;
                    s.pending.extend(s.parser.finish());
                }
            }
        }
    })
}

#[cfg(test)]
mod translate_tests {
    use super::*;
    use crate::sse::test_support::{data, frames, sse_response};
    use serde_json::json;

    fn event(v: Value) -> Vec<u8> {
        format!("data: {v}\n\n").into_bytes()
    }

    fn chunks(out: &[String]) -> Vec<Value> {
        out.iter().filter_map(|f| data(f)).collect()
    }

    fn error_frame(out: &[String]) -> Option<Value> {
        chunks(out).into_iter().find(|v| v.get("error").is_some())
    }

    /// `budget_tokens` is client-supplied: i64::MAX used to panic on `b + 1`.
    #[test]
    fn budget_tokens_of_i64_max_does_not_overflow() {
        let out = translate_request(&json!({
            "model": "claude-sonnet-4",
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"budget_tokens": i64::MAX},
        }))
        .expect("translation must not fail on a huge budget");
        assert!(out["max_tokens"].as_i64().is_some());
    }

    // ----- thinking + tools across turns -----

    #[test]
    fn thinking_signature_survives_a_response_request_round_trip() {
        let upstream = json!({
            "id": "msg_1",
            "content": [
                {"type": "thinking", "thinking": "the user asks about weather", "signature": "sig-abc"},
                {"type": "text", "text": "let me check"},
                {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Moscow"}},
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        });
        let resp = translate_response("claude-x", &upstream);
        let msg = resp
            .pointer("/choices/0/message")
            .cloned()
            .expect("message");
        assert_eq!(msg["reasoning_content"], "the user asks about weather");
        assert_eq!(msg["thinking_blocks"][0]["type"], "thinking");
        assert_eq!(msg["thinking_blocks"][0]["signature"], "sig-abc");

        // Second turn: replay exactly what the client echoes back.
        let req = translate_request(&json!({
            "model": "claude-x",
            "reasoning_effort": "high",
            "messages": [
                {"role": "user", "content": "weather in Moscow?"},
                msg,
                {"role": "tool", "tool_call_id": "toolu_1", "content": "sunny"},
            ],
            "tools": [{"type": "function", "function": {"name": "get_weather"}}],
        }))
        .expect("the replayed turn translates");

        let blocks = req["messages"][1]["content"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(blocks[0]["type"], "thinking", "{req}");
        assert_eq!(blocks[0]["signature"], "sig-abc");
        assert_eq!(blocks[0]["thinking"], "the user asks about weather");
        // ...and the thinking block precedes the tool_use, which is what
        // Anthropic requires when thinking is enabled.
        assert_eq!(blocks[1]["type"], "text");
        assert_eq!(blocks[2]["type"], "tool_use");
    }

    #[test]
    fn thinking_blocks_are_not_replayed_when_thinking_is_off() {
        // Anthropic rejects thinking blocks in a request that has thinking
        // disabled, so they must be dropped rather than forwarded.
        let req = translate_request(&json!({
            "model": "claude-x",
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "yo", "thinking_blocks": [
                    {"type": "thinking", "thinking": "t", "signature": "sig"}
                ]},
            ],
        }))
        .expect("translates");
        let blocks = req["messages"][1]["content"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(blocks.len(), 1, "{req}");
        assert_eq!(blocks[0]["type"], "text");
    }

    #[tokio::test]
    async fn a_streamed_thinking_block_hands_back_its_signature() {
        let body = vec![
            event(json!({"type": "message_start", "message": {"usage": {"input_tokens": 7}}})),
            event(json!({"type": "content_block_start", "index": 0,
                "content_block": {"type": "thinking", "thinking": ""}})),
            event(json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "thinking_delta", "thinking": "pondering"}})),
            event(json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "signature_delta", "signature": "sig-stream-1"}})),
            event(json!({"type": "content_block_stop", "index": 0})),
            event(json!({"type": "content_block_start", "index": 1,
                "content_block": {"type": "tool_use", "id": "toolu_1", "name": "f"}})),
            event(
                json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 4}}),
            ),
            event(json!({"type": "message_stop"})),
        ];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "claude-x", None)).await;
        let block = chunks(&out)
            .into_iter()
            .find_map(|v| v.pointer("/choices/0/delta/thinking_blocks").cloned())
            .unwrap_or_else(|| panic!("no thinking_blocks delta: {out:?}"));
        assert_eq!(block[0]["signature"], "sig-stream-1");
        assert_eq!(block[0]["thinking"], "pondering");
        // The prose still streams as it arrives.
        let text: String = out.join("");
        assert!(text.contains("\"pondering\""), "{text}");
    }

    // ----- hostile block indexes -----

    /// `idx as usize` then `resize(idx + 1, None)`: u64::MAX overflowed, 1e9
    /// asked for a 16 GB vector.
    #[tokio::test]
    async fn a_hostile_content_block_index_ends_the_stream_as_failed() {
        for index in [
            serde_json::json!(18446744073709551615u64),
            serde_json::json!(1_000_000_000u64),
        ] {
            let body = vec![
                event(json!({"type": "message_start", "message": {"usage": {"input_tokens": 3}}})),
                event(json!({"type": "content_block_start", "index": index,
                    "content_block": {"type": "tool_use", "id": "t", "name": "f"}})),
            ];
            let resp = sse_response(body).await;
            let out = frames(translate_sse_stream(resp, "claude-x", None)).await;
            let err = error_frame(&out)
                .unwrap_or_else(|| panic!("no error frame for index {index}: {out:?}"));
            assert_eq!(err["error"]["type"], "upstream_error");
            assert!(
                err["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("out of range")
                    || err["error"]["message"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("rejected"),
                "{err}"
            );
        }
    }

    // ----- mid-stream errors -----

    /// `usage` counters are upstream-chosen: `input_tokens + output_tokens` used
    /// to overflow (panic in debug, a wrapped 0 in release) when a hostile or
    /// broken provider reported both near `u64::MAX`. Found by
    /// `tests/fuzz_parsers.rs`; both the streamed usage chunk and the
    /// non-streaming body must saturate, like the Responses shaping already does.
    #[tokio::test]
    async fn hostile_usage_counters_saturate_instead_of_overflowing() {
        let max = u64::MAX;
        let resp = translate_response(
            "claude-x",
            &json!({"usage": {"input_tokens": max, "output_tokens": 1}}),
        );
        assert_eq!(resp["usage"]["total_tokens"], json!(max), "{resp}");

        let body = vec![
            event(json!({"type": "message_start", "message": {"usage": {"input_tokens": max}}})),
            event(json!({"type": "message_delta", "usage": {"output_tokens": 1}})),
            event(json!({"type": "message_stop"})),
        ];
        let out = frames(translate_sse_stream(
            sse_response(body).await,
            "claude-x",
            None,
        ))
        .await;
        let usage = chunks(&out)
            .into_iter()
            .find_map(|v| v.get("usage").cloned())
            .unwrap_or_else(|| panic!("no usage chunk: {out:?}"));
        assert_eq!(
            usage["total_tokens"],
            json!(max),
            "the total saturates at u64::MAX instead of wrapping to 0"
        );
    }

    #[tokio::test]
    async fn a_fragmented_error_event_becomes_an_error_frame() {
        let body = vec![
            event(json!({"type": "message_start", "message": {"usage": {"input_tokens": 2}}})),
            event(json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": "partial"}})),
            // Split across two writes on purpose.
            b"data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",".to_vec(),
            b"\"message\":\"Overloaded\"}}\n\n".to_vec(),
            event(json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": "never"}})),
            event(json!({"type": "message_stop"})),
        ];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "claude-x", None)).await;
        let err = error_frame(&out).unwrap_or_else(|| panic!("no error frame: {out:?}"));
        assert_eq!(err["error"]["message"], "Overloaded");
        assert_eq!(err["error"]["type"], "upstream_error");
        let text: String = out.join("");
        assert!(text.contains("partial"), "{text}");
        assert!(
            !text.contains("never"),
            "translation stops at the error: {text}"
        );
        assert!(out.last().is_some_and(|f| f.contains("[DONE]")), "{out:?}");
    }

    // ----- the parser cap -----

    #[tokio::test]
    async fn an_endless_event_fails_loudly_instead_of_truncating() {
        let resp = sse_response(vec![vec![b'x'; 2 * 1024 * 1024]]).await;
        let out = frames(translate_sse_stream(resp, "claude-x", None)).await;
        let err = error_frame(&out).unwrap_or_else(|| panic!("no error frame: {out:?}"));
        assert!(
            err["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("cap"),
            "{err}"
        );
        assert!(out.last().is_some_and(|f| f.contains("[DONE]")), "{out:?}");
    }

    // ----- hostile content parts -----

    #[test]
    fn an_unsupported_content_part_is_a_local_error_naming_the_type() {
        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": [
                {"type": "input_audio", "input_audio": {"data": "AA", "format": "wav"}},
            ]}],
        }))
        .expect_err("audio is not translatable");
        assert!(err.contains("input_audio"), "{err}");

        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
            ]}],
        }))
        .expect_err("remote images are not supported");
        assert!(err.contains("image_url"), "{err}");
    }
}
