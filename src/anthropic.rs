//! Anthropic (/v1/messages) ⇄ OpenAI (chat/completions) translation layer.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::{Value, json};

pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
pub const API_VERSION: &str = "2023-06-01";

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
fn content_blocks(content: Option<&Value>) -> Result<Vec<Value>, String> {
    match content {
        None => Ok(vec![json!({"type": "text", "text": ""})]),
        Some(Value::String(s)) => Ok(vec![json!({"type": "text", "text": s})]),
        Some(Value::Array(arr)) => {
            let mut blocks = Vec::new();
            for p in arr {
                match p.get("type").and_then(|t| t.as_str()) {
                    Some("text") => blocks.push(
                        json!({"type": "text", "text": p.get("text").cloned().unwrap_or(json!(""))}),
                    ),
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
                                return Err(
                                    "only base64 data: URLs are supported for images".into()
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(blocks)
        }
        _ => Err("unsupported message content type".into()),
    }
}

pub fn translate_request(body: &Value) -> Result<Value, String> {
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or("missing 'messages' array")?;

    let mut system_texts: Vec<String> = Vec::new();
    let mut out_msgs: Vec<Value> = Vec::new();

    for msg in messages {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
        match role {
            "system" | "developer" => {
                if let Some(c) = msg.get("content").and_then(|c| c.as_str()) {
                    system_texts.push(c.to_string());
                }
            }
            "user" => out_msgs.push(json!({
                "role": "user",
                "content": content_blocks(msg.get("content"))?,
            })),
            "assistant" => {
                let mut blocks = Vec::new();
                if let Some(t) = msg.get("content").and_then(|c| c.as_str())
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
                let result = match msg.get("content") {
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                    None => String::new(),
                };
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
        let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("").to_string();
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

    let mut req = json!({
        "model": body.get("model").cloned().unwrap_or(json!("")),
        // Anthropic requires max_tokens.
        "max_tokens": body
            .get("max_completion_tokens")
            .or_else(|| body.get("max_tokens"))
            .cloned()
            .unwrap_or(json!(32000)),
        "messages": merged,
    });
    if !system_texts.is_empty() {
        req["system"] = json!(system_texts.join("\n\n"));
    }
    if let Some(t) = body.get("temperature") {
        req["temperature"] = t.clone();
    }
    if let Some(t) = body.get("top_p") {
        req["top_p"] = t.clone();
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
    // Thinking: reasoning_effort / thinking.budget_tokens -> thinking config.
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
        .or_else(|| body.pointer("/thinking/budget_tokens").and_then(|b| b.as_i64()));
    match budget {
        Some(b) if b > 0 => {
            req["thinking"] = json!({"type": "enabled", "budget_tokens": b});
        }
        Some(_) => {
            req["thinking"] = json!({"type": "disabled"});
        }
        None => {}
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
        _ => "stop",
    }
}

/// Collect (content, reasoning, tool_calls) from Anthropic content blocks.
fn extract_blocks(blocks: Option<&Vec<Value>>) -> (String, String, Vec<Value>) {
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut tool_calls = Vec::new();
    if let Some(blocks) = blocks {
        for b in blocks {
            match b.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                        content.push_str(t);
                    }
                }
                Some("thinking") => {
                    if let Some(t) = b.get("thinking").and_then(|t| t.as_str()) {
                        reasoning.push_str(t);
                    }
                }
                Some("tool_use") => {
                    tool_calls.push(json!({
                        "index": tool_calls.len(),
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
    (content, reasoning, tool_calls)
}

pub fn translate_response(model: &str, v: &Value) -> Value {
    let (content, reasoning, tool_calls) =
        extract_blocks(v.get("content").and_then(|c| c.as_array()));

    let mut msg = json!({"role": "assistant"});
    if tool_calls.is_empty() {
        msg["content"] = json!(content);
    } else {
        msg["content"] = if content.is_empty() { Value::Null } else { json!(content) };
        msg["tool_calls"] = json!(tool_calls);
    }
    if !reasoning.is_empty() {
        msg["reasoning_content"] = json!(reasoning);
    }

    let u = v.get("usage").cloned().unwrap_or(json!({}));
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
            "prompt_tokens": u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
            "completion_tokens": u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
            "total_tokens": u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0)
                + u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
        },
    })
}

// ---------- SSE stream translation ----------

struct StreamState {
    id: String,
    created: u64,
    model: String,
    sent_role: bool,
    /// Anthropic block index -> OpenAI tool_calls index (for tool_use blocks).
    block_tool_index: Vec<Option<usize>>,
    prompt_tokens: u64,
    completion_tokens: u64,
}

impl StreamState {
    fn chunk(&self, delta: Value, finish: Value) -> Value {
        let mut ch = json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        });
        if self.prompt_tokens > 0 || self.completion_tokens > 0 {
            ch["usage"] = json!({
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.prompt_tokens + self.completion_tokens,
            });
        }
        ch
    }
}

fn translate_event(v: &Value, st: &mut StreamState) -> Option<Value> {
    let ty = v.get("type").and_then(|t| t.as_str())?;
    match ty {
        "message_start" => {
            if let Some(p) = v
                .pointer("/message/usage/input_tokens")
                .and_then(|x| x.as_u64())
            {
                st.prompt_tokens = p;
            }
            if st.sent_role {
                None
            } else {
                st.sent_role = true;
                Some(st.chunk(json!({"role": "assistant"}), Value::Null))
            }
        }
        "content_block_start" => {
            let idx = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
            if st.block_tool_index.len() <= idx {
                st.block_tool_index.resize(idx + 1, None);
            }
            let block = v.get("content_block")?;
            match block.get("type").and_then(|t| t.as_str()) {
                Some("tool_use") => {
                    let tool_idx = st.block_tool_index.iter().flatten().count();
                    st.block_tool_index[idx] = Some(tool_idx);
                    Some(st.chunk(
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
                    ))
                }
                _ => None,
            }
        }
        "content_block_delta" => {
            let idx = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
            let delta = v.get("delta")?;
            match delta.get("type").and_then(|t| t.as_str()) {
                Some("text_delta") => {
                    let text = delta.get("text").cloned().unwrap_or(json!(""));
                    Some(st.chunk(json!({"content": text}), Value::Null))
                }
                Some("thinking_delta") => {
                    let text = delta.get("thinking").cloned().unwrap_or(json!(""));
                    Some(st.chunk(json!({"reasoning_content": text}), Value::Null))
                }
                Some("input_json_delta") => {
                    let tool_idx = st.block_tool_index.get(idx).copied().flatten()?;
                    let partial = delta.get("partial_json").cloned().unwrap_or(json!(""));
                    Some(st.chunk(
                        json!({"tool_calls": [{
                            "index": tool_idx,
                            "function": {"arguments": partial},
                        }]}),
                        Value::Null,
                    ))
                }
                _ => None,
            }
        }
        "message_delta" => {
            if let Some(o) = v.pointer("/usage/output_tokens").and_then(|x| x.as_u64()) {
                st.completion_tokens = o;
            }
            let finish = v
                .pointer("/delta/stop_reason")
                .and_then(|r| r.as_str())
                .map(|r| json!(map_stop(Some(r))));
            finish.map(|f| st.chunk(json!({}), f))
        }
        _ => None,
    }
}

/// Convert an Anthropic SSE upstream response into an OpenAI-style SSE byte stream.
pub fn translate_sse_stream(
    resp: reqwest::Response,
    model: &str,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    struct State {
        inner: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
        parser: crate::sse::SseParser,
        pending: std::collections::VecDeque<Bytes>,
        eof: bool,
        sent_done: bool,
        stats: Option<std::sync::Arc<crate::pool::KeyState>>,
        st: StreamState,
    }

    let state = State {
        inner: Box::pin(resp.bytes_stream()),
        parser: crate::sse::SseParser::new(),
        pending: std::collections::VecDeque::new(),
        eof: false,
        sent_done: false,
        stats,
        st: StreamState {
            id: gen_id(),
            created: now_secs(),
            model: model.to_string(),
            sent_role: false,
            block_tool_index: Vec::new(),
            prompt_tokens: 0,
            completion_tokens: 0,
        },
    };

    futures::stream::unfold(state, move |mut s| async move {
        loop {
            if let Some(data) = s.pending.pop_front() {
                let Ok(v) = serde_json::from_slice::<Value>(&data) else {
                    continue;
                };
                let is_stop = v.get("type").and_then(|t| t.as_str()) == Some("message_stop");
                if let Some(chunk) = translate_event(&v, &mut s.st) {
                    return Some((Ok(crate::sse::frame(&chunk)), s));
                }
                if is_stop {
                    if let Some(k) = &s.stats {
                        add_usage(k, s.st.prompt_tokens, s.st.completion_tokens);
                    }
                    if s.sent_done {
                        continue;
                    }
                    s.sent_done = true;
                    return Some((Ok(Bytes::from_static(crate::sse::DONE_FRAME)), s));
                }
                continue;
            }

            if s.eof {
                if s.sent_done {
                    return None;
                }
                s.sent_done = true;
                return Some((Ok(Bytes::from_static(crate::sse::DONE_FRAME)), s));
            }

            match s.inner.next().await {
                Some(Ok(b)) => s.pending.extend(s.parser.feed(&b)),
                Some(Err(e)) => return Some((Err(io::Error::other(e)), s)),
                None => {
                    s.eof = true;
                    s.pending.extend(s.parser.finish());
                }
            }
        }
    })
}

fn add_usage(key: &crate::pool::KeyState, prompt: u64, completion: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    key.prompt_tokens.fetch_add(prompt, Relaxed);
    key.completion_tokens.fetch_add(completion, Relaxed);
}
