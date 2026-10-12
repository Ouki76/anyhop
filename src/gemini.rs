//! Gemini (generateContent) ⇄ OpenAI (chat/completions) translation layer.

use std::collections::HashMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::{Value, json};

pub fn endpoint(base_url: &str, model: &str, stream: bool) -> String {
    if stream {
        format!("{base_url}/models/{model}:streamGenerateContent?alt=sse")
    } else {
        format!("{base_url}/models/{model}:generateContent")
    }
}

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

fn map_finish(r: &str) -> &'static str {
    match r {
        "STOP" => "stop",
        "MAX_TOKENS" => "length",
        "SAFETY" | "RECITATION" | "PROHIBITED_CONTENT" | "BLOCKLIST" | "SPII" => {
            "content_filter"
        }
        _ => "stop",
    }
}

// ---------- request translation (OpenAI -> Gemini) ----------

/// Extract concatenated text from an OpenAI message content (string or parts array).
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

/// Convert OpenAI user content (string or parts array) into Gemini parts.
fn content_parts(content: Option<&Value>) -> Result<Vec<Value>, String> {
    match content {
        None => Ok(vec![json!({"text": ""})]),
        Some(Value::String(s)) => Ok(vec![json!({"text": s})]),
        Some(Value::Array(arr)) => {
            let mut parts = Vec::new();
            for p in arr {
                match p.get("type").and_then(|t| t.as_str()) {
                    Some("text") => parts.push(json!({"text": p.get("text").cloned().unwrap_or(json!(""))})),
                    Some("image_url") => {
                        let url = p
                            .pointer("/image_url/url")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        match url
                            .strip_prefix("data:")
                            .and_then(|d| d.split_once(";base64,"))
                        {
                            Some((mime, b64)) => parts.push(
                                json!({"inline_data": {"mime_type": mime, "data": b64}}),
                            ),
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
            Ok(parts)
        }
        _ => Err("unsupported message content type".into()),
    }
}

pub fn translate_request(body: &Value) -> Result<Value, String> {
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or("missing 'messages' array")?;

    let mut system_parts: Vec<Value> = Vec::new();
    let mut contents: Vec<Value> = Vec::new();
    // tool_call_id -> function name, for resolving tool result messages
    let mut call_names: HashMap<String, String> = HashMap::new();

    for msg in messages {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
        match role {
            "system" | "developer" => {
                if let Some(t) = content_text(msg.get("content")) {
                    system_parts.push(json!({"text": t}));
                }
            }
            "user" => contents.push(json!({
                "role": "user",
                "parts": content_parts(msg.get("content"))?,
            })),
            "assistant" => {
                let mut parts = Vec::new();
                if let Some(t) = content_text(msg.get("content"))
                    && !t.is_empty()
                {
                    parts.push(json!({"text": t}));
                }
                if let Some(tcs) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                    for tc in tcs {
                        let id = tc.get("id").and_then(|i| i.as_str()).unwrap_or("");
                        let name = tc
                            .pointer("/function/name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let args: Value = tc
                            .pointer("/function/arguments")
                            .and_then(|a| a.as_str())
                            .and_then(|s| serde_json::from_str(s).ok())
                            .unwrap_or(json!({}));
                        if !id.is_empty() {
                            call_names.insert(id.to_string(), name.clone());
                        }
                        let mut fc = json!({"name": name, "args": args});
                        // Replay thoughtSignature if the client echoed it back
                        // (required by Gemini 3 for function calls in history).
                        if let Some(sig) = tc
                            .pointer("/function/thought_signature")
                            .and_then(|s| s.as_str())
                        {
                            fc["thoughtSignature"] = json!(sig);
                        }
                        parts.push(json!({"functionCall": fc}));
                    }
                }
                if parts.is_empty() {
                    parts.push(json!({"text": ""}));
                }
                contents.push(json!({"role": "model", "parts": parts}));
            }
            "tool" => {
                let tcid = msg.get("tool_call_id").and_then(|i| i.as_str()).unwrap_or("");
                let name = msg
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
                    .or_else(|| call_names.get(tcid).cloned())
                    .unwrap_or_else(|| tcid.to_string());
                let result = content_text(msg.get("content")).unwrap_or_default();
                contents.push(json!({
                    "role": "user",
                    "parts": [{
                        "functionResponse": {
                            "name": name,
                            "response": {"result": result},
                        }
                    }],
                }));
            }
            _ => {}
        }
    }

    // Gemini requires strictly alternating user/model turns — merge consecutive same-role entries.
    let mut merged: Vec<Value> = Vec::new();
    for c in contents {
        let role = c.get("role").and_then(|r| r.as_str()).unwrap_or("").to_string();
        if let Some(last) = merged.last_mut()
            && last.get("role").and_then(|r| r.as_str()) == Some(role.as_str())
        {
            let parts = c
                .get("parts")
                .and_then(|p| p.as_array())
                .cloned()
                .unwrap_or_default();
            if let Some(arr) = last.pointer_mut("/parts").and_then(|p| p.as_array_mut()) {
                arr.extend(parts);
            }
            continue;
        }
        merged.push(c);
    }

    let mut gen_cfg = serde_json::Map::new();
    if let Some(t) = body.get("temperature") {
        gen_cfg.insert("temperature".into(), t.clone());
    }
    if let Some(t) = body.get("top_p") {
        gen_cfg.insert("topP".into(), t.clone());
    }
    if let Some(t) = body
        .get("max_completion_tokens")
        .or_else(|| body.get("max_tokens"))
    {
        gen_cfg.insert("maxOutputTokens".into(), t.clone());
    }
    if let Some(stop) = body.get("stop") {
        let seqs = match stop {
            Value::String(s) => vec![json!(s)],
            Value::Array(a) => a.clone(),
            _ => vec![],
        };
        if !seqs.is_empty() {
            gen_cfg.insert("stopSequences".into(), json!(seqs));
        }
    }
    // Thinking: OpenAI reasoning_effort or Anthropic-style thinking.budget_tokens
    // -> generationConfig.thinkingConfig.
    let budget: Option<i64> = body
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
    if let Some(b) = budget {
        let mut tc = json!({"includeThoughts": b > 0});
        if b > 0 {
            tc["thinkingBudget"] = json!(b);
        }
        gen_cfg.insert("thinkingConfig".into(), tc);
    }

    let mut req = json!({"contents": merged});
    if !system_parts.is_empty() {
        req["system_instruction"] = json!({"parts": system_parts});
    }
    if !gen_cfg.is_empty() {
        req["generationConfig"] = json!(gen_cfg);
    }

    if let Some(tools) = body.get("tools").and_then(|t| t.as_array()) {
        let decls: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let f = t.get("function")?;
                Some(json!({
                    "name": f.get("name")?,
                    "description": f.get("description").cloned().unwrap_or(json!("")),
                    "parameters": f.get("parameters").cloned().unwrap_or(json!({"type": "object", "properties": {}})),
                }))
            })
            .collect();
        if !decls.is_empty() {
            req["tools"] = json!([{"function_declarations": decls}]);
        }
    }
    if let Some(tc) = body.get("tool_choice") {
        let mode = match tc {
            Value::String(s) => match s.as_str() {
                "none" => Some("NONE"),
                "required" => Some("ANY"),
                "auto" => Some("AUTO"),
                _ => None,
            },
            Value::Object(_) => Some("ANY"), // forced specific function
            _ => None,
        };
        if let Some(m) = mode {
            req["toolConfig"] = json!({"functionCallingConfig": {"mode": m}});
        }
    }

    Ok(req)
}

// ---------- response translation (Gemini -> OpenAI) ----------

/// (prompt_tokens, completion_tokens) from a Gemini usageMetadata container.
pub fn usage_pair(v: &Value) -> (u64, u64) {
    let um = match v.get("usageMetadata") {
        Some(um) => um,
        None => return (0, 0),
    };
    (
        um.get("promptTokenCount").and_then(|x| x.as_u64()).unwrap_or(0),
        um.get("candidatesTokenCount").and_then(|x| x.as_u64()).unwrap_or(0),
    )
}

fn usage_of(v: &Value) -> Value {
    let um = v.get("usageMetadata").cloned().unwrap_or(json!({}));
    let get = |k: &str| um.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    json!({
        "prompt_tokens": get("promptTokenCount"),
        "completion_tokens": get("candidatesTokenCount"),
        "total_tokens": get("totalTokenCount"),
    })
}

/// Collect (content, reasoning, tool_calls) from a Gemini candidate's parts.
fn extract_parts(candidate: Option<&Value>) -> (String, String, Vec<Value>) {
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut tool_calls = Vec::new();
    let parts = candidate
        .and_then(|c| c.pointer("/content/parts"))
        .and_then(|p| p.as_array());
    if let Some(parts) = parts {
        for part in parts {
            let is_thought = part
                .get("thought")
                .and_then(|t| t.as_bool())
                .unwrap_or(false);
            if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                if is_thought {
                    reasoning.push_str(t);
                } else {
                    content.push_str(t);
                }
            }
            if let Some(fc) = part.get("functionCall") {
                let id = fc
                    .get("id")
                    .and_then(|i| i.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("call_{:x}", now_secs()));
                let mut function = json!({
                    "name": fc.get("name").cloned().unwrap_or(json!("")),
                    "arguments": fc.get("args").cloned().unwrap_or(json!({})).to_string(),
                });
                // Surface the thoughtSignature so clients can echo it back
                // (Gemini 3 validates it on replayed function calls).
                let sig = part
                    .get("thoughtSignature")
                    .or_else(|| fc.get("thoughtSignature"))
                    .and_then(|s| s.as_str());
                if let Some(sig) = sig {
                    function["thought_signature"] = json!(sig);
                }
                tool_calls.push(json!({
                    "index": tool_calls.len(),
                    "id": id,
                    "type": "function",
                    "function": function,
                }));
            }
        }
    }
    (content, reasoning, tool_calls)
}

pub fn translate_response(model: &str, v: &Value) -> Value {
    let candidate = v.pointer("/candidates/0");
    let (content, reasoning, tool_calls) = extract_parts(candidate);
    let finish = candidate
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str())
        .map(map_finish)
        .unwrap_or("stop");

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

    json!({
        "id": gen_id(),
        "object": "chat.completion",
        "created": now_secs(),
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": usage_of(v),
    })
}

// ---------- SSE stream translation ----------

struct SseState {
    id: String,
    created: u64,
    model: String,
    sent_role: bool,
}

fn translate_chunk(v: &Value, st: &mut SseState) -> Value {
    let candidate = v.pointer("/candidates/0");
    let (content, reasoning, tool_calls) = extract_parts(candidate);

    let mut delta = json!({});
    if !st.sent_role {
        delta["role"] = json!("assistant");
        st.sent_role = true;
    }
    if !reasoning.is_empty() {
        delta["reasoning_content"] = json!(reasoning);
    }
    if !content.is_empty() {
        delta["content"] = json!(content);
    }
    if !tool_calls.is_empty() {
        delta["tool_calls"] = json!(tool_calls);
    }
    let finish = candidate
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str())
        .map(|r| json!(map_finish(r)))
        .unwrap_or(Value::Null);

    let mut chunk = json!({
        "id": st.id,
        "object": "chat.completion.chunk",
        "created": st.created,
        "model": st.model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    });
    if v.get("usageMetadata").is_some() {
        chunk["usage"] = usage_of(v);
    }
    chunk
}

/// Convert a Gemini SSE upstream response into an OpenAI-style SSE byte stream.
/// `envelope` unwraps Antigravity's `{"response": {...}}` chunk wrapper first.
pub fn translate_sse_stream(
    resp: reqwest::Response,
    model: &str,
    envelope: bool,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    struct State {
        inner: std::pin::Pin<
            Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>,
        >,
        parser: crate::sse::SseParser,
        pending: std::collections::VecDeque<Bytes>,
        eof: bool,
        sent_done: bool,
        stats: Option<std::sync::Arc<crate::pool::KeyState>>,
        st: SseState,
    }

    let state = State {
        inner: Box::pin(resp.bytes_stream()),
        parser: crate::sse::SseParser::new(),
        pending: std::collections::VecDeque::new(),
        eof: false,
        sent_done: false,
        stats,
        st: SseState {
            id: gen_id(),
            created: now_secs(),
            model: model.to_string(),
            sent_role: false,
        },
    };

    futures::stream::unfold(state, move |mut s| async move {
        loop {
            if let Some(data) = s.pending.pop_front() {
                let Ok(v) = serde_json::from_slice::<Value>(&data) else {
                    continue;
                };
                let v = if envelope { crate::antigravity::unwrap_response(v) } else { v };
                if let Some(k) = &s.stats {
                    let (p, c) = usage_pair(&v);
                    if p > 0 || c > 0 {
                        k.prompt_tokens.fetch_add(p, std::sync::atomic::Ordering::Relaxed);
                        k.completion_tokens.fetch_add(c, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                let chunk = translate_chunk(&v, &mut s.st);
                return Some((Ok(crate::sse::frame(&chunk)), s));
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
