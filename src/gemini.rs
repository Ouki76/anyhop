//! Gemini (generateContent) ⇄ OpenAI (chat/completions) translation layer.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::{Value, json};

/// Gemini rejects a request with more stop sequences than this.
const MAX_STOP_SEQUENCES: usize = 5;
/// Output tokens kept free on top of the thinking budget. `maxOutputTokens`
/// covers thinking *and* the answer, so a client asking for 1024 tokens with a
/// 24576-token thinking budget used to get a `length` finish and no content.
const THINKING_HEADROOM: i64 = 1024;

pub fn endpoint(base_url: &str, model: &str, stream: bool) -> String {
    // Clients may address a model as "models/gemini-2.5-flash" (that is how the
    // Gemini API names it); the path below already carries the `models/` segment,
    // so a prefixed id must not double it into `models/models/…`.
    let model = model.strip_prefix("models/").unwrap_or(model);
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
        "SAFETY"
        | "RECITATION"
        | "PROHIBITED_CONTENT"
        | "BLOCKLIST"
        | "SPII"
        | "LANGUAGE"
        | "IMAGE_SAFETY"
        | "IMAGE_PROHIBITED_CONTENT"
        | "NO_IMAGE" => "content_filter",
        // These are *failed* generations: the text is missing or malformed, so
        // mapping them to "stop" advertised an empty answer as a normal completion
        // (the exact anti-pattern the promptFeedback branch exists to prevent).
        "OTHER" | "MALFORMED_FUNCTION_CALL" | "UNEXPECTED_TOOL_CALL" | "TOO_MANY_TOOL_CALLS" => {
            "content_filter"
        }
        _ => "stop",
    }
}

/// The model's maximum output tokens, used to clamp an inflated
/// `maxOutputTokens`. A budget of 24576 + 1024 headroom on an 8192-cap model
/// (gemini-2.0-flash, 1.5) was a guaranteed 400.
fn output_cap(model: &str) -> i64 {
    if model.contains("gemini-1.5") || model.contains("gemini-2.0") {
        8192
    } else if model.contains("gemini-2.5") || model.contains("gemini-3") {
        65536
    } else {
        // Unknown model: stay at the conservative cap rather than sending a value
        // that only some models accept.
        8192
    }
}

/// Can this model run with thinking disabled?
///
/// gemini-2.5-pro rejects `thinkingBudget: 0` (minimum 128), so
/// `reasoning_effort: "none"` used to be a hard 400 on every Pro model. Omitting
/// `thinkingConfig` is the closest legal request (dynamic thinking).
fn can_disable_thinking(model: &str) -> bool {
    !(model.contains("2.5-pro") || model.contains("2.5_pro"))
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
///
/// A part we cannot translate is an error, not something to drop: dropping it
/// left `parts: []`, which Gemini rejects with a confusing 400 about empty
/// contents *after* the request was already paid for.
fn content_parts(content: Option<&Value>) -> Result<Vec<Value>, String> {
    match content {
        None => Ok(vec![json!({"text": ""})]),
        Some(Value::String(s)) => Ok(vec![json!({"text": s})]),
        Some(Value::Array(arr)) => {
            let mut parts = Vec::new();
            for p in arr {
                match p.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        parts.push(json!({"text": p.get("text").cloned().unwrap_or(json!(""))}))
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
                            Some((mime, b64)) => {
                                parts.push(json!({"inline_data": {"mime_type": mime, "data": b64}}))
                            }
                            None => {
                                return Err(format!(
                                    "unsupported image_url '{url}': only base64 data: URLs \
                                     can be translated to Gemini inline_data"
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
            if parts.is_empty() {
                return Err("message has no translatable content parts".into());
            }
            Ok(parts)
        }
        _ => Err("unsupported message content type".into()),
    }
}

/// Map an OpenAI `response_format` onto Gemini's structured-output fields.
///
/// Dropping the field silently was worse than rejecting it: a `json_schema`
/// request came back as markdown prose with HTTP 200, so the caller believed its
/// contract had been applied. Unknown shapes are therefore a local error.
fn apply_response_format(
    rf: &Value,
    gen_cfg: &mut serde_json::Map<String, Value>,
) -> Result<(), String> {
    let obj = match rf {
        // `null` is how some clients spell "no preference": not an error.
        Value::Null => return Ok(()),
        Value::Object(o) => o,
        _ => return Err("'response_format' must be an object".into()),
    };
    match obj.get("type").and_then(|t| t.as_str()) {
        // Plain text is the default: nothing to ask the upstream for.
        Some("text") => return Ok(()),
        Some("json_object") => {
            gen_cfg.insert("responseMimeType".into(), json!("application/json"));
            return Ok(());
        }
        Some("json_schema") => {}
        // OpenAI always sends `type`, but `{"json_schema": …}` alone is
        // unambiguous enough to accept.
        None if obj.contains_key("json_schema") || obj.contains_key("schema") => {}
        Some(other) => {
            return Err(format!(
                "unsupported 'response_format.type' \"{other}\": \
                 expected \"text\", \"json_object\" or \"json_schema\""
            ));
        }
        None => return Err("'response_format' is missing 'type'".into()),
    }
    // The schema normally sits under `json_schema.schema` (OpenAI's shape), but
    // a bare `schema` beside the type is accepted too.
    let schema = obj
        .get("json_schema")
        .and_then(|js| js.get("schema"))
        .or_else(|| obj.get("schema"))
        .filter(|s| !s.is_null())
        .cloned()
        .ok_or(
            "'response_format' of type \"json_schema\" has no schema: \
             expected 'response_format.json_schema.schema' or 'response_format.schema'",
        )?;
    gen_cfg.insert("responseMimeType".into(), json!("application/json"));
    gen_cfg.insert("responseJsonSchema".into(), schema);
    Ok(())
}

pub fn translate_request(body: &Value) -> Result<Value, String> {
    // The model id drives per-model limits below (output cap, whether thinking can
    // be disabled). It is the *client-facing* id here; a `models/` prefix is
    // stripped so `gemini/models/gemini-2.5-pro` classifies like the bare name.
    let model_id = body.get("model").and_then(|m| m.as_str()).unwrap_or("");
    let model = model_id.strip_prefix("models/").unwrap_or(model_id);
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or("missing 'messages' array")?;

    // Thinking: OpenAI `reasoning_effort` or Anthropic-style
    // `thinking.budget_tokens` -> generationConfig.thinkingConfig. Resolved
    // up front because it changes the shape of the rest of the request.
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
    let thinking_on = budget.is_some_and(|b| b > 0);

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
                        // Gemini's `Part` schema puts `thoughtSignature` next to
                        // `functionCall`, never inside it. Nesting it one level
                        // too deep was rejected upstream with
                        // `Unknown name "thoughtSignature" at
                        // …parts[0].function_call`, and omitting it is rejected
                        // as a missing signature — so the only accepted shape is
                        // the sibling one. Required for replayed function calls
                        // in history (Gemini 3, and 2.5 with dynamic thinking).
                        let mut part = json!({"functionCall": {"name": name, "args": args}});
                        if let Some(sig) = tc
                            .pointer("/function/thought_signature")
                            .and_then(|s| s.as_str())
                        {
                            part["thoughtSignature"] = json!(sig);
                        }
                        parts.push(part);
                    }
                }
                if parts.is_empty() {
                    parts.push(json!({"text": ""}));
                }
                contents.push(json!({"role": "model", "parts": parts}));
            }
            "tool" => {
                let tcid = msg
                    .get("tool_call_id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("");
                // Gemini's functionResponse has no id field: it is correlated by
                // *name*. Without a name we cannot know the function, and sending
                // the raw call id as the name makes the upstream answer a
                // confusing 400 (or worse, calls a function that does not exist).
                let name = match msg
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
                    .or_else(|| call_names.get(tcid).cloned())
                {
                    Some(n) => n,
                    None => {
                        return Err(format!(
                            "tool result for unknown tool_call_id '{tcid}' has no 'name': \
                             Gemini matches functionResponse by name"
                        ));
                    }
                };
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
        let role = c
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
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
    // A system-only conversation is not a conversation: `contents: []` is a hard
    // 400 upstream, so say what is wrong here instead.
    if merged.is_empty() {
        return Err("no user or assistant messages: Gemini needs a non-empty conversation".into());
    }

    let mut gen_cfg = serde_json::Map::new();
    // Thinking models run at a fixed sampling setting; a custom temperature is
    // rejected (mirrors anthropic.rs, which drops the same pair).
    if !thinking_on {
        if let Some(t) = body.get("temperature") {
            gen_cfg.insert("temperature".into(), t.clone());
        }
        if let Some(t) = body.get("top_p") {
            gen_cfg.insert("topP".into(), t.clone());
        }
    }
    if let Some(mt) = body
        .get("max_completion_tokens")
        .or_else(|| body.get("max_tokens"))
    {
        // The thinking budget is spent out of maxOutputTokens: grow the ceiling
        // so the answer itself still has room (Anthropic does the same).
        let value = match (budget.filter(|b| *b > 0), mt.as_i64()) {
            (Some(b), Some(cur)) => {
                let cap = output_cap(model);
                json!(cur.max(b.saturating_add(THINKING_HEADROOM)).min(cap))
            }
            // A client-supplied value above the model cap is the client's call:
            // forward it untouched so the upstream reports the real reason.
            _ => mt.clone(),
        };
        gen_cfg.insert("maxOutputTokens".into(), value);
    }
    if let Some(stop) = body.get("stop") {
        let mut seqs = match stop {
            Value::String(s) => vec![json!(s)],
            Value::Array(a) => a.clone(),
            _ => vec![],
        };
        // Gemini accepts at most five stop sequences — clip instead of forwarding
        // a request that is guaranteed to be rejected.
        seqs.truncate(MAX_STOP_SEQUENCES);
        if !seqs.is_empty() {
            gen_cfg.insert("stopSequences".into(), json!(seqs));
        }
    }
    if let Some(b) = budget {
        // A *zero* budget must be sent explicitly: an absent `thinkingBudget`
        // means dynamic thinking, the exact opposite of `reasoning_effort: none`.
        // Except on models that cannot disable thinking at all — there, 0 is
        // rejected, so the field is omitted (and the request stays valid).
        if b > 0 || can_disable_thinking(model) {
            gen_cfg.insert(
                "thinkingConfig".into(),
                json!({"includeThoughts": b > 0, "thinkingBudget": b}),
            );
        }
    }
    if let Some(rf) = body.get("response_format") {
        apply_response_format(rf, &mut gen_cfg)?;
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
        // Forced choice {"type":"function","function":{"name":X}} must pin
        // allowedFunctionNames=[X] — bare ANY would let the model call others.
        // The mode comes from `type`, not from the presence of an object: treating
        // every object as ANY turned {"type":"none"} into "call any tool".
        let (mode, forced): (Option<&str>, Option<&str>) = match tc {
            Value::String(s) => (
                match s.as_str() {
                    "none" => Some("NONE"),
                    "required" => Some("ANY"),
                    "auto" => Some("AUTO"),
                    _ => None,
                },
                None,
            ),
            Value::Object(_) => {
                let ty = tc.get("type").and_then(|t| t.as_str()).unwrap_or("");
                let name = tc.pointer("/function/name").and_then(|n| n.as_str());
                match ty {
                    "none" => (Some("NONE"), None),
                    "auto" => (Some("AUTO"), None),
                    "required" | "any" => (Some("ANY"), None),
                    // A forced function: ANY restricted to that one name.
                    "function" | "tool" => match name {
                        Some(n) => (Some("ANY"), Some(n)),
                        None => (Some("ANY"), None),
                    },
                    _ => (None, None),
                }
            }
            _ => (None, None),
        };
        if let Some(m) = mode {
            let mut cfg = json!({"mode": m});
            if let Some(n) = forced {
                cfg["allowedFunctionNames"] = json!([n]);
            }
            req["toolConfig"] = json!({"functionCallingConfig": cfg});
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
        um.get("promptTokenCount")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        um.get("candidatesTokenCount")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
    )
}

fn usage_of(v: &Value) -> Value {
    let um = v.get("usageMetadata").cloned().unwrap_or(json!({}));
    let get = |k: &str| um.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
    let prompt = get("promptTokenCount");
    let completion = get("candidatesTokenCount");
    // Upstream `totalTokenCount` includes `thoughtsTokenCount`, which
    // `candidatesTokenCount` (our `completion_tokens`) does not: reusing it
    // reported `total: 176` for `113 + 32` and broke the invariant every client
    // derives cost and context fill from. Thinking is surfaced separately.
    let mut usage = json!({
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt.saturating_add(completion),
    });
    if let Some(thoughts) = um.get("thoughtsTokenCount").and_then(|x| x.as_u64()) {
        usage["completion_tokens_details"] = json!({"reasoning_tokens": thoughts});
    }
    usage
}

/// Tool-call index/id allocator for one translation.
///
/// `index` is monotonic over the whole stream: OpenAI clients merge parallel
/// calls by it, so a counter that restarted per chunk collapsed every call after
/// the first into index 0. Ids come from a counter, never the wall clock —
/// Gemini usually omits them, and `now_secs()` gave all calls of the same second
/// the same id, which made clients correlate two results to one call.
struct PartSink {
    next_index: usize,
    next_id: u64,
    created: u64,
}

impl PartSink {
    fn new(created: u64) -> Self {
        Self {
            next_index: 0,
            next_id: 0,
            created,
        }
    }

    fn call_id(&mut self) -> String {
        self.next_id += 1;
        format!("call_{}_{}", self.created, self.next_id)
    }
}

/// Collect (content, reasoning, tool_calls) from a Gemini candidate's parts.
fn extract_parts(candidate: Option<&Value>, sink: &mut PartSink) -> (String, String, Vec<Value>) {
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
                let index = sink.next_index;
                sink.next_index += 1;
                let id = fc
                    .get("id")
                    .and_then(|i| i.as_str())
                    .filter(|i| !i.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| sink.call_id());
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
                    "index": index,
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
    let created = now_secs();
    let candidate = v.pointer("/candidates/0");
    let mut sink = PartSink::new(created);
    let (content, reasoning, tool_calls) = extract_parts(candidate, &mut sink);
    // A prompt Gemini refused to send to the model: no candidate at all, only
    // `promptFeedback.blockReason` (SAFETY, BLOCKLIST, PROHIBITED_CONTENT, …).
    // Reporting it as `stop` with empty content made a refusal look like a
    // finished, empty answer.
    let blocked = v
        .pointer("/promptFeedback/blockReason")
        .and_then(|r| r.as_str());
    let mut finish = match candidate
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str())
    {
        Some(r) => map_finish(r),
        None if blocked.is_some() => "content_filter",
        None => "stop",
    };
    // Gemini says STOP even when the candidate carries function calls;
    // OpenAI clients dispatch on finish_reason == "tool_calls".
    if finish == "stop" && !tool_calls.is_empty() {
        finish = "tool_calls";
    }

    let mut msg = json!({"role": "assistant"});
    if tool_calls.is_empty() {
        msg["content"] = json!(content);
    } else {
        msg["content"] = if content.is_empty() {
            Value::Null
        } else {
            json!(content)
        };
        msg["tool_calls"] = json!(tool_calls);
    }
    if !reasoning.is_empty() {
        msg["reasoning_content"] = json!(reasoning);
    }
    if let Some(reason) = blocked {
        // Surfaced the OpenAI way: `refusal` next to the `content_filter` finish.
        msg["refusal"] = json!(reason);
    }

    json!({
        "id": gen_id(),
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": usage_of(v),
    })
}

// ---------- SSE stream translation ----------

/// Per-stream translation state.
struct SseState {
    id: String,
    created: u64,
    model: String,
    sent_role: bool,
    /// Monotonic OpenAI tool-call index shared by every chunk of the stream.
    parts: PartSink,
    /// Set as soon as any chunk carries a tool call: the terminal chunk's own
    /// `tool_calls` is empty, so it cannot be used to decide the finish reason.
    saw_tool_call: bool,
    /// Gemini repeats *cumulative* `usageMetadata` on every event; keeping the
    /// last one lets the counters be bumped exactly once, at the end.
    last_usage: Option<(u64, u64)>,
}

fn translate_chunk(v: &Value, st: &mut SseState) -> Value {
    let candidate = v.pointer("/candidates/0");
    let (content, reasoning, tool_calls) = extract_parts(candidate, &mut st.parts);
    if !tool_calls.is_empty() {
        st.saw_tool_call = true;
    }

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
    let blocked = v
        .pointer("/promptFeedback/blockReason")
        .and_then(|r| r.as_str());
    let finish = match candidate
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str())
    {
        Some(r) => {
            let f = map_finish(r);
            // Stop says nothing about the tool calls already streamed.
            if f == "stop" && st.saw_tool_call {
                json!("tool_calls")
            } else {
                json!(f)
            }
        }
        None => match blocked {
            Some(reason) => {
                delta["refusal"] = json!(reason);
                json!("content_filter")
            }
            None => Value::Null,
        },
    };

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

/// (prompt, completion) from an event, when it carries usage at all.
fn event_usage(v: &Value) -> Option<(u64, u64)> {
    match usage_pair(v) {
        (0, 0) => None,
        pair => Some(pair),
    }
}

/// A mid-stream failure: Gemini reports it as `{"error": {...}}` with no
/// candidates, which used to translate into nothing at all.
fn upstream_error(v: &Value) -> Option<String> {
    let err = v.get("error")?;
    if err.is_null() {
        return None;
    }
    Some(
        err.get("message")
            .and_then(|m| m.as_str())
            .or_else(|| err.as_str())
            .unwrap_or("upstream stream error")
            .to_string(),
    )
}

/// One translated upstream stream.
struct StreamState {
    inner: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>,
    parser: crate::sse::SseParser,
    /// Complete `data:` payloads waiting to be translated.
    pending: VecDeque<Bytes>,
    /// Translated frames waiting to be handed to the client.
    out: VecDeque<Bytes>,
    eof: bool,
    /// No more frames will be produced (terminal frame already queued).
    ended: bool,
    usage_added: bool,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
    st: SseState,
}

impl StreamState {
    /// Bump the pool counters once, with the last cumulative usage Gemini sent.
    fn add_usage_once(&mut self) {
        if self.usage_added {
            return;
        }
        self.usage_added = true;
        if let (Some(k), Some((p, c))) = (self.stats.as_ref(), self.st.last_usage.take()) {
            let k = k.clone();
            add_usage(&k, p, c);
        }
    }

    fn push_done(&mut self) {
        self.out
            .push_back(Bytes::from_static(crate::sse::DONE_FRAME));
        self.ended = true;
    }

    /// End the stream with a terminal error frame, then DONE: the client must be
    /// able to tell a failed stream from a finished answer.
    fn fail(&mut self, message: &str) {
        self.add_usage_once();
        self.out.push_back(crate::sse::frame(&json!({
            "error": {"message": message, "type": "upstream_error"}
        })));
        self.push_done();
    }
}

fn add_usage(key: &crate::pool::KeyState, prompt: u64, completion: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    key.prompt_tokens.fetch_add(prompt, Relaxed);
    key.completion_tokens.fetch_add(completion, Relaxed);
}

/// Convert a Gemini SSE upstream response into an OpenAI-style SSE byte stream.
/// `envelope` unwraps Antigravity's `{"response": {...}}` chunk wrapper first.
pub fn translate_sse_stream(
    resp: reqwest::Response,
    model: &str,
    envelope: bool,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    translate_sse_stream_from(
        resp.bytes_stream().map(|r| r.map_err(io::Error::other)),
        model,
        envelope,
        stats,
    )
}

/// Same translation, over an already-opened body stream.
///
/// The proxy hands us a stream it has already watched (first byte, idle
/// deadline), which a `reqwest::Response` cannot express.
pub fn translate_sse_stream_from<S>(
    inner: S,
    model: &str,
    envelope: bool,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    let created = now_secs();
    let state = StreamState {
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
            created,
            model: model.to_string(),
            sent_role: false,
            parts: PartSink::new(created),
            saw_tool_call: false,
            last_usage: None,
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
                let v = if envelope {
                    crate::antigravity::unwrap_response(v)
                } else {
                    v
                };
                if let Some(u) = event_usage(&v) {
                    s.st.last_usage = Some(u);
                }
                if let Some(msg) = upstream_error(&v) {
                    s.fail(&msg);
                    continue;
                }
                let chunk = translate_chunk(&v, &mut s.st);
                s.out.push_back(crate::sse::frame(&chunk));
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
                        // The cap bounds a stream that never frames an event; the
                        // client must hear about the truncation, not receive a
                        // half answer followed by a cheerful `[DONE]`.
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
mod tests {
    use super::*;
    use crate::sse::test_support::{data, frames, key_state, sse_response};

    fn event(v: Value) -> Vec<u8> {
        format!("data: {v}\n\n").into_bytes()
    }

    fn text_event(text: &str) -> Vec<u8> {
        event(json!({"candidates": [{"content": {"role": "model", "parts": [{"text": text}]}}]}))
    }

    fn call_event(name: &str) -> Vec<u8> {
        event(json!({"candidates": [{
            "content": {"role": "model", "parts": [{"functionCall": {"name": name, "args": {}}}]}
        }]}))
    }

    fn finish_event(reason: &str) -> Vec<u8> {
        event(json!({"candidates": [{"content": {"parts": []}, "finishReason": reason}]}))
    }

    fn chunks(out: &[String]) -> Vec<Value> {
        out.iter().filter_map(|f| data(f)).collect()
    }

    fn tool_calls(out: &[String]) -> Vec<Value> {
        chunks(out)
            .into_iter()
            .flat_map(|v| {
                v.pointer("/choices/0/delta/tool_calls")
                    .and_then(|c| c.as_array())
                    .cloned()
                    .unwrap_or_default()
            })
            .collect()
    }

    fn finishes(out: &[String]) -> Vec<Value> {
        chunks(out)
            .into_iter()
            .filter_map(|v| v.pointer("/choices/0/finish_reason").cloned())
            .filter(|f| !f.is_null())
            .collect()
    }

    fn error_frame(out: &[String]) -> Option<Value> {
        chunks(out).into_iter().find(|v| v.get("error").is_some())
    }

    // ----- streaming: tool calls -----

    /// Two `functionCall` events in two chunks must stay two calls: OpenAI
    /// clients merge by `index` and correlate results by `id`, so both arriving
    /// as index 0 with the same id mangled them into one.
    #[tokio::test]
    async fn parallel_tool_calls_in_separate_chunks_keep_their_own_index_and_id() {
        let body = vec![
            call_event("get_weather"),
            call_event("get_time"),
            finish_event("STOP"),
        ];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None)).await;

        let calls = tool_calls(&out);
        assert_eq!(calls.len(), 2, "both calls must reach the client: {out:?}");
        assert_eq!(calls[0]["index"], 0);
        assert_eq!(calls[1]["index"], 1, "indexes must be monotonic");
        assert_ne!(
            calls[0]["id"], calls[1]["id"],
            "parallel calls need distinct ids"
        );
        // The upstream omitted ids, so ours are synthetic — and stable/unique.
        assert!(
            calls[0]["id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("call_"),
            "{:?}",
            calls[0]["id"]
        );
    }

    /// The terminal chunk carries no `tool_calls` of its own; `finish_reason` must
    /// still be `tool_calls`, or the agent loop never executes the call.
    #[tokio::test]
    async fn a_stream_with_tool_calls_finishes_with_tool_calls() {
        let body = vec![call_event("get_weather"), finish_event("STOP")];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None)).await;
        assert_eq!(finishes(&out), vec![json!("tool_calls")], "{out:?}");
    }

    /// ...and a plain text stream still ends with a plain `stop`.
    #[tokio::test]
    async fn a_text_only_stream_finishes_with_stop() {
        let body = vec![text_event("hi"), finish_event("STOP")];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None)).await;
        assert_eq!(finishes(&out), vec![json!("stop")], "{out:?}");
    }

    // ----- streaming: upstream errors -----

    /// A fragmented `{"error": …}` event used to vanish: the client got the
    /// partial text plus `[DONE]`, as if the answer had finished.
    #[tokio::test]
    async fn a_mid_stream_error_event_becomes_an_error_frame() {
        let body = vec![
            text_event("partial"),
            b"data: {\"error\":{\"code\":500,".to_vec(),
            b"\"status\":\"INTERNAL\",\"message\":\"boom\"}}\n\n".to_vec(),
            text_event("never sent"),
            finish_event("STOP"),
        ];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None)).await;

        let err = error_frame(&out).unwrap_or_else(|| panic!("no error frame: {out:?}"));
        assert_eq!(err["error"]["message"], "boom");
        assert_eq!(err["error"]["type"], "upstream_error");
        // Translation stops at the error: no content after it, and the terminal
        // frame is still DONE so SSE clients close cleanly.
        let text: String = out.join("");
        assert!(text.contains("partial"), "{text}");
        assert!(!text.contains("never sent"), "{text}");
        assert!(out.last().is_some_and(|f| f.contains("[DONE]")), "{out:?}");
    }

    // ----- streaming: the parser cap -----

    /// A body that never frames an event must end the stream with an error frame,
    /// not with a silently truncated answer.
    #[tokio::test]
    async fn an_endless_event_fails_loudly_instead_of_truncating() {
        let huge = vec![b'a'; 2 * 1024 * 1024];
        let resp = sse_response(vec![huge]).await;
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None)).await;
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

    // ----- streaming: usage -----

    /// Gemini repeats cumulative `usageMetadata` on every event; adding it per
    /// chunk inflated the counters once per event.
    #[tokio::test]
    async fn cumulative_usage_is_counted_exactly_once() {
        let usage = |completion: u64| json!({"promptTokenCount": 5, "candidatesTokenCount": completion, "totalTokenCount": 5 + completion});
        let with_usage = |text: &str, completion: u64| {
            event(json!({
                "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}}],
                "usageMetadata": usage(completion),
            }))
        };
        let body = vec![
            with_usage("a", 1),
            with_usage("b", 2),
            with_usage("c", 3),
            json_finish_with_usage(3, 8),
        ];
        let key = key_state();
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(
            resp,
            "gemini-x",
            false,
            Some(key.clone()),
        ))
        .await;
        assert!(out.last().is_some_and(|f| f.contains("[DONE]")), "{out:?}");
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(key.prompt_tokens.load(Relaxed), 5);
        assert_eq!(
            key.completion_tokens.load(Relaxed),
            3,
            "the last (cumulative) usage must be added once, not per chunk"
        );
    }

    fn json_finish_with_usage(completion: u64, total: u64) -> Vec<u8> {
        event(json!({
            "candidates": [{"content": {"parts": []}, "finishReason": "STOP"}],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": completion,
                "totalTokenCount": total,
            },
        }))
    }

    // ----- streaming: blocked prompt -----

    /// `promptFeedback.blockReason` with no candidate is a refusal, not an empty
    /// answer.
    #[tokio::test]
    async fn a_blocked_prompt_streams_content_filter() {
        let body = vec![event(json!({"promptFeedback": {"blockReason": "SAFETY"}}))];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None)).await;
        assert_eq!(finishes(&out), vec![json!("content_filter")], "{out:?}");
        let refusal = chunks(&out)
            .into_iter()
            .find_map(|v| v.pointer("/choices/0/delta/refusal").cloned());
        assert_eq!(refusal, Some(json!("SAFETY")));
    }

    // ----- non-stream response -----

    #[test]
    fn a_blocked_prompt_is_a_content_filter_response_with_its_reason() {
        let v = json!({"promptFeedback": {"blockReason": "SAFETY"}});
        let out = translate_response("gemini-x", &v);
        assert_eq!(out["choices"][0]["finish_reason"], "content_filter");
        assert_eq!(out["choices"][0]["message"]["refusal"], "SAFETY");
    }

    #[test]
    fn parallel_tool_calls_in_one_response_get_sequential_indexes() {
        let v = json!({"candidates": [{"content": {"parts": [
            {"functionCall": {"name": "a", "args": {}}},
            {"functionCall": {"name": "b", "args": {}}},
        ]}}]});
        let out = translate_response("gemini-x", &v);
        let calls = out["choices"][0]["message"]["tool_calls"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(calls[0]["index"], 0);
        assert_eq!(calls[1]["index"], 1);
        assert_ne!(calls[0]["id"], calls[1]["id"]);
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }

    // ----- request translation -----

    #[test]
    fn reasoning_effort_none_turns_thinking_off_explicitly() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "none",
        }))
        .expect("translates");
        // Absent thinkingBudget means *dynamic* thinking — the opposite of "none".
        assert_eq!(
            out["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            0
        );
        assert_eq!(
            out["generationConfig"]["thinkingConfig"]["includeThoughts"],
            false
        );
    }

    #[test]
    fn a_big_thinking_budget_grows_max_output_tokens() {
        let out = translate_request(&json!({
            "model": "gemini-2.5-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "high",
            "max_tokens": 1024,
        }))
        .expect("translates");
        // 24576 thinking + 1024 answer headroom, not the client's 1024.
        assert_eq!(
            out["generationConfig"]["maxOutputTokens"],
            24576 + 1024,
            "{out}"
        );

        // ...but never past the model's own cap: 8192-cap models used to receive
        // 25600, which the API rejects outright.
        let out = translate_request(&json!({
            "model": "gemini-2.0-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "high",
            "max_tokens": 1024,
        }))
        .expect("translates");
        assert_eq!(out["generationConfig"]["maxOutputTokens"], 8192, "{out}");
    }

    #[test]
    fn a_small_max_tokens_is_kept_when_thinking_is_off() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 512,
        }))
        .expect("translates");
        assert_eq!(out["generationConfig"]["maxOutputTokens"], 512);
    }

    #[test]
    fn temperature_is_dropped_while_thinking() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "medium",
            "temperature": 0.2,
        }))
        .expect("translates");
        assert!(
            out["generationConfig"].get("temperature").is_none(),
            "{out}"
        );

        // ...and kept when thinking is off.
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.2,
        }))
        .expect("translates");
        assert_eq!(out["generationConfig"]["temperature"], 0.2);
    }

    #[test]
    fn stop_sequences_are_clipped_to_five() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "stop": ["a", "b", "c", "d", "e", "f"],
        }))
        .expect("translates");
        let seqs = out["generationConfig"]["stopSequences"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(seqs.len(), 5, "{out}");
        assert_eq!(seqs[4], "e");
    }

    #[test]
    fn a_system_only_history_is_rejected_locally() {
        let err = translate_request(&json!({
            "messages": [{"role": "system", "content": "be nice"}],
        }))
        .expect_err("no conversation to send");
        assert!(err.contains("no user or assistant messages"), "{err}");
    }

    #[test]
    fn forced_tool_choice_names_the_function() {
        let tools = json!([{"type": "function", "function": {"name": "get_weather"}}]);
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": tools,
            "tool_choice": {"type": "function", "function": {"name": "get_weather"}},
        }))
        .expect("translates");
        assert_eq!(
            out["toolConfig"]["functionCallingConfig"]["mode"], "ANY",
            "{out}"
        );
        assert_eq!(
            out["toolConfig"]["functionCallingConfig"]["allowedFunctionNames"],
            json!(["get_weather"])
        );
    }

    #[test]
    fn an_object_tool_choice_of_type_none_does_not_become_any() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "f"}}],
            "tool_choice": {"type": "none"},
        }))
        .expect("translates");
        assert_eq!(out["toolConfig"]["functionCallingConfig"]["mode"], "NONE");
        assert!(
            out["toolConfig"]["functionCallingConfig"]
                .get("allowedFunctionNames")
                .is_none(),
            "{out}"
        );
    }

    #[test]
    fn an_unsupported_content_part_is_a_local_error_naming_the_type() {
        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "listen"},
                {"type": "input_audio", "input_audio": {"data": "AAA", "format": "wav"}},
            ]}],
        }))
        .expect_err("audio cannot be translated to Gemini");
        assert!(err.contains("input_audio"), "{err}");

        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
            ]}],
        }))
        .expect_err("remote images are not supported");
        assert!(err.contains("image_url"), "{err}");
    }

    #[test]
    fn a_tool_result_with_an_unknown_call_id_is_rejected_locally() {
        let err = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "tool", "tool_call_id": "call_nope", "content": "42"},
            ],
        }))
        .expect_err("no function is named call_nope");
        assert!(err.contains("call_nope"), "{err}");
    }

    #[test]
    fn a_tool_result_whose_call_was_replayed_is_accepted() {
        let out = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "get_weather", "arguments": "{}"},
                }]},
                {"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
            ],
        }))
        .expect("translates");
        // user, model (the call), user (the result) — the result is matched by name.
        assert_eq!(
            out["contents"][2]["parts"][0]["functionResponse"]["name"],
            "get_weather"
        );
    }

    #[test]
    fn a_models_prefixed_id_does_not_double_the_path_segment() {
        assert_eq!(
            endpoint("http://up", "models/gemini-2.5-flash", false),
            "http://up/models/gemini-2.5-flash:generateContent"
        );
        assert_eq!(
            endpoint("http://up", "models/gemini-2.5-flash", true),
            "http://up/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );
    }

    // ----- round trip: the gateway must accept its own output -----

    /// A response replayed verbatim as history used to be rejected both ways:
    /// the signature nested inside `functionCall` gives
    /// `Unknown name "thoughtSignature" at …function_call`, and dropping it gives
    /// `Function call is missing a thought_signature`. The signature belongs on
    /// the Part, next to `functionCall` — the same place the response side reads
    /// it from.
    #[test]
    fn a_replayed_tool_call_puts_the_signature_beside_the_function_call() {
        // Response side: the upstream sends the signature on the Part.
        let upstream = json!({"candidates": [{
            "content": {"role": "model", "parts": [{
                "functionCall": {"name": "get_weather", "args": {"city": "Paris"}},
                "thoughtSignature": "SIG-abc",
            }]},
            "finishReason": "STOP",
        }]});
        let response = translate_response("gemini-x", &upstream);
        let message = response["choices"][0]["message"].clone();
        // The OpenAI-side carrier is unchanged: clients get it to echo back.
        assert_eq!(
            message["tool_calls"][0]["function"]["thought_signature"], "SIG-abc",
            "{message}"
        );

        // Replay it exactly as an agent loop would.
        let call_id = message["tool_calls"][0]["id"].clone();
        let out = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "weather?"},
                message,
                {"role": "tool", "tool_call_id": call_id, "content": "{\"temp_c\":14}"},
                {"role": "user", "content": "and tomorrow?"},
            ],
            "tools": [{"type": "function", "function": {"name": "get_weather"}}],
        }))
        .expect("the gateway must accept its own output");

        let part = &out["contents"][1]["parts"][0];
        assert_eq!(part["thoughtSignature"], "SIG-abc", "{out}");
        assert!(
            part["functionCall"].get("thoughtSignature").is_none(),
            "the signature must not be nested inside functionCall: {out}"
        );
        assert_eq!(part["functionCall"]["name"], "get_weather");
        assert_eq!(part["functionCall"]["args"]["city"], "Paris");
    }

    /// ...and the signature still goes back when the client does not echo one:
    /// the replay must remain a plain `functionCall` part, not an invalid shape.
    #[test]
    fn a_replayed_tool_call_without_a_signature_has_no_stray_field() {
        let out = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "get_weather", "arguments": "{}"},
                }]},
                {"role": "tool", "tool_call_id": "call_1", "content": "sunny"},
            ],
        }))
        .expect("translates");
        let part = &out["contents"][1]["parts"][0];
        assert_eq!(
            part,
            &json!({"functionCall": {"name": "get_weather", "args": {}}})
        );
    }

    // ----- response_format -> structured output -----

    #[test]
    fn response_format_json_object_asks_for_json_mime() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "json_object"},
        }))
        .expect("translates");
        assert_eq!(
            out["generationConfig"]["responseMimeType"],
            "application/json"
        );
        assert!(
            out["generationConfig"].get("responseJsonSchema").is_none(),
            "{out}"
        );
    }

    #[test]
    fn response_format_json_schema_maps_to_response_json_schema() {
        let schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}, "legs": {"type": "integer"}},
            "required": ["name", "legs"],
            "additionalProperties": false,
        });
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "cat", "strict": true, "schema": schema},
            },
        }))
        .expect("translates");
        assert_eq!(
            out["generationConfig"]["responseMimeType"],
            "application/json"
        );
        assert_eq!(out["generationConfig"]["responseJsonSchema"], schema);
    }

    /// `type` is what OpenAI sends, but `{"json_schema": {…}}` alone is accepted.
    #[test]
    fn response_format_json_schema_without_a_type_is_accepted() {
        let schema = json!({"type": "object", "properties": {"ok": {"type": "boolean"}}});
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"json_schema": {"name": "r", "schema": schema}},
        }))
        .expect("translates");
        assert_eq!(out["generationConfig"]["responseJsonSchema"], schema);
    }

    /// A bare `schema` beside the type is accepted as well.
    #[test]
    fn response_format_accepts_a_bare_schema() {
        let schema = json!({"type": "object", "properties": {"n": {"type": "integer"}}});
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "json_schema", "schema": schema},
        }))
        .expect("translates");
        assert_eq!(out["generationConfig"]["responseJsonSchema"], schema);
    }

    #[test]
    fn response_format_text_asks_for_nothing() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "text"},
        }))
        .expect("translates");
        assert!(
            out.get("generationConfig").is_none(),
            "text is the default: no generationConfig needed: {out}"
        );
    }

    /// `null` means "no preference" for some clients and must not become a 400.
    #[test]
    fn response_format_null_is_ignored() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": null,
        }))
        .expect("null is not a structured-output request");
        assert!(out.get("generationConfig").is_none(), "{out}");
    }

    /// A json_schema request with no schema used to be forwarded as if it had
    /// one; silence let the caller believe the contract was applied.
    #[test]
    fn response_format_json_schema_without_a_schema_is_rejected() {
        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "cat"}},
        }))
        .expect_err("a schema was promised but not sent");
        assert!(
            err.contains("response_format") && err.contains("schema"),
            "{err}"
        );

        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "json_schema"},
        }))
        .expect_err("no schema at all");
        assert!(err.contains("response_format"), "{err}");
    }

    #[test]
    fn an_unknown_response_format_is_rejected_by_name() {
        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "response_format": {"type": "xml"},
        }))
        .expect_err("not a format we can map");
        assert!(
            err.contains("response_format.type") && err.contains("xml"),
            "{err}"
        );
    }

    // ----- usage invariant -----

    /// `total_tokens` must be `prompt + completion`. It used to come from
    /// `totalTokenCount`, which includes `thoughtsTokenCount`, so a thinking
    /// response reported 176 for 113 + 32.
    #[test]
    fn total_tokens_is_the_sum_of_prompt_and_completion() {
        let v = json!({
            "candidates": [{"content": {"parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
            "usageMetadata": {
                "promptTokenCount": 113,
                "candidatesTokenCount": 32,
                "totalTokenCount": 176,
                "thoughtsTokenCount": 31,
            },
        });
        let out = translate_response("gemini-x", &v);
        let usage = &out["usage"];
        assert_eq!(usage["prompt_tokens"], 113);
        assert_eq!(usage["completion_tokens"], 32);
        assert_eq!(usage["total_tokens"], 145, "{usage}");
        // The thought count is still visible, just not folded into the total.
        assert_eq!(usage["completion_tokens_details"]["reasoning_tokens"], 31);
    }

    #[test]
    fn total_tokens_saturates_at_the_u64_boundary() {
        let v = json!({"usageMetadata": {
            "promptTokenCount": u64::MAX,
            "candidatesTokenCount": 3,
            "totalTokenCount": u64::MAX,
        }});
        let usage = usage_of(&v);
        assert_eq!(usage["total_tokens"], json!(u64::MAX));
    }
}
