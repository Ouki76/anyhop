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

/// Does this model reason at all?
///
/// Used to decide whether an *unstated* effort should still ask the provider to
/// return its thoughts. Gemini 1.5 and 2.0 have no thinking mode, so asking would
/// only produce a 400; the 2.5 and 3 generations do.
fn is_thinking_model(model: &str) -> bool {
    model.contains("gemini-2.5")
        || model.contains("gemini-3")
        || model.contains("thinking")
        || model.contains("-pro")
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
    // `n` asks for several independent completions. Every translator here emits
    // exactly one `choices[0]`, so forwarding a multi-choice request would hand
    // the client a single answer with no indication that the rest were silently
    // dropped — worse than refusing. A translator that gains multi-candidate
    // support (Gemini's `candidateCount`) can lift this.
    if body
        .get("n")
        .and_then(|n| n.as_i64())
        .is_some_and(|n| n > 1)
    {
        return Err("'n' > 1 is not supported by this provider; ask for one completion".into());
    }

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
    // A client that says nothing about effort still gets thoughts when the model
    // reasons: `includeThoughts` is what makes the provider emit them at all, and
    // a gateway that silently swallowed them made every reasoning UI (DSH, the
    // Claude-style `reasoning_content` panels) look broken. The budget stays the
    // provider's own (dynamic), so nothing is over-spent — only the *visibility*
    // is turned on. `reasoning_effort: "none"` still turns it off, and a model
    // that cannot think is never asked.
    let include_thoughts_default = budget.is_none() && is_thinking_model(model);
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
                // The assistant turn may carry images too (a tool-calling model
                // echoing a screenshot). `content_text` keeps only text, so they
                // were dropped; `content_parts` translates text *and* inline images
                // and refuses anything it cannot express.
                // A null/absent content is the normal shape for a turn that only
                // called tools: start empty and let the tool_calls fill it.
                let mut parts = match msg.get("content") {
                    None | Some(Value::Null) => Vec::new(),
                    other => content_parts(other)?,
                };
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
                        // The id may carry the signature we embedded
                        // (`call_x__thought__<sig>`); the upstream must see the
                        // clean id and a sibling `thoughtSignature`.
                        let (clean_id, _) = decode_call_id(id);
                        if !clean_id.is_empty() {
                            call_names.insert(clean_id.to_string(), name.clone());
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
                        // Gemini 3 requires a thoughtSignature on every replayed
                        // function call. A client rarely echoes one back: OpenAI's
                        // schema has no such field, so we put it under
                        // `function.thought_signature` and only our own clients
                        // return it. Google documents a placeholder for exactly
                        // this case — `skip_thought_signature_validator` — which
                        // passes validation instead of failing the whole request
                        // with `Function call is missing a thought_signature`.
                        //
                        // Lookup order: the plain field, then a nested
                        // `provider_specific_fields` spelling some SDKs use, then
                        // the documented placeholder.
                        let sig: String = match thought_signature_of(tc) {
                            Some(real) => real.to_string(),
                            None => placeholder_thought_signature().to_string(),
                        };
                        part["thoughtSignature"] = json!(sig);
                        parts.push(part);
                    }
                }
                if parts.is_empty() {
                    parts.push(json!({"text": ""}));
                }
                contents.push(json!({"role": "model", "parts": parts}));
            }
            "tool" => {
                // The tool result carries back the same id the client got, which may
                // have the signature embedded (`call_x__thought__<sig>`). The lookup
                // map is keyed by the *clean* id, so strip it here too.
                let raw_tcid = msg
                    .get("tool_call_id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("");
                let (tcid, _sig) = decode_call_id(raw_tcid);
                // `functionResponse` is correlated by *name* (required), and since
                // the SDK gained `id` it can also carry the call id — which is what
                // disambiguates two parallel calls to the same function. We send
                // both: the name keeps older surfaces working, the id makes the
                // correlation exact (`FunctionResponse.id` — "Populated by the
                // client to match the corresponding function call").
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
                // A tool result rides on a `user` turn.
                //
                // The public Gemini SDK builds it as `role: "tool"`, and an earlier
                // round switched to that — but the Antigravity `v1internal`
                // surface rejects it outright: `Role 'tool' is not supported. Please
                // use a valid role: SYSTEM, …, USER, …, MODEL, USER`. `user` is
                // accepted by both surfaces, so it is the one value that works
                // everywhere this translator is used.
                let mut fr = json!({
                    "name": name,
                    "response": {"result": result},
                });
                if !tcid.is_empty() {
                    fr["id"] = json!(tcid);
                }
                contents.push(json!({
                    "role": "user",
                    "parts": [{"functionResponse": fr}],
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
        // Gemini's legal range is 0.0..=2.0. A client value outside it is a
        // guaranteed upstream 400, and the gateway is the layer that can say so
        // in the client's own vocabulary — clamp, like the Anthropic translator
        // already does for its narrower 0..=1 range.
        if let Some(t) = body.get("temperature").and_then(|t| t.as_f64())
            && t.is_finite()
        {
            gen_cfg.insert("temperature".into(), json!(t.clamp(0.0, 2.0)));
        }
        // `topP: 0` is accepted by OpenAI as "disabled"; Gemini treats 0 as an
        // empty nucleus and returns nothing, so it is dropped instead.
        if let Some(t) = body.get("top_p").and_then(|t| t.as_f64())
            && t.is_finite()
            && t > 0.0
        {
            gen_cfg.insert("topP".into(), json!(t.clamp(0.0, 1.0)));
        }
    }
    if let Some(mt) = body
        .get("max_completion_tokens")
        .or_else(|| body.get("max_tokens"))
    {
        // Reject nonsense before it reaches the provider. A negative or zero
        // `max_tokens` used to be forwarded verbatim as `maxOutputTokens`, so the
        // client got an opaque upstream 400 instead of the gateway naming the
        // field — and a negative value is not a number Gemini even parses.
        let Some(cur) = mt.as_i64() else {
            return Err("'max_tokens' must be an integer".into());
        };
        if cur < 1 {
            return Err("'max_tokens' must be at least 1".into());
        }
        // The thinking budget is spent out of maxOutputTokens: grow the ceiling
        // so the answer itself still has room (Anthropic does the same). A
        // client-supplied value above the model cap is the client's call:
        // forward it untouched so the upstream reports the real reason.
        let value = match budget.filter(|b| *b > 0) {
            Some(b) => {
                let cap = output_cap(model);
                json!(cur.max(b.saturating_add(THINKING_HEADROOM)).min(cap))
            }
            None => json!(cur),
        };
        gen_cfg.insert("maxOutputTokens".into(), value);
    }
    if let Some(stop) = body.get("stop") {
        let mut seqs = match stop {
            Value::String(s) => vec![json!(s)],
            Value::Array(a) => a.clone(),
            _ => vec![],
        };
        // Drop what Gemini cannot accept rather than sending a request it is
        // guaranteed to 400. `stopSequences` are plain strings there: a control
        // character (a literal newline, which is what OpenAI's `"\n\n\n"` spelling
        // becomes) is rejected as INVALID_ARGUMENT. The FIM path used to forward
        // exactly that, so every autocomplete through Gemini/Antigravity failed.
        seqs.retain(|q| {
            q.as_str()
                .is_some_and(|t| !t.is_empty() && !t.chars().any(char::is_control))
        });
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
            // Gemini counts thinking **inside** `maxOutputTokens`, so the budget
            // has to fit under it. Sending `reasoning_effort: "high"` (24 576) with
            // an 8192-cap model asked for the impossible and produced a 400 on
            // gemini-1.5/2.0; on 2.5/3 the budget equalled the raised ceiling, so
            // thinking could eat the whole answer and the client got
            // `finish_reason: "length"` with empty content. `anthropic.rs` already
            // clamps this way; the clamp here applies to the ceiling only, which is
            // why the budget slipped through.
            let ceiling = gen_cfg
                .get("maxOutputTokens")
                .and_then(|v| v.as_i64())
                .unwrap_or_else(|| output_cap(model));
            let b = if b > 0 {
                // Leave at least one token for the answer itself.
                b.min(ceiling.saturating_sub(1).max(1))
            } else {
                b
            };
            gen_cfg.insert(
                "thinkingConfig".into(),
                json!({"includeThoughts": b > 0, "thinkingBudget": b}),
            );
        }
    } else if include_thoughts_default {
        // No budget is sent, so the provider keeps its own (dynamic) thinking
        // policy; only the thoughts are asked to be returned.
        gen_cfg.insert("thinkingConfig".into(), json!({"includeThoughts": true}));
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

    // Hosted tools (`web_search`, `file_search`, `code_interpreter`) run on the
    // provider's side; this gateway has no such service, so forwarding the name
    // would change the meaning of the request. `README.md` promises a 400 and
    // `/v1/responses` gives one — the chat path used to *drop* the entry, which
    // meant a client silently got an answer without the tool it asked for.
    crate::proxy::ensure_no_hosted_tools(body)?;

    // Gemini has no `parallel_tool_calls` knob: `toolConfig` offers only
    // AUTO/ANY/NONE and an allow-list, none of which restricts the *number* of
    // calls per turn. A client that asked for one call per turn would silently get
    // several and lose track of them, so say so instead of ignoring the field.
    if body
        .get("parallel_tool_calls")
        .and_then(|v| v.as_bool())
        .is_some_and(|allowed| !allowed)
    {
        return Err(
            "'parallel_tool_calls: false' cannot be honoured by this provider (Gemini has no \
             such control); use a provider that supports it, or allow parallel calls"
                .into(),
        );
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
}

impl PartSink {
    fn new() -> Self {
        Self {
            next_index: 0,
            next_id: 0,
        }
    }

    fn call_id(&mut self) -> String {
        self.next_id += 1;
        // `self.created` is `now_secs()` — a *one-second* clock. Two turns of the
        // same conversation one second apart therefore produced the identical id
        // `call_<secs>_1`, and a multi-step agent loop correlated every tool result
        // to the same call. The counter alone is not enough because it restarts per
        // request, so the id needs per-request entropy as well: a process-wide
        // counter, which is unique for the life of the process without relying on
        // the clock at all.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("call_{seq:x}_{}", self.next_id)
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
                let sig = part
                    .get("thoughtSignature")
                    .or_else(|| fc.get("thoughtSignature"))
                    .and_then(|s| s.as_str());
                if let Some(sig) = sig {
                    // Kept for clients that *do* understand the field…
                    function["thought_signature"] = json!(sig);
                }
                // …and carried inside the id as well, because a standard OpenAI
                // client echoes the id and nothing else. Without one of the two
                // carriers Gemini 3 rejects the replayed call outright.
                let wire_id = encode_call_id(&id, sig);
                tool_calls.push(json!({
                    "index": index,
                    "id": wire_id,
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
    let mut sink = PartSink::new();
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

    let chunk = json!({
        "id": st.id,
        "object": "chat.completion.chunk",
        "created": st.created,
        "model": st.model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    });
    // `usage` never rides a content chunk.
    //
    // OpenAI's contract is a *separate* final chunk with `choices: []` (and only
    // when the client asked via `stream_options.include_usage`); attaching it to a
    // chunk that also carries `delta`/`finish_reason` is a shape the schema does
    // not permit, and clients that sum `usage` over chunks double-counted it.
    // The cumulative value is remembered here and emitted once, at the end, by
    // `push_usage`.
    if let Some(pair) = event_usage(v) {
        st.last_usage = Some(pair);
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
    /// The client asked for a final usage chunk (`stream_options.include_usage`).
    include_usage: bool,
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

    /// The single `choices: []` usage chunk OpenAI clients expect, when the client
    /// asked for it with `stream_options.include_usage`.
    fn push_usage(&mut self) {
        if !self.include_usage {
            return;
        }
        let Some((p, c)) = self.st.last_usage else {
            return;
        };
        let chunk = json!({
            "id": self.st.id,
            "object": "chat.completion.chunk",
            "created": self.st.created,
            "model": self.st.model,
            "choices": [],
            "usage": {
                "prompt_tokens": p,
                "completion_tokens": c,
                "total_tokens": p.saturating_add(c),
            },
        });
        self.out.push_back(crate::sse::frame(&chunk));
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

/// Separator used to carry a thought signature inside a tool-call id.
///
/// OpenAI's tool-call schema has nowhere to put Gemini's signature, but the
/// **id** is echoed back by every client without exception — it is how a tool
/// result is correlated to its call. Embedding the signature there is the only
/// carrier that survives a standard OpenAI client, and it is what LiteLLM does
/// (`call_<uuid>__thought__<base64>`), so an id produced by either gateway is
/// understood by the other.
const THOUGHT_SEP: &str = "__thought__";

/// `call_abc` + signature -> `call_abc__thought__<sig>`.
fn encode_call_id(id: &str, sig: Option<&str>) -> String {
    match sig.filter(|s| !s.is_empty()) {
        Some(sig) => format!("{id}{THOUGHT_SEP}{sig}"),
        None => id.to_string(),
    }
}

/// Split a tool-call id back into (client-visible id, embedded signature).
fn decode_call_id(id: &str) -> (&str, Option<&str>) {
    match id.split_once(THOUGHT_SEP) {
        Some((clean, sig)) if !sig.is_empty() => (clean, Some(sig)),
        _ => (id, None),
    }
}

/// Google's documented placeholder for a function call with no signature.
///
/// `skip_thought_signature_validator`, base64-encoded — the value Google names as
/// the last resort when a conversation is replayed without a real signature (for
/// instance, history carried over from a model that did not produce one). It passes
/// validation; Google notes it "will negatively impact model performance", which is
/// why it is only used when no real signature exists.
///
/// See <https://ai.google.dev/gemini-api/docs/thought-signatures#faqs>.
fn placeholder_thought_signature() -> &'static str {
    "c2tpcF90aG91Z2h0X3NpZ25hdHVyZV92YWxpZGF0b3I="
}

/// The thought signature a client echoed back for one tool call, if any.
///
/// Two spellings are accepted: the flat `function.thought_signature` this gateway
/// emits, and `provider_specific_fields.thought_signature` (either on the call or
/// on its `function`), which is where other gateways and SDKs put it. A real
/// signature always wins over the placeholder.
fn thought_signature_of(tc: &Value) -> Option<&str> {
    // The id first: it is the one carrier every client returns.
    if let Some(id) = tc.get("id").and_then(|i| i.as_str())
        && let (_, Some(sig)) = decode_call_id(id)
    {
        return Some(sig);
    }
    tc.pointer("/function/thought_signature")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            tc.pointer("/provider_specific_fields/thought_signature")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            tc.pointer("/function/provider_specific_fields/thought_signature")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
        })
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
    include_usage: bool,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    translate_sse_stream_from(
        resp.bytes_stream().map(|r| r.map_err(io::Error::other)),
        model,
        envelope,
        stats,
        include_usage,
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
    include_usage: bool,
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
        include_usage,
        stats,
        st: SseState {
            id: gen_id(),
            created,
            model: model.to_string(),
            sent_role: false,
            parts: PartSink::new(),
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
                if !s.ended {
                    // Usage chunk first, then the terminator — in that order, as
                    // OpenAI documents. `push_usage` runs *before* `add_usage_once`,
                    // which `take()`s the remembered pair.
                    s.push_usage();
                    s.add_usage_once();
                    s.push_done();
                } else {
                    s.add_usage_once();
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
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None, true)).await;

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
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None, true)).await;
        assert_eq!(finishes(&out), vec![json!("tool_calls")], "{out:?}");
    }

    /// ...and a plain text stream still ends with a plain `stop`.
    #[tokio::test]
    async fn a_text_only_stream_finishes_with_stop() {
        let body = vec![text_event("hi"), finish_event("STOP")];
        let resp = sse_response(body).await;
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None, true)).await;
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
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None, true)).await;

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
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None, true)).await;
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
            true,
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
        let out = frames(translate_sse_stream(resp, "gemini-x", false, None, true)).await;
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

    /// A client that says nothing about effort still gets the model's thoughts.
    ///
    /// `includeThoughts` is what makes the provider emit them at all. The gateway
    /// used to send nothing, so every reasoning UI — DSH, any panel that reads
    /// `reasoning_content` — showed an empty "Think" section even though the model
    /// was reasoning. Only visibility changes: no budget is sent, so the provider
    /// keeps its own dynamic policy.
    #[test]
    fn a_thinking_model_returns_its_thoughts_without_being_asked() {
        for model in ["gemini-3-flash", "gemini-3.8-flash", "gemini-2.5-flash"] {
            let out = translate_request(&json!({
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
            }))
            .expect("translates");
            assert_eq!(
                out["generationConfig"]["thinkingConfig"]["includeThoughts"], true,
                "{model} must have its thoughts returned: {out}"
            );
            assert!(
                out["generationConfig"]["thinkingConfig"]
                    .get("thinkingBudget")
                    .is_none(),
                "{model}: the budget stays the provider's own: {out}"
            );
        }
    }

    /// …but a model without a thinking mode must never be asked, or the request
    /// becomes a 400.
    #[test]
    fn a_non_thinking_model_is_not_asked_for_thoughts() {
        for model in ["gemini-1.5-flash", "gemini-2.0-flash"] {
            let out = translate_request(&json!({
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
            }))
            .expect("translates");
            assert!(
                out.get("generationConfig").is_none(),
                "{model} must get no thinkingConfig: {out}"
            );
        }
    }

    /// An explicit effort always wins over the default.
    #[test]
    fn an_explicit_effort_overrides_the_default_thought_visibility() {
        let off = translate_request(&json!({
            "model": "gemini-3-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "none",
        }))
        .expect("translates");
        assert_eq!(
            off["generationConfig"]["thinkingConfig"]["includeThoughts"], false,
            "reasoning_effort: none must still hide the thoughts"
        );

        let high = translate_request(&json!({
            "model": "gemini-3-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "reasoning_effort": "high",
        }))
        .expect("translates");
        assert_eq!(
            high["generationConfig"]["thinkingConfig"]["includeThoughts"],
            true
        );
        assert_eq!(
            high["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            24576
        );
    }

    /// The same request shape reaches Antigravity through the shared translator,
    /// so the envelope must carry the flag through unchanged.
    #[test]
    fn the_antigravity_envelope_keeps_the_thought_flag() {
        let inner = translate_request(&json!({
            "model": "gemini-3.8-flash",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .expect("translates");
        let env = crate::antigravity::translate_request_envelope("gemini-3.8-flash", inner, "p")
            .expect("envelope");
        assert_eq!(
            env["request"]["generationConfig"]["thinkingConfig"]["includeThoughts"], true,
            "{env}"
        );
    }

    /// An assistant turn may carry an image; it must not be silently dropped.
    ///
    /// `content_text` kept only text, so a model echoing a screenshot lost it with
    /// no error. `content_parts` translates both and refuses what it cannot express.
    #[test]
    fn an_assistant_image_is_translated() {
        let out = translate_request(&json!({
            "model": "gemini-3-flash",
            "messages": [
                {"role": "user", "content": "what is this?"},
                {"role": "assistant", "content": [
                    {"type": "text", "text": "here"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAA"}},
                ]},
                {"role": "user", "content": "and now?"},
            ],
        }))
        .expect("translates");
        let model_turn = out["contents"]
            .as_array()
            .expect("contents")
            .iter()
            .find(|c| c["role"] == "model")
            .expect("an assistant turn");
        let parts = model_turn["parts"].as_array().expect("parts");
        assert!(
            parts.iter().any(|p| p.get("inline_data").is_some()),
            "the assistant image was dropped: {parts:?}"
        );
        assert!(parts.iter().any(|p| p.get("text").is_some()));
    }

    /// `usage` must never ride a content chunk, and only when it was requested.
    ///
    /// Gemini reports cumulative `usageMetadata` on its own chunks; the translator
    /// attached it to the chunk carrying `delta`/`finish_reason` — a shape the
    /// OpenAI schema does not permit — and sent it unconditionally.
    #[tokio::test]
    async fn usage_is_a_separate_chunk_and_only_when_requested() {
        let body = || {
            vec![
                event(json!({"candidates": [{"content": {"role": "model",
                    "parts": [{"text": "hi"}]}}], "usageMetadata": {"promptTokenCount": 5,
                    "candidatesTokenCount": 2, "totalTokenCount": 7}})),
                event(
                    json!({"candidates": [{"content": {"role": "model", "parts": []},
                    "finishReason": "STOP"}], "usageMetadata": {"promptTokenCount": 5,
                    "candidatesTokenCount": 3, "totalTokenCount": 8}}),
                ),
            ]
        };

        let asked = frames(translate_sse_stream(
            sse_response(body()).await,
            "g",
            false,
            None,
            true,
        ))
        .await;
        let parsed = chunks(&asked);
        // No content chunk carries `usage`.
        for v in &parsed {
            if v.get("usage").is_some() {
                assert_eq!(
                    v["choices"],
                    json!([]),
                    "a usage chunk must have empty choices: {v}"
                );
            }
        }
        let with_usage: Vec<&Value> = parsed.iter().filter(|v| v.get("usage").is_some()).collect();
        assert_eq!(with_usage.len(), 1, "exactly one usage chunk: {asked:?}");
        assert_eq!(with_usage[0]["usage"]["prompt_tokens"], 5);
        assert_eq!(with_usage[0]["usage"]["completion_tokens"], 3);
        assert_eq!(with_usage[0]["usage"]["total_tokens"], 8);

        let unasked = frames(translate_sse_stream(
            sse_response(body()).await,
            "g",
            false,
            None,
            false,
        ))
        .await;
        assert!(
            chunks(&unasked).iter().all(|v| v.get("usage").is_none()),
            "no usage was requested: {unasked:?}"
        );
    }

    /// Gemini counts thinking **inside** `maxOutputTokens`, so the budget must
    /// fit under it.
    ///
    /// `reasoning_effort: "high"` on an 8192-cap model used to send
    /// `thinkingBudget: 24576` alongside `maxOutputTokens: 8192` — an impossible
    /// request (a 400 on 1.5/2.0, and on 2.5/3 the budget equalled the raised
    /// ceiling so thinking could consume the whole answer and the client got
    /// `finish_reason: "length"` with empty content).
    #[test]
    fn the_thinking_budget_always_fits_under_max_output_tokens() {
        for model in [
            "gemini-1.5-flash",
            "gemini-2.0-flash",
            "gemini-2.5-pro",
            "gemini-3-flash",
        ] {
            let out = translate_request(&json!({
                "model": model,
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 200,
                "reasoning_effort": "high",
            }))
            .expect("translates");
            let gc = &out["generationConfig"];
            let ceiling = gc["maxOutputTokens"].as_i64().expect("a ceiling");
            let budget = gc["thinkingConfig"]["thinkingBudget"]
                .as_i64()
                .expect("a budget");
            assert!(
                budget < ceiling,
                "{model}: budget {budget} must leave room under {ceiling}: {out}"
            );
            assert!(budget >= 1, "{model}: a positive budget must stay positive");
        }

        // A generous ceiling keeps the full requested budget.
        let roomy = translate_request(&json!({
            "model": "gemini-2.5-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 65_000,
            "reasoning_effort": "high",
        }))
        .expect("translates");
        assert_eq!(
            roomy["generationConfig"]["thinkingConfig"]["thinkingBudget"], 24_576,
            "a large ceiling must not shrink the requested effort"
        );
    }

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

    /// Invalid sampling/budget values must be rejected *by the gateway*, naming
    /// the field, instead of becoming an opaque upstream 400.
    #[test]
    fn nonsensical_generation_parameters_are_refused_locally() {
        for bad in [0, -1, -5] {
            let err = translate_request(&json!({
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": bad,
            }))
            .expect_err("max_tokens {bad} must be refused");
            assert!(err.contains("max_tokens"), "{err}");
        }
        // A non-integer budget is equally unusable.
        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": "lots",
        }))
        .expect_err("a string budget must be refused");
        assert!(err.contains("max_tokens"), "{err}");

        // …while a legal one is forwarded untouched.
        let ok = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 256,
        }))
        .expect("translates");
        assert_eq!(ok["generationConfig"]["maxOutputTokens"], 256);
    }

    /// Gemini's sampling range is 0..=2 and an out-of-range value is a hard 400;
    /// `topP: 0` returns an empty nucleus. Clamp and drop rather than fail.
    #[test]
    fn sampling_parameters_are_clamped_to_the_gemini_range() {
        let hot = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 999.0,
            "top_p": 5.0,
        }))
        .expect("translates");
        assert_eq!(hot["generationConfig"]["temperature"], 2.0);
        assert_eq!(hot["generationConfig"]["topP"], 1.0);

        let cold = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": -3.0,
            "top_p": 0.0,
        }))
        .expect("translates");
        assert_eq!(cold["generationConfig"]["temperature"], 0.0);
        assert!(
            cold["generationConfig"].get("topP").is_none(),
            "topP: 0 must be dropped, not sent as an empty nucleus: {cold}"
        );

        // NaN/inf cannot be represented in JSON, but a hostile body could try.
        let nan = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": "NaN",
        }))
        .expect("translates");
        assert!(
            nan.get("generationConfig").is_none(),
            "a non-numeric temperature is dropped, not forwarded: {nan}"
        );
    }

    /// `n > 1` asks for several completions; one `choices[0]` is all this
    /// translator emits, so silently returning one answer would lose the rest.
    /// Tool-call ids must be unique across turns, not just within one response.
    ///
    /// The id embedded `now_secs()` — a one-second clock — so two turns a second
    /// apart produced the identical `call_<secs>_1` and a multi-step agent loop
    /// correlated every tool result to the same call. The id now comes from a
    /// process-wide counter and never touches the clock.
    #[test]
    fn tool_call_ids_are_unique_across_requests() {
        // Two sinks stand in for two turns of the same conversation, built in the
        // same second — the case the old id collapsed.
        let mut first_turn = PartSink::new();
        let mut second_turn = PartSink::new();
        let a = first_turn.call_id();
        let b = second_turn.call_id();
        assert_ne!(a, b, "two turns produced the same id: {a}");

        // Ids within one response stay distinct (parallel tool calls).
        let c = first_turn.call_id();
        assert_ne!(a, c, "parallel calls must not share an id");

        // And a long run never repeats.
        let mut seen = std::collections::HashSet::new();
        let mut sink = PartSink::new();
        for _ in 0..1_000 {
            assert!(
                seen.insert(sink.call_id()),
                "an id repeated within one sink"
            );
        }
        for _ in 0..100 {
            let mut fresh = PartSink::new();
            assert!(seen.insert(fresh.call_id()), "an id repeated across sinks");
        }
    }

    #[test]
    fn a_multi_choice_request_is_refused_rather_than_truncated() {
        let err = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "n": 3,
        }))
        .expect_err("n > 1 must be refused");
        assert!(err.contains('n'), "{err}");
        assert!(err.contains("one completion"), "{err}");

        // The default (absent, or n = 1) still works.
        for n in [json!(serde_json::Value::Null), json!(1)] {
            let mut body = json!({"messages": [{"role": "user", "content": "hi"}]});
            if !n.is_null() {
                body["n"] = n;
            }
            translate_request(&body).expect("a single choice is fine");
        }
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

    /// Gemini's `stopSequences` are plain strings and reject control characters,
    /// so a stop sequence the gateway cannot express must be dropped rather than
    /// forwarded into a guaranteed `400 INVALID_ARGUMENT`.
    ///
    /// The FIM path synthesises `stop: ["\n\n\n"]` for chat models; sending it
    /// here made *every* autocomplete through `gemini`/`antigravity` fail.
    #[test]
    fn stop_sequences_with_control_characters_are_dropped_not_forwarded() {
        let out = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "stop": ["\n\n\n", "END", "", "a\tb"],
        }))
        .expect("translates");
        let seqs = out["generationConfig"]["stopSequences"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            seqs,
            vec![json!("END")],
            "only the legal sequence survives: {out}"
        );

        // When nothing legal is left, the field is omitted entirely rather than
        // sent as an empty array (Gemini rejects an empty `stopSequences`).
        let none = translate_request(&json!({
            "messages": [{"role": "user", "content": "hi"}],
            "stop": ["\n\n\n"],
        }))
        .expect("translates");
        assert!(
            none["generationConfig"].get("stopSequences").is_none(),
            "no legal sequence means no field: {none}"
        );
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

    /// A replayed tool call with no echoed signature must still carry one.
    ///
    /// Gemini 3 rejects the whole request otherwise:
    /// `Function call is missing a thought_signature in functionCall parts`.
    /// OpenAI's schema has nowhere to put the signature, so a plain client never
    /// returns it — the documented `skip_thought_signature_validator` placeholder
    /// is what keeps multi-turn tool use working (LiteLLM does the same).
    /// The shape stays a *sibling* `thoughtSignature`, never nested in
    /// `functionCall`.
    #[test]
    fn a_replayed_tool_call_without_a_signature_gets_the_documented_placeholder() {
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
        assert_eq!(part["functionCall"]["name"], "get_weather");
        assert_eq!(
            part["thoughtSignature"],
            placeholder_thought_signature(),
            "a signed part is required even when the client echoed nothing: {part}"
        );
        assert!(
            part["functionCall"].get("thoughtSignature").is_none(),
            "the signature belongs beside functionCall, not inside it: {part}"
        );
    }

    /// A tool result must use `role: "user"`, not `"tool"`.
    ///
    /// The public Gemini SDK builds the turn as `role: "tool"`, and adopting that
    /// broke Antigravity: its `v1internal` surface answers
    /// `Role 'tool' is not supported. Please use a valid role: SYSTEM, …` and the
    /// whole multi-turn tool conversation failed. `user` is the one value both
    /// surfaces accept, so it is what this translator emits.
    #[test]
    fn a_tool_result_uses_the_role_both_surfaces_accept() {
        let out = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "x"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "f", "arguments": "{}"},
                }]},
                {"role": "tool", "tool_call_id": "c1", "content": "r"},
            ],
        }))
        .expect("translates");
        let roles: Vec<&str> = out["contents"]
            .as_array()
            .expect("contents")
            .iter()
            .filter_map(|c| c["role"].as_str())
            .collect();
        assert_eq!(roles, vec!["user", "model", "user"], "{roles:?}");
        assert!(
            !roles.contains(&"tool"),
            "`role: 'tool'` is rejected by the Antigravity surface: {roles:?}"
        );
    }

    /// The signature survives a client that only echoes the tool-call id.
    ///
    /// This is the case that broke real multi-turn tool use: OpenAI's schema has
    /// no field for the signature, so a standard client returns only the id. The
    /// id is therefore the carrier (`call_x__thought__<sig>`, the same convention
    /// LiteLLM uses), and replaying it restores a real signature rather than the
    /// placeholder.
    #[test]
    fn the_signature_round_trips_through_the_tool_call_id() {
        let sig = "ENCRYPTED_SIG==";
        let id = encode_call_id("call_abc", Some(sig));
        assert_eq!(id, format!("call_abc__thought__{sig}"));

        // Decoding is lossless and leaves a plain id alone.
        assert_eq!(decode_call_id(&id), ("call_abc", Some(sig)));
        assert_eq!(decode_call_id("call_plain"), ("call_plain", None));
        // A stray separator with no signature is not a carrier.
        assert_eq!(
            decode_call_id("call_abc__thought__"),
            ("call_abc__thought__", None)
        );

        // End to end: a client echoes only the id.
        let out = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "call tool"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": id, "type": "function",
                    "function": {"name": "memory_search", "arguments": "{}"},
                }]},
                {"role": "tool", "tool_call_id": id, "content": "ok"},
            ],
        }))
        .expect("translates");
        let part = &out["contents"][1]["parts"][0];
        assert_eq!(
            part["thoughtSignature"], sig,
            "a real signature must be recovered from the id, not the placeholder: {part}"
        );
        assert_ne!(part["thoughtSignature"], placeholder_thought_signature());
        // The ids sent upstream are clean, so Gemini's own correlation works.
        assert!(part["functionCall"].get("id").is_none());
        assert_eq!(
            out["contents"][2]["parts"][0]["functionResponse"]["id"], "call_abc",
            "functionResponse carries the clean id"
        );
        assert_eq!(
            out["contents"][2]["parts"][0]["functionResponse"]["name"], "memory_search",
            "the name lookup must strip the signature first"
        );
    }

    /// The id carrier interoperates with a signature written the LiteLLM way.
    #[test]
    fn an_external_id_carrier_is_understood() {
        let out = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "x"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call_9__thought__OTHER_GATEWAY_SIG",
                    "type": "function",
                    "function": {"name": "f", "arguments": "{}"},
                }]},
                {"role": "tool", "tool_call_id": "call_9__thought__OTHER_GATEWAY_SIG",
                 "content": "r"},
            ],
        }))
        .expect("translates");
        assert_eq!(
            out["contents"][1]["parts"][0]["thoughtSignature"],
            "OTHER_GATEWAY_SIG"
        );
    }

    /// A real signature always wins over the placeholder, in either spelling.
    #[test]
    fn a_real_signature_is_preferred_over_the_placeholder() {
        for (label, call) in [
            (
                "flat field (what this gateway emits)",
                json!({"id":"c1","type":"function","function":{
                    "name":"f","arguments":"{}","thought_signature":"REAL-A"}}),
            ),
            (
                "provider_specific_fields on the call",
                json!({"id":"c1","type":"function",
                    "provider_specific_fields":{"thought_signature":"REAL-B"},
                    "function":{"name":"f","arguments":"{}"}}),
            ),
            (
                "provider_specific_fields on the function",
                json!({"id":"c1","type":"function","function":{
                    "name":"f","arguments":"{}",
                    "provider_specific_fields":{"thought_signature":"REAL-C"}}}),
            ),
        ] {
            let out = translate_request(&json!({
                "messages": [
                    {"role": "user", "content": "x"},
                    {"role": "assistant", "tool_calls": [call]},
                    {"role": "tool", "tool_call_id": "c1", "content": "r"},
                ],
            }))
            .expect("translates");
            let sig = out["contents"][1]["parts"][0]["thoughtSignature"]
                .as_str()
                .unwrap_or_default();
            assert_ne!(
                sig,
                placeholder_thought_signature(),
                "{label}: the placeholder must not win over a real signature"
            );
            assert!(sig.starts_with("REAL-"), "{label}: got {sig}");
        }

        // An empty string counts as absent, not as a signature.
        let out = translate_request(&json!({
            "messages": [
                {"role": "user", "content": "x"},
                {"role": "assistant", "tool_calls": [{"id":"c1","type":"function",
                    "function":{"name":"f","arguments":"{}","thought_signature":""}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "r"},
            ],
        }))
        .expect("translates");
        assert_eq!(
            out["contents"][1]["parts"][0]["thoughtSignature"],
            placeholder_thought_signature()
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
