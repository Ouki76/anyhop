//! Codex provider: ChatGPT OAuth accounts proxied to the Codex backend
//! (chatgpt.com/backend-api/codex/responses, OpenAI Responses API).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::{Value, json};
use std::io;
use tracing::warn;

/// Largest tool-call index we will materialise (mirrors `anthropic.rs`): the index
/// arrives from the upstream, and `u64::MAX` overflows the `+1` while `1e9` would
/// size a multi-gigabyte `Vec`.
const MAX_TOOL_INDEX: u64 = 1024;

pub const AUTH_URL: &str = "https://auth.openai.com/oauth/authorize";
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const CALLBACK_PORT: u16 = 1455;
pub const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";

// Token refresh window is configurable via `[tuning] token_refresh_window_secs`.

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_secs() -> u64 {
    now_ms() / 1000
}

fn gen_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("chatcmpl-{nanos:x}")
}

pub use crate::antigravity::AuthError;

struct AccountState {
    access_token: Option<String>,
    expires_at_ms: u64,
    /// Live refresh token: OpenAI rotates it on every refresh, so the current
    /// value may differ from the config's. Persisted via OAuthRecord.
    refresh_token: Option<String>,
}

pub struct CodexAccount {
    identity: String,
    pub email: Option<String>,
    pub account_id: Option<String>,
    provider: String,
    storage: Option<crate::storage::Storage>,
    client: reqwest::Client,
    state: tokio::sync::Mutex<AccountState>,
    tuning: std::sync::Arc<crate::config::Tuning>,
}

impl CodexAccount {
    pub fn new(
        cfg: &crate::config::OAuthAccountConfig,
        provider: &str,
        storage: Option<&crate::storage::Storage>,
        client: reqwest::Client,
        tuning: std::sync::Arc<crate::config::Tuning>,
    ) -> Self {
        let refresh_token = if cfg.refresh_token.is_empty() {
            None
        } else {
            Some(cfg.refresh_token.clone())
        };
        let identity = refresh_token
            .clone()
            .or_else(|| cfg.access_token.clone())
            .unwrap_or_default();

        // Load the cache when we might refresh (a cached rotated refresh token
        // may live there even if a static access token is configured).
        let cached = if cfg.access_token.is_none() || refresh_token.is_some() {
            storage.and_then(|s| s.load_oauth(provider, &identity))
        } else {
            None
        };
        // A rotated refresh token persisted earlier wins over the stale config one.
        let refresh_token = cached
            .as_ref()
            .and_then(|c| c.refresh_token.clone())
            .or(refresh_token);
        let access_token = cfg
            .access_token
            .clone()
            .or_else(|| cached.as_ref().map(|c| c.access_token.clone()))
            .filter(|t| !t.is_empty());
        // A pre-seeded token is treated as non-expiring only when there is no
        // way to refresh — otherwise let it expire and refresh normally.
        let expires_at_ms = if cfg.access_token.is_some() && refresh_token.is_none() {
            u64::MAX
        } else {
            cached.as_ref().map(|c| c.expires_at_ms).unwrap_or(0)
        };

        Self {
            identity,
            email: cfg.email.clone(),
            account_id: cfg.account_id.clone(),
            provider: provider.to_string(),
            storage: storage.cloned(),
            client,
            tuning,
            state: tokio::sync::Mutex::new(AccountState {
                access_token,
                expires_at_ms,
                refresh_token,
            }),
        }
    }

    pub fn pool_secret(&self) -> &str {
        &self.identity
    }

    pub fn label(&self) -> String {
        self.email.clone().unwrap_or_else(|| {
            let digest = sha2::Sha256::digest(self.identity.as_bytes());
            format!("acct:{}", hex::encode(&digest[..4]))
        })
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn persist(&self, access_token: &str, expires_at_ms: u64, refresh_token: Option<&str>) {
        if let Some(s) = &self.storage {
            s.save_oauth(
                &self.provider,
                &self.identity,
                crate::storage::OAuthRecord {
                    access_token: access_token.to_string(),
                    expires_at_ms,
                    project_id: None,
                    refresh_token: refresh_token.map(str::to_string),
                },
            );
        }
    }

    /// Drop the cached access token so the next call refreshes it.
    ///
    /// Called when the upstream rejects a token we believed valid (401/403):
    /// otherwise the rejected token was replayed until `expires_at_ms` (up to an
    /// hour), so a re-enabled account (or an operator retry) failed again with the
    /// same stale credential. The refresh token is kept.
    pub async fn invalidate_access_token(&self) {
        let mut st = self.state.lock().await;
        st.access_token = None;
        st.expires_at_ms = 0;
    }

    pub async fn ensure_access_token(&self) -> Result<String, AuthError> {
        let mut st = self.state.lock().await;
        if let Some(t) = &st.access_token {
            let valid_until = st
                .expires_at_ms
                .saturating_sub(self.tuning.token_refresh_window().as_millis() as u64);
            if now_ms() < valid_until {
                return Ok(t.clone());
            }
        }
        let Some(refresh_token) = st.refresh_token.clone() else {
            return Err(AuthError::Permanent(
                "static access token rejected and no refresh token configured".into(),
            ));
        };
        let resp = self
            .client
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", CLIENT_ID),
                ("refresh_token", refresh_token.as_str()),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Transient(format!("token refresh request failed: {e}")))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet: String = body.chars().take(300).collect();
            return if matches!(status.as_u16(), 400 | 401) {
                Err(AuthError::Permanent(format!(
                    "token refresh rejected ({status}): {snippet}"
                )))
            } else {
                Err(AuthError::Transient(format!(
                    "token refresh failed ({status}): {snippet}"
                )))
            };
        }
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| AuthError::Transient(format!("token refresh: bad JSON: {e}")))?;
        let token = v
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| AuthError::Transient("token refresh: no access_token".into()))?
            .to_string();
        let expires_in = v.get("expires_in").and_then(|e| e.as_u64()).unwrap_or(3600);
        st.expires_at_ms = now_ms() + expires_in * 1000;
        st.access_token = Some(token.clone());
        // OpenAI rotates refresh tokens: persist the replacement, otherwise the
        // old token is invalidated server-side and every later refresh fails.
        if let Some(rt) = v.get("refresh_token").and_then(|t| t.as_str())
            && rt != refresh_token
        {
            st.refresh_token = Some(rt.to_string());
        }
        self.persist(&token, st.expires_at_ms, st.refresh_token.as_deref());
        Ok(token)
    }
}

// ---------- request translation (chat.completions -> Responses API) ----------

pub fn translate_request(model: &str, body: &Value) -> Result<Value, String> {
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or("missing 'messages' array")?;

    let mut instructions: Vec<String> = Vec::new();
    let mut input: Vec<Value> = Vec::new();

    for msg in messages {
        let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
        match role {
            "system" | "developer" => {
                if let Some(t) = text_of(msg.get("content")) {
                    instructions.push(t);
                }
            }
            "user" => input.push(json!({
                "type": "message",
                "role": "user",
                "content": user_content(msg.get("content"))?,
            })),
            "assistant" => {
                if let Some(t) = text_of(msg.get("content"))
                    && !t.is_empty()
                {
                    input.push(json!({
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": t}],
                    }));
                }
                if let Some(tcs) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                    for tc in tcs {
                        input.push(json!({
                            "type": "function_call",
                            "call_id": tc.get("id").cloned().unwrap_or(json!("")),
                            "name": tc.pointer("/function/name").cloned().unwrap_or(json!("")),
                            "arguments": tc.pointer("/function/arguments").cloned().unwrap_or(json!("{}")),
                        }));
                    }
                }
            }
            "tool" => {
                input.push(json!({
                    "type": "function_call_output",
                    "call_id": msg.get("tool_call_id").cloned().unwrap_or(json!("")),
                    "output": text_of(msg.get("content")).unwrap_or_default(),
                }));
            }
            _ => {}
        }
    }

    let mut req = json!({
        "model": model,
        "store": false,
        "stream": true, // Codex backend is stream-only
        "instructions": instructions.join("\n\n"),
        "input": input,
    });

    if let Some(tools) = body.get("tools").and_then(|t| t.as_array()) {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let f = t.get("function")?;
                Some(json!({
                    "type": "function",
                    "name": f.get("name")?,
                    "description": f.get("description").cloned().unwrap_or(json!("")),
                    "parameters": f.get("parameters").cloned().unwrap_or(json!({"type": "object", "properties": {}})),
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
                "none" | "auto" | "required" => Some(tc.clone()),
                _ => None,
            },
            Value::Object(o) => o
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(|n| json!({"type": "function", "name": n})),
            _ => None,
        };
        if let Some(c) = choice {
            req["tool_choice"] = c;
        }
    }
    if let Some(effort) = body.get("reasoning_effort").and_then(|e| e.as_str()) {
        // `none` used to be mapped to `minimal` — the opposite of what the client
        // asked for — and `minimal` is itself rejected by models that only accept
        // low/medium/high. Omit `reasoning` instead: the backend then applies the
        // model's own default, which is the closest legal request.
        let mapped = match effort {
            "none" => None,
            "minimal" => Some("minimal"),
            "xhigh" | "max" => Some("xhigh"),
            other => Some(other),
        };
        if let Some(mapped) = mapped {
            req["reasoning"] = json!({"effort": mapped, "summary": "auto"});
        }
    }
    // No `temperature`: every Codex backend model is a reasoning model, and the
    // Responses API rejects sampling parameters for them — forwarding one turned
    // any client that sets a temperature (most OpenAI SDK examples do) into a 400.
    if body.get("temperature").is_some() {
        tracing::debug!("codex: dropping 'temperature' (reasoning models do not sample)");
    }
    // Structured output: the Responses API expresses it as `text.format`, so a
    // json_schema request used to come back as prose with HTTP 200.
    if let Some(rf) = body.get("response_format") {
        match rf.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "json_schema" => {
                let js = rf.get("json_schema");
                let name = js
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("output");
                let schema = js
                    .and_then(|s| s.get("schema"))
                    .or_else(|| rf.get("schema"))
                    .cloned()
                    .unwrap_or(json!({"type": "object"}));
                let strict = js
                    .and_then(|s| s.get("strict"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                req["text"] = json!({
                    "format": {
                        "type": "json_schema",
                        "name": name,
                        "schema": schema,
                        "strict": strict,
                    }
                });
            }
            "json_object" => {
                req["text"] = json!({"format": {"type": "json_object"}});
            }
            _ => {}
        }
    }
    if let Some(mt) = body
        .get("max_completion_tokens")
        .or_else(|| body.get("max_tokens"))
    {
        req["max_output_tokens"] = mt.clone();
    }

    Ok(req)
}

fn text_of(content: Option<&Value>) -> Option<String> {
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

fn user_content(content: Option<&Value>) -> Result<Vec<Value>, String> {
    match content {
        None => Ok(vec![json!({"type": "input_text", "text": ""})]),
        Some(Value::String(s)) => Ok(vec![json!({"type": "input_text", "text": s})]),
        Some(Value::Array(arr)) => {
            let mut parts = Vec::new();
            for p in arr {
                match p.get("type").and_then(|t| t.as_str()) {
                    Some("text") => parts.push(json!({
                        "type": "input_text",
                        "text": p.get("text").cloned().unwrap_or(json!("")),
                    })),
                    Some("image_url") => {
                        let url = p
                            .pointer("/image_url/url")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        if !url.starts_with("data:") {
                            return Err("only base64 data: URLs are supported for images".into());
                        }
                        parts.push(json!({"type": "input_image", "image_url": url}));
                    }
                    _ => {}
                }
            }
            Ok(parts)
        }
        _ => Err("unsupported message content type".into()),
    }
}

// ---------- stream translation (Responses API events -> chat.completion.chunk) ----------

struct SseState {
    id: String,
    created: u64,
    model: String,
    sent_role: bool,
    /// Responses item_id -> openai tool_calls index.
    item_tool: Vec<(String, usize)>,
    prompt_tokens: u64,
    completion_tokens: u64,
}

impl SseState {
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
                "total_tokens": self.prompt_tokens.saturating_add(self.completion_tokens),
            });
        }
        ch
    }
}

/// One Responses API event -> zero or more OpenAI chunks.
fn translate_event(v: &Value, st: &mut SseState) -> Option<Value> {
    let ty = v.get("type").and_then(|t| t.as_str())?;

    match ty {
        "response.output_text.delta" => {
            let text = v.get("delta").cloned().unwrap_or(json!(""));
            Some(st.chunk(json!({"content": text}), Value::Null))
        }
        "response.reasoning_summary_text.delta" => {
            let text = v.get("delta").cloned().unwrap_or(json!(""));
            Some(st.chunk(json!({"reasoning_content": text}), Value::Null))
        }
        "response.output_item.added" => {
            let item = v.get("item")?;
            if item.get("type").and_then(|t| t.as_str()) != Some("function_call") {
                return None;
            }
            let idx = st.item_tool.len();
            let item_id = item
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string();
            st.item_tool.push((item_id, idx));
            Some(st.chunk(
                json!({"tool_calls": [{
                    "index": idx,
                    "id": item.get("call_id").cloned().unwrap_or(json!("")),
                    "type": "function",
                    "function": {
                        "name": item.get("name").cloned().unwrap_or(json!("")),
                        "arguments": "",
                    },
                }]}),
                Value::Null,
            ))
        }
        "response.function_call_arguments.delta" => {
            let item_id = v.get("item_id").and_then(|i| i.as_str()).unwrap_or("");
            let idx = st
                .item_tool
                .iter()
                .find(|(id, _)| id == item_id)
                .map(|(_, i)| *i)?;
            let delta = v.get("delta").cloned().unwrap_or(json!(""));
            Some(st.chunk(
                json!({"tool_calls": [{"index": idx, "function": {"arguments": delta}}]}),
                Value::Null,
            ))
        }
        "response.completed" | "response.incomplete" => {
            let resp = v.get("response")?;
            if let Some(u) = resp.get("usage") {
                st.prompt_tokens = u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
                st.completion_tokens = u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0);
            }
            let finish = if ty == "response.incomplete" {
                "length"
            } else {
                // tool calls present? then "tool_calls"
                let has_calls = resp
                    .get("output")
                    .and_then(|o| o.as_array())
                    .map(|o| {
                        o.iter().any(|i| {
                            i.get("type").and_then(|t| t.as_str()) == Some("function_call")
                        })
                    })
                    .unwrap_or(false);
                if has_calls { "tool_calls" } else { "stop" }
            };
            Some(st.chunk(json!({}), json!(finish)))
        }
        "response.failed" => {
            // Surface upstream failures instead of a silent empty stream:
            // OpenAI-style error frame, then DONE at EOF.
            let msg = v
                .pointer("/response/error/message")
                .and_then(|m| m.as_str())
                .unwrap_or("upstream response failed");
            Some(json!({
                "error": {"message": msg, "type": "upstream_error", "code": "response_failed"}
            }))
        }
        _ => None,
    }
}

/// Convert the Codex SSE upstream into an OpenAI-style SSE byte stream.
pub fn translate_sse_stream(
    resp: reqwest::Response,
    model: &str,
    stats: Option<std::sync::Arc<crate::pool::KeyState>>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
    struct State {
        inner: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
        parser: crate::sse::SseParser,
        pending: std::collections::VecDeque<Bytes>,
        /// Translated chunks queued for emission (role chunk + event chunk).
        out: std::collections::VecDeque<Bytes>,
        eof: bool,
        sent_done: bool,
        stats: Option<std::sync::Arc<crate::pool::KeyState>>,
        st: SseState,
    }

    let state = State {
        inner: Box::pin(resp.bytes_stream()),
        parser: crate::sse::SseParser::new(),
        pending: std::collections::VecDeque::new(),
        out: std::collections::VecDeque::new(),
        eof: false,
        sent_done: false,
        stats,
        st: SseState {
            id: gen_id(),
            created: now_secs(),
            model: model.to_string(),
            sent_role: false,
            item_tool: Vec::new(),
            prompt_tokens: 0,
            completion_tokens: 0,
        },
    };

    futures::stream::unfold(state, move |mut s| async move {
        loop {
            if let Some(b) = s.out.pop_front() {
                return Some((Ok(b), s));
            }
            if let Some(data) = s.pending.pop_front() {
                let Ok(v) = serde_json::from_slice::<Value>(&data) else {
                    continue;
                };
                let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                // Emit the role chunk for the first event WITHOUT consuming the
                // event itself — its payload is still translated below.
                if !s.st.sent_role {
                    s.st.sent_role = true;
                    let rc = s.st.chunk(json!({"role": "assistant"}), Value::Null);
                    s.out.push_back(crate::sse::frame(&rc));
                }
                // Usage stats for terminal events: translate_event also stashes
                // them into the final chunk, but stats must be recorded even
                // though that arm returns a chunk (the old code skipped it).
                if matches!(ty, "response.completed" | "response.incomplete")
                    && let Some(u) = v.pointer("/response/usage")
                    && let Some(k) = &s.stats
                {
                    use std::sync::atomic::Ordering::Relaxed;
                    k.prompt_tokens.fetch_add(
                        u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                        Relaxed,
                    );
                    k.completion_tokens.fetch_add(
                        u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
                        Relaxed,
                    );
                }
                if let Some(chunk) = translate_event(&v, &mut s.st) {
                    s.out.push_back(crate::sse::frame(&chunk));
                }
                if ty == "response.failed" {
                    warn!("codex upstream: response.failed");
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
                Some(Ok(b)) => match s.parser.feed_checked(&b) {
                    Ok(events) => s.pending.extend(events),
                    Err(e) => {
                        // The cap means the upstream never framed an event: fail the
                        // stream instead of relaying a truncated answer as complete.
                        tracing::debug!(error = %e, "upstream SSE event exceeded the parser cap");
                        s.out.push_back(crate::sse::frame(&json!({
                            "error": {
                                "message": e.to_string(),
                                "type": "upstream_error",
                                "code": "response_failed",
                            }
                        })));
                        s.out
                            .push_back(bytes::Bytes::from_static(crate::sse::DONE_FRAME));
                        s.sent_done = true;
                        s.eof = true;
                    }
                },
                Some(Err(e)) => return Some((Err(io::Error::other(e)), s)),
                None => {
                    s.eof = true;
                    s.pending.extend(s.parser.finish());
                }
            }
        }
    })
}

/// Codex backend is stream-only: collect the SSE stream into a chat.completion.
pub async fn collect_non_stream(resp: reqwest::Response, model: &str) -> Result<Value, String> {
    let stream = translate_sse_stream(resp, model, None);
    futures::pin_mut!(stream);

    let mut content = String::new();
    let mut reasoning = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    let mut finish = "stop".to_string();
    let mut usage = json!({"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0});
    let mut id = gen_id();
    let mut created = now_secs();

    while let Some(item) = stream.next().await {
        let bytes = item.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines() {
            let Some(data) = line.strip_prefix("data: ") else {
                continue;
            };
            if data == "[DONE]" {
                continue;
            }
            let Ok(chunk) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if let Some(s) = chunk.get("id").and_then(|i| i.as_str()) {
                id = s.to_string();
            }
            if let Some(c) = chunk.get("created").and_then(|c| c.as_u64()) {
                created = c;
            }
            if let Some(u) = chunk.get("usage") {
                usage = u.clone();
            }
            let Some(choice) = chunk.pointer("/choices/0") else {
                continue;
            };
            if let Some(f) = choice.get("finish_reason").and_then(|f| f.as_str()) {
                finish = f.to_string();
            }
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(t) = delta.get("content").and_then(|c| c.as_str()) {
                content.push_str(t);
            }
            if let Some(t) = delta.get("reasoning_content").and_then(|c| c.as_str()) {
                reasoning.push_str(t);
            }
            if let Some(tcs) = delta.get("tool_calls").and_then(|t| t.as_array()) {
                for tc in tcs {
                    // `index` is upstream-controlled: cap it before it sizes a Vec
                    // (u64::MAX overflows `+1`; 1e9 allocates gigabytes).
                    let raw = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                    if raw > MAX_TOOL_INDEX {
                        return Err(format!(
                            "tool call index {raw} rejected: the maximum is {MAX_TOOL_INDEX}"
                        ));
                    }
                    let idx = raw as usize;
                    while tool_calls.len() <= idx {
                        tool_calls.push(json!({
                            "id": "", "type": "function",
                            "function": {"name": "", "arguments": ""},
                        }));
                    }
                    if let Some(cid) = tc.get("id").and_then(|i| i.as_str())
                        && !cid.is_empty()
                    {
                        tool_calls[idx]["id"] = json!(cid);
                    }
                    if let Some(n) = tc.pointer("/function/name").and_then(|n| n.as_str())
                        && !n.is_empty()
                    {
                        tool_calls[idx]["function"]["name"] = json!(n);
                    }
                    if let Some(a) = tc.pointer("/function/arguments").and_then(|a| a.as_str()) {
                        let cur = tool_calls[idx]["function"]["arguments"]
                            .as_str()
                            .unwrap_or("")
                            .to_string();
                        tool_calls[idx]["function"]["arguments"] = json!(cur + a);
                    }
                }
            }
        }
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

    Ok(json!({
        "id": id,
        "object": "chat.completion",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": usage,
    }))
}

// ---------- OAuth authorization-code flow with PKCE (`anyhop auth codex`) ----------

fn random_verifier() -> anyhow::Result<String> {
    // PKCE needs a CSPRNG; a time+pid fallback would be predictable.
    let mut raw = [0u8; 48];
    getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("CSPRNG unavailable: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

use sha2::Digest;

/// A started Codex OAuth flow.
pub struct PendingAuth {
    pub url: String,
    pub state: String,
    pub redirect_uri: String,
    verifier: String,
    /// `None` = headless: the code arrives from a public callback or a pasted URL.
    pub listener: Option<tokio::net::TcpListener>,
    http: reqwest::Client,
}

pub struct AuthOutcome {
    pub refresh_token: String,
    pub email: Option<String>,
    pub account_id: Option<String>,
}

/// Start the Codex OAuth flow (non-blocking): returns the URL to open.
pub async fn start_auth(proxy: Option<&str>) -> anyhow::Result<PendingAuth> {
    start_auth_with(proxy, &crate::config::Tuning::default(), None).await
}

/// `redirect_uri = Some(public)` runs headless (the browser comes back to our own
/// /api/auth/callback); `None` keeps the loopback listener on CALLBACK_PORT.
pub async fn start_auth_with(
    proxy: Option<&str>,
    tuning: &crate::config::Tuning,
    redirect_uri: Option<&str>,
) -> anyhow::Result<PendingAuth> {
    let mut builder = reqwest::Client::builder().timeout(tuning.oauth_http_timeout());
    if let Some(p) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(p)?);
    }
    let http = builder.build()?;

    let verifier = random_verifier()?;
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
    // Random, not the clock: the callback route carries no admin key, so the
    // `state` is the only thing binding a `code` to *this* flow.
    let state = crate::antigravity::random_oauth_state()?;
    let redirect = redirect_uri.unwrap_or(REDIRECT_URI).to_string();
    let url = format!(
        "{AUTH_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&scope={}&state={state}&code_challenge={challenge}&code_challenge_method=S256&codex_cli_simplified_flow=true&id_token_add_organizations=true",
        crate::antigravity::urlencoded(&redirect),
        crate::antigravity::urlencoded("openid email profile offline_access"),
    );
    let listener = match redirect_uri {
        Some(_) => None,
        None => Some(
            tokio::net::TcpListener::bind(("127.0.0.1", CALLBACK_PORT))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "cannot bind localhost:{CALLBACK_PORT}: {e} (auth already running?)"
                    )
                })?,
        ),
    };
    Ok(PendingAuth {
        url,
        state,
        redirect_uri: redirect,
        verifier,
        listener,
        http,
    })
}

/// Wait for the browser callback and complete the exchange.
pub async fn complete_auth(p: PendingAuth) -> anyhow::Result<AuthOutcome> {
    let code = wait_for_callback(&p).await?;
    finish(p, &code).await
}

/// Wait for the loopback browser callback and return the authorization code.
///
/// Split from the token exchange so the caller can race it against a pasted
/// callback URL — the panel may be used from another machine, where the browser
/// cannot reach this listener at all.
pub async fn wait_for_callback(p: &PendingAuth) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(listener) = p.listener.as_ref() else {
        anyhow::bail!("this flow is headless — supply the code with complete_with_code()");
    };
    let (mut sock, _) = listener.accept().await?;
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("");
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut got_state = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = Some(crate::antigravity::percent_decode(v)),
                "state" => got_state = Some(v.to_string()),
                _ => {}
            }
        }
    }

    let ok = code.is_some() && got_state.as_deref() == Some(p.state.as_str());
    let (status, page) = if ok {
        (
            "200 OK",
            "<h1>anyhop: authorized</h1><p>You can close this tab.</p>",
        )
    } else {
        ("400 Bad Request", "<h1>anyhop: authorization failed</h1>")
    };
    let html = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{page}"
    );
    let _ = sock.write_all(html.as_bytes()).await;

    let code = code.ok_or_else(|| anyhow::anyhow!("callback without code"))?;
    anyhow::ensure!(
        got_state.as_deref() == Some(p.state.as_str()),
        "state mismatch, retry"
    );
    Ok(code)
}

/// Complete a headless flow with a code obtained elsewhere.
pub async fn complete_with_code(p: PendingAuth, code: &str) -> anyhow::Result<AuthOutcome> {
    finish(p, code).await
}

async fn finish(p: PendingAuth, code: &str) -> anyhow::Result<AuthOutcome> {
    let resp = p
        .http
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", code),
            ("redirect_uri", p.redirect_uri.as_str()),
            ("code_verifier", p.verifier.as_str()),
        ])
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        let snippet: String = body.chars().take(300).collect();
        anyhow::bail!("token exchange failed ({status}): {snippet}");
    }
    let v: Value = serde_json::from_str(&body)?;
    let refresh_token = v
        .get("refresh_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("no refresh_token"))?
        .to_string();
    let id_token = v.get("id_token").and_then(|t| t.as_str()).unwrap_or("");
    let (email, account_id) = parse_id_token(id_token);
    Ok(AuthOutcome {
        refresh_token,
        email,
        account_id,
    })
}

/// CLI OAuth flow: prints a TOML snippet on success.
pub async fn run_auth_flow(proxy: Option<String>) -> anyhow::Result<()> {
    let pending = start_auth(proxy.as_deref()).await?;
    if let Some(p) = &proxy {
        println!("Using proxy: {p}");
    }
    println!(
        "\nOpen this link and sign in to your ChatGPT account:\n\n{}\n",
        pending.url
    );
    let _ = std::process::Command::new("xdg-open")
        .arg(&pending.url)
        .spawn();
    println!("Waiting for the callback on localhost:{CALLBACK_PORT} ...");
    let out = complete_auth(pending).await?;

    println!("\nDone! Add this to anyhop.toml:\n");
    println!("[[providers]]");
    println!("name = \"codex\"");
    println!("type = \"codex\"");
    println!("strategy = \"fill_first\"");
    println!();
    println!("[[providers.accounts]]");
    if let Some(e) = &out.email {
        println!("email = \"{e}\"");
    }
    println!("refresh_token = \"{}\"", out.refresh_token);
    if let Some(a) = &out.account_id {
        println!("account_id = \"{a}\"");
    }
    println!();
    Ok(())
}

/// Extract (email, account_id) from the OpenAI id_token JWT claims.
fn parse_id_token(id_token: &str) -> (Option<String>, Option<String>) {
    let mut parts = id_token.split('.');
    parts.next();
    let Some(payload) = parts.next() else {
        return (None, None);
    };
    let Ok(raw) = URL_SAFE_NO_PAD.decode(payload) else {
        return (None, None);
    };
    let Ok(claims) = serde_json::from_slice::<Value>(&raw) else {
        return (None, None);
    };
    let email = claims
        .pointer("/https://api.openai.com/profile/email")
        .and_then(|e| e.as_str())
        .map(str::to_string);
    let account_id = claims
        .pointer("/https://api.openai.com/auth/chatgpt_account_id")
        .and_then(|e| e.as_str())
        .map(str::to_string);
    (email, account_id)
}

#[cfg(test)]
mod oauth_state_tests {
    use super::*;

    /// Same defect as antigravity: the state was the wall clock in hex.
    #[tokio::test]
    async fn each_flow_gets_an_unpredictable_state() {
        let a = start_auth_with(
            None,
            &crate::config::Tuning::default(),
            Some("https://gw.example.com/api/auth/callback"),
        )
        .await
        .expect("headless flow");
        let b = start_auth_with(
            None,
            &crate::config::Tuning::default(),
            Some("https://gw.example.com/api/auth/callback"),
        )
        .await
        .expect("headless flow");
        assert_ne!(a.state, b.state, "two flows must not share a state");
        assert_eq!(a.state.len(), 64, "32 bytes, hex-encoded");
        assert!(a.url.contains(&format!("state={}", a.state)), "{}", a.url);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        assert_ne!(
            a.state,
            format!("{now:x}"),
            "the state must not be the clock"
        );
        // The PKCE verifier is independent of the state and still present.
        assert!(a.url.contains("code_challenge="), "{}", a.url);
    }
}

/// The Codex provider is a full translation layer: chat.completions in,
/// Responses API out (request), and Responses SSE events back as OpenAI chunks.
/// Both directions are pure functions of the payload, so they are pinned here
/// instead of only through the Python mock upstream.
#[cfg(test)]
mod translate_tests {
    use super::*;

    // ----- request: chat.completions -> Responses API -----

    /// The Codex backend has no "system" role: system/developer content becomes
    /// `instructions`, and the conversation becomes typed `input` items. Getting
    /// this wrong silently drops the operator's system prompt.
    #[test]
    fn a_chat_request_becomes_a_responses_request() {
        let body = json!({
            "model": "ignored-client-model",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "developer", "content": "and precise"},
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi there"},
                {"role": "user", "content": [
                    {"type": "text", "text": "look:"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
                ]}
            ]
        });
        let out = translate_request("gpt-5-codex", &body).expect("translates");

        assert_eq!(out["model"], "gpt-5-codex", "the resolved model wins");
        assert_eq!(out["store"], false);
        assert_eq!(out["stream"], true, "the Codex backend is stream-only");
        assert_eq!(out["instructions"], "be terse\n\nand precise");

        let input = out["input"].as_array().expect("input array");
        assert_eq!(
            input.len(),
            3,
            "system/developer become instructions, the rest is one item each: {input:?}"
        );
        assert_eq!(input[0]["type"], "message");
        assert_eq!(input[0]["role"], "user");
        assert_eq!(input[0]["content"][0]["type"], "input_text");
        assert_eq!(input[0]["content"][0]["text"], "hello");
        // Assistant text is replayed as output_text, not input_text.
        assert_eq!(input[1]["content"][0]["type"], "output_text");
        assert_eq!(input[1]["content"][0]["text"], "hi there");
        // The multimodal user turn keeps its text and its data: image.
        assert_eq!(input[2]["content"][0]["text"], "look:");
        assert_eq!(input[2]["content"][1]["type"], "input_image");
        assert_eq!(
            input[2]["content"][1]["image_url"],
            "data:image/png;base64,AAAA"
        );
    }

    /// Tool calls and their results are how an agent loop continues. A chat
    /// `tool_calls` array must become `function_call` items (in order), and a
    /// `tool` message must become a `function_call_output` bound by call_id.
    #[test]
    fn tool_calls_and_tool_results_round_trip_as_responses_items() {
        let body = json!({
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call_1", "type": "function",
                     "function": {"name": "get_weather", "arguments": "{\"city\":\"Oslo\"}"}},
                    {"id": "call_2", "type": "function",
                     "function": {"name": "get_time", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call_1", "content": "3 degrees"}
            ]
        });
        let out = translate_request("m", &body).expect("translates");
        let input = out["input"].as_array().expect("input");

        let calls: Vec<&Value> = input
            .iter()
            .filter(|i| i["type"] == "function_call")
            .collect();
        assert_eq!(calls.len(), 2, "{input:?}");
        assert_eq!(calls[0]["call_id"], "call_1");
        assert_eq!(calls[0]["name"], "get_weather");
        assert_eq!(calls[0]["arguments"], "{\"city\":\"Oslo\"}");
        assert_eq!(calls[1]["call_id"], "call_2");
        // The assistant turn had no text, so no empty message may be emitted.
        assert!(
            !input
                .iter()
                .any(|i| i["type"] == "message" && i["role"] == "assistant"),
            "an empty assistant message must be dropped: {input:?}"
        );

        let result = input
            .iter()
            .find(|i| i["type"] == "function_call_output")
            .expect("the tool result is forwarded");
        assert_eq!(result["call_id"], "call_1");
        assert_eq!(result["output"], "3 degrees");
    }

    /// OpenAI's chat `tools` have the definition nested under `function`; the
    /// Responses API flattens it. Sending the nested shape is a 400 upstream, so
    /// this is a hard requirement, not cosmetics.
    #[test]
    fn tool_definitions_are_flattened_and_choices_are_mapped() {
        let body = json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {"type": "function", "function": {
                    "name": "f", "description": "does f",
                    "parameters": {"type": "object", "properties": {"x": {"type": "string"}}}
                }},
                {"type": "function", "function": {"name": "g"}}
            ],
            "tool_choice": {"type": "function", "function": {"name": "g"}}
        });
        let out = translate_request("m", &body).expect("translates");
        let tools = out["tools"].as_array().expect("tools");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["type"], "function");
        assert_eq!(tools[0]["name"], "f");
        assert_eq!(tools[0]["description"], "does f");
        assert_eq!(tools[0]["parameters"]["properties"]["x"]["type"], "string");
        assert!(
            tools[0].get("function").is_none(),
            "the nested form must not survive: {:?}",
            tools[0]
        );
        // A tool with no schema still gets a valid empty object schema.
        assert_eq!(tools[1]["parameters"]["type"], "object");
        // A specific choice becomes {type, name}; string choices pass through.
        assert_eq!(out["tool_choice"]["type"], "function");
        assert_eq!(out["tool_choice"]["name"], "g");

        for choice in ["none", "auto", "required"] {
            let body = json!({
                "messages": [{"role": "user", "content": "hi"}],
                "tool_choice": choice
            });
            assert_eq!(
                translate_request("m", &body).expect("translates")["tool_choice"],
                choice
            );
        }
    }

    /// Sampling knobs and the reasoning effort vocabulary (OpenAI chat names vs
    /// Responses names) must be carried, not dropped.
    #[test]
    fn generation_knobs_are_carried_over() {
        let body = json!({
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.3,
            "max_completion_tokens": 512,
            "reasoning_effort": "max"
        });
        let out = translate_request("m", &body).expect("translates");
        // Codex models are reasoning models: the Responses API rejects sampling
        // parameters for them, so a forwarded temperature was a guaranteed 400.
        assert!(
            out.get("temperature").is_none(),
            "temperature must not be forwarded to a reasoning backend: {out}"
        );
        assert_eq!(out["max_output_tokens"], 512);
        assert_eq!(
            out["reasoning"]["effort"], "xhigh",
            "max is xhigh on Responses"
        );
        assert_eq!(out["reasoning"]["summary"], "auto");

        // max_tokens is the legacy spelling and is accepted as a fallback.
        let body = json!({
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 64,
            "reasoning_effort": "minimal"
        });
        let out = translate_request("m", &body).expect("translates");
        assert_eq!(out["max_output_tokens"], 64);
        assert_eq!(out["reasoning"]["effort"], "minimal");
    }

    /// Local validation instead of a doomed upstream call: the Codex backend
    /// cannot fetch remote images, and a body without messages is not a request.
    #[test]
    fn locally_undeliverable_requests_are_rejected_with_a_reason() {
        let missing = json!({"messages": "not an array"});
        assert!(
            translate_request("m", &missing)
                .expect_err("no messages")
                .contains("messages")
        );

        let remote_image = json!({"messages": [{"role": "user", "content": [
            {"type": "image_url", "image_url": {"url": "https://example.com/x.png"}}
        ]}]});
        let err = translate_request("m", &remote_image).expect_err("remote images are refused");
        assert!(err.contains("data:"), "{err}");

        let bad_content = json!({"messages": [{"role": "user", "content": 42}]});
        assert!(translate_request("m", &bad_content).is_err());
    }

    // ----- response: Responses SSE events -> chat.completion.chunk -----

    fn sse_state() -> SseState {
        SseState {
            id: "chatcmpl-test".into(),
            created: 1_700_000_000,
            model: "gpt-5-codex".into(),
            sent_role: false,
            item_tool: Vec::new(),
            prompt_tokens: 0,
            completion_tokens: 0,
        }
    }

    #[test]
    fn text_and_reasoning_deltas_become_content_and_reasoning_content() {
        let mut st = sse_state();
        let text = translate_event(
            &json!({"type": "response.output_text.delta", "delta": "Hello"}),
            &mut st,
        )
        .expect("a chunk");
        assert_eq!(text["object"], "chat.completion.chunk");
        assert_eq!(text["model"], "gpt-5-codex");
        assert_eq!(text["choices"][0]["delta"]["content"], "Hello");
        assert_eq!(text["choices"][0]["finish_reason"], Value::Null);
        assert!(text.get("usage").is_none(), "usage only at the end");

        let reasoning = translate_event(
            &json!({"type": "response.reasoning_summary_text.delta", "delta": "thinking"}),
            &mut st,
        )
        .expect("a chunk");
        assert_eq!(
            reasoning["choices"][0]["delta"]["reasoning_content"],
            "thinking"
        );
    }

    /// Tool calls arrive as an item announcement followed by argument deltas
    /// keyed by `item_id`. The index mapping must be stable, and arguments must
    /// land on the same tool_calls entry; otherwise the client assembles two
    /// half calls.
    #[test]
    fn streamed_tool_calls_keep_one_index_per_item() {
        let mut st = sse_state();
        let added = translate_event(
            &json!({
                "type": "response.output_item.added",
                "item": {"type": "function_call", "id": "item_a", "call_id": "call_a", "name": "f"}
            }),
            &mut st,
        )
        .expect("the tool call is announced");
        assert_eq!(added["choices"][0]["delta"]["tool_calls"][0]["index"], 0);
        assert_eq!(
            added["choices"][0]["delta"]["tool_calls"][0]["id"],
            "call_a"
        );
        assert_eq!(
            added["choices"][0]["delta"]["tool_calls"][0]["function"]["name"],
            "f"
        );
        assert_eq!(
            added["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            ""
        );

        let delta = translate_event(
            &json!({"type": "response.function_call_arguments.delta", "item_id": "item_a", "delta": "{\"x\":"}),
            &mut st,
        )
        .expect("argument delta");
        assert_eq!(
            delta["choices"][0]["delta"]["tool_calls"][0]["index"], 0,
            "the delta must target the announced index"
        );
        assert_eq!(
            delta["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "{\"x\":"
        );

        // A second call gets its own index; an unknown item id is ignored rather
        // than fabricating a call.
        let second = translate_event(
            &json!({
                "type": "response.output_item.added",
                "item": {"type": "function_call", "id": "item_b", "call_id": "call_b", "name": "g"}
            }),
            &mut st,
        )
        .expect("second call");
        assert_eq!(second["choices"][0]["delta"]["tool_calls"][0]["index"], 1);
        assert!(
            translate_event(
                &json!({"type": "response.function_call_arguments.delta", "item_id": "nope", "delta": "x"}),
                &mut st
            )
            .is_none()
        );
        // Non-function items are not tool calls.
        assert!(
            translate_event(
                &json!({"type": "response.output_item.added", "item": {"type": "message"}}),
                &mut st
            )
            .is_none()
        );
    }

    /// The terminal event carries usage and the finish reason; the client relies
    /// on `tool_calls` to know it must run tools, and on `length` to know the
    /// answer was cut off.
    #[test]
    fn the_terminal_event_reports_usage_and_the_right_finish_reason() {
        let mut st = sse_state();
        let done = translate_event(
            &json!({
                "type": "response.completed",
                "response": {
                    "usage": {"input_tokens": 11, "output_tokens": 7},
                    "output": [{"type": "message"}]
                }
            }),
            &mut st,
        )
        .expect("a final chunk");
        assert_eq!(done["choices"][0]["finish_reason"], "stop");
        assert_eq!(done["usage"]["prompt_tokens"], 11);
        assert_eq!(done["usage"]["completion_tokens"], 7);
        assert_eq!(done["usage"]["total_tokens"], 18);

        let mut st = sse_state();
        let with_tools = translate_event(
            &json!({
                "type": "response.completed",
                "response": {"output": [{"type": "function_call"}]}
            }),
            &mut st,
        )
        .expect("a final chunk");
        assert_eq!(with_tools["choices"][0]["finish_reason"], "tool_calls");

        let mut st = sse_state();
        let cut = translate_event(
            &json!({"type": "response.incomplete", "response": {}}),
            &mut st,
        )
        .expect("a final chunk");
        assert_eq!(cut["choices"][0]["finish_reason"], "length");
    }

    /// A failed upstream response must surface as an error frame, not as a
    /// silently empty successful stream.
    #[test]
    fn a_failed_response_becomes_an_error_frame() {
        let mut st = sse_state();
        let err = translate_event(
            &json!({
                "type": "response.failed",
                "response": {"error": {"message": "model overloaded"}}
            }),
            &mut st,
        )
        .expect("an error frame");
        assert_eq!(err["error"]["type"], "upstream_error");
        assert_eq!(err["error"]["code"], "response_failed");
        assert_eq!(err["error"]["message"], "model overloaded");

        // No message at all still produces a usable frame.
        let bare = translate_event(&json!({"type": "response.failed", "response": {}}), &mut st)
            .expect("an error frame");
        assert!(!bare["error"]["message"].as_str().unwrap_or("").is_empty());

        // Unknown/uninteresting events produce nothing.
        assert!(translate_event(&json!({"type": "response.created"}), &mut st).is_none());
    }
}
