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
        let mapped = match effort {
            "none" | "minimal" => "minimal",
            "xhigh" | "max" => "xhigh",
            other => other,
        };
        req["reasoning"] = json!({"effort": mapped, "summary": "auto"});
    }
    if let Some(t) = body.get("temperature") {
        req["temperature"] = t.clone();
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
                "total_tokens": self.prompt_tokens + self.completion_tokens,
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
