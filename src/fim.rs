//! Fill-in-the-middle endpoint: an IDE-friendly autocomplete API.
//!
//! POST /v1/fim/completions {model, prompt, suffix?, max_tokens?}
//! → legacy-completions-style {"choices": [{"text": ...}]}
//!
//! Two modes, chosen by what the provider actually speaks:
//!
//! * **native** — an `openai_compat` provider is forwarded to its own
//!   `/completions` with `prompt`/`suffix` untouched. That is the endpoint FIM
//!   models are trained for (vLLM/SGLang/Together/llama.cpp accept `suffix`, and
//!   code models take their `<|fim_prefix|>…<|fim_suffix|>…<|fim_middle|>` tokens
//!   verbatim in `prompt`). Nothing is rewritten, so the model keeps its native
//!   behaviour.
//! * **wrapped** — providers with no completions endpoint (Gemini, Anthropic,
//!   Codex, Antigravity) get the request as a one-shot chat with a `<FILL_HERE>`
//!   marker. Those models have no FIM API to call: Google's `tab_*` completion
//!   models are served through `generateContent`, so a marker is the only way to
//!   ask them, and the answer is post-processed (fences, prefix/suffix echo).

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::config::ProviderKind;
use crate::providers::{Provider, Resolved};
use crate::proxy::AppState;

const FIM_SYSTEM: &str = "You are a code completion engine. \
The user gives you a code file with a <FILL_HERE> marker. \
Output ONLY the code that belongs at the marker position. \
Never repeat surrounding code. No explanations. No markdown fences.";

pub async fn fim_completions(
    State(state): State<Arc<AppState>>,
    key_perm: Option<axum::extract::Extension<crate::proxy::KeyPermissions>>,
    body: Bytes,
) -> Response {
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return crate::proxy::error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON body: {e}"),
                "invalid_request_error",
            );
        }
    };

    let model = req.get("model").and_then(|m| m.as_str()).unwrap_or("");
    let prompt = req.get("prompt").and_then(|p| p.as_str()).unwrap_or("");
    let suffix = req.get("suffix").and_then(|s| s.as_str()).unwrap_or("");
    if model.is_empty() || prompt.is_empty() {
        return crate::proxy::error_response(
            StatusCode::BAD_REQUEST,
            "missing 'model' or 'prompt'",
            "invalid_request_error",
        );
    }

    {
        let dm = state
            .disabled_models
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let bare = model.strip_prefix("combo/").unwrap_or(model);
        if dm.contains(model) || dm.contains(bare) {
            return crate::proxy::error_response(
                StatusCode::NOT_FOUND,
                format!("model '{model}' is disabled"),
                "model_not_found",
            );
        }
    }

    let max_tokens = req
        .get("max_tokens")
        .and_then(|t| t.as_u64())
        .unwrap_or(256);

    let synthetic = json!({
        "model": model,
        "stream": false,
        "temperature": req.get("temperature").cloned().unwrap_or(json!(0.0)),
        "max_tokens": max_tokens,
        // NB: "```" must NOT be a stop sequence — models love to open with a fence,
        // which would yield an empty completion. Fences are stripped post-hoc.
        "stop": ["\n\n\n"],
        "messages": [
            {"role": "system", "content": FIM_SYSTEM},
            {"role": "user", "content": format!("```{}\n{}<FILL_HERE>\n{}\n```",
                req.get("language").and_then(|l| l.as_str()).unwrap_or(""),
                prompt, suffix)},
        ],
    });

    let router = state.router.load();
    let Some(resolved) = router.resolve(model) else {
        return crate::proxy::error_response(
            StatusCode::NOT_FOUND,
            format!("no provider serves model '{model}'"),
            "model_not_found",
        );
    };

    let key_models = key_perm.as_ref().and_then(|e| e.0.allowed_models.as_ref());

    // FIM is single-shot: one provider target, full key retry loop.
    let (provider, upstream_model) = match &resolved {
        Resolved::One(p, m) => {
            let canonical = format!("{}/{}", p.name, m);
            if crate::proxy::model_disabled(
                &state
                    .disabled_models
                    .read()
                    .unwrap_or_else(|e| e.into_inner()),
                model,
                &canonical,
                m,
            ) {
                return crate::proxy::error_response(
                    StatusCode::NOT_FOUND,
                    format!("model '{model}' is disabled"),
                    "model_not_found",
                );
            }
            if let Some(allowed) = key_models
                && !crate::proxy::model_allowed(allowed, model, &canonical, m)
            {
                return crate::proxy::error_response(
                    StatusCode::FORBIDDEN,
                    format!("model '{model}' is not allowed for this API key"),
                    "model_not_allowed",
                );
            }
            (*p, m.clone())
        }
        Resolved::Chain(chain) => {
            if let Some(allowed) = key_models
                && !crate::proxy::combo_allowed(allowed, model)
            {
                return crate::proxy::error_response(
                    StatusCode::FORBIDDEN,
                    format!("model '{model}' is not allowed for this API key"),
                    "model_not_allowed",
                );
            }
            let active = {
                // one read guard for the whole scan, not per entry
                let disabled = state
                    .disabled_models
                    .read()
                    .unwrap_or_else(|e| e.into_inner());
                chain.iter().find(|(p, m)| {
                    !disabled.contains(&format!("{}/{}", p.name, m))
                        && !disabled.contains(m.as_str())
                })
            };
            match active {
                Some((p, m)) => (*p, m.clone()),
                None => {
                    return crate::proxy::error_response(
                        StatusCode::NOT_FOUND,
                        format!("all targets in combo '{model}' are disabled"),
                        "model_not_found",
                    );
                }
            }
        }
    };

    // Native first: an OpenAI-compatible provider has a real `/completions`, so the
    // prompt (with whatever FIM tokens the client sent) and the suffix go through
    // untouched. Only a provider without that endpoint falls back to the marker.
    if matches!(provider.kind, ProviderKind::OpenaiCompat)
        && !provider
            .no_completions
            .load(std::sync::atomic::Ordering::Relaxed)
    {
        match native_completions(provider, &upstream_model, &req).await {
            Native::Answer(resp) => return resp,
            Native::NoEndpoint => {
                // Remember it: the wrapper is now this provider's FIM path, and an
                // autocomplete call must not spend a round trip discovering that
                // again on every request.
                provider
                    .no_completions
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!(
                    provider = %provider.name,
                    "no /completions endpoint upstream; wrapping FIM as a chat request"
                );
            }
            Native::Unavailable(msg) => {
                return crate::proxy::error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    msg,
                    "provider_unavailable",
                );
            }
        }
    }

    let resp =
        crate::proxy::run_target_pub(&state, provider, &upstream_model, &synthetic, false).await;
    let Some(resp) = resp else {
        return crate::proxy::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("provider '{}' unavailable", provider.name),
            "provider_unavailable",
        );
    };

    let status = resp.status();
    let bytes = match axum::body::to_bytes(resp.into_body(), 1 << 20).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if !status.is_success() {
        return Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let Ok(chat) = serde_json::from_slice::<Value>(&bytes) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let raw = chat
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("");
    let text = trim_prefix_overlap(&trim_suffix_overlap(&strip_fences(raw), suffix), prompt);
    let finish = chat
        .pointer("/choices/0/finish_reason")
        .and_then(|f| f.as_str())
        .unwrap_or("stop");

    Json(json!({
        "id": chat.get("id").cloned().unwrap_or(json!("fcmpl-anyhop")),
        "object": "text_completion",
        "created": chat.get("created").cloned().unwrap_or(json!(0)),
        "model": model,
        "choices": [{"index": 0, "text": text, "finish_reason": finish}],
        "usage": chat.get("usage").cloned().unwrap_or(json!({})),
    }))
    .into_response()
}

/// Outcome of the native attempt.
enum Native {
    /// The provider answered; hand its body straight back.
    Answer(Response),
    /// The provider has no `/completions` (404/405 or a 400 that says so).
    NoEndpoint,
    /// No key could be used at all.
    Unavailable(String),
}

/// Forward `prompt`/`suffix` to the provider's own `/completions`.
///
/// Deliberately minimal: this path exists so FIM models see their native request
/// shape, so it copies the fields a completions endpoint understands and nothing
/// else. Key rotation follows the pool: a 429/5xx cools the key down and the next
/// attempt takes the next key, exactly like the chat path.
async fn native_completions(provider: &Provider, model: &str, req: &Value) -> Native {
    let mut body = serde_json::Map::new();
    body.insert("model".into(), json!(model));
    body.insert(
        "prompt".into(),
        req.get("prompt").cloned().unwrap_or(json!("")),
    );
    if let Some(suffix) = req.get("suffix") {
        body.insert("suffix".into(), suffix.clone());
    }
    body.insert(
        "max_tokens".into(),
        req.get("max_tokens").cloned().unwrap_or(json!(256)),
    );
    body.insert(
        "temperature".into(),
        req.get("temperature").cloned().unwrap_or(json!(0.0)),
    );
    for key in [
        "stop",
        "top_p",
        "presence_penalty",
        "frequency_penalty",
        "seed",
        "n",
    ] {
        if let Some(v) = req.get(key) {
            body.insert(key.into(), v.clone());
        }
    }
    body.insert("stream".into(), json!(false));

    let url = format!("{}/completions", provider.base_url.trim_end_matches('/'));
    let attempts = provider.max_retries.clamp(1, 4);
    for _ in 0..attempts {
        let Some(key) = provider.pool.pick_ready(model, None) else {
            return Native::Unavailable(format!("provider '{}' unavailable", provider.name));
        };
        let mut request = provider
            .client
            .post(&url)
            .bearer_auth(&key.secret)
            .header("content-type", "application/json")
            .json(&serde_json::Value::Object(body.clone()))
            .timeout(provider.timeout);
        for (k, v) in &provider.extra_headers {
            request = request.header(k, v);
        }
        match request.send().await {
            Ok(resp) if resp.status().is_success() => {
                provider.pool.report_success(&key);
                // Pass the upstream body through untouched: whatever the model
                // wrote IS the completion in this mode.
                let status = resp.status();
                let bytes = resp.bytes().await.unwrap_or_default();
                return Native::Answer(
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(bytes))
                        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()),
                );
            }
            Ok(resp) if matches!(resp.status().as_u16(), 404 | 405) => {
                // Not an error of the provider's pool: this API simply has no
                // completions endpoint. Leave the key healthy and fall back.
                provider.pool.report_success(&key);
                return Native::NoEndpoint;
            }
            Ok(resp) => {
                let status = resp.status();
                let retry_hdr = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let text = resp.text().await.unwrap_or_default();
                // A 400 whose body says the endpoint/`suffix` is unsupported is the
                // same signal as a 404: fall back instead of failing the request.
                if status == StatusCode::BAD_REQUEST
                    && (text.contains("suffix")
                        || text.contains("Unsupported")
                        || text.contains("unknown"))
                {
                    provider.pool.report_success(&key);
                    return Native::NoEndpoint;
                }
                if status == StatusCode::TOO_MANY_REQUESTS {
                    let retry = retry_hdr
                        .as_deref()
                        .and_then(crate::proxy::parse_retry_after);
                    provider.pool.report_failure(
                        &key,
                        crate::pool::FailKind::RateLimited {
                            retry_after_secs: retry,
                        },
                        model,
                    );
                    continue;
                }
                if status.is_server_error() {
                    provider
                        .pool
                        .report_failure(&key, crate::pool::FailKind::Server, model);
                    continue;
                }
                // 4xx that is about the *request*: hand it to the caller as-is.
                provider.pool.report_success(&key);
                return Native::Answer(
                    Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(text))
                        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()),
                );
            }
            Err(e) => {
                tracing::debug!(provider = %provider.name, "native completions failed: {e}");
                provider
                    .pool
                    .report_failure(&key, crate::pool::FailKind::Network, model);
            }
        }
    }
    Native::Unavailable(format!(
        "provider '{}' unavailable (native completions)",
        provider.name
    ))
}

/// Cut the head where the completion repeats the end of the prefix.
/// Only overlaps >= 12 chars are trimmed — shorter matches are too ambiguous
/// (indentation, brackets) to safely treat as an echo.
fn trim_prefix_overlap(text: &str, prefix: &str) -> String {
    let pre = prefix.trim_end_matches('\n');
    if pre.is_empty() {
        return text.to_string();
    }
    let max = pre.len().min(text.len());
    // skip offsets that split a multi-byte char — slicing there panics
    for k in (12..=max)
        .rev()
        .filter(|&k| pre.is_char_boundary(pre.len() - k))
    {
        if text.starts_with(&pre[pre.len() - k..]) {
            return text[k..].trim_start_matches('\n').to_string();
        }
    }
    text.to_string()
}

/// Cut the tail where the completion starts echoing the suffix.
///
/// Two passes, because models echo in two shapes:
///
/// * the completion simply continues into the suffix text (exact tail match);
/// * the completion ends *inside* the suffix with a stray quote or bracket first
///   (`const data = await res.json();"` before `\n  return data;`), which the exact
///   tail match misses by one character. The second pass therefore also cuts at the
///   last occurrence of the suffix's first non-empty line, when it is long enough to
///   be an echo rather than a coincidence.
fn trim_suffix_overlap(text: &str, suffix: &str) -> String {
    let suf = suffix.trim_start_matches('\n');
    if suf.is_empty() {
        return text.to_string();
    }
    if let Some(trimmed) = trim_exact_tail(text, suf) {
        return trimmed;
    }
    trim_echoed_first_line(text, suf)
}

/// Exact tail match: the completion ends with a prefix of the suffix.
fn trim_exact_tail(text: &str, suf: &str) -> Option<String> {
    let max = suf.len().min(text.len());
    // >= 4 chars: a 1-2 char "echo" ("}", ");") is usually the completion's
    // own closing brace — trimming it would corrupt the completion.
    // Also skip offsets that split a multi-byte char (slicing there panics).
    for k in (4..=max).rev().filter(|&k| suf.is_char_boundary(k)) {
        if text.ends_with(&suf[..k]) {
            return Some(text[..text.len() - k].trim_end_matches('\n').to_string());
        }
    }
    None
}

/// Second pass: the completion repeats the suffix's first line somewhere near its
/// end, possibly after a stray quote/paren.
fn trim_echoed_first_line(text: &str, suf: &str) -> String {
    // The line the model would start echoing.
    let first = suf
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    // Short lines ("}", "return") appear in any completion; only a distinctive one
    // can be treated as an echo.
    if first.chars().count() < 8 {
        return text.to_string();
    }
    // Only look at the tail: an echo of the following code cannot appear earlier.
    let window_start = text.len().saturating_sub(first.len() + 120);
    let window_start = (0..=window_start)
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0);
    let Some(pos) = text[window_start..].rfind(first) else {
        return text.to_string();
    };
    let cut = window_start + pos;
    let head = text[..cut].trim_end();
    // Drop the stray quote/bracket the model opened right before echoing: it is
    // part of the echo, not of the completion.
    let head = head
        .trim_end_matches(['"', '\'', '`', ')', ']', '}'])
        .trim_end();
    if head.is_empty() {
        return text.to_string();
    }
    head.to_string()
}

/// Remove a markdown fence wrapper if the model added one despite instructions.
fn strip_fences(s: &str) -> String {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        // drop the language tag line
        let rest = match rest.find('\n') {
            Some(i) => &rest[i + 1..],
            None => rest,
        };
        let rest = rest.strip_suffix("```").unwrap_or(rest);
        return rest.trim_end_matches('\n').to_string();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Native FIM: an OpenAI-compatible provider gets the client's prompt (with
    /// whatever FIM tokens it carries), the suffix and the caps verbatim — the
    /// model keeps its native request shape instead of being wrapped into a chat.
    #[tokio::test]
    async fn native_completions_forwards_prompt_and_suffix_untouched() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let _ = tx.send(body);
            let reply = r#"{"id":"cmpl-1","object":"text_completion","choices":[{"index":0,"text":"42","finish_reason":"stop"}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                reply.len(),
                reply
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });

        let cfg: crate::config::ProviderConfig = toml::from_str(&format!(
            r#"
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:{}/v1"
            keys = ["sk-1"]
            "#,
            addr.port()
        ))
        .expect("provider config");
        let provider = crate::providers::Provider::from_config(
            &cfg,
            None,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
            std::time::Duration::from_secs(5),
            1,
        )
        .expect("provider builds offline");

        let prompt =
            "<|fim_prefix|>def add(a, b):\n    return<|fim_suffix|>\nprint(1)<|fim_middle|>";
        let req = json!({
            "model": "deepseek-coder",
            "prompt": prompt,
            "suffix": "\nprint(1)",
            "max_tokens": 32,
            "temperature": 0.1,
        });
        let native = native_completions(&provider, "deepseek-coder", &req).await;
        let Native::Answer(resp) = native else {
            panic!("the provider has a /completions; it must be used");
        };
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let out: Value = serde_json::from_slice(&bytes).expect("json");
        // The body is the provider's, untouched — no marker rewriting, no trimming.
        assert_eq!(out["choices"][0]["text"], "42");

        let sent: Value = serde_json::from_str(&rx.await.expect("recorded body")).expect("json");
        assert_eq!(
            sent["prompt"], prompt,
            "prompt must reach the model verbatim"
        );
        assert_eq!(sent["suffix"], "\nprint(1)");
        assert_eq!(sent["max_tokens"], 32);
        assert_eq!(sent["model"], "deepseek-coder");
    }

    /// A provider without a completions endpoint says 404: the caller falls back to
    /// the marker instead of failing.
    #[tokio::test]
    async fn a_missing_completions_endpoint_falls_back() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            let _ = sock.flush().await;
        });
        let cfg: crate::config::ProviderConfig = toml::from_str(&format!(
            r#"
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:{}/v1"
            keys = ["sk-1"]
            "#,
            addr.port()
        ))
        .expect("provider config");
        let provider = crate::providers::Provider::from_config(
            &cfg,
            None,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
            std::time::Duration::from_secs(5),
            1,
        )
        .expect("provider builds offline");
        let req = json!({"prompt": "x", "max_tokens": 4});
        assert!(matches!(
            native_completions(&provider, "m", &req).await,
            Native::NoEndpoint
        ));
    }

    #[test]
    fn prefix_overlap_multibyte_match() {
        // deep scan crosses the interior of コメント — would panic on byte slicing
        let prompt = "fn f() {\n    // コメント\n    let x = 1;";
        let text = "    let x = 1;\n    // extra\n}";
        assert_eq!(trim_prefix_overlap(text, prompt), "    // extra\n}");
    }

    #[test]
    fn prefix_overlap_multibyte_no_panic() {
        let prompt = "fn f() {\n    // 日本語のコメント\n    let x";
        let text = "completely different completion, long enough to force a deep scan";
        assert_eq!(trim_prefix_overlap(text, prompt), text);
    }

    #[test]
    fn suffix_overlap_multibyte_no_panic() {
        // ； at bytes 2..5: k=4 would slice inside it without the boundary filter
        let suffix = "xy；z";
        let text = "no match at all in this completion";
        assert_eq!(trim_suffix_overlap(text, suffix), text);
    }

    #[test]
    fn suffix_overlap_multibyte_trim() {
        // a 6-byte multibyte echo (>= the 4-char floor) still trims
        let suffix = "；和\nrest";
        let text = "let x = 1；和";
        assert_eq!(trim_suffix_overlap(text, suffix), "let x = 1");
    }

    /// Real completion from `antigravity/tab_jump_flash_lite_preview`: the model
    /// continued into the next line and left a stray quote before it.
    #[test]
    fn suffix_echo_after_a_stray_quote_is_trimmed() {
        let text = "const data = await res.json();\n\n  return data;\"\n}";
        let suffix = "\n  return data;\n}";
        assert_eq!(
            trim_suffix_overlap(text, suffix),
            "const data = await res.json();"
        );
    }

    /// A genuine line that merely resembles the next one must survive.
    #[test]
    fn a_short_next_line_never_eats_the_completion() {
        let text = "foo() {\n  bar();\n}";
        assert_eq!(trim_suffix_overlap(text, "\n}"), text);
        assert_eq!(trim_suffix_overlap(text, "\n  return;"), text);
    }

    #[test]
    fn suffix_overlap_short_echo_not_trimmed() {
        // regression: cursor right before an outer '}' — the completion's own
        // closing brace must NOT be deleted as a "suffix echo"
        let suffix = "\n}";
        let text = "foo() {\n  bar();\n}";
        assert_eq!(trim_suffix_overlap(text, suffix), text);
    }
}
