//! Shared helpers: networking, formatting, clipboard, theme, collapse state.

use gloo_net::http::Request;
use serde::Deserialize;
use sycamore::prelude::*;

use crate::types::{ClientKeyDto, ModelItemDto};

/// Copy `text`, reporting whether it actually landed in the clipboard.
///
/// The old version fired `navigator.clipboard.write_text` and discarded the
/// promise, so every call site printed "Copied!" even when the write was rejected —
/// which is the normal outcome on a plain-HTTP LAN origin (the Clipboard API needs a
/// secure context). The operator then dismissed the "API key created" banner and the
/// key was gone.
pub async fn copy_to_clipboard(text: &str) -> bool {
    let Some(w) = web_sys::window() else {
        return false;
    };
    // The Clipboard API needs a secure context: on a plain-HTTP LAN origin this
    // promise rejects, and the caller must then say "copy failed" instead of
    // claiming success (the key is still on screen to be selected by hand).
    wasm_bindgen_futures::JsFuture::from(w.navigator().clipboard().write_text(text))
        .await
        .is_ok()
}

/// `HH:MM:SS` in the *browser's* local time. The old version did `ts % 86400`,
/// i.e. printed UTC while the user reads it as local time (off by the TZ offset),
/// and had no date component at all. `js_sys::Date` does the TZ math for us.
/// `sk-hop-…wxyz` — the same shape the server's DTO uses, for confirm dialogs.
pub fn mask_key(k: &str) -> String {
    let n = k.chars().count();
    if n <= 8 {
        return "***".to_string();
    }
    let head: String = k.chars().take(7).collect();
    let tail: String = k.chars().skip(n - 4).collect();
    format!("{head}...{tail}")
}

pub fn fmt_time(ts: u64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64((ts * 1000) as f64));
    format!(
        "{:02}:{:02}:{:02}",
        d.get_hours(),
        d.get_minutes(),
        d.get_seconds()
    )
}

/// `MM-DD HH:MM` in local time — for values that can be days old (key creation
/// dates), where a bare clock time would be ambiguous.
pub fn fmt_datetime(ts: u64) -> String {
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64((ts * 1000) as f64));
    format!(
        "{:02}-{:02} {:02}:{:02}",
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes()
    )
}

pub fn fmt_num(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

pub fn stored_key() -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()??
        .get_item("anyhop_admin_key")
        .ok()??
        .into()
}

/// 401 from the API → admin key required.
pub static NEED_AUTH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub async fn fetch_json<T: for<'de> Deserialize<'de>>(url: &str) -> Option<T> {
    let mut req = Request::get(url);
    if let Some(k) = stored_key() {
        req = req.header("Authorization", &format!("Bearer {k}"));
    }
    let resp = req.send().await.ok()?;
    if resp.status() == 401 {
        NEED_AUTH.store(true, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    resp.json::<T>().await.ok()
}

/// POST and report success (2xx). Sets NEED_AUTH on 401 like the other helpers.
pub async fn post_json<B: serde::Serialize>(url: &str, body: &B) -> bool {
    let Ok(req) = Request::post(url).json(body) else {
        return false;
    };
    if let Some(k) = stored_key() {
        req.headers().set("Authorization", &format!("Bearer {k}"));
    }
    match req.send().await {
        Ok(resp) => {
            if resp.status() == 401 {
                NEED_AUTH.store(true, std::sync::atomic::Ordering::Relaxed);
                return false;
            }
            (200..300).contains(&resp.status())
        }
        Err(_) => false,
    }
}

/// POST and return the parsed body, or the server's error message.
///
/// The status *must* be checked: `ApiError` responses are JSON, so `resp.json()`
/// parsed a 400/409/500 into the same type and the caller treated a rejected write
/// as a success (the Settings save printed "saved" and then blanked the admin key the
/// operator had just typed; a rejected combo save closed the editor).
pub async fn post_json_result<B: serde::Serialize, R: for<'de> Deserialize<'de>>(
    url: &str,
    body: &B,
) -> Result<R, String> {
    let req = Request::post(url).json(body).map_err(|e| e.to_string())?;
    if let Some(k) = stored_key() {
        req.headers().set("Authorization", &format!("Bearer {k}"));
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if status == 401 {
        NEED_AUTH.store(true, std::sync::atomic::Ordering::Relaxed);
        return Err("admin key required".to_string());
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        // The body is our own JSON error envelope; fall back to the status when it
        // is not (an empty 404, a proxy page).
        let msg = error_message(&text);
        return Err(if msg.trim().is_empty() {
            format!("request failed (HTTP {status})")
        } else {
            msg
        });
    }
    serde_json::from_str::<R>(&text).map_err(|e| format!("unexpected response: {e}"))
}

/// Backwards-compatible wrapper: `Some` only for a 2xx with a parsable body.
pub async fn post_json_resp<B: serde::Serialize, R: for<'de> Deserialize<'de>>(
    url: &str,
    body: &B,
) -> Option<R> {
    post_json_result(url, body).await.ok()
}

pub fn defer(f: impl FnOnce() + 'static) {
    // Must be a macrotask: spawn_local polls the future synchronously until the
    // first await, which defers nothing and triggers BorrowMutError.
    gloo_timers::callback::Timeout::new(0, f).forget();
}

pub fn current_theme() -> String {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
        .and_then(|e| e.get_attribute("data-theme"))
        .unwrap_or_else(|| "light".into())
}

pub fn set_theme(t: &str) {
    if let Some(w) = web_sys::window() {
        if let Some(e) = w.document().and_then(|d| d.document_element()) {
            let _ = e.set_attribute("data-theme", t);
        }
        if let Ok(Some(s)) = w.local_storage() {
            let _ = s.set_item("theme", t);
        }
    }
}

pub async fn fetch_text(url: &str) -> Option<String> {
    let mut req = Request::get(url);
    if let Some(k) = stored_key() {
        req = req.header("Authorization", &format!("Bearer {k}"));
    }
    let resp = req.send().await.ok()?;
    if resp.status() == 401 {
        NEED_AUTH.store(true, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    // Never load an error body (e.g. into the config editor) as if it were data.
    if resp.status() != 200 {
        return None;
    }
    resp.text().await.ok()
}

/// Extract `error.message` from an API error envelope; fall back to the raw body.
pub fn error_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.to_string())
}

pub async fn put_json<B: serde::Serialize>(url: &str, body: &B) -> Option<String> {
    let req = Request::put(url).json(body).ok()?;
    if let Some(k) = stored_key() {
        req.headers().set("Authorization", &format!("Bearer {k}"));
    }
    let resp = req.send().await.ok()?;
    let ok = resp.status() == 200;
    let text = resp.text().await.ok()?;
    Some(if ok {
        "saved + reloaded".into()
    } else {
        // Show the human message, not the raw JSON envelope.
        error_message(&text)
    })
}

/// Re-fetch the models list into the signal (after enable/disable/refresh actions).
pub async fn reload_models(models: Signal<Vec<ModelItemDto>>) {
    if let Some(d) = fetch_json::<Vec<ModelItemDto>>("/api/models").await {
        models.set(d);
    }
}

/// Re-fetch the client key list into the signal (after add/update/delete actions).
pub async fn reload_client_keys(keys: Signal<Vec<ClientKeyDto>>) {
    if let Some(d) = fetch_json::<Vec<ClientKeyDto>>("/api/client-keys").await {
        keys.set(d);
    }
}
