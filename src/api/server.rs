//! `[server]` settings: read and update from the dashboard.
//!
//! `GET  /api/server`        current values (secrets are reported as "is set", never returned)
//! `POST /api/server/update` partial update; validates, writes, hot-reloads
//!
//! Some values cannot take effect without a restart (the listener, the body-limit
//! layer, the dashboard route table and the state file are all fixed at startup).
//! Those are written to the config file and reported back in `restart_required`
//! instead of being silently ignored.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use super::persist::write_validated;
use super::{ApiError, ApiResult, ok_json};
use crate::proxy::AppState;

#[derive(Serialize)]
pub struct ServerDto {
    listen: String,
    max_retries: usize,
    attempt_timeout_secs: u64,
    max_body_bytes: usize,
    events_history: usize,
    requests_history: usize,
    models_refresh_secs: u64,
    dashboard: bool,
    proxy: Option<String>,
    state_file: String,
    /// Secrets are never sent to the browser — only whether they are configured.
    api_key_set: bool,
    admin_key_set: bool,
    /// Public base URL for OAuth redirects (empty = loopback only).
    public_url: Option<String>,
    /// In-process TLS (both set, or neither).
    tls_cert: Option<String>,
    tls_key: Option<String>,
    log_format: String,
    client_key_max_concurrent: u32,
    auth_fail_burst: u32,
    auth_fail_window_secs: u64,
    /// Every configurable timing/limit (see `config::Tuning`).
    tuning: crate::config::Tuning,
}

#[derive(Deserialize)]
pub struct ServerUpdate {
    listen: Option<String>,
    max_retries: Option<usize>,
    attempt_timeout_secs: Option<u64>,
    max_body_bytes: Option<usize>,
    events_history: Option<usize>,
    requests_history: Option<usize>,
    models_refresh_secs: Option<u64>,
    dashboard: Option<bool>,
    /// Empty string clears the proxy.
    proxy: Option<String>,
    /// `None` = leave unchanged, `Some("")` = clear, `Some(x)` = set.
    api_key: Option<String>,
    admin_key: Option<String>,
    state_file: Option<String>,
    /// Empty string clears it (back to the loopback OAuth flow).
    public_url: Option<String>,
    /// Empty strings clear TLS (back to plain HTTP). Needs a restart.
    tls_cert: Option<String>,
    tls_key: Option<String>,
    log_format: Option<String>,
    client_key_max_concurrent: Option<u32>,
    auth_fail_burst: Option<u32>,
    auth_fail_window_secs: Option<u64>,
    /// Partial update of `[tuning]`; omitted fields keep their value.
    tuning: Option<TuningUpdate>,
}

#[derive(Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct TuningUpdate {
    max_cooldown_secs: Option<u64>,
    base_backoff_secs: Option<u64>,
    rate_limit_cooldown_secs: Option<u64>,
    drain_fallback_secs: Option<u64>,
    models_cache_ttl_secs: Option<u64>,
    connect_timeout_secs: Option<u64>,
    meta_timeout_secs: Option<u64>,
    sticky_ttl_secs: Option<u64>,
    sticky_max_entries: Option<usize>,
    session_prefix_bytes: Option<usize>,
    event_channel_capacity: Option<usize>,
    persist_interval_secs: Option<u64>,
    oauth_http_timeout_secs: Option<u64>,
    token_refresh_window_secs: Option<u64>,
    ui_refresh_secs: Option<u64>,
    sse_keepalive_secs: Option<u64>,
    quota_cache_ttl_secs: Option<u64>,
    response_store_max: Option<usize>,
}

/// Fields that only take effect after a restart, because they are baked into the
/// router/listener/allocator path at startup.
const RESTART_ONLY: &[&str] = &[
    "listen",
    "max_body_bytes",
    "dashboard",
    "state_file",
    "tls_cert",
    "tls_key",
    "log_format",
];

pub async fn get_server(State(state): State<Arc<AppState>>) -> ApiResult {
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return Err(ApiError::not_found(format!("cannot read config: {e}")));
        }
    };
    let cfg: crate::config::Config = match toml::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            return Err(ApiError::bad_request(format!("config parse error: {e}")));
        }
    };
    let s = &cfg.server;
    ok_json(ServerDto {
        listen: s.listen.clone(),
        max_retries: s.max_retries,
        attempt_timeout_secs: s.attempt_timeout_secs,
        max_body_bytes: s.max_body_bytes,
        events_history: s.events_history,
        requests_history: s.requests_history,
        models_refresh_secs: s.models_refresh_secs,
        dashboard: s.dashboard,
        proxy: s.proxy.as_deref().map(super::mask_proxy),
        state_file: s.state_file.clone(),
        api_key_set: s.api_key.is_some(),
        admin_key_set: s.admin_key.is_some(),
        public_url: s.public_url.clone(),
        tls_cert: s.tls_cert.clone(),
        tls_key: s.tls_key.clone(),
        log_format: s.log_format.clone(),
        client_key_max_concurrent: s.client_key_max_concurrent,
        auth_fail_burst: s.auth_fail_burst,
        auth_fail_window_secs: s.auth_fail_window_secs,
        tuning: cfg.tuning.clone(),
    })
}

pub async fn update_server(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ServerUpdate>,
) -> ApiResult {
    // Ranges, not just types: a 1s timeout or a 1MB body limit would be accepted by
    // serde but break the gateway in ways that are hard to diagnose later.
    if let Some(n) = body.max_retries
        && !(1..=32).contains(&n)
    {
        return Err(ApiError::bad_request(
            "max_retries must be between 1 and 32",
        ));
    }
    if let Some(t) = body.attempt_timeout_secs
        && !(1..=3600).contains(&t)
    {
        return Err(ApiError::bad_request(
            "attempt_timeout_secs must be between 1 and 3600",
        ));
    }
    if let Some(b) = body.max_body_bytes
        && !(1024..=256 * 1024 * 1024).contains(&b)
    {
        return Err(ApiError::bad_request(
            "max_body_bytes must be between 1024 and 268435456",
        ));
    }
    if let Some(h) = body.events_history
        && h > 100_000
    {
        return Err(ApiError::bad_request("events_history must be <= 100000"));
    }
    if let Some(h) = body.requests_history
        && h > 100_000
    {
        return Err(ApiError::bad_request("requests_history must be <= 100000"));
    }
    if let Some(r) = body.models_refresh_secs
        && r > 86_400
    {
        return Err(ApiError::bad_request(
            "models_refresh_secs must be <= 86400",
        ));
    }
    if let Some(l) = body.listen.as_deref()
        && (l.trim().is_empty() || !l.contains(':'))
    {
        return Err(ApiError::bad_request("listen must look like host:port"));
    }
    for (name, secret) in [("api_key", &body.api_key), ("admin_key", &body.admin_key)] {
        if let Some(s) = secret
            && !s.is_empty()
            && s.trim().len() < 8
        {
            return Err(ApiError::bad_request(format!(
                "{name} must be at least 8 characters (or empty to disable auth)"
            )));
        }
    }

    let _guard = state.config_lock.lock().await;
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => {
            return Err(ApiError::not_found(format!("cannot read config: {e}")));
        }
    };
    let mut doc = match raw.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return Err(ApiError::bad_request(format!("config parse error: {e}")));
        }
    };
    // Current values: the dashboard posts every field, so "changed" must mean
    // "actually different", otherwise a no-op save would claim a restart is due.
    let current: crate::config::Config = match toml::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            return Err(ApiError::bad_request(format!("config parse error: {e}")));
        }
    };
    let cur = &current.server;
    let cur_tuning = &current.tuning;

    if !doc.contains_key("server") {
        doc["server"] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    let Some(server) = doc["server"].as_table_mut() else {
        return Err(ApiError::unprocessable("'server' is not a table"));
    };

    let mut changed: Vec<&'static str> = Vec::new();
    if let Some(v) = &body.listen
        && v.trim() != cur.listen
    {
        server["listen"] = toml_edit::value(v.trim());
        changed.push("listen");
    }
    if let Some(v) = body.max_retries
        && v != cur.max_retries
    {
        server["max_retries"] = toml_edit::value(v as i64);
        changed.push("max_retries");
    }
    if let Some(v) = body.attempt_timeout_secs
        && v != cur.attempt_timeout_secs
    {
        server["attempt_timeout_secs"] = toml_edit::value(v as i64);
        changed.push("attempt_timeout_secs");
    }
    if let Some(v) = body.max_body_bytes
        && v != cur.max_body_bytes
    {
        server["max_body_bytes"] = toml_edit::value(v as i64);
        changed.push("max_body_bytes");
    }
    if let Some(v) = body.events_history
        && v != cur.events_history
    {
        server["events_history"] = toml_edit::value(v as i64);
        changed.push("events_history");
    }
    if let Some(v) = body.requests_history
        && v != cur.requests_history
    {
        server["requests_history"] = toml_edit::value(v as i64);
        changed.push("requests_history");
    }
    if let Some(v) = body.models_refresh_secs
        && v != cur.models_refresh_secs
    {
        server["models_refresh_secs"] = toml_edit::value(v as i64);
        changed.push("models_refresh_secs");
    }
    if let Some(v) = body.dashboard
        && v != cur.dashboard
    {
        server["dashboard"] = toml_edit::value(v);
        changed.push("dashboard");
    }
    if let Some(v) = body.state_file.as_deref()
        && v.trim() != cur.state_file
    {
        server["state_file"] = toml_edit::value(v.trim());
        changed.push("state_file");
    }
    if let Some(v) = &body.log_format {
        let v = v.trim();
        if v != cur.log_format {
            if !matches!(v, "text" | "json") {
                return Err(ApiError::bad_request("log_format must be text or json"));
            }
            server["log_format"] = toml_edit::value(v);
            changed.push("log_format");
        }
    }
    if let Some(v) = body.client_key_max_concurrent
        && v != cur.client_key_max_concurrent
    {
        if v > 10_000 {
            return Err(ApiError::bad_request(
                "client_key_max_concurrent must be <= 10000",
            ));
        }
        server["client_key_max_concurrent"] = toml_edit::value(v as i64);
        changed.push("client_key_max_concurrent");
    }
    if let Some(v) = body.auth_fail_burst
        && v != cur.auth_fail_burst
    {
        if !(1..=10_000).contains(&v) {
            return Err(ApiError::bad_request("auth_fail_burst must be 1..10000"));
        }
        server["auth_fail_burst"] = toml_edit::value(v as i64);
        changed.push("auth_fail_burst");
    }
    if let Some(v) = body.auth_fail_window_secs
        && v != cur.auth_fail_window_secs
    {
        if !(1..=3600).contains(&v) {
            return Err(ApiError::bad_request(
                "auth_fail_window_secs must be 1..3600",
            ));
        }
        server["auth_fail_window_secs"] = toml_edit::value(v as i64);
        changed.push("auth_fail_window_secs");
    }
    for (key, value, current) in [
        (
            "tls_cert",
            body.tls_cert.as_deref(),
            cur.tls_cert.as_deref(),
        ),
        ("tls_key", body.tls_key.as_deref(), cur.tls_key.as_deref()),
    ] {
        let Some(v) = value else { continue };
        let v = v.trim();
        if v == current.unwrap_or("") {
            continue;
        }
        if v.is_empty() {
            server.remove(key);
        } else {
            server[key] = toml_edit::value(v);
        }
        changed.push(if key == "tls_cert" {
            "tls_cert"
        } else {
            "tls_key"
        });
    }
    if let Some(v) = &body.public_url {
        let v = v.trim().trim_end_matches('/');
        if v != cur.public_url.as_deref().unwrap_or("") {
            if v.is_empty() {
                server.remove("public_url");
                changed.push("public_url");
            } else if !v.starts_with("http://") && !v.starts_with("https://") {
                return Err(ApiError::bad_request(
                    "public_url must start with http:// or https://",
                ));
            } else {
                server["public_url"] = toml_edit::value(v);
                changed.push("public_url");
            }
        }
    }
    if let Some(v) = &body.proxy
        // The form sends the masked value back unchanged; writing it would
        // destroy the real credentials.
        && !super::is_masked(v)
        && cur.proxy.as_deref() != Some(v.trim()).filter(|s| !s.is_empty())
    {
        let v = v.trim();
        if v.is_empty() {
            server.remove("proxy");
        } else {
            server["proxy"] = toml_edit::value(v);
        }
        changed.push("proxy");
    }
    for (name, incoming, current_set) in [
        ("api_key", &body.api_key, cur.api_key.is_some()),
        ("admin_key", &body.admin_key, cur.admin_key.is_some()),
    ] {
        let Some(v) = incoming else { continue };
        let v = v.trim();
        // Compare against "is set" only: the current secret is never sent to the
        // browser, so an identical value still looks like a change — but a secret
        // resend is harmless, and an empty field means "leave it alone".
        if v.is_empty() || current_set {
            if v.is_empty() && current_set {
                server.remove(name);
                changed.push(if name == "api_key" {
                    "api_key"
                } else {
                    "admin_key"
                });
            }
            continue;
        }
        server[name] = toml_edit::value(v);
        changed.push(if name == "api_key" {
            "api_key"
        } else {
            "admin_key"
        });
    }

    // `[tuning]`: every field is optional and only written when it really differs.
    if let Some(t) = &body.tuning {
        let mut table = toml_edit::Table::new();
        table.set_implicit(false);
        let mut put = |key: &'static str, value: i64| {
            table[key] = toml_edit::value(value);
            changed.push(key);
        };
        macro_rules! sync_num {
            ($field:ident, $key:literal) => {
                if let Some(v) = t.$field
                    && v != cur_tuning.$field
                {
                    put($key, v as i64);
                }
            };
        }
        sync_num!(max_cooldown_secs, "max_cooldown_secs");
        sync_num!(base_backoff_secs, "base_backoff_secs");
        sync_num!(rate_limit_cooldown_secs, "rate_limit_cooldown_secs");
        sync_num!(drain_fallback_secs, "drain_fallback_secs");
        sync_num!(models_cache_ttl_secs, "models_cache_ttl_secs");
        sync_num!(connect_timeout_secs, "connect_timeout_secs");
        sync_num!(meta_timeout_secs, "meta_timeout_secs");
        sync_num!(sticky_ttl_secs, "sticky_ttl_secs");
        sync_num!(sticky_max_entries, "sticky_max_entries");
        sync_num!(session_prefix_bytes, "session_prefix_bytes");
        sync_num!(event_channel_capacity, "event_channel_capacity");
        sync_num!(persist_interval_secs, "persist_interval_secs");
        sync_num!(oauth_http_timeout_secs, "oauth_http_timeout_secs");
        sync_num!(token_refresh_window_secs, "token_refresh_window_secs");
        sync_num!(ui_refresh_secs, "ui_refresh_secs");
        sync_num!(sse_keepalive_secs, "sse_keepalive_secs");
        sync_num!(quota_cache_ttl_secs, "quota_cache_ttl_secs");
        sync_num!(response_store_max, "response_store_max");
        if !table.is_empty() {
            // Merge into the existing table so comments and untouched keys survive.
            let existing = doc.get_mut("tuning");
            match existing.map(|i| i.as_table_mut()) {
                Some(Some(tbl)) => {
                    for (k, v) in table.iter() {
                        tbl[k] = v.clone();
                    }
                }
                _ => {
                    doc["tuning"] = toml_edit::Item::Table(table);
                }
            }
        }
    }

    if changed.is_empty() {
        return ok_json(serde_json::json!({"changed": [], "restart_required": []}));
    }
    // The file is validated as a whole by write_validated(), which also runs the
    // Tuning range checks — an out-of-range number never reaches the disk.
    if let Err(resp) = write_validated(&state, &doc).await {
        return Ok(*resp);
    }
    state.events.emit_simple(
        "config",
        "",
        "backoff",
        format!("server settings updated: {}", changed.join(", ")),
    );
    let restart: Vec<&str> = changed
        .iter()
        .copied()
        .filter(|c| RESTART_ONLY.contains(c))
        .collect();
    ok_json(serde_json::json!({"changed": changed, "restart_required": restart}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_only_fields_are_the_startup_baked_ones() {
        // Guard against silently moving a hot field into the restart list (or vice
        // versa): these four are applied when the router/listener are built.
        for f in ["listen", "max_body_bytes", "dashboard", "state_file"] {
            assert!(RESTART_ONLY.contains(&f), "{f} must be restart-only");
        }
        for f in ["max_retries", "api_key", "proxy", "models_refresh_secs"] {
            assert!(!RESTART_ONLY.contains(&f), "{f} must apply on reload");
        }
    }
}
