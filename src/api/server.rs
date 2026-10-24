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
    /// File *name* only (see [`basename`]): the dashboard needs to know a state
    /// file is configured, not where the operator keeps it.
    state_file: String,
    /// Secrets are never sent to the browser — only whether they are configured.
    api_key_set: bool,
    admin_key_set: bool,
    /// Public base URL for OAuth redirects (empty = loopback only).
    public_url: Option<String>,
    /// In-process TLS (both set, or neither). File names only, like `state_file`.
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
    /// `None`/`""` = leave unchanged, `Some(x)` = rotate to `x`.
    ///
    /// An empty field used to *delete* the key — with the dashboard form (which
    /// posts every field) that silently opened `/api/*`, so clearing is now an
    /// explicit request.
    api_key: Option<String>,
    admin_key: Option<String>,
    /// Remove `admin_key`/`api_key`. Refused when `listen` is not loopback.
    #[serde(default)]
    clear_api_key: bool,
    #[serde(default)]
    clear_admin_key: bool,
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
    client_body_timeout_secs: Option<u64>,
    capacity_wait_ms: Option<u64>,
    shutdown_grace_secs: Option<u64>,
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
        state_file: basename(&s.state_file),
        api_key_set: s.api_key.is_some(),
        admin_key_set: s.admin_key.is_some(),
        public_url: s.public_url.clone(),
        tls_cert: s.tls_cert.as_deref().map(basename),
        tls_key: s.tls_key.as_deref().map(basename),
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
    if let Some(v) = body.state_file.as_deref() {
        let v = v.trim();
        // The dashboard only ever sees the basename, so posting it back must not
        // rewrite the path (that would move the state file on the next start).
        let unchanged = v == cur.state_file || basename(&cur.state_file) == v;
        if !unchanged {
            server["state_file"] = toml_edit::value(v);
            changed.push("state_file");
        }
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
        // Basenames are what `get_server` reports, so a round-tripped value is
        // "unchanged" — writing it would point TLS at a file that does not exist.
        if v == current.unwrap_or("") || current.is_some_and(|c| basename(c) == v) {
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
    // Dropping the last credential makes `/api/*` (raw config editor, provider
    // keys, OAuth flows) and `/v1/*` world-open. That is a deliberate choice for a
    // localhost gateway and never for a listening one.
    if body.clear_api_key || body.clear_admin_key {
        // Check the address the process is *actually* bound to, not the one the
        // request asks for. `listen` is restart-only, so `{clear_api_key: true,
        // listen: "127.0.0.1:8080"}` on a live 0.0.0.0 gateway passed the old
        // check and immediately made an unauthenticated admin API while the socket
        // still listened publicly. Changing the listener and clearing the key in
        // one request is therefore refused outright.
        let requested = body.listen.as_deref().map(str::trim);
        if let Some(requested) = requested
            && requested != cur.listen.as_str()
        {
            return Err(ApiError::bad_request(
                "listen changes take effect on restart: change the listener first, then \
                 (with the gateway on a loopback address) clear the key"
                    .to_string(),
            ));
        }
        if !listen_is_loopback(cur.listen.as_str()) {
            return Err(ApiError::bad_request(format!(
                "refusing to clear a key while listen = '{}' is reachable from the \
                 network: bind a loopback address (127.0.0.1) first, or rotate the key instead",
                cur.listen
            )));
        }
    }
    for (name, clear, clear_field, incoming, current) in [
        (
            "api_key",
            body.clear_api_key,
            "clear_api_key",
            body.api_key.as_deref(),
            cur.api_key.as_deref(),
        ),
        (
            "admin_key",
            body.clear_admin_key,
            "clear_admin_key",
            body.admin_key.as_deref(),
            cur.admin_key.as_deref(),
        ),
    ] {
        let incoming = incoming.map(str::trim).filter(|v| !v.is_empty());
        if clear {
            if incoming.is_some() {
                return Err(ApiError::bad_request(format!(
                    "{name}: send a new value or {clear_field}, not both"
                )));
            }
            if current.is_some() {
                server.remove(name);
                changed.push(name);
            }
            continue;
        }
        // A non-empty value always wins: the dashboard cannot show the current
        // secret (it is never sent to the browser), so *any* value it sends is a
        // new one. Resending the same secret is harmless and reported as a no-op.
        let Some(v) = incoming else { continue };
        if current != Some(v) {
            server[name] = toml_edit::value(v);
            changed.push(name);
        }
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
        sync_num!(client_body_timeout_secs, "client_body_timeout_secs");
        sync_num!(capacity_wait_ms, "capacity_wait_ms");
        sync_num!(shutdown_grace_secs, "shutdown_grace_secs");
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
    if changed
        .iter()
        .any(|c| matches!(*c, "api_key" | "admin_key"))
    {
        warn_if_unauthenticated(&state);
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

/// The last path component of `path` ("", when there is none).
///
/// Paths in `GET /api/server` are reported as basenames: the file *name* tells
/// the operator what is configured, while the full path hands anyone who reaches
/// the endpoint a map of the host (`/home/<user>/…`, `/etc/letsencrypt/…`).
/// `update_server` treats a value equal to the current basename as "unchanged".
fn basename(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

/// Whether `host:port` can only be reached from this machine.
///
/// Used as the gate on "clear the only credential": on a public listener that
/// turns the whole admin API into an unauthenticated one.
fn listen_is_loopback(listen: &str) -> bool {
    let host = listen
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(listen)
        .trim_start_matches('[')
        .trim_end_matches(']');
    host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1" || host.starts_with("127.")
}

/// Loud warning whenever a save leaves the gateway without any credential.
///
/// `lib.rs` warns at startup; this covers the hot path — someone clearing the key
/// from the dashboard must see *why* the next `curl /api/providers` works
/// unauthenticated.
fn warn_if_unauthenticated(state: &Arc<AppState>) {
    let Ok(cfg) = crate::config::Config::load(&state.config_path) else {
        return;
    };
    if cfg.server.api_key.is_none() && cfg.server.admin_key.is_none() {
        tracing::warn!(
            "no api_key/admin_key configured: /v1/* and /api/* (raw config editor, provider \
             keys, OAuth) accept unauthenticated requests — set one unless this port is loopback-only"
        );
    }
}

/// Validate a config document, then write it — no reload.
///
/// For writers that reload themselves (the OAuth account append, which holds
/// `config_lock` across the whole read-modify-write, then reloads) and for unit
/// tests that only have a path. Rejecting an invalid document *before* the write
/// is what keeps a bad edit from leaving behind a file the next start cannot load
/// — the bug `append_account` had, since it wrote the document unconditionally.
///
/// The file mode is `config::write_atomic`'s job (it writes a 0600 temp file and
/// renames it over the config, so a save cannot leave the secrets file
/// group/world-readable).
pub(crate) fn write_config_checked(path: &str, text: &str) -> anyhow::Result<()> {
    let parsed: crate::config::Config = toml::from_str(text)
        .map_err(|e| anyhow::anyhow!("invalid config (refusing to write): {e}"))?;
    parsed
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid config (refusing to write): {e}"))?;
    crate::config::write_atomic(path, text).map_err(|e| anyhow::anyhow!("cannot write {path}: {e}"))
}

/// A minimal `AppState` plus temp config files, for tests that drive a handler.
///
/// `AppState` lives in `proxy/mod.rs` (not this change's file), so the tests build
/// the struct field by field here instead of adding a test-only constructor to it.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::{Arc, Mutex, RwLock};

    use crate::proxy::AppState;

    /// Write `body` to a fresh file under the temp dir and hand back the path.
    pub(crate) fn temp_config(body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "anyhop-api-test-{}-{:?}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, body).unwrap();
        path
    }

    /// The smallest config that loads: one key-based provider and one client key.
    pub(crate) const MINIMAL: &str = r#"[[providers]]
name = "mock"
type = "openai_compat"
base_url = "http://127.0.0.1:1/v1"
keys = ["sk-test-key"]

[server]
listen = "127.0.0.1:18080"
api_key = "test-gw-key"
"#;

    pub(crate) fn state(path: &std::path::Path) -> Arc<AppState> {
        Arc::new(AppState {
            router: arc_swap::ArcSwap::from_pointee(crate::providers::ProviderRouter {
                providers: Vec::new(),
                combos: Vec::new(),
            }),
            cfg: RwLock::new(crate::proxy::RtConfig {
                max_retries: 2,
                attempt_timeout: std::time::Duration::from_secs(30),
                api_key: Some("test-gw-key".to_string()),
                admin_key: Some("test-gw-key".to_string()),
                events_history: 8,
                requests_history: 8,
                auth_fail_burst: 3,
                auth_fail_window: std::time::Duration::from_secs(60),
                client_key_max_concurrent: 0,
                tls_enabled: false,
                ratelimit: crate::config::RateLimitConfig::default(),
            }),
            storage: None,
            config_path: path.to_string_lossy().into_owned(),
            events: crate::events::EventBus::new(8),
            auth_state: Mutex::new(None),
            auth_task: Mutex::new(None),
            auth_code_tx: Mutex::new(None),
            auth_start_lock: tokio::sync::Mutex::new(()),
            auth_fails: Mutex::new(crate::middleware::AuthFailures::default()),
            catalog_epoch: AtomicU64::new(0),
            tls_enabled_flag: AtomicBool::new(false),
            models_cache: Mutex::new(None),
            request_log: Mutex::new(VecDeque::new()),
            client_keys: RwLock::new(HashMap::new()),
            disabled_models: RwLock::new(HashSet::new()),
            config_lock: tokio::sync::Mutex::new(()),
            tuning: arc_swap::ArcSwap::from_pointee(crate::config::Tuning::default()),
        })
    }

    /// A body-carrying helper: `Json(body)` from a JSON string, so tests exercise
    /// the same serde contract the dashboard's `fetch` does.
    pub(crate) fn json<T: serde::de::DeserializeOwned>(raw: &str) -> axum::Json<T> {
        axum::Json(serde_json::from_str(raw).unwrap())
    }
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

    // ---------- credentials, paths, file mode ----------

    use crate::api::server::test_support::{MINIMAL, state, temp_config};

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Use the same serde contract the dashboard's `fetch` uses.
    fn update(raw: &str) -> ServerUpdate {
        serde_json::from_str(raw).unwrap()
    }

    /// Rotation was impossible: any non-empty secret was dropped whenever one was
    /// already configured, so a leaked key could only be replaced by hand-editing
    /// the TOML.
    #[tokio::test]
    async fn rotating_the_api_key_rewrites_the_config() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let resp = update_server(
            State(st.clone()),
            Json(update(r#"{"api_key":"rotated-key-abcdef"}"#)),
        )
        .await
        .expect("rotation must be accepted");
        let body = body_json(resp).await;
        assert_eq!(body["changed"], serde_json::json!(["api_key"]), "{body}");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("rotated-key-abcdef"), "{raw}");
        assert!(
            !raw.contains("test-gw-key"),
            "old secret must be gone: {raw}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Resending the same secret is harmless and reported as a no-op (otherwise
    /// every dashboard save would claim a change).
    #[tokio::test]
    async fn resending_the_same_secret_is_a_noop() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let resp = update_server(
            State(st.clone()),
            Json(update(r#"{"api_key":"test-gw-key"}"#)),
        )
        .await
        .expect("resend must be accepted");
        let body = body_json(resp).await;
        assert_eq!(body["changed"], serde_json::json!([]), "{body}");
        let _ = std::fs::remove_file(&path);
    }

    /// `api_key: ""` used to delete the key — i.e. the dashboard form (which posts
    /// every field) could open `/api/*` and `/v1/*` on a public listener.
    #[tokio::test]
    async fn an_empty_secret_field_does_not_clear_the_key() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let resp = update_server(
            State(st.clone()),
            Json(update(r#"{"api_key":"","admin_key":""}"#)),
        )
        .await
        .expect("an empty field is just no change");
        let body = body_json(resp).await;
        assert_eq!(body["changed"], serde_json::json!([]), "{body}");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("test-gw-key"), "the key must survive: {raw}");
        let _ = std::fs::remove_file(&path);
    }

    /// Clearing is allowed, but only as an explicit request — and never on a
    /// listener the network can reach.
    #[tokio::test]
    async fn clearing_a_key_needs_the_explicit_flag_and_a_loopback_listener() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let err = update_server(
            State(st.clone()),
            Json(update(r#"{"clear_api_key":true,"listen":"0.0.0.0:18080"}"#)),
        )
        .await
        .expect_err("clearing on a public listener must be refused");
        assert!(format!("{err:?}").contains("loopback"), "{err:?}");

        let resp = update_server(
            State(st.clone()),
            Json(update(
                r#"{"clear_api_key":true,"listen":"127.0.0.1:18080"}"#,
            )),
        )
        .await
        .expect("clearing on loopback is allowed");
        let body = body_json(resp).await;
        assert_eq!(body["changed"], serde_json::json!(["api_key"]), "{body}");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("api_key"), "the key must be gone: {raw}");
        let _ = std::fs::remove_file(&path);
    }

    /// A value *and* `clear_*` in the same request is ambiguous — refuse it
    /// instead of guessing which one the operator meant.
    #[tokio::test]
    async fn a_new_secret_and_a_clear_flag_together_are_rejected() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let err = update_server(
            State(st.clone()),
            Json(update(
                r#"{"api_key":"rotated-key-abcdef","clear_api_key":true}"#,
            )),
        )
        .await
        .expect_err("ambiguous request");
        assert!(format!("{err:?}").contains("not both"), "{err:?}");
        let _ = std::fs::remove_file(&path);
    }

    /// The config holds provider keys and OAuth refresh tokens; the atomic write
    /// created its temp file with the process umask, so the first save downgraded
    /// 0600 to 0644.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_config_save_keeps_the_file_private() {
        use std::os::unix::fs::PermissionsExt;

        for original in [0o600, 0o644] {
            let path = temp_config(MINIMAL);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(original)).unwrap();
            let st = state(&path);
            let resp = update_server(State(st.clone()), Json(update(r#"{"max_retries":5}"#)))
                .await
                .expect("save");
            assert_eq!(resp.status(), axum::http::StatusCode::OK);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "mode {original:o} became {mode:o}: the secrets file must stay private"
            );
            let _ = std::fs::remove_file(&path);
        }
    }

    /// File paths are a map of the host; the dashboard only needs the names.
    #[tokio::test]
    async fn server_settings_report_basenames_not_paths() {
        let path = temp_config(&format!(
            "{MINIMAL}state_file = \"/var/lib/anyhop/state.redb\"
tls_cert = \"/etc/letsencrypt/live/gw/fullchain.pem\"
tls_key = \"/etc/letsencrypt/live/gw/privkey.pem\"
"
        ));
        let st = state(&path);
        let resp = get_server(State(st.clone())).await.expect("dto");
        let body = body_json(resp).await;
        assert_eq!(body["state_file"], "state.redb", "{body}");
        assert_eq!(body["tls_cert"], "fullchain.pem", "{body}");
        assert_eq!(body["tls_key"], "privkey.pem", "{body}");
        let text = body.to_string();
        assert!(!text.contains("/etc/"), "path leaked: {text}");
        assert!(!text.contains("/var/lib/"), "path leaked: {text}");
        let _ = std::fs::remove_file(&path);
    }

    /// ... and posting a basename back (what the settings form does) must not
    /// overwrite the configured path with a name that does not resolve.
    #[tokio::test]
    async fn a_round_tripped_basename_is_not_written_back() {
        let path = temp_config(&format!(
            "{MINIMAL}tls_cert = \"/etc/letsencrypt/live/gw/fullchain.pem\"
state_file = \"/var/lib/anyhop/state.redb\"
"
        ));
        let st = state(&path);
        let resp = update_server(
            State(st.clone()),
            Json(update(
                r#"{"tls_cert":"fullchain.pem","state_file":"state.redb"}"#,
            )),
        )
        .await
        .expect("save");
        let body = body_json(resp).await;
        assert_eq!(body["changed"], serde_json::json!([]), "{body}");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("/etc/letsencrypt/live/gw/fullchain.pem"),
            "{raw}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn only_loopback_listeners_count_as_local() {
        for local in [
            "127.0.0.1:8080",
            "127.0.0.2:1",
            "localhost:8080",
            "[::1]:8080",
        ] {
            assert!(listen_is_loopback(local), "{local} is loopback");
        }
        for remote in [
            "0.0.0.0:8080",
            "[::]:8080",
            "10.0.0.5:8080",
            "gw.example.com:443",
        ] {
            assert!(!listen_is_loopback(remote), "{remote} is reachable");
        }
    }

    #[test]
    fn basenames_are_the_last_component_only() {
        assert_eq!(basename("/etc/x/cert.pem"), "cert.pem");
        assert_eq!(basename("cert.pem"), "cert.pem");
        assert_eq!(basename("C:\\certs\\cert.pem"), "cert.pem");
        assert_eq!(basename(""), "");
    }
}
