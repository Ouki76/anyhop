use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use super::persist::write_validated;
use super::{ApiError, ApiResult, ok_json};
use crate::config::ProviderKind;
use crate::proxy::AppState;

/// The one `base_url` rule, applied by `provider_add` *and* `provider_update`.
///
/// Update used to accept anything that fit in the field, so
/// `base_url = "file:///etc/passwd"` (or `gopher://169.254.169.254:80/`, a
/// metadata-service probe) could be written by the edit path even though add
/// rejected it — and the request builder then treated the value as an upstream
/// URL. http(s) only, bounded length.
fn validate_base_url(url: &str) -> Result<(), String> {
    let u = url.trim();
    if u.is_empty() {
        return Err("base_url must not be empty".to_string());
    }
    if !(u.starts_with("http://") || u.starts_with("https://")) || u.len() > 2048 {
        return Err("base_url must be an http(s) URL of at most 2048 characters".to_string());
    }
    Ok(())
}

/// In-flight cap per key: `0` is documented as "unlimited", everything else is a
/// real limit. `4294967295` and `1` are both nonsense for a gateway.
fn validate_provider_max_concurrent(n: u32) -> Result<(), String> {
    if n > 10_000 {
        return Err("max_concurrent must be 0 (unlimited) or 1..10000".to_string());
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct AddProvider {
    kind: String,
    name: Option<String>,
    base_url: Option<String>,
    key: Option<String>,
    /// Pass-through endpoints this provider serves (`images`, `audio`,
    /// `realtime`). Only valid for `openai_compat`, same rule as the TOML.
    capabilities: Option<Vec<String>>,
}

/// POST /api/providers/add — append a key-based provider to the config.
/// toml_edit touches only the [[providers]] array: comments and formatting
/// elsewhere in the file survive.
pub async fn provider_add(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddProvider>,
) -> ApiResult {
    let default_base = match body.kind.as_str() {
        "gemini" => Some("https://generativelanguage.googleapis.com/v1beta"),
        "anthropic" => Some("https://api.anthropic.com"),
        "openai_compat" => None,
        _ => {
            return Err(ApiError::bad_request(
                "kind must be gemini|anthropic|openai_compat",
            ));
        }
    };
    if let Some(n) = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        && let Err((_, msg)) = super::validate_name("provider", n)
    {
        return Err(ApiError::bad_request(msg));
    }
    // Same rules as the TOML (`config::Config::validate`): a known capability
    // name, and only on openai_compat. Checking before the write keeps a bad
    // request from leaving a config behind that the next reload would refuse.
    if let Some(caps) = &body.capabilities {
        if let Some(bad) = caps
            .iter()
            .find(|c| !matches!(c.as_str(), "images" | "audio" | "realtime"))
        {
            return Err(ApiError::bad_request(format!(
                "unknown capability '{bad}' (images|audio|realtime)"
            )));
        }
        if !caps.is_empty() && body.kind != "openai_compat" {
            return Err(ApiError::bad_request(
                "capabilities are only supported for openai_compat providers",
            ));
        }
    }
    if let Some(u) = body
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && let Err(msg) = validate_base_url(u)
    {
        return Err(ApiError::bad_request(msg));
    }
    if let Some(k) = body.key.as_deref()
        && let Err((_, msg)) = super::validate_secret_len("key", k)
    {
        return Err(ApiError::bad_request(msg));
    }
    let base_url = body
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let base_url = match base_url.or(default_base) {
        Some(b) => b.to_string(),
        None => {
            return Err(ApiError::bad_request(
                "base_url is required for openai_compat",
            ));
        }
    };
    let key = body.key.as_deref().map(str::trim).filter(|s| !s.is_empty());

    // Serialize config rewrites against concurrent dashboard/OAuth writers.
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
    if !doc.contains_key("providers") {
        doc["providers"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let Some(arr) = doc["providers"].as_array_of_tables_mut() else {
        return Err(ApiError::unprocessable(
            "'providers' is not an array of tables in the config file",
        ));
    };

    // Unique name: kind, kind-2, kind-3…
    let base_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| body.kind.clone());
    let mut name = base_name.clone();
    let mut n = 2;
    while arr
        .iter()
        .any(|p| p.get("name").and_then(|v| v.as_str()) == Some(name.as_str()))
    {
        name = format!("{base_name}-{n}");
        n += 1;
    }

    let mut t = toml_edit::Table::new();
    t["name"] = toml_edit::value(name.clone());
    t["type"] = toml_edit::value(body.kind.clone());
    t["base_url"] = toml_edit::value(base_url);
    t["strategy"] = toml_edit::value("round_robin");
    if let Some(k) = key {
        let mut keys = toml_edit::Array::new();
        keys.push(k);
        t["keys"] = toml_edit::value(keys);
    }
    // An empty list is the default (no pass-through endpoints) — omit the key
    // instead of writing `capabilities = []` noise into the operator's file.
    if let Some(caps) = body.capabilities.as_ref().filter(|c| !c.is_empty()) {
        let mut array = toml_edit::Array::new();
        for cap in caps {
            array.push(cap.as_str());
        }
        t["capabilities"] = toml_edit::value(array);
    }
    arr.push(t);

    // Build before writing: `commit_config_text` parses, validates **and builds**
    // the router, and only then replaces the file. Writing first (as this handler
    // used to) left a config on disk that the next start refuses — adding a
    // provider without a key bricked the gateway until someone edited the file.
    if let Err(resp) = super::persist::commit_config_text(&state, &doc.to_string()).await {
        return Ok(*resp);
    }
    state
        .events
        .emit_simple("config", "", "backoff", format!("provider '{name}' added"));
    ok_json(serde_json::json!({"name": name}))
}

// ---------- provider settings ----------

#[derive(Deserialize)]
pub struct UpdateProvider {
    name: String,
    base_url: Option<String>,
    strategy: Option<String>,
    max_concurrent: Option<u32>,
    drain_below_pct: Option<u32>,
    /// Empty string clears the proxy.
    proxy: Option<String>,
    /// Per-provider attempt budget (overrides `[server]`).
    timeout_secs: Option<u64>,
    max_retries: Option<usize>,
    /// Pass-through endpoints (`images`, `audio`, `realtime`). An empty list
    /// removes the key; `null`/absent leaves it untouched.
    capabilities: Option<Vec<String>>,
}

/// POST /api/providers/update — edit the mutable settings of one provider.
///
/// `name` and `type` are the identity of the provider: renaming would silently
/// break combos, client-key allowlists and `disabled_models`, so it is not
/// offered here (edit the TOML if you really need to).
pub async fn provider_update(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateProvider>,
) -> ApiResult {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    if let Some(s) = &body.strategy
        && !matches!(s.as_str(), "round_robin" | "least_used" | "fill_first")
    {
        return Err(ApiError::bad_request(
            "strategy must be round_robin | least_used | fill_first",
        ));
    }
    if let Some(pct) = body.drain_below_pct
        && pct > 100
    {
        return Err(ApiError::bad_request("drain_below_pct must be <= 100"));
    }
    if let Some(t) = body.timeout_secs
        && !(1..=3600).contains(&t)
    {
        return Err(ApiError::bad_request(
            "timeout_secs must be between 1 and 3600",
        ));
    }
    if let Some(r) = body.max_retries
        && !(1..=32).contains(&r)
    {
        return Err(ApiError::bad_request(
            "max_retries must be between 1 and 32",
        ));
    }
    // Same rules as add: an update must not be able to install a value the
    // create path rejects (a non-http base_url, an absurd concurrency cap).
    if let Some(u) = body.base_url.as_deref()
        && let Err(msg) = validate_base_url(u)
    {
        return Err(ApiError::bad_request(msg));
    }
    if let Some(n) = body.max_concurrent
        && let Err(msg) = validate_provider_max_concurrent(n)
    {
        return Err(ApiError::bad_request(msg));
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
    let Some(arr) = doc
        .get_mut("providers")
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return Err(ApiError::not_found("no providers in the config"));
    };
    let Some(p) = arr
        .iter_mut()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(name))
    else {
        return Err(ApiError::not_found(format!("provider '{name}' not found")));
    };

    if let Some(b) = body.base_url.as_deref() {
        // Validated above (empty, scheme, length) before the file is touched.
        p["base_url"] = toml_edit::value(b.trim());
    }
    if let Some(s) = &body.strategy {
        p["strategy"] = toml_edit::value(s.clone());
    }
    if let Some(t) = body.timeout_secs {
        p["timeout_secs"] = toml_edit::value(t as i64);
    }
    if let Some(r) = body.max_retries {
        p["max_retries"] = toml_edit::value(r as i64);
    }
    if let Some(n) = body.max_concurrent {
        p["max_concurrent"] = toml_edit::value(n as i64);
    }
    if let Some(pct) = body.drain_below_pct {
        p["drain_below_pct"] = toml_edit::value(pct as i64);
    }
    if let Some(proxy) = body.proxy.as_deref() {
        let proxy = proxy.trim();
        // "***" is the masked form the dashboard shows — never write it back.
        if !super::is_masked(proxy) {
            if proxy.is_empty() {
                p.remove("proxy");
            } else {
                p["proxy"] = toml_edit::value(proxy);
            }
        }
    }

    if let Some(caps) = body.capabilities.as_ref() {
        if caps.is_empty() {
            p.remove("capabilities");
        } else {
            let mut array = toml_edit::Array::new();
            for cap in caps {
                array.push(cap.as_str());
            }
            p["capabilities"] = toml_edit::value(array);
        }
        // No name/kind check here: `write_validated` re-parses the whole file
        // through `Config::validate`, which rejects an unknown capability or one
        // on a non-openai_compat provider — and nothing is written in that case.
    }

    if let Err(resp) = write_validated(&state, &doc).await {
        return Ok(*resp);
    }
    state.events.emit_simple(
        "config",
        "",
        "backoff",
        format!("provider '{name}' updated"),
    );
    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
pub struct DeleteProvider {
    name: String,
}

/// POST /api/providers/delete — remove a provider from the config.
pub async fn provider_delete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeleteProvider>,
) -> ApiResult {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
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
    let Some(arr) = doc
        .get_mut("providers")
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return Err(ApiError::not_found("no providers in the config"));
    };
    let Some(idx) = arr
        .iter()
        .position(|p| p.get("name").and_then(|v| v.as_str()) == Some(name))
    else {
        return Err(ApiError::not_found(format!("provider '{name}' not found")));
    };
    arr.remove(idx);

    // Combos referencing the removed provider would fail validation (and would
    // silently degrade the fallback chain), so drop them in the same edit.
    let mut dropped: Vec<String> = Vec::new();
    if let Some(combos) = doc
        .get_mut("combos")
        .and_then(|i| i.as_array_of_tables_mut())
    {
        let mut keep = toml_edit::ArrayOfTables::new();
        for c in combos.iter() {
            let touches = c
                .get("chain")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter().any(|v| {
                        v.as_str()
                            .and_then(|s| s.split_once('/'))
                            .map(|(pr, _)| pr == name)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if touches {
                if let Some(n) = c.get("name").and_then(|v| v.as_str()) {
                    dropped.push(n.to_string());
                }
            } else {
                keep.push(c.clone());
            }
        }
        *combos = keep;
    }

    if let Err(resp) = write_validated(&state, &doc).await {
        return Ok(*resp);
    }
    let detail = if dropped.is_empty() {
        format!("provider '{name}' deleted")
    } else {
        format!(
            "provider '{name}' deleted, removed from combos: {}",
            dropped.join(", ")
        )
    };
    state.events.emit_simple("config", "", "backoff", detail);
    Ok(StatusCode::OK.into_response())
}

// ---------- key management ----------

#[derive(Deserialize)]
pub struct KeyAction {
    provider: String,
    id: String,
}

#[derive(Deserialize)]
pub struct AddKey {
    provider: String,
    secret: String,
}

fn set_key(state: &AppState, action: &KeyAction, enabled: bool) -> ApiResult {
    let router = state.router.load();
    let Some(p) = router.providers.iter().find(|p| p.name == action.provider) else {
        return Err(ApiError::not_found("unknown provider"));
    };
    if p.pool.set_enabled(&action.id, enabled) {
        Ok(StatusCode::OK.into_response())
    } else {
        Err(ApiError::not_found("unknown key"))
    }
}

pub async fn key_enable(State(state): State<Arc<AppState>>, Json(a): Json<KeyAction>) -> ApiResult {
    set_key(&state, &a, true)
}

pub async fn key_disable(
    State(state): State<Arc<AppState>>,
    Json(a): Json<KeyAction>,
) -> ApiResult {
    set_key(&state, &a, false)
}

/// POST /api/keys/delete — forget a credential for good.
///
/// Removes it from the live pool, from the TOML `keys` array (or the OAuth
/// `accounts` entry) and from the runtime-key list in the state file, then
/// reloads so the next request cannot pick it up.
pub async fn key_delete(State(state): State<Arc<AppState>>, Json(a): Json<KeyAction>) -> ApiResult {
    let router = state.router.load();
    let Some(p) = router.providers.iter().find(|p| p.name == a.provider) else {
        return Err(ApiError::not_found("unknown provider"));
    };
    let Some(key) = p.pool.snapshot().into_iter().find(|k| k.id == a.id) else {
        return Err(ApiError::not_found("unknown key"));
    };
    // The snapshot only exposes a hash; resolve the secret through the pool.
    let Some(secret) = p.pool.secret_by_id(&a.id) else {
        return Err(ApiError::not_found("unknown key"));
    };
    let is_oauth = matches!(p.kind, ProviderKind::Antigravity | ProviderKind::Codex);
    // Removing the last credential would leave the provider unusable (and the
    // config invalid); deleting the provider is the honest operation there.
    if p.pool.len() <= 1 {
        return Err(ApiError::conflict(format!(
            "'{}' has only one credential left — delete the provider instead of its last key",
            p.name
        )));
    }
    let provider_name = p.name.clone();
    let kind = p.kind;
    drop(router);

    if is_oauth {
        // OAuth accounts are matched by the hash of their token, the same id the
        // dashboard uses.
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
        let Some(arr) = doc
            .get_mut("providers")
            .and_then(|i| i.as_array_of_tables_mut())
        else {
            return Err(ApiError::not_found("no providers in the config"));
        };
        let Some(pt) = arr
            .iter_mut()
            .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(provider_name.as_str()))
        else {
            return Err(ApiError::not_found("unknown provider"));
        };
        let mut removed = false;
        if let Some(accounts) = pt
            .get_mut("accounts")
            .and_then(|i| i.as_array_of_tables_mut())
        {
            let mut keep = toml_edit::ArrayOfTables::new();
            for acc in accounts.iter() {
                let tok = match kind {
                    ProviderKind::Antigravity => acc.get("refresh_token").and_then(|v| v.as_str()),
                    _ => acc
                        .get("access_token")
                        .and_then(|v| v.as_str())
                        .or_else(|| acc.get("refresh_token").and_then(|v| v.as_str())),
                };
                let matches = tok
                    .map(|t| crate::storage::secret_hash(t) == key.id)
                    .unwrap_or(false);
                if matches {
                    removed = true;
                } else {
                    keep.push(acc.clone());
                }
            }
            *accounts = keep;
        }
        if !removed {
            return Err(ApiError::conflict("account not found in the config file"));
        }
        if let Err(resp) = write_validated(&state, &doc).await {
            return Ok(*resp);
        }
        state.events.emit_simple(
            "config",
            "",
            "backoff",
            format!("account removed from provider '{provider_name}'"),
        );
        return Ok(StatusCode::OK.into_response());
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
    // Rebuild the provider's `keys` array as the complete remaining set: the file
    // keys minus the deleted one, plus any runtime keys that only exist in the
    // state file. Writing just the file keys would leave `keys = []` (an invalid
    // config) whenever the deleted credential was the only one in the TOML.
    let mut remaining: Vec<String> = Vec::new();
    if let Some(arr) = doc
        .get_mut("providers")
        .and_then(|i| i.as_array_of_tables_mut())
    {
        for pt in arr.iter_mut() {
            if pt.get("name").and_then(|v| v.as_str()) != Some(provider_name.as_str()) {
                continue;
            }
            if let Some(keys) = pt.get("keys").and_then(|i| i.as_array()) {
                for v in keys.iter() {
                    if let Some(s) = v.as_str()
                        && s != secret
                        && !remaining.iter().any(|r| r == s)
                    {
                        remaining.push(s.to_string());
                    }
                }
            }
            if let Some(s) = &state.storage {
                for extra in s.list_extra_keys(&provider_name) {
                    if extra != secret && !remaining.contains(&extra) {
                        remaining.push(extra);
                    }
                }
            }
            let mut arr = toml_edit::Array::new();
            for k in &remaining {
                arr.push(k.as_str());
            }
            pt["keys"] = toml_edit::value(arr);
        }
    }

    // Clear the runtime copy *before* the reload. The reload merges every secret
    // the state file still lists back into the pool, so clearing it afterwards
    // kept the deleted key alive until the *next* reload. The list is restored
    // below if the config write is refused, so a rejected edit cannot drop
    // runtime-added keys.
    let extras_before = state
        .storage
        .as_ref()
        .map(|s| s.list_extra_keys(&provider_name))
        .unwrap_or_default();
    if let Some(s) = &state.storage {
        s.delete_extra_key(&provider_name, &secret);
        s.set_extra_keys(&provider_name, Vec::new());
    }

    if let Err(resp) = write_validated(&state, &doc).await {
        if let Some(s) = &state.storage {
            s.set_extra_keys(&provider_name, extras_before);
        }
        return Ok(*resp);
    }
    state.events.emit_simple(
        "config",
        "",
        "backoff",
        format!("key removed from provider '{provider_name}'"),
    );
    Ok(StatusCode::OK.into_response())
}

pub async fn key_add(State(state): State<Arc<AppState>>, Json(a): Json<AddKey>) -> ApiResult {
    let secret = a.secret.trim();
    if secret.len() < 4 {
        return Err(ApiError::bad_request("key too short"));
    }
    if let Err((_, msg)) = super::validate_secret_len("key", secret) {
        return Err(ApiError::bad_request(msg));
    }
    let router = state.router.load();
    let Some(p) = router.providers.iter().find(|p| p.name == a.provider) else {
        return Err(ApiError::not_found("unknown provider"));
    };
    if matches!(p.kind, ProviderKind::Antigravity | ProviderKind::Codex) {
        return Err(ApiError::bad_request(
            "OAuth accounts are added via `anyhop auth …`",
        ));
    }
    if p.pool.contains(secret) {
        // A duplicate secret would be double-counted in rotation and stats.
        return Err(ApiError::conflict("key already exists"));
    }
    let provider_name = p.name.clone();
    drop(router);

    // Write it into the config file: the TOML stays the single source of truth, so
    // the raw-config editor shows the key and a restart without the state file
    // still knows it. (Runtime keys in `redb` remain supported for older setups —
    // they are merged on load and folded into the file by the delete path.)
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
    let Some(arr) = doc
        .get_mut("providers")
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return Err(ApiError::not_found("no providers in the config"));
    };
    let Some(pt) = arr
        .iter_mut()
        .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(provider_name.as_str()))
    else {
        return Err(ApiError::not_found("unknown provider"));
    };
    if !pt.contains_key("keys") {
        pt["keys"] = toml_edit::value(toml_edit::Array::new());
    }
    let Some(keys) = pt.get_mut("keys").and_then(|i| i.as_array_mut()) else {
        return Err(ApiError::unprocessable("'keys' is not an array"));
    };
    if !keys.iter().any(|v| v.as_str() == Some(secret)) {
        keys.push(secret);
    }
    if let Err(resp) = write_validated(&state, &doc).await {
        return Ok(*resp);
    }
    state.events.emit_simple(
        "config",
        "",
        "backoff",
        format!("key added to provider '{provider_name}'"),
    );
    Ok(StatusCode::OK.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::test_support::{MINIMAL, state, temp_config};

    /// The edit path accepted URLs the create path rejects: a `file://` upstream
    /// (local file exfiltration) or a `gopher://` probe at the cloud metadata
    /// service can be written into the config and then fetched by the gateway.
    #[test]
    fn base_urls_must_be_http_or_https() {
        for ok in [
            "http://127.0.0.1:8080/v1",
            "https://api.example.com/v1",
            " https://api.example.com/v1 ",
        ] {
            assert!(validate_base_url(ok).is_ok(), "{ok} must be accepted");
        }
        for bad in [
            "file:///etc/passwd",
            "gopher://169.254.169.254:80/",
            "ftp://example.com/v1",
            "example.com/v1",
            "",
            "  ",
        ] {
            assert!(validate_base_url(bad).is_err(), "{bad} must be rejected");
        }
        let long = format!("https://example.com/{}", "x".repeat(2100));
        assert!(validate_base_url(&long).is_err(), "length must be bounded");
    }

    #[test]
    fn provider_concurrency_is_bounded() {
        assert!(validate_provider_max_concurrent(0).is_ok(), "0 = unlimited");
        assert!(validate_provider_max_concurrent(1).is_ok());
        assert!(validate_provider_max_concurrent(10_000).is_ok());
        assert!(validate_provider_max_concurrent(10_001).is_err());
        assert!(
            validate_provider_max_concurrent(u32::MAX).is_err(),
            "4 billion in-flight requests is not a limit"
        );
    }

    /// The handler must apply those rules, not just the helpers.
    #[tokio::test]
    async fn provider_update_shares_the_add_path_validation() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let before = std::fs::read_to_string(&path).unwrap();

        let body: UpdateProvider =
            serde_json::from_str(r#"{"name":"mock","base_url":"file:///etc/passwd"}"#)
                .expect("deserialize");
        let err = provider_update(State(st.clone()), Json(body))
            .await
            .expect_err("file:// must be rejected");
        assert!(format!("{err:?}").contains("http"), "{err:?}");

        let body: UpdateProvider =
            serde_json::from_str(r#"{"name":"mock","base_url":"gopher://169.254.169.254:80/"}"#)
                .expect("deserialize");
        assert!(
            provider_update(State(st.clone()), Json(body))
                .await
                .is_err(),
            "gopher:// must be rejected"
        );

        let body: UpdateProvider =
            serde_json::from_str(r#"{"name":"mock","max_concurrent":4294967295}"#)
                .expect("deserialize");
        assert!(
            provider_update(State(st.clone()), Json(body))
                .await
                .is_err(),
            "a 4-billion concurrency cap must be rejected"
        );

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "a rejected update must not touch the file"
        );

        // A valid update still goes through.
        let body: UpdateProvider = serde_json::from_str(
            r#"{"name":"mock","base_url":"https://api.example.com/v1","max_concurrent":8}"#,
        )
        .expect("deserialize");
        provider_update(State(st.clone()), Json(body))
            .await
            .expect("valid update");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("https://api.example.com/v1"), "{raw}");
        assert!(raw.contains("max_concurrent = 8"), "{raw}");
        let _ = std::fs::remove_file(&path);
    }
}

/// Provider add/delete rewrite the whole provider list and (for add) a key. The
/// config is the only source of truth across a restart, so every accepted edit
/// must leave a document the next start can load, and every rejected one must
/// leave the file untouched.
#[cfg(test)]
mod edit_tests {
    use super::*;
    use crate::api::server::test_support::{json, state, temp_config};

    /// Two providers and a combo that spans them, so deletion has something to
    /// clean up and the config stays valid afterwards.
    const TWO: &str = r#"
        [[providers]]
        name = "mock"
        type = "openai_compat"
        base_url = "http://127.0.0.1:1/v1"
        keys = ["sk-one"]
        models = ["m"]

        [[providers]]
        name = "spare"
        type = "openai_compat"
        base_url = "http://127.0.0.1:2/v1"
        keys = ["sk-two"]
        models = ["m2"]

        [[combos]]
        name = "chain"
        chain = ["mock/m", "spare/m2"]

        [[combos]]
        name = "alone"
        chain = ["spare/m2"]

        [server]
        listen = "127.0.0.1:18080"
        api_key = "test-gw-key"
    "#;

    fn load(path: &std::path::Path) -> crate::config::Config {
        let raw = std::fs::read_to_string(path).expect("read");
        let cfg: crate::config::Config = toml::from_str(&raw).expect("the file must still parse");
        cfg.validate()
            .expect("the file must still be a loadable config");
        cfg
    }

    /// Adding a provider must write something the runtime can build, install it,
    /// and stay out of the way of the existing entries (comments included).
    #[tokio::test]
    async fn adding_a_provider_installs_it_and_keeps_the_config_loadable() {
        let seed = format!("# keep this comment\n{TWO}");
        let path = temp_config(&seed);
        let st = state(&path);

        let resp = provider_add(
            State(st.clone()),
            json(
                r#"{"kind":"openai_compat","base_url":"http://127.0.0.1:3/v1","key":"sk-new","capabilities":["images"]}"#,
            ),
        )
        .await
        .expect("added");
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["name"], "openai_compat", "{body}");

        let cfg = load(&path);
        let names: Vec<&str> = cfg.providers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["mock", "spare", "openai_compat"], "{names:?}");
        let added = cfg
            .providers
            .iter()
            .find(|p| p.name == "openai_compat")
            .expect("the new provider");
        assert_eq!(added.keys, vec!["sk-new".to_string()]);
        assert_eq!(added.capabilities, vec!["images".to_string()]);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("keep this comment"),
            "the operator's comments must survive the edit"
        );
        // The live router follows (reload_config ran).
        assert_eq!(st.router.load().providers.len(), 3);

        // The default name is not overwritten by a second provider of that kind.
        let resp = provider_add(
            State(st.clone()),
            json(r#"{"kind":"openai_compat","base_url":"http://127.0.0.1:4/v1","key":"sk-new2"}"#),
        )
        .await
        .expect("added");
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["name"], "openai_compat-2", "{body}");
        assert_eq!(load(&path).providers.len(), 4);

        let _ = std::fs::remove_file(&path);
    }

    /// Nothing is written when the request is invalid — not even a partial
    /// provider entry.
    #[tokio::test]
    async fn a_rejected_provider_add_leaves_the_file_untouched() {
        let path = temp_config(TWO);
        let st = state(&path);
        let before = std::fs::read_to_string(&path).expect("read");

        for body in [
            r#"{"kind":"openai_compat","base_url":"file:///etc/passwd","key":"sk-x"}"#,
            r#"{"kind":"openai_compat","base_url":"http://127.0.0.1:3/v1","key":"sk-x","capabilities":["shell"]}"#,
            r#"{"kind":"gemini","base_url":"http://127.0.0.1:3/v1","key":"sk-x","capabilities":["images"]}"#,
            r#"{"kind":"mystery","base_url":"http://127.0.0.1:3/v1","key":"sk-x"}"#,
            r#"{"kind":"openai_compat","key":"sk-x"}"#,
            r#"{"kind":"openai_compat","base_url":"http://127.0.0.1:3/v1","name":"bad name/x","key":"sk-x"}"#,
        ] {
            let parsed: AddProvider = serde_json::from_str(body).expect("valid JSON case");
            assert!(
                provider_add(State(st.clone()), Json(parsed)).await.is_err(),
                "{body} must be rejected"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            before,
            "a rejected add rewrote the config"
        );
        assert_eq!(st.router.load().providers.len(), 0, "nothing installed");
        let _ = std::fs::remove_file(&path);
    }

    /// Deleting a provider has to remove the combos that reference it in the same
    /// edit: the dangling chain would fail validation, so the delete would either
    /// be refused or (worse) leave a file the next start cannot load.
    #[tokio::test]
    async fn deleting_a_provider_also_drops_the_combos_that_used_it() {
        let path = temp_config(TWO);
        let st = state(&path);

        provider_delete(State(st.clone()), json(r#"{"name":"mock"}"#))
            .await
            .expect("deleted");

        let cfg = load(&path);
        let names: Vec<&str> = cfg.providers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["spare"], "{names:?}");
        let combos: Vec<&str> = cfg.combos.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            combos,
            vec!["alone"],
            "the combo that referenced 'mock' had to go, the other one stays"
        );
        assert_eq!(st.router.load().providers.len(), 1);

        // Unknown provider: a 404, and nothing changes.
        assert!(
            provider_delete(State(st.clone()), json(r#"{"name":"ghost"}"#))
                .await
                .is_err()
        );
        assert_eq!(st.router.load().providers.len(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
