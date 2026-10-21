use std::collections::HashMap;
use std::sync::{Arc, RwLockReadGuard, RwLockWriteGuard};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::persist::persist_client_keys;
use crate::proxy::AppState;

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKeyDto {
    pub key: String,
    pub masked: String,
    pub name: String,
    pub models: Vec<String>,
    pub created_at: u64,
    /// Sustained requests per minute (0 = unlimited).
    pub rpm: u32,
    /// Spike allowance (0 = same as `rpm`).
    pub burst: u32,
}

#[derive(Deserialize)]
pub struct AddClientKey {
    pub name: Option<String>,
    pub key: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub rpm: Option<u32>,
    #[serde(default)]
    pub burst: Option<u32>,
    /// In-flight cap for this key (None = server default).
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

#[derive(Deserialize)]
pub struct DeleteClientKey {
    pub key: String,
}

#[derive(Deserialize)]
pub struct UpdateClientKey {
    pub key: String,
    pub name: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
    /// `None` keeps the current limit; `Some(0)` removes it.
    #[serde(default)]
    pub rpm: Option<u32>,
    #[serde(default)]
    pub burst: Option<u32>,
}

// Poison-recovering guards (same policy as `pool::lock`): the map holds plain
// config values, so a panic elsewhere must not brick key management.
type KeyMap = HashMap<String, Arc<crate::proxy::ClientKeyRuntime>>;

fn ck_read(state: &AppState) -> RwLockReadGuard<'_, KeyMap> {
    state.client_keys.read().unwrap_or_else(|e| e.into_inner())
}

fn ck_write(state: &AppState) -> RwLockWriteGuard<'_, KeyMap> {
    state.client_keys.write().unwrap_or_else(|e| e.into_inner())
}

/// Normalise a limit pair: rpm 0 and None both mean "unlimited".
fn normalise_limit(rpm: Option<u32>, burst: Option<u32>) -> (Option<u32>, Option<u32>) {
    match rpm {
        Some(r) if r > 0 => (Some(r), burst.filter(|b| *b > 0)),
        _ => (None, None),
    }
}

/// Storage feed + TOML rewrite, in that order: the feed survives a failed file
/// rewrite, and both mutating handlers used to repeat this block verbatim.
async fn save_keys(state: &Arc<AppState>) {
    let all: Vec<_> = ck_read(state).values().map(|r| r.cfg.clone()).collect();
    if let Some(s) = &state.storage {
        s.save_feed("client_keys", &all);
    }
    persist_client_keys(state).await;
}

pub fn mask_key(k: &str) -> String {
    let n = k.chars().count();
    if n <= 8 {
        return "***".to_string();
    }
    let head: String = k.chars().take(7).collect();
    let tail: String = k.chars().skip(n - 4).collect();
    format!("{head}...{tail}")
}

/// A failure to seed the OS RNG is not recoverable for key generation, but it
/// must surface as a 500 rather than panicking the worker thread.
pub fn generate_client_key() -> Option<String> {
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).ok()?;
    Some(format!("sk-hop-{}", hex::encode(bytes)))
}

fn to_dto(rt: &crate::proxy::ClientKeyRuntime) -> ClientKeyDto {
    let k = &rt.cfg;
    ClientKeyDto {
        key: k.key.clone(),
        masked: mask_key(&k.key),
        name: k.name.clone().unwrap_or_else(|| mask_key(&k.key)),
        models: k.models.clone(),
        created_at: k.created_at.unwrap_or(0),
        rpm: k.rpm.unwrap_or(0),
        burst: k.burst.unwrap_or(0),
    }
}

pub async fn client_keys_list(State(state): State<Arc<AppState>>) -> Response {
    let map = ck_read(&state);
    let mut list: Vec<ClientKeyDto> = map.values().map(|r| to_dto(r)).collect();
    list.sort_by_key(|a| std::cmp::Reverse(a.created_at));
    Json(list).into_response()
}

pub async fn client_key_add(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddClientKey>,
) -> Response {
    let key_str = match body.key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => match generate_client_key() {
            Some(k) => k,
            None => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "cannot generate a key")
                    .into_response();
            }
        },
    };

    if let Err((code, msg)) = super::validate_secret_len("client key", &key_str) {
        return (code, msg).into_response();
    }
    if let Some(n) = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        && let Err((code, msg)) = super::validate_name("client key", n)
    {
        return (code, msg).into_response();
    }
    if key_str.len() < 4 {
        return (StatusCode::BAD_REQUEST, "key must be at least 4 characters").into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| Some(format!("Key {}", mask_key(&key_str))));

    let (rpm, burst) = normalise_limit(body.rpm, body.burst);
    let client_key = crate::config::ClientKeyConfig {
        key: key_str.clone(),
        name: name.clone(),
        models: body.models.clone(),
        created_at: Some(now),
        rpm,
        burst,
        max_concurrent: body.max_concurrent,
    };

    let runtime = Arc::new(crate::proxy::ClientKeyRuntime::new(client_key.clone()));
    {
        let mut map = ck_write(&state);
        if map.contains_key(&key_str) {
            return (StatusCode::CONFLICT, "API key already exists").into_response();
        }
        map.insert(key_str.clone(), runtime.clone());
    }
    save_keys(&state).await;

    state.events.emit_simple(
        "auth",
        "",
        "backoff",
        format!(
            "created client API key '{}'",
            name.as_deref().unwrap_or(&key_str)
        ),
    );

    Json(to_dto(&runtime)).into_response()
}

pub async fn client_key_delete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeleteClientKey>,
) -> Response {
    let removed = ck_write(&state).remove(&body.key);
    let Some(k) = removed else {
        return (StatusCode::NOT_FOUND, "API key not found").into_response();
    };
    save_keys(&state).await;

    state.events.emit_simple(
        "auth",
        "",
        "backoff",
        format!(
            "deleted client API key '{}'",
            k.cfg.name.as_deref().unwrap_or(&k.cfg.key)
        ),
    );
    StatusCode::OK.into_response()
}

pub async fn client_key_update(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateClientKey>,
) -> Response {
    let updated = {
        let mut map = ck_write(&state);
        let Some(prev) = map.get(&body.key).cloned() else {
            return (StatusCode::NOT_FOUND, "API key not found").into_response();
        };
        let mut cfg = prev.cfg.clone();
        if let Some(name) = body.name
            && !name.trim().is_empty()
        {
            cfg.name = Some(name.trim().to_string());
        }
        cfg.models = body.models;
        // `rpm: None` keeps the current limit; `Some(0)` clears it.
        if body.rpm.is_some() || body.burst.is_some() {
            let (rpm, burst) = normalise_limit(body.rpm.or(cfg.rpm), body.burst.or(cfg.burst));
            cfg.rpm = rpm;
            cfg.burst = burst;
        }
        // rebind keeps the live bucket when the limits did not change.
        let rt = Arc::new(prev.rebind(cfg));
        map.insert(body.key.clone(), rt.clone());
        rt
    };

    save_keys(&state).await;
    Json(to_dto(&updated)).into_response()
}
