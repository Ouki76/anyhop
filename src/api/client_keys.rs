use std::collections::HashMap;
use std::sync::{Arc, RwLockReadGuard, RwLockWriteGuard};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use super::persist::persist_client_keys;
use super::{ApiError, ApiResult, ok_json};
use crate::proxy::AppState;

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKeyDto {
    /// In-flight cap for this key (None = the server default). Must be exposed or
    /// the dashboard silently rewrites it away on the next edit.
    pub max_concurrent: Option<u32>,
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
    /// `None` = keep the current name; `Some(x)` = rename to `x` (validated).
    pub name: Option<String>,
    /// `None` = keep the current allowlist; `Some(vec![])` = allow every model.
    ///
    /// This used to be `Vec<String>` with `#[serde(default)]`: a rename, or any
    /// client that did not repeat the allowlist, silently emptied it.
    pub models: Option<Vec<String>>,
    /// `None` keeps the current limit; `Some(0)` removes it.
    #[serde(default)]
    pub rpm: Option<u32>,
    #[serde(default)]
    pub burst: Option<u32>,
    /// In-flight cap for this key (`None` keeps it, `Some(0)` = server default).
    pub max_concurrent: Option<u32>,
}

/// A model allowlist is written into the config file verbatim, so it needs the
/// same kind of bound as a name: without one, a single request can add megabytes
/// of `models` to the TOML.
const MAX_KEY_MODELS: usize = 64;
const MAX_MODEL_LEN: usize = 256;

/// Normalise and bound a model allowlist.
fn check_models(models: &[String]) -> Result<Vec<String>, String> {
    if models.len() > MAX_KEY_MODELS {
        return Err(format!(
            "a client key may allow at most {MAX_KEY_MODELS} models"
        ));
    }
    let mut out = Vec::with_capacity(models.len());
    for m in models {
        let m = m.trim();
        if m.is_empty() {
            continue;
        }
        if m.chars().count() > MAX_MODEL_LEN {
            return Err(format!(
                "a model name must be at most {MAX_MODEL_LEN} characters"
            ));
        }
        out.push(m.to_string());
    }
    Ok(out)
}

/// In-flight cap for a client key: `0` means "use the server default".
fn check_max_concurrent(n: u32) -> Result<(), String> {
    if n > 10_000 {
        return Err("max_concurrent must be 0 (server default) or 1..10000".to_string());
    }
    Ok(())
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
        max_concurrent: k.max_concurrent,
    }
}

pub async fn client_keys_list(State(state): State<Arc<AppState>>) -> ApiResult {
    let map = ck_read(&state);
    let mut list: Vec<ClientKeyDto> = map.values().map(|r| to_dto(r)).collect();
    list.sort_by_key(|a| std::cmp::Reverse(a.created_at));
    ok_json(list)
}

pub async fn client_key_add(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddClientKey>,
) -> ApiResult {
    let key_str = match body.key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None => match generate_client_key() {
            Some(k) => k,
            None => {
                return Err(ApiError::internal("cannot generate a key"));
            }
        },
    };

    if let Err((_, msg)) = super::validate_secret_len("client key", &key_str) {
        return Err(ApiError::bad_request(msg));
    }
    if let Some(n) = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        && let Err((_, msg)) = super::validate_name("client key", n)
    {
        return Err(ApiError::bad_request(msg));
    }
    if key_str.len() < 4 {
        return Err(ApiError::bad_request("key must be at least 4 characters"));
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
    let models = match check_models(&body.models) {
        Ok(m) => m,
        Err(msg) => return Err(ApiError::bad_request(msg)),
    };
    if let Some(n) = body.max_concurrent
        && let Err(msg) = check_max_concurrent(n)
    {
        return Err(ApiError::bad_request(msg));
    }
    let client_key = crate::config::ClientKeyConfig {
        key: key_str.clone(),
        name: name.clone(),
        models,
        created_at: Some(now),
        rpm,
        burst,
        max_concurrent: body.max_concurrent,
    };

    // New keys follow the live [ratelimit] backend like the ones loaded from TOML.
    let ratelimit = state.rt().ratelimit;
    let runtime = Arc::new(crate::proxy::ClientKeyRuntime::new_with(
        client_key.clone(),
        &ratelimit,
    ));
    {
        let mut map = ck_write(&state);
        if map.contains_key(&key_str) {
            return Err(ApiError::conflict("API key already exists"));
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

    ok_json(to_dto(&runtime))
}

pub async fn client_key_delete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeleteClientKey>,
) -> ApiResult {
    let removed = ck_write(&state).remove(&body.key);
    let Some(k) = removed else {
        return Err(ApiError::not_found("API key not found"));
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
    Ok(StatusCode::OK.into_response())
}

pub async fn client_key_update(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateClientKey>,
) -> ApiResult {
    // Validate before touching the live map: this handler used to skip every
    // check `client_key_add` makes (a 70 000-character name went straight into
    // the config file).
    let name = match body.name.as_deref() {
        Some(raw) => {
            let n = raw.trim();
            if let Err((_, msg)) = super::validate_name("client key", n) {
                return Err(ApiError::bad_request(msg));
            }
            Some(n.to_string())
        }
        None => None,
    };
    let models = match body.models.as_deref() {
        Some(m) => match check_models(m) {
            Ok(v) => Some(v),
            Err(msg) => return Err(ApiError::bad_request(msg)),
        },
        None => None,
    };
    if let Some(n) = body.max_concurrent
        && let Err(msg) = check_max_concurrent(n)
    {
        return Err(ApiError::bad_request(msg));
    }

    // Snapshot before taking the map lock (no lock nesting with `cfg`).
    let ratelimit = state.rt().ratelimit;
    let updated = {
        let mut map = ck_write(&state);
        let Some(prev) = map.get(&body.key).cloned() else {
            return Err(ApiError::not_found("API key not found"));
        };
        let mut cfg = prev.cfg.clone();
        if let Some(n) = name {
            cfg.name = Some(n);
        }
        // `None` = unchanged: a request that only renames the key must not wipe
        // the allowlist it did not mention.
        if let Some(m) = models {
            cfg.models = m;
        }
        if let Some(n) = body.max_concurrent {
            cfg.max_concurrent = Some(n);
        }
        // `rpm: None` keeps the current limit; `Some(0)` clears it.
        if body.rpm.is_some() || body.burst.is_some() {
            let (rpm, burst) = normalise_limit(body.rpm.or(cfg.rpm), body.burst.or(cfg.burst));
            cfg.rpm = rpm;
            cfg.burst = burst;
        }
        // rebind keeps the live bucket when the limits did not change.
        let rt = Arc::new(prev.rebind(cfg, &ratelimit));
        map.insert(body.key.clone(), rt.clone());
        rt
    };

    save_keys(&state).await;
    ok_json(to_dto(&updated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::test_support::{MINIMAL, json, state, temp_config};

    /// A rename that does not mention `models` must not wipe the allowlist.
    ///
    /// `models` used to be `Vec<String>` with `#[serde(default)]`, so every
    /// request that omitted it replaced the allowlist with an empty one — i.e.
    /// "rename this key" silently opened it to every model.
    #[test]
    fn omitting_models_means_leave_them_alone() {
        let body: UpdateClientKey =
            serde_json::from_str(r#"{"key":"sk-hop-x","name":"renamed"}"#).expect("deserialize");
        assert!(body.models.is_none(), "absent models must not mean 'empty'");
        let explicit: UpdateClientKey =
            serde_json::from_str(r#"{"key":"sk-hop-x","models":[]}"#).expect("deserialize");
        assert_eq!(
            explicit.models.as_deref(),
            Some(&[][..]),
            "an explicit empty list still clears the allowlist"
        );
    }

    #[tokio::test]
    async fn a_rename_keeps_the_allowlist_in_place() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let cfg = crate::config::ClientKeyConfig {
            key: "sk-hop-attrib".to_string(),
            name: Some("old".to_string()),
            models: vec!["mock/one".to_string(), "mock/two".to_string()],
            created_at: Some(1),
            rpm: None,
            burst: None,
            max_concurrent: Some(4),
        };
        let ratelimit = st.rt().ratelimit;
        let rt = Arc::new(crate::proxy::ClientKeyRuntime::new_with(cfg, &ratelimit));
        ck_write(&st).insert("sk-hop-attrib".to_string(), rt);

        client_key_update(
            State(st.clone()),
            json(r#"{"key":"sk-hop-attrib","name":"renamed"}"#),
        )
        .await
        .expect("rename");

        let after = ck_read(&st).get("sk-hop-attrib").cloned().expect("key");
        assert_eq!(after.cfg.name.as_deref(), Some("renamed"));
        assert_eq!(
            after.cfg.models,
            vec!["mock/one".to_string(), "mock/two".to_string()],
            "the allowlist must survive a rename"
        );
        assert_eq!(after.cfg.max_concurrent, Some(4), "and so must the cap");
        let _ = std::fs::remove_file(&path);
    }

    /// `client_key_add` validated the name; update did not, so a 70 KB name went
    /// straight into the config file and an empty one replaced a real label.
    #[tokio::test]
    async fn update_validates_the_name_like_add_does() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let cfg = crate::config::ClientKeyConfig {
            key: "sk-hop-name".to_string(),
            name: Some("keep".to_string()),
            models: Vec::new(),
            created_at: None,
            rpm: None,
            burst: None,
            max_concurrent: None,
        };
        let ratelimit = st.rt().ratelimit;
        ck_write(&st).insert(
            "sk-hop-name".to_string(),
            Arc::new(crate::proxy::ClientKeyRuntime::new_with(cfg, &ratelimit)),
        );

        let huge = format!(r#"{{"key":"sk-hop-name","name":"{}"}}"#, "x".repeat(70_000));
        let body: UpdateClientKey = serde_json::from_str(&huge).expect("deserialize");
        assert!(
            client_key_update(State(st.clone()), Json(body))
                .await
                .is_err(),
            "a 70 000-character name must be rejected"
        );

        for bad in [
            r#"{"key":"sk-hop-name","name":"bad name/x"}"#,
            r#"{"key":"sk-hop-name","name":"   "}"#,
        ] {
            let body: UpdateClientKey = serde_json::from_str(bad).expect("deserialize");
            assert!(
                client_key_update(State(st.clone()), Json(body))
                    .await
                    .is_err(),
                "{bad} must be rejected"
            );
        }
        let after = ck_read(&st).get("sk-hop-name").cloned().expect("key");
        assert_eq!(after.cfg.name.as_deref(), Some("keep"), "nothing changed");
        assert!(
            std::fs::read_to_string(&path).unwrap().len() < 10_000,
            "the config must not have grown"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn model_allowlists_are_bounded() {
        assert!(check_models(&vec!["m".to_string(); MAX_KEY_MODELS]).is_ok());
        assert!(
            check_models(&vec!["m".to_string(); MAX_KEY_MODELS + 1]).is_err(),
            "too many entries"
        );
        assert!(
            check_models(&["m".repeat(MAX_MODEL_LEN + 1)]).is_err(),
            "an entry longer than {MAX_MODEL_LEN} must be rejected"
        );
        // Blank entries (a stray empty option in the form) are dropped, not stored.
        assert_eq!(
            check_models(&[" a ".to_string(), String::new()]).unwrap(),
            vec!["a".to_string()]
        );
        assert!(check_max_concurrent(0).is_ok(), "0 = server default");
        assert!(check_max_concurrent(10_000).is_ok());
        assert!(check_max_concurrent(10_001).is_err());
        assert!(check_max_concurrent(u32::MAX).is_err());
    }
}
