use std::collections::HashMap;
use std::sync::{Arc, RwLockReadGuard, RwLockWriteGuard};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use super::persist::save_client_keys;
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
        // Same rule as the model-toggle endpoint: a control character in an
        // allowlist entry ends up in a Prometheus label, the event feed and the log.
        if m.chars().any(|c| c.is_control()) {
            return Err("a model name must not contain control characters".to_string());
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

#[cfg_attr(not(test), allow(dead_code))] // the tests seed the map directly
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

/// The live client keys as config records.
fn current_keys(state: &Arc<AppState>) -> Vec<crate::config::ClientKeyConfig> {
    ck_read(state).values().map(|r| r.cfg.clone()).collect()
}

/// Turn a boxed error response into something `ApiResult` can return.
///
/// `commit_config_text` produces a ready-made response (400 for a rejected edit,
/// 500 for a failed write); the handlers return `ApiResult`, so the response is
/// converted back to the equivalent typed error.
fn boxed(resp: &axum::response::Response) -> ApiError {
    let status = resp.status();
    let msg = match status.as_u16() {
        400 | 422 => "the config was rejected",
        409 => "the config changed underneath this request, try again",
        _ => "cannot write the config file",
    };
    match status.as_u16() {
        400 | 422 => ApiError::BadRequest(msg.into()),
        409 => ApiError::Conflict(msg.into()),
        _ => ApiError::Internal(msg.into()),
    }
}

/// Reject a name another key already uses.
///
/// The name is a Prometheus label and the Requests-tab identity; two keys sharing
/// it produce duplicate series and `Config::validate` refuses the file it would have
/// produced — which used to leave a config that every later write rejected.
fn ensure_unique_name(
    keys: &[crate::config::ClientKeyConfig],
    name: Option<&str>,
    except: Option<&str>,
) -> Result<(), ApiError> {
    let Some(name) = name.map(str::trim).filter(|n| !n.is_empty()) else {
        return Ok(());
    };
    if keys
        .iter()
        .any(|k| Some(k.key.as_str()) != except && k.name.as_deref().map(str::trim) == Some(name))
    {
        return Err(ApiError::conflict(format!(
            "another client key is already named '{name}'"
        )));
    }
    Ok(())
}

pub fn mask_key(k: &str) -> String {
    // The head and tail slices must never overlap: with `take(7)` + `skip(n-4)` a
    // 9-char key was printed in full (`sk-team...am-a` reconstructs it), and that
    // mask becomes the default key *name*, which is a Prometheus label and part of
    // the event/request feeds. Short keys get no mask at all.
    let n = k.chars().count();
    if n < 16 {
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

    // Compute the list this request wants and let the config writer validate,
    // write and install it. The live map is not touched here: `install_config`
    // rebuilds it from the file, so a rejected or failed write leaves the running
    // gateway exactly as it was.
    let mut keys = current_keys(&state);
    if keys.iter().any(|k| k.key == key_str) {
        return Err(ApiError::conflict("API key already exists"));
    }
    ensure_unique_name(&keys, client_key.name.as_deref(), None)?;
    keys.push(client_key.clone());
    save_client_keys(&state, &keys)
        .await
        .map_err(|r| boxed(&r))?;

    // The installed runtime (with its live bucket) is the one to report.
    let runtime = ck_read(&state).get(&key_str).cloned();

    state.events.emit_simple(
        "auth",
        "",
        "backoff",
        format!(
            "created client API key '{}'",
            name.as_deref().unwrap_or(&key_str)
        ),
    );

    match runtime {
        Some(rt) => ok_json(to_dto(&rt)),
        None => Err(ApiError::internal(
            "the key was written but is not in the live map",
        )),
    }
}

pub async fn client_key_delete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeleteClientKey>,
) -> ApiResult {
    let keys = current_keys(&state);
    let Some(k) = keys.iter().find(|k| k.key == body.key).cloned() else {
        return Err(ApiError::not_found("API key not found"));
    };
    let remaining: Vec<_> = keys.into_iter().filter(|k| k.key != body.key).collect();
    save_client_keys(&state, &remaining)
        .await
        .map_err(|r| boxed(&r))?;

    state.events.emit_simple(
        "auth",
        "",
        "backoff",
        format!(
            "deleted client API key '{}'",
            k.name.as_deref().unwrap_or(&k.key)
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

    let mut keys = current_keys(&state);
    let Some(prev) = keys.iter().find(|k| k.key == body.key).cloned() else {
        return Err(ApiError::not_found("API key not found"));
    };
    let mut cfg = prev;
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
    ensure_unique_name(&keys, cfg.name.as_deref(), Some(&body.key))?;
    for k in &mut keys {
        if k.key == body.key {
            *k = cfg.clone();
        }
    }
    save_client_keys(&state, &keys)
        .await
        .map_err(|r| boxed(&r))?;

    match ck_read(&state).get(&body.key).cloned() {
        Some(rt) => ok_json(to_dto(&rt)),
        None => Err(ApiError::internal(
            "the key was written but is not in the live map",
        )),
    }
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

    /// Adding a client key on a gateway with no admin credential must be refused.
    ///
    /// This handler used to splice the file directly and write it *without*
    /// `Config::validate`, so it happily produced `[[client_keys]]` next to a
    /// missing `[server] api_key` — a document the validator rejects. From then on
    /// every later writer, `POST /api/reload`, SIGHUP and the next start refused the
    /// config, i.e. the admin API locked itself out of its own file.
    #[tokio::test]
    async fn a_client_key_without_an_admin_credential_is_refused_and_writes_nothing() {
        let path = temp_config(
            r#"[[providers]]
name = "mock"
type = "openai_compat"
base_url = "http://127.0.0.1:1/v1"
keys = ["sk-test-key"]

[server]
listen = "127.0.0.1:18080"
"#,
        );
        let st = state(&path);
        let body: AddClientKey =
            serde_json::from_str(r#"{"name":"tenant","models":[]}"#).expect("deserialize");
        let err = client_key_add(State(st.clone()), Json(body))
            .await
            .expect_err("a key without an admin credential must be refused");
        assert!(
            format!("{err:?}").to_lowercase().contains("config"),
            "unexpected error {err:?}"
        );
        // The file must still be the one that was there — and it must still validate.
        let raw = std::fs::read_to_string(&path).expect("read");
        let cfg: crate::config::Config = toml::from_str(&raw).expect("parse");
        cfg.validate().expect("the file on disk must stay valid");
        assert!(
            cfg.client_keys.is_empty(),
            "nothing may have been written: {raw}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Two keys may not share a name: it is a Prometheus label value, and a
    /// duplicate sample makes Prometheus reject the whole scrape.
    #[tokio::test]
    async fn a_duplicate_name_is_a_conflict() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        for (key, name) in [("sk-hop-one", "team"), ("sk-hop-two", "team")] {
            let body: AddClientKey =
                serde_json::from_str(&format!(r#"{{"key":"{key}","name":"{name}","models":[]}}"#))
                    .expect("deserialize");
            let res = client_key_add(State(st.clone()), Json(body)).await;
            if key == "sk-hop-one" {
                res.expect("the first key is added");
            } else {
                let err = res.expect_err("the second key must be refused");
                assert!(format!("{err:?}").contains("already named"), "{err:?}");
            }
        }
        let _ = std::fs::remove_file(&path);
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

/// Secret handling for client keys: what an operator is shown, and what a
/// generated key looks like. Both are small functions with a big blast radius —
/// a mask that leaks is a leaked credential in a screenshot.
#[cfg(test)]
mod secret_tests {
    use super::*;
    use crate::api::server::test_support::{MINIMAL, json, state, temp_config};

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    /// A mask must keep enough to recognise a key and never enough to use it.
    #[test]
    fn a_mask_never_reveals_the_middle_of_a_key() {
        let key = "sk-hop-0123456789abcdef0123456789abcdef";
        let masked = mask_key(key);
        assert!(masked.contains("..."), "{masked}");
        assert!(
            masked.starts_with("sk-hop-"),
            "the prefix identifies the key"
        );
        assert!(masked.ends_with("cdef"), "the tail identifies the key");
        assert!(!masked.contains("456789abcdef012345"), "the middle leaked");
        assert!(masked.len() < key.len());

        // Anything short enough to be guessable is not shown at all.
        for short in ["", "a", "abcd", "12345678"] {
            assert_eq!(mask_key(short), "***", "short key {short:?} must be hidden");
        }
    }

    /// A generated key must be unpredictable, correctly shaped, and unique.
    #[test]
    fn generated_keys_are_prefixed_random_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let k = generate_client_key().expect("the OS RNG works");
            assert!(k.starts_with("sk-hop-"), "{k}");
            let body = &k["sk-hop-".len()..];
            assert_eq!(body.len(), 40, "20 random bytes, hex encoded: {k}");
            assert!(
                body.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "lowercase hex only: {k}"
            );
            assert!(seen.insert(k), "a generated key repeated");
        }
    }

    /// `rpm = 0` / absent means "unlimited", and a burst is meaningless without a
    /// sustained limit — the normalisation must drop both, not store a 0.
    #[test]
    fn limits_are_normalised_to_none_when_unlimited() {
        assert_eq!(normalise_limit(Some(60), Some(10)), (Some(60), Some(10)));
        assert_eq!(
            normalise_limit(Some(60), Some(0)),
            (Some(60), None),
            "a zero burst means 'same as rpm'"
        );
        assert_eq!(normalise_limit(Some(0), Some(10)), (None, None));
        assert_eq!(normalise_limit(None, Some(10)), (None, None));
    }

    /// Add and delete both rewrite `client_keys` in the TOML. The file is the
    /// single source of truth (a restart reloads it), so a mutation the API
    /// reports as successful must be on disk and still parse.
    #[tokio::test]
    async fn adding_and_deleting_a_key_keeps_the_config_loadable() {
        let path = temp_config(MINIMAL);
        let st = state(&path);

        let added = client_key_add(
            State(st.clone()),
            json(r#"{"key":"sk-hop-tenant-one","name":"tenant","models":["mock/one"],"max_concurrent":2}"#),
        )
        .await
        .expect("added");
        let dto = body_json(added).await;
        assert_eq!(dto["key"], "sk-hop-tenant-one");
        assert_eq!(dto["name"], "tenant");
        assert_eq!(dto["models"][0], "mock/one");
        assert_eq!(dto["max_concurrent"], 2);
        assert_eq!(dto["masked"], mask_key("sk-hop-tenant-one"));

        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("still a valid config");
        assert_eq!(parsed.client_keys.len(), 1);
        assert_eq!(parsed.client_keys[0].key, "sk-hop-tenant-one");
        assert_eq!(parsed.client_keys[0].max_concurrent, Some(2));

        // The same key cannot be added twice (the map is keyed by the secret).
        let dup = client_key_add(State(st.clone()), json(r#"{"key":"sk-hop-tenant-one"}"#)).await;
        assert!(dup.is_err(), "a duplicate key must be refused");

        // Generated keys go down the same path.
        let generated = client_key_add(State(st.clone()), json(r#"{"name":"second"}"#))
            .await
            .expect("generated");
        let generated = body_json(generated).await;
        assert!(
            generated["key"]
                .as_str()
                .unwrap_or("")
                .starts_with("sk-hop-"),
            "{generated}"
        );

        // Delete removes it from the map and from the file.
        client_key_delete(State(st.clone()), json(r#"{"key":"sk-hop-tenant-one"}"#))
            .await
            .expect("deleted");
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("still a valid config");
        assert_eq!(
            parsed.client_keys.len(),
            1,
            "only the generated key is left"
        );
        assert_ne!(parsed.client_keys[0].key, "sk-hop-tenant-one");
        assert!(!ck_read(&st).contains_key("sk-hop-tenant-one"));

        // Deleting something that is not there is a 404, not a silent success.
        assert!(
            client_key_delete(State(st.clone()), json(r#"{"key":"sk-hop-nope"}"#))
                .await
                .is_err()
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Input validation happens before anything is written: too-short keys, huge
    /// secrets, and unusable names must be refused without touching the config.
    #[tokio::test]
    async fn invalid_keys_are_refused_before_the_config_is_written() {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        let before = std::fs::read_to_string(&path).expect("read");

        let too_many_models = format!(
            r#"{{"key":"sk-hop-ok","models":[{}]}}"#,
            vec!["\"m\""; MAX_KEY_MODELS + 1].join(",")
        );
        for body in [
            r#"{"key":"abc"}"#.to_string(),
            r#"{"key":"sk-hop-ok","name":"bad/name"}"#.to_string(),
            too_many_models,
            r#"{"key":"sk-hop-ok","max_concurrent":10001}"#.to_string(),
        ] {
            let parsed: AddClientKey = serde_json::from_str(&body).expect("the case is valid JSON");
            assert!(
                client_key_add(State(st.clone()), Json(parsed))
                    .await
                    .is_err(),
                "{body} must be rejected"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            before,
            "a rejected add must not rewrite the config"
        );
        assert!(ck_read(&st).is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
