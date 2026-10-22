use std::sync::Arc;

use crate::proxy::AppState;

pub(crate) async fn persist_client_keys(state: &Arc<AppState>) {
    let all: Vec<_> = state
        .client_keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|r| r.cfg.clone())
        .collect();
    // Serialize config rewrites: a concurrent writer reading the pre-write
    // file would silently drop this update from disk.
    let _guard = state.config_lock.lock().await;
    if let Err(e) = save_client_keys_to_toml(&state.config_path, &all) {
        tracing::warn!("cannot persist client_keys to config: {e}");
    }
}

pub(crate) async fn persist_disabled_models(state: &Arc<AppState>) {
    let all: Vec<_> = state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect();
    let _guard = state.config_lock.lock().await;
    if let Err(e) = save_disabled_models_to_toml(&state.config_path, &all) {
        tracing::warn!("cannot persist disabled_models to config: {e}");
    }
}

/// Validate an edited config document *before* writing it, then write + reload.
///
/// Writing first and reloading second (the old pattern) could leave a file on
/// disk that the running gateway refuses to load — a config that bricks the next
/// restart. Here a bad edit is rejected while the previous file is still intact.
pub(crate) async fn write_validated(
    state: &Arc<AppState>,
    doc: &toml_edit::DocumentMut,
) -> Result<(), Box<axum::response::Response>> {
    commit_config_text(state, &doc.to_string())
        .await
        .map(|_| ())
}

/// Parse, validate, build the router, write, swap — in that order.
///
/// `crate::apply_config` does the build before the write, so a config that the
/// validator accepts but the runtime rejects (a proxy URL `reqwest` cannot parse,
/// for instance) is refused while the old file is still the one on disk. Returns
/// the number of providers that were installed.
pub(crate) async fn commit_config_text(
    state: &Arc<AppState>,
    text: &str,
) -> Result<usize, Box<axum::response::Response>> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let parsed: crate::config::Config = match toml::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            return Err(Box::new(
                (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response(),
            ));
        }
    };
    if let Err(e) = parsed.validate() {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response(),
        ));
    }
    match crate::apply_config(state, parsed, text) {
        Ok(n) => Ok(n),
        // A rejected build never reached the disk; a write failure left the file
        // (and the live router) as it was — report which one it was.
        Err(crate::ConfigApplyError::Build(e)) => Err(Box::new(
            (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response(),
        )),
        Err(crate::ConfigApplyError::Write(e)) => Err(Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot write config: {e}"),
            )
                .into_response(),
        )),
    }
}

/// toml_edit keeps the rest of the file (comments, key order) untouched.
pub fn save_client_keys_to_toml(
    path: &str,
    keys: &[crate::config::ClientKeyConfig],
) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;

    let mut arr = toml_edit::ArrayOfTables::new();
    for k in keys {
        let mut t = toml_edit::Table::new();
        t["key"] = toml_edit::value(k.key.clone());
        if let Some(name) = &k.name {
            t["name"] = toml_edit::value(name.clone());
        }
        let mut models = toml_edit::Array::new();
        for m in &k.models {
            models.push(m.as_str());
        }
        t["models"] = toml_edit::value(models);
        if let Some(ca) = k.created_at {
            t["created_at"] = toml_edit::value(ca as i64);
        }
        if let Some(rpm) = k.rpm {
            t["rpm"] = toml_edit::value(rpm as i64);
        }
        if let Some(burst) = k.burst {
            t["burst"] = toml_edit::value(burst as i64);
        }
        // Without this every client-key edit silently dropped the key's
        // concurrency cap, and the next reload fell back to "unlimited".
        if let Some(max_concurrent) = k.max_concurrent {
            t["max_concurrent"] = toml_edit::value(max_concurrent as i64);
        }
        arr.push(t);
    }
    doc["client_keys"] = toml_edit::Item::ArrayOfTables(arr);

    crate::config::write_atomic(path, &doc.to_string())?;
    Ok(())
}

pub fn save_disabled_models_to_toml(path: &str, disabled: &[String]) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;

    let mut arr = toml_edit::Array::new();
    for s in disabled {
        arr.push(s.as_str());
    }
    doc["disabled_models"] = toml_edit::value(arr);

    crate::config::write_atomic(path, &doc.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!(
            "anyhop-persist-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("anyhop.toml");
        std::fs::write(&path, "listen = \"127.0.0.1:1\"\n").expect("seed");
        let s = path.to_str().expect("utf-8").to_string();
        (path, s)
    }

    fn key(
        rpm: Option<u32>,
        burst: Option<u32>,
        max_concurrent: Option<u32>,
    ) -> crate::config::ClientKeyConfig {
        crate::config::ClientKeyConfig {
            key: "sk-tenant".to_string(),
            name: Some("tenant".to_string()),
            models: vec!["m1".to_string()],
            created_at: Some(1_700_000_000),
            rpm,
            burst,
            max_concurrent,
        }
    }

    /// F: `max_concurrent` was missing from the writer, so every client-key edit
    /// (add/update/delete of *any* key) rewrote the file without it — silently
    /// removing every tenant's concurrency cap. The next reload then fell back to
    /// `[server] client_key_max_concurrent` (usually unlimited).
    #[test]
    fn the_client_key_round_trip_keeps_max_concurrent() {
        let (dir, path) = scratch("max-concurrent");
        let keys = vec![key(Some(60), Some(5), Some(3))];
        save_client_keys_to_toml(&path, &keys).expect("write");

        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("parse back");
        assert_eq!(
            parsed.client_keys[0].max_concurrent,
            Some(3),
            "the concurrency cap was dropped by the TOML round-trip"
        );
        // The rest of the record survives too.
        assert_eq!(parsed.client_keys[0].rpm, Some(60));
        assert_eq!(parsed.client_keys[0].burst, Some(5));
        assert_eq!(parsed.client_keys[0].models, vec!["m1".to_string()]);

        // An unset cap stays unset (no bogus 0 written).
        let keys = vec![key(None, None, None)];
        save_client_keys_to_toml(&path, &keys).expect("write");
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("parse back");
        assert_eq!(parsed.client_keys[0].max_concurrent, None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rewritten config must stay owner-only (it holds no client secrets here,
    /// but the same writer produces the provider config).
    #[cfg(unix)]
    #[test]
    fn rewriting_client_keys_keeps_the_file_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = scratch("perms");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        save_client_keys_to_toml(&path, &[key(None, None, Some(1))]).expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o077, 0, "config mode {mode:o} is not owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
