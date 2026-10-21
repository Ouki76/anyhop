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
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let text = doc.to_string();
    let parsed: crate::config::Config = match toml::from_str(&text) {
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
    if let Err(e) = crate::config::write_atomic(&state.config_path, &text) {
        return Err(Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot write config: {e}"),
            )
                .into_response(),
        ));
    }
    if let Err(e) = crate::reload_config(state) {
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                format!("config saved but reload failed: {e}"),
            )
                .into_response(),
        ));
    }
    Ok(())
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
