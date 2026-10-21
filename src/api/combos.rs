//! Combo (virtual model with a fallback chain) management.
//!
//! `GET  /api/combos`        list `{name, chain}`
//! `POST /api/combos/add`    {name, chain: ["provider/model", ...]}
//! `POST /api/combos/update` {name, chain}   (name is the key; chain replaced)
//! `POST /api/combos/delete` {name}
//!
//! Every mutation rewrites `[[combos]]` in the TOML (comments preserved) and
//! hot-reloads, after validating the *whole* file — an invalid chain is rejected
//! before anything is written, so the gateway cannot end up with a broken config.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::persist::write_validated;
use crate::proxy::AppState;

#[derive(Serialize, Deserialize)]
pub struct ComboDto {
    pub name: String,
    pub chain: Vec<String>,
}

#[derive(Deserialize)]
pub struct ComboBody {
    pub name: String,
    #[serde(default)]
    pub chain: Vec<String>,
}

/// Reject names that cannot be addressed as a model id or would confuse the
/// dashboard (`combo/` prefix is reserved, `/` splits provider from model).
fn clean_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("combo name must not be empty".into());
    }
    if n.contains('/') {
        return Err("combo name must not contain '/'".into());
    }
    if n.len() > 64 {
        return Err("combo name must be at most 64 characters".into());
    }
    Ok(n.to_string())
}

fn clean_chain(chain: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(chain.len());
    for entry in chain {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        if !e.contains('/') {
            return Err(format!(
                "'{e}' must be written as provider/model (e.g. openrouter/deepseek-chat)"
            ));
        }
        if !out.iter().any(|x| x == e) {
            out.push(e.to_string());
        }
    }
    if out.is_empty() {
        return Err("a combo needs at least one provider/model target".into());
    }
    Ok(out)
}

pub async fn combos(State(state): State<Arc<AppState>>) -> Response {
    let router = state.router.load();
    let list: Vec<ComboDto> = router
        .combos
        .iter()
        .map(|c| ComboDto {
            name: c.name.clone(),
            chain: c.chain.clone(),
        })
        .collect();
    Json(list).into_response()
}

fn toml_combo(name: &str, chain: &[String]) -> toml_edit::Table {
    let mut t = toml_edit::Table::new();
    t["name"] = toml_edit::value(name);
    let mut arr = toml_edit::Array::new();
    for c in chain {
        arr.push(c.as_str());
    }
    t["chain"] = toml_edit::value(arr);
    t
}

pub async fn combo_add(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ComboBody>,
) -> Response {
    let name = match clean_name(&body.name) {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let chain = match clean_chain(&body.chain) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let _guard = state.config_lock.lock().await;
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => return (StatusCode::NOT_FOUND, format!("cannot read config: {e}")).into_response(),
    };
    let mut doc = match raw.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("config parse error: {e}")).into_response();
        }
    };
    if !doc.contains_key("combos") {
        doc["combos"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let Some(arr) = doc["combos"].as_array_of_tables_mut() else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "'combos' is not an array of tables in the config file",
        )
            .into_response();
    };
    if arr
        .iter()
        .any(|c| c.get("name").and_then(|v| v.as_str()) == Some(name.as_str()))
    {
        return (StatusCode::CONFLICT, format!("combo '{name}' already exists"))
            .into_response();
    }
    arr.push(toml_combo(&name, &chain));
    finish(
        &state,
        doc,
        format!("combo '{name}' added"),
        Json(ComboDto { name, chain }).into_response(),
    )
    .await
}

pub async fn combo_update(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ComboBody>,
) -> Response {
    let name = match clean_name(&body.name) {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let chain = match clean_chain(&body.chain) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let _guard = state.config_lock.lock().await;
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => return (StatusCode::NOT_FOUND, format!("cannot read config: {e}")).into_response(),
    };
    let mut doc = match raw.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("config parse error: {e}")).into_response();
        }
    };
    let Some(arr) = doc
        .get_mut("combos")
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return (StatusCode::NOT_FOUND, "no combos in the config").into_response();
    };
    let Some(existing) = arr
        .iter_mut()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(name.as_str()))
    else {
        return (StatusCode::NOT_FOUND, format!("combo '{name}' not found")).into_response();
    };
    let mut arr_val = toml_edit::Array::new();
    for c in &chain {
        arr_val.push(c.as_str());
    }
    existing["chain"] = toml_edit::value(arr_val);
    finish(
        &state,
        doc,
        format!("combo '{name}' updated"),
        Json(ComboDto { name, chain }).into_response(),
    )
    .await
}

pub async fn combo_delete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ComboBody>,
) -> Response {
    let name = match clean_name(&body.name) {
        Ok(n) => n,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let _guard = state.config_lock.lock().await;
    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => return (StatusCode::NOT_FOUND, format!("cannot read config: {e}")).into_response(),
    };
    let mut doc = match raw.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("config parse error: {e}")).into_response();
        }
    };
    let Some(arr) = doc
        .get_mut("combos")
        .and_then(|i| i.as_array_of_tables_mut())
    else {
        return (StatusCode::NOT_FOUND, "no combos in the config").into_response();
    };
    let Some(idx) = arr
        .iter()
        .position(|c| c.get("name").and_then(|v| v.as_str()) == Some(name.as_str()))
    else {
        return (StatusCode::NOT_FOUND, format!("combo '{name}' not found")).into_response();
    };
    arr.remove(idx);
    finish(
        &state,
        doc,
        format!("combo '{name}' deleted"),
        StatusCode::OK.into_response(),
    )
    .await
}

/// Validate the edited document, write it, reload, and pass through `ok`.
async fn finish(
    state: &Arc<AppState>,
    doc: toml_edit::DocumentMut,
    event: String,
    ok: Response,
) -> Response {
    if let Err(resp) = write_validated(state, &doc).await {
        return resp;
    }
    state.events.emit_simple("config", "", "backoff", event);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_must_be_addressable() {
        assert_eq!(clean_name("  fast ").unwrap(), "fast");
        assert!(clean_name("").is_err());
        assert!(clean_name("   ").is_err());
        assert!(clean_name("a/b").is_err(), "a slash would be read as provider/model");
        assert!(clean_name(&"x".repeat(65)).is_err());
        assert!(clean_name(&"x".repeat(64)).is_ok());
    }

    #[test]
    fn chain_entries_must_be_provider_qualified() {
        let ok = clean_chain(&["a/m".into(), " b/m2 ".into()]).unwrap();
        assert_eq!(ok, vec!["a/m".to_string(), "b/m2".to_string()]);
        // Duplicates collapse, keeping the first occurrence order.
        let dedup = clean_chain(&["a/m".into(), "a/m".into(), "b/m".into()]).unwrap();
        assert_eq!(dedup, vec!["a/m".to_string(), "b/m".to_string()]);
        assert!(clean_chain(&[]).is_err());
        assert!(clean_chain(&["no-slash".into()]).is_err());
    }

    #[test]
    fn toml_table_round_trips() {
        let t = toml_combo("fast", &["a/m".to_string(), "b/n".to_string()]);
        let mut root = toml_edit::DocumentMut::new();
        let mut arr = toml_edit::ArrayOfTables::new();
        arr.push(t);
        root["combos"] = toml_edit::Item::ArrayOfTables(arr);
        let parsed: crate::config::Config = toml::from_str(&root.to_string()).unwrap();
        assert_eq!(parsed.combos.len(), 1);
        assert_eq!(parsed.combos[0].name, "fast");
        assert_eq!(parsed.combos[0].chain, vec!["a/m", "b/n"]);
    }
}