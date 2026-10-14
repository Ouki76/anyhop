//! JSON management API — always enabled, the dashboard is just a client of it.
//!
//! GET  /api/providers          providers + key snapshots
//! GET  /api/quotas             per-account model quotas (antigravity)
//! GET  /api/events             SSE stream of failover events (JSON)
//! POST /api/keys/enable        {provider, id}
//! POST /api/keys/disable       {provider, id}
//! POST /api/keys/add           {provider, secret}

use std::convert::Infallible;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::config::ProviderKind;
use crate::pool::KeySnapshot;
use crate::proxy::AppState;

#[derive(Serialize)]
pub struct ProviderDto {
    name: String,
    kind: &'static str,
    strategy: &'static str,
    base_url: String,
    keys: Vec<KeySnapshot>,
}

pub async fn providers(State(state): State<Arc<AppState>>) -> Response {
    let router = state.router.load();
    let data: Vec<ProviderDto> = router
        .providers
        .iter()
        .map(|p| ProviderDto {
            name: p.name.clone(),
            kind: match p.kind {
                ProviderKind::OpenaiCompat => "openai_compat",
                ProviderKind::Gemini => "gemini",
                ProviderKind::Antigravity => "antigravity",
                ProviderKind::Anthropic => "anthropic",
                ProviderKind::Codex => "codex",
            },
            strategy: match p.strategy {
                crate::config::Strategy::RoundRobin => "round_robin",
                crate::config::Strategy::LeastUsed => "least_used",
                crate::config::Strategy::FillFirst => "fill_first",
            },
            base_url: p.base_url.clone(),
            keys: p.pool.snapshot(),
        })
        .collect();
    Json(data).into_response()
}

#[derive(Serialize)]
pub struct QuotaModelDto {
    id: String,
    pct: Option<u64>,
    low: bool,
    reset: String,
}

#[derive(Serialize)]
pub struct QuotaDto {
    provider: String,
    account: String,
    models: Vec<QuotaModelDto>,
}

pub async fn quotas(State(state): State<Arc<AppState>>) -> Response {
    let router = state.router.load();
    let mut out = Vec::new();
    for p in &router.providers {
        for (account, models) in p.quotas().await {
            out.push(QuotaDto {
                provider: p.name.clone(),
                account,
                models: models
                    .into_iter()
                    .map(|m| {
                        let pct = m.remaining_fraction.map(|f| (f * 100.0).round() as u64);
                        QuotaModelDto {
                            id: m.id,
                            pct,
                            low: pct.is_some_and(|p| p < 10),
                            reset: m.reset_time.unwrap_or_default(),
                        }
                    })
                    .collect(),
            });
        }
    }
    Json(out).into_response()
}

pub async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let replay = futures::stream::iter(
        state
            .events
            .recent()
            .into_iter()
            .filter_map(|e| serde_json::to_string(&e).ok())
            .map(|j| Ok(Event::default().data(j))),
    );
    let rx = state.events.subscribe();
    let live = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|ev| async move {
        match ev {
            Ok(e) => serde_json::to_string(&e)
                .ok()
                .map(|j| Ok(Event::default().data(j))),
            Err(_) => None,
        }
    });
    let stream = replay.chain(live);
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    )
}

// ---------- config management ----------

/// GET /api/config — raw TOML.
pub async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    match std::fs::read_to_string(&state.config_path) {
        Ok(toml) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], toml).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, format!("cannot read config: {e}")).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ConfigUpdate {
    toml: String,
}

/// PUT /api/config — validate, write, hot-reload.
pub async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ConfigUpdate>,
) -> Response {
    if let Err(e) = toml::from_str::<crate::config::Config>(&body.toml) {
        return (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response();
    }
    if let Err(e) = std::fs::write(&state.config_path, &body.toml) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("cannot write config: {e}"))
            .into_response();
    }
    match crate::reload_config(&state) {
        Ok(n) => {
            state
                .events
                .emit_simple("config", "", "backoff", format!("config saved, {n} providers reloaded"));
            StatusCode::OK.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("config saved but reload failed: {e}"))
            .into_response(),
    }
}

/// POST /api/reload — re-read config from disk.
pub async fn reload(State(state): State<Arc<AppState>>) -> Response {
    match crate::reload_config(&state) {
        Ok(n) => (StatusCode::OK, format!("reloaded {n} providers")).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("reload failed: {e}")).into_response(),
    }
}

// ---------- OAuth account onboarding from the dashboard ----------

#[derive(Clone, serde::Serialize)]
pub struct AuthStateDto {
    kind: String,
    status: String, // waiting | done | error
    url: String,
    message: String,
}

#[derive(Deserialize)]
pub struct AuthStart {
    kind: String,
}

pub async fn auth_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthStart>,
) -> Response {
    let is_ag = body.kind == "antigravity";
    if !is_ag && body.kind != "codex" {
        return (StatusCode::BAD_REQUEST, "kind must be antigravity|codex").into_response();
    }
    // A flow is already waiting: hand back its URL instead of re-binding the port.
    {
        let g = state.auth_state.lock().unwrap();
        if let Some(a) = g.as_ref()
            && a.status == "waiting"
        {
            return Json(serde_json::json!({"url": a.url, "resumed": true})).into_response();
        }
    }
    let kind = body.kind.clone();
    let (url, wait): (String, std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<(String, Option<String>, Option<String>, Option<String>)>> + Send>>) =
        if is_ag {
            let pending = match crate::antigravity::start_auth(None).await {
                Ok(p) => p,
                Err(e) => return (StatusCode::CONFLICT, e.to_string()).into_response(),
            };
            let url = pending.url.clone();
            (url, Box::pin(async move {
                crate::antigravity::complete_auth(pending)
                    .await
                    .map(|o| (o.refresh_token, o.email, o.project_id, None))
            }))
        } else {
            let pending = match crate::codex::start_auth(None).await {
                Ok(p) => p,
                Err(e) => return (StatusCode::CONFLICT, e.to_string()).into_response(),
            };
            let url = pending.url.clone();
            (url, Box::pin(async move {
                crate::codex::complete_auth(pending)
                    .await
                    .map(|o| (o.refresh_token, o.email, None, o.account_id))
            }))
        };

    *state.auth_state.lock().unwrap() = Some(AuthStateDto {
        kind: kind.clone(),
        status: "waiting".into(),
        url: url.clone(),
        message: "waiting for browser callback".into(),
    });

    let st = state.clone();
    tokio::spawn(async move {
        // Abandoned flows must not hold the callback port forever.
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(300), wait).await;
        let outcome = match outcome {
            Ok(o) => o,
            Err(_) => {
                let mut g = st.auth_state.lock().unwrap();
                if let Some(a) = g.as_mut() {
                    a.status = "error".into();
                    a.message = "authorization timed out (5 min)".into();
                }
                return;
            }
        };
        match outcome {
            Ok((refresh_token, email, project_id, account_id)) => {
                let msg = match append_account(&st.config_path, &kind, &refresh_token, email.as_deref(), project_id.as_deref(), account_id.as_deref()) {
                    Ok(()) => match crate::reload_config(&st) {
                        Ok(_) => "account added and config reloaded".to_string(),
                        Err(e) => format!("account saved, reload failed: {e}"),
                    },
                    Err(e) => format!("account obtained but config update failed: {e}"),
                };
                let mut g = st.auth_state.lock().unwrap();
                if let Some(a) = g.as_mut() {
                    a.status = "done".into();
                    a.message = msg;
                }
                st.events.emit_simple("auth", "", "backoff", "account added via dashboard".into());
            }
            Err(e) => {
                let mut g = st.auth_state.lock().unwrap();
                if let Some(a) = g.as_mut() {
                    a.status = "error".into();
                    a.message = e.to_string();
                }
            }
        }
    });

    Json(serde_json::json!({"url": url})).into_response()
}

pub async fn auth_status(State(state): State<Arc<AppState>>) -> Response {
    let g = state.auth_state.lock().unwrap().clone();
    Json(g).into_response()
}

/// Append an OAuth account to the config file, preserving existing content.
fn append_account(
    path: &str,
    kind: &str,
    refresh_token: &str,
    email: Option<&str>,
    project_id: Option<&str>,
    account_id: Option<&str>,
) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let mut doc: toml::Value = toml::from_str(&raw)?;
    let providers = doc
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a table"))?
        .entry("providers")
        .or_insert_with(|| toml::Value::Array(vec![]));
    let arr = providers
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("'providers' is not an array"))?;

    // Find the first provider of this kind, else create it.
    let idx = arr.iter().position(|p| {
        p.get("type").and_then(|t| t.as_str()) == Some(kind)
    });
    let idx = match idx {
        Some(i) => i,
        None => {
            let mut t = toml::map::Map::new();
            t.insert("name".into(), kind.into());
            t.insert("type".into(), kind.into());
            t.insert("strategy".into(), "fill_first".into());
            arr.push(toml::Value::Table(t));
            arr.len() - 1
        }
    };
    let provider = arr[idx]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("provider entry is not a table"))?;
    let accounts = provider
        .entry("accounts")
        .or_insert_with(|| toml::Value::Array(vec![]));
    let accounts = accounts
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("'accounts' is not an array"))?;

    let mut acc = toml::map::Map::new();
    if let Some(e) = email {
        acc.insert("email".into(), e.into());
    }
    acc.insert("refresh_token".into(), refresh_token.into());
    if let Some(p) = project_id {
        acc.insert("project_id".into(), p.into());
    }
    if let Some(a) = account_id {
        acc.insert("account_id".into(), a.into());
    }
    accounts.push(toml::Value::Table(acc));

    std::fs::write(path, toml::to_string_pretty(&doc)?)?;
    Ok(())
}

// ---------- provider management ----------

#[derive(Deserialize)]
pub struct AddProvider {
    kind: String,
    name: Option<String>,
    base_url: Option<String>,
    key: Option<String>,
}

/// POST /api/providers/add — append a key-based provider to the config.
pub async fn provider_add(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddProvider>,
) -> Response {
    let default_base = match body.kind.as_str() {
        "gemini" => Some("https://generativelanguage.googleapis.com/v1beta"),
        "anthropic" => Some("https://api.anthropic.com"),
        "openai_compat" => None,
        _ => {
            return (StatusCode::BAD_REQUEST, "kind must be gemini|anthropic|openai_compat")
                .into_response();
        }
    };
    let base_url = body.base_url.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let base_url = match base_url.or(default_base) {
        Some(b) => b.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, "base_url is required for openai_compat")
                .into_response();
        }
    };
    let key = body.key.as_deref().map(str::trim).filter(|s| !s.is_empty());

    let raw = match std::fs::read_to_string(&state.config_path) {
        Ok(r) => r,
        Err(e) => return (StatusCode::NOT_FOUND, format!("cannot read config: {e}")).into_response(),
    };
    let mut doc: toml::Value = match toml::from_str(&raw) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("config parse error: {e}")).into_response(),
    };
    let providers = doc
        .as_table_mut()
        .expect("config root")
        .entry("providers")
        .or_insert_with(|| toml::Value::Array(vec![]));
    let arr = providers.as_array_mut().expect("providers array");

    // Уникальное имя: kind, kind-2, kind-3…
    let base_name = body.name.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
        .unwrap_or_else(|| body.kind.clone());
    let mut name = base_name.clone();
    let mut n = 2;
    while arr.iter().any(|p| p.get("name").and_then(|v| v.as_str()) == Some(&name)) {
        name = format!("{base_name}-{n}");
        n += 1;
    }

    let mut t = toml::map::Map::new();
    t.insert("name".into(), name.clone().into());
    t.insert("type".into(), body.kind.clone().into());
    t.insert("base_url".into(), base_url.into());
    t.insert("strategy".into(), "round_robin".into());
    if let Some(k) = key {
        t.insert("keys".into(), toml::Value::Array(vec![k.into()]));
    }
    arr.push(toml::Value::Table(t));

    let serialized = match toml::to_string_pretty(&doc) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = std::fs::write(&state.config_path, serialized) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("cannot write config: {e}"))
            .into_response();
    }
    match crate::reload_config(&state) {
        Ok(_) => {
            state.events.emit_simple("config", "", "backoff", format!("provider '{name}' added"));
            Json(serde_json::json!({"name": name})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("saved but reload failed: {e}")).into_response(),
    }
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

fn set_key(state: &AppState, action: &KeyAction, enabled: bool) -> Response {
    let router = state.router.load();
    let Some(p) = router.providers.iter().find(|p| p.name == action.provider) else {
        return (StatusCode::NOT_FOUND, "unknown provider").into_response();
    };
    if p.pool.set_enabled(&action.id, enabled) {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "unknown key").into_response()
    }
}

pub async fn key_enable(
    State(state): State<Arc<AppState>>,
    Json(a): Json<KeyAction>,
) -> Response {
    set_key(&state, &a, true)
}

pub async fn key_disable(
    State(state): State<Arc<AppState>>,
    Json(a): Json<KeyAction>,
) -> Response {
    set_key(&state, &a, false)
}

pub async fn key_add(State(state): State<Arc<AppState>>, Json(a): Json<AddKey>) -> Response {
    let secret = a.secret.trim();
    if secret.len() < 4 {
        return (StatusCode::BAD_REQUEST, "key too short").into_response();
    }
    let router = state.router.load();
    let Some(p) = router.providers.iter().find(|p| p.name == a.provider) else {
        return (StatusCode::NOT_FOUND, "unknown provider").into_response();
    };
    if matches!(p.kind, ProviderKind::Antigravity | ProviderKind::Codex) {
        return (
            StatusCode::BAD_REQUEST,
            "OAuth accounts are added via `anyhop auth …`",
        )
            .into_response();
    }
    p.pool.add_key(secret.to_string());
    if let Some(s) = &state.storage {
        s.save_extra_key(&p.name, secret);
    }
    StatusCode::OK.into_response()
}
