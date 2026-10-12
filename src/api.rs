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
use axum::http::StatusCode;
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
    let rx = state.events.subscribe();
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|ev| async move {
        match ev {
            Ok(e) => serde_json::to_string(&e)
                .ok()
                .map(|j| Ok(Event::default().data(j))),
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    )
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
