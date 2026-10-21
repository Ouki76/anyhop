use std::convert::Infallible;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::Serialize;

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
    models: Vec<String>,
    /// Settings the dashboard can edit (`POST /api/providers/update`).
    max_concurrent: u32,
    drain_below_pct: u32,
    proxy: Option<String>,
    /// OAuth providers get accounts instead of keys: the UI must not offer
    /// "add key" there.
    oauth: bool,
    /// Per-provider overrides of the global attempt budget.
    timeout_secs: u64,
    max_retries: usize,
    /// Pass-through endpoints this provider declared (`images`, `audio`,
    /// `realtime`). Read-only here: they are edited in the TOML or through
    /// `POST /api/providers/update`, and the dashboard only displays them.
    capabilities: Vec<String>,
}

pub async fn providers(State(state): State<Arc<AppState>>) -> Response {
    let router = state.router.load();
    let mut data = Vec::new();
    for p in &router.providers {
        data.push((p, p.effective_models().await));
    }
    let data: Vec<ProviderDto> = data
        .iter()
        .map(|(p, models)| ProviderDto {
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
            models: models.as_ref().clone(),
            max_concurrent: p.max_concurrent,
            drain_below_pct: p.drain_below_pct,
            proxy: p.proxy.as_deref().map(super::mask_proxy),
            oauth: matches!(p.kind, ProviderKind::Antigravity | ProviderKind::Codex),
            timeout_secs: p.timeout.as_secs(),
            max_retries: p.max_retries,
            capabilities: p.capabilities.clone(),
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

/// GET /api/requests — recent upstream attempts (newest first).
pub async fn requests(State(state): State<Arc<AppState>>) -> Response {
    // Poison-recovering (see `pool::lock`): the log holds plain records, and a
    // panic while holding it must not break the Requests tab forever.
    let data: Vec<_> = state
        .request_log
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .rev()
        .cloned()
        .collect();
    Json(data).into_response()
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
            .interval(state.tuning.sse_keepalive())
            .text("ping"),
    )
}
