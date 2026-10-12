//! Web dashboard: askama templates + htmx (polled table) + SSE (live failover feed).

use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::response::sse::{Event, Sse};
use futures::StreamExt;

use crate::pool::KeySnapshot;
use crate::proxy::AppState;

struct ProviderView {
    name: String,
    kind: String,
    strategy: String,
    base_url: String,
    keys: Vec<KeySnapshot>,
}

fn collect_providers(state: &AppState) -> Vec<ProviderView> {
    state
        .router
        .providers
        .iter()
        .map(|p| ProviderView {
            name: p.name.clone(),
            kind: match p.kind {
                crate::config::ProviderKind::OpenaiCompat => "openai_compat",
                crate::config::ProviderKind::Gemini => "gemini",
                crate::config::ProviderKind::Antigravity => "antigravity",
            }
            .to_string(),
            strategy: match p.strategy {
                crate::config::Strategy::RoundRobin => "round_robin",
                crate::config::Strategy::LeastUsed => "least_used",
                crate::config::Strategy::FillFirst => "fill_first",
            }
            .to_string(),
            base_url: p.base_url.clone(),
            keys: p.pool.snapshot(),
        })
        .collect()
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    providers: Vec<ProviderView>,
}

#[derive(Template)]
#[template(path = "keys_table.html")]
struct KeysTableTemplate {
    providers: Vec<ProviderView>,
}

pub async fn index(State(state): State<Arc<AppState>>) -> Response {
    let tpl = DashboardTemplate {
        providers: collect_providers(&state),
    };
    match tpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn keys_partial(State(state): State<Arc<AppState>>) -> Response {
    let tpl = KeysTableTemplate {
        providers: collect_providers(&state),
    };
    match tpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn events_sse(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|ev| async move {
        match ev {
            Ok(e) => Some(Ok(Event::default().data(e.to_html()))),
            Err(_) => None, // lagged — just drop
        }
    });
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    )
}

pub async fn htmx_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("../assets/htmx.min.js"),
    )
        .into_response()
}

pub async fn htmx_sse_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        include_str!("../assets/htmx-sse.js"),
    )
        .into_response()
}
