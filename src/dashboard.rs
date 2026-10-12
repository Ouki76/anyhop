//! Web dashboard: askama templates + htmx (polled table) + SSE (live failover feed).

use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::response::sse::{Event, Sse};
use futures::StreamExt;
use serde::Deserialize;

use crate::pool::KeySnapshot;
use crate::proxy::AppState;

struct ProviderView {
    name: String,
    kind: String,
    strategy: String,
    base_url: String,
    keys: Vec<KeySnapshot>,
}

fn collect_providers(router: &crate::providers::ProviderRouter) -> Vec<ProviderView> {
    router
        .providers
        .iter()
        .map(|p| ProviderView {
            name: p.name.clone(),
            kind: match p.kind {
                crate::config::ProviderKind::OpenaiCompat => "openai_compat",
                crate::config::ProviderKind::Gemini => "gemini",
                crate::config::ProviderKind::Antigravity => "antigravity",
                crate::config::ProviderKind::Anthropic => "anthropic",
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
    let router = state.router.load();
    let tpl = DashboardTemplate {
        providers: collect_providers(&router),
    };
    match tpl.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn keys_partial(State(state): State<Arc<AppState>>) -> Response {
    let router = state.router.load();
    let tpl = KeysTableTemplate {
        providers: collect_providers(&router),
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

fn set_key(state: &AppState, form: &KeyAction, enabled: bool) -> Response {
    let router = state.router.load();
    let Some(p) = router.providers.iter().find(|p| p.name == form.provider) else {
        return (StatusCode::NOT_FOUND, "unknown provider").into_response();
    };
    if p.pool.set_enabled(&form.id, enabled) {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "unknown key").into_response()
    }
}

pub async fn key_enable(State(state): State<Arc<AppState>>, Form(f): Form<KeyAction>) -> Response {
    set_key(&state, &f, true)
}

pub async fn key_disable(State(state): State<Arc<AppState>>, Form(f): Form<KeyAction>) -> Response {
    set_key(&state, &f, false)
}

pub async fn key_add(State(state): State<Arc<AppState>>, Form(f): Form<AddKey>) -> Response {
    let secret = f.secret.trim();
    if secret.len() < 4 {
        return (StatusCode::BAD_REQUEST, "key too short").into_response();
    }
    let router = state.router.load();
    let Some(p) = router.providers.iter().find(|p| p.name == f.provider) else {
        return (StatusCode::NOT_FOUND, "unknown provider").into_response();
    };
    if matches!(p.kind, crate::config::ProviderKind::Antigravity) {
        return (StatusCode::BAD_REQUEST, "antigravity accounts are added via `anyhop auth antigravity`").into_response();
    }
    p.pool.add_key(secret.to_string());
    if let Some(s) = &state.storage {
        s.save_extra_key(&p.name, secret);
    }
    StatusCode::OK.into_response()
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
