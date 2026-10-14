use gloo_net::eventsource::futures::EventSource;
use gloo_net::http::Request;
use serde::Deserialize;
use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;
use futures::StreamExt;

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct KeyDto {
    id: String,
    masked: String,
    status: String,
    cooldown_remaining_secs: u64,
    in_flight: u32,
    requests: u64,
    failures: u64,
    prompt_tokens: u64,
    completion_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct ProviderDto {
    name: String,
    kind: String,
    strategy: String,
    base_url: String,
    keys: Vec<KeyDto>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct QuotaModelDto {
    id: String,
    pct: Option<u64>,
    low: bool,
    reset: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct QuotaDto {
    provider: String,
    account: String,
    models: Vec<QuotaModelDto>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct EventDto {
    ts: u64,
    provider: String,
    key: String,
    kind: String,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Providers,
    Quotas,
    Events,
    Config,
}

const TABS: &[(Tab, &str)] = &[
    (Tab::Overview, "Overview"),
    (Tab::Providers, "Providers"),
    (Tab::Quotas, "Quotas"),
    (Tab::Events, "Events"),
    (Tab::Config, "Config"),
];

#[derive(Debug, Clone, PartialEq, Deserialize)]
struct AuthStateDto {
    kind: String,
    status: String,
    url: String,
    message: String,
}

fn fmt_time(ts: u64) -> String {
    let s = ts % 86400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

fn fmt_num(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(url: &str) -> Option<T> {
    Request::get(url).send().await.ok()?.json::<T>().await.ok()
}

async fn post_json<B: serde::Serialize>(url: &str, body: &B) {
    if let Ok(req) = Request::post(url).json(body) {
        let _ = req.send().await;
    }
}

fn main() {
    console_error_panic_hook::set_once();
    sycamore::render(App);
}

fn tab_from_hash() -> Tab {
    let hash = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .unwrap_or_default();
    match hash.trim_start_matches('#') {
        "providers" => Tab::Providers,
        "quotas" => Tab::Quotas,
        "events" => Tab::Events,
        "config" => Tab::Config,
        _ => Tab::Overview,
    }
}

fn current_theme() -> String {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
        .and_then(|e| e.get_attribute("data-theme"))
        .unwrap_or_else(|| "light".into())
}

fn set_theme(t: &str) {
    if let Some(w) = web_sys::window() {
        if let Some(e) = w.document().and_then(|d| d.document_element()) {
            let _ = e.set_attribute("data-theme", t);
        }
        if let Ok(Some(s)) = w.local_storage() {
            let _ = s.set_item("theme", t);
        }
    }
}

#[component]
fn ThemeToggle() -> View {
    let theme = create_signal(current_theme());
    view! {
        button(class="theme-btn", on:click=move |_| {
            let next = if theme.get_clone() == "dark" { "light" } else { "dark" };
            set_theme(next);
            theme.set(next.to_string());
        }) {
            span(class="sq") {}
            (if theme.get_clone() == "dark" { "Light" } else { "Dark" })
        }
    }
}

#[component]
fn App() -> View {
    let tab = create_signal(tab_from_hash());
    let providers = create_signal(Vec::<ProviderDto>::new());
    let quotas = create_signal(Vec::<QuotaDto>::new());
    let events = create_signal(Vec::<EventDto>::new());
    let loaded = create_signal(false);

    spawn_local({
        async move {
            loop {
                if let Some(data) = fetch_json::<Vec<ProviderDto>>("/api/providers").await {
                    providers.set(data);
                    loaded.set(true);
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    });

    spawn_local({
        async move {
            loop {
                if let Some(data) = fetch_json::<Vec<QuotaDto>>("/api/quotas").await {
                    quotas.set(data);
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    spawn_local({
        async move {
            loop {
                match EventSource::new("/api/events") {
                    Ok(mut es) => match es.subscribe("message") {
                        Ok(mut stream) => {
                            while let Some(item) = stream.next().await {
                                match item {
                                    Ok((_ty, msg)) => {
                                        if let Some(data) = msg.data().as_string()
                                            && let Ok(ev) = serde_json::from_str::<EventDto>(&data)
                                        {
                                            events.update(|v| {
                                                v.insert(0, ev);
                                                v.truncate(200);
                                            });
                                        }
                                    }
                                    Err(e) => {
                                        web_sys::console::warn_1(
                                            &format!("[anyhop] SSE item error: {:?}", e).into(),
                                        );
                                    }
                                }
                            }
                            web_sys::console::warn_1(&"[anyhop] SSE stream ended".into());
                        }
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!("[anyhop] SSE subscribe failed: {:?}", e).into(),
                            );
                        }
                    },
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("[anyhop] SSE new failed: {:?}", e).into(),
                        );
                    }
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    });

    view! {
        div(class="topbar") {}
        div(class="wrap") {
            div(class="top") {
                div {
                    div(class="logo") {
                        div(class="logo-mark") { i {} i {} i {} i {} }
                        span(class="logo-text") { "anyhop" }
                    }
                    div(class="tagline") { "LLM Gateway · Rotation · Failover" }
                }
                ThemeToggle()
            }

            nav(class="tabs") {
                Indexed(
                    list=create_signal(TABS.to_vec()),
                    view=move |(t, label)| {
                        let cur = tab;
                        view! {
                            button(
                                class=if cur.get() == t { "tab active" } else { "tab" },
                                on:click=move |_| {
                                    cur.set(t);
                                    let name = match t {
                                        Tab::Overview => "overview",
                                        Tab::Providers => "providers",
                                        Tab::Quotas => "quotas",
                                        Tab::Events => "events",
                                        Tab::Config => "config",
                                    };
                                    if let Some(w) = web_sys::window() {
                                        let _ = w.location().set_hash(name);
                                    }
                                },
                            ) { (label) }
                        }
                    },
                )
            }

            div(class="tab-content") {
                (match tab.get() {
                    Tab::Overview => view! { OverviewTab(providers=providers, events=events) },
                    Tab::Providers => view! { ProvidersTab(providers=providers) },
                    Tab::Quotas => view! { QuotasTab(quotas=quotas) },
                    Tab::Events => view! { EventsTab(events=events) },
                    Tab::Config => view! { ConfigTab() },
                })
            }

            div(class="footer") {
                span { "anyhop v" (env!("CARGO_PKG_VERSION")) }
                span(class="pix") { i {} i {} i {} i {} i {} }
                span { "self-hosted · zero deps" }
            }
        }
    }
}

// ---------- Обзор ----------

#[component(inline_props)]
fn OverviewTab(providers: Signal<Vec<ProviderDto>>, events: Signal<Vec<EventDto>>) -> View {
    let n_providers = create_memo(move || providers.get_clone().len());
    let total_requests = create_memo(move || {
        providers
            .get_clone()
            .iter()
            .flat_map(|p| p.keys.iter())
            .map(|k| k.requests)
            .sum::<u64>()
    });
    let total_tokens = create_memo(move || {
        providers
            .get_clone()
            .iter()
            .flat_map(|p| p.keys.iter())
            .map(|k| k.prompt_tokens + k.completion_tokens)
            .sum::<u64>()
    });
    let in_flight = create_memo(move || {
        providers
            .get_clone()
            .iter()
            .flat_map(|p| p.keys.iter())
            .map(|k| k.in_flight as u64)
            .sum::<u64>()
    });

    view! {
        div(class="stats") {
            div(class="stat") {
                div(class="num") { (n_providers.get_clone()) }
                div(class="lbl") { "Providers" }
            }
            div(class="stat") {
                div(class="num") { (fmt_num(in_flight.get_clone())) }
                div(class="lbl") { "In flight" }
            }
            div(class="stat") {
                div(class="num") { (fmt_num(total_requests.get_clone())) }
                div(class="lbl") { "Total requests" }
            }
            div(class="stat") {
                div(class="num") { (fmt_num(total_tokens.get_clone())) }
                div(class="lbl") { "Tokens processed" }
            }
        }
        div(class="section-title") { "Recent events" }
        div(class="card") {
            EventList(events=events, limit=5)
        }
    }
}

// ---------- Провайдеры ----------

#[component(inline_props)]
fn ProvidersTab(providers: Signal<Vec<ProviderDto>>) -> View {
    view! {
        Indexed(
            list=providers,
            view=|p| view! { ProviderCard(p=p) },
        )
    }
}

#[component(inline_props)]
fn ProviderCard(p: ProviderDto) -> View {
    let pname_rows = p.name.clone();
    let pname_footer = p.name.clone();
    let pkind_footer = p.kind.clone();
    let oauth = p.kind == "antigravity" || p.kind == "codex";

    // Агрегированный статус провайдера: зелёный/жёлтый/красный квадратик
    let health = {
        let total = p.keys.len();
        let dead = p.keys.iter().filter(|k| k.status == "dead").count();
        let cool = p.keys.iter().filter(|k| k.status == "cooldown").count();
        if total > 0 && dead == total {
            "pdot pdot-err"
        } else if dead + cool > 0 {
            "pdot pdot-warn"
        } else {
            "pdot pdot-ok"
        }
    };

    // Футер карточки собирается ДО view!, чтобы не тащить захваты в динамические замыкания.
    let footer = if oauth {
        view! { OAuthAddButton(kind=pkind_footer) }
    } else {
        view! { AddKeyForm(provider=pname_footer) }
    };

    view! {
        div(class="card") {
            div(class="card-head") {
                span(class=health) {}
                b { (p.name) }
                span(class="badge accent") { (p.kind) }
                span(class="badge") { (p.strategy) }
                span(class="badge raw") { (p.base_url) }
            }
            table {
                tr {
                    th { "Key" } th { "Status" } th { "Cooldown" } th { "In-flight" }
                    th { "Requests" } th { "Failures" } th { "Tokens in" } th { "Tokens out" } th { "" }
                }
                Indexed(
                    list=create_signal(p.keys),
                    view=move |k: KeyDto| {
                        let chip = format!("chip chip-{}", k.status);
                        let status = k.status.clone();
                        let prov = pname_rows.clone();
                        view! {
                            tr {
                                td(class="mono") { (k.masked) }
                                td { span(class=chip) { (k.status) } }
                                td(class="num") { (if k.cooldown_remaining_secs > 0 { format!("{}s", k.cooldown_remaining_secs) } else { "—".into() }) }
                                td(class="num") { (k.in_flight) }
                                td(class="num") { (fmt_num(k.requests)) }
                                td(class="num") { (fmt_num(k.failures)) }
                                td(class="num") { (fmt_num(k.prompt_tokens)) }
                                td(class="num") { (fmt_num(k.completion_tokens)) }
                                td { KeyActionButton(provider=prov, id=k.id.clone(), status=status) }
                            }
                        }
                    },
                )
            }
            (footer)
        }
    }
}

#[component(inline_props)]
fn OAuthAddButton(kind: String) -> View {
    let auth = create_signal(Option::<AuthStateDto>::None);
    let label = format!("Add {} account", kind);
    view! {
        div(class="addkey") {
            button(class="btn btn-primary", on:click=move |_| {
                let kind = kind.clone();
                spawn_local(async move {
                    let body = serde_json::json!({"kind": kind});
                    let Ok(req) = Request::post("/api/auth/start").json(&body) else { return };
                    let Ok(resp) = req.send().await else { return };
                    let Ok(v) = resp.json::<serde_json::Value>().await else { return };
                    let Some(url) = v.get("url").and_then(|u| u.as_str()).map(str::to_string) else { return };
                    auth.set(Some(AuthStateDto {
                        kind: kind.clone(),
                        status: "waiting".into(),
                        url: url.clone(),
                        message: "waiting for browser callback".into(),
                    }));
                    if let Some(w) = web_sys::window() {
                        let _ = w.open_with_url_and_target(&url, "_blank");
                    }
                    loop {
                        gloo_timers::future::sleep(std::time::Duration::from_secs(2)).await;
                        if let Some(s) = fetch_json::<AuthStateDto>("/api/auth/status").await {
                            let terminal = s.status != "waiting";
                            auth.set(Some(s));
                            if terminal { break; }
                        }
                    }
                });
            }) { (label) }
        }
        (match auth.get_clone() {
            Some(a) => {
                let cls = format!("auth-banner auth-{}", a.status);
                let msg = if a.status == "waiting" {
                    "Authorization opened in a new tab — complete the sign-in".to_string()
                } else {
                    a.message
                };
                view! { div(class=cls) { (msg) } }
            }
            None => view! {},
        })
    }
}

#[component(inline_props)]
fn AddKeyForm(provider: String) -> View {
    let new_key = create_signal(String::new());
    view! {
        div(class="addkey") {
            input(class="input", r#type="text", placeholder="add a key…",
                  bind:value=new_key)
            button(class="btn btn-primary", on:click=move |_| {
                let secret = new_key.get_clone();
                if secret.len() >= 4 {
                    new_key.set(String::new());
                    let provider = provider.clone();
                    spawn_local(async move {
                        let body = serde_json::json!({"provider": provider, "secret": secret});
                        post_json("/api/keys/add", &body).await;
                    });
                }
            }) { "Add" }
        }
    }
}

#[component(inline_props)]
fn KeyActionButton(provider: String, id: String, status: String) -> View {
    let dead = status == "dead";
    let label = if dead { "enable" } else { "disable" };
    let class = if dead { "btn" } else { "btn btn-danger" };
    let url = if dead { "/api/keys/enable" } else { "/api/keys/disable" };
    view! {
        button(class=class, on:click=move |_| {
            let body = serde_json::json!({"provider": provider.clone(), "id": id.clone()});
            spawn_local(async move {
                post_json(url, &body).await;
            });
        }) { (label) }
    }
}

// ---------- Квоты ----------

async fn fetch_text(url: &str) -> Option<String> {
    Request::get(url).send().await.ok()?.text().await.ok()
}

async fn put_json<B: serde::Serialize>(url: &str, body: &B) -> Option<String> {
    let req = Request::put(url).json(body).ok()?;
    let resp = req.send().await.ok()?;
    let ok = resp.status() == 200;
    let text = resp.text().await.ok()?;
    Some(if ok { "saved + reloaded".into() } else { text })
}

#[component]
fn ConfigTab() -> View {
    let toml = create_signal(String::new());
    let status = create_signal(String::new());
    let loaded = create_signal(false);

    spawn_local({
        let toml = toml;
        let loaded = loaded;
        async move {
            if let Some(t) = fetch_text("/api/config").await {
                toml.set(t);
                loaded.set(true);
            }
        }
    });

    view! {
        div(class="section-title") { "Config" }
        div(class="card") {
            (if loaded.get() {
                view! {
                    textarea(class="config-editor", bind:value=toml)
                }
            } else {
                view! { div(class="loading") { "Loading…" } }
            })
            div(class="config-actions") {
                button(class="btn btn-primary", on:click=move |_| {
                    let body = serde_json::json!({"toml": toml.get_clone()});
                    spawn_local(async move {
                        let msg = put_json("/api/config", &body).await
                            .unwrap_or_else(|| "request failed".into());
                        status.set(msg);
                    });
                }) { "Save & reload" }
                button(class="btn", on:click=move |_| {
                    spawn_local(async move {
                        let _ = Request::post("/api/reload").send().await;
                    });
                }) { "Reload from disk" }
                span(class="config-status") { (status.get_clone()) }
            }
        }
    }
}

#[component(inline_props)]
fn QuotasTab(quotas: Signal<Vec<QuotaDto>>) -> View {
    view! {
        (if quotas.get_clone().is_empty() {
            view! { div(class="card") { div(class="empty") {
                div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                "Quotas appear for OAuth providers (antigravity)"
            } } }
        } else {
            view! {
                div(class="quota-grid") {
                    Keyed(
                        list=quotas,
                        view=|q: QuotaDto| view! { QuotaCard(q=q) },
                        key=|q: &QuotaDto| format!("{}:{}", q.provider, q.account),
                    )
                }
            }
        })
    }
}

#[component(inline_props)]
fn QuotaCard(q: QuotaDto) -> View {
    let open = create_signal(false);
    // Сводка для свёрнутого состояния: худшая квота по аккаунту.
    let worst = q.models.iter().filter_map(|m| m.pct).min();
    let worst_txt = match worst {
        Some(p) => format!("min {}%", p),
        None => String::new(),
    };
    let worst_low = worst.is_some_and(|p| p < 10);

    view! {
        div(class=create_memo(move || if open.get() { "quota-card open" } else { "quota-card" })) {
            div(class="quota-card-head", on:click=move |_| open.set(!open.get())) {
                b { (q.provider) }
                span(class="badge raw") { (q.account) }
                span(class=if worst_low { "quota-worst low" } else { "quota-worst" }) { (worst_txt) }
                span(class="quota-caret") { (if open.get() { "–" } else { "+" }) }
            }
            div(class="quota-body") {
                Indexed(
                    list=create_signal(q.models),
                    view=|m: QuotaModelDto| {
                        let id = m.id.clone();
                        let title = m.id.clone();
                        let pct = m.pct;
                        let cls = if m.low { "quota-fill low" } else { "quota-fill" };
                        let width = pct.map(|p| format!("width:{}%", p)).unwrap_or_default();
                        let reset = if m.reset.is_empty() {
                            String::new()
                        } else {
                            m.reset.get(..10).unwrap_or(&m.reset).to_string()
                        };
                        view! {
                            div(class="quota-row") {
                                span(class="quota-name", title=title) { (id) }
                                (match pct {
                                    Some(p) => view! {
                                        div(class="quota-bar") { div(class=cls, style=width) {} }
                                        span(class="quota-pct") { (format!("{}%", p)) }
                                    },
                                    None => view! {
                                        div(class="quota-bar empty") {}
                                        span(class="quota-pct") { "—" }
                                    },
                                })
                                span(class="quota-reset") { (reset) }
                            }
                        }
                    },
                )
            }
        }
    }
}

// ---------- События ----------

#[component(inline_props)]
fn EventsTab(events: Signal<Vec<EventDto>>) -> View {
    view! {
        div(class="card") {
            EventList(events=events, limit=200)
        }
    }
}

#[component(inline_props)]
fn EventList(events: Signal<Vec<EventDto>>, limit: usize) -> View {
    let limited = create_memo(move || {
        events.get_clone().into_iter().take(limit).collect::<Vec<_>>()
    });
    view! {
        (if limited.get_clone().is_empty() {
            view! { div(class="empty") {
                div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                "No events yet — all quiet"
            } }
        } else {
            view! {
                div(class="events") {
                    Indexed(
                        list=create_signal(limited.get_clone()),
                        view=|e: EventDto| {
                            let kind_cls = format!("ev-kind ev-{}", e.kind);
                            let kind_txt = e.kind.clone();
                            view! {
                                div(class="ev") {
                                    span(class="ev-ts") { (fmt_time(e.ts)) }
                                    span(class=kind_cls) { (kind_txt) }
                                    b { (e.provider) }
                                    span(class="ev-detail") { (e.key) " — " (e.detail) }
                                }
                            }
                        },
                    )
                }
            }
        })
    }
}
