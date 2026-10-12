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
}

const TABS: &[(Tab, &str)] = &[
    (Tab::Overview, "Overview"),
    (Tab::Providers, "Providers"),
    (Tab::Quotas, "Quotas"),
    (Tab::Events, "Events"),
];

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
    let tab = create_signal(Tab::Overview);
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
                if let Ok(mut es) = EventSource::new("/api/events")
                    && let Ok(mut stream) = es.subscribe("message")
                {
                    while let Some(Ok((_ty, msg))) = stream.next().await {
                        if let Some(data) = msg.as_string()
                            && let Ok(ev) = serde_json::from_str::<EventDto>(&data)
                        {
                            events.update(|v| {
                                v.insert(0, ev);
                                v.truncate(200);
                            });
                        }
                    }
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    });

    let active_keys = create_memo(move || {
        providers
            .get_clone()
            .iter()
            .map(|p| p.keys.iter().filter(|k| k.status == "active").count())
            .sum::<usize>()
    });
    let total_keys = create_memo(move || {
        providers.get_clone().iter().map(|p| p.keys.len()).sum::<usize>()
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
                div(class="status-pill") {
                    div(class="pulse") {}
                    (format!("{}/{} keys active", active_keys.get_clone(), total_keys.get_clone()))
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
                                on:click=move |_| cur.set(t),
                            ) { (label) }
                        }
                    },
                )
            }

            (match tab.get() {
                Tab::Overview => view! { OverviewTab(providers=providers, events=events) },
                Tab::Providers => view! { ProvidersTab(providers=providers) },
                Tab::Quotas => view! { QuotasTab(quotas=quotas) },
                Tab::Events => view! { EventsTab(events=events) },
            })
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
    let new_key = create_signal(String::new());
    let pname_rows = p.name.clone();
    let pname_add = p.name.clone();
    let oauth = p.kind == "antigravity" || p.kind == "codex";

    view! {
        div(class="card") {
            div(class="card-head") {
                b { (p.name) }
                span(class="badge accent") { (p.kind) }
                span(class="badge") { (p.strategy) }
                span(class="badge") { (p.base_url) }
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
            (if !oauth {
                let pname2 = pname_add.clone();
                view! {
                    div(class="addkey") {
                        input(class="input", r#type="text", placeholder="add a key…",
                              bind:value=new_key)
                        button(class="btn btn-primary", on:click=move |_| {
                            let secret = new_key.get_clone();
                            if secret.len() >= 4 {
                                new_key.set(String::new());
                                let provider = pname2.clone();
                                spawn_local(async move {
                                    let body = serde_json::json!({"provider": provider, "secret": secret});
                                    post_json("/api/keys/add", &body).await;
                                });
                            }
                        }) { "Add" }
                    }
                }
            } else {
                view! {}
            })
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

#[component(inline_props)]
fn QuotasTab(quotas: Signal<Vec<QuotaDto>>) -> View {
    view! {
        (if quotas.get_clone().is_empty() {
            view! { div(class="card") { div(class="empty") { "Quotas appear for OAuth providers (antigravity)" } } }
        } else {
            view! {
                Indexed(
                    list=quotas,
                    view=|q: QuotaDto| view! {
                        div(class="card") {
                            div(class="card-head") {
                                b { (q.provider) }
                                span(class="badge") { (q.account) }
                            }
                            table {
                                tr { th { "Model" } th { "Remaining" } th { "Reset" } }
                                Indexed(
                                    list=create_signal(q.models),
                                    view=|m: QuotaModelDto| {
                                        let reset = if m.reset.is_empty() { "—".to_string() } else { m.reset.clone() };
                                        view! {
                                        tr {
                                            td(class="mono") { (m.id) }
                                            td {
                                                (match m.pct {
                                                    Some(pct) => {
                                                        let cls = if m.low { "quota-fill low" } else { "quota-fill" };
                                                        view! {
                                                            div(class="quota-bar") {
                                                                div(class=cls, style=format!("width: {}%", pct)) {}
                                                            }
                                                            span(class="quota-pct") { (format!("{}%", pct)) }
                                                        }
                                                    }
                                                    None => view! { "—" },
                                                })
                                            }
                                            td { (reset) }
                                        }
                                        }
                                    },
                                )
                            }
                        }
                    },
                )
            }
        })
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
            view! { div(class="empty") { "No events yet — all quiet" } }
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
