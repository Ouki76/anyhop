use gloo_net::eventsource::futures::EventSource;
use gloo_net::http::Request;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use sycamore::prelude::*;
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

fn fmt_time(ts: u64) -> String {
    let s = ts % 86400;
    format!("{:02}:{:02}:{:02}Z", s / 3600, (s / 60) % 60, s % 60)
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

#[component]
fn App() -> View {
    let providers = create_signal(Vec::<ProviderDto>::new());
    let quotas = create_signal(Vec::<QuotaDto>::new());
    let events = create_signal(Vec::<EventDto>::new());
    let loaded = create_signal(false);

    // Poll providers every 3s.
    spawn_local({
        let providers = providers;
        let loaded = loaded;
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

    // Poll quotas every 60s (first fetch right away).
    spawn_local({
        let quotas = quotas;
        async move {
            loop {
                if let Some(data) = fetch_json::<Vec<QuotaDto>>("/api/quotas").await {
                    quotas.set(data);
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    // Live failover events via SSE.
    spawn_local({
        let events = events;
        async move {
            loop {
                match EventSource::new("/api/events") {
                    Ok(mut es) => {
                        match es.subscribe("message") {
                            Ok(mut stream) => {
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
                            Err(_) => {}
                        }
                    }
                    Err(_) => {}
                }
                // Reconnect after a pause.
                gloo_timers::future::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    });

    view! {
        div(class="wrap") {
            header {
                h1 { "anyhop" span(class="dot") { "." } }
                span(class="sub") { "LLM gateway · key rotation · failover" }
            }
            (if loaded.get() {
                view! {
                    ProvidersView(providers=*providers)
                    QuotasView(quotas=*quotas)
                    EventsView(events=*events)
                }
            } else {
                view! { div(class="loading") { "Загрузка…" } }
            })
        }
    }
}

#[component(inline_props)]
fn ProvidersView(providers: ReadSignal<Vec<ProviderDto>>) -> View {
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
        div(class="provider") {
            div(class="provider-head") {
                b { (p.name) }
                span(class="badge") { (p.kind) }
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
                                td { (if k.cooldown_remaining_secs > 0 { format!("{}s", k.cooldown_remaining_secs) } else { "—".into() }) }
                                td { (k.in_flight) }
                                td { (k.requests) }
                                td { (k.failures) }
                                td { (k.prompt_tokens) }
                                td { (k.completion_tokens) }
                                td { KeyActionButton(provider=prov, id=k.id.clone(), status=status) }
                            }
                        }
                    },
                )
            }
            (if !oauth {
                let pname2 = pname_add.clone();
                view! {
                    div(style="padding: 8px 16px;") {
                        div(class="addkey") {
                            input(class="input", r#type="text", placeholder="добавить ключ…",
                                  bind:value=new_key)
                            button(class="btn", on:click=move |_| {
                                let secret = new_key.get_clone();
                                let provider = pname2.clone();
                                spawn_local(async move {
                                    let body = serde_json::json!({"provider": provider, "secret": secret});
                                    post_json("/api/keys/add", &body).await;
                                });
                            }) { "add key" }
                        }
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

#[component(inline_props)]
fn QuotasView(quotas: ReadSignal<Vec<QuotaDto>>) -> View {
    view! {
        h2 { "Квоты аккаунтов" }
        Indexed(
            list=quotas,
            view=|q: QuotaDto| view! {
                div(class="provider") {
                    div(class="provider-head") {
                        b { (q.provider) }
                        span(class="badge") { (q.account) }
                    }
                    table {
                        tr { th { "Model" } th { "Remaining" } th { "Reset" } }
                        Indexed(
                            list=create_signal(q.models),
                            view=|m: QuotaModelDto| view! {
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
                                    td { (if m.reset.is_empty() { "—".to_string() } else { m.reset.clone() }) }
                                }
                            },
                        )
                    }
                }
            },
        )
    }
}

#[component(inline_props)]
fn EventsView(events: ReadSignal<Vec<EventDto>>) -> View {
    view! {
        h2 { "Failover events (live)" }
        div(class="events") {
            Indexed(
                list=events,
                view=|e: EventDto| {
                    let kind_cls = e.kind.clone();
                    let kind_txt = e.kind.clone();
                    view! {
                        div(class=format!("ev ev-{}", kind_cls)) {
                            span(class="ev-ts") { (fmt_time(e.ts)) }
                            b { (e.provider) }
                            " [" (kind_txt) "] " (e.key) " — " (e.detail)
                        }
                    }
                },
            )
        }
    }
}
