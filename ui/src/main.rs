mod tabs;
mod types;
mod util;

use futures::StreamExt;
use gloo_net::eventsource::futures::EventSource;
use sycamore::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use tabs::*;
use types::*;
use util::*;

fn main() {
    console_error_panic_hook::set_once();
    sycamore::render(App);
}

/// Writing to signals from external sources (SSE, timers, hashchange) must not
/// happen synchronously: an incoming event may land inside someone else's effect
/// and sycamore panics with BorrowMutError. Defer to a macrotask.
fn tab_from_hash() -> Tab {
    let hash = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .unwrap_or_default();
    let h = hash.trim_start_matches('#');
    if h.starts_with("providers") {
        Tab::Providers
    } else {
        match h {
            "models" => Tab::Models,
            "keys" | "api-keys" => Tab::ApiKeys,
            "quotas" => Tab::Quotas,
            "events" => Tab::Events,
            "requests" => Tab::Requests,
            "settings" => Tab::Settings,
            "config" => Tab::Config,
            _ => Tab::Overview,
        }
    }
}

/// #providers/<name> -> Some(name)
fn provider_from_hash() -> Option<String> {
    let hash = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .unwrap_or_default();
    hash.trim_start_matches('#')
        .strip_prefix("providers/")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[component]
fn AuthBanner() -> View {
    let key = create_signal(String::new());
    view! {
        div(class="auth-banner auth-waiting", style="margin: 0 0 20px") {
            "Admin key required: "
            input(class="input", r#type="password", placeholder="admin key…", bind:value=key,
                style="max-width: 280px; margin: 0 10px;")
            button(class="btn btn-primary", on:click=move |_| {
                let k = key.get_clone();
                if !k.is_empty()
                    && let Some(w) = web_sys::window() {
                        if let Ok(Some(s)) = w.local_storage() {
                            let _ = s.set_item("anyhop_admin_key", &k);
                        }
                        let _ = w.location().reload();
                    }
            }) { "Save" }
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
    // Mobile menu: the sidebar collapses into a toggle below 720px.
    let nav_open = create_signal(false);
    let need_auth = create_signal(
        stored_key().is_none() && NEED_AUTH.load(std::sync::atomic::Ordering::Relaxed),
    );
    // Selected provider (detail page) lives in the root scope so it survives
    // tab remounts; a single hashchange listener for the whole app.
    let selected_provider = create_signal(provider_from_hash());
    let providers = create_signal(Vec::<ProviderDto>::new());
    let quotas = create_signal(Vec::<QuotaDto>::new());
    let events = create_signal(Vec::<EventDto>::new());
    let client_keys = create_signal(Vec::<ClientKeyDto>::new());
    let models = create_signal(Vec::<ModelItemDto>::new());
    let loaded = create_signal(false);

    // Single hashchange listener for the whole app: back/forward navigation
    // switches both the tab and the provider detail page.
    if let Some(w) = web_sys::window() {
        let cb = wasm_bindgen::closure::Closure::wrap(Box::new(move || {
            defer(move || {
                let t = tab_from_hash();
                if tab.get() != t {
                    tab.set(t);
                }
                selected_provider.set(provider_from_hash());
            });
        }) as Box<dyn Fn()>);
        let _ = w.add_event_listener_with_callback("hashchange", cb.as_ref().unchecked_ref());
        cb.forget();
    }

    spawn_local({
        async move {
            loop {
                if let Some(data) = fetch_json::<Vec<ModelItemDto>>("/api/models").await {
                    if !models.is_alive() {
                        break;
                    }
                    // Skip no-op updates: a set() re-renders every dependent view.
                    if models.get_clone() != data {
                        models.set(data);
                    }
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    spawn_local({
        async move {
            loop {
                if let Some(data) = fetch_json::<Vec<ClientKeyDto>>("/api/client-keys").await {
                    if !client_keys.is_alive() {
                        break;
                    }
                    if client_keys.get_clone() != data {
                        client_keys.set(data);
                    }
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    spawn_local({
        async move {
            loop {
                if let Some(data) = fetch_json::<Vec<ProviderDto>>("/api/providers").await {
                    if !providers.is_alive() {
                        break;
                    }
                    // Skip no-op updates — a set() would rebuild the open detail
                    // page and wipe any in-progress form state every 3 seconds.
                    if providers.get_clone() != data {
                        providers.set(data);
                    }
                    loaded.set(true);
                }
                let na = NEED_AUTH.load(std::sync::atomic::Ordering::Relaxed);
                if na && need_auth.is_alive() {
                    need_auth.set(true);
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    });

    spawn_local({
        async move {
            loop {
                if let Some(data) = fetch_json::<Vec<QuotaDto>>("/api/quotas").await {
                    if !quotas.is_alive() {
                        break;
                    }
                    if quotas.get_clone() != data {
                        quotas.set(data);
                    }
                }
                gloo_timers::future::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    });

    spawn_local({
        async move {
            loop {
                // Stop retrying once the root scope is gone.
                if !events.is_alive() {
                    break;
                }
                // EventSource cannot send an Authorization header, so the admin
                // key has to travel as `?key=` (the server accepts it for GET
                // only). Without it, `/api/events` returns 401 whenever admin_key
                // or api_key is configured, and the Events tab stays empty
                // forever. Recomputed each attempt so a key entered in the auth
                // modal takes effect on the next reconnect.
                let es_url = match stored_key() {
                    Some(k) => format!("/api/events?key={}", js_sys::encode_uri_component(&k)),
                    None => "/api/events".to_string(),
                };
                match EventSource::new(&es_url) {
                    Ok(mut es) => match es.subscribe("message") {
                        Ok(mut stream) => {
                            // The server replays its whole recent-buffer on every
                            // connect, and this loop reconnects after any drop.
                            // Without a reset each reconnect duplicated the entire
                            // list (200 entries of the same events). Clearing once
                            // per connection keeps the replay authoritative.
                            if events.is_alive() {
                                events.set(Vec::new());
                            }
                            while let Some(item) = stream.next().await {
                                if !events.is_alive() {
                                    break;
                                }
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
        div(class="layout") {
            aside(class="side") {
                div(class="side-top") {
                    div(class="logo") {
                        div(class="logo-mark") { i {} i {} i {} i {} }
                        span(class="logo-text") { "anyhop" }
                    }
                    // Only rendered as a button on narrow screens (CSS hides it
                    // above 720px, where the full nav is always visible).
                    button(
                        class=if nav_open.get_clone() { "nav-burger open" } else { "nav-burger" },
                        on:click=move |_| nav_open.set(!nav_open.get_clone()),
                    ) {
                        span {}
                        span {}
                        span {}
                    }
                }

                nav(class=if nav_open.get_clone() { "side-nav open" } else { "side-nav" }) {
                    (NAV.iter().map(|(group, items)| {
                        let items_v: Vec<View> = items.iter().map(|(t, label)| {
                            let t = *t;
                            let label = *label;
                            view! {
                                button(
                                    class=if tab.get() == t { "nav-item active" } else { "nav-item" },
                                    on:click=move |_| {
                                        tab.set(t);
                                        nav_open.set(false);
                                        if let Some(w) = web_sys::window() {
                                            let _ = w.location().set_hash(t.hash());
                                        }
                                    },
                                ) { (label) }
                            }
                        }).collect();
                        view! {
                            div(class="nav-group") {
                                div(class="nav-label") { (*group) }
                                (items_v)
                            }
                        }
                    }).collect::<Vec<_>>())
                }

                div(class="side-foot") {
                    ThemeToggle()
                    div(class="side-endpoint") {
                        (web_sys::window()
                            .and_then(|w| w.location().host().ok())
                            .map(|h| format!("{h}/v1"))
                            .unwrap_or_default())
                    }
                    div(class="side-meta") {
                        span { "anyhop v" (env!("CARGO_PKG_VERSION")) }
                    }
                }
            }

            main(class="main") {
                (if need_auth.get() {
                    view! { AuthBanner() }
                } else {
                    view! {}
                })

                div(class="tab-content") {
                    (match tab.get() {
                        Tab::Overview => view! { OverviewTab(providers=providers, events=events, client_keys=client_keys, models=models, quotas=quotas) },
                        Tab::Providers => view! { ProvidersTab(providers=providers, selected=selected_provider) },
                        Tab::Models => view! { ModelsTab(models=models) },
                        Tab::ApiKeys => view! { ApiKeysTab(client_keys=client_keys, models=models) },
                        Tab::Quotas => view! { QuotasTab(quotas=quotas) },
                        Tab::Events => view! { EventsTab(events=events) },
                        Tab::Requests => view! { RequestsTab() },
                        Tab::Settings => view! { SettingsTab() },
                        Tab::Config => view! { ConfigTab() },
                    })
                }
            }
        }
    }
}
