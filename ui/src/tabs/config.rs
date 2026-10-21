use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::util::*;

#[component]
pub fn ConfigTab() -> View {
    let toml = create_signal(String::new());
    let status = create_signal(String::new());
    let loaded = create_signal(false);

    spawn_local(async move {
        let t = fetch_text("/api/config").await;
        // The tab may be unmounted before the fetch resolves.
        if !toml.is_alive() {
            return;
        }
        match t {
            Some(t) => {
                toml.set(t);
                loaded.set(true);
            }
            // Don't hang on "Loading…" forever (401/network).
            None => status.set("cannot load config (check admin key / server)".into()),
        }
    });

    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Config" }
                div(class="page-sub") { "Edit anyhop.toml — saving hot-reloads the gateway" }
            }
        }
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
                        if status.is_alive() {
                            status.set(msg);
                        }
                    });
                }) { "Save & reload" }
                button(class="btn", on:click=move |_| {
                    spawn_local(async move {
                        // post via the shared helper: /api/reload needs the admin key
                        let ok = post_json("/api/reload", &serde_json::json!({})).await;
                        if status.is_alive() {
                            status.set(if ok { "reloaded from disk".into() } else { "reload failed".into() });
                        }
                    });
                }) { "Reload from disk" }
                span(class="config-status") { (status.get_clone()) }
            }
        }
    }
}
