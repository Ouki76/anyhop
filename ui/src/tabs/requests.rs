use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::*;
use crate::util::*;

#[component]
pub fn RequestsTab() -> View {
    let items = create_signal(Vec::<RequestDto>::new());
    spawn_local(async move {
        loop {
            // Check liveness BEFORE the fetch too: when the tab is gone and the
            // request keeps failing, the check inside would never be reached.
            if !items.is_alive() {
                break;
            }
            if let Some(data) = fetch_json::<Vec<RequestDto>>("/api/requests").await {
                // The tab may have been dismounted while the fetch was in flight —
                // setting a disposed signal panics, so check after the await.
                if !items.is_alive() {
                    break;
                }
                // Skip no-op updates: a set() re-renders the whole table.
                if items.get_clone() != data {
                    items.set(data);
                }
            }
            gloo_timers::future::sleep(std::time::Duration::from_secs(2)).await;
        }
    });

    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Requests" }
                div(class="page-sub") {
                    (format!("{} recent requests through the gateway", items.get_clone().len()))
                }
            }
        }
        div(class="card") {
            (if items.get_clone().is_empty() {
                view! { div(class="empty") {
                    div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                    "No requests yet"
                } }
            } else {
                view! {
                    div(class="table-scroll") {
                        table {
                            thead {
                                tr {
                                    th { "Time" } th { "Provider" } th { "Model" } th { "Key" }
                                    th { "Client" } th { "Status" } th { "Latency" } th { "" }
                                }
                            }
                            Indexed(
                                list=items,
                                view=|r: RequestDto| {
                                    let chip = if r.status == "200" { "chip chip-active" }
                                        else if r.status == "429" { "chip chip-cooldown" }
                                        else { "chip chip-dead" };
                                    view! {
                                        tr {
                                            // data-label powers the card layout on phones
                                            td(class="mono", data-label="time") { (fmt_time(r.ts)) }
                                            td(data-label="provider") { (r.provider) }
                                            td(class="mono", data-label="model") { (r.model) }
                                            td(class="mono", data-label="key") { (r.key) }
                                            td(class="mono", data-label="client") {
                                                (r.client_key.clone().unwrap_or_else(|| "master".into()))
                                            }
                                            td(data-label="status") { span(class=chip) { (r.status) } }
                                            td(class="num", data-label="latency") { (format!("{}ms", r.latency_ms)) }
                                            td(data-label="type") { (if r.stream { "stream" } else { "" }) }
                                        }
                                    }
                                },
                            )
                        }
                    }
                }
            })
        }
    }
}
