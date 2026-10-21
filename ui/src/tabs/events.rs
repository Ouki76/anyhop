use sycamore::prelude::*;

use crate::types::*;
use crate::util::*;

#[component(inline_props)]
pub fn EventsTab(events: Signal<Vec<EventDto>>) -> View {
    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Events" }
                div(class="page-sub") {
                    (format!("{} events — rotation, failover and quota, newest first", events.get_clone().len()))
                }
            }
        }
        div(class="card") {
            EventList(events=events, limit=200)
        }
    }
}

#[component(inline_props)]
pub fn EventList(events: Signal<Vec<EventDto>>, limit: usize) -> View {
    // One signal per component instance, kept in sync by an effect. Creating the
    // signal inside the `if` below would allocate a fresh one every time the
    // list flips between empty and non-empty.
    let limited = create_memo(move || {
        events.get_clone().into_iter().take(limit).collect::<Vec<_>>()
    });
    let shown = create_signal(Vec::<EventDto>::new());
    create_effect(move || shown.set(limited.get_clone()));
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
                        list=shown,
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
