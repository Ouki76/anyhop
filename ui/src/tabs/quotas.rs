use sycamore::prelude::*;

use crate::types::*;

#[component(inline_props)]
pub fn QuotasTab(quotas: Signal<Vec<QuotaDto>>) -> View {
    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Quotas" }
                div(class="page-sub") { "Remaining rate-limit budget per OAuth account" }
            }
        }
        (if quotas.get_clone().is_empty() {
            view! { div(class="card") { div(class="empty") {
                div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                "Quotas appear for OAuth providers (antigravity)"
            } } }
        } else {
            view! {
                div(class="section-title") {
                    "Accounts"
                    span(class="cnt") { (format!("{} configured", quotas.get_clone().len())) }
                }
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
pub fn QuotaCard(q: QuotaDto) -> View {
    // Open by default — like the quota cards on Overview; the page exists to
    // show the bars, hiding them behind a click made it look empty.
    let open = create_signal(true);
    // Summary for the collapsed state: worst quota of the account.
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
                span(class="quota-caret") { (if open.get() { "−" } else { "+" }) }
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
