use sycamore::prelude::*;

use crate::types::*;
use crate::util::*;
use super::events::EventList;

#[component(inline_props)]
pub fn OverviewTab(
    providers: Signal<Vec<ProviderDto>>,
    events: Signal<Vec<EventDto>>,
    client_keys: Signal<Vec<ClientKeyDto>>,
    models: Signal<Vec<ModelItemDto>>,
    quotas: Signal<Vec<QuotaDto>>,
) -> View {
    let n_keys = create_memo(move || client_keys.get_clone().len());
    let n_models_enabled = create_memo(move || models.get_clone().iter().filter(|m| m.enabled).count());
    let n_models_total = create_memo(move || models.get_clone().len());
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
    // key health rollup for the status band
    let key_health = create_memo(move || {
        let mut total = 0usize;
        let mut active = 0usize;
        let mut dead = 0usize;
        let mut cool = 0usize;
        for k in providers.get_clone().iter().flat_map(|p| p.keys.iter()) {
            total += 1;
            match k.status.as_str() {
                "active" => active += 1,
                "dead" => dead += 1,
                "cooldown" => cool += 1,
                _ => {}
            }
        }
        (total, active, dead, cool)
    });
    let quota_min = create_memo(move || {
        quotas
            .get_clone()
            .iter()
            .flat_map(|q| q.models.iter())
            .filter_map(|m| m.pct)
            .min()
    });
    let n_providers = create_memo(move || providers.get_clone().len());

    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Overview" }
                div(class="page-sub") { "Gateway state at a glance — refreshed live" }
            }
        }

        // status band
        ({
            let (total, active, dead, cool) = key_health.get_clone();
            let (dot, msg) = if total == 0 {
                ("ok-dot warn", "No keys configured".to_string())
            } else if dead > 0 {
                ("ok-dot err", format!("{dead} of {total} keys dead"))
            } else if cool > 0 {
                ("ok-dot warn", format!("{cool} of {total} keys cooling down"))
            } else {
                ("ok-dot ok", "All systems operational".to_string())
            };
            view! {
                div(class="ok-band") {
                    span(class=dot) {}
                    b { (msg) }
                    span(class="meta") {
                        (format!("{active}/{total} keys · {} in flight · {} client keys",
                            fmt_num(in_flight.get_clone()), n_keys.get_clone()))
                    }
                }
            }
        })

        // big numbers
        div(class="bignums") {
            div(class="bignum") {
                div(class="n") {
                    (n_models_enabled.get_clone())
                    span(class="u") { (format!("/{}", n_models_total.get_clone())) }
                }
                div(class="l") { "Models on" }
            }
            div(class="bignum") {
                div(class="n") {
                    // Unknown quota (no snapshot yet, or no metered provider):
                    // a lone dash, not "—%" which reads like a broken number.
                    (match quota_min.get_clone() {
                        Some(p) => {
                            let v = view! { (format!("{p}")) span(class="u") { "%" } };
                            v
                        }
                        None => view! { span(class="u") { "n/a" } },
                    })
                }
                div(
                    class="l",
                    title="Smallest remaining quota across every account and model, in percent",
                ) { "Quota left" }
            }
            div(class="bignum") {
                div(class="n") { (fmt_num(total_requests.get_clone())) }
                div(class="l") { "Requests" }
            }
            div(class="bignum") {
                div(class="n") { (fmt_num(total_tokens.get_clone())) }
                div(class="l") { "Tokens" }
            }
        }

        div(class="section-title") {
            "Providers"
            span(class="cnt") { (format!("{} configured", n_providers.get_clone())) }
        }
        ((move || {
            let qs = quotas.get_clone();
            let ps = providers.get_clone();
            if !qs.is_empty() {
                // account cards with live quota bars
                let cards: Vec<View> = qs
                    .into_iter()
                    .map(|q| {
                        let href = format!("#providers/{}", q.provider);
                        let rows: Vec<View> = q
                            .models
                            .iter()
                            .take(3)
                            .map(|m| {
                                let id = m.id.clone();
                                let title = m.id.clone();
                                let pct = m.pct;
                                let cls = if m.low { "quota-fill low" } else { "quota-fill" };
                                let width = pct.map(|p| format!("width:{}%", p)).unwrap_or_default();
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
                                    }
                                }
                            })
                            .collect();
                        let title = if q.account.is_empty() {
                            q.provider.clone()
                        } else {
                            q.account.clone()
                        };
                        let badge = q.provider.clone();
                        view! {
                            a(class="quota-card open ov-link", href=href) {
                                div(class="quota-card-head") {
                                    // The account is what distinguishes two cards of the
                                    // same provider, so it is the title.
                                    b { (title) }
                                    span(class="badge") { (badge) }
                                }
                                div(class="quota-body") { (rows) }
                            }
                        }
                    })
                    .collect();
                view! { div(class="quota-grid") { (cards) } }
            } else if !ps.is_empty() {
                // no quota data (API-key providers) — plain health rows
                let rows: Vec<View> = ps
                    .into_iter()
                    .map(|p| {
                        let total = p.keys.len();
                        let active = p.keys.iter().filter(|k| k.status == "active").count();
                        let reqs: u64 = p.keys.iter().map(|k| k.requests).sum();
                        let health = if total > 0 && active == 0 {
                            "pdot pdot-err"
                        } else if active < total {
                            "pdot pdot-warn"
                        } else {
                            "pdot pdot-ok"
                        };
                        let href = format!("#providers/{}", p.name);
                        view! {
                            a(class="key-row ov-link", href=href) {
                                span(class=health) {}
                                b { (p.name) }
                                span(class="badge") { (p.strategy) }
                                span(class="key-stats") {
                                    (format!("{active}/{total} keys · {} req", fmt_num(reqs)))
                                }
                            }
                        }
                    })
                    .collect();
                view! { div(class="card") { div(class="key-list") { (rows) } } }
            } else {
                view! { div(class="card") { div(class="empty") {
                    div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                    "No providers configured yet"
                } } }
            }
        })())

        div(class="section-title") { "Recent events" }
        EventList(events=events, limit=5)
    }
}
