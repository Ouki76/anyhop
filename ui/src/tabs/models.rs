use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::*;
use crate::util::*;

#[component(inline_props)]
pub fn ModelsTab(models: Signal<Vec<ModelItemDto>>) -> View {
    let search = create_signal(String::new());
    // --- combos (virtual models with a fallback chain) ---
    let combos = create_signal(Vec::<ComboDto>::new());
    let combo_editing = create_signal(Option::<String>::None); // Some("") = new
    let combo_name = create_signal(String::new());
    let combo_chain = create_signal(Vec::<String>::new());
    let combo_error = create_signal(String::new());
    let combo_pick = create_signal(String::new());
    let confirm_combo_delete = create_signal(Option::<String>::None);
    let prov_filter = create_signal("all".to_string());
    let copied_id = create_signal(String::new());
    let is_refreshing = create_signal(false);
    // "Disable all" is one click away from taking every model offline: confirm it.
    let confirm_disable_all = create_signal(false);

    spawn_local(async move {
        if let Some(list) = fetch_json::<Vec<ComboDto>>("/api/combos").await
            && combos.is_alive()
        {
            combos.set(list);
        }
    });

    let combo_choices = create_memo(move || {
        // Every model id is a valid chain entry; combos themselves are not
        // (no nesting — a combo pointing at a combo would need cycle detection).
        models
            .get_clone()
            .into_iter()
            .filter(|m| m.provider != "combo")
            .map(|m| m.id)
            .collect::<Vec<_>>()
    });

    let total = create_memo(move || models.get_clone().len());
    let enabled_count =
        create_memo(move || models.get_clone().iter().filter(|m| m.enabled).count());

    let providers = create_memo(move || {
        let mut set = std::collections::BTreeSet::new();
        for m in models.get_clone() {
            set.insert(m.provider);
        }
        set.into_iter().collect::<Vec<_>>()
    });

    let filtered = create_memo(move || {
        let q = search.get_clone().to_lowercase();
        let pf = prov_filter.get_clone();
        models
            .get_clone()
            .into_iter()
            .filter(|m| {
                if pf != "all" && m.provider != pf {
                    return false;
                }
                if q.is_empty() {
                    return true;
                }
                m.id.to_lowercase().contains(&q)
                    || m.name.to_lowercase().contains(&q)
                    || m.provider.to_lowercase().contains(&q)
            })
            .collect::<Vec<_>>()
    });

    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Models" }
                div(class="page-sub") {
                    (format!("{} of {} enabled · served via /v1/models", enabled_count.get_clone(), total.get_clone()))
                }
            }
            div(class="row") {
                button(
                    class=if is_refreshing.get() { "btn btn-sm btn-primary" } else { "btn btn-sm" },
                    on:click=move |_| {
                        if is_refreshing.get() {
                            return;
                        }
                        is_refreshing.set(true);
                        spawn_local(async move {
                            if let Some(d) = post_json_resp::<_, Vec<ModelItemDto>>("/api/models/refresh", &serde_json::json!({})).await {
                                models.set(d);
                            }
                            // The tab may be unmounted while the (slow) refresh runs.
                            if is_refreshing.is_alive() {
                                is_refreshing.set(false);
                            }
                        });
                    },
                ) {
                    (if is_refreshing.get() { "Refreshing…" } else { "Refresh" })
                }
                button(class="btn btn-sm", on:click=move |_| {
                    spawn_local(async move {
                        post_json("/api/models/enable-all", &serde_json::json!({})).await;
                        reload_models(models).await;
                    });
                }) { "Enable all" }
                button(class="btn btn-sm", on:click=move |_| confirm_disable_all.set(true)) {
                    "Disable all"
                }
            }
        }

        (if confirm_disable_all.get_clone() {
            view! {
                div(class="modal-overlay", on:click=move |_| confirm_disable_all.set(false)) {
                    div(class="modal", on:click=move |e: web_sys::MouseEvent| e.stop_propagation()) {
                        div(class="modal-head") { b { "Disable every model?" } }
                        div(class="modal-body") {
                            div(class="dim-text mb-12") {
                                (format!(
                                    "All {} models stop being served immediately: clients get 404 until you re-enable them.",
                                    total.get_clone(),
                                ))
                            }
                        }
                        div(class="modal-actions") {
                            button(class="btn", on:click=move |_| confirm_disable_all.set(false)) { "Cancel" }
                            button(class="btn btn-danger", on:click=move |_| {
                                spawn_local(async move {
                                    post_json("/api/models/disable-all", &serde_json::json!({})).await;
                                    reload_models(models).await;
                                    if confirm_disable_all.is_alive() {
                                        confirm_disable_all.set(false);
                                    }
                                });
                            }) { "Disable all" }
                        }
                    }
                }
            }
        } else {
            view! {}
        })

        div(class="search-bar") {
            input(class="input", r#type="text", placeholder="Filter by name or provider…", bind:value=search)

            ProviderSelect(providers=providers, value=prov_filter)
        }

        div(class="card") {
            (if filtered.get_clone().is_empty() {
                view! {
                    div(class="empty") {
                        div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                        "No models match the filter"
                    }
                }
            } else {
                view! {
                    div(class="key-list") {
                        Indexed(
                            list=filtered,
                            view=move |m: ModelItemDto| {
                                let id = m.id.clone();
                                let id_memo = m.id.clone();
                                let id_copy = m.id.clone();
                                let id_toggle = m.id.clone();
                                let prov = m.provider.clone();
                                let enabled = m.enabled;
                                let is_copied = create_memo(move || copied_id.get_clone() == id_memo);

                                let dot = if enabled { "pdot pdot-ok" } else { "pdot pdot-dim" };
                                let toggle_label = if enabled { "Disable" } else { "Enable" };
                                let toggle_url = if enabled { "/api/models/disable" } else { "/api/models/enable" };

                                view! {
                                    div(class=if enabled { "model-row" } else { "model-row off" }) {
                                        span(class=dot) {}
                                        span(class="model-row-id") { (id) }
                                        span(class="dim-text") { (prov) }
                                        div(class="model-row-actions") {
                                            button(class="btn-ghost", on:click=move |_| {
                                                let id_str = id_copy.clone();
                                                let copied_id = copied_id;
                                                spawn_local(async move {
                                                    if copy_to_clipboard(&id_str).await {
                                                        copied_id.set(id_str);
                                                    }
                                                    gloo_timers::callback::Timeout::new(2000, move || {
                                                        if copied_id.is_alive() { copied_id.set(String::new()); }
                                                    }).forget();
                                                });
                                            }) { (if is_copied.get() { "Copied" } else { "Copy ID" }) }
                                            button(class="btn-ghost", on:click=move |_| {
                                                let id = id_toggle.clone();
                                                spawn_local(async move {
                                                    post_json(toggle_url, &serde_json::json!({"model": id})).await;
                                                    reload_models(models).await;
                                                });
                                            }) { (toggle_label) }
                                        }
                                    }
                                }
                            },
                        )
                    }
                }
            })
        }
            // ---- combos: virtual models with a fallback chain ----
            div(class="section-title") {
                "Combos"
                span(class="cnt") {
                    (match combos.get_clone().len() {
                        1 => "1 combo".to_string(),
                        n => format!("{n} combos"),
                    })
                }
                // The action belongs with the heading, not at the bottom of the list.
                (if combo_editing.get_clone().is_none() {
                    view! {
                        button(class="btn btn-sm ml-auto", on:click=move |_| {
                            combo_name.set(String::new());
                            combo_chain.set(Vec::new());
                            combo_error.set(String::new());
                            combo_editing.set(Some(String::new()));
                        }) { "+ New combo" }
                    }
                } else {
                    view! {}
                })
            }
            div(class="card") {
                (if combos.get_clone().is_empty() && combo_editing.get_clone().is_none() {
                    view! { div(class="empty") {
                        "No combos yet — a combo is a virtual model that falls back through a chain of provider/models."
                    } }
                } else {
                    view! { div(class="key-list") {
                        Indexed(
                            list=combos,
                            view=move |c: ComboDto| {
                                let c_name = c.name.clone();
                                let c_name_del = c.name.clone();
                                let c_name_edit = c.name.clone();
                                let chain = c.chain.clone();
                                let n = chain.len();
                                let chips: Vec<View> = chain
                                    .iter()
                                    .enumerate()
                                    .map(|(i, m)| {
                                        let label = format!("{}. {}", i + 1, m);
                                        view! { span(class="model-chip") { (label) } }
                                    })
                                    .collect();
                                view! {
                                    div(class="key-row combo-row") {
                                        b { (c_name) }
                                        span(class="badge") { (format!("{n} targets")) }
                                        div(class="key-stats combo-chain") { (chips) }
                                        button(class="btn-ghost", on:click=move |_| {
                                            combo_name.set(c_name_edit.clone());
                                            combo_chain.set(chain.clone());
                                            combo_error.set(String::new());
                                            combo_editing.set(Some(c_name_edit.clone()));
                                        }) { "Edit" }
                                        button(class="btn-ghost btn-ghost-danger", on:click=move |_| {
                                            confirm_combo_delete.set(Some(c_name_del.clone()));
                                        }) { "Delete" }
                                    }
                                }
                            },
                        )
                    } }
                })

                (match combo_editing.get_clone() {
                    None => view! {},
                    Some(name) => {
                        let is_new = name.is_empty();
                        let save_name = name.clone();
                        let del_name = name.clone();
                        let chain_now = combo_chain.get_clone();
                        let chain_len = chain_now.len();
                        let steps: Vec<View> = chain_now
                            .clone()
                            .into_iter()
                            .enumerate()
                            .map(|(i, m)| {
                                let m_keep = m;
                                view! {
                                    div(class="chain-step") {
                                        span(class="mono") { (format!("{}. {}", i + 1, m_keep)) }
                                        div(class="row gap-6") {
                                            button(
                                                class="btn-ghost", disabled=i == 0,
                                                on:click=move |_| {
                                                    let mut c = combo_chain.get_clone();
                                                    if i > 0 {
                                                        c.swap(i - 1, i);
                                                        combo_chain.set(c);
                                                    }
                                                },
                                            ) { "↑" }
                                            button(
                                                class="btn-ghost", disabled=i + 1 >= chain_len,
                                                on:click=move |_| {
                                                    let mut c = combo_chain.get_clone();
                                                    if i + 1 < c.len() {
                                                        c.swap(i, i + 1);
                                                        combo_chain.set(c);
                                                    }
                                                },
                                            ) { "↓" }
                                            button(
                                                class="btn-ghost btn-ghost-danger",
                                                on:click=move |_| {
                                                    let mut c = combo_chain.get_clone();
                                                    if i < c.len() {
                                                        c.remove(i);
                                                        combo_chain.set(c);
                                                    }
                                                },
                                            ) { "✕" }
                                        }
                                    }
                                }
                            })
                            .collect();
                        view! {
                            div(class="drawer mt-16") {
                                div(class="row mb-12") {
                                    b(class="text-13") { (if is_new { "New combo" } else { "Edit combo" }) }
                                }
                                div(class="form-group") {
                                    label(class="form-label") { "Name (used as the model id)" }
                                    input(
                                        class="input", r#type="text", placeholder="e.g. fast",
                                        bind:value=combo_name, disabled=!is_new, value=name.clone(),
                                    )
                                }
                                div(class="form-group") {
                                    label(class="form-label") { "Fallback chain — tried top to bottom" }
                                    (steps)
                                    (if chain_now.is_empty() {
                                        view! { div(class="dim-text") { "Empty — add at least one provider/model below." } }
                                    } else {
                                        view! {}
                                    })
                                    div(class="row gap-10 mt-10") {
                                        select(class="select input-w320", bind:value=combo_pick) {
                                            option(value="") { "Add provider / model…" }
                                            (combo_choices.get_clone().into_iter().map(|id| {
                                                let v = id.clone();
                                                let l = id;
                                                view! { option(value=v) { (l) } }
                                            }).collect::<Vec<_>>())
                                        }
                                        button(class="btn btn-sm", on:click=move |_| {
                                            let pick = combo_pick.get_clone();
                                            if pick.is_empty() {
                                                return;
                                            }
                                            let mut c = combo_chain.get_clone();
                                            if !c.iter().any(|x| *x == pick) {
                                                c.push(pick.clone());
                                                combo_chain.set(c);
                                            }
                                            combo_pick.set(String::new());
                                        }) { "Add" }
                                    }
                                }
                                (if combo_error.get_clone().is_empty() {
                                    view! {}
                                } else {
                                    view! { div(class="auth-banner auth-error flush") { (combo_error.get_clone()) } }
                                })
                                div(class="row gap-10 mt-16") {
                                    button(class="btn btn-primary btn-sm", on:click=move |_| {
                                        let name = combo_name.get_clone().trim().to_string();
                                        let chain = combo_chain.get_clone();
                                        let path = if save_name.is_empty() {
                                            "/api/combos/add"
                                        } else {
                                            "/api/combos/update"
                                        };
                                        let body = serde_json::json!({"name": name, "chain": chain});
                                        spawn_local(async move {
                                            // The error branch used to be unreachable:
                                            // `post_json_resp` parsed the JSON error
                                            // envelope and reported success, so a
                                            // rejected combo closed the editor.
                                            match post_json_result::<_, serde_json::Value>(path, &body).await {
                                                Ok(_) => {
                                                    if let Some(list) = fetch_json::<Vec<ComboDto>>("/api/combos").await
                                                        && combos.is_alive()
                                                    {
                                                        combos.set(list);
                                                    }
                                                    if combo_editing.is_alive() {
                                                        combo_editing.set(None);
                                                    }
                                                    reload_models(models).await;
                                                }
                                                Err(e) => {
                                                    if combo_error.is_alive() {
                                                        combo_error.set(format!("could not save: {e}"));
                                                    }
                                                }
                                            }
                                        });
                                    }) { "Save combo" }
                                    button(class="btn btn-sm", on:click=move |_| combo_editing.set(None)) {
                                        "Cancel"
                                    }
                                    (if is_new {
                                        view! {}
                                    } else {
                                        view! {
                                            button(class="btn btn-sm btn-danger", on:click=move |_| {
                                                confirm_combo_delete.set(Some(del_name.clone()));
                                            }) { "Delete combo" }
                                        }
                                    })
                                }
                            }
                        }
                    }
                })
            }

            (match confirm_combo_delete.get_clone() {
                Some(name) => {
                    let name_del = name.clone();
                    let name_show = name.clone();
                    view! {
                        div(class="modal-overlay", on:click=move |_| confirm_combo_delete.set(None)) {
                            div(class="modal", on:click=move |e: web_sys::MouseEvent| e.stop_propagation()) {
                                div(class="modal-head") { "Delete this combo?" }
                                div(class="modal-body") {
                                    div(class="dim-text") {
                                        "Clients using " span(class="mono") { (name_show) }
                                        " will get 404. Providers and models stay as they are."
                                    }
                                }
                                div(class="modal-actions") {
                                    button(class="btn", on:click=move |_| confirm_combo_delete.set(None)) { "Cancel" }
                                    button(class="btn btn-danger", on:click=move |_| {
                                        let name = name_del.clone();
                                        confirm_combo_delete.set(None);
                                        spawn_local(async move {
                                            let body = serde_json::json!({"name": name});
                                            post_json("/api/combos/delete", &body).await;
                                            if let Some(list) = fetch_json::<Vec<ComboDto>>("/api/combos").await
                                                && combos.is_alive()
                                            {
                                                combos.set(list);
                                            }
                                            reload_models(models).await;
                                        });
                                    }) { "Delete combo" }
                                }
                            }
                        }
                    }
                }
                None => view! {},
            })

    }
}

/// Custom dropdown — the native <select> popup is rendered by the OS and cannot
/// be styled, so the menu is a regular absolutely-positioned element.
#[component(inline_props)]
pub fn ProviderSelect(providers: ReadSignal<Vec<String>>, value: Signal<String>) -> View {
    let open = create_signal(false);
    let label = create_memo(move || {
        let v = value.get_clone();
        if v == "all" {
            "All providers".to_string()
        } else {
            v
        }
    });

    view! {
        div(class="combo") {
            button(class="select combo-btn", on:click=move |_| open.set(!open.get())) {
                span { (label.get_clone()) }
                span(class="combo-arrow") {}
            }
            (if open.get() {
                view! {
                    div(class="combo-backdrop", on:click=move |_| open.set(false)) {}
                    div(class="combo-menu") {
                        div(
                            class=if value.get_clone() == "all" { "combo-item active" } else { "combo-item" },
                            on:click=move |_| {
                                value.set("all".into());
                                open.set(false);
                            },
                        ) { "All providers" }
                        Indexed(
                            list=providers,
                            view=move |p: String| {
                                let p_click = p.clone();
                                let p_label = p.clone();
                                view! {
                                    div(
                                        class=if value.get_clone() == p { "combo-item active" } else { "combo-item" },
                                        on:click=move |_| {
                                            value.set(p_click.clone());
                                            open.set(false);
                                        },
                                    ) { (p_label) }
                                }
                            },
                        )
                    }
                }
            } else {
                view! {}
            })

        }
    }
}
