use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::*;
use crate::util::*;


/// A small pill naming where a number came from (`override`, `provider`, …).
fn src_badge(source: &str) -> View {
    let cls = format!("src-badge src-{source}");
    let text = source.to_string();
    view! { span(class=cls) { (text) } }
}

/// Re-seed the editor's three fields from an API response.
///
/// `bind:value` keeps whatever the operator typed, so after a reset (or a save the
/// server normalised) the field would keep showing a value the model no longer
/// has — and the next Save would put the stale number back.
fn apply_limits_json(
    v: &serde_json::Value,
    ctx: Signal<String>,
    out: Signal<String>,
    inp: Signal<String>,
) {
    // The API answers with the operator's own values (`overridden` set), which is
    // what the inputs show; the effective numbers stay beside them.
    let got = |k: &str| v.get(k).and_then(|n| n.as_u64()).unwrap_or(0);
    if ctx.is_alive() {
        ctx.set(sig_str(got("context_window")));
    }
    if out.is_alive() {
        out.set(sig_str(got("max_output_tokens")));
    }
    if inp.is_alive() {
        inp.set(sig_str(got("max_input_tokens")));
    }
}

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
    // --- per-model limits (context window / token caps) ---
    let limits_editing = create_signal(Option::<String>::None);
    let lim_ctx = create_signal(String::new());
    let lim_out = create_signal(String::new());
    let lim_in = create_signal(String::new());
    let lim_error = create_signal(String::new());
    let lim_saved = create_signal(false);

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

    // The model whose limits are open, looked up live so the panel shows what the
    // server actually stored after a save.
    let lim_current = create_memo(move || {
        let id = limits_editing.get_clone()?;
        models.get_clone().into_iter().find(|m| m.id == id)
    });

    let open_limits = move |id: String| {
        if let Some(m) = models.get_clone().into_iter().find(|m| m.id == id) {
            // The inputs hold the operator's own numbers (empty when there is no
            // override); the provider's value is shown beside them as the
            // effective one, so typing replaces it instead of silently copying it.
            lim_ctx.set(sig_str(m.override_of("context_window")));
            lim_out.set(sig_str(m.override_of("max_output_tokens")));
            lim_in.set(sig_str(m.override_of("max_input_tokens")));
        }
        lim_error.set(String::new());
        lim_saved.set(false);
        limits_editing.set(Some(id));
    };

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
                                let id_limits = m.id.clone();
                                let id_chip = m.id.clone();
                                // "131k ctx · 8k out", and only for what is actually known.
                                let limit_chips = {
                                    let mut parts = Vec::new();
                                    if m.limits.context_window > 0 {
                                        parts.push(format!("{} ctx", m.context_label()));
                                    }
                                    if m.limits.max_output_tokens > 0 {
                                        parts.push(format!("{} out", m.output_label()));
                                    }
                                    if parts.is_empty() {
                                        String::new()
                                    } else {
                                        parts.join(" · ")
                                    }
                                };
                                let has_limits = !limit_chips.is_empty();

                                view! {
                                    div(class=if enabled { "model-row" } else { "model-row off" }) {
                                        span(class=dot) {}
                                        span(class="model-row-id") { (id) }
                                        span(class="dim-text") { (prov) }
                                        button(
                                            class=if has_limits { "chip-btn has-limits" } else { "chip-btn" },
                                            title="View or override this model's limits",
                                            on:click=move |_| { open_limits(id_chip.clone()); }
                                        ) {
                                            (if has_limits { limit_chips.clone() } else { "+ limits".to_string() })
                                        }
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
                                                open_limits(id_limits.clone());
                                            }) { "Limits" }
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
            // ---- per-model limits: effective value, override, reset ----
            (match lim_current.get_clone() {
                None => view! {},
                Some(m) => {
                    let id = m.id.clone();
                    let id_save = m.id.clone();
                    let ctx_eff = m.context_exact();
                    let out_eff = m.output_exact();
                    let in_eff = m.input_exact();
                    let ctx_src = m.source_of("context_window");
                    let out_src = m.source_of("max_output_tokens");
                    let in_src = m.source_of("max_input_tokens");
                    let inherited = !m.limits_source.is_empty()
                        && m.limits_source != m.id
                        && m.limits_source != format!("combo/{}", m.id);
                    let inherited_from = m.limits_source.clone();
                    let id_ctx_reset = m.id.clone();
                    let id_out_reset = m.id.clone();
                    let id_in_reset = m.id.clone();
                    let can_reset_ctx = m.is_overridden("context_window");
                    let can_reset_out = m.is_overridden("max_output_tokens");
                    let can_reset_in = m.is_overridden("max_input_tokens");
                    // One clone per place the macro consumes the value. Plain digits
                    // here: a number input renders its placeholder through a font
                    // that swallows the thin-space grouping.
                    // The effective number, so an empty field still says what would
                    // be used. A prefix like "default 1048576" does not fit a number
                    // input and gets clipped.
                    let ph = |n: u64| if n == 0 { "—".to_string() } else { n.to_string() };
                    let ctx_ph = ph(m.limits.context_window);
                    let out_ph = ph(m.limits.max_output_tokens);
                    let in_ph = ph(m.limits.max_input_tokens);
                    view! {
                        div(class="card model-limits") {
                            div(class="limits-head") {
                                div {
                                    div(class="limits-title") { "Model limits" }
                                    div(class="limits-model") { (id.clone()) }
                                }
                                button(class="btn btn-sm", on:click=move |_| {
                                    if lim_error.is_alive() { lim_error.set(String::new()); }
                                    limits_editing.set(None);
                                }) { "Close" }
                            }
                            (if inherited {
                                view! { div(class="limits-note") {
                                    (format!("The stored values live on '{}' — a shared entry. Saving here creates an override for this model only.", inherited_from))
                                } }
                            } else {
                                view! {}
                            })
                            div(class="limits-body") {
                                div(class="lim-row lim-headrow") {
                                    span { "Parameter" }
                                    span { "Effective" }
                                    span(title="empty = use the effective value") { "Your override" }
                                }
                                div(class="lim-row") {
                                    div(class="lim-name") {
                                        "Context window"
                                        div(class="lim-hint") { "Prompt + completion, in tokens" }
                                    }
                                    div(class="lim-effective") {
                                        (ctx_eff.clone())
                                        (src_badge(&ctx_src))
                                    }
                                    div(class="lim-edit") {
                                        input(class="input input-num", r#type="number", min="0",
                                              max="10000000",
                                              placeholder=ctx_ph.clone(),
                                              bind:value=lim_ctx)
                                        (if can_reset_ctx {
                                            view! {
                                                button(class="btn btn-sm", title="remove this override",
                                                       on:click=move |_| {
                                                           let id = id_ctx_reset.clone();
                                                           spawn_local(async move {
                                                               match post_json_result::<_, serde_json::Value>(
                                                                   "/api/models/limits",
                                                                   &serde_json::json!({"model": id, "context_window": null}),
                                                               ).await {
                                                                   Ok(v) => {
                                                                       apply_limits_json(&v, lim_ctx, lim_out, lim_in);
                                                                       reload_models(models).await;
                                                                   }
                                                                   Err(e) => { if lim_error.is_alive() { lim_error.set(e); } }
                                                               }
                                                           });
                                                       }) { "Reset" }
                                            }
                                        } else {
                                            view! {}
                                        })
                                    }
                                }
                                div(class="lim-row") {
                                    div(class="lim-name") {
                                        "Max output tokens"
                                        div(class="lim-hint") { "Cap on the completion" }
                                    }
                                    div(class="lim-effective") {
                                        (out_eff.clone())
                                        (src_badge(&out_src))
                                    }
                                    div(class="lim-edit") {
                                        input(class="input input-num", r#type="number", min="0",
                                              max="1000000",
                                              placeholder=out_ph.clone(),
                                              bind:value=lim_out)
                                        (if can_reset_out {
                                            view! {
                                                button(class="btn btn-sm", title="remove this override",
                                                       on:click=move |_| {
                                                           let id = id_out_reset.clone();
                                                           spawn_local(async move {
                                                               match post_json_result::<_, serde_json::Value>(
                                                                   "/api/models/limits",
                                                                   &serde_json::json!({"model": id, "max_output_tokens": null}),
                                                               ).await {
                                                                   Ok(v) => {
                                                                       apply_limits_json(&v, lim_ctx, lim_out, lim_in);
                                                                       reload_models(models).await;
                                                                   }
                                                                   Err(e) => { if lim_error.is_alive() { lim_error.set(e); } }
                                                               }
                                                           });
                                                       }) { "Reset" }
                                            }
                                        } else {
                                            view! {}
                                        })
                                    }
                                }
                                div(class="lim-row") {
                                    div(class="lim-name") {
                                        "Max input tokens"
                                        div(class="lim-hint") { "Prompt alone, when the provider states one" }
                                    }
                                    div(class="lim-effective") {
                                        (in_eff.clone())
                                        (src_badge(&in_src))
                                    }
                                    div(class="lim-edit") {
                                        input(class="input input-num", r#type="number", min="0",
                                              max="10000000",
                                              placeholder=in_ph.clone(),
                                              bind:value=lim_in)
                                        (if can_reset_in {
                                            view! {
                                                button(class="btn btn-sm", title="remove this override",
                                                       on:click=move |_| {
                                                           let id = id_in_reset.clone();
                                                           spawn_local(async move {
                                                               match post_json_result::<_, serde_json::Value>(
                                                                   "/api/models/limits",
                                                                   &serde_json::json!({"model": id, "max_input_tokens": null}),
                                                               ).await {
                                                                   Ok(v) => {
                                                                       apply_limits_json(&v, lim_ctx, lim_out, lim_in);
                                                                       reload_models(models).await;
                                                                   }
                                                                   Err(e) => { if lim_error.is_alive() { lim_error.set(e); } }
                                                               }
                                                           });
                                                       }) { "Reset" }
                                            }
                                        } else {
                                            view! {}
                                        })
                                    }
                                }
                            }
                            (if !lim_error.get_clone().is_empty() {
                                view! { div(class="auth-banner auth-error flush") { (lim_error.get_clone()) } }
                            } else if lim_saved.get_clone() {
                                view! { div(class="auth-banner auth-ok flush") { "saved" } }
                            } else {
                                view! {}
                            })
                            div(class="limits-foot") {
                                button(class="btn btn-primary", on:click=move |_| {
                                    let id = id_save.clone();
                                    let (ctx, out, input) = match (parse_opt(&lim_ctx.get_clone()),
                                                                   parse_opt(&lim_out.get_clone()),
                                                                   parse_opt(&lim_in.get_clone())) {
                                        (Ok(c), Ok(o), Ok(i)) => (c, o, i),
                                        _ => {
                                            if lim_error.is_alive() {
                                                lim_error.set("limits must be whole numbers (or empty)".to_string());
                                            }
                                            return;
                                        }
                                    };
                                    spawn_local(async move {
                                        let body = serde_json::json!({
                                            "model": id,
                                            "context_window": opt_json(ctx),
                                            "max_output_tokens": opt_json(out),
                                            "max_input_tokens": opt_json(input),
                                        });
                                        match post_json_result::<_, serde_json::Value>("/api/models/limits", &body).await {
                                            Ok(v) => {
                                                apply_limits_json(&v, lim_ctx, lim_out, lim_in);
                                                reload_models(models).await;
                                                if lim_saved.is_alive() { lim_saved.set(true); }
                                                gloo_timers::callback::Timeout::new(2500, move || {
                                                    if lim_saved.is_alive() { lim_saved.set(false); }
                                                }).forget();
                                            }
                                            Err(e) => {
                                                if lim_error.is_alive() { lim_error.set(e); }
                                            }
                                        }
                                    });
                                }) { "Save limits" }
                                span(class="dim-text") {
                                    "Stored in anyhop.toml and published in /v1/models."
                                }
                            }
                        }
                    }
                }
            })

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
