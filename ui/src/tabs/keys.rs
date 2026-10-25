use gloo_net::http::Request;

use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::*;
use crate::util::*;

#[component(inline_props)]
pub fn ApiKeysTab(
    client_keys: Signal<Vec<ClientKeyDto>>,
    models: Signal<Vec<ModelItemDto>>,
) -> View {
    let show_create = create_signal(false);
    let name_input = create_signal(String::new());
    let key_input = create_signal(String::new());
    let rpm_input = create_signal(String::new());
    let burst_input = create_signal(String::new());
    let max_concurrent_input = create_signal(String::new());
    let restrict_models = create_signal(false);
    let selected_models = create_signal(std::collections::HashSet::<String>::new());
    let model_search = create_signal(String::new());
    let created_banner = create_signal(Option::<ClientKeyDto>::None);
    let create_error = create_signal(String::new());
    // id -> secret, filled on demand: the listing never carries the secret, so
    // "Show"/"Copy" fetch it once and remember it for this tab.
    let revealed = create_signal(std::collections::HashMap::<String, String>::new());
    let copied_key = create_signal(String::new());
    // Surfaced above the list: "cannot reveal the key: …".
    let copy_status = create_signal(String::new());

    // Inline edit for existing key
    let editing_key = create_signal(Option::<String>::None);
    // Delete confirmation: the key waiting for a "yes, delete" click.
    let confirm_delete = create_signal(Option::<String>::None);
    let edit_rpm = create_signal(String::new());
    let edit_burst = create_signal(String::new());
    let edit_max_concurrent = create_signal(String::new());
    let edit_models = create_signal(std::collections::HashSet::<String>::new());
    let edit_search = create_signal(String::new());

    let total_keys = create_memo(move || client_keys.get_clone().len());

    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "API Keys" }
                div(class="page-sub") {
                    (format!("{} client keys · authenticate via Authorization: Bearer", total_keys.get_clone()))
                }
            }
            (if !show_create.get() {
                view! {
                    button(class="btn btn-primary", on:click=move |_| show_create.set(true)) { "+ Create API Key" }
                }
            } else {
                view! {}
            })
        }

        (match created_banner.get_clone() {
            Some(k) => {
                // The creation response is the only place the secret appears; a
                // key rebuilt from the listing has none to show.
                let secret = k.key.clone().unwrap_or_default();
                let key_txt = secret.clone();
                let key_memo = secret.clone();
                let key_copy = secret;
                let is_copied = create_memo(move || copied_key.get_clone() == key_memo);
                view! {
                    div(class="created-key-box") {
                        div(class="row-between") {
                            b { "API Key Created" }
                            button(class="btn btn-sm", on:click=move |_| created_banner.set(None)) { "✕ Dismiss" }
                        }
                        div(class="dim-text") {
                            "Copy this key now. It provides client access to your configured anyhop models."
                        }
                        div(class="key-text") { (key_txt) }
                        div(class="row mt-4") {
                            button(class="btn btn-primary btn-sm", on:click=move |_| {
                                let text = key_copy.clone();
                                let copied_key = copied_key;
                                spawn_local(async move {
                                    // Only claim success when the clipboard write
                                    // actually succeeded; otherwise the operator
                                    // dismisses the banner and the key is lost.
                                    if copy_to_clipboard(&text).await {
                                        copied_key.set(text);
                                    } else {
                                        copied_key.set("copy failed — select it".to_string());
                                    }
                                    gloo_timers::callback::Timeout::new(2000, move || {
                                        if copied_key.is_alive() { copied_key.set(String::new()); }
                                    }).forget();
                                });
                            }) { (if is_copied.get() { "Copied!" } else { "Copy Key" }) }
                        }
                    }
                }
            }
            None => view! {},
        })

        (if show_create.get() {
            let available_models = create_memo(move || {
                let q = model_search.get_clone().to_lowercase();
                models
                    .get_clone()
                    .into_iter()
                    .filter(|m| q.is_empty() || m.id.to_lowercase().contains(&q) || m.name.to_lowercase().contains(&q))
                    .collect::<Vec<_>>()
            });

            view! {
                div(class="card key-form") {
                    div(class="row-between mb-16") {
                        b { "Create New API Key" }
                        button(class="btn btn-sm", on:click=move |_| show_create.set(false)) { "Cancel" }
                    }

                    div(class="form-group") {
                        label(class="form-label") { "Key Name / Description" }
                        input(class="input", r#type="text", placeholder="e.g. Cursor IDE, OpenWebUI, Team Dev", bind:value=name_input)
                    }

                    div(class="form-group") {
                        label(class="form-label") { "Custom API Key (optional)" }
                        input(class="input", r#type="text", placeholder="Leave empty to auto-generate sk-hop-...", bind:value=key_input)
                    }

                    div(class="form-group") {
                        label(class="form-label") { "Rate limit (optional)" }
                        div(class="row gap-10") {
                            input(
                                class="input input-w200", r#type="number", min="0",
                                placeholder="requests / minute (empty = unlimited)",
                                bind:value=rpm_input,
                            )
                            input(
                                class="input input-w200", r#type="number", min="0",
                                placeholder="burst (default = rpm)",
                                bind:value=burst_input,
                            )
                            input(
                                class="input input-w200", r#type="number", min="0",
                                placeholder="max concurrent (empty = server default)",
                                bind:value=max_concurrent_input,
                            )
                        }
                        div(class="dim-text mb-12") {
                            "Token bucket: rpm is the sustained rate, burst caps the spike. max concurrent limits in-flight requests (429 when exceeded)."
                        }
                    }

                    div(class="form-group") {
                        label(class="form-label") { "Model Access" }
                        div(class="row gap-10 mb-12") {
                            button(
                                class=if !restrict_models.get() { "btn btn-primary btn-sm" } else { "btn btn-sm" },
                                on:click=move |_| restrict_models.set(false),
                            ) { "All Models (unrestricted)" }
                            button(
                                class=if restrict_models.get() { "btn btn-primary btn-sm" } else { "btn btn-sm" },
                                on:click=move |_| restrict_models.set(true),
                            ) { "Specific Models only" }
                        }

                        (if restrict_models.get() {
                            view! {
                                div {
                                    div(class="row mb-8") {
                                        input(class="input input-w250", r#type="text", placeholder="Filter models…", bind:value=model_search)
                                        button(class="btn btn-sm", on:click=move |_| {
                                            let mut s = std::collections::HashSet::new();
                                            for m in models.get_clone() {
                                                s.insert(m.id);
                                            }
                                            selected_models.set(s);
                                        }) { "Select all" }
                                        button(class="btn btn-sm", on:click=move |_| {
                                            selected_models.set(std::collections::HashSet::new());
                                        }) { "Deselect all" }
                                        span(class="badge raw dim") {
                                            (format!("{} selected", selected_models.get_clone().len()))
                                        }
                                    }
                                    div(class="model-picker") {
                                        Indexed(
                                            list=available_models,
                                            view=move |m: ModelItemDto| {
                                                let id = m.id.clone();
                                                let id_check = m.id.clone();
                                                let is_checked = create_memo(move || selected_models.get_clone().contains(&id_check));
                                                view! {
                                                    label(class="model-picker-item") {
                                                        input(
                                                            r#type="checkbox",
                                                            checked=is_checked.get(),
                                                            on:change=move |_| {
                                                                let mut s = selected_models.get_clone();
                                                                if s.contains(&id) {
                                                                    s.remove(&id);
                                                                } else {
                                                                    s.insert(id.clone());
                                                                }
                                                                selected_models.set(s);
                                                            },
                                                        )
                                                        span(class="mono") { (m.id.clone()) }
                                                        span(class="badge dim") { (m.provider.clone()) }
                                                    }
                                                }
                                            },
                                        )
                                    }
                                }
                            }
                        } else {
                            view! {}
                        })
                    }

                    (if !copy_status.get_clone().is_empty() {
                        view! { div(class="auth-banner auth-error flush") { (copy_status.get_clone()) } }
                    } else {
                        view! {}
                    })

                    div(class="row gap-10 mt-20") {
                        button(class="btn btn-primary", on:click=move |_| {
                            let name = name_input.get_clone();
                            let key = key_input.get_clone();
                            // `None` = leave unset (unlimited). Parsing junk into 0
                            // used to post "unlimited" silently.
                            let rpm = rpm_input.get_clone().trim().parse::<u32>().ok().filter(|n| *n > 0);
                            let burst = burst_input.get_clone().trim().parse::<u32>().ok().filter(|n| *n > 0);
                            let max_concurrent = max_concurrent_input
                                .get_clone()
                                .trim()
                                .parse::<u32>()
                                .ok()
                                .filter(|n| *n > 0);
                            let models_vec = if restrict_models.get() {
                                selected_models.get_clone().into_iter().collect::<Vec<_>>()
                            } else {
                                Vec::new()
                            };
                            spawn_local(async move {
                                let body = serde_json::json!({
                                    "name": if name.trim().is_empty() { None } else { Some(name.trim()) },
                                    "key": if key.trim().is_empty() { None } else { Some(key.trim()) },
                                    "models": models_vec,
                                    "rpm": rpm,
                                    "burst": burst,
                                    "max_concurrent": max_concurrent,
                                });
                                let req = match Request::post("/api/client-keys/add").json(&body) {
                                    Ok(r) => r,
                                    Err(e) => {
                                        create_error.set(format!("bad request: {e}"));
                                        return;
                                    }
                                };
                                if let Some(k) = stored_key() {
                                    req.headers().set("Authorization", &format!("Bearer {k}"));
                                }
                                let resp = match req.send().await {
                                    Ok(r) => r,
                                    Err(e) => {
                                        if create_error.is_alive() {
                                            create_error.set(format!("network error: {e}"));
                                        }
                                        return;
                                    }
                                };
                                // The tab may be gone after the await — all the
                                // signals below live in its scope.
                                if !create_error.is_alive() {
                                    return;
                                }
                                if resp.status() == 200 {
                                    if let Ok(dto) = resp.json::<ClientKeyDto>().await {
                                        created_banner.set(Some(dto));
                                        create_error.set(String::new());
                                        reload_client_keys(client_keys).await;
                                        name_input.set(String::new());
                                        key_input.set(String::new());
                                        selected_models.set(std::collections::HashSet::new());
                                        restrict_models.set(false);
                                        show_create.set(false);
                                    }
                                } else {
                                    let text = resp.text().await.unwrap_or_default();
                                    create_error.set(format!("error {}: {}", resp.status(), text));
                                }
                            });
                        }) { "Create API Key" }
                        button(class="btn", on:click=move |_| show_create.set(false)) { "Cancel" }
                    }
                    (if !create_error.get_clone().is_empty() {
                        view! { div(class="auth-banner auth-error flush") { (create_error.get_clone()) } }
                    } else {
                        view! {}
                    })
                }
            }
        } else {
            view! {}
        })

        div(class="section-title") {
            "Client keys"
            span(class="cnt") { (format!("{} total", total_keys.get_clone())) }
        }
        div(class="card") {
            (if client_keys.get_clone().is_empty() {
                view! {
                    div(class="empty") {
                        div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                        "No API keys created yet. Create one to authenticate client apps."
                    }
                }
            } else {
                view! {
                    div(class="key-list") {
                        Indexed(
                            list=client_keys,
                            view=move |k: ClientKeyDto| {
                                let k_key_reveal_memo = k.id.clone();
                                let k_key_copy = k.id.clone();
                                let k_key_edit = k.id.clone();
                                let k_key_del = k.id.clone();
                                let k_key_btn_rev = k.id.clone();
                                let k_key_btn_cp = k.id.clone();
                                let k_key_btn_ed = k.id.clone();
                                let k_models_btn_ed = k.models.clone();
                                let k_lim_btn_ed = k.rpm;
                                let k_burst_btn_ed = k.burst;
                                let k_conc_btn_ed = k.max_concurrent;
                                let k_name = k.name.clone();
                                let k_created_at = k.created_at;
                                let k_rpm = k.rpm;
                                let k_models = k.models.clone();

                                let is_rev = create_memo(move || revealed.get_clone().contains_key(&k_key_reveal_memo));
                                let is_copied = create_memo(move || copied_key.get_clone() == k_key_copy);
                                let is_editing = create_memo(move || editing_key.get_clone().as_deref() == Some(&k_key_edit));

                                let masked = k.masked.clone();
                                let k_key_display = k.id.clone();
                                let display_key = create_memo(move || {
                                    match revealed.get_clone().get(&k_key_display) {
                                        Some(secret) => secret.clone(),
                                        None => masked.clone(),
                                    }
                                });

                                let models_display = if k_models.is_empty() {
                                    view! { span(class="dim-text") { "All models" } }
                                } else {
                                    let n = k_models.len();
                                    let chips: Vec<View> = k_models
                                        .into_iter()
                                        .map(|m| view! { span(class="model-chip") { (m) } })
                                        .collect();
                                    view! {
                                        span(class="dim-text") { (format!("{n} models:")) }
                                        (chips)
                                    }
                                };

                                let edit_drawer = if is_editing.get() {
                                    let avail = create_memo(move || {
                                        let q = edit_search.get_clone().to_lowercase();
                                        models
                                            .get_clone()
                                            .into_iter()
                                            .filter(|m| q.is_empty() || m.id.to_lowercase().contains(&q) || m.name.to_lowercase().contains(&q))
                                            .collect::<Vec<_>>()
                                    });
                                    let k_save_key = k.key.clone();
                                    let k_edit_rpm = k.rpm;
                                    let k_edit_burst = k.burst;
                                    view! {
                                        div(class="drawer mt-12") {
                                            div(class="row mb-8") {
                                                b(class="text-13") { "Edit Allowed Models:" }
                                                input(class="input input-w200", r#type="text", placeholder="Filter…", bind:value=edit_search)
                                                button(class="btn btn-sm", on:click=move |_| {
                                                    let mut s = std::collections::HashSet::new();
                                                    for m in models.get_clone() {
                                                        s.insert(m.id);
                                                    }
                                                    edit_models.set(s);
                                                }) { "Select all" }
                                                button(class="btn btn-sm", on:click=move |_| {
                                                    edit_models.set(std::collections::HashSet::new());
                                                }) { "Deselect all (allow all)" }
                                            }
                                            div(class="model-picker sm") {
                                                Indexed(
                                                    list=avail,
                                                    view=move |m: ModelItemDto| {
                                                        let id = m.id.clone();
                                                        let id_c = m.id.clone();
                                                        let is_ch = create_memo(move || edit_models.get_clone().contains(&id_c));
                                                        view! {
                                                            label(class="model-picker-item") {
                                                                input(
                                                                    r#type="checkbox",
                                                                    checked=is_ch.get(),
                                                                    on:change=move |_| {
                                                                        let mut s = edit_models.get_clone();
                                                                        if s.contains(&id) {
                                                                            s.remove(&id);
                                                                        } else {
                                                                            s.insert(id.clone());
                                                                        }
                                                                        edit_models.set(s);
                                                                    },
                                                                )
                                                                span(class="mono") { (m.id.clone()) }
                                                            }
                                                        }
                                                    },
                                                )
                                            }
                                            div(class="row mt-16 mb-8") {
                                                b(class="text-13") { "Rate limit:" }
                                                input(
                                                    class="input input-w200", r#type="number", min="0",
                                                    placeholder="rpm (0 = unlimited)",
                                                    bind:value=edit_rpm,
                                                    value=if k_edit_rpm > 0 { k_edit_rpm.to_string() } else { String::new() },
                                                )
                                                input(
                                                    class="input input-w200", r#type="number", min="0",
                                                    placeholder="burst (0 = same as rpm)",
                                                    bind:value=edit_burst,
                                                    value=if k_edit_burst > 0 { k_edit_burst.to_string() } else { String::new() },
                                                )
                                                input(
                                                    class="input input-w200", r#type="number", min="0",
                                                    placeholder="max concurrent (empty = default)",
                                                    bind:value=edit_max_concurrent,
                                                )
                                            }
                                            div(class="row mt-10") {
                                                button(class="btn btn-primary btn-sm", on:click=move |_| {
                                                    let key = k_save_key.clone();
                                                    let m_list: Vec<String> = edit_models.get_clone().into_iter().collect();
                                                    // Empty means "unchanged": sending 0 would clear
                                                    // the limit, which is not what an untouched
                                                    // field means.
                                                    let rpm: Option<u32> = edit_rpm.get_clone().trim().parse().ok();
                                                    let burst: Option<u32> = edit_burst.get_clone().trim().parse().ok();
                                                    let conc: Option<u32> = edit_max_concurrent.get_clone().trim().parse().ok();
                                                    spawn_local(async move {
                                                        let body = serde_json::json!({
                                                            "key": key,
                                                            "models": m_list,
                                                            "rpm": rpm,
                                                            "burst": burst,
                                                            "max_concurrent": conc,
                                                        });
                                                        post_json("/api/client-keys/update", &body).await;
                                                        reload_client_keys(client_keys).await;
                                                        if editing_key.is_alive() {
                                                            editing_key.set(None);
                                                        }
                                                    });
                                                }) { "Save models" }
                                                button(class="btn btn-sm", on:click=move |_| editing_key.set(None)) { "Cancel" }
                                            }
                                        }
                                    }
                                } else {
                                    view! {}
                                };

                                view! {
                                    div(class="client-key-row") {
                                        div(class="client-key-head") {
                                            b { (k_name) }
                                            span(class="mono dim-text") { (display_key.get_clone()) }
                                            (if k_rpm > 0 {
                                                view! { span(class="badge raw") { (format!("{k_rpm} rpm")) } }
                                            } else {
                                                view! {}
                                            })
                                            (if k_created_at > 0 {
                                                view! { span(class="dim-text") { (fmt_datetime(k_created_at)) } }
                                            } else {
                                                view! {}
                                            })
                                            div(class="client-key-actions") {
                                                button(class="btn-ghost", on:click=move |_| {
                                                    let id = k_key_btn_rev.clone();
                                                    if revealed.get_clone().contains_key(&id) {
                                                        let mut map = revealed.get_clone();
                                                        map.remove(&id);
                                                        revealed.set(map);
                                                        return;
                                                    }
                                                    spawn_local(async move {
                                                        match post_json_result::<_, serde_json::Value>(
                                                            "/api/client-keys/reveal",
                                                            &serde_json::json!({"id": id.clone()}),
                                                        ).await {
                                                            Ok(v) => {
                                                                if let Some(secret) = v.get("key").and_then(|k| k.as_str()) {
                                                                    let mut map = revealed.get_clone();
                                                                    map.insert(id, secret.to_string());
                                                                    revealed.set(map);
                                                                }
                                                            }
                                                            Err(e) => {
                                                                if copy_status.is_alive() {
                                                                    copy_status.set(format!("cannot reveal the key: {e}"));
                                                                }
                                                            }
                                                        }
                                                    });
                                                }) { (if is_rev.get() { "Hide" } else { "Show" }) }

                                                button(class="btn-ghost", on:click=move |_| {
                                                    let id = k_key_btn_cp.clone();
                                                    let copied_key = copied_key;
                                                    spawn_local(async move {
                                                        // The listing has no secret: fetch it, then copy.
                                                        let secret = match revealed.get_clone().get(&id) {
                                                            Some(s) => Ok(s.clone()),
                                                            None => post_json_result::<_, serde_json::Value>(
                                                                "/api/client-keys/reveal",
                                                                &serde_json::json!({"id": id.clone()}),
                                                            )
                                                            .await
                                                            .map(|v| v["key"].as_str().unwrap_or_default().to_string()),
                                                        };
                                                        let key_str = match secret {
                                                            Ok(s) if !s.is_empty() => s,
                                                            Ok(_) => String::new(),
                                                            Err(e) => {
                                                                if copy_status.is_alive() {
                                                                    copy_status.set(format!("cannot reveal the key: {e}"));
                                                                }
                                                                String::new()
                                                            }
                                                        };
                                                        if key_str.is_empty() {
                                                            return;
                                                        }
                                                        if copy_to_clipboard(&key_str).await {
                                                            copied_key.set(key_str);
                                                        }
                                                        gloo_timers::callback::Timeout::new(2000, move || {
                                                            if copied_key.is_alive() { copied_key.set(String::new()); }
                                                        }).forget();
                                                    });
                                                }) { (if is_copied.get() { "Copied" } else { "Copy" }) }

                                                button(class="btn-ghost", on:click=move |_| {
                                                    if is_editing.get() {
                                                        editing_key.set(None);
                                                    } else {
                                                        edit_models.set(k_models_btn_ed.iter().cloned().collect());
                                                        // Seed the limit fields too, otherwise an
                                                        // untouched input sends 0 and wipes the limit.
                                                        edit_rpm.set(if k_lim_btn_ed > 0 { k_lim_btn_ed.to_string() } else { String::new() });
                                                        edit_burst.set(if k_burst_btn_ed > 0 { k_burst_btn_ed.to_string() } else { String::new() });
                                                        edit_max_concurrent.set(k_conc_btn_ed.map(|n| n.to_string()).unwrap_or_default());
                                                        editing_key.set(Some(k_key_btn_ed.clone()));
                                                    }
                                                }) { "Models" }

                                                button(class="btn-ghost btn-ghost-danger", on:click=move |_| {
                                                    // A misclick here revokes a key that clients are
                                                    // using right now, so ask first.
                                                    confirm_delete.set(Some(k_key_del.clone()));
                                                }) { "Delete" }
                                            }
                                        }
                                        div(class="client-key-models") {
                                            (models_display)
                                        }
                                        (edit_drawer)
                                    }
                                }
                            },
                        )
                    }
                }
            })
        }

        // Delete confirmation modal.
        (match confirm_delete.get_clone() {
            Some(key) => {
                let key_del = key.clone();
                let key_label = key.clone();
                view! {
                    div(class="modal-overlay", on:click=move |_| confirm_delete.set(None)) {
                        div(class="modal", on:click=move |e: web_sys::MouseEvent| e.stop_propagation()) {
                            div(class="modal-head") { "Delete this API key?" }
                            div(class="modal-body") {
                                div(class="dim-text mb-12") {
                                    "Any client using it will immediately get 401. This cannot be undone."
                                }
                                div(class="mono text-13") { (mask_key(&key_label)) }
                            }
                            div(class="modal-actions") {
                                button(class="btn", on:click=move |_| confirm_delete.set(None)) { "Cancel" }
                                button(class="btn btn-danger", on:click=move |_| {
                                    let key = key_del.clone();
                                    confirm_delete.set(None);
                                    spawn_local(async move {
                                        let body = serde_json::json!({"key": key});
                                        post_json("/api/client-keys/delete", &body).await;
                                        reload_client_keys(client_keys).await;
                                    });
                                }) { "Delete key" }
                            }
                        }
                    }
                }
            }
            None => view! {},
        })
    }
}
