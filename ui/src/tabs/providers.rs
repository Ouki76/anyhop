use gloo_net::http::Request;

use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::*;
use crate::util::*;

const KNOWN_TYPES: &[(&str, &str, &str)] = &[
    (
        "antigravity",
        "Antigravity",
        "Google OAuth accounts · Gemini/Claude",
    ),
    ("codex", "Codex", "ChatGPT OAuth accounts"),
    ("gemini", "Gemini API", "any compatible endpoint"),
    ("anthropic", "Anthropic API", "any compatible endpoint"),
    (
        "openai_compat",
        "OpenAI-compatible",
        "any Chat Completions endpoint",
    ),
];

#[component(inline_props)]
pub fn ProvidersTab(providers: Signal<Vec<ProviderDto>>, selected: Signal<Option<String>>) -> View {
    let go = move |name: Option<String>| {
        selected.set(name.clone());
        if let Some(w) = web_sys::window() {
            let h = match &name {
                Some(n) => format!("providers/{n}"),
                None => "providers".into(),
            };
            let _ = w.location().set_hash(&h);
        }
    };

    view! {
        (match selected.get_clone() {
            Some(name) => view! { ProviderDetail(name=name, providers=providers) },
            None => view! { ProviderCatalog(providers=providers, go=go) },
        })
    }
}

#[component(inline_props)]
pub fn ProviderCatalog(
    providers: Signal<Vec<ProviderDto>>,
    go: impl Fn(Option<String>) + Copy + 'static,
) -> View {
    // Which KNOWN_TYPES entry is being added right now (modal open state).
    let adding: Signal<Option<&'static str>> = create_signal(None);
    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Providers" }
                div(class="page-sub") { "Upstream providers — accounts, API keys and rotation" }
            }
        }

        div(class="section-title") {
            "Configured"
            span(class="cnt") {
                (match providers.get_clone().len() {
                    1 => "1 provider".to_string(),
                    n => format!("{n} providers"),
                })
            }
        }
        ((move || {
            let ps = providers.get_clone();
            if ps.is_empty() {
                view! { div(class="card") { div(class="empty") {
                    div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                    "No providers configured yet — pick one below"
                } } }
            } else {
                let rows: Vec<View> = ps
                    .into_iter()
                    .map(|p| {
                        let total = p.keys.len();
                        let active = p.keys.iter().filter(|k| k.status == "active").count();
                        let reqs: u64 = p.keys.iter().map(|k| k.requests).sum();
                        let toks: u64 = p.keys.iter().map(|k| k.prompt_tokens + k.completion_tokens).sum();
                        let health = if total > 0 && active == 0 {
                            "pdot pdot-err"
                        } else if active < total {
                            "pdot pdot-warn"
                        } else {
                            "pdot pdot-ok"
                        };
                        let name = p.name.clone();
                        view! {
                            div(class="key-row prov-row", on:click=move |_| go(Some(name.clone()))) {
                                span(class=health) {}
                                b { (p.name) }
                                span(class="badge accent") { (p.kind) }
                                span(class="key-stats") {
                                    (format!("{active}/{total} keys · {} req · {} tok",
                                        fmt_num(reqs), fmt_num(toks)))
                                }
                            }
                        }
                    })
                    .collect();
                view! { div(class="card") { div(class="key-list") { (rows) } } }
            }
        })())

        ((move || {
            // Every type is offered: a second provider of the same kind is
            // legitimate (two OpenAI-compatible endpoints, two Anthropic keys
            // with different base URLs). The suggested name is made unique so
            // the backend's duplicate-name check does not reject it.
            let available: Vec<(&'static str, &'static str, &'static str)> =
                KNOWN_TYPES.to_vec();
            {
                let n = available.len();
                let rows: Vec<View> = available
                    .into_iter()
                    .map(|(kind, title, desc)| {
                        let existing = providers
                            .get_clone()
                            .iter()
                            .any(|p| p.kind == kind);
                        let action = if existing { "Add another" } else { "Set up" };
                        view! {
                            div(class="key-row prov-row", on:click=move |_| adding.set(Some(kind))) {
                                span(class="pdot pdot-dim") {}
                                b { (title) }
                                span(class="ev-detail") { (desc) }
                                span(class="setup-link") { (action) }
                            }
                        }
                    })
                    .collect();
                view! {
                    div(class="section-title") {
                        "Available"
                        span(class="cnt") { (format!("{n} types")) }
                    }
                    div(class="card avail-list") {
                        div(class="key-list") { (rows) }
                    }
                }
            }
        })())

        (match adding.get_clone() {
            Some(kind) => {
                let (_, title, desc) = KNOWN_TYPES
                    .iter()
                    .copied()
                    .find(|(k, _, _)| *k == kind)
                    .unwrap_or((kind, kind, ""));
                // provider names are unique: suffix a second instance
                let existing: Vec<String> = providers
                    .get_clone()
                    .into_iter()
                    .map(|p| p.name)
                    .collect();
                let mut suggested = kind.to_string();
                let mut n = 2;
                while existing.contains(&suggested) {
                    suggested = format!("{kind}-{n}");
                    n += 1;
                }
                view! {
                    AddProviderModal(
                        kind=kind, title=title, desc=desc,
                        default_name=suggested, close=adding, go=go,
                    )
                }
            }
            None => view! {},
        })
    }
}

/// "Set up" modal for an available provider type: key-based kinds get a
/// name/base_url/key form (POST /api/providers/add), OAuth kinds start the
/// browser sign-in flow. Both paths hot-reload the gateway server-side.
#[component(inline_props)]
pub fn AddProviderModal(
    kind: &'static str,
    title: &'static str,
    desc: &'static str,
    default_name: String,
    close: Signal<Option<&'static str>>,
    go: impl Fn(Option<String>) + Copy + 'static,
) -> View {
    let oauth = kind == "antigravity" || kind == "codex";
    let name = create_signal(default_name);
    let default_url = match kind {
        "gemini" => "https://generativelanguage.googleapis.com/v1beta",
        "anthropic" => "https://api.anthropic.com",
        _ => "",
    };
    let base_url = create_signal(default_url.to_string());
    let key = create_signal(String::new());
    let error = create_signal(String::new());
    let busy = create_signal(false);
    let auth = create_signal(Option::<AuthStateDto>::None);
    let paste_url = create_signal(String::new());
    // The name the OAuth flow should create/populate (a second antigravity
    // provider gets its own account pool this way).
    let name_for_auth = name;

    let start_oauth = move |_| {
        spawn_local(async move {
            let body = serde_json::json!({
                "kind": kind,
                "provider": name_for_auth.get_clone(),
            });
            // Report failures: a 401/409/500 used to parse into the error envelope,
            // find no `url` and return silently — the button looked dead.
            let v = match post_json_result::<_, serde_json::Value>("/api/auth/start", &body).await {
                Ok(v) => v,
                Err(e) => {
                    if error.is_alive() {
                        error.set(format!("cannot start sign-in: {e}"));
                    }
                    return;
                }
            };
            let Some(url) = v.get("url").and_then(|u| u.as_str()).map(str::to_string) else {
                if error.is_alive() {
                    error.set("cannot start sign-in: the server returned no URL".into());
                }
                return;
            };
            let mode = v
                .get("mode")
                .and_then(|m| m.as_str())
                .unwrap_or("loopback")
                .to_string();
            // The modal may have been closed while the request was in flight.
            if !auth.is_alive() {
                return;
            }
            auth.set(Some(AuthStateDto {
                kind: kind.into(),
                provider: String::new(),
                status: "waiting".into(),
                url: url.clone(),
                mode,
                message: "waiting for browser callback".into(),
            }));
            if let Some(w) = web_sys::window() {
                let _ = w.open_with_url_and_target(&url, "_blank");
            }
            let mut failures = 0;
            loop {
                gloo_timers::future::sleep(std::time::Duration::from_secs(2)).await;
                if !auth.is_alive() {
                    break; // modal closed mid-flow
                }
                match fetch_json::<AuthStateDto>("/api/auth/status").await {
                    Some(s) if s.kind != kind && s.status == "waiting" => {
                        // Another tab started a different provider's flow; do not
                        // adopt it, just keep waiting for ours.
                        failures += 1;
                        if failures >= 10 {
                            break;
                        }
                    }
                    Some(s) => {
                        failures = 0;
                        let done = s.status == "done";
                        let terminal = s.status != "waiting";
                        auth.set(Some(s));
                        if terminal {
                            if done {
                                // account saved + reloaded server-side; the provider
                                // was auto-created with name = kind
                                close.set(None);
                                go(Some(kind.to_string()));
                            }
                            break;
                        }
                    }
                    None => {
                        // status endpoint failing (e.g. 401) — don't poll forever
                        failures += 1;
                        if failures >= 5 {
                            break;
                        }
                    }
                }
            }
        });
    };

    let submit = move |_| {
        if busy.get() {
            return;
        }
        let k = key.get_clone();
        let u = base_url.get_clone();
        let n = name.get_clone();
        if k.trim().len() < 4 {
            error.set("API key is required".into());
            return;
        }
        if kind == "openai_compat" && u.trim().is_empty() {
            error.set("Base URL is required for OpenAI-compatible providers".into());
            return;
        }
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            let body = serde_json::json!({
                "kind": kind,
                "name": n.trim(),
                "base_url": u.trim(),
                "key": k.trim(),
            });
            let req = match Request::post("/api/providers/add").json(&body) {
                Ok(r) => r,
                Err(e) => {
                    error.set(format!("bad request: {e}"));
                    busy.set(false);
                    return;
                }
            };
            if let Some(k) = stored_key() {
                req.headers().set("Authorization", &format!("Bearer {k}"));
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    if error.is_alive() {
                        error.set(format!("network error: {e}"));
                        busy.set(false);
                    }
                    return;
                }
            };
            if resp.status() == 200 {
                let added = resp
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|v| v.get("name").and_then(|x| x.as_str()).map(str::to_string));
                // The modal (or its whole tab) may be gone after the awaits.
                if close.is_alive() {
                    close.set(None);
                }
                if let Some(n) = added {
                    go(Some(n));
                }
            } else {
                let msg = format!(
                    "error {}: {}",
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                );
                if error.is_alive() {
                    error.set(msg);
                    busy.set(false);
                }
            }
        });
    };

    view! {
        div(class="modal-overlay", on:click=move |_| close.set(None)) {
            div(class="modal", on:click=|e: web_sys::MouseEvent| e.stop_propagation()) {
                div(class="modal-head") {
                    b { (title) }
                    span(class="badge accent") { (kind) }
                    button(class="btn-ghost modal-close", on:click=move |_| close.set(None)) { "✕" }
                }
                div(class="modal-body") {
                    div(class="dim-text mb-12") { (desc) }
                    (if oauth {
                        view! {
                            div {
                                div(class="form-group") {
                                    label(class="form-label") { "Provider name" }
                                    input(class="input", r#type="text", bind:value=name)
                                    div(class="form-hint") {
                                        "Several providers of the same type can coexist with separate account pools."
                                    }
                                }
                                div(class="modal-note") {
                                    "Opens a browser window for account sign-in. The provider is created once the account is authorized."
                                }
                                (match auth.get_clone() {
                                    Some(a) => {
                                        let cls = format!("auth-banner auth-{} flush", a.status);
                                        let msg = if a.status == "waiting" {
                                            "Authorization opened in a new tab — complete the sign-in".to_string()
                                        } else {
                                            a.message
                                        };
                                        let waiting = a.status == "waiting";
                                        view! {
                                            div(class=cls) { (msg) }
                                            (if waiting {
                                                view! {
                                                    div(class="form-group mt-12") {
                                                        label(class="form-label") { "Browser could not reach this gateway?" }
                                                        input(
                                                            class="input", r#type="text",
                                                            placeholder="paste the URL your browser ended up on",
                                                            bind:value=paste_url,
                                                        )
                                                        div(class="form-hint") {
                                                            "Copy the full address from the address bar (it contains code=…) and press Complete."
                                                        }
                                                    }
                                                    div(class="row gap-10") {
                                                        button(class="btn btn-sm", on:click=move |_| {
                                                            let v = paste_url.get_clone();
                                                            if v.trim().is_empty() { return; }
                                                            spawn_local(async move {
                                                                let _ = post_json("/api/auth/complete", &serde_json::json!({"url": v})).await;
                                                                if paste_url.is_alive() { paste_url.set(String::new()); }
                                                            });
                                                        }) { "Complete sign-in" }
                                                    }
                                                }
                                            } else {
                                                view! {}
                                            })
                                        }
                                    }
                                    None => view! {},
                                })
                            }
                        }
                    } else {
                        view! {
                            div {
                                div(class="form-group") {
                                    label(class="form-label") { "Name" }
                                    input(class="input", r#type="text", bind:value=name)
                                }
                                div(class="form-group") {
                                    label(class="form-label") { "Base URL" }
                                    input(class="input", r#type="text", placeholder="https://…/v1", bind:value=base_url)
                                }
                                div(class="form-group") {
                                    label(class="form-label") { "API key" }
                                    input(class="input", r#type="password", placeholder="sk-…", bind:value=key)
                                }
                                div(class="modal-note") { "Saved to anyhop.toml · hot-reloads the gateway" }
                            }
                        }
                    })
                    (if !error.get_clone().is_empty() {
                        view! { div(class="auth-banner auth-error flush", role="alert") { (error.get_clone()) } }
                    } else {
                        view! {}
                    })
                }
                div(class="modal-actions") {
                    button(class="btn", on:click=move |_| {
                        let waiting = auth
                            .get_clone()
                            .is_some_and(|a| a.status == "waiting");
                        spawn_local(async move {
                            // Abandoning the dialog must abandon the flow: a waiting
                            // flow holds the local callback port and would hijack the
                            // next "add account".
                            if waiting {
                                let _ = post_json("/api/auth/cancel", &serde_json::json!({})).await;
                            }
                            if auth.is_alive() {
                                auth.set(None);
                            }
                            if close.is_alive() {
                                close.set(None);
                            }
                        });
                    }) {
                        (if auth.get_clone().is_some_and(|a| a.status == "waiting") {
                            "Cancel sign-in"
                        } else {
                            "Cancel"
                        })
                    }
                    (if oauth {
                        view! {
                            button(class="btn btn-primary", on:click=start_oauth) { "Authorize account" }
                        }
                    } else {
                        view! {
                            button(class="btn btn-primary", on:click=submit) {
                                (if busy.get() { "Adding…" } else { "Add provider" })
                            }
                        }
                    })
                }
            }
        }
    }
}

#[component(inline_props)]
pub fn ProviderDetail(name: String, providers: Signal<Vec<ProviderDto>>) -> View {
    view! {
        a(class="back-link", href="#providers") { "all providers" }
        (match providers.get_clone().into_iter().find(|p| p.name == name) {
            Some(p) => {
                view! {
                    ProviderCard(p=p)
                }
            }
            None => {
                let msg = format!("provider '{name}' not found in config — add it via Config tab");
                view! {
                    div(class="card") { div(class="empty") {
                        div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                        (msg)
                    } }
                }
            }
        })
    }
}

#[component(inline_props)]
pub fn ProviderCard(p: ProviderDto) -> View {
    let pname_rows = p.name.clone();
    let pname_footer = p.name.clone();
    let p_settings = p.clone();
    let p_danger = p.name.clone();
    let pkind_footer = p.kind.clone();
    let oauth = p.kind == "antigravity" || p.kind == "codex";

    let total = p.keys.len();
    let active = p.keys.iter().filter(|k| k.status == "active").count();
    let dead = p.keys.iter().filter(|k| k.status == "dead").count();
    let cool = p.keys.iter().filter(|k| k.status == "cooldown").count();
    let requests: u64 = p.keys.iter().map(|k| k.requests).sum();
    let failures: u64 = p.keys.iter().map(|k| k.failures).sum();
    let tokens: u64 = p
        .keys
        .iter()
        .map(|k| k.prompt_tokens + k.completion_tokens)
        .sum();
    let in_flight: u64 = p.keys.iter().map(|k| k.in_flight as u64).sum();

    let (dot, band_msg) = if total == 0 {
        ("ok-dot warn", "No keys configured".to_string())
    } else if dead == total {
        ("ok-dot err", format!("All {total} keys dead"))
    } else if dead > 0 || cool > 0 {
        let mut parts = Vec::new();
        if dead > 0 {
            parts.push(format!("{dead} dead"));
        }
        if cool > 0 {
            parts.push(format!("{cool} cooling down"));
        }
        ("ok-dot warn", parts.join(" · "))
    } else {
        ("ok-dot ok", "All keys operational".to_string())
    };

    let footer = if oauth {
        view! { OAuthAddButton(kind=pkind_footer, provider=pname_footer) }
    } else {
        view! { AddKeyForm(provider=pname_footer) }
    };

    let list_view = if p.keys.is_empty() {
        view! {
            div(class="empty") {
                div(class="pix") { i {} i {} i {} i {} i {} i {} i {} i {} i {} }
                "No keys yet — add one below"
            }
        }
    } else {
        view! {
            div(class="key-list") {
                Indexed(
                    list=create_signal(p.keys),
                    view=move |k: KeyDto| {
                        let chip = format!("chip chip-{}", k.status);
                        let status = k.status.clone();
                        let prov = pname_rows.clone();
                        let prov_del = pname_rows.clone();
                        let masked_del = k.masked.clone();
                        let id_act = k.id.clone();
                        let id_del = k.id.clone();
                        let stats = format!(
                            "{} req · {} fail · {} in / {} out",
                            fmt_num(k.requests), fmt_num(k.failures),
                            fmt_num(k.prompt_tokens), fmt_num(k.completion_tokens)
                        );
                        let cooldown_v = if k.cooldown_remaining_secs > 0 {
                            view! { span(class="key-cooldown") { (format!("cooldown {}s", k.cooldown_remaining_secs)) } }
                        } else { view! {} };
                        let inflight_v = if k.in_flight > 0 {
                            view! { span(class="key-inflight") { (format!("▶ {}", k.in_flight)) } }
                        } else { view! {} };
                        view! {
                            div(class="key-row") {
                                span(class=chip) { (k.status) }
                                span(class="mono key-id") { (k.masked) }
                                (inflight_v)
                                span(class="key-stats") { (stats) }
                                (cooldown_v)
                                KeyActionButton(provider=prov, id=id_act, status=status)
                                KeyDeleteButton(provider=prov_del, id=id_del, masked=masked_del)
                            }
                        }
                    },
                )
            }
        }
    };

    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { (p.name) }
                div(class="page-sub badges") {
                    span(class="badge accent") { (p.kind) }
                    span(class="badge") { (p.strategy) }
                    span(class="badge raw") { (p.base_url) }
                }
            }
        }

        div(class="ok-band") {
            span(class=dot) {}
            b { (band_msg) }
            span(class="meta") {
                (format!("{active}/{total} keys · {} in flight · {} failed",
                    fmt_num(in_flight), fmt_num(failures)))
            }
        }

        div(class="bignums") {
            div(class="bignum") {
                div(class="n") { (active) span(class="u") { (format!("/{total}")) } }
                div(class="l") { "Keys active" }
            }
            div(class="bignum") {
                div(class="n") { (fmt_num(requests)) }
                div(class="l") { "Requests" }
            }
            div(class="bignum") {
                div(class="n") { (fmt_num(tokens)) }
                div(class="l") { "Tokens" }
            }
            div(class="bignum") {
                div(class="n") { (fmt_num(in_flight)) }
                div(class="l") { "In flight" }
            }
        }

        div(class="section-title") {
            "Keys"
            span(class="cnt") { (format!("{total} configured")) }
        }
        div(class="card") {
            (list_view)
            (footer)
        }

        ProviderSettings(provider=p_settings)

        div(class="section-title") { "Danger zone" }
        div(class="card danger-card") {
            div(class="row-between") {
                div {
                    b { "Delete this provider" }
                    div(class="dim-text") {
                        "Removes it from the config, together with any combo that references it. Keys and stats are lost."
                    }
                }
                DeleteProviderButton(provider=p_danger)
            }
        }
    }
}

/// Edit the settings the config exposes for a provider (POST /api/providers/update).
#[component(inline_props)]
pub fn ProviderSettings(provider: ProviderDto) -> View {
    let pname = provider.name.clone();
    let base_url = create_signal(provider.base_url.clone());
    let strategy = create_signal(provider.strategy.clone());
    let max_concurrent = create_signal(provider.max_concurrent.to_string());
    let drain_pct = create_signal(provider.drain_below_pct.to_string());
    let proxy = create_signal(provider.proxy.clone().unwrap_or_default());
    let timeout_secs = create_signal(provider.timeout_secs.to_string());
    let max_retries = create_signal(provider.max_retries.to_string());
    let saved = create_signal(false);
    let error = create_signal(String::new());

    view! {
        div(class="section-title") { "Settings" }
        div(class="card") {
            div(class="card-head") { b { "Provider" } }
            div(class="settings-grid cols-2") {
                div(class="form-group") {
                    label(class="form-label") { "Base URL" }
                    input(class="input", r#type="text", bind:value=base_url)
                }
                div(class="form-group") {
                    label(class="form-label") { "Rotation strategy" }
                    select(class="select", bind:value=strategy) {
                        option(value="round_robin") { "round_robin" }
                        option(value="least_used") { "least_used" }
                        option(value="fill_first") { "fill_first" }
                    }
                    div(class="form-hint") {
                        (match strategy.get_clone().as_str() {
                            "least_used" => "Each request goes to the key with the fewest requests.",
                            "fill_first" => "Exhausts one key's quota before moving to the next.",
                            _ => "Spreads requests evenly across all keys.",
                        })
                    }
                }
                div(class="form-group") {
                    label(class="form-label") { "Max concurrent per key" }
                    input(class="input", r#type="number", min="0", bind:value=max_concurrent)
                    div(class="form-hint") { "0 = unlimited" }
                }
                div(class="form-group") {
                    label(class="form-label") { "Drain below %" }
                    input(class="input", r#type="number", min="0", max="100", bind:value=drain_pct)
                    div(class="form-hint") { "Proactive cooldown before a key hits its limit. 0 = off" }
                }
                div(class="form-group") {
                    label(class="form-label") { "Attempt timeout, s" }
                    input(class="input", r#type="number", min="1", bind:value=timeout_secs)
                    div(class="form-hint") { "Per attempt. Slow upstreams may need minutes." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Max attempts" }
                    input(class="input", r#type="number", min="1", max="32", bind:value=max_retries)
                    div(class="form-hint") { "Each attempt uses a different key." }
                }
                div(class="form-group span-2") {
                    label(class="form-label") { "Proxy (http / socks5)" }
                    input(class="input", r#type="text", placeholder="empty = direct connection", bind:value=proxy)
                    div(class="form-hint") { "Credentials are masked; leave the *** value untouched to keep them." }
                }
            }
            (if error.get_clone().is_empty() {
                view! {}
            } else {
                view! { div(class="auth-banner auth-error flush", role="alert") { (error.get_clone()) } }
            })
            div(class="card-foot") {
                button(class="btn btn-primary", on:click=move |_| {
                    // A number that does not parse must be *omitted* (leave the value
                    // alone), not sent as 0: `max_concurrent = 0` means "unlimited",
                    // so a typo silently removed the cap.
                    let body = serde_json::json!({
                        "name": pname.clone(),
                        "base_url": base_url.get_clone(),
                        "strategy": strategy.get_clone(),
                        "max_concurrent": max_concurrent.get_clone().trim().parse::<u32>().ok(),
                        "drain_below_pct": drain_pct.get_clone().trim().parse::<u32>().ok(),
                        "proxy": proxy.get_clone(),
                        "timeout_secs": timeout_secs.get_clone().trim().parse::<u64>().ok(),
                        "max_retries": max_retries.get_clone().trim().parse::<usize>().ok(),
                    });
                    spawn_local(async move {
                        if post_json("/api/providers/update", &body).await {
                            if saved.is_alive() {
                                saved.set(true);
                                error.set(String::new());
                            }
                        } else if error.is_alive() {
                            error.set("could not save the provider settings".into());
                        }
                    });
                }) { "Save settings" }
                (if saved.get_clone() {
                    view! { span(class="dim-text") { "saved" } }
                } else {
                    view! {}
                })
            }
        }
    }
}

/// Delete a provider after an explicit confirmation.
#[component(inline_props)]
pub fn DeleteProviderButton(provider: String) -> View {
    let confirm = create_signal(false);
    let name = provider.clone();
    view! {
        button(class="btn btn-danger", on:click=move |_| confirm.set(true)) { "Delete provider" }
        (if confirm.get_clone() {
            let del = name.clone();
            let show = name.clone();
            view! {
                div(class="modal-overlay", on:click=move |_| confirm.set(false)) {
                    div(class="modal", on:click=move |e: web_sys::MouseEvent| e.stop_propagation()) {
                        div(class="modal-head") { "Delete this provider?" }
                        div(class="modal-body") {
                            div(class="dim-text mb-12") {
                                "The provider and its keys are removed from the config file."
                                " Combos that reference it are deleted as well."
                            }
                            div(class="mono text-13") { (show) }
                        }
                        div(class="modal-actions") {
                            button(class="btn", on:click=move |_| confirm.set(false)) { "Cancel" }
                            button(class="btn btn-danger", on:click=move |_| {
                                let name = del.clone();
                                confirm.set(false);
                                spawn_local(async move {
                                    let body = serde_json::json!({"name": name});
                                    if post_json("/api/providers/delete", &body).await
                                        && let Some(w) = web_sys::window()
                                    {
                                        let _ = w.location().set_hash("providers");
                                        let _ = w.location().reload();
                                    }
                                });
                            }) { "Delete provider" }
                        }
                    }
                }
            }
        } else {
            view! {}
        })
    }
}

/// Delete one credential (POST /api/keys/delete), behind a confirmation.
#[component(inline_props)]
pub fn KeyDeleteButton(provider: String, id: String, masked: String) -> View {
    let confirm = create_signal(false);
    view! {
        button(class="btn-ghost btn-ghost-danger", on:click=move |_| confirm.set(true)) { "delete" }
        (if confirm.get_clone() {
            let prov = provider.clone();
            let kid = id.clone();
            let label = masked.clone();
            view! {
                div(class="modal-overlay", on:click=move |_| confirm.set(false)) {
                    div(class="modal", on:click=move |e: web_sys::MouseEvent| e.stop_propagation()) {
                        div(class="modal-head") { "Delete this key?" }
                        div(class="modal-body") {
                            div(class="dim-text mb-12") {
                                "It is removed from the config file and the live pool."
                                " The last key of a provider cannot be deleted — delete the provider instead."
                            }
                            div(class="mono text-13") { (label) }
                        }
                        div(class="modal-actions") {
                            button(class="btn", on:click=move |_| confirm.set(false)) { "Cancel" }
                            button(class="btn btn-danger", on:click=move |_| {
                                let body = serde_json::json!({"provider": prov.clone(), "id": kid.clone()});
                                confirm.set(false);
                                spawn_local(async move {
                                    if post_json("/api/keys/delete", &body).await
                                        && let Some(w) = web_sys::window()
                                    {
                                        let _ = w.location().reload();
                                    }
                                });
                            }) { "Delete key" }
                        }
                    }
                }
            }
        } else {
            view! {}
        })
    }
}

impl ProviderDto {
    /// See [`crate::types::ProviderShape`]: identity + settings, no counters.
    pub fn shape(&self) -> ProviderShape {
        (
            self.name.clone(),
            self.kind.clone(),
            self.base_url.clone(),
            self.strategy.clone(),
            self.keys
                .iter()
                .map(|k| (k.id.clone(), k.masked.clone(), k.status.clone()))
                .collect(),
            self.models.clone(),
            self.max_concurrent,
            self.drain_below_pct,
            self.capabilities.clone(),
        )
    }
}

#[component(inline_props)]
pub fn AddKeyForm(provider: String) -> View {
    let new_key = create_signal(String::new());
    let error = create_signal(String::new());
    view! {
        div(class="addkey") {
            // A provider key is a credential: masked input, like the add-provider form.
            input(class="input", r#type="password", placeholder="add a key…",
                  bind:value=new_key, autocomplete="off")
            button(class="btn btn-primary", on:click=move |_| {
                let secret = new_key.get_clone();
                if secret.len() < 4 {
                    if error.is_alive() {
                        error.set("a key needs at least 4 characters".to_string());
                    }
                    return;
                }
                let provider = provider.clone();
                spawn_local(async move {
                    let body = serde_json::json!({"provider": provider, "secret": secret});
                    // Keep the typed secret in the field on failure: it is the only
                    // copy the operator has.
                    match post_json_result::<_, serde_json::Value>("/api/keys/add", &body).await {
                        Ok(_) => {
                            new_key.set(String::new());
                            if error.is_alive() {
                                error.set(String::new());
                            }
                            if let Some(w) = web_sys::window() {
                                let _ = w.location().reload();
                            }
                        }
                        Err(e) => {
                            if error.is_alive() {
                                error.set(format!("could not add the key: {e}"));
                            }
                        }
                    }
                });
            }) { "Add" }
            (if !error.get_clone().is_empty() {
                view! { div(class="auth-banner auth-error flush", role="alert") { (error.get_clone()) } }
            } else {
                view! {}
            })
        }
    }
}

#[component(inline_props)]
pub fn OAuthAddButton(kind: String, provider: String) -> View {
    let auth = create_signal(Option::<AuthStateDto>::None);
    let paste_url = create_signal(String::new());
    let action_error = create_signal(String::new());
    let provider_name = provider.clone();
    let label = format!("Add {kind} account");
    view! {
        div(class="addkey") {
            button(class="btn btn-primary", on:click=move |_| {
                let kind = kind.clone();
                let kind_for_kind = kind.clone();
                let provider_name_for_auth = provider_name.clone();
                let kind_in_defer = kind.clone();
                let kind_for_poll = kind.clone();
                spawn_local(async move {
                    let body = serde_json::json!({
                        "kind": kind_for_kind,
                        // append to this provider, not to the first one of that type
                        "provider": provider_name_for_auth.clone(),
                    });
                    let v = match post_json_result::<_, serde_json::Value>("/api/auth/start", &body).await {
                        Ok(v) => v,
                        Err(e) => {
                            if action_error.is_alive() {
                                action_error.set(format!("cannot start sign-in: {e}"));
                            }
                            return;
                        }
                    };
                    let Some(url) = v.get("url").and_then(|u| u.as_str()).map(str::to_string) else {
                        if action_error.is_alive() {
                            action_error.set("cannot start sign-in: the server returned no URL".into());
                        }
                        return;
                    };
                    let url2 = url.clone();
                    defer(move || {
                        if auth.is_alive() {
                            auth.set(Some(AuthStateDto {
                                kind: kind_in_defer,
                                provider: String::new(),
                                status: "waiting".into(),
                                url: url2,
                                mode: String::new(),
                                message: "waiting for browser callback".into(),
                            }));
                        }
                    });
                    if let Some(w) = web_sys::window() {
                        let _ = w.open_with_url_and_target(&url, "_blank");
                    }
                    // Poll until the flow finishes; bail out if the component
                    // was unmounted (writing a disposed signal panics) or the
                    // status endpoint keeps failing (e.g. 401).
                    let mut failures = 0;
                    loop {
                        gloo_timers::future::sleep(std::time::Duration::from_secs(2)).await;
                        if !auth.is_alive() {
                            break;
                        }
                        match fetch_json::<AuthStateDto>("/api/auth/status").await {
                            Some(s) if s.kind != kind_for_poll && s.status == "waiting" => {
                                // Someone else's flow is pending; do not adopt it.
                                failures += 1;
                                if failures >= 10 {
                                    break;
                                }
                            }
                            Some(s) => {
                                failures = 0;
                                let terminal = s.status != "waiting";
                                auth.set(Some(s));
                                if terminal { break; }
                            }
                            None => {
                                failures += 1;
                                if failures >= 5 {
                                    break;
                                }
                            }
                        }
                    }
                });
            }) { (label) }
        }
        (match auth.get_clone() {
            Some(a) => {
                let cls = format!("auth-banner auth-{}", a.status);
                let waiting = a.status == "waiting";
                let msg = if waiting {
                    "Authorization opened in a new tab — complete the sign-in".to_string()
                } else {
                    a.message
                };
                let auth_for_cancel = auth;
                view! {
                    div(class="row gap-10 mt-8 wrap") {
                        div(class=cls) { (msg) }
                        (if waiting {
                            view! {
                                input(
                                    class="input input-w320", r#type="text",
                                    placeholder="or paste the redirected URL here",
                                    bind:value=paste_url,
                                )
                                button(class="btn btn-sm", on:click=move |_| {
                                    let v = paste_url.get_clone();
                                    if v.trim().is_empty() { return; }
                                    spawn_local(async move {
                                        let _ = post_json("/api/auth/complete", &serde_json::json!({"url": v})).await;
                                        if paste_url.is_alive() { paste_url.set(String::new()); }
                                    });
                                }) { "Complete" }
                            }
                        } else {
                            view! {}
                        })
                        (if waiting {
                            view! {
                                button(class="btn btn-sm", on:click=move |_| {
                                    spawn_local(async move {
                                        // Free the callback port instead of leaving the
                                        // flow pending for five minutes.
                                        let _ = post_json("/api/auth/cancel", &serde_json::json!({})).await;
                                        if auth_for_cancel.is_alive() {
                                            auth_for_cancel.set(None);
                                        }
                                    });
                                }) { "Cancel sign-in" }
                            }
                        } else {
                            view! {}
                        })
                    }
                }
            }
            None => view! {},
        })
        (if !action_error.get_clone().is_empty() {
            view! { div(class="auth-banner auth-error flush", role="alert") { (action_error.get_clone()) } }
        } else {
            view! {}
        })
    }
}

#[component(inline_props)]
pub fn KeyActionButton(provider: String, id: String, status: String) -> View {
    let dead = status == "dead";
    let label = if dead { "enable" } else { "disable" };
    let class = if dead { "btn" } else { "btn btn-danger" };
    let url = if dead {
        "/api/keys/enable"
    } else {
        "/api/keys/disable"
    };
    let error = create_signal(String::new());
    view! {
        button(class=class, on:click=move |_| {
            let body = serde_json::json!({"provider": provider.clone(), "id": id.clone()});
            spawn_local(async move {
                // A failed enable/disable used to be indistinguishable from a click
                // that worked (the result was dropped).
                if let Err(e) = post_json_result::<_, serde_json::Value>(url, &body).await {
                    if error.is_alive() {
                        error.set(format!("{label} failed: {e}"));
                    }
                } else if let Some(w) = web_sys::window() {
                    let _ = w.location().reload();
                }
            });
        }) { (label) }
        (if !error.get_clone().is_empty() {
            view! { div(class="auth-banner auth-error flush", role="alert") { (error.get_clone()) } }
        } else {
            view! {}
        })
    }
}
