//! `[server]` settings form.
//!
//! Everything the config file can express for the gateway itself, without making
//! the admin edit raw TOML. Fields that are baked in at startup (listener, body
//! limit, dashboard routes, state file) are written but flagged: the API reports
//! them back in `restart_required`, and the UI says so instead of pretending the
//! change took effect.

use sycamore::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::types::*;
use crate::util::*;

#[component]
pub fn SettingsTab() -> View {
    let loaded = create_signal(false);
    let listen = create_signal(String::new());
    let max_retries = create_signal(String::new());
    let timeout = create_signal(String::new());
    let max_body = create_signal(String::new());
    let events_history = create_signal(String::new());
    let requests_history = create_signal(String::new());
    let refresh_secs = create_signal(String::new());
    let proxy = create_signal(String::new());
    let state_file = create_signal(String::new());
    let public_url = create_signal(String::new());
    let tls_cert = create_signal(String::new());
    let tls_key = create_signal(String::new());
    let log_format = create_signal("text".to_string());
    let ck_max_concurrent = create_signal(String::new());
    let auth_fail_burst = create_signal(String::new());
    let auth_fail_window = create_signal(String::new());
    let dashboard = create_signal(true);
    let api_key = create_signal(String::new());
    let admin_key = create_signal(String::new());
    let t_max_cooldown = create_signal(String::new());
    let t_base_backoff = create_signal(String::new());
    let t_rl_cooldown = create_signal(String::new());
    let t_drain_fallback = create_signal(String::new());
    let t_models_ttl = create_signal(String::new());
    let t_connect_timeout = create_signal(String::new());
    let t_meta_timeout = create_signal(String::new());
    let t_sticky_ttl = create_signal(String::new());
    let t_sticky_max = create_signal(String::new());
    let t_session_prefix = create_signal(String::new());
    let t_event_cap = create_signal(String::new());
    let t_persist = create_signal(String::new());
    let t_oauth_timeout = create_signal(String::new());
    let t_token_window = create_signal(String::new());
    let t_ui_refresh = create_signal(String::new());
    let t_sse_keepalive = create_signal(String::new());
    let t_quota_ttl = create_signal(String::new());
    let t_resp_store = create_signal(String::new());
    let api_key_set = create_signal(false);
    let admin_key_set = create_signal(false);
    let status = create_signal(String::new());
    let restart = create_signal(Vec::<String>::new());

    spawn_local(async move {
        if let Some(s) = fetch_json::<ServerDto>("/api/server").await
            && loaded.is_alive()
        {
            listen.set(s.listen);
            max_retries.set(s.max_retries.to_string());
            timeout.set(s.attempt_timeout_secs.to_string());
            max_body.set(s.max_body_bytes.to_string());
            events_history.set(s.events_history.to_string());
            requests_history.set(s.requests_history.to_string());
            refresh_secs.set(s.models_refresh_secs.to_string());
            proxy.set(s.proxy.unwrap_or_default());
            state_file.set(s.state_file);
            public_url.set(s.public_url.unwrap_or_default());
            tls_cert.set(s.tls_cert.unwrap_or_default());
            tls_key.set(s.tls_key.unwrap_or_default());
            log_format.set(s.log_format);
            ck_max_concurrent.set(s.client_key_max_concurrent.to_string());
            auth_fail_burst.set(s.auth_fail_burst.to_string());
            auth_fail_window.set(s.auth_fail_window_secs.to_string());
            dashboard.set(s.dashboard);
            let t = s.tuning;
            t_max_cooldown.set(t.max_cooldown_secs.to_string());
            t_base_backoff.set(t.base_backoff_secs.to_string());
            t_rl_cooldown.set(t.rate_limit_cooldown_secs.to_string());
            t_drain_fallback.set(t.drain_fallback_secs.to_string());
            t_models_ttl.set(t.models_cache_ttl_secs.to_string());
            t_connect_timeout.set(t.connect_timeout_secs.to_string());
            t_meta_timeout.set(t.meta_timeout_secs.to_string());
            t_sticky_ttl.set(t.sticky_ttl_secs.to_string());
            t_sticky_max.set(t.sticky_max_entries.to_string());
            t_session_prefix.set(t.session_prefix_bytes.to_string());
            t_event_cap.set(t.event_channel_capacity.to_string());
            t_persist.set(t.persist_interval_secs.to_string());
            t_oauth_timeout.set(t.oauth_http_timeout_secs.to_string());
            t_token_window.set(t.token_refresh_window_secs.to_string());
            t_ui_refresh.set(t.ui_refresh_secs.to_string());
            t_sse_keepalive.set(t.sse_keepalive_secs.to_string());
            t_quota_ttl.set(t.quota_cache_ttl_secs.to_string());
            t_resp_store.set(t.response_store_max.to_string());
            api_key_set.set(s.api_key_set);
            admin_key_set.set(s.admin_key_set);
            loaded.set(true);
        }
    });

    let int_of = |s: &str| s.trim().parse::<u64>().unwrap_or(0);

    view! {
        div(class="page-head") {
            div {
                div(class="page-title") { "Settings" }
                div(class="page-sub") { "Gateway-wide options from the [server] section of anyhop.toml" }
            }
        }

        div(class="card") {
            div(class="card-head") { b { "Gateway" } }
            (if !loaded.get_clone() {
                view! { div(class="empty") { "Loading…" } }
            } else {
                view! {
                    div(class="settings-grid") {
                        div(class="form-group") {
                            label(class="form-label") { "Listen address" }
                            input(class="input", r#type="text", bind:value=listen)
                            div(class="form-hint") { "host:port — applies after a restart" }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Max upstream attempts" }
                            input(class="input", r#type="number", min="1", max="32", bind:value=max_retries)
                            div(class="form-hint") { "Per request, each attempt uses a different key" }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Attempt timeout, s" }
                            input(class="input", r#type="number", min="1", max="3600", bind:value=timeout)
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Max request body, bytes" }
                            input(class="input", r#type="number", min="1024", bind:value=max_body)
                            div(class="form-hint") { "Applies after a restart" }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Events history" }
                            input(class="input", r#type="number", min="0", bind:value=events_history)
                            div(class="form-hint") { "0 = in-memory only, not persisted" }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Requests history" }
                            input(class="input", r#type="number", min="0", bind:value=requests_history)
                            div(class="form-hint") { "0 = in-memory only, not persisted" }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Model list refresh, s" }
                            input(class="input", r#type="number", min="0", bind:value=refresh_secs)
                            div(class="form-hint") { "0 = never refresh" }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "State file" }
                            input(class="input", r#type="text", placeholder="empty = no persistence", bind:value=state_file)
                            div(class="form-hint") { "Applies after a restart" }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Public URL" }
                            input(class="input", r#type="text", placeholder="https://gateway.example.com", bind:value=public_url)
                            div(class="form-hint") {
                                "Used for OAuth redirects when the panel is not opened on this machine. Empty = localhost callback only."
                            }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "TLS certificate (PEM)" }
                            input(class="input", r#type="text", placeholder="/etc/anyhop/cert.pem", bind:value=tls_cert)
                            div(class="form-hint") { "Serves HTTPS directly. Empty = plain HTTP (terminate TLS at a proxy). Restart required." }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "TLS private key (PEM)" }
                            input(class="input", r#type="password", placeholder="/etc/anyhop/key.pem", bind:value=tls_key)
                            div(class="form-hint") { "Must match the certificate. Restart required." }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Log format" }
                            select(class="select", bind:value=log_format) {
                                option(value="text") { "text" }
                                option(value="json") { "json" }
                            }
                            div(class="form-hint") { "json for log shippers. Restart required." }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Client key concurrency" }
                            input(class="input", r#type="number", min="0", bind:value=ck_max_concurrent)
                            div(class="form-hint") { "Default in-flight cap per client key (0 = unlimited)." }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Auth failures before lockout" }
                            input(class="input", r#type="number", min="1", bind:value=auth_fail_burst)
                            div(class="form-hint") { "Per IP, on /v1 and /api." }
                        }
                        div(class="form-group") {
                            label(class="form-label") { "Lockout window, s" }
                            input(class="input", r#type="number", min="1", bind:value=auth_fail_window)
                        }
                        div(class="form-group span-2") {
                            label(class="form-label") { "Upstream proxy for all providers" }
                            input(class="input", r#type="text", placeholder="empty = direct connection", bind:value=proxy)
                            div(class="form-hint") { "Credentials are masked; leave the *** value untouched to keep them." }
                        }
                    }
                    div(class="settings-grid") {
                        div(class="form-group span-2") {
                            label(class="switch") {
                                input(
                                    r#type="checkbox",
                                    checked=dashboard.get_clone(),
                                    on:change=move |_| dashboard.set(!dashboard.get_clone()),
                                )
                                span(class="switch-track") { span(class="switch-thumb") {} }
                                span(class="switch-text") {
                                    "Serve the dashboard at /dashboard"
                                    span(class="dim") { " — needs a restart" }
                                }
                            }
                        }
                    }
                }
            })
            div(class="card-foot") {
                button(class="btn btn-primary", on:click=move |_| {
                    let mut body = serde_json::json!({
                        "listen": listen.get_clone(),
                        "max_retries": int_of(&max_retries.get_clone()) as usize,
                        "attempt_timeout_secs": int_of(&timeout.get_clone()),
                        "max_body_bytes": int_of(&max_body.get_clone()) as usize,
                        "events_history": int_of(&events_history.get_clone()) as usize,
                        "requests_history": int_of(&requests_history.get_clone()) as usize,
                        "models_refresh_secs": int_of(&refresh_secs.get_clone()),
                        "dashboard": dashboard.get_clone(),
                        "proxy": proxy.get_clone(),
                        "state_file": state_file.get_clone(),
                        "public_url": public_url.get_clone(),
                        "tls_cert": tls_cert.get_clone(),
                        "tls_key": tls_key.get_clone(),
                        "log_format": log_format.get_clone(),
                        "client_key_max_concurrent": int_of(&ck_max_concurrent.get_clone()) as usize,
                        "auth_fail_burst": int_of(&auth_fail_burst.get_clone()) as usize,
                        "auth_fail_window_secs": int_of(&auth_fail_window.get_clone()),
                        "tuning": {
                            "max_cooldown_secs": int_of(&t_max_cooldown.get_clone()),
                            "base_backoff_secs": int_of(&t_base_backoff.get_clone()),
                            "rate_limit_cooldown_secs": int_of(&t_rl_cooldown.get_clone()),
                            "drain_fallback_secs": int_of(&t_drain_fallback.get_clone()),
                            "models_cache_ttl_secs": int_of(&t_models_ttl.get_clone()),
                            "connect_timeout_secs": int_of(&t_connect_timeout.get_clone()),
                            "meta_timeout_secs": int_of(&t_meta_timeout.get_clone()),
                            "sticky_ttl_secs": int_of(&t_sticky_ttl.get_clone()),
                            "sticky_max_entries": int_of(&t_sticky_max.get_clone()) as usize,
                            "session_prefix_bytes": int_of(&t_session_prefix.get_clone()) as usize,
                            "event_channel_capacity": int_of(&t_event_cap.get_clone()) as usize,
                            "persist_interval_secs": int_of(&t_persist.get_clone()),
                            "oauth_http_timeout_secs": int_of(&t_oauth_timeout.get_clone()),
                            "token_refresh_window_secs": int_of(&t_token_window.get_clone()),
                            "ui_refresh_secs": int_of(&t_ui_refresh.get_clone()),
                            "sse_keepalive_secs": int_of(&t_sse_keepalive.get_clone()),
                            "quota_cache_ttl_secs": int_of(&t_quota_ttl.get_clone()),
                            "response_store_max": int_of(&t_resp_store.get_clone()) as usize,
                        },
                    });
                    // Secrets: only send what the admin actually typed.
                    let k = api_key.get_clone();
                    if !k.trim().is_empty() {
                        body["api_key"] = serde_json::Value::String(k.trim().to_string());
                    }
                    let a = admin_key.get_clone();
                    if !a.trim().is_empty() {
                        body["admin_key"] = serde_json::Value::String(a.trim().to_string());
                    }
                    spawn_local(async move {
                        match post_json_resp::<_, serde_json::Value>("/api/server/update", &body).await {
                            Some(v) => {
                                let rs: Vec<String> = v
                                    .get("restart_required")
                                    .and_then(|r| r.as_array())
                                    .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                                    .unwrap_or_default();
                                if status.is_alive() {
                                    restart.set(rs.clone());
                                    status.set(if rs.is_empty() {
                                        "saved".to_string()
                                    } else {
                                        "saved — restart required".to_string()
                                    });
                                    api_key.set(String::new());
                                    admin_key.set(String::new());
                                }
                            }
                            None => {
                                if status.is_alive() {
                                    status.set("could not save (check the values and the server log)".into());
                                }
                            }
                        }
                    });
                }) { "Save settings" }
                button(class="btn", on:click=move |_| {
                    spawn_local(async move {
                        if let Some(s) = fetch_json::<ServerDto>("/api/server").await {
                            listen.set(s.listen);
                            max_retries.set(s.max_retries.to_string());
                            timeout.set(s.attempt_timeout_secs.to_string());
                            max_body.set(s.max_body_bytes.to_string());
                            events_history.set(s.events_history.to_string());
                            requests_history.set(s.requests_history.to_string());
                            refresh_secs.set(s.models_refresh_secs.to_string());
                            proxy.set(s.proxy.unwrap_or_default());
                            state_file.set(s.state_file);
                            public_url.set(s.public_url.clone().unwrap_or_default());
                            tls_cert.set(s.tls_cert.clone().unwrap_or_default());
                            tls_key.set(s.tls_key.clone().unwrap_or_default());
                            log_format.set(s.log_format.clone());
                            ck_max_concurrent.set(s.client_key_max_concurrent.to_string());
                            auth_fail_burst.set(s.auth_fail_burst.to_string());
                            auth_fail_window.set(s.auth_fail_window_secs.to_string());
                            dashboard.set(s.dashboard);
                            let t = s.tuning;
                            t_max_cooldown.set(t.max_cooldown_secs.to_string());
                            t_base_backoff.set(t.base_backoff_secs.to_string());
                            t_rl_cooldown.set(t.rate_limit_cooldown_secs.to_string());
                            t_drain_fallback.set(t.drain_fallback_secs.to_string());
                            t_models_ttl.set(t.models_cache_ttl_secs.to_string());
                            t_connect_timeout.set(t.connect_timeout_secs.to_string());
                            t_meta_timeout.set(t.meta_timeout_secs.to_string());
                            t_sticky_ttl.set(t.sticky_ttl_secs.to_string());
                            t_sticky_max.set(t.sticky_max_entries.to_string());
                            t_session_prefix.set(t.session_prefix_bytes.to_string());
                            t_event_cap.set(t.event_channel_capacity.to_string());
                            t_persist.set(t.persist_interval_secs.to_string());
                            t_oauth_timeout.set(t.oauth_http_timeout_secs.to_string());
                            t_token_window.set(t.token_refresh_window_secs.to_string());
                            t_ui_refresh.set(t.ui_refresh_secs.to_string());
                            t_sse_keepalive.set(t.sse_keepalive_secs.to_string());
                            t_quota_ttl.set(t.quota_cache_ttl_secs.to_string());
                            t_resp_store.set(t.response_store_max.to_string());
            t_resp_store.set(t.response_store_max.to_string());
                            api_key.set(String::new());
                            admin_key.set(String::new());
                            if status.is_alive() {
                                status.set("reloaded from disk".into());
                                restart.set(Vec::new());
                            }
                        }
                    });
                }) { "Reload from disk" }
                (if status.get_clone().is_empty() {
                    view! {}
                } else {
                    view! { span(class="dim-text") { (status.get_clone()) } }
                })
            }
            (if restart.get_clone().is_empty() {
                view! {}
            } else {
                view! {
                    div(class="auth-banner auth-waiting flush") {
                        "Restart required for: " (restart.get_clone().join(", "))
                    }
                }
            })
        }

        div(class="card mt-20") {
            div(class="card-head") {
                b { "Tuning" }
                span(class="dim-text") { "cooldowns, timeouts, cache and buffer sizes" }
            }
            div(class="settings-grid") {
                div(class="form-group") {
                    label(class="form-label") { "Max cooldown, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_max_cooldown)
                    div(class="form-hint") { "Hard cap on how long a failing key stays benched." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Backoff base, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_base_backoff)
                    div(class="form-hint") { "Doubles per consecutive failure, capped above." }
                }
                div(class="form-group") {
                    label(class="form-label") { "429 cooldown, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_rl_cooldown)
                    div(class="form-hint") { "Used when the upstream sends no Retry-After." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Drain fallback, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_drain_fallback)
                    div(class="form-hint") { "Cooldown when the reset window is unparseable." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Model cache TTL, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_models_ttl)
                    div(class="form-hint") { "How long a fetched model list stays fresh." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Connect timeout, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_connect_timeout)
                }
                div(class="form-group") {
                    label(class="form-label") { "Meta timeout, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_meta_timeout)
                    div(class="form-hint") { "Model listing and quota probes." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Sticky TTL, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_sticky_ttl)
                    div(class="form-hint") { "Keeps a conversation on one key for caching." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Sticky entries" }
                    input(class="input", r#type="number", min="16", bind:value=t_sticky_max)
                    div(class="form-hint") { "Map size before eviction." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Session prefix, bytes" }
                    input(class="input", r#type="number", min="256", bind:value=t_session_prefix)
                    div(class="form-hint") { "Body bytes hashed into the session id." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Event buffer" }
                    input(class="input", r#type="number", min="1", bind:value=t_event_cap)
                    div(class="form-hint") { "SSE broadcast capacity." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Persist interval, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_persist)
                }
                div(class="form-group") {
                    label(class="form-label") { "OAuth timeout, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_oauth_timeout)
                }
                div(class="form-group") {
                    label(class="form-label") { "Token refresh window, s" }
                    input(class="input", r#type="number", min="0", bind:value=t_token_window)
                    div(class="form-hint") { "Refresh OAuth tokens this early. 0 = on expiry." }
                }
                div(class="form-group") {
                    label(class="form-label") { "UI refresh, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_ui_refresh)
                    div(class="form-hint") { "Dashboard live-view poll interval." }
                }
                div(class="form-group") {
                    label(class="form-label") { "SSE keep-alive, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_sse_keepalive)
                    div(class="form-hint") { "Ping interval so proxies keep the stream open." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Quota cache, s" }
                    input(class="input", r#type="number", min="1", bind:value=t_quota_ttl)
                    div(class="form-hint") { "How long a per-account quota snapshot is reused." }
                }
                div(class="form-group") {
                    label(class="form-label") { "Response store" }
                    input(class="input", r#type="number", min="0", bind:value=t_resp_store)
                    div(class="form-hint") { "Replies kept for previous_response_id (0 = off)." }
                }
            }
            div(class="card-foot") {
                span(class="dim-text") { "Applies on the next config reload; keys already benched keep their timer." }
            }
        }

        div(class="card mt-20") {
            div(class="card-head") { b { "Access" } }
            div(class="settings-grid") {
                div(class="form-group") {
                    label(class="form-label") {
                        "Gateway API key "
                        (if api_key_set.get_clone() {
                            view! { span(class="badge accent") { "set" } }
                        } else {
                            view! { span(class="badge") { "none — /v1 is open" } }
                        })
                    }
                    input(
                        class="input", r#type="password",
                        placeholder="leave empty to keep the current key",
                        bind:value=api_key,
                    )
                    div(class="form-hint") { "Required by /v1/* when set." }
                }
                div(class="form-group") {
                    label(class="form-label") {
                        "Admin key "
                        (if admin_key_set.get_clone() {
                            view! { span(class="badge accent") { "set" } }
                        } else {
                            view! { span(class="badge") { "inherits API key" } }
                        })
                    }
                    input(
                        class="input", r#type="password",
                        placeholder="leave empty to keep the current key",
                        bind:value=admin_key,
                    )
                    div(class="form-hint") { "Guards /api/* and /dashboard. Falls back to the gateway key." }
                }
            }
            div(class="card-foot") {
                span(class="dim-text") {
                    "Secrets are never sent to the browser — only whether they are set."
                }
            }
        }
    }
}
