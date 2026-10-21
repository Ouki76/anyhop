//! anyhop — OpenAI-compatible LLM gateway with key rotation.
//!
//! Exposed as a library so the pure hot-path helpers (byte scanner, SSE parser,
//! CSP builder, header classification) can be benchmarked and covered by
//! `cargo bench` / integration tests. The binary in `src/main.rs` only sets the
//! global allocator and calls [`run`].

pub mod anthropic;
pub mod antigravity;
pub mod api;
pub mod middleware;
pub mod codex;
pub mod config;
#[cfg(feature = "dashboard")]
pub mod dashboard;
pub mod events;
pub mod fim;
pub mod gemini;
pub mod pool;
pub mod scan;
pub mod sse;
pub mod storage;
pub mod providers;
pub mod proxy;
pub mod ratelimit;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::serve::ListenerExt;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub fn run() -> anyhow::Result<()> {
    let workers = std::env::var("ANYHOP_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            // Default: no more than 4 and no more than the machine's core count.
            std::thread::available_parallelism()
                .map(|n| n.get().min(4))
                .unwrap_or(2)
        });
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    if handle_cli().await? {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::var("ANYHOP_CONFIG").unwrap_or_else(|_| "anyhop.toml".into());
    let cfg = config::Config::load(&config_path)?;
    info!("loaded config from {config_path}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&config_path)
            && meta.permissions().mode() & 0o077 != 0
        {
            tracing::warn!("config {config_path} is readable by others — secrets! chmod 600 recommended");
        }
    }

    let storage = if cfg.server.state_file.is_empty() {
        None
    } else {
        match storage::Storage::open(&cfg.server.state_file) {
            Ok(s) => {
                info!("state storage: {}", cfg.server.state_file);
                Some(s)
            }
            Err(e) => {
                tracing::warn!("cannot open state file '{}': {e} (running without persistence)", cfg.server.state_file);
                None
            }
        }
    };

    let tuning = std::sync::Arc::new(cfg.tuning.clone());
    // OAuth access tokens (and rotated refresh tokens) are cached in the state
    // file; without it every restart falls back to the tokens in the config,
    // which may already be revoked after a rotation.
    if cfg.server.state_file.is_empty() {
        let oauth = cfg.providers.iter().any(|p| {
            matches!(
                p.kind,
                config::ProviderKind::Antigravity | config::ProviderKind::Codex
            )
        });
        if oauth {
            tracing::warn!(
                "state_file is empty: refreshed OAuth tokens will not survive a restart                  (rotated refresh tokens may then be lost) — set [server] state_file"
            );
        }
    }

    let events_tx = events::EventBus::with_capacity(
        cfg.server.events_history,
        cfg.tuning.event_channel_capacity,
    );
    if let Some(s) = &storage
        && let Some(ev) = s.load_feed::<Vec<events::DashEvent>>("events")
    {
        events_tx.restore(ev);
        info!("restored {} events from state", events_tx.recent().len());
    }

    let mut providers = Vec::new();
    for p in &cfg.providers {
        let provider = providers::Provider::from_config(
            p,
            storage.as_ref(),
            Some(&events_tx),
            cfg.server.proxy.as_deref(),
            tuning.clone(),
            Duration::from_secs(cfg.server.attempt_timeout_secs),
            cfg.server.max_retries,
        )?;
        info!(
            "provider '{}' ({} keys, strategy {:?})",
            provider.name,
            provider.pool.len(),
            p.strategy
        );
        providers.push(provider);
    }

    for c in &cfg.combos {
        info!("combo '{}' ({} targets)", c.name, c.chain.len());
    }
    if cfg.server.api_key.is_some() {
        info!("gateway API key auth enabled for /v1/*");
    }

    // Merge keys added at runtime via the dashboard.
    if let Some(s) = &storage {
        for p in &providers {
            if matches!(p.kind, config::ProviderKind::Antigravity) {
                continue;
            }
            for secret in s.list_extra_keys(&p.name) {
                if !p.pool.contains(&secret) {
                    info!("provider '{}': loaded extra key from state", p.name);
                    p.pool.add_key(secret);
                }
            }
        }
    }

    // TOML is the single source of truth for client keys / disabled models
    // (every API mutation writes it synchronously). Merging the storage feed
    // here would resurrect entries the admin deleted from the file by hand;
    // reload_config already does full replacement — startup now matches.
    let mut client_keys_map = std::collections::HashMap::new();
    for k in cfg.client_keys.clone() {
        client_keys_map.insert(k.key.clone(), Arc::new(proxy::ClientKeyRuntime::new(k)));
    }

    let mut disabled_models_set = std::collections::HashSet::new();
    for m in cfg.disabled_models.clone() {
        disabled_models_set.insert(m);
    }

    let state = Arc::new(proxy::AppState {
        router: arc_swap::ArcSwap::from_pointee(providers::ProviderRouter {
            providers,
            combos: cfg.combos.clone(),
        }),
        cfg: std::sync::RwLock::new(proxy::RtConfig {
            max_retries: cfg.server.max_retries,
            attempt_timeout: Duration::from_secs(cfg.server.attempt_timeout_secs),
            api_key: cfg.server.api_key.clone(),
            admin_key: cfg.server.admin_key.clone().or(cfg.server.api_key.clone()),
            events_history: cfg.server.events_history,
            requests_history: cfg.server.requests_history,
        }),
        storage: storage.clone(),
        config_path: config_path.clone(),
        events: events_tx,
        auth_state: std::sync::Mutex::new(None),
        auth_task: std::sync::Mutex::new(None),
        auth_code_tx: std::sync::Mutex::new(None),
        auth_state_token: std::sync::Mutex::new(None),
        request_log: std::sync::Mutex::new(std::collections::VecDeque::new()),
        client_keys: std::sync::RwLock::new(client_keys_map),
        disabled_models: std::sync::RwLock::new(disabled_models_set),
        config_lock: tokio::sync::Mutex::new(()),
        tuning: tuning.clone(),
    });
    if let Some(s) = &state.storage
        && let Some(reqs) = s.load_feed::<Vec<events::RequestRecord>>("requests")
    {
        let n = reqs.len();
        *state.request_log.lock().unwrap_or_else(|e| e.into_inner()) = reqs.into();
        info!("restored {n} request records from state");
    }

    let app = build_router(state.clone(), &cfg);

    spawn_background_tasks(state.clone(), &cfg);

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    // TCP_NODELAY on accepted sockets. Without it Nagle + delayed ACK adds ~40 ms
    // to a fraction of keep-alive requests — measured with test/soak.py: p95 went
    // from 42 ms to ~1 ms. axum::serve does not set it for us.
    let listener = listener.tap_io(|stream| {
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!("cannot set TCP_NODELAY: {e}");
        }
    });
    info!("anyhop listening on http://{}", cfg.server.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                // Missing SIGTERM support must not block Ctrl+C shutdown:
                // fall back to a never-resolving future for the term branch.
                let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .ok();
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = async {
                        match term.as_mut() {
                            Some(t) => { t.recv().await; }
                            None => std::future::pending::<()>().await,
                        }
                    } => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            info!("shutting down gracefully");
        })
        .await?;

    // Final state flush — the periodic persist task dies with the runtime.
    persist_feeds(&state);
    if let Some(s) = &state.storage {
        s.flush_async().await;
    }
    Ok(())
}

/// Rebuild providers/router from the config file (state restored from storage).
pub fn reload_config(state: &Arc<proxy::AppState>) -> anyhow::Result<usize> {
    let cfg = config::Config::load(&state.config_path)?;
    let mut providers = Vec::new();
    for p in &cfg.providers {
        providers.push(providers::Provider::from_config(
            p,
            state.storage.as_ref(),
            Some(&state.events),
            cfg.server.proxy.as_deref(),
            state.tuning.clone(),
            Duration::from_secs(cfg.server.attempt_timeout_secs),
            cfg.server.max_retries,
        )?);
    }
    if let Some(s) = &state.storage {
        for p in &providers {
            if matches!(p.kind, config::ProviderKind::Antigravity) {
                continue;
            }
            for secret in s.list_extra_keys(&p.name) {
                if !p.pool.contains(&secret) {
                    p.pool.add_key(secret);
                }
            }
        }
    }
    let n = providers.len();
    state.router.store(Arc::new(providers::ProviderRouter {
        providers,
        combos: cfg.combos.clone(),
    }));
    *state.cfg.write().unwrap_or_else(|e| e.into_inner()) = proxy::RtConfig {
        max_retries: cfg.server.max_retries,
        attempt_timeout: Duration::from_secs(cfg.server.attempt_timeout_secs),
        api_key: cfg.server.api_key.clone(),
        admin_key: cfg.server.admin_key.clone().or(cfg.server.api_key.clone()),
        events_history: cfg.server.events_history,
        requests_history: cfg.server.requests_history,
    };
    state.events.set_cap(cfg.server.events_history);
    // Full replacement, not a merge: keys/models removed from the config must disappear.
    {
        let mut ck = state.client_keys.write().unwrap_or_else(|e| e.into_inner());
        // Rebuild from the file, but keep the live rate-limiter buckets of keys
        // whose limits did not change (a reload must not hand out fresh quota).
        let prev: std::collections::HashMap<_, _> =
            ck.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        ck.clear();
        for k in &cfg.client_keys {
            let runtime = match prev.get(&k.key) {
                Some(old) => Arc::new(old.rebind(k.clone())),
                None => Arc::new(proxy::ClientKeyRuntime::new(k.clone())),
            };
            ck.insert(k.key.clone(), runtime);
        }
    }
    {
        let mut dm = state.disabled_models.write().unwrap_or_else(|e| e.into_inner());
        dm.clear();
        for m in &cfg.disabled_models {
            dm.insert(m.clone());
        }
    }
    Ok(n)
}

/// Handle `--help` and `anyhop auth …`. Returns `true` when the command was
/// handled (the caller then exits without starting the gateway).
///
/// `anyhop auth` / `anyhop auth bogus` used to fall through and start the server
/// instead of reporting a usage error — a typo must not silently launch a gateway.
async fn handle_cli() -> anyhow::Result<bool> {
    let args: Vec<String> = std::env::args().collect();
    let Some(cmd) = args.get(1) else {
        return Ok(false); // no arguments: start the gateway
    };

    match cmd.as_str() {
        "--help" | "-h" => {
            println!("anyhop — OpenAI-compatible LLM gateway with key rotation\n");
            println!("USAGE:");
            println!("  anyhop                                          start the gateway");
            println!("  anyhop auth antigravity [--proxy socks5://…]    add an Antigravity account via Google OAuth");
            println!("  anyhop auth codex       [--proxy socks5://…]    add a ChatGPT/Codex account via OpenAI OAuth");
            println!("  anyhop --help                                   this text");
            println!("\nENV:");
            println!("  ANYHOP_CONFIG   path to config (default: anyhop.toml)");
            println!("  ANYHOP_WORKERS  tokio worker threads (default: min(4, cores))");
            println!("  RUST_LOG        log filter (default: info)");
            Ok(true)
        }
        "auth" => {
            let kind = args.get(2).map(String::as_str).unwrap_or("");
            if kind != "antigravity" && kind != "codex" {
                anyhow::bail!("usage: anyhop auth antigravity|codex [--proxy URL]");
            }
            // `anyhop auth X --proxy` with no URL used to be dropped silently by
            // the old windows(2) scan and the flow ran direct. Parse explicitly:
            // every extra argument is either `--proxy <url>` or an error.
            let mut proxy: Option<String> = None;
            let mut it = args.iter().skip(3);
            while let Some(w) = it.next() {
                match w.as_str() {
                    "--proxy" => match it.next() {
                        Some(url) if !url.trim().is_empty() => proxy = Some(url.clone()),
                        _ => anyhow::bail!(
                            "--proxy needs a URL: anyhop auth {kind} --proxy socks5://host:port"
                        ),
                    },
                    other => anyhow::bail!("unknown argument '{other}' (try anyhop --help)"),
                }
            }
            if kind == "antigravity" {
                antigravity::run_auth_flow(proxy).await?;
            } else {
                codex::run_auth_flow(proxy).await?;
            }
            Ok(true)
        }
        other => anyhow::bail!("unknown argument '{other}' (try anyhop --help)"),
    }
}

/// Assemble the HTTP surface: `/v1/*` (gateway auth), `/api/*` + `/metrics`
/// (admin auth), `/healthz`, and the optional dashboard — with the hardening
/// header layer applied last so it also covers auth rejections.
fn build_router(state: Arc<proxy::AppState>, cfg: &config::Config) -> axum::Router {
    let api = axum::Router::new()
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/fim/completions", post(fim::fim_completions))
        .route("/v1/completions", post(fim::fim_completions))
        .route("/v1/models", get(proxy::list_models))
        .route("/v1/embeddings", post(proxy::embeddings))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_api_key,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(cfg.server.max_body_bytes));

    let admin_base = axum::Router::new()
        .route("/api/providers", get(api::providers))
        .route("/api/requests", get(api::requests))
        .route("/api/quotas", get(api::quotas))
        .route("/api/events", get(api::events))
        .route("/api/keys/enable", post(api::key_enable))
        .route("/api/keys/disable", post(api::key_disable))
        .route("/api/keys/add", post(api::key_add))
        .route("/api/keys/delete", post(api::key_delete))
        .route("/api/providers/add", post(api::provider_add))
        .route("/api/providers/update", post(api::provider_update))
        .route("/api/providers/delete", post(api::provider_delete))
        .route("/api/combos", get(api::combos))
        .route("/api/combos/add", post(api::combo_add))
        .route("/api/combos/update", post(api::combo_update))
        .route("/api/combos/delete", post(api::combo_delete))
        .route("/api/client-keys", get(api::client_keys_list).post(api::client_key_add))
        .route("/api/client-keys/add", post(api::client_key_add))
        .route("/api/client-keys/delete", post(api::client_key_delete))
        .route("/api/client-keys/update", post(api::client_key_update))
        .route("/api/models", get(api::models_list))
        .route("/api/models/refresh", post(api::models_refresh))
        .route("/api/models/enable", post(api::model_enable))
        .route("/api/models/disable", post(api::model_disable))
        .route("/api/models/toggle", post(api::model_toggle))
        .route("/api/models/enable-all", post(api::models_enable_all))
        .route("/api/models/disable-all", post(api::models_disable_all))
        .route("/api/config", get(api::get_config).put(api::put_config))
        .route("/api/reload", post(api::reload))
        .route("/api/server", get(api::get_server))
        .route("/api/server/update", post(api::update_server))
        .route("/api/auth/start", post(api::auth_start))
        .route("/api/auth/status", get(api::auth_status))
        .route("/api/auth/cancel", post(api::auth_cancel))
        .route("/api/auth/complete", post(api::auth_complete))
        // Prometheus exposition: under the admin layer like the rest — a scraper
        // authenticates with `bearer_token` (or `?key=`, allowed for GET).
        .route("/metrics", get(api::metrics))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_admin_key,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(cfg.server.max_body_bytes));

    // Applied last so it also normalises the bodies produced by the auth layers.
    let app = axum::Router::new()
        .merge(api)
        .merge(admin_base)
        // Provider redirect target for OAuth when [server] public_url is set.
        // No admin key here: the browser carries the OAuth state instead.
        .route("/api/auth/callback", get(api::auth_callback))
        .route("/healthz", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(middleware::json_errors));

    #[cfg(feature = "dashboard")]
    let app = if cfg.server.dashboard {
        info!("dashboard: /dashboard (Sycamore UI)");
        app.route("/", get(|| async { axum::response::Redirect::to("/dashboard") }))
            .route("/dashboard", get(dashboard::index))
            .route("/dashboard/", get(dashboard::index))
            .route("/dashboard/{*path}", get(dashboard::asset))
    } else {
        info!("dashboard disabled by config");
        app
    };

    let app = app
        .with_state(state.clone())
        // Outermost layer: hardening headers on every response, including 401s
        // and errors produced by the auth middlewares inside.
        .layer(axum::middleware::from_fn(middleware::security_headers));

    app
    }

/// Long-running maintenance tasks: SIGHUP hot reload, periodic stats/feed
/// persistence and periodic model-list refresh.
fn spawn_background_tasks(state: Arc<proxy::AppState>, cfg: &config::Config) {
    // Hot-reload on SIGHUP.
    #[cfg(unix)]
    {
        let st = state.clone();
        tokio::spawn(async move {
            // Registration can fail on exotic kernels/containers; treat it as
            // "hot reload unavailable" rather than panicking the reload task.
            let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("SIGHUP handler unavailable, hot reload disabled: {e}");
                    return;
                }
            };
            loop {
                sig.recv().await;
                match reload_config(&st) {
                    Ok(n) => info!("SIGHUP: config reloaded ({n} providers)"),
                    Err(e) => tracing::warn!("SIGHUP: reload failed, keeping current config: {e}"),
                }
            }
        });
    }

    // Periodic stats persistence.
    let st_stats = state.clone();
    let persist_every = state.tuning.persist_interval();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(persist_every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            persist_feeds(&st_stats);
        }
    });

    // Periodic models refresh from all providers (immediate warm-up + interval).
    let refresh_interval = cfg.server.models_refresh_secs;
    if refresh_interval > 0 {
        let st_models = state.clone();
        tokio::spawn(async move {
            api::refresh_all_providers(&st_models).await;
            let mut interval = tokio::time::interval(Duration::from_secs(refresh_interval));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                api::refresh_all_providers(&st_models).await;
            }
        });
    }
}

/// Persist stats + event/request feeds. Called by the periodic task and once
/// more at shutdown (the task is dropped with the runtime).
/// history = 0 means "in-memory only" for that feed — skip persisting it.
fn persist_feeds(state: &Arc<proxy::AppState>) {
    let router = state.router.load();
    for p in &router.providers {
        p.pool.persist_stats();
    }
    let Some(s) = &state.storage else { return };
    let rt = state.rt();
    if rt.events_history > 0 {
        s.save_feed("events", &state.events.recent());
    }
    if rt.requests_history > 0 {
        let v: Vec<_> = state
            .request_log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect();
        s.save_feed("requests", &v);
    }
}

