mod anthropic;
mod antigravity;
mod api;
mod codex;
mod config;
#[cfg(feature = "dashboard")]
mod dashboard;
mod events;
mod fim;
mod gemini;
mod pool;
mod scan;
mod sse;
mod storage;
mod providers;
mod proxy;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use tracing::info;
use tracing_subscriber::EnvFilter;

fn bearer_ok(req: &Request, expected: &str) -> bool {
    let header_ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t == expected)
        .unwrap_or(false);
    // EventSource не умеет заголовки — для GET допускаем ?key=
    let query_ok = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("key="))
                .map(str::to_string)
        })
        .map(|k| k == expected)
        .unwrap_or(false);
    header_ok || query_ok
}

/// Gateway auth: /v1/* requires Bearer <api_key> when configured.
async fn require_api_key(
    State(state): State<Arc<proxy::AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(expected) = state.rt().api_key
        && !bearer_ok(&req, &expected)
    {
        return proxy::error_response(
            StatusCode::UNAUTHORIZED,
            "invalid or missing gateway API key",
            "authentication_error",
        );
    }
    next.run(req).await
}

/// Admin auth: /api/* and /dashboard require Bearer <admin_key> (or api_key) when set.
async fn require_admin_key(
    State(state): State<Arc<proxy::AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let rt = state.rt();
    if let Some(expected) = rt.admin_key.or(rt.api_key)
        && !bearer_ok(&req, &expected)
    {
        return proxy::error_response(
            StatusCode::UNAUTHORIZED,
            "invalid or missing admin key",
            "authentication_error",
        );
    }
    next.run(req).await
}

#[cfg(not(feature = "alloc-mimalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "alloc-mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// jemalloc: фоновый поток возвращает неиспользуемые страницы ОС (5с decay).
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
static malloc_conf: &[u8] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

fn main() -> anyhow::Result<()> {
    let workers = std::env::var("ANYHOP_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            // По умолчанию: не больше 4 и не больше ядер машины.
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
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "auth" && (args[2] == "antigravity" || args[2] == "codex") {
        let proxy = args
            .windows(2)
            .find(|w| w[0] == "--proxy")
            .map(|w| w[1].clone());
        return if args[2] == "antigravity" {
            antigravity::run_auth_flow(proxy).await
        } else {
            codex::run_auth_flow(proxy).await
        };
    }
    if args.len() >= 2 && (args[1] == "--help" || args[1] == "-h") {
        println!("anyhop — OpenAI-compatible LLM gateway with key rotation\n");
        println!("USAGE:");
        println!("  anyhop                                          start the gateway");
        println!("  anyhop auth antigravity [--proxy socks5://…]    add an Antigravity account via Google OAuth");
        println!("  anyhop auth codex       [--proxy socks5://…]    add a ChatGPT/Codex account via OpenAI OAuth");
        println!("\nENV:");
        println!("  ANYHOP_CONFIG   path to config (default: anyhop.toml)");
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
            tracing::warn!("config {config_path} is readable by others — секреты! chmod 600 рекомендую");
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

    let events_tx = events::EventBus::new(cfg.server.events_history);
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
        request_log: std::sync::Mutex::new(std::collections::VecDeque::new()),
    });
    if let Some(s) = &state.storage
        && let Some(reqs) = s.load_feed::<Vec<events::RequestRecord>>("requests")
    {
        let n = reqs.len();
        *state.request_log.lock().unwrap() = reqs.into();
        info!("restored {n} request records from state");
    }

    let api = axum::Router::new()
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/fim/completions", post(fim::fim_completions))
        .route("/v1/completions", post(fim::fim_completions))
        .route("/v1/models", get(proxy::list_models))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
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
        .route("/api/providers/add", post(api::provider_add))
        .route("/api/config", get(api::get_config).put(api::put_config))
        .route("/api/reload", post(api::reload))
        .route("/api/auth/start", post(api::auth_start))
        .route("/api/auth/status", get(api::auth_status))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_key,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(cfg.server.max_body_bytes));

    let app = axum::Router::new()
        .merge(api)
        .merge(admin_base)
        .route("/healthz", get(|| async { "ok" }));

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

    let app = app.with_state(state.clone());

    // Hot-reload on SIGHUP.
    #[cfg(unix)]
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("SIGHUP handler");
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
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let router = state.router.load();
            for p in &router.providers {
                p.pool.persist_stats();
            }
            if let Some(s) = &state.storage {
                s.save_feed("events", &state.events.recent());
                let log = state.request_log.lock().unwrap();
                let v: Vec<_> = log.iter().cloned().collect();
                drop(log);
                s.save_feed("requests", &v);
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    info!("anyhop listening on http://{}", cfg.server.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            info!("shutting down gracefully");
        })
        .await?;
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
    *state.cfg.write().unwrap() = proxy::RtConfig {
        max_retries: cfg.server.max_retries,
        attempt_timeout: Duration::from_secs(cfg.server.attempt_timeout_secs),
        api_key: cfg.server.api_key.clone(),
        admin_key: cfg.server.admin_key.clone().or(cfg.server.api_key.clone()),
        events_history: cfg.server.events_history,
        requests_history: cfg.server.requests_history,
    };
    state.events.set_cap(cfg.server.events_history);
    Ok(n)
}
