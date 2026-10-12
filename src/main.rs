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

/// Gateway auth: /v1/* requires Bearer <api_key> when configured.
async fn require_api_key(
    State(state): State<Arc<proxy::AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(expected) = state.rt().api_key {
        let ok = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t == expected)
            .unwrap_or(false);
        if !ok {
            return proxy::error_response(
                StatusCode::UNAUTHORIZED,
                "invalid or missing gateway API key",
                "authentication_error",
            );
        }
    }
    next.run(req).await
}

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let events_tx = events::EventBus::new();

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
        }),
        storage: storage.clone(),
        config_path: config_path.clone(),
        events: events_tx,
    });

    let api = axum::Router::new()
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/fim/completions", post(fim::fim_completions))
        .route("/v1/completions", post(fim::fim_completions))
        .route("/v1/models", get(proxy::list_models))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    let app = axum::Router::new()
        .merge(api)
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/providers", get(api::providers))
        .route("/api/quotas", get(api::quotas))
        .route("/api/events", get(api::events))
        .route("/api/keys/enable", post(api::key_enable))
        .route("/api/keys/disable", post(api::key_disable))
        .route("/api/keys/add", post(api::key_add));

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
        }
    });

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    info!("anyhop listening on http://{}", cfg.server.listen);
    axum::serve(listener, app).await?;
    Ok(())
}

/// Rebuild providers/router from the config file (state restored from storage).
fn reload_config(state: &Arc<proxy::AppState>) -> anyhow::Result<usize> {
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
    };
    Ok(n)
}
