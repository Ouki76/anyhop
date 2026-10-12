mod antigravity;
mod config;
mod dashboard;
mod events;
mod gemini;
mod pool;
mod storage;
mod providers;
mod proxy;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "auth" && args[2] == "antigravity" {
        let proxy = args
            .windows(2)
            .find(|w| w[0] == "--proxy")
            .map(|w| w[1].clone());
        return antigravity::run_auth_flow(proxy).await;
    }
    if args.len() >= 2 && (args[1] == "--help" || args[1] == "-h") {
        println!("anyhop — OpenAI-compatible LLM gateway with key rotation\n");
        println!("USAGE:");
        println!("  anyhop                                          start the gateway");
        println!("  anyhop auth antigravity [--proxy socks5://…]    add an Antigravity account via Google OAuth");
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

    let (events_tx, _) = tokio::sync::broadcast::channel::<events::DashEvent>(256);

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

    let state = Arc::new(proxy::AppState {
        router: providers::ProviderRouter { providers },
        max_retries: cfg.server.max_retries,
        attempt_timeout: Duration::from_secs(cfg.server.attempt_timeout_secs),
        events: events_tx,
    });

    let app = axum::Router::new()
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/models", get(proxy::list_models))
        .route("/healthz", get(|| async { "ok" }))
        .route("/", get(|| async { axum::response::Redirect::to("/dashboard") }))
        .route("/dashboard", get(dashboard::index))
        .route("/dashboard/partials/keys", get(dashboard::keys_partial))
        .route("/dashboard/events", get(dashboard::events_sse))
        .route("/dashboard/static/htmx.min.js", get(dashboard::htmx_js))
        .route("/dashboard/static/sse.js", get(dashboard::htmx_sse_js))
        .with_state(state.clone());

    // Periodic stats persistence.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            for p in &state.router.providers {
                p.pool.persist_stats();
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    info!("anyhop listening on http://{}", cfg.server.listen);
    axum::serve(listener, app).await?;
    Ok(())
}
