mod antigravity;
mod config;
mod gemini;
mod pool;
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
        return antigravity::run_auth_flow().await;
    }
    if args.len() >= 2 && (args[1] == "--help" || args[1] == "-h") {
        println!("anyhop — OpenAI-compatible LLM gateway with key rotation\n");
        println!("USAGE:");
        println!("  anyhop                            start the gateway");
        println!("  anyhop auth antigravity           add an Antigravity account via Google OAuth");
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

    let mut providers = Vec::new();
    for p in &cfg.providers {
        let provider = providers::Provider::from_config(p)?;
        info!(
            "provider '{}' ({} keys, strategy {:?})",
            provider.name,
            provider.pool.len(),
            p.strategy
        );
        providers.push(provider);
    }

    let http = reqwest::Client::builder()
        .user_agent(concat!("anyhop/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(32)
        .build()?;

    let state = Arc::new(proxy::AppState {
        router: providers::ProviderRouter { providers },
        http,
        max_retries: cfg.server.max_retries,
        attempt_timeout: Duration::from_secs(cfg.server.attempt_timeout_secs),
    });

    let app = axum::Router::new()
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/models", get(proxy::list_models))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    info!("anyhop listening on http://{}", cfg.server.listen);
    axum::serve(listener, app).await?;
    Ok(())
}
