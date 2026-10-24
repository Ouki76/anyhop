//! anyhop — OpenAI-compatible LLM gateway with key rotation.
//!
//! Exposed as a library so the pure hot-path helpers (byte scanner, SSE parser,
//! CSP builder, header classification) can be benchmarked and covered by
//! `cargo bench` / integration tests. The binary in `src/main.rs` only sets the
//! global allocator and calls [`run`].

// Production code must not panic on bad input; tests may unwrap freely.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod anthropic;
pub mod antigravity;
pub mod api;
pub mod codex;
pub mod config;
#[cfg(feature = "dashboard")]
pub mod dashboard;
pub mod distributed;
pub mod events;
pub mod fim;
pub mod gemini;
pub mod logging;
pub mod middleware;
pub mod pool;
pub mod providers;
pub mod proxy;
pub mod ratelimit;
pub mod scan;
pub mod sse;
pub mod storage;
pub mod tls;
pub mod ws;

use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::serve::ListenerExt;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Normalise a `disabled_models` entry so every spelling of a combo means the same
/// thing: the catalogue stores combos **bare** (`testcombo`), while the request
/// path also accepts `combo/testcombo`, so a hand-written `disabled_models =
/// ["combo/x"]` used to be honoured by one path and ignored by `/v1/models`.
fn disabled_entry(raw: &str) -> String {
    raw.strip_prefix("combo/").unwrap_or(raw).to_string()
}

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

    // The log format comes from the config, which means peeking at it before the
    // subscriber exists. A broken config falls back to text: the real error is
    // reported right after by Config::load.
    let config_path = std::env::var("ANYHOP_CONFIG").unwrap_or_else(|_| "anyhop.toml".into());
    let json_logs = std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|raw| toml::from_str::<config::Config>(&raw).ok())
        .is_some_and(|c| c.server.log_format == "json");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if json_logs {
        tracing_subscriber::fmt()
            .event_format(logging::JsonFormat)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }

    let cfg = config::Config::load(&config_path)?;

    info!("loaded config from {config_path}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&config_path)
            && meta.permissions().mode() & 0o077 != 0
        {
            tracing::warn!(
                "config {config_path} is readable by others — secrets! chmod 600 recommended"
            );
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
                tracing::warn!(
                    "cannot open state file '{}': {e} (running without persistence)",
                    cfg.server.state_file
                );
                None
            }
        }
    };

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
                "state_file is empty: refreshed OAuth tokens will not survive a restart (rotated refresh tokens may then be lost) — set [server] state_file"
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

    let providers = build_providers(&cfg, storage.as_ref(), Some(&events_tx))?;
    for p in &providers {
        info!(
            "provider '{}' ({} keys, strategy {:?})",
            p.name,
            p.pool.len(),
            p.strategy
        );
    }

    for c in &cfg.combos {
        info!("combo '{}' ({} targets)", c.name, c.chain.len());
    }
    match (&cfg.server.api_key, &cfg.server.admin_key) {
        (None, None) => tracing::warn!(
            "no api_key/admin_key configured: /v1/* and /api/* (raw config editor, provider keys, \
             OAuth) accept unauthenticated requests — set one unless this port is loopback-only"
        ),
        _ => info!("gateway API key auth enabled for /v1/*"),
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
        let runtime = proxy::ClientKeyRuntime::new_with(k.clone(), &cfg.ratelimit);
        client_keys_map.insert(k.key.clone(), Arc::new(runtime));
    }

    let mut disabled_models_set = std::collections::HashSet::new();
    for m in cfg.disabled_models.clone() {
        // Store both spellings: `combo/x` in the file must hide the bare `x` in
        // the catalogue and in the request path alike.
        disabled_models_set.insert(disabled_entry(&m));
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
            auth_fail_burst: cfg.server.auth_fail_burst,
            auth_fail_window: Duration::from_secs(cfg.server.auth_fail_window_secs),
            client_key_max_concurrent: cfg.server.client_key_max_concurrent,
            tls_enabled: cfg.server.tls_cert.is_some(),
            ratelimit: cfg.ratelimit.clone(),
        }),
        storage: storage.clone(),
        config_path: config_path.clone(),
        events: events_tx,
        auth_state: std::sync::Mutex::new(None),
        auth_task: std::sync::Mutex::new(None),
        auth_code_tx: std::sync::Mutex::new(None),
        auth_start_lock: tokio::sync::Mutex::new(()),
        auth_fails: std::sync::Mutex::new(crate::middleware::AuthFailures::default()),
        tls_enabled_flag: std::sync::atomic::AtomicBool::new(cfg.server.tls_cert.is_some()),
        catalog_epoch: std::sync::atomic::AtomicU64::new(1),
        models_cache: std::sync::Mutex::new(None),
        request_log: std::sync::Mutex::new(std::collections::VecDeque::new()),
        client_keys: std::sync::RwLock::new(client_keys_map),
        disabled_models: std::sync::RwLock::new(disabled_models_set),
        config_lock: tokio::sync::Mutex::new(()),
        tuning: arc_swap::ArcSwap::from_pointee(cfg.tuning.clone()),
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

    let raw_listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    let make = || app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    // Fires when the graceful shutdown starts, so the drain can be bounded.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    // TCP_NODELAY on accepted sockets. Without it Nagle + delayed ACK adds ~40 ms
    // to a fraction of keep-alive requests — measured with test/soak.py: p95 went
    // from 42 ms to ~1 ms. axum::serve does not set it for us.
    //
    // The tap has to sit *outside* the TLS wrapper: axum implements
    // `Connected<IncomingStream<TapIo<L, F>>>` for `L::Addr`, which is what makes
    // `ConnectInfo<SocketAddr>` available (the brute-force guard needs the peer IP).
    match (&cfg.server.tls_cert, &cfg.server.tls_key) {
        (Some(cert), Some(key)) => {
            let tls = tls::TlsConfig::from_pem_files(cert, key)
                .map_err(|e| anyhow::anyhow!("cannot start TLS: {e}"))?;
            info!("anyhop listening on https://{} (TLS)", cfg.server.listen);
            let listener = tls::TlsListener::new(raw_listener, tls).tap_io(|stream| {
                if let Err(e) = stream.get_ref().0.set_nodelay(true) {
                    tracing::debug!("cannot set TCP_NODELAY: {e}");
                }
            });
            let server =
                axum::serve(listener, make()).with_graceful_shutdown(drain_signal(stop_rx.clone()));
            serve_until_stopped(
                server,
                stop_tx,
                shutdown_signal(),
                cfg.tuning.shutdown_grace(),
            )
            .await?;
        }
        _ => {
            info!("anyhop listening on http://{}", cfg.server.listen);
            let listener = raw_listener.tap_io(|stream| {
                if let Err(e) = stream.set_nodelay(true) {
                    tracing::debug!("cannot set TCP_NODELAY: {e}");
                }
            });
            let server =
                axum::serve(listener, make()).with_graceful_shutdown(drain_signal(stop_rx.clone()));
            serve_until_stopped(
                server,
                stop_tx,
                shutdown_signal(),
                cfg.tuning.shutdown_grace(),
            )
            .await?;
        }
    }

    // Final state flush — the periodic persist task dies with the runtime.
    persist_feeds(&state);
    if let Some(s) = &state.storage {
        s.flush_async().await;
    }
    Ok(())
}

/// Everything the runtime needs from a config that was built successfully.
///
/// Preparing is separate from installing so a bad edit can fail *before* the
/// file is touched: the old code wrote first and reloaded second, which left a
/// config on disk that the next start (or the next reload) refused.
struct PreparedConfig {
    router: providers::ProviderRouter,
    cfg: config::Config,
}

/// Why a config edit could not be applied.
#[derive(Debug)]
pub enum ConfigApplyError {
    /// The providers could not be built (an edit that `validate` let through, an
    /// invalid proxy URL, …). Nothing was written and nothing was swapped.
    Build(anyhow::Error),
    /// The config file could not be written. The running process is unchanged.
    Write(std::io::Error),
}

impl std::fmt::Display for ConfigApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigApplyError::Build(e) => write!(f, "{e}"),
            ConfigApplyError::Write(e) => write!(f, "cannot write config: {e}"),
        }
    }
}

impl std::error::Error for ConfigApplyError {}

/// Build every provider of a config. `Provider::from_config` is where a config
/// can be rejected even though `Config::validate` accepted it (a proxy URL that
/// `reqwest` cannot parse, for instance) — callers must treat an error here as
/// "do not write the file".
fn build_providers(
    cfg: &config::Config,
    storage: Option<&storage::Storage>,
    events: Option<&events::EventBus>,
) -> anyhow::Result<Vec<providers::Provider>> {
    let tuning = Arc::new(cfg.tuning.clone());
    let mut out = Vec::with_capacity(cfg.providers.len());
    for p in &cfg.providers {
        out.push(providers::Provider::from_config(
            p,
            storage,
            events,
            cfg.server.proxy.as_deref(),
            tuning.clone(),
            Duration::from_secs(cfg.server.attempt_timeout_secs),
            cfg.server.max_retries,
        )?);
    }
    Ok(out)
}

/// Rebuild providers/router from the config file (state restored from storage).
pub fn reload_config(state: &Arc<proxy::AppState>) -> anyhow::Result<usize> {
    let cfg = config::Config::load(&state.config_path)?;
    let prepared = prepare_config(state, cfg)?;
    Ok(install_config(state, prepared))
}

/// [`reload_config`] behind the config lock, for callers that run off the async
/// runtime's hot path (SIGHUP, `POST /api/reload`).
///
/// Without the lock, a reload that read the file while a dashboard writer was in
/// the middle of its read-modify-write installed the *older* document: the edit
/// stayed on disk but was reverted in memory (a new client key answered 401, a
/// disabled model came back, a deleted provider reappeared) until the next reload.
pub async fn reload_config_locked(state: &Arc<proxy::AppState>) -> anyhow::Result<usize> {
    let _guard = state.config_lock.lock().await;
    reload_config(state)
}

/// Validate-and-write a config document: build first, write second, swap last.
///
/// This ordering is the fix for "a saved config can brick the next start": any
/// error happens while the file and the live router are both still the old ones.
pub fn apply_config(
    state: &Arc<proxy::AppState>,
    cfg: config::Config,
    text: &str,
) -> Result<usize, ConfigApplyError> {
    // Everything fallible that can reject the edit happens here, before the write.
    let prepared = prepare_config(state, cfg).map_err(ConfigApplyError::Build)?;
    config::write_atomic(&state.config_path, text).map_err(ConfigApplyError::Write)?;
    // `install_config` only swaps already-built values in place (every lock
    // recovers from poisoning), so it cannot fail half way and leave the live
    // process on a router that does not match the file just written.
    Ok(install_config(state, prepared))
}

/// Build a provider set from `cfg` without touching the live state.
fn prepare_config(
    state: &Arc<proxy::AppState>,
    cfg: config::Config,
) -> anyhow::Result<PreparedConfig> {
    // The pools that are rebuilt below restore their health/stats from storage.
    // The writer batches for two seconds, so without this flush a key that just
    // returned 401 (still sitting in the batch) would come back `active`, and a
    // disabled key would be re-enabled by any dashboard save.
    if let Some(s) = &state.storage {
        for p in state.router.load().providers.iter() {
            // Push the live counters into the mirror so the rebuilt pool restores
            // them instead of the last periodic snapshot.
            p.pool.persist_stats();
        }
        s.flush_in_place();
    }

    let mut list = build_providers(&cfg, state.storage.as_ref(), Some(&state.events))?;
    {
        let live = state.router.load();
        for p in &mut list {
            // Reuse the live pool when the credentials, the strategy and the
            // limits are unchanged: a rebuilt one would drop every cooldown, the
            // per-model quotas and the consecutive-failure counters.
            if let Some(prev) = live.providers.iter().find(|o| o.name == p.name)
                && prev.pool.signature() == p.pool.signature()
            {
                p.pool = prev.pool.clone();
            }
            // NOTE: tuning is applied in `install_config`, *after* a successful
            // write. Setting it here (as this used to) mutated the live pools
            // before `write_atomic`, so a config save that failed on disk still
            // changed runtime behaviour — file and process disagreed and the 500
            // did not say so.
        }
    }
    // Merge keys added at runtime via the dashboard (never for OAuth providers:
    // their credentials are accounts, not standalone secrets).
    if let Some(s) = &state.storage {
        for p in &list {
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
    Ok(PreparedConfig {
        router: providers::ProviderRouter {
            providers: list,
            combos: cfg.combos.clone(),
        },
        cfg,
    })
}

/// Publish a prepared config: router, runtime settings, tuning, client keys and
/// model toggles. Infallible by construction.
fn install_config(state: &Arc<proxy::AppState>, prepared: PreparedConfig) -> usize {
    let cfg = prepared.cfg;
    let n = prepared.router.providers.len();
    // Providers, combos and model lists may all have changed.
    state.invalidate_catalog();
    // Tuning reaches the reused pools here — after `write_atomic`, so a rejected or
    // failed save leaves runtime behaviour untouched (see `prepare_config`).
    let tuning = Arc::new(cfg.tuning.clone());
    for p in &prepared.router.providers {
        p.pool.set_tuning(tuning.clone());
    }
    state.router.store(Arc::new(prepared.router));
    // `[tuning]` is reported as hot by /api/server/update, so it must actually
    // reach every reader — it used to stay at the value captured at startup.
    state.tuning.store(Arc::new(cfg.tuning.clone()));
    state.tls_enabled_flag.store(
        cfg.server.tls_cert.is_some(),
        std::sync::atomic::Ordering::Relaxed,
    );
    *state.cfg.write().unwrap_or_else(|e| e.into_inner()) = proxy::RtConfig {
        max_retries: cfg.server.max_retries,
        attempt_timeout: Duration::from_secs(cfg.server.attempt_timeout_secs),
        api_key: cfg.server.api_key.clone(),
        admin_key: cfg.server.admin_key.clone().or(cfg.server.api_key.clone()),
        events_history: cfg.server.events_history,
        requests_history: cfg.server.requests_history,
        auth_fail_burst: cfg.server.auth_fail_burst,
        auth_fail_window: Duration::from_secs(cfg.server.auth_fail_window_secs),
        client_key_max_concurrent: cfg.server.client_key_max_concurrent,
        tls_enabled: cfg.server.tls_cert.is_some(),
        ratelimit: cfg.ratelimit.clone(),
    };
    state.events.set_cap(cfg.server.events_history);
    if let Some(s) = &state.storage {
        s.set_response_max(cfg.tuning.response_store_max);
    }
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
                Some(old) => Arc::new(old.rebind(k.clone(), &cfg.ratelimit)),
                None => Arc::new(proxy::ClientKeyRuntime::new_with(k.clone(), &cfg.ratelimit)),
            };
            ck.insert(k.key.clone(), runtime);
        }
    }
    {
        let mut dm = state
            .disabled_models
            .write()
            .unwrap_or_else(|e| e.into_inner());
        dm.clear();
        for m in &cfg.disabled_models {
            dm.insert(disabled_entry(m));
            dm.insert(m.clone());
        }
    }
    n
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
            println!(
                "  anyhop auth antigravity [--proxy socks5://…]    add an Antigravity account via Google OAuth"
            );
            println!(
                "  anyhop auth codex       [--proxy socks5://…]    add a ChatGPT/Codex account via OpenAI OAuth"
            );
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
        .route("/v1/models/{*id}", get(proxy::get_model))
        .route("/v1/embeddings", post(proxy::embeddings))
        .route("/v1/responses", post(proxy::responses::responses))
        // Pass-through media: the provider must declare the capability.
        .route(
            "/v1/images/generations",
            post(proxy::media::images_generations),
        )
        .route("/v1/images/edits", post(proxy::media::images_edits))
        .route("/v1/audio/speech", post(proxy::media::audio_speech))
        .route(
            "/v1/audio/transcriptions",
            post(proxy::media::audio_transcriptions),
        )
        .route(
            "/v1/audio/translations",
            post(proxy::media::audio_translations),
        )
        // WebSocket upgrade; the handler hijacks the connection itself.
        .route("/v1/realtime", get(proxy::realtime::realtime))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::require_api_key,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(
            cfg.server.max_body_bytes,
        ));

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
        .route(
            "/api/client-keys",
            get(api::client_keys_list).post(api::client_key_add),
        )
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
        .layer(axum::extract::DefaultBodyLimit::max(
            cfg.server.max_body_bytes,
        ));

    // Applied last so it also normalises the bodies produced by the auth layers.
    let app = axum::Router::new()
        .merge(api)
        .merge(admin_base)
        // Provider redirect target for OAuth when [server] public_url is set.
        // No admin key here: the browser carries the OAuth state instead.
        .route("/api/auth/callback", get(api::auth_callback))
        .route("/healthz", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(middleware::json_errors))
        // A body that stops arriving must fail instead of holding the connection
        // (and its client-key concurrency slot) open forever.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            request_body_deadline,
        ))
        // Outermost: measures the whole request, including auth and error paths.
        .layer(axum::middleware::from_fn(middleware::record_metrics));

    #[cfg(feature = "dashboard")]
    let app = if cfg.server.dashboard {
        info!("dashboard: /dashboard (Sycamore UI)");
        app.route(
            "/",
            get(|| async { axum::response::Redirect::to("/dashboard") }),
        )
        .route("/dashboard", get(dashboard::index))
        .route("/dashboard/", get(dashboard::index))
        .route("/dashboard/{*path}", get(dashboard::asset))
    } else {
        info!("dashboard disabled by config");
        app
    };

    app.with_state(state.clone())
        // Outermost layer: hardening headers on every response, including 401s
        // and errors produced by the auth middlewares inside.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::security_headers,
        ))
}

/// How long in-flight work gets after a termination signal before the process
/// exits anyway.
///
/// The graceful path waits for every open connection, and an SSE/streaming
/// response stays open for as long as the client keeps it — before this bound,
/// SIGTERM never completed (measured: still running after 10 s, only exiting when
/// the client disconnected), so the final `persist_feeds` + flush never ran and an
/// orchestrator's SIGKILL lost the last state. The budget is
/// `[tuning] shutdown_grace_secs`.
///
/// The request-body deadline lives in `request_body_deadline` below:
/// `DefaultBodyLimit` bounds the *size*, not the time, and a client that declares
/// a Content-Length then sends a few bytes per second used to hold a connection —
/// and a client-key concurrency slot — open indefinitely (slowloris).
///
/// Resolves once the graceful drain has started.
async fn drain_signal(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|started| *started).await;
}

/// Serve until `signal` resolves, then drain for at most `grace`.
///
/// `stop` publishes the drain to the server future; after `grace` the server task
/// is aborted rather than awaited forever, so the caller always reaches its final
/// flush.
async fn serve_until_stopped<S, F>(
    server: S,
    stop: tokio::sync::watch::Sender<bool>,
    signal: F,
    grace: Duration,
) -> anyhow::Result<()>
where
    // `axum::serve` yields a type that is only `IntoFuture`, so it is awaited
    // inside the spawned task rather than passed to `spawn` directly.
    S: std::future::IntoFuture<Output = std::io::Result<()>> + Send + 'static,
    S::IntoFuture: Send,
    F: std::future::Future<Output = ()>,
{
    let mut handle = tokio::spawn(async move { server.await });
    // Wake on *either* a signal or the server giving up. Waiting only on the signal
    // meant a fatal accept error (EMFILE, a closed listener) left the process
    // running with nothing accepting and no error until someone sent a signal —
    // a gateway that looks healthy and serves nothing.
    tokio::select! {
        _ = signal => {}
        early = &mut handle => {
            let e = match early {
                Ok(Ok(())) => "axum::serve returned without an error".to_string(),
                Ok(Err(e)) => format!("{e}"),
                Err(join) => format!("server task panicked: {join}"),
            };
            // Tell the writer to stop too, then report: exiting is the honest
            // answer (a supervisor restarts us), silence is not.
            let _ = stop.send(true);
            return Err(anyhow::anyhow!("server stopped accepting: {e}"));
        }
    }
    let _ = stop.send(true);
    match tokio::time::timeout(grace, &mut handle).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err(anyhow::anyhow!("server error: {e}")),
        Ok(Err(join)) => Err(anyhow::anyhow!("server task failed: {join}")),
        Err(_elapsed) => {
            // Exit with connections still open: the state flush below matters more
            // than a stream that may never end.
            handle.abort();
            info!("shutdown grace period ({grace:?}) elapsed, abandoning in-flight connections");
            Ok(())
        }
    }
}

/// Wrap a request body so every chunk (not the whole upload) must arrive within
/// `idle`.
fn body_with_idle_timeout(body: axum::body::Body, idle: Duration) -> axum::body::Body {
    let timed = tokio_stream::StreamExt::timeout(body.into_data_stream(), idle);
    let stream = futures::StreamExt::map(timed, |item| match item {
        Ok(chunk) => chunk.map_err(std::io::Error::other),
        Err(_elapsed) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "request body read timed out",
        )),
    });
    axum::body::Body::from_stream(stream)
}

/// Per-chunk read deadline for request bodies: `[tuning] client_body_timeout_secs`
/// (default 30 s). Bounds slowloris — without it a client trickling 100 B/s holds
/// a connection, and a client-key slot, forever.
async fn request_body_deadline(
    axum::extract::State(state): axum::extract::State<Arc<proxy::AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let idle = state.tuning().client_body_timeout();
    let body = body_with_idle_timeout(body, idle);
    next.run(axum::extract::Request::from_parts(parts, body))
        .await
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
            let mut sig =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("SIGHUP handler unavailable, hot reload disabled: {e}");
                        return;
                    }
                };
            loop {
                sig.recv().await;
                match reload_config_locked(&st).await {
                    Ok(n) => info!("SIGHUP: config reloaded ({n} providers)"),
                    Err(e) => tracing::warn!("SIGHUP: reload failed, keeping current config: {e}"),
                }
            }
        });
    }

    // Periodic stats persistence.
    let st_stats = state.clone();
    let persist_every = state.tuning().persist_interval();
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

/// Resolves on Ctrl+C or SIGTERM (the process is expected to exit afterwards).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        // Missing SIGTERM support must not block Ctrl+C shutdown:
        // fall back to a never-resolving future for the term branch.
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    const BASE: &str = r#"
        [server]
        listen = "127.0.0.1:18080"

        [[providers]]
        name = "mock"
        type = "openai_compat"
        base_url = "http://127.0.0.1:9/v1"
        keys = ["good-key", "other-key"]
        models = ["test-model"]
    "#;

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anyhop-lib-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// A running state for one config file. `storage` is optional because only the
    /// health-persistence tests need it.
    fn test_state(
        tag: &str,
        text: &str,
        storage: Option<storage::Storage>,
    ) -> (Arc<proxy::AppState>, String) {
        let dir = scratch_dir(tag);
        let path = dir.join("anyhop.toml");
        std::fs::write(&path, text).expect("seed config");
        let path = path.to_str().expect("utf-8 path").to_string();
        let cfg: config::Config = toml::from_str(text).expect("fixture parses");
        cfg.validate().expect("fixture is valid");
        let providers = build_providers(&cfg, storage.as_ref(), None).expect("builds offline");
        let state = Arc::new(proxy::AppState {
            router: arc_swap::ArcSwap::from_pointee(providers::ProviderRouter {
                providers,
                combos: Vec::new(),
            }),
            cfg: std::sync::RwLock::new(proxy::RtConfig {
                max_retries: cfg.server.max_retries,
                attempt_timeout: Duration::from_secs(cfg.server.attempt_timeout_secs),
                api_key: None,
                admin_key: None,
                events_history: cfg.server.events_history,
                requests_history: cfg.server.requests_history,
                auth_fail_burst: cfg.server.auth_fail_burst,
                auth_fail_window: Duration::from_secs(cfg.server.auth_fail_window_secs),
                client_key_max_concurrent: 0,
                tls_enabled: false,
                ratelimit: cfg.ratelimit.clone(),
            }),
            storage,
            config_path: path.clone(),
            events: events::EventBus::new(8),
            auth_state: std::sync::Mutex::new(None),
            auth_task: std::sync::Mutex::new(None),
            auth_code_tx: std::sync::Mutex::new(None),
            auth_start_lock: tokio::sync::Mutex::new(()),
            auth_fails: std::sync::Mutex::new(crate::middleware::AuthFailures::default()),
            catalog_epoch: std::sync::atomic::AtomicU64::new(1),
            tls_enabled_flag: AtomicBool::new(false),
            models_cache: std::sync::Mutex::new(None),
            request_log: std::sync::Mutex::new(std::collections::VecDeque::new()),
            client_keys: std::sync::RwLock::new(std::collections::HashMap::new()),
            disabled_models: std::sync::RwLock::new(std::collections::HashSet::new()),
            config_lock: tokio::sync::Mutex::new(()),
            tuning: arc_swap::ArcSwap::from_pointee(cfg.tuning.clone()),
        });
        (state, path)
    }

    fn open_storage(tag: &str) -> (storage::Storage, std::path::PathBuf) {
        let dir = scratch_dir(&format!("{tag}-db"));
        let path = dir.join("state.redb");
        let store = storage::Storage::open(path.to_str().expect("utf-8")).expect("open state");
        (store, dir)
    }

    // ----- A: the write path must not leave a config the runtime refuses -----

    /// A config that `validate()` accepts can still fail to build (here: a proxy
    /// URL `reqwest` cannot parse). The old order — write, then reload — left that
    /// config on disk, so the *next* start exited with a hard error. The build now
    /// happens first, so a rejected edit leaves the file byte-identical.
    #[tokio::test]
    async fn a_config_that_fails_to_build_never_reaches_the_file() {
        let (state, path) = test_state("apply-order", BASE, None);
        let original = std::fs::read_to_string(&path).expect("read");

        // Valid TOML, passes validate(), fails in Provider::from_config.
        let broken = BASE.replace(
            "listen = \"127.0.0.1:18080\"",
            "listen = \"127.0.0.1:18080\"\n        proxy = \"http://[\"",
        );
        let parsed: config::Config = toml::from_str(&broken).expect("still parses");
        assert!(
            parsed.validate().is_ok(),
            "the fixture must pass validation to exercise the build step"
        );

        let err = apply_config(&state, parsed, &broken).expect_err("bad proxy must be rejected");
        assert!(
            matches!(err, ConfigApplyError::Build(_)),
            "expected a build failure, got {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            original,
            "a rejected edit rewrote the config file (the next start would fail)"
        );

        // The live router is unchanged as well: same provider, same pool.
        assert_eq!(state.router.load().providers.len(), 1);
    }

    // ----- C: `[tuning]` edits must actually be applied -----

    /// `/api/server/update` reports `tuning` as changed *without*
    /// `restart_required`, so a reload has to publish it. It used to keep the
    /// `Arc<Tuning>` created at startup, making the edit a silent no-op.
    #[tokio::test]
    async fn a_reload_publishes_the_new_tuning_to_the_live_process() {
        let (state, path) = test_state("tuning", BASE, None);
        assert_eq!(state.tuning().max_cooldown_secs, 3600);

        let edited =
            format!("{BASE}\n[tuning]\nmax_cooldown_secs = 7\nrate_limit_cooldown_secs = 2\n");
        std::fs::write(&path, &edited).expect("edit config");
        let n = reload_config(&state).expect("reload");
        assert_eq!(n, 1);

        assert_eq!(
            state.tuning().max_cooldown_secs,
            7,
            "the reload did not publish the new tuning (still the startup value)"
        );
        assert_eq!(state.tuning().rate_limit_cooldown_secs, 2);

        // The pool must follow: a 429 without Retry-After uses the configured 2 s.
        let pool = state.router.load().providers[0].pool.clone();
        let key = pool.pick("m", None).expect("a key");
        pool.report_failure(
            &key,
            crate::pool::FailKind::RateLimited {
                retry_after_secs: None,
            },
            "m",
        );
        assert!(
            pool.snapshot()[0].cooldown_remaining_secs <= 2,
            "the pool ignored the reloaded rate_limit_cooldown_secs"
        );
    }

    // ----- D: a reload must not resurrect dead keys or lose counters -----

    /// A key that just returned 401 is `dead`; the health record is still in the
    /// 2 s storage batch. Rebuilding the pool used to restore nothing, so any
    /// dashboard save brought the key back. Unchanged providers now keep their
    /// live pool, and rebuilt ones restore from a flushed store.
    #[tokio::test]
    async fn a_reload_keeps_a_dead_key_dead_and_reuses_the_live_pool() {
        let (store, dir) = open_storage("reload-health");
        let (state, path) = test_state("reload-health", BASE, Some(store));

        let pool = state.router.load().providers[0].pool.clone();
        let victim = pool.pick("m", None).expect("a key");
        let victim_id = pool.snapshot()[0].id.clone();
        assert_eq!(
            victim.masked(),
            pool.snapshot()[0].masked,
            "the fixture assumes the first pick is the first key"
        );
        pool.report_failure(&victim, crate::pool::FailKind::Auth, "m");
        victim
            .requests
            .store(41, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(pool.snapshot()[0].status, "dead");

        // An unrelated edit that does not touch this provider's credentials.
        let edited = BASE.replace(
            "listen = \"127.0.0.1:18080\"",
            "listen = \"127.0.0.1:18080\"\n        max_retries = 3",
        );
        std::fs::write(&path, &edited).expect("edit config");
        reload_config(&state).expect("reload");

        let after = state.router.load().providers[0].pool.clone();
        assert!(
            Arc::ptr_eq(&pool, &after),
            "an unchanged provider's pool must be reused, not rebuilt"
        );
        let snap = after.snapshot();
        let dead = snap.iter().find(|k| k.id == victim_id).expect("key");
        assert_eq!(dead.status, "dead", "the reload resurrected a dead key");
        assert_eq!(dead.requests, 41, "the reload lost the live counters");

        // A provider that *does* change is rebuilt — and must still see the dead
        // record (i.e. the store was flushed before the restore).
        let with_new_key = edited.replace(
            "keys = [\"good-key\", \"other-key\"]",
            "keys = [\"good-key\", \"other-key\", \"third-key\"]",
        );
        std::fs::write(&path, &with_new_key).expect("edit config");
        reload_config(&state).expect("reload");
        let rebuilt = state.router.load().providers[0].pool.clone();
        assert!(
            !Arc::ptr_eq(&pool, &rebuilt),
            "a changed key set must rebuild"
        );
        let dead = rebuilt
            .snapshot()
            .into_iter()
            .find(|k| k.id == victim_id)
            .expect("key");
        assert_eq!(
            dead.status, "dead",
            "a rebuilt pool lost the dead key because the batch was not flushed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Per-model cooldowns are persisted now: a rebuilt pool must not forget that
    /// one model is out of quota (that caused an immediate doomed retry).
    #[tokio::test]
    async fn a_rebuilt_pool_restores_per_model_cooldowns() {
        let (store, dir) = open_storage("reload-model-cd");
        let (state, path) = test_state("reload-model-cd", BASE, Some(store));

        let until_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
            + 60_000;
        let pool = state.router.load().providers[0].pool.clone();
        // Both keys report the quota, so the model is exhausted pool-wide.
        for _ in 0..2 {
            let key = pool.pick("m-1", None).expect("a key");
            pool.report_failure(&key, crate::pool::FailKind::ModelQuota { until_ms }, "m-1");
        }

        // Changing the strategy forces a rebuild while keeping the same two keys,
        // so the restored cooldowns must make the model unavailable pool-wide.
        let edited = BASE.replace(
            "models = [\"test-model\"]",
            "models = [\"test-model\"]\n        strategy = \"fill_first\"",
        );
        std::fs::write(&path, &edited).expect("edit config");
        reload_config(&state).expect("reload");

        let rebuilt = state.router.load().providers[0].pool.clone();
        assert!(
            !Arc::ptr_eq(&pool, &rebuilt),
            "a strategy change must rebuild"
        );
        assert!(
            rebuilt.pick("m-1", None).is_none(),
            "the model cooldown was lost by the rebuild"
        );
        assert!(
            rebuilt.pick("m-2", None).is_some(),
            "other models must still work"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- L: a deleted runtime key must not come back through the reload -----

    /// `key_delete` removes a runtime-added key from the file *and* from the state
    /// file's extras list, then reloads. The reload merges extras back into the
    /// pool, so a stale list resurrected the key — it stayed live until the next
    /// reload.
    #[tokio::test]
    async fn a_reload_drops_a_runtime_key_removed_from_the_extras_list() {
        let (store, dir) = open_storage("extras");
        store.save_extra_key("mock", "runtime-key");
        // The list must be readable the instant it is written; the writer task is
        // asynchronous and the reload right after a delete reads it.
        assert!(
            store
                .list_extra_keys("mock")
                .contains(&"runtime-key".to_string()),
            "the extras list is not readable immediately after the write"
        );

        let (state, path) = test_state("extras", BASE, Some(store));
        reload_config(&state).expect("reload");
        assert!(
            state.router.load().providers[0]
                .pool
                .contains("runtime-key"),
            "the reload must merge a runtime-added key"
        );

        // What key_delete does: rebuild the file without the key, clear the list,
        // then reload.
        let storage = state.storage.as_ref().expect("storage");
        storage.set_extra_keys("mock", Vec::new());
        // The file never listed the runtime key (it was added from the dashboard).
        std::fs::write(&path, BASE).expect("edit config");
        reload_config(&state).expect("reload");
        assert!(
            !state.router.load().providers[0]
                .pool
                .contains("runtime-key"),
            "the deleted runtime key survived the reload (stale extras list)"
        );
        assert_eq!(state.router.load().providers[0].pool.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- F3: shutdown must complete while a stream is open -----

    /// An SSE response stays open until the client leaves. `with_graceful_shutdown`
    /// alone therefore never completed, the final flush never ran, and an
    /// orchestrator had to SIGKILL the process.
    #[tokio::test]
    async fn shutdown_completes_even_with_a_stream_still_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let app = axum::Router::new().route(
            "/stream",
            axum::routing::get(|| async {
                // Never yields a chunk: an SSE stream waiting for an upstream that
                // never answers.
                axum::body::Body::from_stream(futures::stream::pending::<
                    Result<bytes::Bytes, std::io::Error>,
                >())
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let server = axum::serve(listener, app).with_graceful_shutdown(drain_signal(stop_rx));
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            serve_until_stopped(
                server,
                stop_tx,
                async {
                    let _ = signal_rx.await;
                },
                Duration::from_millis(300),
            )
            .await
        });

        let client = tokio::spawn(async move {
            let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
            sock.write_all(b"GET /stream HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .expect("write request");
            let mut head = [0u8; 128];
            // Read the response head so the stream is really open, then hold the
            // socket (the body never ends).
            let _ = sock.read(&mut head).await.expect("read head");
            std::future::pending::<()>().await;
        });
        // Give the client time to be mid-stream, then signal termination.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = signal_tx.send(());
        let started = std::time::Instant::now();
        let joined = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("the shutdown never completed")
            .expect("server task panicked");
        let elapsed = started.elapsed();
        joined.expect("the server must stop");
        assert!(
            elapsed < Duration::from_secs(3),
            "shutdown waited {elapsed:?} for an endless stream"
        );
        client.abort();
    }

    // ----- F5: a stalled request body must not hang forever -----

    /// `DefaultBodyLimit` bounds size, not time. A body that stops arriving used to
    /// keep the request (and its client-key concurrency slot) alive indefinitely.
    #[tokio::test]
    async fn a_stalled_request_body_fails_instead_of_hanging() {
        let stream = futures::StreamExt::chain(
            futures::stream::iter(vec![Ok::<_, axum::Error>(bytes::Bytes::from_static(b"x"))]),
            futures::stream::pending::<Result<bytes::Bytes, axum::Error>>(),
        );
        let body = body_with_idle_timeout(
            axum::body::Body::from_stream(stream),
            Duration::from_millis(100),
        );
        let read = tokio::time::timeout(
            Duration::from_secs(3),
            axum::body::to_bytes(body, 1024 * 1024),
        )
        .await;
        match read {
            Ok(Ok(bytes)) => panic!("the stalled body resolved as {bytes:?}"),
            Ok(Err(_)) => {} // the read failed with the deadline: what we want
            Err(_) => panic!("reading a stalled body hung: no read deadline was applied"),
        }
    }

    /// A body that arrives promptly is untouched by the wrapper.
    #[tokio::test]
    async fn a_normal_request_body_is_passed_through() {
        let body = body_with_idle_timeout(axum::body::Body::from("hello"), Duration::from_secs(30));
        let bytes = axum::body::to_bytes(body, 1024).await.expect("body");
        assert_eq!(&bytes[..], b"hello");
    }
}

#[cfg(test)]
mod disabled_entry_tests {
    use super::disabled_entry;

    /// `disabled_models = ["combo/x"]` must hide the bare `x` the catalogue serves;
    /// the two spellings used to disagree between paths.
    #[test]
    fn a_qualified_combo_is_reduced_to_its_bare_name() {
        assert_eq!(disabled_entry("combo/testcombo"), "testcombo");
        assert_eq!(disabled_entry("testcombo"), "testcombo");
        // A provider-qualified model keeps its slash: only "combo/" is special.
        assert_eq!(disabled_entry("mock/test-model"), "mock/test-model");
        assert_eq!(disabled_entry("combo/combo/x"), "combo/x");
    }
}
