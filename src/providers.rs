use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// HTTP client for upstream calls, optionally behind a proxy.
pub fn build_http_client(proxy: Option<&str>) -> anyhow::Result<reqwest::Client> {
    build_http_client_with(proxy, &crate::config::Tuning::default())
}

pub fn build_http_client_with(
    proxy: Option<&str>,
    tuning: &crate::config::Tuning,
) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("anyhop/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(tuning.connect_timeout())
        .pool_max_idle_per_host(tuning.sticky_max_entries.min(64))
        // Ambient proxy variables are deliberately ignored.
        //
        // reqwest 0.12 enables its `system-proxy` feature by default, so
        // `HTTPS_PROXY`/`ALL_PROXY`/`HTTP_PROXY` were honoured even with no proxy
        // configured here. For a gateway that *forwards credentials*, that is the
        // difference between "the operator chose a proxy" and "whoever can set an
        // environment variable — an `EnvironmentFile=`, a compose `env_file`, a
        // parent process, a CI runner — receives `Authorization: Bearer <provider
        // key>`, `x-api-key` and `x-goog-api-key` for every upstream call, plus the
        // plaintext replies", with no config change and no warning.
        //
        // A proxy is therefore opt-in and explicit: `[server] proxy` or a
        // per-provider/per-account `proxy` key. Nothing else routes traffic.
        .no_proxy();
    if let Some(p) = proxy {
        let proxy =
            reqwest::Proxy::all(p).map_err(|e| anyhow::anyhow!("invalid proxy url '{p}': {e}"))?;
        b = b.proxy(proxy);
    }
    Ok(b.build()?)
}

use crate::antigravity::{self, Account};
use crate::config::{ProviderConfig, ProviderKind};
use crate::events::EventBus;
use crate::pool::KeyPool;
use crate::storage::Storage;

// Cache TTL and meta timeouts live in `[tuning]` (config::Tuning).

/// (account label, per-model quotas)
type AccountQuotas = Vec<(String, Vec<antigravity::ModelQuota>)>;

/// What a provider's model listing yields: the ids, and whatever limits the
/// provider stated for them.
#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    pub models: Vec<String>,
    /// Keyed by the model id as the provider spells it.
    pub limits: std::collections::HashMap<String, crate::limits::Limits>,
}

impl Catalogue {
    fn push(&mut self, id: String, limits: crate::limits::Limits) {
        if !limits.is_empty() {
            self.limits.insert(id.clone(), limits);
        }
        if !self.models.contains(&id) {
            self.models.push(id);
        }
    }

    fn finish(mut self) -> Self {
        self.models.sort();
        self.models.dedup();
        self
    }
}

pub struct Provider {
    pub name: String,
    /// Per-provider overrides: some upstreams need minutes, others seconds.
    pub timeout: Duration,
    pub max_retries: usize,
    pub tuning: Arc<crate::config::Tuning>,
    pub kind: ProviderKind,
    pub strategy: crate::config::Strategy,
    pub drain_below_pct: u32,
    /// Effective admission limit per key (0 = unlimited); kept for the dashboard.
    pub max_concurrent: u32,
    /// Provider-level proxy as written in the config (accounts may override).
    pub proxy: Option<String>,
    pub base_url: String,
    pub client: reqwest::Client,
    /// Shared with the router: a config reload reuses the live pool (and with it
    /// the cooldowns and counters) when nothing about the credentials changed.
    pub pool: Arc<KeyPool>,
    pub models: Arc<Vec<String>>,
    pub extra_headers: Vec<(String, String)>,
    /// Pass-through capabilities declared in the config ("images", "audio",
    /// "realtime"). Empty = chat/completions/embeddings only. Kept on the
    /// runtime provider so `proxy::media` can route without re-reading the
    /// config file on every request.
    pub capabilities: Vec<String>,
    /// Antigravity OAuth accounts, index-aligned with pool keys
    /// (pool secret == account refresh token).
    ag_accounts: Vec<Arc<Account>>,
    /// Codex (ChatGPT) OAuth accounts.
    codex_accounts: Vec<Arc<crate::codex::CodexAccount>>,
    /// Upstream model list plus its fetch time.
    ///
    /// An `ArcSwap` rather than a `Mutex`: `resolve_single` reads it for every
    /// provider on every request (to see whether a model belongs to it), and a
    /// lock there contended with the periodic refresh for no benefit. Loading is
    /// a single atomic read, and a refresh publishes a whole new snapshot.
    models_cache: arc_swap::ArcSwap<Option<(Instant, Arc<Vec<String>>)>>,
    /// Optional URL of a richer catalogue to read limits from (`limits_url`).
    limits_url: Option<String>,
    /// Set once the provider answered 404/405 for `/completions`: FIM requests then
    /// go straight to the marker path instead of paying a doomed round trip on
    /// every keystroke.
    pub no_completions: std::sync::atomic::AtomicBool,
    /// Limits parsed from the last successful catalogue fetch (model id -> limits).
    /// Empty until the first refresh; a provider that publishes numbers is the most
    /// accurate source there is.
    discovered_limits: arc_swap::ArcSwap<std::collections::HashMap<String, crate::limits::Limits>>,
    quota_cache: Mutex<Option<(Instant, AccountQuotas)>>,
}

impl Provider {
    pub fn from_config(
        cfg: &ProviderConfig,
        storage: Option<&Storage>,
        events: Option<&EventBus>,
        default_proxy: Option<&str>,
        tuning: Arc<crate::config::Tuning>,
        default_timeout: Duration,
        default_retries: usize,
    ) -> anyhow::Result<Self> {
        // Priority: account.proxy > provider.proxy > server-wide proxy.
        let effective_proxy = cfg.proxy.as_deref().or(default_proxy);
        let base_url = cfg.base_url.trim_end_matches('/').to_string();
        let mut codex_accounts: Vec<Arc<crate::codex::CodexAccount>> = Vec::new();
        let (secrets, ag_accounts) = match cfg.kind {
            ProviderKind::OpenaiCompat | ProviderKind::Gemini | ProviderKind::Anthropic => {
                anyhow::ensure!(
                    !cfg.keys.is_empty(),
                    "provider '{}': no keys configured",
                    cfg.name
                );
                anyhow::ensure!(
                    !base_url.is_empty() || matches!(cfg.kind, ProviderKind::Anthropic),
                    "provider '{}': base_url is required",
                    cfg.name
                );
                (cfg.keys.clone(), Vec::new())
            }
            ProviderKind::Antigravity | ProviderKind::Codex => {
                let auth_cmd = if matches!(cfg.kind, ProviderKind::Antigravity) {
                    "anyhop auth antigravity"
                } else {
                    "anyhop auth codex"
                };
                anyhow::ensure!(
                    !cfg.accounts.is_empty(),
                    "provider '{}': no accounts configured (run `{auth_cmd}`)",
                    cfg.name
                );
                // The configured tuning, not `Tuning::default()`: connect_timeout
                // and the pool settings were dead config for every Antigravity and
                // Codex account (only the provider-wide client below honoured them).
                let provider_client = build_http_client_with(effective_proxy, &tuning)?;
                let mut ag: Vec<Arc<Account>> = Vec::new();
                for a in &cfg.accounts {
                    let client = match &a.proxy {
                        Some(p) => build_http_client_with(Some(p), &tuning)?,
                        None => provider_client.clone(),
                    };
                    if matches!(cfg.kind, ProviderKind::Antigravity) {
                        ag.push(Arc::new(Account::new(
                            a,
                            &cfg.name,
                            storage,
                            client,
                            tuning.clone(),
                        )));
                    } else {
                        codex_accounts.push(Arc::new(crate::codex::CodexAccount::new(
                            a,
                            &cfg.name,
                            storage,
                            client,
                            tuning.clone(),
                        )));
                    }
                }
                let secrets: Vec<String> = if matches!(cfg.kind, ProviderKind::Antigravity) {
                    ag.iter().map(|a| a.pool_secret().to_string()).collect()
                } else {
                    codex_accounts
                        .iter()
                        .map(|a| a.pool_secret().to_string())
                        .collect()
                };
                (secrets, ag)
            }
        };
        let base_url = if base_url.is_empty() {
            match cfg.kind {
                ProviderKind::Antigravity => antigravity::DAILY_ENDPOINT.to_string(),
                ProviderKind::Anthropic => crate::anthropic::DEFAULT_BASE_URL.to_string(),
                ProviderKind::Codex => "https://chatgpt.com/backend-api/codex".to_string(),
                _ => base_url,
            }
        } else {
            base_url
        };
        // The tuning the config asked for. Passing it here (rather than letting
        // the pool default) is what makes max_cooldown / backoff / sticky_mode /
        // TTLs actual config instead of decoration.
        let pool = KeyPool::new(
            cfg.name.clone(),
            secrets,
            cfg.strategy,
            cfg.max_concurrent,
            storage.cloned(),
            events.cloned(),
            tuning.clone(),
        );
        // OAuth credentials are refresh tokens: label them with the account
        // e-mail so the dashboard shows "user@example.com" instead of a token
        // prefix (which also used to leak the first 8 characters of the token).
        for acc in &ag_accounts {
            pool.set_label(acc.pool_secret(), &acc.label());
        }
        for acc in &codex_accounts {
            pool.set_label(acc.pool_secret(), &acc.label());
        }

        Ok(Self {
            name: cfg.name.clone(),
            kind: cfg.kind,
            strategy: cfg.strategy,
            drain_below_pct: cfg.drain_below_pct,
            max_concurrent: cfg.max_concurrent,
            proxy: cfg.proxy.clone(),
            base_url,
            timeout: cfg
                .timeout_secs
                .map(Duration::from_secs)
                .unwrap_or(default_timeout),
            max_retries: cfg.max_retries.unwrap_or(default_retries),
            tuning: tuning.clone(),
            client: build_http_client_with(effective_proxy, &tuning)?,
            pool: Arc::new(pool),
            models: Arc::new(cfg.models.clone()),
            extra_headers: cfg
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            capabilities: cfg.capabilities.clone(),
            limits_url: cfg
                .limits_url
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(str::to_string),
            no_completions: std::sync::atomic::AtomicBool::new(false),
            ag_accounts,
            codex_accounts,
            models_cache: arc_swap::ArcSwap::from_pointee(None),
            discovered_limits: arc_swap::ArcSwap::from_pointee(std::collections::HashMap::new()),
            quota_cache: Mutex::new(None),
        })
    }

    /// True when this provider explicitly declares `cap` ("images", "audio",
    /// "realtime").
    ///
    /// The `openai_compat` check is not redundant with config validation: only
    /// that kind may declare capabilities (`Config::validate` rejects the rest),
    /// and repeating it here keeps a hand-built router — tests, a future
    /// reload path — from routing an image request to an API that cannot serve
    /// it. Silence ("no declaration") must never be read as "capable".
    pub fn has_capability(&self, cap: &str) -> bool {
        matches!(self.kind, ProviderKind::OpenaiCompat)
            && self.capabilities.iter().any(|c| c == cap)
    }

    /// Find the OAuth account behind a pool key (antigravity only).
    pub fn ag_account(&self, secret: &str) -> Option<Arc<Account>> {
        self.ag_accounts
            .iter()
            .find(|a| a.pool_secret() == secret)
            .cloned()
    }

    /// Find the Codex account behind a pool key.
    pub fn codex_account(&self, secret: &str) -> Option<Arc<crate::codex::CodexAccount>> {
        self.codex_accounts
            .iter()
            .find(|a| a.pool_secret() == secret)
            .cloned()
    }

    /// Static config + fresh cache. Upstream is only queried as a bootstrap when
    /// there is no static list (antigravity) and the cache is empty/stale. Never hits
    /// the network when models are explicitly configured.
    /// Returns a shared handle: `/v1/models` and the dashboard poll this on every
    /// request, and cloning a 124-element `Vec<String>` each time was pure waste.
    /// Test hook: pretend the last refresh reported these limits.
    #[cfg(test)]
    pub fn set_discovered_limits_for_test(
        &self,
        limits: std::collections::HashMap<String, crate::limits::Limits>,
    ) {
        self.discovered_limits.store(Arc::new(limits));
    }

    /// What this provider stated about one model's limits, if anything.
    ///
    /// Keyed by the id the provider publishes, which is what `effective_models`
    /// hands out, so the lookup is a plain hash probe.
    pub fn discovered_limits(&self, model: &str) -> Option<crate::limits::Limits> {
        let map = self.discovered_limits.load();
        map.get(model).copied().filter(|l| !l.is_empty())
    }

    pub async fn effective_models(&self) -> Arc<Vec<String>> {
        {
            let cache = self.models_cache.load();
            if let Some((ts, list)) = cache.as_ref()
                && ts.elapsed() < self.tuning.models_cache_ttl()
            {
                return Arc::clone(list);
            }
        }
        if !self.models.is_empty() {
            return Arc::clone(&self.models);
        }
        Arc::new(self.refresh_models().await)
    }

    pub async fn fetch_upstream_models(&self) -> Result<Catalogue, String> {
        match self.kind {
            ProviderKind::Antigravity => {
                let Some(key) = self.pool.pick("", None) else {
                    return Err("no active key/account".into());
                };
                let Some(acc) = self.ag_account(&key.secret) else {
                    return Err("no account for key".into());
                };
                let token = acc.ensure_access_token().await.map_err(|e| e.to_string())?;
                let list = antigravity::fetch_available_models(
                    acc.client(),
                    &self.base_url,
                    &token,
                    self.tuning.meta_timeout(),
                )
                .await
                .map_err(|e| e.to_string())?;
                let mut cat = Catalogue::default();
                for m in list {
                    cat.push(m.id, m.limits);
                }
                Ok(cat.finish())
            }
            ProviderKind::OpenaiCompat => {
                let Some(key) = self.pool.pick("", None) else {
                    return Err("no active key".into());
                };
                let base = self.base_url.trim_end_matches('/');
                let url = format!("{base}/models");
                let mut req = self
                    .client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", key.secret));
                for (k, v) in &self.extra_headers {
                    req = req.header(k, v);
                }
                let resp = req
                    .timeout(self.tuning.meta_timeout())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("upstream returned status {}", resp.status()));
                }
                let val: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
                let mut cat = Catalogue::default();
                let mut take = |item: &serde_json::Value, id: &str| {
                    cat.push(id.to_string(), crate::limits::from_json(item));
                };
                if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                            take(item, id);
                        }
                    }
                } else if let Some(arr) = val.get("models").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(id) = item
                            .get("id")
                            .or_else(|| item.get("name"))
                            .and_then(|v| v.as_str())
                        {
                            take(item, id);
                        }
                    }
                }
                // The OpenAI-compatible catalogue often carries no limits at all
                // (DashScope: only id/object/created/owned_by). When the operator
                // points `limits_url` at the vendor's richer catalogue, read the
                // numbers from there. No vendor is special-cased here: which
                // endpoint publishes what is the operator's call, not a guess.
                if let Some(_url) = self.limits_url.as_deref() {
                    for (id, l) in self.fetch_limits_catalogue(&key.secret).await {
                        cat.limits.entry(id).or_insert(l);
                    }
                }
                Ok(cat.finish())
            }
            ProviderKind::Gemini => {
                let Some(key) = self.pool.pick("", None) else {
                    return Err("no active key".into());
                };
                let base = self.base_url.trim_end_matches('/');
                let url = format!("{base}/models");
                // key in a header, not the URL — reqwest errors include the URL
                // in their Display, so a ?key= query would leak it into logs
                let mut req = self.client.get(&url).header("x-goog-api-key", &key.secret);
                // Same extra headers as the chat path: a gemini provider behind a
                // gateway that needs a routing/beta header served completions but
                // returned 401 for /v1/models (and an empty dashboard catalogue).
                for (k, v) in &self.extra_headers {
                    req = req.header(k, v);
                }
                let resp = req
                    .timeout(self.tuning.meta_timeout())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("gemini returned status {}", resp.status()));
                }
                let val: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
                let mut cat = Catalogue::default();
                if let Some(arr) = val.get("models").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(methods) = item
                            .get("supportedGenerationMethods")
                            .and_then(|v| v.as_array())
                            && !methods
                                .iter()
                                .any(|m| m.as_str() == Some("generateContent"))
                        {
                            continue;
                        }
                        if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                            let clean_id = name.strip_prefix("models/").unwrap_or(name);
                            cat.push(clean_id.to_string(), crate::limits::from_json(item));
                        }
                    }
                }
                Ok(cat.finish())
            }
            ProviderKind::Anthropic => {
                let Some(key) = self.pool.pick("", None) else {
                    return Err("no active key".into());
                };
                let base = if self.base_url.is_empty() {
                    "https://api.anthropic.com".to_string()
                } else {
                    self.base_url.trim_end_matches('/').to_string()
                };
                let url = if base.ends_with("/v1") {
                    format!("{base}/models")
                } else {
                    format!("{base}/v1/models")
                };
                let mut req = self
                    .client
                    .get(&url)
                    .header("x-api-key", &key.secret)
                    .header("anthropic-version", crate::anthropic::API_VERSION);
                for (k, v) in &self.extra_headers {
                    req = req.header(k, v);
                }
                let resp = req
                    .timeout(self.tuning.meta_timeout())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("anthropic returned status {}", resp.status()));
                }
                let val: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
                let mut cat = Catalogue::default();
                if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                            cat.push(id.to_string(), crate::limits::from_json(item));
                        }
                    }
                }
                Ok(cat.finish())
            }
            ProviderKind::Codex => {
                // Codex (Responses API) has no model-list endpoint —
                // use the static config only, invent nothing.
                Ok(Catalogue {
                    models: self.models.as_ref().clone(),
                    limits: std::collections::HashMap::new(),
                })
            }
        }
    }

    /// Read per-model limits from the catalogue `limits_url` points at.
    ///
    /// The OpenAI-compatible `/models` of some vendors says nothing about sizes
    /// (DashScope returns only `id/object/created/owned_by`) while their native
    /// catalogue publishes them; the operator names that catalogue once, per
    /// provider. The page walk is bounded (10 x 100) so a misbehaving catalogue
    /// cannot hang a refresh, and any failure is a debug log — limits are metadata,
    /// never a reason to fail the model list.
    async fn fetch_limits_catalogue(
        &self,
        key: &str,
    ) -> std::collections::HashMap<String, crate::limits::Limits> {
        let mut out = std::collections::HashMap::new();
        let Some(meta_base) = self.limits_url.clone() else {
            return out;
        };
        for page in 1..=10u32 {
            let sep = if meta_base.contains('?') { '&' } else { '?' };
            let url = format!("{meta_base}{sep}page_size=100&page_no={page}");
            let resp = match self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {key}"))
                .timeout(self.tuning.meta_timeout())
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(provider = %self.name, "limits catalogue: {e}");
                    break;
                }
            };
            if !resp.status().is_success() {
                tracing::debug!(
                    provider = %self.name,
                    status = %resp.status(),
                    "limits catalogue returned an error status"
                );
                break;
            }
            let Ok(v) = resp.json::<serde_json::Value>().await else {
                break;
            };
            let entries = v
                .pointer("/output/models")
                .and_then(|m| m.as_array())
                .or_else(|| v.get("models").and_then(|m| m.as_array()))
                .or_else(|| v.get("data").and_then(|m| m.as_array()));
            let Some(entries) = entries else { break };
            let n = entries.len();
            for e in entries {
                let Some(id) = e
                    .get("model")
                    .or_else(|| e.get("id"))
                    .or_else(|| e.get("name"))
                    .and_then(|i| i.as_str())
                else {
                    continue;
                };
                let limits = crate::limits::from_json(e);
                if !limits.is_empty() {
                    out.entry(id.trim_start_matches("models/").to_string())
                        .or_insert(limits);
                }
            }
            if n < 100 {
                break;
            }
        }
        if !out.is_empty() {
            tracing::debug!(
                provider = %self.name,
                models = out.len(),
                "limits read from the vendor catalogue"
            );
        }
        out
    }

    /// Refresh models from upstream and update the cache.
    /// Combines any models statically configured in TOML with dynamically discovered ones.
    pub async fn refresh_models(&self) -> Vec<String> {
        match self.fetch_upstream_models().await {
            Ok(fetched) if !fetched.models.is_empty() => {
                // The provider's own numbers replace the previous snapshot: a model
                // that vanished must not keep publishing a stale window.
                self.discovered_limits.store(Arc::new(fetched.limits));
                let mut all = self.models.as_ref().clone();
                for m in fetched.models {
                    if !all.contains(&m) {
                        all.push(m);
                    }
                }
                self.publish_models(all.clone());
                all
            }
            Ok(_) => {
                // Upstream returned an empty list — treat the static config as current.
                let all = self.models.as_ref().clone();
                self.publish_models(all.clone());
                all
            }
            Err(e) => {
                tracing::debug!(provider = %self.name, "models refresh failed: {e}");
                let mut all = self.models.as_ref().clone();
                // A whole new snapshot is published, so a reader either sees the
                // previous cache or this one — never a half-updated value.
                let current = self.models_cache.load_full();
                match current.as_ref() {
                    Some((_, list)) => {
                        for m in list.iter() {
                            if !all.contains(m) {
                                all.push(m.clone());
                            }
                        }
                        // Bump the timestamp: do not hammer a dead upstream on every /v1/models.
                        self.models_cache
                            .store(Arc::new(Some((Instant::now(), list.clone()))));
                    }
                    None => {
                        // Negative cache: shift the timestamp back so only a short
                        // window remains before the next attempt (a tenth of the
                        // TTL, at most a minute) instead of hammering a dead
                        // upstream on every /v1/models.
                        let ttl = self.tuning.models_cache_ttl();
                        let margin = Duration::from_secs((ttl.as_secs() / 10).min(60));
                        let ts = Instant::now()
                            .checked_sub(ttl.saturating_sub(margin))
                            .unwrap_or_else(Instant::now);
                        self.models_cache
                            .store(Arc::new(Some((ts, Arc::new(all.clone())))));
                    }
                }
                all
            }
        }
    }

    /// Publish a freshly fetched model list (and its fetch time) to readers.
    fn publish_models(&self, all: Vec<String>) {
        self.models_cache
            .store(Arc::new(Some((Instant::now(), Arc::new(all)))));
    }

    /// Per-account model quotas (antigravity only), cached for 60s.
    pub async fn quotas(&self) -> AccountQuotas {
        if !matches!(self.kind, ProviderKind::Antigravity) {
            return Vec::new();
        }
        {
            let cache = self.quota_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((ts, q)) = &*cache
                && ts.elapsed() < self.tuning.quota_cache_ttl()
            {
                return q.clone();
            }
        }
        let mut out = Vec::new();
        for acc in &self.ag_accounts {
            let Ok(token) = acc.ensure_access_token().await else {
                continue;
            };
            if let Ok(models) = antigravity::fetch_available_models(
                acc.client(),
                &self.base_url,
                &token,
                self.tuning.meta_timeout(),
            )
            .await
            {
                out.push((acc.label(), models));
            }
        }
        // Cache unconditionally (empty result included): on a total failure this
        // is a 60s negative cache, so a dead account isn't re-refreshing its
        // OAuth token + refetching models on every dashboard poll.
        let mut cache = self.quota_cache.lock().unwrap_or_else(|e| e.into_inner());
        *cache = Some((Instant::now(), out.clone()));
        out
    }
}

/// Resolves incoming model names to providers.
pub struct ProviderRouter {
    pub providers: Vec<Provider>,
    pub combos: Vec<crate::config::ComboConfig>,
}

pub enum Resolved<'a> {
    One(&'a Provider, String),
    /// Ordered fallback chain of (provider, upstream_model).
    Chain(Vec<(&'a Provider, String)>),
}

impl ProviderRouter {
    pub fn resolve<'a>(&'a self, model: &str) -> Option<Resolved<'a>> {
        let combo_name = model.strip_prefix("combo/").unwrap_or(model);
        if let Some(c) = self.combos.iter().find(|c| c.name == combo_name) {
            let chain: Vec<_> = c
                .chain
                .iter()
                .filter_map(|m| {
                    // Chain entries are "provider/model" (see example config).
                    // An unknown provider prefix is a config error: skip the
                    // entry instead of letting it fall through to a wildcard
                    // provider with a garbage model id.
                    if let Some((prefix, _)) = m.split_once('/')
                        && self.providers.iter().all(|p| p.name != prefix)
                    {
                        tracing::warn!(combo = %c.name, entry = %m,
                            "combo chain entry references an unknown provider — skipped");
                        return None;
                    }
                    self.resolve_single(m)
                })
                .collect();
            if !chain.is_empty() {
                return Some(Resolved::Chain(chain));
            }
        }
        self.resolve_single(model).map(|(p, m)| Resolved::One(p, m))
    }

    /// `model` may be "provider/upstream-model" (explicit) or a bare model name
    /// matched against each provider's model list (empty list = wildcard).
    /// Explicit model lists take priority over wildcard providers.
    fn resolve_single<'a>(&'a self, model: &str) -> Option<(&'a Provider, String)> {
        if let Some((prefix, rest)) = model.split_once('/')
            && let Some(p) = self.providers.iter().find(|p| p.name == prefix)
        {
            return Some((p, rest.to_string()));
        }
        // Two lookups per provider: the static config list, then the dynamically
        // discovered one. The latter is read through an `ArcSwap` snapshot — no
        // lock on the request path, so a periodic model refresh cannot make every
        // in-flight request queue behind it.
        let listed = self.providers.iter().find(|p| {
            if p.models.iter().any(|m| m == model) {
                return true;
            }
            let cache = p.models_cache.load();
            matches!(&**cache, Some((_, list)) if list.iter().any(|m| m == model))
        });
        if let Some(p) = listed {
            return Some((p, model.to_string()));
        }

        // Wildcard providers accept any model name. With more than one of them
        // the choice is arbitrary, so make it a config smell instead of a
        // silent misroute: prefer an explicit `provider/model` request.
        let mut wildcards = self.providers.iter().filter(|p| p.models.is_empty());
        let first = wildcards.next()?;
        let extra = wildcards.count();
        if extra > 0 {
            tracing::debug!(
                model = %model, providers = extra + 1,
                "model matches no explicit list and several providers are wildcards; \
                 using the first one — request '{provider}/{model}' to disambiguate",
                provider = first.name
            );
        }
        Some((first, model.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::FailKind;

    /// A proxy in the environment must not silently receive provider credentials.
    ///
    /// `reqwest` 0.12 enables its `system-proxy` feature by default, so before
    /// `.no_proxy()` a bare `HTTPS_PROXY=…` (an `EnvironmentFile=`, a compose
    /// `env_file`, a parent process) captured every upstream call — and with it
    /// every `Authorization`/`x-api-key` header. The proof here is behavioural, not
    /// a config inspection: point the proxy variable at a listener that records
    /// what it is asked to CONNECT to, run a real request to a *different* live
    /// upstream, and require that the proxy saw nothing.
    #[tokio::test]
    async fn ambient_proxy_env_does_not_intercept_upstream_calls() {
        // The upstream the client really talks to.
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let served = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let served_here = served.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let (mut sock, _) = upstream.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            served_here.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });

        // The proxy that must stay idle.
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxied = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let proxied_here = proxied.clone();
        tokio::spawn(async move {
            if tokio::time::timeout(Duration::from_millis(700), proxy.accept())
                .await
                .is_ok()
            {
                proxied_here.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        // SAFETY-equivalent of a hostile environment: the variable is set for the
        // duration of this one client build, which is read at build time.
        //
        // `set_var` is unsafe from Rust 2024 on and is racy across threads, so the
        // client is built while holding a lock that no other test in this binary
        // takes; the value is restored immediately afterwards.
        // `set_var` is unsafe in edition 2024 (it races with concurrent readers).
        // Serialised by a lock no other test in this binary takes, restored
        // immediately, and the crate denies `unsafe_code` everywhere else.
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = (
            std::env::var_os("HTTP_PROXY"),
            std::env::var_os("http_proxy"),
        );
        let proxy_url = format!("http://{proxy_addr}");
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("HTTP_PROXY", &proxy_url);
            std::env::set_var("http_proxy", &proxy_url);
        }
        let client = build_http_client_with(None, &crate::config::Tuning::default());
        #[allow(unsafe_code)]
        unsafe {
            match previous.0 {
                Some(v) => std::env::set_var("HTTP_PROXY", v),
                None => std::env::remove_var("HTTP_PROXY"),
            }
            match previous.1 {
                Some(v) => std::env::set_var("http_proxy", v),
                None => std::env::remove_var("http_proxy"),
            }
        }
        drop(guard);

        let client = client.expect("client builds");
        let resp = client
            .get(format!("http://{upstream_addr}/probe"))
            .header("x-api-key", "sk-must-not-leak")
            .send()
            .await
            .expect("the request must reach the upstream directly");
        assert_eq!(resp.status(), 200);
        // Let the proxy's acceptor notice (it should not).
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !proxied.load(std::sync::atomic::Ordering::SeqCst),
            "a proxy from the environment received the request (credential leak)"
        );
        assert!(
            served.load(std::sync::atomic::Ordering::SeqCst),
            "the upstream was never contacted"
        );
    }

    fn provider(extra: &str) -> Provider {
        let src = format!(
            r#"
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:9/v1"
            keys = ["sk-1", "sk-2"]
            {extra}
            "#
        );
        let cfg: ProviderConfig = toml::from_str(&src).expect("test provider config");
        Provider::from_config(
            &cfg,
            None,
            None,
            None,
            Arc::new(crate::config::Tuning::default()),
            Duration::from_secs(30),
            2,
        )
        .expect("provider builds offline")
    }

    /// The second catalogue is a *config* value, not a vendor name: whatever URL
    /// `limits_url` holds is walked (paged) and its `model_info`-shaped numbers are
    /// merged into the discovered map.
    #[tokio::test]
    async fn limits_url_is_read_and_paged_without_any_vendor_knowledge() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 2048];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // Page 1 has two models, page 2 is empty; only the first request
                // carries no `page_no`, which is what the client sends.
                let body = if req.contains("page_no=1") || !req.contains("page_no") {
                    r#"{"output":{"models":[
                        {"model":"alpha","model_info":{"context_window":1000,"max_input_tokens":900,"max_output_tokens":100}},
                        {"model":"beta","model_info":{"context_window":2000}}
                    ]}}"#
                } else {
                    r#"{"output":{"models":[]}}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });

        let p = provider(&format!(
            r#"limits_url = "http://127.0.0.1:{}/api/v1/models""#,
            addr.port()
        ));
        let found = p.fetch_limits_catalogue("sk-1").await;
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found["alpha"].context_window, 1000);
        assert_eq!(found["alpha"].max_output_tokens, 100);
        assert_eq!(found["alpha"].max_input_tokens, 900);
        assert_eq!(found["beta"].context_window, 2000);
    }

    /// B: the production constructor must hand the configured tuning to the pool.
    /// It used to call `KeyPool::new`, which substituted `Tuning::default()`, so
    /// every `[tuning]` cooldown/backoff knob was dead config.
    #[test]
    fn from_config_hands_the_configured_tuning_to_the_pool() {
        let cfg: ProviderConfig = toml::from_str(
            r#"
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:9/v1"
            keys = ["sk-1"]
            "#,
        )
        .expect("config");
        let tuning = Arc::new(crate::config::Tuning {
            rate_limit_cooldown_secs: 1,
            base_backoff_secs: 1,
            max_cooldown_secs: 2,
            sticky_mode: "map".to_string(),
            ..crate::config::Tuning::default()
        });
        let p = Provider::from_config(
            &cfg,
            None,
            None,
            None,
            tuning.clone(),
            Duration::from_secs(30),
            2,
        )
        .expect("builds offline");
        assert!(
            Arc::ptr_eq(&p.pool.tuning(), &tuning),
            "the pool must hold the config's tuning, not a default"
        );

        // …and it is what the pool actually uses.
        let k = p.pool.pick("m", None).expect("a key");
        p.pool.report_failure(
            &k,
            FailKind::RateLimited {
                retry_after_secs: None,
            },
            "m",
        );
        assert!(
            p.pool.snapshot()[0].cooldown_remaining_secs <= 1,
            "configured rate_limit_cooldown_secs = 1 was ignored"
        );
    }

    // ----- L: resolution reads the model cache without locking -----

    /// A model discovered by a refresh must resolve to the provider that found
    /// it, and a later snapshot must be seen immediately: the router caches
    /// nothing of its own, it only reads the published snapshot.
    #[test]
    fn resolution_follows_the_dynamic_model_cache() {
        let wildcard = provider("");
        let mut listed = provider("");
        listed.name = "listed".to_string();
        let router = ProviderRouter {
            providers: vec![wildcard, listed],
            combos: Vec::new(),
        };

        // Unknown everywhere: the wildcard provider takes it.
        match router.resolve("brand-new") {
            Some(Resolved::One(p, m)) => {
                assert_eq!(p.name, "mock");
                assert_eq!(m, "brand-new");
            }
            _ => panic!("the wildcard provider must answer"),
        }

        // The second provider discovers it upstream; explicit discovery wins over
        // the wildcard fallback, so the request goes where the model really is.
        router.providers[1].publish_models(vec!["brand-new".to_string()]);
        match router.resolve("brand-new") {
            Some(Resolved::One(p, _)) => {
                assert_eq!(p.name, "listed", "the refreshed list was not consulted");
            }
            _ => panic!("resolve returned nothing"),
        }

        // A new snapshot (the model vanished) is visible at once — no stale cache.
        router.providers[1].publish_models(Vec::new());
        match router.resolve("brand-new") {
            Some(Resolved::One(p, _)) => assert_eq!(p.name, "mock"),
            _ => panic!("resolve returned nothing"),
        }
    }

    #[test]
    fn an_explicit_provider_prefix_still_wins() {
        let p = provider("");
        let router = ProviderRouter {
            providers: vec![p],
            combos: Vec::new(),
        };
        match router.resolve("mock/any-model-at-all") {
            Some(Resolved::One(provider, model)) => {
                assert_eq!(provider.name, "mock");
                assert_eq!(model, "any-model-at-all");
            }
            _ => panic!("an explicit prefix must resolve"),
        }
    }
}
