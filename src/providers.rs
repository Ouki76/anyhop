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
        .pool_max_idle_per_host(tuning.sticky_max_entries.min(64));
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
    pub pool: KeyPool,
    pub models: Arc<Vec<String>>,
    pub extra_headers: Vec<(String, String)>,
    /// Antigravity OAuth accounts, index-aligned with pool keys
    /// (pool secret == account refresh token).
    ag_accounts: Vec<Arc<Account>>,
    /// Codex (ChatGPT) OAuth accounts.
    codex_accounts: Vec<Arc<crate::codex::CodexAccount>>,
    models_cache: Mutex<Option<(Instant, Arc<Vec<String>>)>>,
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
                let provider_client = build_http_client(effective_proxy)?;
                let mut ag: Vec<Arc<Account>> = Vec::new();
                for a in &cfg.accounts {
                    let client = match &a.proxy {
                        Some(p) => build_http_client(Some(p))?,
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
        let pool = KeyPool::new(
            cfg.name.clone(),
            secrets,
            cfg.strategy,
            cfg.max_concurrent,
            storage.cloned(),
            events.cloned(),
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
            pool,
            models: Arc::new(cfg.models.clone()),
            extra_headers: cfg
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            ag_accounts,
            codex_accounts,
            models_cache: Mutex::new(None),
            quota_cache: Mutex::new(None),
        })
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
    pub async fn effective_models(&self) -> Arc<Vec<String>> {
        {
            let cache = self.models_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((ts, list)) = &*cache
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

    pub async fn fetch_upstream_models(&self) -> Result<Vec<String>, String> {
        match self.kind {
            ProviderKind::Antigravity => {
                let Some(key) = self.pool.pick("", None) else {
                    return Err("no active key/account".into());
                };
                let Some(acc) = self.ag_account(&key.secret) else {
                    return Err("no account for key".into());
                };
                let token = acc.ensure_access_token().await.map_err(|e| e.to_string())?;
                let list =
                    antigravity::fetch_available_models(acc.client(), &self.base_url, &token)
                        .await
                        .map_err(|e| e.to_string())?;
                Ok(list.into_iter().map(|m| m.id).collect())
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
                let mut models = Vec::new();
                if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                            models.push(id.to_string());
                        }
                    }
                } else if let Some(arr) = val.get("models").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(id) = item
                            .get("id")
                            .or_else(|| item.get("name"))
                            .and_then(|v| v.as_str())
                        {
                            models.push(id.to_string());
                        }
                    }
                }
                models.sort();
                models.dedup();
                Ok(models)
            }
            ProviderKind::Gemini => {
                let Some(key) = self.pool.pick("", None) else {
                    return Err("no active key".into());
                };
                let base = self.base_url.trim_end_matches('/');
                let url = format!("{base}/models");
                // key in a header, not the URL — reqwest errors include the URL
                // in their Display, so a ?key= query would leak it into logs
                let resp = self
                    .client
                    .get(&url)
                    .header("x-goog-api-key", &key.secret)
                    .timeout(self.tuning.meta_timeout())
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("gemini returned status {}", resp.status()));
                }
                let val: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
                let mut models = Vec::new();
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
                            models.push(clean_id.to_string());
                        }
                    }
                }
                models.sort();
                models.dedup();
                Ok(models)
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
                let mut models = Vec::new();
                if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                            models.push(id.to_string());
                        }
                    }
                }
                models.sort();
                models.dedup();
                Ok(models)
            }
            ProviderKind::Codex => {
                // Codex (Responses API) has no model-list endpoint —
                // use the static config only, invent nothing.
                Ok(self.models.as_ref().clone())
            }
        }
    }

    /// Refresh models from upstream and update the cache.
    /// Combines any models statically configured in TOML with dynamically discovered ones.
    pub async fn refresh_models(&self) -> Vec<String> {
        match self.fetch_upstream_models().await {
            Ok(fetched) if !fetched.is_empty() => {
                let mut all = self.models.as_ref().clone();
                for m in fetched {
                    if !all.contains(&m) {
                        all.push(m);
                    }
                }
                *self.models_cache.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some((Instant::now(), Arc::new(all.clone())));
                all
            }
            Ok(_) => {
                // Upstream returned an empty list — treat the static config as current.
                let all = self.models.as_ref().clone();
                *self.models_cache.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some((Instant::now(), Arc::new(all.clone())));
                all
            }
            Err(e) => {
                tracing::debug!(provider = %self.name, "models refresh failed: {e}");
                let mut all = self.models.as_ref().clone();
                let mut cache = self.models_cache.lock().unwrap_or_else(|e| e.into_inner());
                match &*cache {
                    Some((_, list)) => {
                        for m in list.iter() {
                            if !all.contains(m) {
                                all.push(m.clone());
                            }
                        }
                        // Bump the timestamp: do not hammer a dead upstream on every /v1/models.
                        *cache = Some((Instant::now(), list.clone()));
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
                        *cache = Some((ts, Arc::new(all.clone())));
                    }
                }
                all
            }
        }
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
            if let Ok(models) =
                antigravity::fetch_available_models(acc.client(), &self.base_url, &token).await
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
        let listed = self.providers.iter().find(|p| {
            if p.models.iter().any(|m| m == model) {
                return true;
            }
            let guard = p.models_cache.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .as_ref()
                .is_some_and(|(_, list)| list.iter().any(|m| m == model))
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
