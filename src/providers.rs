use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// HTTP client for upstream calls, optionally behind a proxy.
pub fn build_http_client(proxy: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent(concat!("anyhop/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(32);
    if let Some(p) = proxy {
        let proxy = reqwest::Proxy::all(p)
            .map_err(|e| anyhow::anyhow!("invalid proxy url '{p}': {e}"))?;
        b = b.proxy(proxy);
    }
    Ok(b.build()?)
}

use crate::antigravity::{self, Account};
use crate::config::{ProviderConfig, ProviderKind};
use crate::events::EventBus;
use crate::pool::KeyPool;
use crate::storage::Storage;

const MODELS_CACHE_TTL: Duration = Duration::from_secs(600);

/// (account label, per-model quotas)
type AccountQuotas = Vec<(String, Vec<antigravity::ModelQuota>)>;

pub struct Provider {
    pub name: String,
    pub kind: ProviderKind,
    pub strategy: crate::config::Strategy,
    pub drain_below_pct: u32,
    pub base_url: String,
    pub client: reqwest::Client,
    pub pool: KeyPool,
    pub models: Vec<String>,
    pub extra_headers: Vec<(String, String)>,
    /// Antigravity OAuth accounts, index-aligned with pool keys
    /// (pool secret == account refresh token).
    ag_accounts: Vec<Arc<Account>>,
    /// Codex (ChatGPT) OAuth accounts.
    codex_accounts: Vec<Arc<crate::codex::CodexAccount>>,
    models_cache: Mutex<Option<(Instant, Vec<String>)>>,
    quota_cache: Mutex<Option<(Instant, AccountQuotas)>>,
}

impl Provider {
    pub fn from_config(
        cfg: &ProviderConfig,
        storage: Option<&Storage>,
        events: Option<&EventBus>,
        default_proxy: Option<&str>,
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
                        ag.push(Arc::new(Account::new(a, &cfg.name, storage, client)));
                    } else {
                        codex_accounts.push(Arc::new(crate::codex::CodexAccount::new(
                            a, &cfg.name, storage, client,
                        )));
                    }
                }
                let secrets: Vec<String> = if matches!(cfg.kind, ProviderKind::Antigravity) {
                    ag.iter().map(|a| a.pool_secret().to_string()).collect()
                } else {
                    codex_accounts.iter().map(|a| a.pool_secret().to_string()).collect()
                };
                (secrets, ag)
            }
        };
        let base_url = if base_url.is_empty() {
            match cfg.kind {
                ProviderKind::Antigravity => antigravity::DAILY_ENDPOINT.to_string(),
                ProviderKind::Anthropic => crate::anthropic::DEFAULT_BASE_URL.to_string(),
                ProviderKind::Codex => {
                    "https://chatgpt.com/backend-api/codex".to_string()
                }
                _ => base_url,
            }
        } else {
            base_url
        };
        Ok(Self {
            name: cfg.name.clone(),
            kind: cfg.kind,
            strategy: cfg.strategy,
            drain_below_pct: cfg.drain_below_pct,
            base_url,
            client: build_http_client(effective_proxy)?,
            pool: KeyPool::new(
                cfg.name.clone(),
                secrets,
                cfg.strategy,
                cfg.max_concurrent,
                storage.cloned(),
                events.cloned(),
            ),
            models: cfg.models.clone(),
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

    /// Configured models, or a dynamically fetched list for antigravity
    /// (cached for 10 minutes).
    pub async fn effective_models(&self) -> Vec<String> {
        if !self.models.is_empty() {
            return self.models.clone();
        }
        if !matches!(self.kind, ProviderKind::Antigravity) {
            return Vec::new();
        }
        {
            let cache = self.models_cache.lock().unwrap();
            if let Some((ts, list)) = &*cache
                && ts.elapsed() < MODELS_CACHE_TTL
            {
                return list.clone();
            }
        }
        let Some(key) = self.pool.pick("") else {
            return Vec::new();
        };
        let Some(acc) = self.ag_account(&key.secret) else {
            return Vec::new();
        };
        let Ok(token) = acc.ensure_access_token().await else {
            return Vec::new();
        };
        match antigravity::fetch_available_models(acc.client(), &self.base_url, &token).await {
            Ok(list) if !list.is_empty() => {
                let ids: Vec<String> = list.iter().map(|m| m.id.clone()).collect();
                let mut cache = self.models_cache.lock().unwrap();
                *cache = Some((Instant::now(), ids.clone()));
                ids
            }
            _ => Vec::new(),
        }
    }

    /// Per-account model quotas (antigravity only), cached for 60s.
    pub async fn quotas(&self) -> AccountQuotas {
        if !matches!(self.kind, ProviderKind::Antigravity) {
            return Vec::new();
        }
        {
            let cache = self.quota_cache.lock().unwrap();
            if let Some((ts, q)) = &*cache
                && ts.elapsed() < Duration::from_secs(60)
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
        if !out.is_empty() {
            let mut cache = self.quota_cache.lock().unwrap();
            *cache = Some((Instant::now(), out.clone()));
        }
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
                .filter_map(|m| self.resolve_single(m))
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
        self.providers
            .iter()
            .find(|p| p.models.iter().any(|m| m == model))
            .or_else(|| self.providers.iter().find(|p| p.models.is_empty()))
            .map(|p| (p, model.to_string()))
    }
}
