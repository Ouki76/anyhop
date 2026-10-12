use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::antigravity::{self, Account};
use crate::config::{ProviderConfig, ProviderKind};
use crate::events::DashEvent;
use crate::pool::KeyPool;
use crate::storage::Storage;

const MODELS_CACHE_TTL: Duration = Duration::from_secs(600);

pub struct Provider {
    pub name: String,
    pub kind: ProviderKind,
    pub strategy: crate::config::Strategy,
    pub base_url: String,
    pub pool: KeyPool,
    pub models: Vec<String>,
    pub extra_headers: Vec<(String, String)>,
    /// Antigravity OAuth accounts, index-aligned with pool keys
    /// (pool secret == account refresh token).
    ag_accounts: Vec<Arc<Account>>,
    models_cache: Mutex<Option<(Instant, Vec<String>)>>,
}

impl Provider {
    pub fn from_config(
        cfg: &ProviderConfig,
        storage: Option<&Storage>,
        events: Option<&tokio::sync::broadcast::Sender<DashEvent>>,
    ) -> anyhow::Result<Self> {
        let base_url = cfg.base_url.trim_end_matches('/').to_string();
        let (secrets, ag_accounts) = match cfg.kind {
            ProviderKind::OpenaiCompat | ProviderKind::Gemini => {
                anyhow::ensure!(
                    !cfg.keys.is_empty(),
                    "provider '{}': no keys configured",
                    cfg.name
                );
                anyhow::ensure!(
                    !base_url.is_empty(),
                    "provider '{}': base_url is required",
                    cfg.name
                );
                (cfg.keys.clone(), Vec::new())
            }
            ProviderKind::Antigravity => {
                anyhow::ensure!(
                    !cfg.accounts.is_empty(),
                    "provider '{}': no accounts configured (run `anyhop auth antigravity`)",
                    cfg.name
                );
                let accounts: Vec<Arc<Account>> = cfg
                    .accounts
                    .iter()
                    .map(|a| Account::new(a, &cfg.name, storage))
                    .map(Arc::new)
                    .collect();
                let secrets: Vec<String> =
                    accounts.iter().map(|a| a.pool_secret().to_string()).collect();
                (secrets, accounts)
            }
        };
        let base_url = if base_url.is_empty() {
            antigravity::DAILY_ENDPOINT.to_string()
        } else {
            base_url
        };
        Ok(Self {
            name: cfg.name.clone(),
            kind: cfg.kind,
            strategy: cfg.strategy,
            base_url,
            pool: KeyPool::new(
                cfg.name.clone(),
                secrets,
                cfg.strategy,
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
            models_cache: Mutex::new(None),
        })
    }

    /// Find the OAuth account behind a pool key (antigravity only).
    pub fn ag_account(&self, secret: &str) -> Option<Arc<Account>> {
        self.ag_accounts
            .iter()
            .find(|a| a.pool_secret() == secret)
            .cloned()
    }

    /// Configured models, or a dynamically fetched list for antigravity
    /// (cached for 10 minutes).
    pub async fn effective_models(&self, http: &reqwest::Client) -> Vec<String> {
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
        let Some(key) = self.pool.pick() else {
            return Vec::new();
        };
        let Some(acc) = self.ag_account(&key.secret) else {
            return Vec::new();
        };
        let Ok(token) = acc.ensure_access_token(http).await else {
            return Vec::new();
        };
        match antigravity::fetch_available_models(http, &self.base_url, &token).await {
            Ok(list) if !list.is_empty() => {
                let mut cache = self.models_cache.lock().unwrap();
                *cache = Some((Instant::now(), list.clone()));
                list
            }
            _ => Vec::new(),
        }
    }
}

/// Resolves incoming model names to providers.
pub struct ProviderRouter {
    pub providers: Vec<Provider>,
}

impl ProviderRouter {
    /// `model` may be "provider/upstream-model" (explicit) or a bare model name
    /// matched against each provider's model list (empty list = wildcard).
    /// Returns (provider, upstream_model_name).
    pub fn resolve<'a>(&'a self, model: &str) -> Option<(&'a Provider, String)> {
        if let Some((prefix, rest)) = model.split_once('/')
            && let Some(p) = self.providers.iter().find(|p| p.name == prefix)
        {
            return Some((p, rest.to_string()));
        }
        self.providers
            .iter()
            .find(|p| p.models.is_empty() || p.models.iter().any(|m| m == model))
            .map(|p| (p, model.to_string()))
    }
}
