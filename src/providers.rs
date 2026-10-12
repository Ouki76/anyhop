use crate::config::{ProviderConfig, ProviderKind};
use crate::pool::KeyPool;

pub struct Provider {
    pub name: String,
    #[allow(dead_code)]
    pub kind: ProviderKind,
    pub base_url: String,
    pub pool: KeyPool,
    pub models: Vec<String>,
    pub extra_headers: Vec<(String, String)>,
}

impl Provider {
    pub fn from_config(cfg: &ProviderConfig) -> anyhow::Result<Self> {
        match cfg.kind {
            ProviderKind::OpenaiCompat => {}
            ProviderKind::Gemini => {}
        }
        anyhow::ensure!(
            !cfg.keys.is_empty(),
            "provider '{}': no keys configured",
            cfg.name
        );
        Ok(Self {
            name: cfg.name.clone(),
            kind: cfg.kind,
            base_url: cfg.base_url.trim_end_matches('/').to_string(),
            pool: KeyPool::new(cfg.keys.clone(), cfg.strategy),
            models: cfg.models.clone(),
            extra_headers: cfg
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
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
