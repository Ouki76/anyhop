//! JSON management API — always enabled, the dashboard is just a client of it.
//!
//! GET  /api/providers             providers + key snapshots
//! GET  /api/quotas                per-account model quotas (antigravity)
//! GET  /api/requests              recent upstream attempts
//! GET  /api/events                SSE stream of failover events (JSON)
//! POST /api/keys/enable|disable   {provider, id}
//! POST /api/keys/add              {provider, secret}
//! POST /api/providers/add         {kind, name?, base_url?, key?}
//! POST /api/providers/update      {name, base_url?, strategy?, max_concurrent?, …}
//! POST /api/providers/delete      {name}
//! GET  /api/combos                virtual models + chains
//! GET  /api/server                [server] settings (secrets reported as "is set")
//! POST /api/server/update         partial update of [server]
//! POST /api/combos/add|update|delete  {name, chain}
//! GET  /api/client-keys           list client API keys
//! POST /api/client-keys/add       {name?, key?, models}
//! POST /api/client-keys/update    {key, name?, models}
//! POST /api/client-keys/delete    {key}
//! GET  /api/models                models with enabled flag
//! POST /api/models/refresh        re-fetch model lists from all providers
//! POST /api/models/enable|disable|toggle  {model}
//! POST /api/models/enable-all|disable-all
//! GET|POST /api/models/limits     per-model context window / token caps (null clears)
//! GET|PUT /api/config             raw TOML read / validate+write+reload
//! POST /api/reload                re-read config from disk
//! POST /api/auth/start            {kind: antigravity|codex} OAuth onboarding
//! GET  /api/auth/status           OAuth flow status
//! GET  /metrics                   Prometheus text exposition (admin auth)
//!
//! Gateway surface (not here): POST /v1/chat/completions, /v1/embeddings,
//! /v1/fim/completions, GET /v1/models.

use axum::http::StatusCode;

pub mod auth;
pub mod client_keys;
pub mod combos;
pub mod config_mgmt;
pub mod errors;
pub mod histograms;
pub mod metrics;
pub mod models;
pub mod persist;
pub mod provider_keys;
pub mod providers;
pub mod server;

pub use auth::*;
pub use client_keys::*;
pub use combos::*;
pub use config_mgmt::*;
pub use errors::{ApiError, ApiResult, ok_json};
pub use metrics::*;
pub use models::*;
pub use provider_keys::*;
pub use providers::*;
pub use server::*;

/// Hide `user:pass@` inside a proxy URL before it leaves the server.
///
/// Proxies are frequently written as `http://user:pass@host:port` in the config;
/// the dashboard only needs to show *that* a proxy is set, and the edit form must
/// not round-trip the credentials back to the browser (or into a screenshot).
pub(crate) fn mask_proxy(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://***:***@{host}{}", &rest[authority_end..]),
        None => url.to_string(),
    }
}

/// Names end up in model ids (`provider/model`), config keys and log lines, so
/// they are restricted to a short, safe alphabet. Bounding the length matters:
/// without it a 70 KB "name" is happily written into anyhop.toml.
pub(crate) fn validate_name(kind: &str, name: &str) -> Result<(), (StatusCode, String)> {
    let n = name.trim();
    if n.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{kind} name must not be empty"),
        ));
    }
    if n.chars().count() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{kind} name must be at most 64 characters"),
        ));
    }
    if let Some(bad) = n
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "{kind} name may only contain letters, digits, '-', '_' and '.' (found '{bad}')"
            ),
        ));
    }
    Ok(())
}

/// Guard against multi-megabyte secrets and URLs in the config file.
pub(crate) fn validate_secret_len(kind: &str, value: &str) -> Result<(), (StatusCode, String)> {
    if value.len() > 8192 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{kind} must be at most 8192 characters"),
        ));
    }
    Ok(())
}

/// A masked value sent back by a form means "unchanged".
pub(crate) fn is_masked(value: &str) -> bool {
    value.contains("***")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_credentials_are_masked() {
        assert_eq!(
            mask_proxy("http://user:secret@10.0.0.1:3128"),
            "http://***:***@10.0.0.1:3128"
        );
        assert_eq!(
            mask_proxy("socks5://alice:p@ss@host.example:1080"),
            "socks5://***:***@host.example:1080"
        );
        // Nothing to hide: returned untouched.
        for plain in ["socks5://127.0.0.1:1080", "http://proxy.internal:3128"] {
            assert_eq!(mask_proxy(plain), plain);
        }
        // Not a URL at all — leave it alone rather than mangling it.
        assert_eq!(mask_proxy("host:3128"), "host:3128");
    }

    #[test]
    fn masked_values_are_detected() {
        assert!(is_masked("http://***:***@host:1"));
        assert!(!is_masked("http://user:pw@host:1"));
        assert!(!is_masked(""));
    }

    #[test]
    fn masking_survives_a_path_suffix() {
        assert_eq!(
            mask_proxy("http://u:p@h:1/some?q=1"),
            "http://***:***@h:1/some?q=1"
        );
    }
}
