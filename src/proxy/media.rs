//! Image and audio pass-through endpoints:
//!
//! | route                        | upstream path             | body      |
//! |------------------------------|---------------------------|-----------|
//! | `POST /v1/images/generations`| `/images/generations`     | JSON      |
//! | `POST /v1/images/edits`      | `/images/edits`           | multipart |
//! | `POST /v1/audio/speech`      | `/audio/speech`           | JSON      |
//! | `POST /v1/audio/transcriptions` | `/audio/transcriptions`| multipart |
//! | `POST /v1/audio/translations`| `/audio/translations`     | multipart |
//!
//! Everything here is a relay: the request is forwarded byte-for-byte (the only
//! mutation is splicing the upstream model name into the existing `model`
//! value) and the response keeps the upstream status, content-type and body.
//! That is deliberate — images and audio are binary or streamed, so parsing them
//! into a `serde_json::Value` (what `embeddings.rs` does for Gemini) would
//! corrupt them, and re-encoding a multipart body would drop parts we do not
//! model (`n`, `size`, repeated `image[]`, …).
//!
//! # Why capability gating is explicit
//!
//! Chat routing accepts any provider that lists a model, or any wildcard
//! provider. Reusing that rule here would let an image request be sent to a
//! chat-only provider that happens to share the model list: it would either fail
//! upstream (after putting a healthy key in cooldown) or, worse, succeed against
//! a model that means something else there. So a provider only receives image
//! or audio traffic when its config *declares* the capability
//! (`capabilities = ["images"]` on an `openai_compat` provider, validated in
//! `config::Config::validate`). A request with no such provider is refused with
//! `400 unsupported_capability` instead of being silently mis-routed.

use std::collections::HashSet;
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, Bytes};
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use futures::StreamExt;

use crate::config::ComboConfig;
use crate::pool::{FailKind, KeyGuard, KeyState};
use crate::providers::{Provider, ProviderRouter};

use super::access::{combo_allowed, model_allowed, model_disabled};
use super::{AppState, KeyPermissions, error_response};

// ---------- handlers ----------

/// `POST /v1/images/generations` — JSON body, `model` required.
pub async fn images_generations(
    State(state): State<Arc<AppState>>,
    key_perm: Option<Extension<KeyPermissions>>,
    body: Bytes,
) -> Response {
    json_request(state, key_perm, body, Endpoint::IMAGES_GENERATIONS).await
}

/// `POST /v1/images/edits` — multipart/form-data, forwarded as-is.
pub async fn images_edits(
    State(state): State<Arc<AppState>>,
    key_perm: Option<Extension<KeyPermissions>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    multipart_request(state, key_perm, &headers, body, Endpoint::IMAGES_EDITS).await
}

/// `POST /v1/audio/speech` — JSON body (TTS), `model` required.
pub async fn audio_speech(
    State(state): State<Arc<AppState>>,
    key_perm: Option<Extension<KeyPermissions>>,
    body: Bytes,
) -> Response {
    json_request(state, key_perm, body, Endpoint::AUDIO_SPEECH).await
}

/// `POST /v1/audio/transcriptions` — multipart/form-data, forwarded as-is.
pub async fn audio_transcriptions(
    State(state): State<Arc<AppState>>,
    key_perm: Option<Extension<KeyPermissions>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    multipart_request(
        state,
        key_perm,
        &headers,
        body,
        Endpoint::AUDIO_TRANSCRIPTIONS,
    )
    .await
}

/// `POST /v1/audio/translations` — multipart/form-data, forwarded as-is.
pub async fn audio_translations(
    State(state): State<Arc<AppState>>,
    key_perm: Option<Extension<KeyPermissions>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    multipart_request(
        state,
        key_perm,
        &headers,
        body,
        Endpoint::AUDIO_TRANSLATIONS,
    )
    .await
}

// ---------- endpoint table ----------

/// Which kind of provider declaration an endpoint needs.
///
/// A separate type (instead of a `&str`) so the mapping "endpoint → capability"
/// exists exactly once and the error messages cannot drift from the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Capability {
    Images,
    Audio,
}

impl Capability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Images => "images",
            Self::Audio => "audio",
        }
    }

    /// The exact config snippet that enables this capability.
    ///
    /// Quoted verbatim into the 400 body: "it does not work" is not actionable,
    /// "add this line" is.
    fn enable_hint(self) -> String {
        format!("capabilities = [\"{}\"]", self.as_str())
    }
}

/// One pass-through endpoint: where it goes upstream and what it needs.
#[derive(Clone, Copy, Debug)]
struct Endpoint {
    /// Path appended to the provider `base_url` (already slash-trimmed).
    path: &'static str,
    capability: Capability,
}

impl Endpoint {
    const IMAGES_GENERATIONS: Self = Self {
        path: "/images/generations",
        capability: Capability::Images,
    };
    const IMAGES_EDITS: Self = Self {
        path: "/images/edits",
        capability: Capability::Images,
    };
    const AUDIO_SPEECH: Self = Self {
        path: "/audio/speech",
        capability: Capability::Audio,
    };
    const AUDIO_TRANSCRIPTIONS: Self = Self {
        path: "/audio/transcriptions",
        capability: Capability::Audio,
    };
    const AUDIO_TRANSLATIONS: Self = Self {
        path: "/audio/translations",
        capability: Capability::Audio,
    };

    /// `images/generations` — used in log/error messages.
    fn label(self) -> &'static str {
        self.path.trim_start_matches('/')
    }
}

// ---------- request extraction ----------

/// A media request, reduced to what the relay needs.
struct MediaRequest {
    /// Model id exactly as the client wrote it (`provider/model`, combo, bare).
    model: String,
    /// Span of that id inside `body`, so it can be spliced in place.
    model_span: Range<usize>,
    /// Raw request bytes: forwarded untouched apart from the model splice.
    body: Bytes,
    /// Incoming multipart content-type (boundary included); `None` = JSON.
    content_type: Option<String>,
}

/// Extract the model from a JSON body and relay.
async fn json_request(
    state: Arc<AppState>,
    key_perm: Option<Extension<KeyPermissions>>,
    body: Bytes,
    endpoint: Endpoint,
) -> Response {
    // Only `model` is needed to route; the rest is forwarded verbatim.
    let Some(span) = crate::scan::string_field_span(&body, b"model") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing or invalid 'model' field",
            "invalid_request_error",
        );
    };
    let model = String::from_utf8_lossy(&body[span.clone()]).into_owned();
    if model.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing or invalid 'model' field",
            "invalid_request_error",
        );
    }
    let request = MediaRequest {
        model,
        model_span: span,
        body,
        content_type: None,
    };
    forward(state, key_perm, request, endpoint).await
}

/// Extract the model from a `multipart/form-data` body and relay.
async fn multipart_request(
    state: Arc<AppState>,
    key_perm: Option<Extension<KeyPermissions>>,
    headers: &HeaderMap,
    body: Bytes,
    endpoint: Endpoint,
) -> Response {
    // The boundary lives in the incoming content-type and is forwarded with the
    // body: generating a new one would mean re-encoding the form.
    let Some(content_type) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "multipart request requires a Content-Type header with the form boundary",
            "invalid_request_error",
        );
    };
    if !content_type
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("multipart/form-data")
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "{} expects multipart/form-data, got '{content_type}'",
                endpoint.label()
            ),
            "invalid_request_error",
        );
    }
    let Some(span) = multipart_field_span(&body, "model") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing 'model' field (send it as a multipart form field)",
            "invalid_request_error",
        );
    };
    // Nothing constrains a form value the way JSON does, and the value is spliced
    // back into the forwarded body — reject anything that is not a plausible id.
    let Ok(model) = std::str::from_utf8(&body[span.clone()]) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the 'model' form field must be valid UTF-8",
            "invalid_request_error",
        );
    };
    if model.is_empty() || model.len() > 200 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "missing or invalid 'model' form field",
            "invalid_request_error",
        );
    }
    let request = MediaRequest {
        model: model.to_string(),
        model_span: span,
        body,
        content_type: Some(content_type.to_string()),
    };
    forward(state, key_perm, request, endpoint).await
}

// ---------- routing ----------

/// The outcome of resolving a model for a media endpoint.
enum Plan<'a> {
    /// Explicit `provider/model`, or a bare model with exactly one match.
    One(&'a Provider, String),
    /// A combo, already restricted to targets that declare the capability.
    Chain(Vec<(&'a Provider, String)>),
}

/// A routing refusal, rendered as the gateway's JSON error envelope.
///
/// Not an [`crate::api::ApiError`] on purpose: that type derives its `type` from
/// the status, and `unsupported_capability` / `model_not_found` /
/// `model_not_allowed` are the vocabulary chat already ships (clients branch on
/// them), so the envelope is built with [`error_response`] like `chat` and
/// `embeddings` do.
#[derive(Debug)]
struct Reject {
    status: StatusCode,
    message: String,
    kind: &'static str,
}

impl Reject {
    fn into_response(self) -> Response {
        error_response(self.status, self.message, self.kind)
    }

    /// 404 — same wording as chat, so a client sees one vocabulary.
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
            kind: "model_not_found",
        }
    }

    /// 403 — the client key may not use this model.
    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
            kind: "model_not_allowed",
        }
    }

    /// 400 — nothing can serve this endpoint because no provider declares it.
    fn unsupported(message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
            kind: "unsupported_capability",
        }
    }

    fn unsupported_provider(cap: Capability, provider: &Provider) -> Self {
        Self::unsupported(format!(
            "provider '{}' does not declare the '{}' capability, so it cannot serve this endpoint; \
             add {} to it in the config to enable it",
            provider.name,
            cap.as_str(),
            cap.enable_hint()
        ))
    }

    fn unsupported_model(cap: Capability, model: &str, served_by: &[&str]) -> Self {
        let detail = match served_by {
            [] => format!("model '{model}' is not served by any provider"),
            [only] => format!("model '{model}' is served by {only}, which does not declare"),
            many => format!(
                "model '{model}' is served by {}, none of which declares",
                many.join(", ")
            ),
        };
        Self::unsupported(format!(
            "{detail} the '{}' capability; add {} to an openai_compat provider that serves it",
            cap.as_str(),
            cap.enable_hint()
        ))
    }

    fn unsupported_combo(cap: Capability, model: &str, targets: &[(&Provider, String)]) -> Self {
        let listed: Vec<String> = targets
            .iter()
            .map(|(p, m)| format!("{}/{}", p.name, m))
            .collect();
        let detail = if listed.is_empty() {
            "it has no resolvable target".to_string()
        } else {
            format!("its targets are {}", listed.join(", "))
        };
        Self::unsupported(format!(
            "combo '{model}' has no target that declares the '{}' capability ({detail}); \
             add {} to one of those providers",
            cap.as_str(),
            cap.enable_hint()
        ))
    }

    /// 400 — several capable providers would accept the same bare model.
    fn ambiguous(cap: Capability, model: &str, candidates: &[String]) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "model '{model}' matches {} providers that declare the '{}' capability ({}); \
                 request '<provider>/{model}' to disambiguate",
                candidates.len(),
                cap.as_str(),
                candidates.join(", ")
            ),
            kind: "invalid_request_error",
        }
    }
}

/// Resolve `model` to target(s) for `cap`, capability-aware.
///
/// Resolution order mirrors [`ProviderRouter::resolve`] (combo first, then
/// `provider/model`, then a bare model), but every candidate must declare `cap`.
fn plan<'a>(router: &'a ProviderRouter, model: &str, cap: Capability) -> Result<Plan<'a>, Reject> {
    // A combo name shadows a model of the same name (documented on
    // `ProviderRouter::resolve`) and `combo/x` is always a combo.
    let combo_name = model.strip_prefix("combo/").unwrap_or(model);
    if let Some(combo) = router.combos.iter().find(|c| c.name == combo_name) {
        return chain_for_combo(router, combo, model, cap);
    }

    if let Some((prefix, rest)) = model.split_once('/')
        && let Some(provider) = router.providers.iter().find(|p| p.name == prefix)
    {
        if !provider.has_capability(cap.as_str()) {
            return Err(Reject::unsupported_provider(cap, provider));
        }
        return Ok(Plan::One(provider, rest.to_string()));
    }

    bare(&router.providers, model, cap).map(|(p, m)| Plan::One(p, m))
}

/// Expand a combo into the targets that declare `cap`.
///
/// Only the first *capable* target is guaranteed to be tried; the rest stay in
/// the chain as fallbacks, exactly like `embeddings.rs` does for its own
/// provider filter.
fn chain_for_combo<'a>(
    router: &'a ProviderRouter,
    combo: &ComboConfig,
    model: &str,
    cap: Capability,
) -> Result<Plan<'a>, Reject> {
    let all = combo_targets(router, combo);
    let capable: Vec<(&Provider, String)> = all
        .iter()
        .filter(|(p, _)| p.has_capability(cap.as_str()))
        .map(|(p, m)| (*p, m.clone()))
        .collect();
    if capable.is_empty() {
        return Err(Reject::unsupported_combo(cap, model, &all));
    }
    Ok(Plan::Chain(capable))
}

/// Resolve every chain entry of a combo, skipping unknown providers.
fn combo_targets<'a>(
    router: &'a ProviderRouter,
    combo: &ComboConfig,
) -> Vec<(&'a Provider, String)> {
    let mut out = Vec::new();
    for entry in &combo.chain {
        match entry.split_once('/') {
            Some((prefix, rest)) => match router.providers.iter().find(|p| p.name == prefix) {
                Some(provider) => out.push((provider, rest.to_string())),
                // Same rule as `ProviderRouter::resolve`: an unknown prefix is a
                // config error, and falling through to a wildcard provider would
                // route a garbage model id there.
                None => tracing::warn!(
                    combo = %combo.name, entry = %entry,
                    "combo chain entry references an unknown provider — skipped"
                ),
            },
            // Bare entry: the first provider that lists it, else the first
            // wildcard one (`resolve_single` order).
            None => {
                let listed = router
                    .providers
                    .iter()
                    .find(|p| serves(p, entry) == Some(true));
                let any =
                    listed.or_else(|| router.providers.iter().find(|p| serves(p, entry).is_some()));
                if let Some(provider) = any {
                    out.push((provider, entry.to_string()));
                }
            }
        }
    }
    out
}

/// Resolve a bare model among the providers that declare `cap`.
///
/// Strict by design: an ambiguous name is a 400 listing the candidates instead
/// of an arbitrary pick, because guessing wrong on an image/audio endpoint means
/// a 404 from upstream (or a different model than the caller meant).
fn bare<'a>(
    providers: &'a [Provider],
    model: &str,
    cap: Capability,
) -> Result<(&'a Provider, String), Reject> {
    let servable: Vec<(&Provider, bool)> = providers
        .iter()
        .filter_map(|p| serves(p, model).map(|explicit| (p, explicit)))
        .collect();
    if servable.is_empty() {
        return Err(Reject::not_found(format!(
            "no provider serves model '{model}'"
        )));
    }

    let capable: Vec<(&Provider, bool)> = servable
        .iter()
        .filter(|(p, _)| p.has_capability(cap.as_str()))
        .copied()
        .collect();
    if capable.is_empty() {
        let names: Vec<&str> = servable.iter().map(|(p, _)| p.name.as_str()).collect();
        return Err(Reject::unsupported_model(cap, model, &names));
    }

    // An explicit model list beats a wildcard provider — the priority
    // `ProviderRouter::resolve_single` uses — so a dedicated image provider does
    // not lose to a catch-all chat provider.
    let (explicit, wildcard): (Vec<_>, Vec<_>) =
        capable.into_iter().partition(|(_, explicit)| *explicit);
    let candidates = if explicit.is_empty() {
        wildcard
    } else {
        explicit
    };
    match candidates.as_slice() {
        [(provider, _)] => Ok((*provider, model.to_string())),
        [] => Err(Reject::unsupported_model(cap, model, &[])),
        many => {
            let listed: Vec<String> = many
                .iter()
                .map(|(p, _)| format!("{}/{}", p.name, model))
                .collect();
            Err(Reject::ambiguous(cap, model, &listed))
        }
    }
}

/// Whether `p` would accept `model`: `Some(true)` when the model is in its
/// configured list, `Some(false)` when it is a wildcard (empty list = any model),
/// `None` when it plainly cannot serve it.
///
/// Only the static list is consulted. The cached list is populated by a network
/// refresh, and routing an image request must never trigger one.
fn serves(p: &Provider, model: &str) -> Option<bool> {
    if p.models.iter().any(|m| m == model) {
        Some(true)
    } else if p.models.is_empty() {
        Some(false)
    } else {
        None
    }
}

/// Apply the same policy checks as chat: `disabled_models` first (404), then the
/// client-key allowlist (403), with chat's exact messages.
fn authorize<'a>(
    plan: Plan<'a>,
    model: &str,
    cap: Capability,
    key_models: Option<&[String]>,
    disabled: &HashSet<String>,
) -> Result<Vec<(&'a Provider, String)>, Reject> {
    match plan {
        Plan::One(provider, upstream) => {
            let canonical = format!("{}/{}", provider.name, upstream);
            if model_disabled(disabled, model, &canonical, &upstream) {
                return Err(Reject::not_found(format!("model '{model}' is disabled")));
            }
            if let Some(allowed) = key_models
                && !model_allowed(allowed, model, &canonical, &upstream)
            {
                return Err(Reject::forbidden(format!(
                    "model '{model}' is not allowed for this API key"
                )));
            }
            Ok(vec![(provider, upstream)])
        }
        Plan::Chain(targets) => {
            // The requested name may be bare (disabled) or "combo/name".
            let bare = model.strip_prefix("combo/").unwrap_or(model);
            if disabled.contains(model) || disabled.contains(bare) {
                return Err(Reject::not_found(format!("model '{model}' is disabled")));
            }
            if let Some(allowed) = key_models
                && !combo_allowed(allowed, model)
            {
                return Err(Reject::forbidden(format!(
                    "model '{model}' is not allowed for this API key"
                )));
            }
            let active: Vec<(&Provider, String)> = targets
                .into_iter()
                .filter(|(p, m)| {
                    !disabled.contains(&format!("{}/{}", p.name, m))
                        && !disabled.contains(m.as_str())
                })
                .collect();
            if active.is_empty() {
                // Mention the capability: some targets were dropped before this
                // check, so "disabled" alone would be misleading.
                return Err(Reject::not_found(format!(
                    "all targets in combo '{model}' are disabled or lack the '{}' capability",
                    cap.as_str()
                )));
            }
            Ok(active)
        }
    }
}

// ---------- relay ----------

/// Forward one media request, with key rotation and the chat-style retry rules.
async fn forward(
    state: Arc<AppState>,
    key_perm: Option<Extension<KeyPermissions>>,
    request: MediaRequest,
    endpoint: Endpoint,
) -> Response {
    let key_models = key_perm
        .as_ref()
        .and_then(|e| e.0.allowed_models.as_deref());
    let client_key_owned = key_perm.as_ref().and_then(|e| e.0.key_name.clone());
    let client_key = client_key_owned.as_deref();

    let router = state.router.load();
    let planned = match plan(&router, &request.model, endpoint.capability) {
        Ok(plan) => plan,
        Err(reject) => return reject.into_response(),
    };
    let is_combo = matches!(planned, Plan::Chain(_));
    let targets = {
        let disabled = state
            .disabled_models
            .read()
            .unwrap_or_else(|e| e.into_inner());
        match authorize(
            planned,
            &request.model,
            endpoint.capability,
            key_models,
            &disabled,
        ) {
            Ok(targets) => targets,
            Err(reject) => return reject.into_response(),
        }
    };

    let max_attempts = state.rt().max_retries;
    let mut attempts = 0usize;
    for (provider, upstream_model) in &targets {
        // Per-provider overrides win over the global budget (same as chat).
        let budget = if provider.max_retries > 0 {
            provider.max_retries
        } else {
            max_attempts
        };
        for _ in 0..budget.max(1) {
            attempts += 1;
            let Some(key) = provider.pool.pick(upstream_model, None) else {
                break; // pool exhausted for this model — try the next target
            };
            let Some(guard) = key.try_acquire() else {
                continue; // saturated: try another key without penalising this one
            };

            let body = splice_model(&request.body, &request.model_span, upstream_model);
            let mut request_builder = provider
                .client
                .post(format!("{}{}", provider.base_url, endpoint.path));
            request_builder = match &request.content_type {
                // The boundary is part of the header, and must survive verbatim.
                Some(content_type) => {
                    request_builder.header(header::CONTENT_TYPE, content_type.as_str())
                }
                None => request_builder.header(header::CONTENT_TYPE, "application/json"),
            };
            let mut req = request_builder.bearer_auth(&key.secret).body(body);
            for (name, value) in &provider.extra_headers {
                req = req.header(name, value);
            }

            let started = Instant::now();
            let resp = match tokio::time::timeout(provider.timeout, req.send()).await {
                Err(_) => {
                    drop(guard);
                    provider
                        .pool
                        .report_failure(&key, FailKind::Network, upstream_model);
                    tracing::warn!(provider = %provider.name, key = %key.masked(), "media: attempt timed out");
                    log_attempt(
                        &state,
                        provider,
                        upstream_model,
                        &key,
                        started,
                        "timeout",
                        client_key,
                    );
                    continue;
                }
                Ok(Err(e)) => {
                    drop(guard);
                    provider
                        .pool
                        .report_failure(&key, FailKind::Network, upstream_model);
                    tracing::warn!(provider = %provider.name, key = %key.masked(), error = %e, "media: network error");
                    log_attempt(
                        &state,
                        provider,
                        upstream_model,
                        &key,
                        started,
                        "network",
                        client_key,
                    );
                    continue;
                }
                Ok(Ok(resp)) => resp,
            };

            let status = resp.status();
            if status.is_success() {
                provider.pool.report_success(&key);
                log_attempt(
                    &state,
                    provider,
                    upstream_model,
                    &key,
                    started,
                    status.as_str(),
                    client_key,
                );
                // The guard rides along in the stream: the key keeps its
                // in-flight slot until the client has the whole payload.
                return relay_upstream(resp, guard);
            }

            // Failure: classify exactly like chat so key health stays consistent.
            let retry_after_secs = resp
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            log_attempt(
                &state,
                provider,
                upstream_model,
                &key,
                started,
                status.as_str(),
                client_key,
            );

            match status.as_u16() {
                429 => {
                    provider.pool.report_failure(
                        &key,
                        FailKind::RateLimited { retry_after_secs },
                        upstream_model,
                    );
                }
                401 | 403 => {
                    provider
                        .pool
                        .report_failure(&key, FailKind::Auth, upstream_model);
                }
                code if code >= 500 => {
                    provider
                        .pool
                        .report_failure(&key, FailKind::Server, upstream_model);
                }
                _ => {
                    // The caller's problem (400/404/413/…): relay the upstream
                    // body untouched instead of burning keys on retries. It is
                    // usually a JSON error with a precise message.
                    return relay_upstream(resp, guard);
                }
            }
            drop(guard);
        }
    }

    let mut resp = if is_combo {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "combo '{}': all {} target(s) exhausted for {}",
                request.model,
                targets.len(),
                endpoint.label()
            ),
            "provider_unavailable",
        )
    } else {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "no available key could serve '{}' for {} after {attempts} attempt(s)",
                request.model,
                endpoint.label()
            ),
            "provider_unavailable",
        )
    };
    // Tell the client when retrying is worth it: without this a single-key
    // provider in a short cooldown looks permanently down.
    if let Some((provider, upstream_model)) = targets.first()
        && let Some(wait) = provider.pool.wake_after(upstream_model)
        && let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string())
    {
        resp.headers_mut().insert(header::RETRY_AFTER, value);
    }
    resp
}

/// Upstream headers worth relaying. An allowlist, not a copy: hop-by-hop
/// headers (content-length, transfer-encoding, connection) describe the upstream
/// framing, not ours.
fn forward_header(name: &HeaderName) -> bool {
    matches!(
        *name,
        header::CONTENT_TYPE | header::CACHE_CONTROL | header::ETAG | header::RETRY_AFTER
    ) || name.as_str().starts_with("x-ratelimit-")
        || name.as_str() == "x-request-id"
}

/// Relay an upstream response: status and content-type as received, body streamed
/// without buffering (a 20 MiB image or a long TTS clip must not be copied into
/// memory just to be handed to the client).
fn relay_upstream(resp: reqwest::Response, guard: KeyGuard) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let headers: Vec<(HeaderName, HeaderValue)> = resp
        .headers()
        .iter()
        .filter(|(name, _)| forward_header(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let stream = resp.bytes_stream().map(move |chunk| {
        let _ = &guard;
        chunk.map_err(|e| std::io::Error::other(format!("upstream stream error: {e}")))
    });
    relay(status, headers, Body::from_stream(stream))
}

/// Build a response with an exact status, a fixed header list and a raw body.
///
/// Kept separate from [`relay_upstream`] so the "status + content-type + bytes
/// are relayed verbatim" rule is unit-testable without an upstream.
fn relay(status: StatusCode, headers: Vec<(HeaderName, HeaderValue)>, body: Body) -> Response {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(body).unwrap_or_else(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot build the upstream response",
            "internal_error",
        )
    })
}

// ---------- body helpers ----------

/// Replace the model value inside the raw body, in place.
///
/// `Bytes::clone` is a refcount bump, so when the client already sent the
/// upstream name (the common case) this costs nothing; otherwise it is one
/// allocation and two memcpys. A JSON round-trip would reformat the body and
/// drop keys we do not know about — exactly what a pass-through must not do.
fn splice_model(body: &Bytes, span: &Range<usize>, model: &str) -> Bytes {
    if body.get(span.clone()) == Some(model.as_bytes()) {
        return body.clone();
    }
    let mut out = Vec::with_capacity(body.len() - span.len() + model.len());
    out.extend_from_slice(&body[..span.start]);
    out.extend_from_slice(model.as_bytes());
    out.extend_from_slice(&body[span.end..]);
    Bytes::from(out)
}

/// Span of a multipart form value, e.g. `name="model"`.
///
/// The form is never parsed into parts nor re-encoded — that would drop fields
/// this module does not model (`n`, `size`, repeated `image[]` parts, provider
/// specific options) and invent a new boundary. Locating the value's byte span is
/// enough to splice the upstream model name in.
fn multipart_field_span(body: &[u8], field: &str) -> Option<Range<usize>> {
    let needle = format!("name=\"{field}\"");
    let mut from = 0usize;
    while let Some(offset) = memchr::memmem::find(&body[from..], needle.as_bytes()) {
        let at = from + offset;
        // `filename="model"` also contains `name="model"` (after "file"), so the
        // preceding byte must not be part of an identifier.
        let standalone = at == 0
            || !matches!(
                body[at - 1],
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'
            );
        // …and the match must sit in a `Content-Disposition` header line, not in
        // the *value* of another part (a prompt may quote `name="model"`).
        let line_start = body[..at]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        let line = &body[line_start..at];
        let in_disposition = {
            const DISPOSITION: &[u8] = b"content-disposition";
            line.len() >= DISPOSITION.len()
                && line
                    .windows(DISPOSITION.len())
                    .any(|w| w.eq_ignore_ascii_case(DISPOSITION))
        };
        if standalone && in_disposition {
            // Part headers end at the first empty line; the value follows it and
            // runs until the next CRLF (which begins the boundary).
            let after = at + needle.len();
            let sep = memchr::memmem::find(&body[after..], b"\r\n\r\n")?;
            let start = after + sep + 4;
            let end = memchr::memmem::find(&body[start..], b"\r\n").map(|i| start + i)?;
            let value = trim_span(&body[start..end]);
            return Some(start + value.start..start + value.end);
        }
        from = at + 1;
    }
    None
}

/// Trim ASCII whitespace (browsers/paste tools add some), keeping it a span.
fn trim_span(value: &[u8]) -> Range<usize> {
    let start = value
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    if end <= start {
        start..start
    } else {
        start..end
    }
}

/// One attempted upstream call, recorded in the Requests tab.
fn log_attempt(
    state: &AppState,
    provider: &Provider,
    model: &str,
    key: &KeyState,
    started: Instant,
    status: &str,
    client_key: Option<&str>,
) {
    state.log_request(crate::events::RequestRecord {
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        provider: provider.name.clone(),
        model: model.to_string(),
        key: key.masked(),
        status: status.to_string(),
        latency_ms: started.elapsed().as_millis() as u64,
        // Never streaming to the client in the SSE sense: the body is relayed as
        // one payload, so the Requests tab must not show it as a stream.
        stream: false,
        client_key: client_key.map(str::to_string),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProviderConfig, Tuning};
    use std::time::Duration;

    const IMAGE_PROVIDER: &str = r#"
        name = "images"
        type = "openai_compat"
        base_url = "http://127.0.0.1:1/v1"
        keys = ["sk-images"]
        models = ["gpt-image-1"]
        capabilities = ["images"]
    "#;

    const SECOND_IMAGE_PROVIDER: &str = r#"
        name = "images2"
        type = "openai_compat"
        base_url = "http://127.0.0.1:2/v1"
        keys = ["sk-images2"]
        models = ["gpt-image-1"]
        capabilities = ["images"]
    "#;

    /// Declares the capability but lists no models: a wildcard for images.
    const WILDCARD_IMAGE_PROVIDER: &str = r#"
        name = "anyimage"
        type = "openai_compat"
        base_url = "http://127.0.0.1:3/v1"
        keys = ["sk-any"]
        capabilities = ["images"]
    "#;

    /// Chat-only provider that happens to list the same image model.
    const CHAT_PROVIDER: &str = r#"
        name = "chat"
        type = "openai_compat"
        base_url = "http://127.0.0.1:4/v1"
        keys = ["sk-chat"]
        models = ["gpt-image-1", "gpt-4o"]
    "#;

    const AUDIO_PROVIDER: &str = r#"
        name = "speech"
        type = "openai_compat"
        base_url = "http://127.0.0.1:5/v1"
        keys = ["sk-speech"]
        models = ["tts-1", "whisper-1"]
        capabilities = ["audio"]
    "#;

    fn provider(source: &str) -> Provider {
        let cfg: ProviderConfig = toml::from_str(source).expect("test provider config");
        Provider::from_config(
            &cfg,
            None,
            None,
            None,
            Arc::new(Tuning::default()),
            Duration::from_secs(30),
            2,
        )
        .expect("provider builds offline")
    }

    fn router(providers: Vec<Provider>, combos: &[(&str, &[&str])]) -> ProviderRouter {
        ProviderRouter {
            providers,
            combos: combos
                .iter()
                .map(|(name, chain)| ComboConfig {
                    name: (*name).to_string(),
                    chain: chain.iter().map(|c| (*c).to_string()).collect(),
                })
                .collect(),
        }
    }

    fn expect_one<'a>(result: Result<Plan<'a>, Reject>) -> (&'a Provider, String) {
        match result {
            Ok(Plan::One(provider, model)) => (provider, model),
            Ok(Plan::Chain(_)) => panic!("expected a single target, got a chain"),
            Err(reject) => panic!("unexpected rejection: {}", reject.message),
        }
    }

    fn expect_reject(result: Result<Plan<'_>, Reject>) -> Reject {
        match result {
            Ok(_) => panic!("expected a rejection"),
            Err(reject) => reject,
        }
    }

    // ----- model resolution -----

    #[test]
    fn explicit_provider_model_routes_to_that_provider() {
        let r = router(vec![provider(IMAGE_PROVIDER), provider(CHAT_PROVIDER)], &[]);
        let (p, m) = expect_one(plan(&r, "images/gpt-image-1", Capability::Images));
        assert_eq!(p.name, "images");
        assert_eq!(m, "gpt-image-1");
    }

    #[test]
    fn bare_model_picks_the_capable_provider_not_the_chat_one() {
        // "chat" lists the model too and comes first: capability gating, not
        // list order, must decide.
        let r = router(vec![provider(CHAT_PROVIDER), provider(IMAGE_PROVIDER)], &[]);
        let (p, m) = expect_one(plan(&r, "gpt-image-1", Capability::Images));
        assert_eq!(p.name, "images");
        assert_eq!(m, "gpt-image-1");
        // The same model on the audio endpoint is not an image request.
        let r = router(vec![provider(IMAGE_PROVIDER)], &[]);
        assert!(plan(&r, "gpt-image-1", Capability::Audio).is_err());
    }

    #[test]
    fn bare_model_on_a_wildcard_capable_provider_routes() {
        let r = router(vec![provider(WILDCARD_IMAGE_PROVIDER)], &[]);
        let (p, m) = expect_one(plan(&r, "whatever-image-model", Capability::Images));
        assert_eq!(p.name, "anyimage");
        assert_eq!(m, "whatever-image-model");
    }

    #[test]
    fn explicit_model_list_wins_over_a_wildcard_provider() {
        let r = router(
            vec![provider(WILDCARD_IMAGE_PROVIDER), provider(IMAGE_PROVIDER)],
            &[],
        );
        let (p, _) = expect_one(plan(&r, "gpt-image-1", Capability::Images));
        assert_eq!(p.name, "images", "the dedicated provider must win");
    }

    #[test]
    fn two_capable_providers_for_one_bare_model_is_ambiguous() {
        let r = router(
            vec![provider(IMAGE_PROVIDER), provider(SECOND_IMAGE_PROVIDER)],
            &[],
        );
        let reject = expect_reject(plan(&r, "gpt-image-1", Capability::Images));
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.kind, "invalid_request_error");
        // Both candidates are named, and the fix is spelled out.
        assert!(
            reject.message.contains("images/gpt-image-1"),
            "{}",
            reject.message
        );
        assert!(
            reject.message.contains("images2/gpt-image-1"),
            "{}",
            reject.message
        );
        assert!(
            reject.message.contains("disambiguate"),
            "{}",
            reject.message
        );
    }

    #[test]
    fn unknown_model_is_404_model_not_found() {
        let r = router(vec![provider(IMAGE_PROVIDER)], &[]);
        let reject = expect_reject(plan(&r, "nope-1", Capability::Images));
        assert_eq!(reject.status, StatusCode::NOT_FOUND);
        assert_eq!(reject.kind, "model_not_found");
        assert!(reject.message.contains("no provider serves model 'nope-1'"));
    }

    // ----- capability gating -----

    #[test]
    fn missing_capability_is_400_unsupported_capability() {
        let r = router(vec![provider(CHAT_PROVIDER)], &[]);
        let reject = expect_reject(plan(&r, "gpt-image-1", Capability::Images));
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.kind, "unsupported_capability");
        // Names the capability, the provider that would serve it, and the fix.
        assert!(reject.message.contains("'images'"), "{}", reject.message);
        assert!(
            reject.message.contains("served by chat"),
            "{}",
            reject.message
        );
        assert!(
            reject.message.contains(r#"capabilities = ["images"]"#),
            "{}",
            reject.message
        );
    }

    #[test]
    fn explicit_provider_without_the_capability_is_refused() {
        // `chat/gpt-image-1` is explicit, so it must not fall back to a capable
        // provider: the caller asked for that provider.
        let r = router(vec![provider(CHAT_PROVIDER), provider(IMAGE_PROVIDER)], &[]);
        let reject = expect_reject(plan(&r, "chat/gpt-image-1", Capability::Images));
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.kind, "unsupported_capability");
        assert!(
            reject.message.contains("provider 'chat'"),
            "{}",
            reject.message
        );
    }

    #[test]
    fn audio_and_images_are_separate_capabilities() {
        let r = router(vec![provider(AUDIO_PROVIDER)], &[]);
        let (p, m) = expect_one(plan(&r, "tts-1", Capability::Audio));
        assert_eq!(p.name, "speech");
        assert_eq!(m, "tts-1");
        // An audio provider is not an image provider.
        let reject = expect_reject(plan(&r, "tts-1", Capability::Images));
        assert_eq!(reject.kind, "unsupported_capability");
        assert!(reject.message.contains("'images'"), "{}", reject.message);
    }

    // ----- combos -----

    // ----- handlers -----

    /// The handlers must be usable as axum routes exactly as `lib.rs` will wire
    /// them. This pins the extractor set — `State`, an optional `Extension`,
    /// then `HeaderMap`, with `Bytes` last — which a router line depends on and
    /// which nothing else in the unit tests exercises.
    #[test]
    fn handlers_satisfy_the_axum_handler_contract() {
        use axum::routing::post;

        let _: axum::Router<Arc<AppState>> = axum::Router::new()
            .route("/v1/images/generations", post(images_generations))
            .route("/v1/images/edits", post(images_edits))
            .route("/v1/audio/speech", post(audio_speech))
            .route("/v1/audio/transcriptions", post(audio_transcriptions))
            .route("/v1/audio/translations", post(audio_translations));
    }

    #[test]
    fn combo_uses_the_first_target_that_declares_the_capability() {
        let r = router(
            vec![provider(CHAT_PROVIDER), provider(IMAGE_PROVIDER)],
            &[("media", &["chat/gpt-image-1", "images/gpt-image-1"])],
        );
        match plan(&r, "media", Capability::Images) {
            Ok(Plan::Chain(targets)) => {
                assert_eq!(targets.len(), 1, "only the capable target remains");
                assert_eq!(targets[0].0.name, "images");
                assert_eq!(targets[0].1, "gpt-image-1");
            }
            other => panic!(
                "expected a chain, got {}",
                match other {
                    Ok(_) => "a single target".to_string(),
                    Err(r) => r.message,
                }
            ),
        }
    }

    #[test]
    fn combo_without_a_capable_target_is_unsupported() {
        let r = router(
            vec![provider(CHAT_PROVIDER)],
            &[("media", &["chat/gpt-image-1"])],
        );
        let reject = expect_reject(plan(&r, "media", Capability::Images));
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.kind, "unsupported_capability");
        assert!(
            reject.message.contains("combo 'media'"),
            "{}",
            reject.message
        );
        assert!(
            reject.message.contains("chat/gpt-image-1"),
            "{}",
            reject.message
        );
        // "combo/media" is the same combo.
        let reject = expect_reject(plan(&r, "combo/media", Capability::Images));
        assert_eq!(reject.kind, "unsupported_capability");
    }

    #[test]
    fn combo_keeps_capable_fallbacks_in_chain_order() {
        let r = router(
            vec![provider(IMAGE_PROVIDER), provider(SECOND_IMAGE_PROVIDER)],
            &[("media", &["images/gpt-image-1", "images2/gpt-image-1"])],
        );
        match plan(&r, "media", Capability::Images) {
            Ok(Plan::Chain(targets)) => {
                let names: Vec<&str> = targets.iter().map(|(p, _)| p.name.as_str()).collect();
                assert_eq!(names, vec!["images", "images2"]);
            }
            _ => panic!("expected a chain"),
        }
    }

    // ----- policy: allowlist + disabled_models -----

    #[test]
    fn disabled_model_is_404_exactly_like_chat() {
        let r = router(vec![provider(IMAGE_PROVIDER)], &[]);
        let planned = plan(&r, "images/gpt-image-1", Capability::Images);
        let mut disabled = HashSet::new();
        disabled.insert("images/gpt-image-1".to_string());
        let reject = match authorize(
            planned.expect("resolves"),
            "images/gpt-image-1",
            Capability::Images,
            None,
            &disabled,
        ) {
            Ok(_) => panic!("expected a rejection"),
            Err(reject) => reject,
        };
        assert_eq!(reject.status, StatusCode::NOT_FOUND);
        assert_eq!(reject.kind, "model_not_found");
        assert_eq!(
            reject.message, "model 'images/gpt-image-1' is disabled",
            "the message must match chat's"
        );

        // The bare model name is disabled-able too.
        let planned = plan(&r, "gpt-image-1", Capability::Images);
        let mut disabled = HashSet::new();
        disabled.insert("gpt-image-1".to_string());
        let reject = match authorize(
            planned.expect("resolves"),
            "gpt-image-1",
            Capability::Images,
            None,
            &disabled,
        ) {
            Ok(_) => panic!("expected a rejection"),
            Err(reject) => reject,
        };
        assert_eq!(reject.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn client_key_allowlist_is_403_exactly_like_chat() {
        let r = router(vec![provider(IMAGE_PROVIDER)], &[]);
        let allowed = vec!["gpt-4o".to_string()];
        let planned = plan(&r, "images/gpt-image-1", Capability::Images);
        let reject = match authorize(
            planned.expect("resolves"),
            "images/gpt-image-1",
            Capability::Images,
            Some(&allowed),
            &HashSet::new(),
        ) {
            Ok(_) => panic!("expected a rejection"),
            Err(reject) => reject,
        };
        assert_eq!(reject.status, StatusCode::FORBIDDEN);
        assert_eq!(reject.kind, "model_not_allowed");
        assert_eq!(
            reject.message, "model 'images/gpt-image-1' is not allowed for this API key",
            "the message must match chat's"
        );

        // The upstream name alone is enough to grant it.
        let allowed = vec!["gpt-image-1".to_string()];
        let planned = plan(&r, "images/gpt-image-1", Capability::Images);
        assert!(
            authorize(
                planned.expect("resolves"),
                "images/gpt-image-1",
                Capability::Images,
                Some(&allowed),
                &HashSet::new(),
            )
            .is_ok()
        );
    }

    #[test]
    fn combo_policy_uses_combo_allowlist_and_drops_disabled_targets() {
        let r = router(
            vec![provider(IMAGE_PROVIDER), provider(SECOND_IMAGE_PROVIDER)],
            &[("media", &["images/gpt-image-1", "images2/gpt-image-1"])],
        );

        // A disabled combo name is a 404 before any target is looked at.
        let planned = plan(&r, "media", Capability::Images);
        let mut disabled = HashSet::new();
        disabled.insert("media".to_string());
        let reject = match authorize(
            planned.expect("resolves"),
            "media",
            Capability::Images,
            None,
            &disabled,
        ) {
            Ok(_) => panic!("expected a rejection"),
            Err(reject) => reject,
        };
        assert_eq!(reject.status, StatusCode::NOT_FOUND);

        // A disabled target is dropped, the rest of the chain survives.
        let planned = plan(&r, "media", Capability::Images);
        let mut disabled = HashSet::new();
        disabled.insert("images/gpt-image-1".to_string());
        let targets = authorize(
            planned.expect("resolves"),
            "media",
            Capability::Images,
            None,
            &disabled,
        )
        .expect("one target left");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0.name, "images2");

        // Disabling every target is a 404 that mentions the capability.
        let planned = plan(&r, "media", Capability::Images);
        let mut disabled = HashSet::new();
        disabled.insert("images/gpt-image-1".to_string());
        disabled.insert("images2/gpt-image-1".to_string());
        let reject = match authorize(
            planned.expect("resolves"),
            "media",
            Capability::Images,
            None,
            &disabled,
        ) {
            Ok(_) => panic!("expected a rejection"),
            Err(reject) => reject,
        };
        assert_eq!(reject.status, StatusCode::NOT_FOUND);
        assert!(reject.message.contains("'images'"), "{}", reject.message);

        // Allowlist must name the combo (or "combo/media").
        let planned = plan(&r, "media", Capability::Images);
        let allowed = vec!["combo/media".to_string()];
        assert!(
            authorize(
                planned.expect("resolves"),
                "media",
                Capability::Images,
                Some(&allowed),
                &HashSet::new(),
            )
            .is_ok()
        );
        let planned = plan(&r, "media", Capability::Images);
        let allowed = vec!["gpt-image-1".to_string()];
        let reject = match authorize(
            planned.expect("resolves"),
            "media",
            Capability::Images,
            Some(&allowed),
            &HashSet::new(),
        ) {
            Ok(_) => panic!("expected a rejection"),
            Err(reject) => reject,
        };
        assert_eq!(reject.status, StatusCode::FORBIDDEN);
    }

    // ----- body handling -----

    #[test]
    fn json_model_is_spliced_in_place() {
        let body = Bytes::from_static(br#"{"model":"images/gpt-image-1","prompt":"x"}"#);
        let span = crate::scan::string_field_span(&body, b"model").expect("model span");
        let out = splice_model(&body, &span, "gpt-image-1");
        assert_eq!(&out[..], br#"{"model":"gpt-image-1","prompt":"x"}"#);
        // Same name: no copy, the body is shared (Bytes clone is a refcount bump).
        let same = splice_model(&body, &span, "images/gpt-image-1");
        assert_eq!(same, body);
        // A longer name grows the buffer correctly.
        let out = splice_model(&body, &span, "a-much-longer-upstream-model-name");
        assert_eq!(
            &out[..],
            br#"{"model":"a-much-longer-upstream-model-name","prompt":"x"}"#
        );
    }

    #[test]
    fn multipart_model_field_is_located_without_re_encoding() {
        let body = b"--X\r\n\
Content-Disposition: form-data; name=\"model\"\r\n\r\n\
gpt-image-1\r\n\
--X\r\n\
Content-Disposition: form-data; name=\"prompt\"\r\n\r\n\
a cat\r\n\
--X--\r\n";
        let span = multipart_field_span(body, "model").expect("model field");
        assert_eq!(&body[span.clone()], b"gpt-image-1".as_slice());

        // Splice keeps the boundary, the part order and every other byte.
        let spliced = splice_model(&Bytes::from(body.to_vec()), &span, "dall-e-3");
        let expected = String::from_utf8_lossy(body).replace("gpt-image-1", "dall-e-3");
        assert_eq!(String::from_utf8_lossy(&spliced), expected);
        assert_eq!(
            spliced.len(),
            body.len() - "gpt-image-1".len() + "dall-e-3".len()
        );
    }

    #[test]
    fn multipart_without_a_model_field_is_not_routed() {
        let body = b"--X\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"model\"\r\n\r\n\
\x00\x01binary\r\n\
--X--\r\n";
        // `filename="model"` must not be mistaken for `name="model"`.
        assert!(multipart_field_span(body, "model").is_none());
        // Nor must a body without the field at all.
        assert!(multipart_field_span(b"--X--\r\n", "model").is_none());
    }

    #[test]
    fn multipart_field_values_are_trimmed() {
        let body =
            b"--X\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n  tts-1 \r\n--X--\r\n";
        let span = multipart_field_span(body, "model").expect("model field");
        assert_eq!(&body[span], b"tts-1".as_slice());
    }

    #[test]
    fn a_prompt_quoting_the_field_name_does_not_hide_the_real_field() {
        // The prompt value contains the literal text `name="model"` — only a
        // match inside a Content-Disposition header line may be trusted.
        let body = b"--X\r\n\
Content-Disposition: form-data; name=\"prompt\"\r\n\r\n\
draw the text name=\"model\" on it\r\n\
--X\r\n\
Content-Disposition: form-data; name=\"model\"\r\n\r\n\
whisper-1\r\n\
--X--\r\n";
        let span = multipart_field_span(body, "model").expect("model field");
        assert_eq!(&body[span], b"whisper-1".as_slice());
    }

    // ----- response relay -----

    #[tokio::test]
    async fn binary_bodies_are_relayed_verbatim() {
        // A real PNG header including bytes that are not UTF-8: a JSON round-trip
        // or a lossy conversion anywhere in this path would corrupt them.
        let png: &[u8] = &[
            0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0x00, 0xfe,
        ];
        let resp = relay(
            StatusCode::BAD_REQUEST,
            vec![(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )],
            Body::from(png.to_vec()),
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1024)
            .await
            .expect("body is readable");
        assert_eq!(&bytes[..], png);
    }

    #[test]
    fn only_safe_upstream_headers_are_relayed() {
        for ok in ["content-type", "cache-control", "etag", "retry-after"] {
            assert!(
                forward_header(&HeaderName::from_static(ok)),
                "{ok} should be relayed"
            );
        }
        assert!(forward_header(&HeaderName::from_static("x-request-id")));
        // Framing headers describe the upstream connection, not ours.
        for bad in ["content-length", "transfer-encoding", "connection"] {
            assert!(
                !forward_header(&HeaderName::from_static(bad)),
                "{bad} must never be copied"
            );
        }
        assert!(!forward_header(&HeaderName::from_static("authorization")));
    }

    /// The global `json_errors` layer only touches error statuses whose
    /// content-type is not JSON. Pinning both halves matters here because images
    /// and audio are binary: a 2xx payload must arrive byte-identical, while a
    /// non-JSON *error* body is folded into the JSON envelope (pre-existing
    /// behaviour of every `/v1` route, not introduced by this module).
    ///
    /// Runs over a loopback socket: `tower` is not a direct dependency, so
    /// `Router::oneshot` is unavailable in a unit test.
    #[tokio::test]
    async fn json_errors_keeps_2xx_binary_intact_but_envelopes_non_json_errors() {
        use axum::routing::post;

        const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff];

        async fn ok_binary() -> Response {
            let mut resp = Response::new(Body::from(PNG.to_vec()));
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
            resp
        }
        async fn bad_binary() -> Response {
            let mut resp = Response::new(Body::from(b"upstream said no".to_vec()));
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            resp
        }

        let app = axum::Router::new()
            .route("/v1/images/generations", post(ok_binary))
            .route("/v1/audio/speech", post(bad_binary))
            .layer(axum::middleware::from_fn(crate::middleware::json_errors));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = reqwest::Client::new();

        // 2xx binary: relayed byte-for-byte, content-type untouched.
        let resp = client
            .post(format!("http://{addr}/v1/images/generations"))
            .send()
            .await
            .expect("request the fake upstream");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        let bytes = resp.bytes().await.expect("body");
        assert_eq!(&bytes[..], PNG);

        // Non-JSON error: the middleware rewrites it into the JSON envelope, so
        // the noise stays valid JSON for clients (status is preserved).
        let resp = client
            .post(format!("http://{addr}/v1/audio/speech"))
            .send()
            .await
            .expect("request the fake upstream");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("application/json"))
        );
        let body: serde_json::Value = resp.json().await.expect("JSON envelope");
        assert_eq!(body["error"]["code"], 400);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("upstream said no"),
            "{body}"
        );

        server.abort();
    }
}
