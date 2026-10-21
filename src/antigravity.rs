//! Antigravity provider: Google OAuth accounts proxied through the internal
//! cloudcode-pa endpoints (the same backend the Antigravity IDE uses).
//!
//! Wire protocol notes (mirrors the native client):
//! - Auth: OAuth2 authorization-code flow against Google, Bearer access token.
//! - Requests: POST {base}/v1internal:generateContent | :streamGenerateContent?alt=sse
//!   with an envelope {"model", "project", "userAgent", "request": <gemini body>}.
//! - Responses wrap the Gemini payload in a top-level "response" field.
//! - Project id comes from loadCodeAssist (cloudaicompanionProject).

use std::time::{SystemTime, UNIX_EPOCH};

use sha2::Digest;

use serde_json::{Value, json};
use tracing::warn;

pub const CLIENT_ID: &str =
    "REDACTED-SET-VIA-ENV";
pub const CLIENT_SECRET: &str = "REDACTED-SET-VIA-ENV";
pub const CALLBACK_PORT: u16 = 51121;

const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v2/userinfo?alt=json";

pub const PROD_ENDPOINT: &str = "https://cloudcode-pa.googleapis.com";
pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";
const API_VERSION: &str = "v1internal";

const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];

/// UA used by generate/stream/model-list requests. Version floor 2.9.1 —
/// cloudcode rejects newer models for older clients.
pub const USER_AGENT: &str = "antigravity/hub/2.9.1 darwin/arm64";

// Refresh tokens are renewed slightly before expiry; the window is
// `[tuning] token_refresh_window_secs`.

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug)]
pub enum AuthError {
    /// Refresh token is dead (invalid_grant) — account must be re-authorized.
    Permanent(String),
    /// Network / 5xx — worth retrying later.
    Transient(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Permanent(m) => write!(f, "permanent: {m}"),
            AuthError::Transient(m) => write!(f, "transient: {m}"),
        }
    }
}

struct AccountState {
    access_token: Option<String>,
    /// Unix millis when the access token expires.
    expires_at_ms: u64,
    project_id: Option<String>,
    /// Live refresh token (may have been rotated since the config was written).
    refresh_token: Option<String>,
}

pub struct Account {
    /// Pool identity: refresh token when present, else the static access token.
    identity: String,
    pub email: Option<String>,
    project_id_static: Option<String>,
    provider: String,
    storage: Option<crate::storage::Storage>,
    client: reqwest::Client,
    state: tokio::sync::Mutex<AccountState>,
    tuning: std::sync::Arc<crate::config::Tuning>,
}

impl Account {
    pub fn new(
        cfg: &crate::config::OAuthAccountConfig,
        provider: &str,
        storage: Option<&crate::storage::Storage>,
        client: reqwest::Client,
        tuning: std::sync::Arc<crate::config::Tuning>,
    ) -> Self {
        let refresh_token = if cfg.refresh_token.is_empty() {
            None
        } else {
            Some(cfg.refresh_token.clone())
        };
        let identity = refresh_token
            .clone()
            .or_else(|| cfg.access_token.clone())
            .unwrap_or_default();

        // Pre-seeded token from config, else cached token from previous runs.
        // Load the cache when we might refresh — a rotated refresh token may
        // live there even if a static access token is configured.
        let cached = if cfg.access_token.is_none() || refresh_token.is_some() {
            storage.and_then(|s| s.load_oauth(provider, &identity))
        } else {
            None
        };
        // A rotated refresh token persisted earlier wins over the stale config one.
        let refresh_token = cached
            .as_ref()
            .and_then(|c| c.refresh_token.clone())
            .or(refresh_token);
        let access_token = cfg
            .access_token
            .clone()
            .or_else(|| cached.as_ref().map(|c| c.access_token.clone()))
            .filter(|t| !t.is_empty());
        // Pre-seeded tokens never expire — but only when there's no refresh token
        // to renew them; with one configured, let the seed expire and refresh.
        let expires_at_ms = if cfg.access_token.is_some() && refresh_token.is_none() {
            u64::MAX
        } else {
            cached.as_ref().map(|c| c.expires_at_ms).unwrap_or(0)
        };
        let project_id = cfg
            .project_id
            .clone()
            .or_else(|| cached.as_ref().and_then(|c| c.project_id.clone()));

        Self {
            identity,
            email: cfg.email.clone(),
            project_id_static: cfg.project_id.clone(),
            provider: provider.to_string(),
            storage: storage.cloned(),
            client,
            tuning,
            state: tokio::sync::Mutex::new(AccountState {
                access_token,
                expires_at_ms,
                project_id,
                refresh_token,
            }),
        }
    }

    fn persist(
        &self,
        access_token: &str,
        expires_at_ms: u64,
        project_id: Option<&str>,
        refresh_token: Option<&str>,
    ) {
        if let Some(s) = &self.storage {
            s.save_oauth(
                &self.provider,
                &self.identity,
                crate::storage::OAuthRecord {
                    access_token: access_token.to_string(),
                    expires_at_ms,
                    project_id: project_id.map(str::to_string),
                    refresh_token: refresh_token.map(str::to_string),
                },
            );
        }
    }

    /// Identifier used as the pool key secret.
    pub fn pool_secret(&self) -> &str {
        &self.identity
    }

    /// HTTP client for this account (account proxy if configured).
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn label(&self) -> String {
        self.email.clone().unwrap_or_else(|| {
            // Google refresh tokens all share the same prefix ("1//0c…"),
            // so we mask by hash — otherwise different accounts get identical labels.
            let digest = sha2::Sha256::digest(self.identity.as_bytes());
            format!("acct:{}", hex::encode(&digest[..4]))
        })
    }

    /// Returns a valid access token, refreshing it if expired.
    pub async fn ensure_access_token(&self) -> Result<String, AuthError> {
        let mut st = self.state.lock().await;
        if let Some(t) = &st.access_token {
            let window = self.tuning.token_refresh_window().as_millis() as u64;
            if !needs_refresh(st.expires_at_ms, now_ms(), window) {
                return Ok(t.clone());
            }
        }

        let Some(refresh_token) = st.refresh_token.clone() else {
            return Err(AuthError::Permanent(
                "static access token rejected and no refresh token configured".into(),
            ));
        };
        let resp = self
            .client
            .post(TOKEN_ENDPOINT)
            .form(&[
                ("client_id", CLIENT_ID),
                ("client_secret", CLIENT_SECRET),
                ("refresh_token", refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Transient(format!("token refresh request failed: {e}")))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet: String = body.chars().take(300).collect();
            return if matches!(status.as_u16(), 400 | 401) {
                Err(AuthError::Permanent(format!(
                    "token refresh rejected ({status}): {snippet}"
                )))
            } else {
                Err(AuthError::Transient(format!(
                    "token refresh failed ({status}): {snippet}"
                )))
            };
        }

        let v: Value = serde_json::from_str(&body)
            .map_err(|e| AuthError::Transient(format!("token refresh: bad JSON: {e}")))?;
        let token = v
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| AuthError::Transient("token refresh: no access_token".into()))?
            .to_string();
        let expires_in = v.get("expires_in").and_then(|e| e.as_u64()).unwrap_or(3600);
        st.expires_at_ms = now_ms() + expires_in * 1000;
        st.access_token = Some(token.clone());
        // If the issuer rotated the refresh token, keep and persist the replacement.
        if let Some(rt) = v.get("refresh_token").and_then(|t| t.as_str())
            && rt != refresh_token
        {
            st.refresh_token = Some(rt.to_string());
        }
        let project = st.project_id.clone();
        self.persist(
            &token,
            st.expires_at_ms,
            project.as_deref(),
            st.refresh_token.as_deref(),
        );
        Ok(token)
    }

    /// Returns the cloudcode project id, resolving it via loadCodeAssist on first use.
    pub async fn ensure_project_id(&self, access_token: &str) -> Result<String, AuthError> {
        if let Some(p) = &self.project_id_static {
            return Ok(p.clone());
        }
        let mut st = self.state.lock().await;
        if let Some(p) = &st.project_id {
            return Ok(p.clone());
        }

        let resp = self
            .client
            .post(format!("{PROD_ENDPOINT}/{API_VERSION}:loadCodeAssist"))
            .bearer_auth(access_token)
            .header("User-Agent", USER_AGENT)
            .json(&json!({"metadata": {"ideType": "ANTIGRAVITY"}}))
            .send()
            .await
            .map_err(|e| AuthError::Transient(format!("loadCodeAssist failed: {e}")))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet: String = body.chars().take(300).collect();
            return if matches!(status.as_u16(), 401 | 403) {
                Err(AuthError::Permanent(format!(
                    "loadCodeAssist {status}: {snippet}"
                )))
            } else {
                Err(AuthError::Transient(format!(
                    "loadCodeAssist {status}: {snippet}"
                )))
            };
        }

        let v: Value = serde_json::from_str(&body)
            .map_err(|e| AuthError::Transient(format!("loadCodeAssist: bad JSON: {e}")))?;
        let project = ["cloudaicompanionProject", "projectId", "project"]
            .iter()
            .find_map(|k| match v.get(*k) {
                Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
                Some(Value::Object(o)) => o
                    .get("id")
                    .and_then(|i| i.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                _ => None,
            })
            .ok_or_else(|| {
                AuthError::Transient(
                    "loadCodeAssist: no project id (account may need onboarding in Antigravity IDE)"
                        .into(),
                )
            })?;
        st.project_id = Some(project.clone());
        if let Some(t) = &st.access_token {
            let t = t.clone();
            let rt = st.refresh_token.clone();
            self.persist(&t, st.expires_at_ms, Some(&project), rt.as_deref());
        }
        Ok(project)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelQuota {
    pub id: String,
    /// 0.0–1.0 remaining quota, when reported.
    pub remaining_fraction: Option<f64>,
    pub reset_time: Option<String>,
}

/// Fetch the account's available models (with quota info) from cloudcode.
pub async fn fetch_available_models(
    http: &reqwest::Client,
    base_url: &str,
    access_token: &str,
) -> Result<Vec<ModelQuota>, AuthError> {
    let resp = http
        .post(format!("{base_url}/{API_VERSION}:fetchAvailableModels"))
        .bearer_auth(access_token)
        .header("User-Agent", USER_AGENT)
        .json(&json!({}))
        .send()
        .await
        .map_err(|e| AuthError::Transient(format!("fetchAvailableModels failed: {e}")))?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let snippet: String = body.chars().take(300).collect();
        // 401/403 mean the token itself is bad — retrying won't help
        return if matches!(status.as_u16(), 401 | 403) {
            Err(AuthError::Permanent(format!(
                "fetchAvailableModels {status}: {snippet}"
            )))
        } else {
            Err(AuthError::Transient(format!(
                "fetchAvailableModels {status}: {snippet}"
            )))
        };
    }
    let v: Value = serde_json::from_str(&body)
        .map_err(|e| AuthError::Transient(format!("fetchAvailableModels: bad JSON: {e}")))?;

    // Expected shape: {"models": {"<id>": {...quotaInfo...}, ...}};
    // tolerate {"models": [{"name"|"id": ...}]}.
    let quota_of = |m: &Value| -> (Option<f64>, Option<String>) {
        let q = m.get("quotaInfo").or_else(|| m.get("quota"));
        let frac = q
            .and_then(|q| q.get("remainingFraction").or_else(|| q.get("remaining")))
            .and_then(|f| {
                f.as_f64()
                    .or_else(|| f.as_str().and_then(|s| s.parse().ok()))
            });
        let reset = q
            .and_then(|q| q.get("resetTime").or_else(|| q.get("reset_time")))
            .and_then(|r| r.as_str())
            .map(str::to_string);
        (frac, reset)
    };
    let models = match v.get("models") {
        Some(Value::Object(o)) => o
            .iter()
            .map(|(id, m)| {
                let (remaining_fraction, reset_time) = quota_of(m);
                ModelQuota {
                    id: id.clone(),
                    remaining_fraction,
                    reset_time,
                }
            })
            .collect(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|m| {
                let id = m
                    .get("name")
                    .or_else(|| m.get("id"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.trim_start_matches("models/").to_string())?;
                let (remaining_fraction, reset_time) = quota_of(m);
                Some(ModelQuota {
                    id,
                    remaining_fraction,
                    reset_time,
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(models)
}

// ---------- request/response adaptation (on top of the Gemini translator) ----------

/// Wrap a prebuilt Gemini request body into the Antigravity v1internal envelope,
/// applying the wire quirks: systemInstruction camelCase, parametersJsonSchema.
pub fn translate_request_envelope(
    model: &str,
    mut inner: Value,
    project_id: &str,
) -> Result<Value, String> {
    if let Some(obj) = inner.as_object_mut()
        && let Some(si) = obj.remove("system_instruction")
    {
        obj.insert("systemInstruction".into(), si);
    }
    if let Some(tools) = inner.get_mut("tools").and_then(|t| t.as_array_mut()) {
        for tool in tools.iter_mut() {
            for key in ["function_declarations", "functionDeclarations"] {
                if let Some(decls) = tool.get_mut(key).and_then(|d| d.as_array_mut()) {
                    for decl in decls.iter_mut() {
                        if let Some(obj) = decl.as_object_mut()
                            && let Some(p) = obj.remove("parameters")
                        {
                            obj.insert("parametersJsonSchema".into(), p);
                        }
                    }
                }
            }
        }
    }

    Ok(json!({
        "model": model,
        "project": project_id,
        "userAgent": "antigravity",
        "request": inner,
    }))
}

pub fn endpoint(base_url: &str, stream: bool) -> String {
    if stream {
        format!("{base_url}/{API_VERSION}:streamGenerateContent?alt=sse")
    } else {
        format!("{base_url}/{API_VERSION}:generateContent")
    }
}

/// Parse Google's 429 error details for the exact quota reset time (unix ms).
/// Handles RetryInfo.retryDelay ("123s") and quotaResetTimeStamp (RFC3339).
pub fn parse_quota_reset_ms(body: &str) -> Option<u64> {
    let v: Value = serde_json::from_str(body).ok()?;
    let details = v.pointer("/error/details")?.as_array()?;
    let mut until: Option<u64> = None;
    for d in details {
        if let Some(rd) = d.get("retryDelay").and_then(|s| s.as_str())
            && let Some(secs) = rd.strip_suffix('s').and_then(|s| s.parse::<f64>().ok())
        {
            // take the LATER reset like the timestamp branch below — a shorter
            // retryDelay must not shrink a known later quota reset
            let candidate = now_ms() + (secs * 1000.0) as u64;
            until = Some(until.map_or(candidate, |u: u64| u.max(candidate)));
        }
        if let Some(ts) = d.get("quotaResetTimeStamp").and_then(|s| s.as_str())
            && let Some(ms) = parse_rfc3339_ms(ts)
        {
            until = Some(until.map_or(ms, |u: u64| u.max(ms)));
        }
    }
    until
}

/// Minimal RFC3339 ("YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]") → unix ms.
fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let (date, rest) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: i64 = dp.next()?.parse().ok()?;
    let d: i64 = dp.next()?.parse().ok()?;
    let (time, off) = match rest.find(['Z', '+']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => match rest.rfind('-') {
            Some(i) if i > 6 => (&rest[..i], &rest[i..]),
            _ => (rest, "Z"),
        },
    };
    let time = time.split('.').next()?;
    let mut tp = time.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let sec: i64 = tp.next()?.parse().ok()?;
    let off_secs: i64 = if off == "Z" || off.is_empty() {
        0
    } else {
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let o = &off[1..];
        let mut op = o.split(':');
        let oh: i64 = op.next()?.parse().ok()?;
        let om: i64 = op.next().unwrap_or("0").parse().ok()?;
        sign * (oh * 3600 + om * 60)
    };
    let days = days_from_civil(y, mo, d);
    let secs = days * 86400 + h * 3600 + mi * 60 + sec - off_secs;
    Some(secs.max(0) as u64 * 1000)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Unwrap the v1internal `{"response": {...}}` envelope if present.
pub fn unwrap_response(v: Value) -> Value {
    match v.get("response") {
        Some(inner) if inner.is_object() => inner.clone(),
        _ => v,
    }
}

// ---------- OAuth authorization-code flow (for `anyhop auth antigravity`) ----------

pub fn build_auth_url(state: &str) -> String {
    build_auth_url_with(state, &loopback_redirect_uri())
}

pub fn build_auth_url_with(state: &str, redirect_uri: &str) -> String {
    format!(
        "{AUTH_ENDPOINT}?access_type=offline&client_id={CLIENT_ID}&prompt=consent&redirect_uri={}&response_type=code&scope={}&state={state}",
        urlencoded(redirect_uri),
        urlencoded(&SCOPES.join(" ")),
    )
}

pub fn urlencoded(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn exchange_code(
    http: &reqwest::Client,
    code: &str,
    redirect_uri: &str,
) -> anyhow::Result<AuthTokens> {
    let resp = http
        .post(TOKEN_ENDPOINT)
        .form(&[
            ("code", code),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        let snippet: String = body.chars().take(300).collect();
        anyhow::bail!("token exchange failed ({status}): {snippet}");
    }
    let v: Value = serde_json::from_str(&body)?;
    let access_token = v
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("no access_token in exchange response"))?
        .to_string();
    let refresh_token = v
        .get("refresh_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("no refresh_token in exchange response (retry the auth URL)")
        })?
        .to_string();
    Ok(AuthTokens {
        access_token,
        refresh_token,
    })
}

pub async fn fetch_email(http: &reqwest::Client, access_token: &str) -> Option<String> {
    let resp = http
        .get(USERINFO_ENDPOINT)
        .bearer_auth(access_token)
        .header("User-Agent", USER_AGENT)
        .send()
        .await
        .ok()?;
    let v: Value = resp.json().await.ok()?;
    v.get("email").and_then(|e| e.as_str()).map(str::to_string)
}

/// Should a cached access token be renewed?
///
/// Refreshing *before* expiry (window, default 5 min) keeps a request from
/// paying the refresh latency; `window = 0` means "refresh only when expired".
fn needs_refresh(expires_at_ms: u64, now_ms: u64, window_ms: u64) -> bool {
    now_ms >= expires_at_ms.saturating_sub(window_ms)
}

/// A started OAuth flow: URL for the user + listener waiting for the callback.
pub struct PendingAuth {
    pub url: String,
    pub state: String,
    /// Redirect URI sent to the provider; must match the one in the auth URL.
    pub redirect_uri: String,
    /// Present for the loopback flow only. `None` = headless, the code arrives
    /// from a public callback route or a pasted URL.
    pub listener: Option<tokio::net::TcpListener>,
    http: reqwest::Client,
}

pub struct AuthOutcome {
    pub refresh_token: String,
    pub email: Option<String>,
    pub project_id: Option<String>,
}

/// Start the OAuth flow (non-blocking): returns the URL to open.
pub async fn start_auth(proxy: Option<&str>) -> anyhow::Result<PendingAuth> {
    start_auth_with(proxy, &crate::config::Tuning::default(), None).await
}

/// Start the flow. `redirect_uri = Some(public)` runs headless: the provider
/// sends the browser to that URL (our own /api/auth/callback), so the panel can
/// be used from another machine. `None` keeps the loopback listener.
pub async fn start_auth_with(
    proxy: Option<&str>,
    tuning: &crate::config::Tuning,
    redirect_uri: Option<&str>,
) -> anyhow::Result<PendingAuth> {
    let mut builder = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(tuning.oauth_http_timeout());
    if let Some(p) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(p)?);
    }
    let http = builder.build()?;
    let state = format!("{:x}", now_ms());
    match redirect_uri {
        Some(uri) => {
            let url = build_auth_url_with(&state, uri);
            Ok(PendingAuth {
                url,
                state,
                redirect_uri: uri.to_string(),
                listener: None,
                http,
            })
        }
        None => {
            let uri = loopback_redirect_uri();
            let url = build_auth_url_with(&state, &uri);
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", CALLBACK_PORT))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "cannot bind localhost:{CALLBACK_PORT}: {e} (auth already running?)"
                    )
                })?;
            Ok(PendingAuth {
                url,
                state,
                redirect_uri: uri,
                listener: Some(listener),
                http,
            })
        }
    }
}

pub fn loopback_redirect_uri() -> String {
    format!("http://localhost:{CALLBACK_PORT}/oauth-callback")
}

/// Wait for the browser callback and complete the exchange.
pub async fn complete_auth(p: PendingAuth) -> anyhow::Result<AuthOutcome> {
    let code = wait_for_callback(&p).await?;
    finish(p, &code).await
}

/// Wait for the loopback browser callback and return the authorization code.
///
/// Split from the token exchange so the caller can race it against a pasted
/// callback URL (`tokio::select!`) — the panel may be used from another machine,
/// where the browser cannot reach this listener at all.
pub async fn wait_for_callback(p: &PendingAuth) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Some(listener) = p.listener.as_ref() else {
        anyhow::bail!("this flow is headless — supply the code with complete_with_code()");
    };
    let (mut sock, _) = listener.accept().await?;
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("");
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut got_state = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = Some(crate::antigravity::percent_decode(v)),
                "state" => got_state = Some(v.to_string()),
                _ => {}
            }
        }
    }

    let ok = code.is_some() && got_state.as_deref() == Some(p.state.as_str());
    let (status, page) = if ok {
        (
            "200 OK",
            "<h1>anyhop: authorized</h1><p>You can close this tab.</p>",
        )
    } else {
        ("400 Bad Request", "<h1>anyhop: authorization failed</h1>")
    };
    let html = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{page}"
    );
    let _ = sock.write_all(html.as_bytes()).await;

    let code = code.ok_or_else(|| anyhow::anyhow!("callback without code"))?;
    anyhow::ensure!(
        got_state.as_deref() == Some(p.state.as_str()),
        "state mismatch, retry"
    );
    Ok(code)
}

/// Complete a flow with a code obtained elsewhere (public callback, pasted URL).
pub async fn complete_with_code(p: PendingAuth, code: &str) -> anyhow::Result<AuthOutcome> {
    finish(p, code).await
}

async fn finish(p: PendingAuth, code: &str) -> anyhow::Result<AuthOutcome> {
    let tokens = exchange_code(&p.http, code, &p.redirect_uri).await?;
    let email = fetch_email(&p.http, &tokens.access_token).await;

    // Best-effort project discovery so the snippet is complete.
    let account = Account::new(
        &crate::config::OAuthAccountConfig {
            refresh_token: tokens.refresh_token.clone(),
            email: email.clone(),
            project_id: None,
            account_id: None,
            access_token: None,
            proxy: None,
        },
        "antigravity",
        None,
        p.http.clone(),
        std::sync::Arc::new(crate::config::Tuning::default()),
    );
    let project_id = match account.ensure_project_id(&tokens.access_token).await {
        Ok(p) => Some(p),
        Err(e) => {
            warn!("project id not resolved: {e} (auto-resolved on first request)");
            None
        }
    };

    Ok(AuthOutcome {
        refresh_token: tokens.refresh_token,
        email,
        project_id,
    })
}

/// CLI OAuth flow: prints a TOML snippet on success.
pub async fn run_auth_flow(proxy: Option<String>) -> anyhow::Result<()> {
    let pending = start_auth(proxy.as_deref()).await?;
    if let Some(p) = &proxy {
        println!("Using proxy: {p}");
    }
    println!(
        "\nOpen this link in a browser and sign in to your Google account:\n\n{}\n",
        pending.url
    );
    let _ = std::process::Command::new("xdg-open")
        .arg(&pending.url)
        .spawn();
    println!("Waiting for the callback on localhost:{CALLBACK_PORT} ...");
    println!("Exchanging the authorization code for tokens...");
    let out = complete_auth(pending).await?;

    println!("\nDone! Add the account to anyhop.toml:\n");
    println!("[[providers]]");
    println!("name = \"antigravity\"");
    println!("type = \"antigravity\"");
    println!("strategy = \"fill_first\"");
    println!("\n[[providers.accounts]]");
    if let Some(e) = &out.email {
        println!("email = \"{e}\"");
    }
    println!("refresh_token = \"{}\"", out.refresh_token);
    if let Some(p) = &out.project_id {
        println!("project_id = \"{p}\"");
    }
    println!();
    Ok(())
}

pub fn percent_decode(s: &str) -> String {
    // Byte-based: slicing &s[i+1..i+3] panics when a multi-byte char follows '%'
    // (the callback query is attacker-controllable on localhost).
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod token_rotation_tests {
    use super::*;

    fn temp_storage(tag: &str) -> crate::storage::Storage {
        let path = std::env::temp_dir().join(format!(
            "anyhop-oauth-{tag}-{}-{:?}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        crate::storage::Storage::open(path.to_str().unwrap()).unwrap()
    }

    fn account_with(
        storage: &crate::storage::Storage,
        cfg: crate::config::OAuthAccountConfig,
    ) -> Account {
        Account::new(
            &cfg,
            "antigravity",
            Some(storage),
            reqwest::Client::new(),
            std::sync::Arc::new(crate::config::Tuning::default()),
        )
    }

    /// A refresh token rotated by the issuer and cached earlier must win over the
    /// (stale) one in the config file, otherwise the next restart loses the account.
    #[tokio::test]
    async fn a_rotated_refresh_token_beats_the_configured_one() {
        let storage = temp_storage("rotated");
        storage.save_oauth(
            "antigravity",
            "1//old",
            crate::storage::OAuthRecord {
                access_token: "ya29.fresh".into(),
                expires_at_ms: now_ms() + 3_600_000,
                project_id: Some("proj".into()),
                refresh_token: Some("1//rotated".into()),
            },
        );
        // The write is handed to the storage task; a Flush ack orders it before
        // the read below (and doubles as a check that it is not lost).
        storage.flush_async().await;
        let acc = account_with(
            &storage,
            crate::config::OAuthAccountConfig {
                refresh_token: "1//old".into(),
                email: Some("a@b.c".into()),
                project_id: None,
                account_id: None,
                access_token: None,
                proxy: None,
            },
        );
        // Cached rotation is adopted at construction time.
        assert_eq!(
            acc.state.lock().await.refresh_token.as_deref(),
            Some("1//rotated")
        );
    }

    /// With no cache (fresh install) the configured token is used as-is.
    #[tokio::test]
    async fn without_a_cache_the_configured_token_is_kept() {
        let storage = temp_storage("nocache");
        let acc = account_with(
            &storage,
            crate::config::OAuthAccountConfig {
                refresh_token: "1//config".into(),
                email: None,
                project_id: None,
                account_id: None,
                access_token: None,
                proxy: None,
            },
        );
        assert_eq!(
            acc.state.lock().await.refresh_token.as_deref(),
            Some("1//config")
        );
    }
}

#[cfg(test)]
mod refresh_window_tests {
    use super::needs_refresh;

    const MIN: u64 = 60_000;

    #[test]
    fn a_fresh_token_is_used_as_is() {
        // 1h left, 5 min window: no refresh.
        assert!(!needs_refresh(60 * MIN, 0, 5 * MIN));
    }

    #[test]
    fn a_token_inside_the_window_is_refreshed_early() {
        // 4 min left with a 5 min window: refresh now, not after expiry.
        assert!(needs_refresh(4 * MIN, 0, 5 * MIN));
    }

    #[test]
    fn an_expired_token_is_refreshed() {
        assert!(needs_refresh(0, 1, 5 * MIN));
    }

    #[test]
    fn a_zero_window_refreshes_only_on_expiry() {
        assert!(!needs_refresh(1, 0, 0));
        assert!(needs_refresh(0, 1, 0));
    }
}
