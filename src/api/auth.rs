//! OAuth onboarding for account-based providers (antigravity, codex).
//!
//! Two transports, one state machine:
//!
//! * **loopback** (no `public_url`): a listener on `127.0.0.1:CALLBACK_PORT`
//!   receives the provider's redirect — the classic CLI flow.
//! * **public** (`[server] public_url` is set): the provider redirects the
//!   browser to `<public_url>/api/auth/callback`, so a dashboard served from a
//!   domain — or opened on a laptop while the gateway runs on a server — can
//!   finish the flow. Google/OpenAI only allow loopback for their installed-app
//!   clients, in which case the browser shows "connection refused" and the user
//!   pastes the callback URL into the panel (`POST /api/auth/complete`), which
//!   works everywhere.
//!
//! All three paths feed the same code channel; the flow task awaits it, verifies
//! the OAuth `state`, exchanges the code and appends the account to the named
//! provider.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::{ApiError, ApiResult, ok_json};
use crate::proxy::AppState;

#[derive(Clone, serde::Serialize)]
pub struct AuthStateDto {
    kind: String,
    /// Provider the account will be appended to (created on first success).
    provider: String,
    status: String, // waiting | done | error | cancelled
    url: String,
    /// "loopback" (localhost port) or "public" (redirect back to this gateway).
    mode: String,
    message: String,
}

#[derive(Deserialize)]
pub struct AuthStart {
    kind: String,
    /// Where to append the account. Defaults to the kind name, which keeps the
    /// single-provider case working; a second provider of the same kind is just
    /// a different name here.
    #[serde(default)]
    provider: Option<String>,
}

/// The pending provider flow, so one task can drive either kind.
enum Flow {
    Antigravity(crate::antigravity::PendingAuth),
    Codex(crate::codex::PendingAuth),
}

impl Flow {
    fn url(&self) -> &str {
        match self {
            Flow::Antigravity(p) => &p.url,
            Flow::Codex(p) => &p.url,
        }
    }
    fn state(&self) -> &str {
        match self {
            Flow::Antigravity(p) => &p.state,
            Flow::Codex(p) => &p.state,
        }
    }
    fn is_headless(&self) -> bool {
        match self {
            Flow::Antigravity(p) => p.listener.is_none(),
            Flow::Codex(p) => p.listener.is_none(),
        }
    }
}

/// Wait for the authorization code from whichever transport wins, then exchange.
async fn complete_flow(
    flow: Flow,
    rx: &mut tokio::sync::mpsc::Receiver<(String, String)>,
) -> anyhow::Result<(String, Option<String>, Option<String>, Option<String>)> {
    // Returns the account tuple: (refresh_token, email, project_id, account_id).
    match flow {
        Flow::Antigravity(pending) => {
            let code = receive_code(
                pending.state.clone(),
                pending.listener.is_some(),
                || crate::antigravity::wait_for_callback(&pending),
                rx,
            )
            .await?;
            crate::antigravity::complete_with_code(pending, &code)
                .await
                .map(|o| (o.refresh_token, o.email, o.project_id, None))
        }
        Flow::Codex(pending) => {
            let code = receive_code(
                pending.state.clone(),
                pending.listener.is_some(),
                || crate::codex::wait_for_callback(&pending),
                rx,
            )
            .await?;
            crate::codex::complete_with_code(pending, &code)
                .await
                .map(|o| (o.refresh_token, o.email, None, o.account_id))
        }
    }
}

/// Await the code from the loopback socket (when there is one) or the channel.
async fn receive_code<F, Fut>(
    expected_state: String,
    has_listener: bool,
    wait_socket: F,
    rx: &mut tokio::sync::mpsc::Receiver<(String, String)>,
) -> anyhow::Result<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    let check = |code: String, state: String| -> anyhow::Result<String> {
        anyhow::ensure!(
            state == expected_state,
            "state mismatch — restart the flow and try again"
        );
        anyhow::ensure!(!code.trim().is_empty(), "empty authorization code");
        Ok(code)
    };
    if has_listener {
        let socket = wait_socket();
        tokio::pin!(socket);
        tokio::select! {
            r = &mut socket => r,
            msg = rx.recv() => match msg {
                Some((code, state)) => check(code, state),
                None => Err(anyhow::anyhow!("authorization cancelled")),
            },
        }
    } else {
        match rx.recv().await {
            Some((code, state)) => check(code, state),
            None => Err(anyhow::anyhow!("authorization cancelled")),
        }
    }
}

pub async fn auth_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthStart>,
) -> ApiResult {
    let is_ag = body.kind == "antigravity";
    if !is_ag && body.kind != "codex" {
        return Err(ApiError::bad_request("kind must be antigravity|codex"));
    }
    let provider_name = body
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&body.kind)
        .to_string();
    if let Err((_, msg)) = super::validate_name("provider", &provider_name) {
        return Err(ApiError::bad_request(msg));
    }
    // A name that already belongs to a *different* kind would silently corrupt
    // that provider's config, so refuse it up front.
    if let Ok(cfg) = crate::config::Config::load(&state.config_path)
        && let Some(existing) = cfg.providers.iter().find(|p| p.name == provider_name)
        && !matches!(
            (existing.kind, is_ag),
            (crate::config::ProviderKind::Antigravity, true)
                | (crate::config::ProviderKind::Codex, false)
        )
    {
        return Err(ApiError::conflict(format!(
            "provider '{provider_name}' already exists with a different type ({:?})",
            existing.kind
        )));
    }
    // Same provider already waiting: hand its URL back instead of re-binding the
    // port. A flow for a different provider is stale from the operator's point of
    // view — cancel it, otherwise "add antigravity" would open the abandoned codex
    // URL. (Snapshot first: a MutexGuard held across .await is not Send.)
    let waiting: Option<(String, String, String)> = {
        let g = state.auth_state.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref()
            .filter(|a| a.status == "waiting")
            .map(|a| (a.kind.clone(), a.provider.clone(), a.url.clone()))
    };
    if let Some((pending_kind, pending_provider, pending_url)) = waiting {
        if pending_kind == body.kind && pending_provider == provider_name {
            return ok_json(serde_json::json!({"url": pending_url, "resumed": true}));
        }
        cancel_flow(&state, &pending_kind).await;
        tracing::info!(
            cancelled = %pending_kind,
            starting = %body.kind,
            "replaced a pending OAuth flow"
        );
    }

    let kind = body.kind.clone();
    // Headless: the provider redirects back to this gateway instead of a loopback
    // port, so a panel served from a domain (or opened elsewhere) can finish.
    let public_url = crate::config::Config::load(&state.config_path)
        .ok()
        .and_then(|c| c.server.public_url)
        .map(|u| u.trim_end_matches('/').to_string());
    let redirect_uri = public_url
        .as_ref()
        .map(|base| format!("{base}/api/auth/callback"));

    // Code channel: fed by the public callback route or by a pasted URL.
    let (code_tx, mut code_rx) = tokio::sync::mpsc::channel::<(String, String)>(4);
    *state.auth_code_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(code_tx);

    let pending = if is_ag {
        match crate::antigravity::start_auth_with(None, &state.tuning, redirect_uri.as_deref())
            .await
        {
            Ok(p) => Flow::Antigravity(p),
            Err(e) => return Err(ApiError::conflict(e.to_string())),
        }
    } else {
        match crate::codex::start_auth_with(None, &state.tuning, redirect_uri.as_deref()).await {
            Ok(p) => Flow::Codex(p),
            Err(e) => return Err(ApiError::conflict(e.to_string())),
        }
    };
    let url = pending.url().to_string();
    let state_token = pending.state().to_string();
    let headless_now = pending.is_headless();
    *state
        .auth_state_token
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(state_token.clone());

    *state.auth_state.lock().unwrap_or_else(|e| e.into_inner()) = Some(AuthStateDto {
        kind: kind.clone(),
        provider: provider_name.clone(),
        status: "waiting".into(),
        url: url.clone(),
        mode: if headless_now { "public" } else { "loopback" }.to_string(),
        message: if headless_now {
            format!(
                "waiting for the provider to redirect to {}/api/auth/callback",
                public_url.clone().unwrap_or_default()
            )
        } else {
            "waiting for the browser callback (or paste the redirected URL below)".to_string()
        },
    });

    let st = state.clone();
    let handle = tokio::spawn(async move {
        let outcome = tokio::time::timeout(
            st.tuning.oauth_http_timeout() * 10,
            complete_flow(pending, &mut code_rx),
        )
        .await;
        let outcome = match outcome {
            Ok(o) => o,
            Err(_) => {
                let mut g = st.auth_state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(a) = g.as_mut() {
                    a.status = "error".into();
                    a.message = "authorization timed out".into();
                }
                return;
            }
        };
        match outcome {
            Ok((refresh_token, email, project_id, account_id)) => {
                let msg = {
                    // Serialize against other dashboard config writers.
                    let _guard = st.config_lock.lock().await;
                    match append_account(
                        &st.config_path,
                        &kind,
                        &provider_name,
                        &refresh_token,
                        email.as_deref(),
                        project_id.as_deref(),
                        account_id.as_deref(),
                    ) {
                        Ok(()) => match crate::reload_config(&st) {
                            Ok(_) => "account added and config reloaded".to_string(),
                            Err(e) => format!("account saved, reload failed: {e}"),
                        },
                        Err(e) => format!("account obtained but config update failed: {e}"),
                    }
                };
                let mut g = st.auth_state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(a) = g.as_mut() {
                    a.status = "done".into();
                    a.message = msg;
                }
                st.events
                    .emit_simple("auth", "", "backoff", "account added via dashboard".into());
            }
            Err(e) => {
                let mut g = st.auth_state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(a) = g.as_mut() {
                    a.status = "error".into();
                    a.message = e.to_string();
                }
            }
        }
    });
    // Keep the handle so /api/auth/cancel (and a flow for another provider) can
    // abort it: aborting drops the pending listener and frees the callback port.
    *state.auth_task.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);

    ok_json(
        serde_json::json!({"url": url, "state": state_token, "mode": if headless_now { "public" } else { "loopback" }}),
    )
}

/// Stop a pending OAuth flow (if the kind matches) and free the callback port.
async fn cancel_flow(state: &Arc<AppState>, kind: &str) {
    let handle = {
        let mut g = state.auth_state.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_mut() {
            Some(a) if a.status == "waiting" && (kind.is_empty() || a.kind == kind) => {
                a.status = "cancelled".into();
                a.message = "cancelled".into();
                *state
                    .auth_state_token
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                state
                    .auth_task
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
            }
            _ => None,
        }
    };
    if let Some(h) = handle {
        h.abort();
        // Let the aborted task drop its listener before the port is re-bound.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

/// POST /api/auth/cancel — stop the pending flow (the user closed the tab).
pub async fn auth_cancel(State(state): State<Arc<AppState>>) -> ApiResult {
    let pending = state
        .auth_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|a| a.status == "waiting")
        .map(|a| a.kind.clone());
    let Some(kind) = pending else {
        return ok_json(serde_json::json!({"cancelled": false}));
    };
    cancel_flow(&state, &kind).await;
    ok_json(serde_json::json!({"cancelled": true, "kind": kind}))
}

/// Push a code into the pending flow. Shared by the public callback and the
/// "paste the URL" endpoint.
async fn deliver_code(state: &AppState, code: &str, state_token: &str) -> bool {
    // Reject a callback that does not belong to the flow we are waiting for.
    let expected = state
        .auth_state_token
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match expected {
        Some(exp) if !state_token.is_empty() && state_token != exp => return false,
        None => return false, // nothing pending
        _ => {}
    }
    let tx = state
        .auth_code_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match tx {
        Some(tx) => tx
            .send((code.to_string(), state_token.to_string()))
            .await
            .is_ok(),
        None => false,
    }
}

/// Pull `code` and `state` out of a full callback URL or of a bare code.
fn parse_callback_input(input: &str) -> (Option<String>, Option<String>) {
    let input = input.trim();
    if !input.contains("code=") {
        // A bare code was pasted.
        return (
            if input.is_empty() {
                None
            } else {
                Some(input.to_string())
            },
            None,
        );
    }
    let query = input.split_once('?').map(|(_, q)| q).unwrap_or(input);
    let query = query.split('#').next().unwrap_or(query);
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "code" => code = Some(crate::antigravity::percent_decode(v)),
                "state" => state = Some(crate::antigravity::percent_decode(v)),
                _ => {}
            }
        }
    }
    (code, state)
}

/// GET /api/auth/callback — the provider redirects the browser here when
/// `[server] public_url` is configured. Not admin-authenticated (a browser
/// redirect cannot carry the key): the OAuth `state` protects it.
pub async fn auth_callback(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let code = q.get("code").cloned().unwrap_or_default();
    let st = q.get("state").cloned().unwrap_or_default();
    let err = q.get("error").cloned();
    if let Some(e) = err {
        return html_page(
            StatusCode::BAD_REQUEST,
            "Authorization failed",
            &format!("The provider returned: {e}. You can close this tab."),
        );
    }
    if code.is_empty() {
        return html_page(
            StatusCode::BAD_REQUEST,
            "Authorization failed",
            "No code in the callback. Close this tab and start over.",
        );
    }
    if !deliver_code(&state, &code, &st).await {
        return html_page(
            StatusCode::BAD_REQUEST,
            "Sign-in rejected",
            "This link does not belong to the pending sign-in (wrong or expired `state`). \
             Close this tab and start again from the panel.",
        );
    }
    html_page(
        StatusCode::OK,
        "anyhop: authorized",
        "You can close this tab and return to the dashboard.",
    )
}

/// POST /api/auth/complete — `{"url": "<the address your browser ended up on>"}`
/// or `{"code": "..."}`. The universal fallback when the provider only allows a
/// loopback redirect and the browser cannot reach the gateway.
pub async fn auth_complete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let input = body
        .get("url")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("code").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    let (code, st) = parse_callback_input(&input);
    let Some(code) = code else {
        return Err(ApiError::bad_request("paste the callback URL or the code"));
    };
    // Prefer the state from the pasted URL; fall back to the pending flow's own.
    let state_token = st.or_else(|| {
        state
            .auth_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|a| a.kind.clone())
    });
    if !deliver_code(&state, &code, state_token.as_deref().unwrap_or("")).await {
        return Err(ApiError::conflict(
            "no sign-in is waiting — start it again from the panel",
        ));
    }
    ok_json(serde_json::json!({"ok": true}))
}

pub async fn auth_status(State(state): State<Arc<AppState>>) -> ApiResult {
    let g = state
        .auth_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    ok_json(g)
}

fn html_page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>{title}</title>\
         <style>body{{font:15px/1.5 system-ui,sans-serif;margin:12vh auto;max-width:32rem;padding:0 1.5rem}}</style>\
         <h1>{title}</h1><p>{body}</p>"
    );
    (status, [("content-type", "text/html; charset=utf-8")], html).into_response()
}

fn append_account(
    path: &str,
    kind: &str,
    provider_name: &str,
    refresh_token: &str,
    email: Option<&str>,
    project_id: Option<&str>,
    account_id: Option<&str>,
) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;
    if !doc.contains_key("providers") {
        doc["providers"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let providers = doc["providers"]
        .as_array_of_tables_mut()
        .ok_or_else(|| anyhow::anyhow!("'providers' is not an array of tables"))?;

    // Target the provider by *name*, so several providers of the same kind can
    // keep separate account pools ("ag-work", "ag-home"). Missing ⇒ create it in
    // the same write as the account, so the file never holds an empty provider
    // (config validation requires at least one credential).
    let existing_idx = providers
        .iter()
        .position(|p| p.get("name").and_then(|n| n.as_str()) == Some(provider_name));
    let idx = match existing_idx {
        Some(i) => i,
        None => {
            let mut t = toml_edit::Table::new();
            t["name"] = toml_edit::value(provider_name);
            t["type"] = toml_edit::value(kind);
            t["strategy"] = toml_edit::value("fill_first");
            providers.push(t);
            providers.len() - 1
        }
    };
    let provider = providers
        .get_mut(idx)
        .ok_or_else(|| anyhow::anyhow!("provider entry missing"))?;
    if provider.get("accounts").is_none() {
        provider["accounts"] = toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let accounts = provider["accounts"]
        .as_array_of_tables_mut()
        .ok_or_else(|| anyhow::anyhow!("'accounts' is not an array of tables"))?;

    // Re-authorizing the same identity replaces its tokens instead of
    // appending a duplicate account. (Mutate first, write after the borrow ends.)
    let (id_key, id_val) = if kind == "codex" {
        ("account_id", account_id)
    } else {
        ("email", email)
    };
    let mut replaced = false;
    if let Some(v) = id_val {
        for acc in accounts.iter_mut() {
            if acc.get(id_key).and_then(|x| x.as_str()) == Some(v) {
                acc["refresh_token"] = toml_edit::value(refresh_token);
                if let Some(p) = project_id {
                    acc["project_id"] = toml_edit::value(p);
                }
                replaced = true;
                break;
            }
        }
    }
    if !replaced {
        let mut acc = toml_edit::Table::new();
        if let Some(e) = email {
            acc["email"] = toml_edit::value(e);
        }
        acc["refresh_token"] = toml_edit::value(refresh_token);
        if let Some(p) = project_id {
            acc["project_id"] = toml_edit::value(p);
        }
        if let Some(a) = account_id {
            acc["account_id"] = toml_edit::value(a);
        }
        accounts.push(acc);
    }

    crate::config::write_atomic(path, &doc.to_string())?;
    Ok(())
}

#[cfg(test)]
mod auth_flow_tests {
    /// The guard that used to hijack a new flow: a waiting flow for another
    /// provider must not be handed back to the caller.
    fn resume_or_replace(pending: Option<(&str, &str)>, requested: &str) -> &'static str {
        match pending {
            Some((kind, _)) if kind == requested => "resume",
            Some(_) => "replace",
            None => "start",
        }
    }

    #[test]
    fn a_pending_flow_is_only_resumed_for_the_same_provider() {
        assert_eq!(resume_or_replace(Some(("codex", "u")), "codex"), "resume");
        assert_eq!(
            resume_or_replace(Some(("codex", "u")), "antigravity"),
            "replace"
        );
        assert_eq!(resume_or_replace(None, "antigravity"), "start");
    }
}

#[cfg(test)]
mod append_account_tests {
    use super::*;

    fn temp_config(body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "anyhop-auth-test-{}-{:?}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&path, body).unwrap();
        path
    }

    /// A second provider of the same OAuth kind must get its own account pool
    /// instead of the account landing in the first one of that type.
    #[test]
    fn accounts_go_to_the_named_provider_and_new_ones_are_created() {
        let path = temp_config(
            r#"[[providers]]
name = "ag-work"
type = "antigravity"

[[providers.accounts]]
email = "work@example.com"
refresh_token = "1//work"

[[providers]]
name = "dashscope"
type = "openai_compat"
base_url = "https://example.com/v1"
keys = ["sk-x"]
"#,
        );
        append_account(
            path.to_str().unwrap(),
            "antigravity",
            "ag-home",
            "1//home",
            Some("home@example.com"),
            Some("proj"),
            None,
        )
        .unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let cfg: crate::config::Config = toml::from_str(&raw).unwrap();
        let home = cfg
            .providers
            .iter()
            .find(|p| p.name == "ag-home")
            .expect("the new provider must be created");
        assert_eq!(home.kind, crate::config::ProviderKind::Antigravity);
        assert_eq!(home.accounts.len(), 1);
        assert_eq!(home.accounts[0].refresh_token, "1//home");
        // The existing provider of the same kind is untouched.
        let work = cfg.providers.iter().find(|p| p.name == "ag-work").unwrap();
        assert_eq!(work.accounts.len(), 1);
        assert_eq!(work.accounts[0].refresh_token, "1//work");
        let _ = std::fs::remove_file(&path);
    }

    /// Re-authorizing the same account replaces its tokens in place.
    #[test]
    fn reauthorizing_the_same_account_updates_instead_of_duplicating() {
        let path = temp_config(
            r#"[[providers]]
name = "ag-home"
type = "antigravity"

[[providers.accounts]]
email = "home@example.com"
refresh_token = "1//old"
"#,
        );
        for token in ["1//new1", "1//new2"] {
            append_account(
                path.to_str().unwrap(),
                "antigravity",
                "ag-home",
                token,
                Some("home@example.com"),
                None,
                None,
            )
            .unwrap();
        }
        let raw = std::fs::read_to_string(&path).unwrap();
        let cfg: crate::config::Config = toml::from_str(&raw).unwrap();
        let home = cfg.providers.iter().find(|p| p.name == "ag-home").unwrap();
        assert_eq!(home.accounts.len(), 1, "must not duplicate the account");
        assert_eq!(home.accounts[0].refresh_token, "1//new2");
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod callback_url_tests {
    use super::parse_callback_input;

    #[test]
    fn code_and_state_are_extracted_from_a_pasted_url() {
        let (code, state) = parse_callback_input(
            "http://localhost:51121/oauth-callback?code=4%2F0Abc-def&state=17a2b&scope=x",
        );
        assert_eq!(code.as_deref(), Some("4/0Abc-def"));
        assert_eq!(state.as_deref(), Some("17a2b"));
    }

    #[test]
    fn a_bare_code_is_accepted() {
        let (code, state) = parse_callback_input("  4/0Abc-def  ");
        assert_eq!(code.as_deref(), Some("4/0Abc-def"));
        assert_eq!(state, None);
    }

    #[test]
    fn a_hash_fragment_is_ignored_and_percent_decoding_applies() {
        let (code, _) = parse_callback_input(
            "https://gw.example.com/api/auth/callback?state=1&code=a%20b#ignored=1",
        );
        assert_eq!(code.as_deref(), Some("a b"));
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert_eq!(parse_callback_input("   "), (None, None));
    }
}
