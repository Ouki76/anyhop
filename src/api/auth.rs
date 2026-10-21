use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::proxy::AppState;

#[derive(Clone, serde::Serialize)]
pub struct AuthStateDto {
    kind: String,
    status: String, // waiting | done | error
    url: String,
    message: String,
}

#[derive(Deserialize)]
pub struct AuthStart {
    kind: String,
}

pub async fn auth_start(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthStart>,
) -> Response {
    let is_ag = body.kind == "antigravity";
    if !is_ag && body.kind != "codex" {
        return (StatusCode::BAD_REQUEST, "kind must be antigravity|codex").into_response();
    }
    // A flow for the same provider is already waiting: hand its URL back instead
    // of re-binding the callback port. A flow for a *different* provider is stale
    // from the operator's point of view — cancel it, otherwise "add antigravity"
    // would silently open the abandoned codex URL.
    // (The snapshot is taken and the guard dropped before any await: a
    // MutexGuard held across .await would make this handler non-Send.)
    let waiting: Option<(String, String)> = {
        let g = state.auth_state.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref()
            .filter(|a| a.status == "waiting")
            .map(|a| (a.kind.clone(), a.url.clone()))
    };
    if let Some((pending_kind, pending_url)) = waiting {
        if pending_kind == body.kind {
            return Json(serde_json::json!({"url": pending_url, "resumed": true})).into_response();
        }
        cancel_flow(&state, &pending_kind).await;
        tracing::info!(
            cancelled = %pending_kind,
            starting = %body.kind,
            "replaced a pending OAuth flow"
        );
    }

    let kind = body.kind.clone();
    // (refresh_token, email, project_id, account_id)
    type AuthOutcome = anyhow::Result<(String, Option<String>, Option<String>, Option<String>)>;
    type AuthWait = std::pin::Pin<Box<dyn std::future::Future<Output = AuthOutcome> + Send>>;
    let (url, wait): (String, AuthWait) =
        if is_ag {
            let pending = match crate::antigravity::start_auth(None).await {
                Ok(p) => p,
                Err(e) => return (StatusCode::CONFLICT, e.to_string()).into_response(),
            };
            let url = pending.url.clone();
            (url, Box::pin(async move {
                crate::antigravity::complete_auth(pending)
                    .await
                    .map(|o| (o.refresh_token, o.email, o.project_id, None))
            }))
        } else {
            let pending = match crate::codex::start_auth(None).await {
                Ok(p) => p,
                Err(e) => return (StatusCode::CONFLICT, e.to_string()).into_response(),
            };
            let url = pending.url.clone();
            (url, Box::pin(async move {
                crate::codex::complete_auth(pending)
                    .await
                    .map(|o| (o.refresh_token, o.email, None, o.account_id))
            }))
        };

    *state.auth_state.lock().unwrap_or_else(|e| e.into_inner()) = Some(AuthStateDto {
        kind: kind.clone(),
        status: "waiting".into(),
        url: url.clone(),
        message: "waiting for browser callback".into(),
    });

    let st = state.clone();
    let handle = tokio::spawn(async move {
        // Abandoned flows must not hold the callback port forever.
        // An abandoned OAuth tab must not hold the callback port forever.
        let outcome = tokio::time::timeout(st.tuning.oauth_http_timeout() * 10, wait).await;
        let outcome = match outcome {
            Ok(o) => o,
            Err(_) => {
                let mut g = st.auth_state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(a) = g.as_mut() {
                    a.status = "error".into();
                    a.message = "authorization timed out (5 min)".into();
                }
                return;
            }
        };
        match outcome {
            Ok((refresh_token, email, project_id, account_id)) => {
                let msg = {
                    // Serialize against other dashboard config writers.
                    let _guard = st.config_lock.lock().await;
                    match append_account(&st.config_path, &kind, &refresh_token, email.as_deref(), project_id.as_deref(), account_id.as_deref()) {
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
                st.events.emit_simple("auth", "", "backoff", "account added via dashboard".into());
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
    *state
        .auth_task
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(handle);

    Json(serde_json::json!({"url": url})).into_response()
}

/// Stop a pending OAuth flow (if the kind matches) and free the callback port.
async fn cancel_flow(state: &Arc<AppState>, kind: &str) {
    let handle = {
        let mut g = state.auth_state.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_mut() {
            Some(a) if a.status == "waiting" && (kind.is_empty() || a.kind == kind) => {
                a.status = "cancelled".into();
                a.message = "cancelled".into();
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
pub async fn auth_cancel(State(state): State<Arc<AppState>>) -> Response {
    let pending = state
        .auth_state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|a| a.status == "waiting")
        .map(|a| a.kind.clone());
    let Some(kind) = pending else {
        return Json(serde_json::json!({"cancelled": false})).into_response();
    };
    cancel_flow(&state, &kind).await;
    Json(serde_json::json!({"cancelled": true, "kind": kind})).into_response()
}

pub async fn auth_status(State(state): State<Arc<AppState>>) -> Response {
    let g = state.auth_state.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Json(g).into_response()
}

/// Append an OAuth account to the config file (toml_edit: comments and
/// formatting elsewhere survive). An existing account with the same identity
/// (email for antigravity, account_id for codex) is refreshed in place.
fn append_account(
    path: &str,
    kind: &str,
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

    // Find the first provider of this kind, else create it.
    let idx = providers
        .iter()
        .position(|p| p.get("type").and_then(|t| t.as_str()) == Some(kind));
    let idx = match idx {
        Some(i) => i,
        None => {
            let mut t = toml_edit::Table::new();
            t["name"] = toml_edit::value(kind);
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
        assert_eq!(resume_or_replace(Some(("codex", "u")), "antigravity"), "replace");
        assert_eq!(resume_or_replace(None, "antigravity"), "start");
    }
}
