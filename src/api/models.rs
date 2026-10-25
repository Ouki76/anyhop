use std::collections::HashSet;
use std::sync::{Arc, RwLockReadGuard};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use super::persist::{save_disabled_models, save_model_limits};
use super::{ApiResult, ok_json};
use crate::config::{ModelLimit, ModelLimits};
use crate::limits::{Limits, Resolved};
use crate::proxy::AppState;

#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct ModelLimitsDto {
    /// The number that applies. 0 = nobody states it.
    pub context_window: u64,
    pub max_output_tokens: u64,
    pub max_input_tokens: u64,
}

/// Where each number came from: `override`, `provider` or `unknown`.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
pub struct SourcesDto {
    pub context_window: String,
    pub max_output_tokens: String,
    pub max_input_tokens: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ModelItemDto {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub enabled: bool,
    /// The numbers that apply (override → provider; 0 = unknown).
    #[serde(default)]
    pub limits: ModelLimitsDto,
    /// Provenance per field, so the dashboard can label a provider figure
    /// differently from an operator override.
    #[serde(default)]
    pub sources: SourcesDto,
    /// The operator's own values (0 = not set). These are what the editor's inputs
    /// show, and what the per-field Reset button clears.
    #[serde(default)]
    pub overrides: ModelLimitsDto,
    /// The config key the overrides live under ("" when there are none): a limit
    /// set on the bare name `beta` shows up on `mock/beta` with this set to `beta`.
    #[serde(default)]
    pub limits_source: String,
}

/// `POST /api/models/limits` — set or clear per-model limits.
///
/// A field that is *absent* is left alone, `null` clears it, a number sets it.
/// Clearing the last field removes the entry entirely, so "reset" cannot leave a
/// `[[model_limits]]` block with three zeros behind.
#[derive(Deserialize)]
pub struct LimitsUpdate {
    pub model: String,
    #[serde(default, deserialize_with = "present_field")]
    pub context_window: Field<u64>,
    #[serde(default, deserialize_with = "present_field")]
    pub max_output_tokens: Field<u64>,
    #[serde(default, deserialize_with = "present_field")]
    pub max_input_tokens: Field<u64>,
}

/// Did the client mention this field at all, and with what?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Field<T> {
    #[default]
    Absent,
    Clear,
    Set(T),
}

fn present_field<'de, D>(d: D) -> Result<Field<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<u64>::deserialize(d)?;
    Ok(match v {
        Some(n) => Field::Set(n),
        None => Field::Clear,
    })
}

#[derive(Deserialize)]
pub struct ModelAction {
    pub model: String,
}

// Poison-recovering guards (same policy as `pool::lock`): the set holds plain
// strings with no invariant a panic could corrupt, so a poisoned lock must not
// make every model toggle fail for the rest of the process.
fn dm_read(state: &AppState) -> RwLockReadGuard<'_, HashSet<String>> {
    state
        .disabled_models
        .read()
        .unwrap_or_else(|e| e.into_inner())
}

/// The disabled set as a sorted list (stable output, no duplicate spellings).
fn current_disabled(state: &Arc<AppState>) -> Vec<String> {
    let mut all: Vec<_> = dm_read(state).iter().cloned().collect();
    all.sort();
    all.dedup();
    all
}

/// Persist the whole disabled list through the config writer (validate → write →
/// install) and return any error to the caller.
async fn save_disabled(
    state: &Arc<AppState>,
    list: &[String],
) -> Result<(), Box<axum::response::Response>> {
    save_disabled_models(state, list).await?;
    state.invalidate_catalog();
    Ok(())
}

/// Map a boxed error response to the typed error `ApiResult` wants.
fn boxed(resp: &axum::response::Response) -> super::ApiError {
    match resp.status().as_u16() {
        400 | 422 => super::ApiError::BadRequest("the config was rejected".into()),
        _ => super::ApiError::Internal("cannot write the config file".into()),
    }
}

/// `combo/flash` and `flash` name the same model; also drop the bare half of a
/// `provider/model` id so both spellings agree.
fn normalize(a: &ModelAction) -> &str {
    a.model
        .trim()
        .strip_prefix("combo/")
        .unwrap_or(a.model.trim())
}

/// Longest accepted model id.
///
/// Every `disabled_models` entry ends up in the TOML file, which is rewritten in
/// full on every toggle, and in the event feed. An unbounded id (the field is a
/// bare `String`) meant one request could add a multi-megabyte entry that every
/// later config write had to fsync.
const MAX_MODEL_ID_LEN: usize = 256;

/// Reject model ids that cannot be real catalogue entries.
fn validate_model_action(a: &ModelAction) -> Result<(), super::ApiError> {
    let m = a.model.trim();
    if m.is_empty() {
        return Err(super::ApiError::BadRequest("model is required".into()));
    }
    if m.chars().count() > MAX_MODEL_ID_LEN {
        return Err(super::ApiError::BadRequest(format!(
            "model id is too long (max {MAX_MODEL_ID_LEN} characters)"
        )));
    }
    // Reject control characters: they corrupt the log line, the event payload and
    // (via the TOML writer) make the config file unreadable.
    if m.chars().any(|c| c.is_control()) {
        return Err(super::ApiError::BadRequest(
            "model id must not contain control characters".into(),
        ));
    }
    Ok(())
}

/// Is `model` disabled under either spelling?
///
/// Matches `proxy::access::model_disabled` exactly: the request path blocks a
/// `provider/model` id when either the qualified id or its bare model name is in
/// the set. The toggle has to use the same predicate — it used to test the
/// qualified id only, so a model disabled by its bare name showed as disabled
/// while the toggle kept inserting the qualified id (still disabled, and one more
/// entry every click).
fn is_disabled(dm: &HashSet<String>, model: &str) -> bool {
    if dm.contains(model) {
        return true;
    }
    match model.split_once('/') {
        // "provider/model": the bare model name disables it everywhere.
        Some((_, rest)) => dm.contains(rest),
        // A bare name may also be stored as "combo/<name>".
        None => dm.contains(&format!("combo/{model}")),
    }
}

/// Clear every spelling `is_disabled` recognises — the exact inverse of it.
fn clear_model(dm: &mut HashSet<String>, model: &str) {
    dm.remove(model);
    match model.split_once('/') {
        Some((_, rest)) => {
            dm.remove(rest);
        }
        None => {
            dm.remove(&format!("combo/{model}"));
        }
    }
}

pub async fn models_list(State(state): State<Arc<AppState>>) -> ApiResult {
    let router = state.router.load();
    let disabled = dm_read(&state).clone();
    let mut list = Vec::new();

    let limits = state
        .model_limits
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    for p in &router.providers {
        for m in p.effective_models().await.iter() {
            let id = format!("{}/{}", p.name, m);
            let enabled = !is_disabled(&disabled, &id);
            let (limits_dto, sources, overrides, source) =
                limits_of(&limits, p.discovered_limits(m), &id);
            list.push(ModelItemDto {
                id,
                name: m.to_string(),
                provider: p.name.clone(),
                enabled,
                limits: limits_dto,
                sources,
                overrides,
                limits_source: source,
            });
        }
    }
    for c in &router.combos {
        // Mirrors the request path: "combo/x" and bare "x" both disable a combo.
        let enabled = !is_disabled(&disabled, &c.name);
        let (limits_dto, sources, overrides, source) = limits_of(&limits, None, &c.name);
        list.push(ModelItemDto {
            id: c.name.clone(),
            name: c.name.clone(),
            provider: "combo".into(),
            enabled,
            limits: limits_dto,
            sources,
            overrides,
            limits_source: source,
        });
    }

    ok_json(list)
}

/// Resolve the three layers for one model into wire shape.
///
/// `provider` is what the provider's own catalogue stated (Antigravity, Gemini,
/// DashScope's native list, OpenRouter-shaped gateways); the operator's override
/// wins over it. The returned `overrides` are only what the operator set — that is
/// what the editor's inputs and the per-field Reset button work with.
fn limits_of(
    limits: &ModelLimits,
    provider: Option<Limits>,
    id: &str,
) -> (ModelLimitsDto, SourcesDto, ModelLimitsDto, String) {
    let over = limits.get(id);
    let resolved = Resolved::resolve(
        over.map(|l| Limits {
            context_window: l.context_window,
            max_output_tokens: l.max_output_tokens,
            max_input_tokens: l.max_input_tokens,
        }),
        provider,
    );
    let overrides = ModelLimitsDto {
        context_window: over.map(|l| l.context_window).unwrap_or(0),
        max_output_tokens: over.map(|l| l.max_output_tokens).unwrap_or(0),
        max_input_tokens: over.map(|l| l.max_input_tokens).unwrap_or(0),
    };
    (
        ModelLimitsDto {
            context_window: resolved.limits.context_window,
            max_output_tokens: resolved.limits.max_output_tokens,
            max_input_tokens: resolved.limits.max_input_tokens,
        },
        SourcesDto {
            context_window: resolved.source_of("context_window").to_string(),
            max_output_tokens: resolved.source_of("max_output_tokens").to_string(),
            max_input_tokens: resolved.source_of("max_input_tokens").to_string(),
        },
        overrides,
        over.map(|l| l.model.clone()).unwrap_or_default(),
    )
}

pub async fn models_limits(State(state): State<Arc<AppState>>) -> ApiResult {
    let limits = state
        .model_limits
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut out: Vec<_> = limits
        .entries()
        .iter()
        .cloned()
        .map(|l| {
            let overridden: Vec<String> = l.overridden().into_iter().map(str::to_string).collect();
            (l, overridden)
        })
        .collect();
    out.sort_by(|a, b| a.0.model.cmp(&b.0.model));
    ok_json(
        out.into_iter()
            .map(|(l, overridden)| {
                serde_json::json!({
                    "model": l.model,
                    "context_window": l.context_window,
                    "max_output_tokens": l.max_output_tokens,
                    "max_input_tokens": l.max_input_tokens,
                    "overridden": overridden,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub async fn models_limits_set(
    State(state): State<Arc<AppState>>,
    Json(update): Json<LimitsUpdate>,
) -> ApiResult {
    let model = update.model.trim().to_string();
    if model.is_empty() {
        return Err(super::ApiError::BadRequest("model is required".into()));
    }
    if model.chars().count() > ModelLimit::MAX_MODEL_LEN || model.chars().any(|c| c.is_control()) {
        return Err(super::ApiError::BadRequest(
            "invalid model id (too long, or contains control characters)".into(),
        ));
    }

    // Work from the installed snapshot, not from a pre-lock read: the writer below
    // re-validates and rebuilds from the file, and a concurrent edit must not be
    // overwritten with a stale list.
    let mut list: Vec<ModelLimit> = state
        .model_limits
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .entries()
        .to_vec();

    // The entry the operator is editing: the id itself, or an inherited bare-name
    // entry when they are looking at `provider/model` that inherits from `model`.
    let idx = list.iter().position(|l| l.model == model).or_else(|| {
        // Inherited from a bare-name entry: find the entry it came from.
        let inherited = state
            .model_limits
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&model)?
            .model
            .clone();
        list.iter().position(|l| l.model == inherited)
    });

    let mut entry = match idx {
        // The entry the operator is editing: replace it in place.
        Some(i) if list[i].model == model => list.remove(i),
        // Inherited from a shared bare-name entry: copy its values into a dedicated
        // entry and leave the shared one alone (a `provider/model` edit must not
        // silently change every other provider serving that model).
        Some(i) => ModelLimit {
            model: model.clone(),
            ..list[i].clone()
        },
        None => ModelLimit {
            model: model.clone(),
            ..Default::default()
        },
    };
    apply_field(&mut entry.context_window, update.context_window);
    apply_field(&mut entry.max_output_tokens, update.max_output_tokens);
    apply_field(&mut entry.max_input_tokens, update.max_input_tokens);

    if let Err(e) = entry.check() {
        // `check()` also rejects an all-zero entry; that is the "reset everything"
        // case, which must remove the entry rather than fail.
        let reset = entry.is_empty();
        let existed = idx.is_some_and(|i| list.get(i).is_some_and(|l| l.model == model));
        if !(reset && (existed || idx.is_some())) {
            return Err(super::ApiError::BadRequest(format!("{e}")));
        }
    }
    if !entry.is_empty() {
        list.push(entry.clone());
    }
    list.sort_by(|a, b| a.model.cmp(&b.model));

    save_model_limits(&state, &list)
        .await
        .map_err(|resp| boxed(&resp))?;
    state.invalidate_catalog();
    state.events.emit_simple(
        "models",
        &entry.model,
        "limits",
        if entry.is_empty() {
            "limits reset".to_string()
        } else {
            format!(
                "limits: {}",
                entry
                    .overridden()
                    .into_iter()
                    .map(|f| format!(
                        "{f}={}",
                        match f {
                            "context_window" => entry.context_window,
                            "max_output_tokens" => entry.max_output_tokens,
                            _ => entry.max_input_tokens,
                        }
                    ))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        },
    );
    ok_json(serde_json::json!({
        "model": if entry.is_empty() { model } else { entry.model.clone() },
        "context_window": entry.context_window,
        "max_output_tokens": entry.max_output_tokens,
        "max_input_tokens": entry.max_input_tokens,
        "overridden": entry.overridden(),
    }))
}

fn apply_field(target: &mut u64, field: Field<u64>) {
    match field {
        Field::Absent => {}
        Field::Clear => *target = 0,
        Field::Set(n) => *target = n,
    }
}

pub async fn models_refresh(State(state): State<Arc<AppState>>) -> ApiResult {
    refresh_all_providers(&state).await;
    state.invalidate_catalog();
    state.events.emit_simple(
        "models",
        "",
        "backoff",
        "refreshed models from all providers".into(),
    );
    models_list(State(state)).await
}

/// Fetch model lists from all providers in parallel (10s timeout per provider inside).
pub async fn refresh_all_providers(state: &Arc<AppState>) {
    let router = state.router.load();
    futures::future::join_all(router.providers.iter().map(|p| p.refresh_models())).await;
    // Covers the background refresh task as well as the manual endpoint.
    state.invalidate_catalog();
}

pub async fn model_enable(
    State(state): State<Arc<AppState>>,
    Json(a): Json<ModelAction>,
) -> ApiResult {
    validate_model_action(&a)?;
    let model = normalize(&a).to_string();
    // Compute the list this request wants; the writer validates, writes and
    // installs it. Mutating the live set first meant a concurrent config write
    // could revert it while the request had already answered "enabled".
    let mut list = current_disabled(&state);
    {
        let dm: HashSet<String> = list.iter().cloned().collect();
        let mut dm = dm;
        clear_model(&mut dm, &model);
        list = dm.into_iter().collect();
    }
    list.sort();
    save_disabled(&state, &list).await.map_err(|r| boxed(&r))?;

    state.events.emit_simple(
        "models",
        &model,
        "backoff",
        format!("model '{model}' enabled"),
    );

    ok_json(serde_json::json!({ "model": model, "enabled": true }))
}

pub async fn model_disable(
    State(state): State<Arc<AppState>>,
    Json(a): Json<ModelAction>,
) -> ApiResult {
    validate_model_action(&a)?;
    let model = normalize(&a).to_string();
    let mut list = current_disabled(&state);
    if !list.iter().any(|m| m == &model) {
        list.push(model.clone());
    }
    save_disabled(&state, &list).await.map_err(|r| boxed(&r))?;

    state.events.emit_simple(
        "models",
        &model,
        "dead",
        format!("model '{model}' disabled"),
    );

    ok_json(serde_json::json!({ "model": model, "enabled": false }))
}

pub async fn model_toggle(
    State(state): State<Arc<AppState>>,
    Json(a): Json<ModelAction>,
) -> ApiResult {
    validate_model_action(&a)?;
    let model = normalize(&a).to_string();
    let mut list = current_disabled(&state);
    let new_enabled = {
        let mut dm: HashSet<String> = list.iter().cloned().collect();
        // Toggle must agree with `models_list`/the request path: an entry in any
        // spelling counts as disabled, and enabling clears all of them.
        if is_disabled(&dm, &model) {
            clear_model(&mut dm, &model);
            list = dm.into_iter().collect();
            list.sort();
            true
        } else {
            list.push(model.clone());
            false
        }
    };
    save_disabled(&state, &list).await.map_err(|r| boxed(&r))?;

    let kind = if new_enabled { "backoff" } else { "dead" };
    state.events.emit_simple(
        "models",
        &model,
        kind,
        format!(
            "model '{model}' {}",
            if new_enabled { "enabled" } else { "disabled" }
        ),
    );

    ok_json(serde_json::json!({ "model": model, "enabled": new_enabled }))
}

pub async fn models_enable_all(State(state): State<Arc<AppState>>) -> ApiResult {
    save_disabled(&state, &[]).await.map_err(|r| boxed(&r))?;
    state
        .events
        .emit_simple("models", "", "backoff", "all models enabled".into());
    Ok(StatusCode::OK.into_response())
}

pub async fn models_disable_all(State(state): State<Arc<AppState>>) -> ApiResult {
    let router = state.router.load();
    let mut all_ids = Vec::new();
    for p in &router.providers {
        for m in p.effective_models().await.iter() {
            all_ids.push(format!("{}/{}", p.name, m));
        }
    }
    for c in &router.combos {
        all_ids.push(c.name.clone());
    }

    let mut list = current_disabled(&state);
    for id in all_ids {
        if !list.iter().any(|m| m == &id) {
            list.push(id);
        }
    }
    save_disabled(&state, &list).await.map_err(|r| boxed(&r))?;

    state
        .events
        .emit_simple("models", "", "dead", "all models disabled".into());
    Ok(StatusCode::OK.into_response())
}

/// The `disabled_models` set has three spellings in play (`m`, `provider/m`,
/// `combo/m`). Listing, toggling and the request path must agree, or a toggle
/// inserts a second entry that is already disabled and never undoes the first.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::server::test_support::{MINIMAL, json, state, temp_config};
    use crate::config::{ComboConfig, ProviderConfig};

    fn action(model: &str) -> Json<ModelAction> {
        json(&serde_json::json!({ "model": model }).to_string())
    }

    /// The router the tests expect to be serving (`mock/m`, `mock/m2`, combo `x`).
    ///
    /// Any config write reinstalls the router from the *file*, which in these tests
    /// has no providers — so a test that writes a limit and then looks at the
    /// catalogue has to put this router back.
    fn catalogue() -> crate::providers::ProviderRouter {
        let pcfg: ProviderConfig = toml::from_str(
            r#"
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:1/v1"
            keys = ["sk-test"]
            models = ["m", "m2"]
            "#,
        )
        .expect("provider config");
        let provider = crate::providers::Provider::from_config(
            &pcfg,
            None,
            None,
            None,
            std::sync::Arc::new(crate::config::Tuning::default()),
            std::time::Duration::from_secs(5),
            1,
        )
        .expect("builds offline");
        crate::providers::ProviderRouter {
            providers: vec![provider],
            combos: vec![ComboConfig {
                name: "x".to_string(),
                chain: vec!["mock/m".to_string()],
            }],
        }
    }

    fn install_catalogue(st: &std::sync::Arc<AppState>) {
        st.router.store(std::sync::Arc::new(catalogue()));
    }

    /// A state with one provider serving `mock/m` and one combo `combo/x`.
    fn state_with_catalogue() -> (std::sync::Arc<AppState>, std::path::PathBuf) {
        let path = temp_config(MINIMAL);
        let st = state(&path);
        install_catalogue(&st);
        (st, path)
    }

    // ----- the predicates -----

    #[test]
    fn a_disabled_spelling_matches_every_other_spelling_of_the_same_model() {
        let mut dm = HashSet::new();
        // A bare model name disables it under every provider and as a combo.
        dm.insert("flash".to_string());
        assert!(is_disabled(&dm, "flash"));
        assert!(is_disabled(&dm, "combo/flash"));
        assert!(is_disabled(&dm, "openrouter/flash"));
        assert!(!is_disabled(&dm, "flash-lite"));

        // A combo name stored with the prefix is the same model as the bare one.
        let mut dm = HashSet::new();
        dm.insert("combo/flash".to_string());
        assert!(is_disabled(&dm, "flash"));
        assert!(is_disabled(&dm, "combo/flash"));
        assert!(!is_disabled(&dm, "other"));

        // A qualified id disables exactly the id the listing passes around
        // (`provider/model`); another provider's identically named model is a
        // different entry. (The request path additionally consults the canonical
        // and upstream ids — see the `proxy::access` tests.)
        let mut dm = HashSet::new();
        dm.insert("mock/m".to_string());
        assert!(is_disabled(&dm, "mock/m"));
        assert!(!is_disabled(&dm, "other/m"));
    }

    /// `clear_model` has to be the exact inverse of `is_disabled`: an enable that
    /// leaves one spelling behind leaves the model disabled.
    #[test]
    fn enabling_clears_every_spelling_the_predicate_recognises() {
        for (model, seeded) in [
            ("mock/m", vec!["mock/m", "m"]),
            ("flash", vec!["flash", "combo/flash"]),
            ("combo/flash", vec!["flash", "combo/flash"]),
        ] {
            let mut dm: HashSet<String> = seeded.iter().map(|s| s.to_string()).collect();
            assert!(is_disabled(&dm, model), "{model} must start disabled");
            clear_model(&mut dm, model);
            assert!(
                !is_disabled(&dm, model),
                "enabling {model} left {dm:?} behind"
            );
        }
    }

    #[test]
    fn the_combo_prefix_is_normalised_away() {
        assert_eq!(
            normalize(&ModelAction {
                model: "  combo/x  ".into()
            }),
            "x"
        );
        assert_eq!(
            normalize(&ModelAction {
                model: "mock/m".into()
            }),
            "mock/m"
        );
        assert_eq!(
            normalize(&ModelAction {
                model: " x ".into()
            }),
            "x"
        );
    }

    // ----- the handlers: state, file and idempotence -----

    /// Every toggle rewrites the config. Two toggles must return to the starting
    /// point — the old code inserted a second spelling instead, so the model
    /// stayed disabled and the file grew on every click.
    #[tokio::test]
    async fn toggling_twice_restores_the_model_and_leaves_no_stale_entry() {
        let (st, path) = state_with_catalogue();

        model_toggle(State(st.clone()), action("mock/m"))
            .await
            .expect("disable");
        assert!(is_disabled(&dm_read(&st), "mock/m"));
        model_toggle(State(st.clone()), action("mock/m"))
            .await
            .expect("enable");
        assert!(
            !is_disabled(&dm_read(&st), "mock/m"),
            "the second toggle must re-enable the model"
        );
        assert!(
            dm_read(&st).is_empty(),
            "a stale spelling survived: {:?}",
            dm_read(&st)
        );

        // Disabling by the bare name and toggling by the qualified id must still
        // reach the enabled state (they are the same model).
        model_disable(State(st.clone()), action("m"))
            .await
            .expect("disable by bare name");
        assert!(is_disabled(&dm_read(&st), "mock/m"));
        let resp = model_toggle(State(st.clone()), action("mock/m"))
            .await
            .expect("toggle the qualified id");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["enabled"], true, "{body}");

        // The file agrees with the live set: empty, and still a valid config.
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("valid config");
        assert!(parsed.disabled_models.is_empty(), "{raw}");
        let _ = std::fs::remove_file(&path);
    }

    /// `disable-all` must cover provider models *and* combos; `enable-all` must
    /// clear everything again.
    #[tokio::test]
    async fn disable_all_covers_models_and_combos_and_enable_all_clears_them() {
        let (st, path) = state_with_catalogue();

        models_disable_all(State(st.clone()))
            .await
            .expect("disable all");
        let dm = dm_read(&st).clone();
        assert!(dm.contains("mock/m"), "{dm:?}");
        assert!(dm.contains("mock/m2"), "{dm:?}");
        assert!(dm.contains("x"), "{dm:?}");
        assert!(is_disabled(&dm, "combo/x"));

        // The listing reflects it.
        let listed = models_list(State(st.clone())).await.expect("list");
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(listed.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .all(|m| m["enabled"] == false),
            "{listed}"
        );

        models_enable_all(State(st.clone()))
            .await
            .expect("enable all");
        assert!(dm_read(&st).is_empty());
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("valid config");
        assert!(parsed.disabled_models.is_empty(), "{raw}");
        let _ = std::fs::remove_file(&path);
    }

    // ----- per-model limits -----

    fn limits_update(body: serde_json::Value) -> Json<LimitsUpdate> {
        json(&body.to_string())
    }

    /// View → edit → reset, with the file and the published catalogue in step.
    #[tokio::test]
    async fn a_limit_round_trips_and_a_full_reset_removes_the_entry() {
        let (st, path) = state_with_catalogue();

        let resp = models_limits_set(
            State(st.clone()),
            limits_update(serde_json::json!({
                "model": "mock/m",
                "context_window": 131072,
                "max_output_tokens": 8192,
            })),
        )
        .await
        .expect("set");
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(body["context_window"], 131072);
        assert_eq!(
            body["overridden"],
            serde_json::json!(["context_window", "max_output_tokens"])
        );

        // The runtime map answers to both spellings.
        let live = st.model_limits.read().unwrap().clone();
        assert_eq!(live.get("mock/m").map(|l| l.max_output_tokens), Some(8192));
        assert_eq!(live.get("m").map(|l| l.context_window), Some(131072));

        // The file is valid and carries the entry.
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("valid config");
        assert_eq!(parsed.model_limits.len(), 1, "{raw}");
        assert_eq!(parsed.model_limits[0].context_window, 131072);

        // The catalogue publishes them in the ecosystem's spelling. (The write above
        // reinstalled the router from the file, which has no providers.)
        install_catalogue(&st);
        let listed = crate::proxy::list_models(State(st.clone()), None).await;
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(listed.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let m = listed["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "mock/m")
            .unwrap_or_else(|| panic!("mock/m listed: {listed}"));
        assert_eq!(m["context_length"], 131072, "{listed}");
        assert_eq!(m["max_completion_tokens"], 8192, "{listed}");

        // Clearing one field keeps the others…
        models_limits_set(
            State(st.clone()),
            limits_update(serde_json::json!({
                "model": "mock/m",
                "max_output_tokens": null,
            })),
        )
        .await
        .expect("clear one");
        let live = st.model_limits.read().unwrap().clone();
        let l = live.get("mock/m").expect("still set");
        assert_eq!(l.context_window, 131072);
        assert_eq!(l.max_output_tokens, 0);

        // …and clearing the last one removes the entry from the file entirely.
        models_limits_set(
            State(st.clone()),
            limits_update(serde_json::json!({"model": "mock/m", "context_window": null})),
        )
        .await
        .expect("clear the last");
        assert!(
            st.model_limits.read().unwrap().is_empty(),
            "{:?}",
            st.model_limits.read().unwrap()
        );
        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(
            !raw.contains("model_limits"),
            "left an empty block behind: {raw}"
        );
        let parsed: crate::config::Config = toml::from_str(&raw).expect("valid config");
        assert!(parsed.model_limits.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    /// A limit set on the bare name applies to every provider; editing the
    /// qualified id must create its own entry instead of rewriting the shared one.
    #[tokio::test]
    async fn editing_an_inherited_limit_does_not_rewrite_the_shared_entry() {
        let (st, path) = state_with_catalogue();
        models_limits_set(
            State(st.clone()),
            limits_update(serde_json::json!({"model": "m", "context_window": 32000})),
        )
        .await
        .expect("bare name");

        // The qualified id inherits it… (re-install: the write above rebuilt the
        // router from the file)
        install_catalogue(&st);
        let listed = models_list(State(st.clone())).await.expect("list");
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(listed.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let row = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "mock/m")
            .expect("mock/m listed");
        assert_eq!(row["limits"]["context_window"], 32000, "{listed}");
        assert_eq!(row["limits_source"], "m", "{listed}");

        // …and editing it materialises a dedicated entry.
        models_limits_set(
            State(st.clone()),
            limits_update(serde_json::json!({"model": "mock/m", "max_output_tokens": 4096})),
        )
        .await
        .expect("qualified");
        let live = st.model_limits.read().unwrap().clone();
        assert_eq!(live.entries().len(), 2, "{live:?}");
        assert_eq!(live.get("m").unwrap().context_window, 32000);
        let qualified = live.get("mock/m").expect("dedicated entry");
        assert_eq!(qualified.context_window, 32000, "inherited the window");
        assert_eq!(qualified.max_output_tokens, 4096);
        let _ = std::fs::remove_file(&path);
    }

    /// The layers reach the API in the right order: the provider's own numbers,
    /// an override on top, and each field labelled with where it came from (that
    /// label is what the dashboard shows).
    #[tokio::test]
    async fn provider_layer_and_override_are_reported_with_their_source() {
        let (st, path) = state_with_catalogue();
        let router = st.router.load();
        let p = &router.providers[0];
        // `mock/m` gets a provider-published window; nothing is invented for a
        // model the provider says nothing about.
        p.set_discovered_limits_for_test(std::collections::HashMap::from([(
            "m".to_string(),
            crate::limits::Limits {
                context_window: 524_288,
                max_output_tokens: 16_384,
                max_input_tokens: 0,
            },
        )]));
        drop(router);

        let listed = models_list(State(st.clone())).await.expect("list");
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(listed.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let m = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "mock/m")
            .expect("mock/m listed");
        assert_eq!(m["limits"]["context_window"], 524_288, "{listed}");
        assert_eq!(m["sources"]["context_window"], "provider", "{listed}");
        assert_eq!(m["overrides"]["context_window"], 0, "{listed}");

        // An override wins over the provider figure, field by field.
        models_limits_set(
            State(st.clone()),
            limits_update(serde_json::json!({"model": "mock/m", "max_output_tokens": 4_096})),
        )
        .await
        .expect("override");
        install_catalogue(&st);
        // The router was reinstalled from the file, so re-seed the provider numbers.
        let router = st.router.load();
        router.providers[0].set_discovered_limits_for_test(std::collections::HashMap::from([(
            "m".to_string(),
            crate::limits::Limits {
                context_window: 524_288,
                max_output_tokens: 16_384,
                max_input_tokens: 0,
            },
        )]));
        drop(router);
        let listed = models_list(State(st.clone())).await.expect("list");
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(listed.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        let m = listed
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "mock/m")
            .expect("mock/m listed");
        assert_eq!(m["limits"]["context_window"], 524_288, "{listed}");
        assert_eq!(m["sources"]["context_window"], "provider", "{listed}");
        assert_eq!(m["limits"]["max_output_tokens"], 4_096, "{listed}");
        assert_eq!(m["sources"]["max_output_tokens"], "override", "{listed}");
        let _ = std::fs::remove_file(&path);
    }

    /// Nonsense is refused *before* the file is rewritten.
    #[tokio::test]
    async fn invalid_limits_are_rejected_and_the_file_is_untouched() {
        let (st, path) = state_with_catalogue();
        let before = std::fs::read_to_string(&path).expect("read");

        for bad in [
            serde_json::json!({"model": "", "context_window": 1}),
            serde_json::json!({"model": "mock/m", "context_window": 100, "max_output_tokens": 500}),
            serde_json::json!({"model": "mock/m", "context_window": u64::MAX}),
            serde_json::json!({"model": "mock/m", "max_output_tokens": 0}),
        ] {
            let err = models_limits_set(State(st.clone()), limits_update(bad.clone()))
                .await
                .err()
                .unwrap_or_else(|| panic!("{bad} was accepted"));
            assert!(
                err.to_string().to_lowercase().contains("model")
                    || format!("{err:?}").to_lowercase().contains("bad"),
                "{err:?}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            before,
            "a rejected request rewrote the config"
        );
        assert!(st.model_limits.read().unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
