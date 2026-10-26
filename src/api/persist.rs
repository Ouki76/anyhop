use std::sync::Arc;

use crate::proxy::AppState;

/// Persist the **whole** client-key list: validate, build, write, install.
///
/// The caller passes the list it wants (current list ± its change); it does not
/// mutate the live map itself. That order fixes three defects at once:
///
/// * the old path spliced the file with `toml_edit` and wrote it *without*
///   running `Config::validate`, so two API-reachable inputs (a key added on a
///   gateway with no `api_key`, two keys sharing a `name`) produced a file that
///   every later writer, `POST /api/reload`, SIGHUP and the next start rejected —
///   the admin API locked itself out;
/// * the snapshot was taken *before* `config_lock`, so two concurrent editors
///   could write each other's stale list (a revoked key came back);
/// * a failed write was swallowed and the handler still answered 2xx.
///
/// Installing happens inside `commit_config_text`, which rebuilds the live map
/// from the file — so state and disk can no longer disagree.
pub(crate) async fn save_client_keys(
    state: &Arc<AppState>,
    keys: &[crate::config::ClientKeyConfig],
) -> Result<(), Box<axum::response::Response>> {
    let _guard = state.config_lock.lock().await;
    let text = client_keys_text(&state.config_path, keys).map_err(io_error)?;
    commit_config_text(state, &text).await.map(|_| ())
}

/// Run `edit` against a *fresh* snapshot taken **while `config_lock` is held**.
///
/// Every persisted list on this API is a whole-list rewrite, so the caller has to
/// read the current value, change one entry and write the result back. Reading
/// before the lock makes that a read-modify-write race: two dashboard tabs each
/// snapshot `[a, b]`, the first writes `[a', b]`, the second writes `[a, b']`, and
/// the first edit is gone from the TOML *and* from memory. `persist.rs`'s own docs
/// describe exactly this bug as fixed for client keys; the same pattern remained
/// for `disabled_models` and `[[model_limits]]`.
///
/// `edit` therefore receives the list and returns the list it wants, and it may
/// reject with a response of its own.
pub(crate) async fn with_locked_list<T, F>(
    state: &Arc<AppState>,
    read: impl Fn(&AppState) -> T,
    edit: F,
    write: impl Fn(&str, &T) -> anyhow::Result<String>,
) -> Result<(), Box<axum::response::Response>>
where
    F: FnOnce(T) -> Result<T, Box<axum::response::Response>>,
{
    let _guard = state.config_lock.lock().await;
    let current = read(state);
    let next = edit(current)?;
    let text = write(&state.config_path, &next).map_err(io_error)?;
    commit_config_text(state, &text).await.map(|_| ())
}

/// A config-file read/parse failure is *our* problem, not the caller's: 404 used to
/// make a permissions or ENOSPC error look like a wrong URL.
fn io_error(e: anyhow::Error) -> Box<axum::response::Response> {
    use axum::response::IntoResponse;
    Box::new(super::ApiError::internal(format!("cannot read the config file: {e}")).into_response())
}

/// Validate an edited config document *before* writing it, then write + reload.
///
/// Writing first and reloading second (the old pattern) could leave a file on
/// disk that the running gateway refuses to load — a config that bricks the next
/// restart. Here a bad edit is rejected while the previous file is still intact.
pub(crate) async fn write_validated(
    state: &Arc<AppState>,
    doc: &toml_edit::DocumentMut,
) -> Result<(), Box<axum::response::Response>> {
    commit_config_text(state, &doc.to_string())
        .await
        .map(|_| ())
}

/// Parse, validate, build the router, write, swap — in that order.
///
/// `crate::apply_config` does the build before the write, so a config that the
/// validator accepts but the runtime rejects (a proxy URL `reqwest` cannot parse,
/// for instance) is refused while the old file is still the one on disk. Returns
/// the number of providers that were installed.
pub(crate) async fn commit_config_text(
    state: &Arc<AppState>,
    text: &str,
) -> Result<usize, Box<axum::response::Response>> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let parsed: crate::config::Config = match toml::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            return Err(Box::new(
                (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response(),
            ));
        }
    };
    if let Err(e) = parsed.validate() {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response(),
        ));
    }
    match crate::apply_config(state, parsed, text) {
        Ok(n) => Ok(n),
        // A rejected build never reached the disk; a write failure left the file
        // (and the live router) as it was — report which one it was.
        Err(crate::ConfigApplyError::Build(e)) => Err(Box::new(
            (StatusCode::BAD_REQUEST, format!("invalid config: {e}")).into_response(),
        )),
        Err(crate::ConfigApplyError::Write(e)) => Err(Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot write config: {e}"),
            )
                .into_response(),
        )),
    }
}

/// toml_edit keeps the rest of the file (comments, key order) untouched.
pub fn client_keys_text(
    path: &str,
    keys: &[crate::config::ClientKeyConfig],
) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;

    let mut arr = toml_edit::ArrayOfTables::new();
    for k in keys {
        let mut t = toml_edit::Table::new();
        t["key"] = toml_edit::value(k.key.clone());
        if let Some(name) = &k.name {
            t["name"] = toml_edit::value(name.clone());
        }
        let mut models = toml_edit::Array::new();
        for m in &k.models {
            models.push(m.as_str());
        }
        t["models"] = toml_edit::value(models);
        if let Some(ca) = k.created_at {
            t["created_at"] = toml_edit::value(ca as i64);
        }
        if let Some(rpm) = k.rpm {
            t["rpm"] = toml_edit::value(rpm as i64);
        }
        if let Some(burst) = k.burst {
            t["burst"] = toml_edit::value(burst as i64);
        }
        // Without this every client-key edit silently dropped the key's
        // concurrency cap, and the next reload fell back to "unlimited".
        if let Some(max_concurrent) = k.max_concurrent {
            t["max_concurrent"] = toml_edit::value(max_concurrent as i64);
        }
        arr.push(t);
    }
    doc["client_keys"] = toml_edit::Item::ArrayOfTables(arr);

    Ok(doc.to_string())
}

pub fn model_limits_text(
    path: &str,
    limits: &[crate::config::ModelLimit],
) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;

    let mut arr = toml_edit::ArrayOfTables::new();
    for l in limits {
        let mut t = toml_edit::Table::new();
        t["model"] = toml_edit::value(l.model.clone());
        // Only the fields that carry a value: an explicit `0` in the file is
        // indistinguishable from "unset" anyway, and a shorter diff is easier to
        // review when the dashboard edits one number.
        if l.context_window > 0 {
            t["context_window"] = toml_edit::value(l.context_window as i64);
        }
        if l.max_output_tokens > 0 {
            t["max_output_tokens"] = toml_edit::value(l.max_output_tokens as i64);
        }
        if l.max_input_tokens > 0 {
            t["max_input_tokens"] = toml_edit::value(l.max_input_tokens as i64);
        }
        arr.push(t);
    }
    if limits.is_empty() {
        // Leave no empty header behind (`[[model_limits]]` with no entries).
        doc.remove("model_limits");
    } else {
        doc["model_limits"] = toml_edit::Item::ArrayOfTables(arr);
    }

    Ok(doc.to_string())
}

pub fn disabled_models_text(path: &str, disabled: &[String]) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let mut doc = raw.parse::<toml_edit::DocumentMut>()?;

    let mut arr = toml_edit::Array::new();
    for s in disabled {
        arr.push(s.as_str());
    }
    doc["disabled_models"] = toml_edit::value(arr);

    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!(
            "anyhop-persist-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("anyhop.toml");
        std::fs::write(&path, "listen = \"127.0.0.1:1\"\n").expect("seed");
        let s = path.to_str().expect("utf-8").to_string();
        (path, s)
    }

    fn key(
        rpm: Option<u32>,
        burst: Option<u32>,
        max_concurrent: Option<u32>,
    ) -> crate::config::ClientKeyConfig {
        crate::config::ClientKeyConfig {
            key: "sk-tenant".to_string(),
            name: Some("tenant".to_string()),
            models: vec!["m1".to_string()],
            created_at: Some(1_700_000_000),
            rpm,
            burst,
            max_concurrent,
        }
    }

    /// F: `max_concurrent` was missing from the writer, so every client-key edit
    /// (add/update/delete of *any* key) rewrote the file without it — silently
    /// removing every tenant's concurrency cap. The next reload then fell back to
    /// `[server] client_key_max_concurrent` (usually unlimited).
    #[test]
    fn the_client_key_round_trip_keeps_max_concurrent() {
        let (dir, path) = scratch("max-concurrent");
        let keys = vec![key(Some(60), Some(5), Some(3))];
        let text = client_keys_text(&path, &keys).expect("build");
        crate::config::write_atomic(&path, &text).expect("write");

        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("parse back");
        assert_eq!(
            parsed.client_keys[0].max_concurrent,
            Some(3),
            "the concurrency cap was dropped by the TOML round-trip"
        );
        // The rest of the record survives too.
        assert_eq!(parsed.client_keys[0].rpm, Some(60));
        assert_eq!(parsed.client_keys[0].burst, Some(5));
        assert_eq!(parsed.client_keys[0].models, vec!["m1".to_string()]);

        // An unset cap stays unset (no bogus 0 written).
        let keys = vec![key(None, None, None)];
        let text = client_keys_text(&path, &keys).expect("build");
        crate::config::write_atomic(&path, &text).expect("write");
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("parse back");
        assert_eq!(parsed.client_keys[0].max_concurrent, None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rewritten config must stay owner-only (it holds no client secrets here,
    /// but the same writer produces the provider config).
    #[cfg(unix)]
    #[test]
    fn rewriting_client_keys_keeps_the_file_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, path) = scratch("perms");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let text = client_keys_text(&path, &[key(None, None, Some(1))]).expect("build");
        crate::config::write_atomic(&path, &text).expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o077, 0, "config mode {mode:o} is not owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The disabled-model list is a plain array in the config file. Rewriting it
    /// must not duplicate the key (each toggle used to append another array) and
    /// must leave the rest of the file — comments included — alone.
    #[test]
    fn the_disabled_models_round_trip_keeps_one_array() {
        let (dir, path) = scratch("disabled");
        std::fs::write(
            &path,
            "# operator notes: keep me\nlisten = \"127.0.0.1:1\"\n",
        )
        .expect("seed");
        for _ in 0..2 {
            let text =
                disabled_models_text(&path, &["a/model".into(), "combo/x".into()]).expect("build");
            crate::config::write_atomic(&path, &text).expect("write");
        }

        let raw = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            raw.matches("disabled_models").count(),
            1,
            "a second save duplicated the key:\n{raw}"
        );
        assert!(raw.contains("keep me"), "comments must survive:\n{raw}");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("parse back");
        assert_eq!(
            parsed.disabled_models,
            vec!["a/model".to_string(), "combo/x".to_string()]
        );

        // Removing every entry leaves an empty array, not a stale one.
        let text = disabled_models_text(&path, &[]).expect("build");
        crate::config::write_atomic(&path, &text).expect("clear");
        let raw = std::fs::read_to_string(&path).expect("read");
        let parsed: crate::config::Config = toml::from_str(&raw).expect("parse back");
        assert!(parsed.disabled_models.is_empty(), "{raw}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----- commit_config_text: build before write -----

    /// `commit_config_text` is the single write path for the raw config editor and
    /// every other config mutation. Nothing may reach the disk before the new
    /// document has been parsed, validated *and* built: a file that the runtime
    /// refuses would brick the next start.
    #[tokio::test]
    async fn a_rejected_document_never_reaches_the_disk() {
        use crate::api::server::test_support::{MINIMAL, state, temp_config};

        let path = temp_config(MINIMAL);
        let st = state(&path);
        let before = std::fs::read_to_string(&path).expect("read");

        // 1) Not TOML at all.
        let err = commit_config_text(&st, "providers = [[")
            .await
            .expect_err("parse error");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);

        // 2) Valid TOML, rejected by Config::validate (a provider with no keys).
        let keyless = r#"
            [[providers]]
            name = "mock"
            type = "openai_compat"
            base_url = "http://127.0.0.1:1/v1"

            [server]
            listen = "127.0.0.1:18080"
        "#;
        let err = commit_config_text(&st, keyless)
            .await
            .expect_err("no keys must be refused");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "an invalid document must leave the old config intact"
        );

        // 3) Valid and buildable *looking*, but the runtime cannot build it: a
        //    proxy URL reqwest rejects. This is the case only a build-first order
        //    catches (validate() cannot know).
        let unbuildable = MINIMAL.replace(
            "listen = \"127.0.0.1:18080\"",
            "listen = \"127.0.0.1:18080\"\nproxy = \"http://[\"",
        );
        let err = commit_config_text(&st, &unbuildable)
            .await
            .expect_err("an unbuildable config must be refused");
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "write-then-build would have left the broken config on disk"
        );
        // Nothing was swapped into the live router either.
        assert_eq!(st.router.load().providers.len(), 0);

        // A document that does build is written and installed.
        let n = commit_config_text(&st, MINIMAL)
            .await
            .expect("valid config");
        assert_eq!(n, 1, "one provider installed");
        assert_ne!(std::fs::read_to_string(&path).unwrap(), "", "written");
        assert_eq!(st.router.load().providers.len(), 1);
        assert_eq!(st.router.load().providers[0].name, "mock");
    }

    /// A write failure must be reported as a server error, not as "invalid
    /// config" and not as success: the operator has to know the file did not
    /// change.
    #[tokio::test]
    async fn an_unwritable_config_reports_a_server_error() {
        use crate::api::server::test_support::{MINIMAL, state};

        let dir =
            std::env::temp_dir().join(format!("anyhop-persist-unwritable-{}", std::process::id()));
        let path = dir.join("state").join("anyhop.toml");
        let st = state(&path);
        let err = commit_config_text(&st, MINIMAL)
            .await
            .expect_err("the directory does not exist");
        assert_eq!(err.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            st.router.load().providers.len(),
            0,
            "a write failure must not install the new router"
        );
    }
}
