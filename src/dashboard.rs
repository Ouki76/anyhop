//! Optional web dashboard: serves the embedded Sycamore WASM build (ui/dist).
//! All logic lives in the JSON API; this is static file serving only.

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use rust_embed::Embed;
use sha2::Digest;

#[derive(Embed)]
#[folder = "ui/dist"]
struct UiAssets;

pub async fn index() -> Response {
    let Some(file) = UiAssets::get("index.html") else {
        return (
            StatusCode::NOT_FOUND,
            "ui not built; run `trunk build` in ui/",
        )
            .into_response();
    };
    let html = file.data.to_vec();

    let mut resp = (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // index.html — no cache (otherwise the browser loads a stale wasm hash
            // after an update).
            (header::CACHE_CONTROL, "no-cache"),
        ],
        html.clone(),
    )
        .into_response();

    // The SPA needs a strict CSP, and trunk emits two *inline* scripts (the theme
    // bootstrap and the wasm loader). Their bodies change with every build, so the
    // policy allows exactly those scripts by hash instead of falling back to
    // 'unsafe-inline' (which would let any injected <script> run and steal the
    // admin key from localStorage).
    apply_csp(&mut resp, &html);
    resp
}

/// Attach the hashed CSP a dashboard document needs.
///
/// Applied to *every* copy of index.html: `/dashboard`, `/dashboard/` and the
/// wildcard route (`/dashboard/index.html`), which reaches the same bytes.
/// Without it, an injected script on the wildcard URL can read the admin key out
/// of `localStorage` — the policy is the whole defence against that.
fn apply_csp(resp: &mut Response, html: &[u8]) {
    if let Some(policy) = csp_for(html)
        && let Ok(v) = HeaderValue::from_str(&policy)
    {
        resp.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, v);
    }
}

pub async fn asset(Path(path): Path<String>) -> Response {
    // `UiAssets::get` only resolves exact embedded paths, but reject traversal
    // before it ever sees the input.
    if path.contains("..") || path.starts_with('/') {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_file(&path)
}

fn serve_file(path: &str) -> Response {
    match UiAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            // index.html — no cache; hashed assets can be cached for a long time.
            let is_index = path == "index.html";
            let cache = if is_index {
                "no-cache"
            } else {
                "public, max-age=31536000, immutable"
            };
            let data = content.data.to_vec();
            let mut resp = (
                [
                    (header::CONTENT_TYPE, mime.as_ref()),
                    (header::CACHE_CONTROL, cache),
                ],
                data.clone(),
            )
                .into_response();
            if is_index {
                apply_csp(&mut resp, &data);
            }
            resp
        }
        None => (
            StatusCode::NOT_FOUND,
            "ui not built; run `trunk build` in ui/",
        )
            .into_response(),
    }
}

/// Build the CSP for the given index.html, hashing every inline `<script>`.
///
/// `wasm-unsafe-eval` is required for `WebAssembly.instantiate` (used by
/// wasm-bindgen) — it permits wasm compilation only, unlike `unsafe-eval`.
///
/// `pub` only so `cargo bench` can measure it.
pub fn csp_for(html: &[u8]) -> Option<String> {
    let html = std::str::from_utf8(html).ok()?;
    let mut script_src = String::from("'self' 'wasm-unsafe-eval'");
    for body in inline_scripts(html) {
        // Hash the body EXACTLY as the browser sees it: CSP compares the raw text
        // content of the element, so trimming whitespace produces a hash that
        // never matches and silently blocks the app.
        let digest = sha2::Sha256::digest(body.as_bytes());
        let hash = base64::engine::general_purpose::STANDARD.encode(digest);
        script_src.push_str(&format!(" 'sha256-{hash}'"));
    }
    Some(format!(
        "default-src 'none'; \
         script-src {script_src}; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'; \
         base-uri 'none'; \
         form-action 'none'; \
         frame-ancestors 'none'"
    ))
}

/// Bodies of `<script>` elements that have no `src` attribute.
fn inline_scripts(html: &str) -> Vec<&str> {
    // Case-insensitive tag matching. HTML is case-insensitive and a bundler that
    // emitted `<SCRIPT>` would have been skipped silently: the hash list would then
    // miss exactly the script it was supposed to allow, and the SPA would refuse to
    // boot with no error anyone could see. Folding is ASCII, so indices match.
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut off = 0usize;
    while let Some(start) = lower[off..].find("<script") {
        let start = off + start;
        let after = &html[start..];
        let Some(open_end) = lower[start..].find('>') else {
            break;
        };
        let tag = lower[start..start + open_end].to_string();
        let body_start = open_end + 1;
        let Some(body_end) = lower[start + body_start..].find("</script>") else {
            break;
        };
        let body = &after[body_start..body_start + body_end];
        // External scripts (`src=...`) are already covered by 'self'.
        if !tag.contains("src=") {
            out.push(body);
        }
        off = start + body_start + body_end + "</script>".len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csp_of(resp: &Response) -> Option<String> {
        resp.headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    /// `/dashboard/index.html` (the wildcard route) used to be served with no
    /// policy at all, while `/dashboard` had one. The CSP is what stops an
    /// injected script from reading the admin key out of `localStorage`, so both
    /// URLs must carry it.
    #[tokio::test]
    async fn both_index_urls_carry_the_policy() {
        if UiAssets::get("index.html").is_none() {
            // A source checkout without `trunk build`; nothing to serve.
            return;
        }
        let direct = index().await;
        let policy = csp_of(&direct).expect("/dashboard must set a CSP");
        assert!(policy.contains("default-src 'none'"), "{policy}");

        let wildcard = serve_file("index.html");
        assert_eq!(wildcard.status(), StatusCode::OK);
        let policy = csp_of(&wildcard).expect("/dashboard/index.html must set the same CSP");
        assert!(policy.contains("script-src"), "{policy}");
        assert!(
            !policy.contains("script-src 'self' 'unsafe-inline'"),
            "inline scripts must stay hash-pinned: {policy}"
        );
        // The hashed asset keeps its long cache and needs no policy.
        let wasm = UiAssets::iter()
            .find(|p| p.ends_with(".wasm"))
            .map(|p| p.to_string());
        if let Some(path) = wasm {
            let resp = serve_file(&path);
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(csp_of(&resp), None, "a binary asset needs no CSP");
        }
    }

    #[test]
    fn inline_scripts_are_collected_and_external_ones_skipped() {
        let html = r#"<html><head>
            <script>var a=1;</script>
            <script type="module" src="/app.js"></script>
            <script type="module">await init();</script>
        </head></html>"#;
        let got = inline_scripts(html);
        assert_eq!(got.len(), 2, "external script must be skipped: {got:?}");
        // Bodies keep their surrounding whitespace: CSP hashes the raw text.
        assert_eq!(got[0], "var a=1;");
        assert_eq!(got[1], "await init();");
    }

    /// HTML is case-insensitive: an uppercase tag must still be hashed, or the
    /// policy would forbid the very script the app needs.
    #[test]
    fn an_uppercase_script_tag_is_hashed_too() {
        let html = br#"<SCRIPT>var a=1;</SCRIPT><script>run();</script>"#;
        let scripts = inline_scripts(std::str::from_utf8(html).expect("utf8"));
        assert_eq!(scripts.len(), 2, "got {scripts:?}");
        assert_eq!(scripts[0], "var a=1;");
        let policy = csp_for(html).expect("csp");
        // Two distinct hashes.
        assert_eq!(policy.matches("sha256-").count(), 2, "{policy}");
    }

    #[test]
    fn csp_hashes_every_inline_script() {
        let html = br#"<script>var a=1;</script><script type="module">run();</script>"#;
        let policy = csp_for(html).expect("csp");
        assert!(policy.contains("default-src 'none'"), "{policy}");
        assert!(policy.contains("'wasm-unsafe-eval'"), "{policy}");
        assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
        // One hash per inline script.
        assert_eq!(policy.matches("'sha256-").count(), 2, "{policy}");
        // Scripts must never be allowed inline wholesale.
        assert!(
            !policy.contains("script-src 'self' 'unsafe-inline'"),
            "{policy}"
        );
    }

    #[test]
    fn csp_hash_is_the_real_sha256_of_the_body() {
        let html = br#"<script>inline();</script>"#;
        let policy = csp_for(html).unwrap();
        let expected = base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest("inline();".as_bytes()));
        assert!(policy.contains(&format!("'sha256-{expected}'")), "{policy}");
    }

    #[test]
    fn csp_hash_covers_the_whitespace_around_the_body() {
        // Regression: an earlier version hashed `body.trim()`, which never matches
        // the browser's hash and silently blocks every inline script (blank page).
        let html = b"<script>\n  boot();\n</script>";
        let policy = csp_for(html).unwrap();
        let with_ws = base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest(b"\n  boot();\n"));
        let trimmed =
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(b"boot();"));
        assert!(
            policy.contains(&with_ws),
            "must hash the raw body: {policy}"
        );
        assert!(!policy.contains(&trimmed), "must not hash the trimmed body");
    }

    #[test]
    fn csp_survives_a_document_without_scripts() {
        let policy = csp_for(b"<html></html>").unwrap();
        assert!(
            policy.contains("script-src 'self' 'wasm-unsafe-eval';"),
            "{policy}"
        );
    }

    #[test]
    fn malformed_html_does_not_hang_or_panic() {
        for html in [
            &b"<script>"[..],
            &b"<script>unterminated"[..],
            &b"<script type="[..],
            &b""[..],
        ] {
            let _ = csp_for(html);
        }
    }
}

/// The static-file route is internet-facing, so the traversal guard is a
/// security boundary: every path that could reach outside the embedded bundle
/// must 404 before the asset lookup.
#[cfg(test)]
mod asset_tests {
    use super::*;

    async fn status_and_body(resp: Response) -> (StatusCode, Vec<u8>) {
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("body")
            .to_vec();
        (status, body)
    }

    #[tokio::test]
    async fn traversal_paths_are_rejected_without_leaking_a_file() {
        for path in [
            "../Cargo.toml",
            "../../etc/passwd",
            "/etc/passwd",
            "assets/../../anyhop.toml",
            "..",
        ] {
            let resp = asset(Path(path.to_string())).await;
            let (status, body) = status_and_body(resp).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "path {path:?} must 404");
            let text = String::from_utf8_lossy(&body);
            assert!(
                !text.contains("[package]") && !text.contains("root:"),
                "path {path:?} leaked a file: {text}"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_asset_is_a_404_and_the_index_is_served_with_a_policy() {
        let (status, _) =
            status_and_body(asset(Path("does-not-exist.bin".to_string())).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        if UiAssets::get("index.html").is_none() {
            return; // a checkout without `trunk build`
        }
        let resp = asset(Path("index.html".to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache",
            "the entry point must not be cached"
        );
        assert!(
            resp.headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_some(),
            "serving index.html through the wildcard route must keep the CSP"
        );
        let (_, body) = status_and_body(resp).await;
        assert!(!body.is_empty());
    }
}
