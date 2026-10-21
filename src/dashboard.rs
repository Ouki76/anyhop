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
    if let Some(policy) = csp_for(&html)
        && let Ok(v) = HeaderValue::from_str(&policy)
    {
        resp.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, v);
    }
    resp
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
            let cache = if path == "index.html" {
                "no-cache"
            } else {
                "public, max-age=31536000, immutable"
            };
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref()),
                    (header::CACHE_CONTROL, cache),
                ],
                content.data.to_vec(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "ui not built; run `trunk build` in ui/").into_response(),
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
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<script") {
        let after = &rest[start..];
        let Some(open_end) = after.find('>') else { break };
        let tag = &after[..open_end];
        let body_start = open_end + 1;
        let Some(body_end) = after[body_start..].find("</script>") else {
            break;
        };
        let body = &after[body_start..body_start + body_end];
        // External scripts (`src=...`) are already covered by 'self'.
        if !tag.contains("src=") {
            out.push(body);
        }
        rest = &after[body_start + body_end..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let trimmed = base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest(b"boot();"));
        assert!(policy.contains(&with_ws), "must hash the raw body: {policy}");
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