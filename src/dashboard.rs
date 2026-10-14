//! Optional web dashboard: serves the embedded Sycamore WASM build (ui/dist).
//! All logic lives in the JSON API (api.rs); this is static file serving only.

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "ui/dist"]
struct UiAssets;

pub async fn index() -> Response {
    serve_file("index.html")
}

pub async fn asset(Path(path): Path<String>) -> Response {
    serve_file(&path)
}

fn serve_file(path: &str) -> Response {
    match UiAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            // index.html — без кэша (иначе браузер грузит старый wasm-хэш после обновления).
            // Хэшированные ассеты можно кэшировать надолго.
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

