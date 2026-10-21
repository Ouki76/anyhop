fn main() {
    // rust-embed requires ui/dist to exist at compile time; create a placeholder
    // so the crate builds before the first `trunk build`.
    let dist = std::path::Path::new("ui/dist");
    if !dist.join("index.html").exists() {
        // Say it out loud: a silent placeholder means `/dashboard` serves
        // "ui not built" in production and nobody notices until a user asks.
        println!(
            "cargo:warning=ui/dist is missing — the dashboard will serve a placeholder. \
             Run `cd ui && trunk build --release` (or use --no-default-features)."
        );
        std::fs::create_dir_all(dist).unwrap();
        std::fs::write(
            dist.join("index.html"),
            "<h1>anyhop ui not built — run `trunk build --release` in ui/</h1>",
        )
        .unwrap();
    }
    // Track every file so hashed filename changes trigger a rebuild.
    println!("cargo:rerun-if-changed=ui/dist");
    if let Ok(entries) = std::fs::read_dir(dist) {
        for e in entries.flatten() {
            println!("cargo:rerun-if-changed={}", e.path().display());
        }
    }
}
