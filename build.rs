fn main() {
    // rust-embed requires ui/dist to exist at compile time; create a placeholder
    // so the crate builds before the first `trunk build`.
    let dist = std::path::Path::new("ui/dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(dist).unwrap();
        std::fs::write(
            dist.join("index.html"),
            "<h1>anyhop ui not built — run `trunk build --release` in ui/</h1>",
        )
        .unwrap();
    }
    println!("cargo:rerun-if-changed=ui/dist");
}
