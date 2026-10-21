//! Binary entry point.
//!
//! Everything lives in the `anyhop` library (`src/lib.rs`); this file only owns
//! the global allocator (a binary-level concern) and the runtime bootstrap.

#[cfg(not(feature = "alloc-mimalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "alloc-mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// jemalloc: background thread returns unused pages to the OS (5s decay).
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
static malloc_conf: &[u8] = b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000\0";

fn main() -> anyhow::Result<()> {
    anyhop::run()
}
