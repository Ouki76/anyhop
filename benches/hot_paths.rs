//! Hot-path micro-benchmarks (dependency-free: `cargo bench`).
//!
//! These cover the code that runs on *every* request, so a regression here is a
//! regression in throughput. Deliberately not criterion: one less 200-crate
//! dependency tree, and the numbers we need (ns/op + MB/s, best-of-N) are simple.
//!
//! Run: `cargo bench`

use std::collections::VecDeque;
use std::hint::black_box;
use std::time::{Duration, Instant};

use anyhop::pool::KeyPool;
use anyhop::proxy::session_key;
use anyhop::scan::{peek_request, string_field_span};
use anyhop::sse::SseParser;
use bytes::Bytes;

const ROUNDS: usize = 5;

/// Run `f` `iters` times, keep the best round; returns (ns per op, MB/s or 0).
fn bench<F: FnMut()>(name: &str, iters: u32, bytes: usize, mut f: F) {
    // Warm up: first round pays page faults and branch-predictor training.
    for _ in 0..iters.min(1000) {
        f();
    }
    let mut best = Duration::MAX;
    for _ in 0..ROUNDS {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let d = t.elapsed();
        if d < best {
            best = d;
        }
    }
    let ns = best.as_nanos() as f64 / iters as f64;
    if bytes > 0 {
        let mbps = (bytes as f64 / (1024.0 * 1024.0)) / (best.as_secs_f64() / iters as f64);
        println!("{name:<44} {ns:>10.0} ns/op {mbps:>9.1} MB/s");
    } else {
        println!("{name:<44} {ns:>10.0} ns/op");
    }
}

fn chat_body(padding: usize) -> Bytes {
    let filler = "x".repeat(padding);
    Bytes::from(format!(
        r#"{{"model":"gpt-4o-mini","messages":[{{"role":"system","content":"{filler}"}},{{"role":"user","content":"hi"}}],"stream":true,"temperature":0.7}}"#
    ))
}

fn main() {
    println!("anyhop hot-path benchmarks\n");

    // ---------- byte-level request scanner ----------
    let small = chat_body(0);
    let mid = chat_body(64 * 1024);
    let big = chat_body(1024 * 1024);
    // Worst case: the model field is absent, so the whole body is scanned.
    let no_model = Bytes::from(format!(
        r#"{{"messages":[{{"role":"user","content":"{}"}}]}}"#,
        "y".repeat(64 * 1024)
    ));

    bench("scan::peek_request 172B", 200_000, small.len(), || {
        black_box(peek_request(black_box(&small)));
    });
    bench("scan::peek_request 64KiB", 20_000, mid.len(), || {
        black_box(peek_request(black_box(&mid)));
    });
    bench("scan::peek_request 1MiB", 2_000, big.len(), || {
        black_box(peek_request(black_box(&big)));
    });
    bench("scan::peek_request 64KiB, no model", 20_000, no_model.len(), || {
        black_box(peek_request(black_box(&no_model)));
    });
    bench("scan::string_field_span 64KiB", 50_000, mid.len(), || {
        black_box(string_field_span(black_box(&mid), b"model"));
    });

    // ---------- sticky session hash ----------
    bench("chat::session_key 64KiB body", 100_000, 4096, || {
        black_box(session_key(black_box("gpt-4o-mini"), black_box(&mid)));
    });

    // ---------- SSE parsing (translated streams) ----------
    // One realistic chunk: 10 events of a Gemini-style delta.
    let chunk: Vec<u8> = (0..10)
        .map(|i| {
            format!(
                "data: {{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":\"tok{i}\"}}]}}}}]}}\r\n\r\n"
            )
        })
        .collect::<String>()
        .into_bytes();

    // What the streaming translators actually do: parse a chunk, bulk-extend the
    // frames into their queue.
    let one_event: Vec<u8> =
        b"data: {\"c\":[{\"p\":[{\"t\":\"tok\"}]}]}\r\n\r\n".to_vec();

    bench("sse::feed + extend into VecDeque", 100_000, chunk.len(), || {
        let mut p = SseParser::new();
        let mut pending: VecDeque<Bytes> = VecDeque::new();
        pending.extend(p.feed(black_box(&chunk)));
        black_box(pending.len());
    });
    bench("sse::feed one event per chunk", 200_000, 96, || {
        let mut p = SseParser::new();
        let mut pending: VecDeque<Bytes> = VecDeque::new();
        pending.extend(p.feed(black_box(&one_event[..])));
        black_box(pending.len());
    });

    // ---------- key-pool selection ----------
    let pool = KeyPool::new(
        "bench".into(),
        vec!["k1".into(), "k2".into(), "k3".into(), "k4".into()],
        anyhop::config::Strategy::RoundRobin,
        0,
        None,
        None,
    );
    bench("pool::pick round_robin, no cooldowns", 1_000_000, 0, || {
        black_box(pool.pick(black_box("m"), None).map(|k| k.requests.load(std::sync::atomic::Ordering::Relaxed)));
    });
    bench("pool::pick round_robin + sticky", 1_000_000, 0, || {
        black_box(pool.pick(black_box("m"), Some(42)).is_some());
    });
    bench("pool::snapshot (dashboard poll)", 100_000, 0, || {
        black_box(pool.snapshot().len());
    });

    // ---------- dashboard CSP ----------
    #[cfg(feature = "dashboard")]
    {
        let html = std::fs::read("ui/dist/index.html").unwrap_or_else(|_| {
            br#"<html><script>boot();</script></html>"#.to_vec()
        });
        bench("dashboard::csp_for (per page load)", 20_000, html.len(), || {
            black_box(anyhop::dashboard::csp_for(black_box(&html)));
        });
    }

    println!();
}