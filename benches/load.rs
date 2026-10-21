//! HTTP load generator, so throughput numbers come from a client that is not the
//! bottleneck (a Python load generator caps out around 8k rps on its own).
//!
//! Needs a running gateway; without `ANYHOP_LOAD_URL` it exits immediately.
//!
//!     ANYHOP_LOAD_URL=http://127.0.0.1:18080 cargo bench --bench load
//!     ANYHOP_LOAD_URL=... ANYHOP_LOAD_PATH=/v1/models ANYHOP_LOAD_CONCURRENCY=64 \
//!         ANYHOP_LOAD_DURATION=10 cargo bench --bench load
//!
//! Env:
//!   ANYHOP_LOAD_URL          base url (required, else the bench skips)
//!   ANYHOP_LOAD_PATH         default /v1/chat/completions
//!   ANYHOP_LOAD_KEY          bearer key, default test-gw-key
//!   ANYHOP_LOAD_CONCURRENCY  parallel in-flight requests, default 64
//!   ANYHOP_LOAD_DURATION     seconds, default 10
//!   ANYHOP_LOAD_STREAM       "1" to send stream=true bodies (chat path only)

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use reqwest::Client;

const CHAT_BODY: &str = r#"{"model":"mock/test-model","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"ping"}]}"#;
const CHAT_BODY_STREAM: &str = r#"{"model":"mock/test-model","stream":true,"messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"ping"}]}"#;

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

#[tokio::main]
async fn main() {
    let Ok(base) = std::env::var("ANYHOP_LOAD_URL") else {
        println!("load bench skipped: set ANYHOP_LOAD_URL (e.g. http://127.0.0.1:18080)");
        return;
    };
    let path = env_or("ANYHOP_LOAD_PATH", "/v1/chat/completions");
    let key = env_or("ANYHOP_LOAD_KEY", "test-gw-key");
    let concurrency: usize = env_or("ANYHOP_LOAD_CONCURRENCY", "64")
        .parse()
        .unwrap_or(64);
    let seconds: u64 = env_or("ANYHOP_LOAD_DURATION", "10").parse().unwrap_or(10);
    let stream = std::env::var("ANYHOP_LOAD_STREAM").as_deref() == Ok("1");

    let client = Client::builder()
        .pool_max_idle_per_host(concurrency)
        .tcp_nodelay(true)
        .build()
        .expect("http client");

    let url = format!("{base}{path}");
    let is_chat = path.contains("chat");
    // Warm up the connection pool so the first samples are not connect latency.
    // Same method as the load phase — GET for /healthz and /v1/models.
    let warm = if is_chat {
        client
            .post(&url)
            .bearer_auth(&key)
            .header("content-type", "application/json")
            .body(CHAT_BODY)
            .send()
            .await
    } else {
        client.get(&url).bearer_auth(&key).send().await
    };
    match warm {
        Ok(r) if r.status().is_success() => {}
        Ok(r) => {
            println!(
                "load bench: warm-up returned {} — is the mock set up?",
                r.status()
            );
            return;
        }
        Err(e) => {
            println!("load bench: cannot reach {url}: {e}");
            return;
        }
    }

    let done = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    // Status histogram + first failure reason: a benchmark that hides *why* it
    // failed is useless for debugging.
    let statuses: Arc<Mutex<Vec<(String, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut tasks = Vec::with_capacity(concurrency);

    let start = Instant::now();
    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.clone();
        let key = key.clone();
        let done = done.clone();
        let failed = failed.clone();
        let statuses = statuses.clone();
        tasks.push(tokio::spawn(async move {
            let mut lat: Vec<u64> = Vec::with_capacity(4096);
            while Instant::now() < deadline {
                let t = Instant::now();
                let req = if is_chat {
                    client
                        .post(&url)
                        .bearer_auth(&key)
                        .header("content-type", "application/json")
                        .body(if stream { CHAT_BODY_STREAM } else { CHAT_BODY })
                } else {
                    client.get(&url).bearer_auth(&key)
                };
                match req.send().await {
                    Ok(resp) => {
                        // Drain fully: for SSE this measures time to the last byte.
                        let status = resp.status();
                        let body = resp.bytes().await;
                        if status.is_success() && body.is_ok() {
                            done.fetch_add(1, Ordering::Relaxed);
                            lat.push(t.elapsed().as_micros() as u64);
                        } else {
                            failed.fetch_add(1, Ordering::Relaxed);
                            let label = if status.is_success() {
                                "body-error".to_string()
                            } else {
                                status.as_str().to_string()
                            };
                            let mut g = statuses.lock().unwrap_or_else(|e| e.into_inner());
                            match g.iter_mut().find(|(k, _)| *k == label) {
                                Some((_, n)) => *n += 1,
                                None => g.push((label, 1)),
                            }
                        }
                    }
                    Err(e) => {
                        failed.fetch_add(1, Ordering::Relaxed);
                        let mut g = statuses.lock().unwrap_or_else(|e| e.into_inner());
                        let label = format!("conn-error: {e}");
                        match g.iter_mut().find(|(k, _)| *k == label) {
                            Some((_, n)) => *n += 1,
                            None => g.push((label, 1)),
                        }
                    }
                }
            }
            lat
        }));
    }

    let mut all = Vec::new();
    for t in tasks {
        if let Ok(mut v) = t.await {
            all.append(&mut v);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let ok = done.load(Ordering::Relaxed);
    let bad = failed.load(Ordering::Relaxed);
    all.sort_unstable();
    let pct = |p: f64| -> f64 {
        if all.is_empty() {
            return 0.0;
        }
        let i = ((all.len() as f64 * p) as usize).min(all.len() - 1);
        all[i] as f64 / 1000.0
    };

    println!(
        "{path} · {concurrency} conns · {seconds}s\n\
         {ok} ok, {bad} failed → {rps:.0} req/s\n\
         latency p50={p50:.2}ms p95={p95:.2}ms p99={p99:.2}ms",
        rps = ok as f64 / elapsed,
        p50 = pct(0.50),
        p95 = pct(0.95),
        p99 = pct(0.99),
    );
    let g = statuses.lock().unwrap_or_else(|e| e.into_inner());
    if !g.is_empty() {
        println!("failures:");
        for (label, n) in g.iter() {
            println!("  {n:>6} × {label}");
        }
    }
}
