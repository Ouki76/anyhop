//! Failover event feed: broadcast to live subscribers + replayable recent buffer.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DashEvent {
    pub ts: u64,
    pub provider: String,
    pub key: String,
    pub kind: String,
    pub detail: String,
}

impl DashEvent {
    pub fn new(provider: &str, key: &str, kind: &str, detail: String) -> Self {
        Self {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            provider: provider.to_string(),
            key: key.to_string(),
            kind: kind.to_string(),
            detail,
        }
    }
}

/// One upstream attempt record for the Requests tab.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RequestRecord {
    pub ts: u64,
    pub provider: String,
    pub model: String,
    pub key: String,
    /// HTTP status as string ("200", "429") or "timeout"/"network".
    pub status: String,
    pub latency_ms: u64,
    pub stream: bool,
    /// Name of the client key that authorised the request (None = master key).
    #[serde(default)]
    pub client_key: Option<String>,
}

/// Shared event bus: live broadcast + replayable recent buffer with a runtime cap.
#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<DashEvent>,
    recent: Arc<Mutex<VecDeque<DashEvent>>>,
    cap: Arc<AtomicUsize>,
}

/// Poison-recovering lock (same policy as `pool::lock`): the guards below cover
/// a plain buffer with no invariant a panic could corrupt, so one panic must not
/// take the event feed down for the rest of the process.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl EventBus {
    /// Config: 0 means "in-memory default (100), no persistence".
    fn normalize(cap: usize) -> usize {
        if cap == 0 { 100 } else { cap }
    }

    pub fn new(cap: usize) -> Self {
        Self::with_capacity(cap, 256)
    }

    /// `channel_capacity` is the SSE broadcast buffer: subscribers lagging more
    /// than this many events behind get `Lagged` (and we resubscribe).
    pub fn with_capacity(cap: usize, channel_capacity: usize) -> Self {
        let cap = Self::normalize(cap);
        let (tx, _) = tokio::sync::broadcast::channel(channel_capacity.max(1));
        Self {
            tx,
            recent: Arc::new(Mutex::new(VecDeque::with_capacity(cap.max(16)))),
            cap: Arc::new(AtomicUsize::new(cap)),
        }
    }

    pub fn set_cap(&self, cap: usize) {
        self.cap.store(Self::normalize(cap), Ordering::Relaxed);
    }

    pub fn emit(&self, ev: DashEvent) {
        let _ = self.tx.send(ev.clone());
        let cap = self.cap.load(Ordering::Relaxed);
        let mut buf = lock(&self.recent);
        while buf.len() >= cap.max(1) {
            buf.pop_front();
        }
        buf.push_back(ev);
    }

    pub fn emit_simple(&self, provider: &str, key: &str, kind: &str, detail: String) {
        self.emit(DashEvent::new(provider, key, kind, detail));
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DashEvent> {
        self.tx.subscribe()
    }

    pub fn recent(&self) -> Vec<DashEvent> {
        lock(&self.recent).iter().cloned().collect()
    }

    /// Restore a persisted buffer (called once at startup).
    pub fn restore(&self, events: Vec<DashEvent>) {
        let cap = self.cap.load(Ordering::Relaxed);
        let mut buf = lock(&self.recent);
        *buf = events.into_iter().collect();
        while buf.len() > cap.max(1) {
            buf.pop_front();
        }
    }
}
