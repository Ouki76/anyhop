//! Failover event feed: broadcast to live subscribers + ring buffer for replay.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const RECENT_CAPACITY: usize = 100;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DashEvent {
    pub ts: u64,
    pub provider: String,
    pub key: String,
    pub kind: &'static str,
    pub detail: String,
}

impl DashEvent {
    pub fn new(provider: &str, key: &str, kind: &'static str, detail: String) -> Self {
        Self {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            provider: provider.to_string(),
            key: key.to_string(),
            kind,
            detail,
        }
    }
}

/// Shared event bus: live broadcast + replayable recent buffer.
#[derive(Clone)]
pub struct EventBus {
    tx: tokio::sync::broadcast::Sender<DashEvent>,
    recent: Arc<Mutex<VecDeque<DashEvent>>>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            tx,
            recent: Arc::new(Mutex::new(VecDeque::with_capacity(RECENT_CAPACITY))),
        }
    }

    pub fn emit(&self, ev: DashEvent) {
        let _ = self.tx.send(ev.clone());
        let mut buf = self.recent.lock().unwrap();
        if buf.len() >= RECENT_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(ev);
    }

    pub fn emit_simple(&self, provider: &str, key: &str, kind: &'static str, detail: String) {
        self.emit(DashEvent::new(provider, key, kind, detail));
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DashEvent> {
        self.tx.subscribe()
    }

    pub fn recent(&self) -> Vec<DashEvent> {
        self.recent.lock().unwrap().iter().cloned().collect()
    }
}
