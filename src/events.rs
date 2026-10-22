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

#[cfg(test)]
mod tests {
    use super::*;

    fn details(bus: &EventBus) -> Vec<String> {
        bus.recent().into_iter().map(|e| e.detail).collect()
    }

    /// The dashboard reads this buffer as "the last N things that happened". It
    /// must keep the *newest* events, in order, and never grow past the cap.
    #[test]
    fn the_buffer_keeps_the_newest_events_up_to_the_cap() {
        let bus = EventBus::new(3);
        for i in 0..6 {
            bus.emit_simple("p", "k", "backoff", format!("e{i}"));
        }
        assert_eq!(
            details(&bus),
            vec!["e3", "e4", "e5"],
            "the oldest events must be the ones dropped"
        );

        // A cap of 1 is legal and still keeps the latest event.
        let bus = EventBus::new(1);
        bus.emit_simple("p", "k", "backoff", "first".into());
        bus.emit_simple("p", "k", "backoff", "second".into());
        assert_eq!(details(&bus), vec!["second"]);
    }

    /// `events_history = 0` is documented as "in-memory default, no persistence":
    /// the ring must still work (with 100 entries), not be a dead feed.
    #[test]
    fn a_zero_cap_falls_back_to_the_documented_default() {
        let bus = EventBus::new(0);
        for i in 0..150 {
            bus.emit_simple("p", "k", "backoff", format!("e{i}"));
        }
        let kept = bus.recent();
        assert_eq!(kept.len(), 100, "the documented default is 100 events");
        assert_eq!(kept.last().expect("non-empty").detail, "e149");
        assert_eq!(kept.first().expect("non-empty").detail, "e50");
    }

    /// `set_cap` is what a live `[tuning]`/`[server]` edit calls: it must apply
    /// to the existing buffer, not only to future writes.
    #[test]
    fn lowering_the_cap_evicts_immediately() {
        let bus = EventBus::new(10);
        for i in 0..6 {
            bus.emit_simple("p", "k", "backoff", format!("e{i}"));
        }
        bus.set_cap(2);
        bus.emit_simple("p", "k", "backoff", "e6".into());
        assert_eq!(details(&bus), vec!["e5", "e6"]);
    }

    /// Restoring the persisted feed at startup must respect the cap by dropping
    /// the oldest rows — a bigger history from a previous run must not make the
    /// buffer unbounded.
    #[test]
    fn restore_keeps_the_newest_events_and_respects_the_cap() {
        let bus = EventBus::new(3);
        let restored: Vec<DashEvent> = (0..5)
            .map(|i| DashEvent::new("p", "k", "backoff", format!("r{i}")))
            .collect();
        bus.restore(restored);
        assert_eq!(details(&bus), vec!["r2", "r3", "r4"]);

        // Restoring an empty feed clears anything left over.
        bus.restore(Vec::new());
        assert!(bus.recent().is_empty());
    }

    /// Live subscribers (the SSE endpoint) get exactly the events that are
    /// emitted after they subscribe — this is the path the dashboard's feed uses.
    #[tokio::test]
    async fn a_subscriber_receives_events_emitted_after_it_subscribes() {
        let bus = EventBus::new(8);
        bus.emit_simple("p", "k", "backoff", "before".into());
        let mut rx = bus.subscribe();
        bus.emit_simple("p", "k", "dead", "after".into());

        let ev = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("an event arrives")
            .expect("the channel is open");
        assert_eq!(ev.detail, "after", "only events after subscribing");
        assert_eq!(ev.kind, "dead");
        assert_eq!(ev.provider, "p");
        assert!(ev.ts > 0, "events carry a timestamp for the UI");
        // And the buffer has both.
        assert_eq!(details(&bus), vec!["before", "after"]);
    }

    /// The feeds are persisted as JSON: the record shape must round-trip, and an
    /// older row without `client_key` must still deserialize (default).
    #[test]
    fn records_round_trip_through_json() {
        let ev = DashEvent::new("p", "k-masked", "rate_limited", "cooling".into());
        let back: DashEvent = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(back.detail, "cooling");
        assert_eq!(back.key, "k-masked");

        let legacy: RequestRecord = serde_json::from_str(
            r#"{"ts":1,"provider":"p","model":"m","key":"k","status":"200","latency_ms":3,"stream":false}"#,
        )
        .expect("a record written before client_key existed still loads");
        assert_eq!(legacy.client_key, None);
    }
}
