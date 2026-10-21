//! Embedded persistence (redb): key health, OAuth token cache, usage stats, and
//! the Responses API store behind `previous_response_id`.
//! Writes are batched through a channel and flushed every 2s in one transaction.
//!
//! Records are keyed by sha256(secret) hashes, but OAuth access tokens and
//! runtime-added provider keys (EXTRAS) are stored in cleartext by necessity —
//! the state file is created with 0600 permissions; treat it as a secret.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::Digest;

const HEALTH: TableDefinition<&str, &[u8]> = TableDefinition::new("health");
const OAUTH: TableDefinition<&str, &[u8]> = TableDefinition::new("oauth");
const STATS: TableDefinition<&str, &[u8]> = TableDefinition::new("stats");
/// Keys added at runtime via the dashboard: "extra:{provider}" -> JSON [secret, ...].
const EXTRAS: TableDefinition<&str, &[u8]> = TableDefinition::new("extras");
/// Feed buffers: "feed:events" / "feed:requests" -> JSON array.
const FEEDS: TableDefinition<&str, &[u8]> = TableDefinition::new("feeds");
/// Responses API store: "resp_..." -> JSON [`StoredResponse`].
const RESPONSES: TableDefinition<&str, &[u8]> = TableDefinition::new("responses");

/// Entries kept in the response store until `[tuning] response_store_max` says
/// otherwise. The config is not visible where the store is opened (the state file
/// is the only input), so the request path pushes the configured cap; eviction
/// itself always runs in the writer task.
const DEFAULT_RESPONSE_MAX: usize = 1000;

/// Stable short id for a credential: sha256(secret)[..16] as hex.
pub fn secret_hash(secret: &str) -> String {
    let digest = sha2::Sha256::digest(secret.as_bytes());
    hex::encode(&digest[..16])
}

/// Storage key for a pool credential: "{provider}:{sha256(secret)[..16]}".
pub fn key_id(provider: &str, secret: &str) -> String {
    format!("{provider}:{}", secret_hash(secret))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HealthRecord {
    pub status: u8, // 0 active, 1 cooldown, 2 dead
    pub cooldown_until_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OAuthRecord {
    pub access_token: String,
    pub expires_at_ms: u64,
    pub project_id: Option<String>,
    /// Rotated refresh token, when the issuer rotates them (OpenAI does).
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct StatsRecord {
    pub requests: u64,
    pub failures: u64,
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
}

/// One completed Responses API reply, kept so a follow-up can continue the
/// conversation with `previous_response_id` instead of resending the history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredResponse {
    /// The `resp_*` id handed to the client (and accepted as
    /// `previous_response_id`).
    pub id: String,
    /// Unix seconds; also the eviction order (oldest first).
    pub created_at: u64,
    /// Client-facing model name of the request that produced it.
    pub model: String,
    /// Provider that answered (informational; replay does not pin it).
    pub provider: String,
    /// The translated chat messages that produced this response (so a follow-up
    /// can replay the conversation).
    pub input: serde_json::Value,
    /// The assistant text.
    pub output_text: String,
    /// Usage in Responses naming (`input_tokens`/`output_tokens`/`total_tokens`),
    /// when the provider reported it.
    pub usage: Option<serde_json::Value>,
}

/// Storage key for a stored response. Kept in one place so the batched write and
/// the immediate delete agree on it.
fn response_key(id: &str) -> String {
    format!("r:{id}")
}

#[derive(Debug)]
enum StorageMsg {
    Health {
        key: String,
        rec: HealthRecord,
    },
    OAuth {
        key: String,
        rec: OAuthRecord,
    },
    Stats {
        key: String,
        rec: StatsRecord,
    },
    /// Runtime-added keys for a provider, as a complete list (idempotent: the
    /// last writer wins, so add and remove cannot interleave into a wrong state).
    ExtraKeys {
        provider: String,
        secrets: Vec<String>,
    },
    Feed {
        key: String,
        data: Vec<u8>,
    },
    /// A completed Responses API reply, keyed by its `resp_*` id.
    Response {
        id: String,
        rec: StoredResponse,
    },
    /// Drop a stored response now (immediate, like `ExtraKeys`).
    DeleteResponse {
        id: String,
    },
    /// Flush pending writes now and ack — used at shutdown so the final batch
    /// isn't lost when the runtime drops the writer task.
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl StorageMsg {
    fn key(&self) -> String {
        // Variant-qualified: Health/OAuth/Stats share the same credential id —
        // without a prefix they collide in the pending map and only the last
        // record within a flush window would survive.
        match self {
            StorageMsg::Health { key, .. } => format!("h:{key}"),
            StorageMsg::OAuth { key, .. } => format!("o:{key}"),
            StorageMsg::Stats { key, .. } => format!("s:{key}"),
            StorageMsg::ExtraKeys { provider, .. } => format!("extras:{provider}"),
            StorageMsg::Feed { key, .. } => key.clone(),
            // Same key as the write, so a delete can drop a queued record.
            StorageMsg::Response { id, .. } | StorageMsg::DeleteResponse { id } => response_key(id),
            // Flush is handled inline by the writer loop, never queued.
            StorageMsg::Flush(_) => unreachable!("flush messages are not queued"),
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    db: Arc<Database>,
    tx: tokio::sync::mpsc::UnboundedSender<StorageMsg>,
    /// Response-store cap, written by the request path and read by the writer.
    response_max: Arc<AtomicUsize>,
    /// Responses saved but not yet committed by the writer.
    ///
    /// The disk write is batched, but a follow-up call arrives immediately after
    /// the reply it continues — within the same second, not in two. Reads check
    /// this map first so `previous_response_id` works on the very next request;
    /// the writer drops each entry once its record is on disk.
    recent: Arc<Mutex<HashMap<String, StoredResponse>>>,
}

impl Storage {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let db = Arc::new(Database::create(Path::new(path))?);
        // The state file holds OAuth tokens and runtime-added keys: owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        // Ensure tables exist.
        let wtx = db.begin_write()?;
        {
            let _ = wtx.open_table(HEALTH)?;
            let _ = wtx.open_table(OAUTH)?;
            let _ = wtx.open_table(STATS)?;
            let _ = wtx.open_table(EXTRAS)?;
            let _ = wtx.open_table(FEEDS)?;
            let _ = wtx.open_table(RESPONSES)?;
        }
        wtx.commit()?;

        let response_max = Arc::new(AtomicUsize::new(DEFAULT_RESPONSE_MAX));
        let recent: Arc<Mutex<HashMap<String, StoredResponse>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let writer_max = response_max.clone();
        let writer_recent = recent.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StorageMsg>();
        let writer_db = db.clone();
        tokio::spawn(async move {
            let mut pending: HashMap<String, StorageMsg> = HashMap::new();
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // The cap can change on a config reload; read it per batch so the
                // writer always evicts against the current value.
                let cap = || writer_max.load(Ordering::Relaxed);
                tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(m) => {
                            dispatch(&writer_db, &mut pending, m, cap(), &writer_recent);
                            while let Ok(m) = rx.try_recv() {
                                dispatch(&writer_db, &mut pending, m, cap(), &writer_recent);
                            }
                        }
                        None => {
                            flush(&writer_db, &mut pending, cap(), &writer_recent);
                            break;
                        }
                    },
                    _ = interval.tick() => flush(&writer_db, &mut pending, cap(), &writer_recent),
                }
            }
        });
        Ok(Self {
            db,
            tx,
            response_max,
            recent,
        })
    }

    fn read_json<T: for<'de> Deserialize<'de>>(
        &self,
        table: TableDefinition<&str, &[u8]>,
        key: &str,
    ) -> Option<T> {
        let rtx = self.db.begin_read().ok()?;
        let t = rtx.open_table(table).ok()?;
        let v = t.get(key).ok()??;
        serde_json::from_slice(v.value()).ok()
    }

    pub fn save_health(&self, provider: &str, secret: &str, rec: HealthRecord) {
        let _ = self.tx.send(StorageMsg::Health {
            key: key_id(provider, secret),
            rec,
        });
    }

    pub fn load_health(&self, provider: &str, secret: &str) -> Option<HealthRecord> {
        self.read_json(HEALTH, &key_id(provider, secret))
    }

    pub fn save_oauth(&self, provider: &str, secret: &str, rec: OAuthRecord) {
        let _ = self.tx.send(StorageMsg::OAuth {
            key: key_id(provider, secret),
            rec,
        });
    }

    pub fn load_oauth(&self, provider: &str, secret: &str) -> Option<OAuthRecord> {
        self.read_json(OAUTH, &key_id(provider, secret))
    }

    pub fn save_stats(&self, provider: &str, secret: &str, rec: StatsRecord) {
        let _ = self.tx.send(StorageMsg::Stats {
            key: key_id(provider, secret),
            rec,
        });
    }

    pub fn load_stats(&self, provider: &str, secret: &str) -> Option<StatsRecord> {
        self.read_json(STATS, &key_id(provider, secret))
    }

    /// Persist a runtime-added key (survives restarts).
    pub fn save_extra_key(&self, provider: &str, secret: &str) {
        let mut list = self.list_extra_keys(provider);
        if !list.iter().any(|s| s == secret) {
            list.push(secret.to_string());
            self.set_extra_keys(provider, list);
        }
    }

    /// Forget a runtime-added key (e.g. revoked in the dashboard).
    pub fn delete_extra_key(&self, provider: &str, secret: &str) {
        let mut list = self.list_extra_keys(provider);
        if let Some(i) = list.iter().position(|s| s == secret) {
            list.remove(i);
            self.set_extra_keys(provider, list);
        }
    }

    /// Replace the whole runtime-key list for a provider (empty = clear).
    pub fn set_extra_keys(&self, provider: &str, secrets: Vec<String>) {
        let _ = self.tx.send(StorageMsg::ExtraKeys {
            provider: provider.to_string(),
            secrets,
        });
    }

    pub fn list_extra_keys(&self, provider: &str) -> Vec<String> {
        self.read_json(EXTRAS, &format!("extra:{provider}"))
            .unwrap_or_default()
    }

    /// Persist a feed buffer (events / requests).
    pub fn save_feed<T: Serialize>(&self, name: &str, value: &T) {
        if let Ok(data) = serde_json::to_vec(value) {
            let _ = self.tx.send(StorageMsg::Feed {
                key: format!("feed:{name}"),
                data,
            });
        }
    }

    pub fn load_feed<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Option<T> {
        self.read_json(FEEDS, &format!("feed:{name}"))
    }

    /// Set how many responses the store keeps (`[tuning] response_store_max`,
    /// 0 = keep none). Cheap by design: the request path only stores this value,
    /// the writer task does the eviction.
    pub fn set_response_max(&self, max: usize) {
        self.response_max.store(max, Ordering::Relaxed);
    }

    /// Keep a completed response so a follow-up can chain to it with
    /// `previous_response_id`.
    ///
    /// The disk write is batched (responses are ~KB and never latency critical),
    /// but the record is visible to [`Storage::load_response`] immediately through
    /// `recent`: the next turn of a conversation arrives right away, not after
    /// the two-second flush.
    pub fn save_response(&self, id: &str, rec: StoredResponse) {
        self.remember(id, &rec);
        if self
            .tx
            .send(StorageMsg::Response {
                id: id.to_string(),
                rec,
            })
            .is_err()
        {
            // No writer left: do not keep promising a record nobody will persist.
            self.forget(id);
        }
    }

    /// Look a response up by its `resp_*` id. `None` when it was never stored,
    /// has been evicted, or the store is empty.
    pub fn load_response(&self, id: &str) -> Option<StoredResponse> {
        if let Some(rec) = self.recent_record(id) {
            return Some(rec);
        }
        self.read_json(RESPONSES, id)
    }

    /// Every stored response id (eviction bookkeeping, tests, diagnostics).
    /// The order is not insertion or eviction order.
    pub fn list_responses(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rtx) = self.db.begin_read()
            && let Ok(t) = rtx.open_table(RESPONSES)
            && let Ok(iter) = t.iter()
        {
            // A key that cannot be decoded cannot be evicted either; skip it.
            for (key, _) in iter.flatten() {
                out.push(key.value().to_string());
            }
        }
        // A poisoned lock only means some other request panicked mid-insert;
        // recovering keeps the store readable. Same idiom as the rest of the crate.
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        for id in recent.keys() {
            if !out.iter().any(|seen| seen == id) {
                out.push(id.clone());
            }
        }
        out
    }

    /// Forget a stored response now (an explicit delete must not wait for the
    /// batch window, otherwise a replay in between would still succeed).
    pub fn delete_response(&self, id: &str) {
        self.forget(id);
        let _ = self
            .tx
            .send(StorageMsg::DeleteResponse { id: id.to_string() });
    }

    /// Record a not-yet-flushed response for immediate reads.
    fn remember(&self, id: &str, rec: &StoredResponse) {
        self.recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.to_string(), rec.clone());
    }

    /// Drop a response from the immediate-read window.
    fn forget(&self, id: &str) {
        self.recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }

    /// The not-yet-flushed record for `id`, if there is one.
    fn recent_record(&self, id: &str) -> Option<StoredResponse> {
        self.recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    /// Flush all pending writes and wait for the ack (shutdown path).
    pub async fn flush_async(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(StorageMsg::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

/// Apply one message: the rare admin writes go to disk immediately, everything
/// else joins the current batch.
fn dispatch(
    db: &Arc<Database>,
    pending: &mut HashMap<String, StorageMsg>,
    m: StorageMsg,
    response_max: usize,
    recent: &Mutex<HashMap<String, StoredResponse>>,
) {
    match m {
        StorageMsg::Flush(ack) => {
            flush(db, pending, response_max, recent);
            let _ = ack.send(());
        }
        // Extras are rare (admin actions) and carry their whole list, so write
        // them immediately instead of batching. OAuth records too: a rotated
        // refresh token that is still in the batch when the process dies is
        // gone, and the config's stale token may already be revoked.
        StorageMsg::ExtraKeys { .. } => flush_extras(db, &m),
        StorageMsg::OAuth { .. } => {
            let mut one = HashMap::new();
            one.insert(m.key(), m);
            flush(db, &mut one, response_max, recent);
        }
        StorageMsg::DeleteResponse { id } => {
            // Drop a queued write for the same id first, otherwise the next
            // flush would resurrect what was just deleted.
            pending.remove(&response_key(&id));
            delete_response_now(db, &id);
        }
        other => {
            pending.insert(other.key(), other);
        }
    }
}

/// Remove one response from disk outside the batch window.
fn delete_response_now(db: &Arc<Database>, id: &str) {
    let wtx = match db.begin_write() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("storage: response delete failed to begin write tx: {e}");
            return;
        }
    };
    if let Ok(mut t) = wtx.open_table(RESPONSES) {
        let _ = t.remove(id);
    }
    if let Err(e) = wtx.commit() {
        tracing::warn!("storage: response delete commit failed: {e}");
    }
}

/// Keep at most `max` stored responses, oldest `created_at` first (0 = keep
/// none, which is what a disabled store means).
///
/// Runs inside the writer's write transaction right after new records were
/// inserted, so the request path never scans or deletes. A full pass per flush
/// that actually wrote a response is cheaper than maintaining a second index for
/// a table of KB-scale records.
fn evict_responses(
    t: &mut redb::Table<'_, &'static str, &'static [u8]>,
    max: usize,
) -> Vec<String> {
    if max == 0 {
        // Disabled: drop whatever is left over from a larger cap.
        let doomed: Vec<String> = match t.iter() {
            Ok(iter) => iter
                .filter_map(|e| e.ok().map(|(k, _)| k.value().to_string()))
                .collect(),
            Err(_) => return Vec::new(),
        };
        for id in &doomed {
            let _ = t.remove(id.as_str());
        }
        return doomed;
    }
    let mut rows: Vec<(u64, String)> = Vec::new();
    match t.iter() {
        Ok(iter) => {
            for entry in iter {
                let Ok((key, value)) = entry else { continue };
                // Only `created_at` matters here; serde skips the rest.
                let created = serde_json::from_slice::<ResponseCreatedAt>(value.value())
                    .map(|r| r.created_at)
                    .unwrap_or(0);
                rows.push((created, key.value().to_string()));
            }
        }
        Err(e) => {
            tracing::warn!("storage: cannot scan responses for eviction: {e}");
            return Vec::new();
        }
    }
    if rows.len() <= max {
        return Vec::new();
    }
    // Oldest first; the id breaks ties so eviction is deterministic when several
    // responses share a timestamp.
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let excess = rows.len() - max;
    let mut removed = Vec::new();
    for (_, id) in rows.into_iter().take(excess) {
        let _ = t.remove(id.as_str());
        removed.push(id);
    }
    removed
}

/// The single field eviction needs from a [`StoredResponse`]; unknown fields are
/// ignored, which keeps the scan from allocating the whole record.
#[derive(Deserialize)]
struct ResponseCreatedAt {
    created_at: u64,
}

fn flush_extras(db: &Arc<Database>, msg: &StorageMsg) {
    let StorageMsg::ExtraKeys { provider, secrets } = msg else {
        return;
    };
    let wtx = match db.begin_write() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("storage: extra-key flush failed to begin write tx: {e}");
            return;
        }
    };
    {
        let mut t = match wtx.open_table(EXTRAS) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("storage: cannot open extras table: {e}");
                return;
            }
        };
        let key = format!("extra:{provider}");
        if secrets.is_empty() {
            let _ = t.remove(key.as_str());
        } else if let Ok(j) = serde_json::to_vec(secrets) {
            let _ = t.insert(key.as_str(), j.as_slice());
        }
    }
    if let Err(e) = wtx.commit() {
        tracing::warn!("storage: extra-key commit failed: {e}");
    }
}

fn flush(
    db: &Arc<Database>,
    pending: &mut HashMap<String, StorageMsg>,
    response_max: usize,
    recent: &Mutex<HashMap<String, StoredResponse>>,
) {
    if pending.is_empty() {
        return;
    }
    // Open the write tx BEFORE draining: on failure the batch survives to the
    // next tick instead of being silently dropped.
    let wtx = match db.begin_write() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(
                "storage: flush failed to begin write tx ({e}), {} msgs kept",
                pending.len()
            );
            return;
        }
    };
    let msgs: Vec<StorageMsg> = pending.drain().map(|(_, m)| m).collect();
    // Ids whose record reached the table (or was evicted from it) in this batch.
    let mut flushed: Vec<String> = Vec::new();
    {
        if let Ok(mut t) = wtx.open_table(HEALTH) {
            for m in &msgs {
                if let StorageMsg::Health { key, rec } = m
                    && let Ok(j) = serde_json::to_vec(rec)
                {
                    let _ = t.insert(key.as_str(), j.as_slice());
                }
            }
        }
        if let Ok(mut t) = wtx.open_table(OAUTH) {
            for m in &msgs {
                if let StorageMsg::OAuth { key, rec } = m
                    && let Ok(j) = serde_json::to_vec(rec)
                {
                    let _ = t.insert(key.as_str(), j.as_slice());
                }
            }
        }
        if let Ok(mut t) = wtx.open_table(FEEDS) {
            for m in &msgs {
                if let StorageMsg::Feed { key, data } = m {
                    let _ = t.insert(key.as_str(), data.as_slice());
                }
            }
        }
        if let Ok(mut t) = wtx.open_table(STATS) {
            for m in &msgs {
                if let StorageMsg::Stats { key, rec } = m
                    && let Ok(j) = serde_json::to_vec(rec)
                {
                    let _ = t.insert(key.as_str(), j.as_slice());
                }
            }
        }
        if let Ok(mut t) = wtx.open_table(RESPONSES) {
            for m in &msgs {
                if let StorageMsg::Response { id, rec } = m
                    && let Ok(j) = serde_json::to_vec(rec)
                    && t.insert(id.as_str(), j.as_slice()).is_ok()
                {
                    flushed.push(id.clone());
                }
            }
            // Only pay for the cap check when this batch actually grew the store.
            if !flushed.is_empty() {
                flushed.extend(evict_responses(&mut t, response_max));
            }
        }
    }
    if let Err(e) = wtx.commit() {
        tracing::warn!("storage: commit failed: {e}");
        return;
    }
    // These records are on disk now (or were just evicted), so the immediate-read
    // window no longer needs them; `load_response` falls through to the table.
    let mut cache = recent.lock().unwrap_or_else(|e| e.into_inner());
    for id in &flushed {
        cache.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique scratch state file: redb locks the path, so tests cannot share one.
    async fn open_scratch(tag: &str) -> (Storage, std::path::PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "anyhop-storage-{tag}-{}-{nanos}.redb",
            std::process::id()
        ));
        let store = Storage::open(path.to_str().expect("temp paths are UTF-8"))
            .expect("the state file opens");
        (store, path)
    }

    fn rec(id: &str, created_at: u64) -> StoredResponse {
        StoredResponse {
            id: id.to_string(),
            created_at,
            model: "mock/test-model".to_string(),
            provider: "mock".to_string(),
            input: serde_json::json!([{"role": "user", "content": "hi"}]),
            output_text: "there".to_string(),
            usage: Some(serde_json::json!({
                "input_tokens": 1,
                "output_tokens": 1,
                "total_tokens": 2
            })),
        }
    }

    fn sorted(mut ids: Vec<String>) -> Vec<String> {
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn a_response_round_trips_through_the_state_file() {
        let (store, path) = open_scratch("roundtrip").await;
        let saved = rec("resp_1", 10);
        store.save_response("resp_1", saved.clone());
        // Batched write: nothing is on disk until the batch flushes.
        store.flush_async().await;

        assert_eq!(store.load_response("resp_1"), Some(saved));
        assert_eq!(sorted(store.list_responses()), vec!["resp_1".to_string()]);
        assert!(
            store.load_response("resp_missing").is_none(),
            "an unknown id must not invent a record"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The whole point of `recent`: a follow-up arrives right after the reply, not
    /// after the two-second flush, so the record must be readable before its disk
    /// write happens.
    #[tokio::test]
    async fn a_saved_response_is_readable_before_the_batch_flushes() {
        let (store, path) = open_scratch("read-your-write").await;
        let saved = rec("resp_1", 1);
        store.save_response("resp_1", saved.clone());

        assert_eq!(
            store.load_response("resp_1"),
            Some(saved),
            "the next turn must see a response the batch has not written yet"
        );
        assert_eq!(sorted(store.list_responses()), vec!["resp_1".to_string()]);

        store.flush_async().await;
        assert!(
            store.recent.lock().map(|r| r.is_empty()).unwrap_or(false),
            "the writer drops the entry once the record is on disk"
        );
        // Still readable — from the state file this time.
        assert!(store.load_response("resp_1").is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_deleted_unflushed_response_is_gone_from_the_read_window() {
        let (store, path) = open_scratch("delete-recent").await;
        store.save_response("resp_1", rec("resp_1", 1));
        assert!(store.load_response("resp_1").is_some());

        store.delete_response("resp_1");
        assert!(
            store.load_response("resp_1").is_none(),
            "a delete takes effect immediately, not at the next flush"
        );
        store.flush_async().await;
        assert!(store.list_responses().is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn eviction_keeps_the_newest_entries_at_the_cap() {
        let (store, path) = open_scratch("evict").await;
        store.set_response_max(2);
        for (id, created_at) in [("resp_a", 1), ("resp_b", 2), ("resp_c", 3)] {
            store.save_response(id, rec(id, created_at));
        }
        store.flush_async().await;

        assert_eq!(
            sorted(store.list_responses()),
            vec!["resp_b".to_string(), "resp_c".to_string()],
            "the oldest record (resp_a) is the one evicted"
        );
        assert!(store.load_response("resp_a").is_none());
        assert!(store.load_response("resp_c").is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn eviction_runs_on_every_write_past_the_cap() {
        let (store, path) = open_scratch("evict-window").await;
        store.set_response_max(1);
        for (id, created_at) in [("resp_a", 1), ("resp_b", 2)] {
            store.save_response(id, rec(id, created_at));
            store.flush_async().await;
        }
        assert_eq!(sorted(store.list_responses()), vec!["resp_b".to_string()]);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_zero_cap_empties_the_store() {
        let (store, path) = open_scratch("cap-zero").await;
        store.set_response_max(4);
        store.save_response("resp_a", rec("resp_a", 1));
        store.flush_async().await;
        assert_eq!(store.list_responses().len(), 1);

        // Disabled after the fact: the next batch clears what is left over.
        store.set_response_max(0);
        store.save_response("resp_b", rec("resp_b", 2));
        store.flush_async().await;
        assert!(store.list_responses().is_empty());
        assert!(store.load_response("resp_a").is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn delete_response_removes_a_batched_and_a_flushed_record() {
        let (store, path) = open_scratch("delete").await;
        store.set_response_max(10);
        // Already flushed.
        store.save_response("resp_done", rec("resp_done", 1));
        store.flush_async().await;
        // Still sitting in the batch: the delete must drop it too.
        store.save_response("resp_queued", rec("resp_queued", 2));
        store.delete_response("resp_done");
        store.delete_response("resp_queued");
        store.flush_async().await;

        assert!(store.list_responses().is_empty());
        assert!(store.load_response("resp_done").is_none());
        assert!(store.load_response("resp_queued").is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn other_tables_still_work_next_to_the_response_store() {
        let (store, path) = open_scratch("coexist").await;
        store.save_health(
            "mock",
            "sk-test",
            HealthRecord {
                status: 1,
                cooldown_until_ms: 42,
            },
        );
        store.save_response("resp_1", rec("resp_1", 1));
        store.flush_async().await;

        // The version check: sharing one write transaction must not disturb the
        // tables that were there before.
        assert_eq!(
            store
                .load_health("mock", "sk-test")
                .map(|h| h.cooldown_until_ms),
            Some(42)
        );
        assert!(store.load_response("resp_1").is_some());

        let _ = std::fs::remove_file(&path);
    }
}
