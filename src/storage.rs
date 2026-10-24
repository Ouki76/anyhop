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

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
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

/// Largest serialized record the response store accepts, in bytes.
///
/// A count cap alone is not a memory bound: 1000 records of 32 MiB would be 32 GB
/// of state file written by one client that keeps sending long conversations.
/// Records are a conversation's messages plus the assistant text, and a real one
/// is tens of KiB, so 256 KiB is generous — while keeping the worst case at
/// `response_store_max × 256 KiB`. A larger record is simply not stored: the
/// reply it belongs to has already been sent, and refusing the *request* would
/// break a working conversation just because it cannot be resumed later.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// How many responses the immediate-read window keeps.
///
/// `recent` exists so a follow-up can see the reply it continues before the
/// two-second batch flush; it is a short-lived write buffer, so a small count is
/// plenty (a client making more than this many calls inside one flush window is
/// not waiting on any of them).
const RECENT_MAX_ENTRIES: usize = 64;

/// Approximate byte budget for the immediate-read window.
///
/// Same reasoning as [`MAX_RESPONSE_BYTES`], for the in-memory copy: entries are
/// dropped (they are still queued for the state file) once the window holds more
/// than this, so a burst of large replies cannot pin memory that the disk write
/// does not need.
const RECENT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Stable short id for a credential: sha256(secret)[..16] as hex.
pub fn secret_hash(secret: &str) -> String {
    let digest = sha2::Sha256::digest(secret.as_bytes());
    hex::encode(&digest[..16])
}

/// Storage key for a pool credential: "{provider}:{sha256(secret)[..16]}".
pub fn key_id(provider: &str, secret: &str) -> String {
    format!("{provider}:{}", secret_hash(secret))
}

/// Health of one credential as persisted between restarts and across reloads.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthRecord {
    pub status: u8, // 0 active, 1 cooldown, 2 dead
    pub cooldown_until_ms: u64,
    /// Per-model cooldowns (upstream model id -> until unix ms). A pool that is
    /// rebuilt by a config reload must not forget that one model is exhausted —
    /// that is exactly how a reload used to turn a per-model 429 back into a
    /// request that hits the same quota again.
    #[serde(default)]
    pub model_cooldowns: std::collections::HashMap<String, u64>,
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

/// What a rebuilt key pool restores for one credential (see
/// [`Storage::load_pool_records`]).
#[derive(Debug, Clone, Default)]
pub struct RestoredKey {
    pub health: Option<HealthRecord>,
    pub stats: Option<StatsRecord>,
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
    /// Which client key produced this response.
    ///
    /// `resp_*` ids are unguessable, but an id is also a capability: whoever has
    /// it can make the gateway replay that conversation as the assistant turn of
    /// a new request. Binding the record to its owner means a key that somehow
    /// learns another key's id cannot read that conversation back. `None` is a
    /// record from before ownership was tracked (or from a gateway that requires
    /// no key at all); it stays replayable so an upgrade does not break live
    /// conversations, and it reveals nothing a caller could not have sent itself.
    #[serde(default)]
    pub owner: Option<String>,
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
    ///
    /// The record travels **pre-serialized**: `save_response` has to measure the
    /// encoded size to enforce [`MAX_RESPONSE_BYTES`], so encoding it again in the
    /// writer would be pure work.
    Response {
        id: String,
        data: Vec<u8>,
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
    ///
    /// Bounded by both entry count and approximate bytes: it is a cache for one
    /// flush window, not a second copy of the store.
    recent: Arc<Mutex<HashMap<String, RecentEntry>>>,
    /// The batch not committed yet, shared with the writer task.
    ///
    /// Health and stats are queued here directly (rather than through the
    /// channel) so a reader always sees the value this process wrote last: a
    /// config reload rebuilds pools from storage, and one that missed a `dead`
    /// record still sitting in the 2 s batch would resurrect the key. It also lets
    /// [`Storage::flush_blocking`] flush everything, in order, from any thread.
    pending: Arc<Mutex<HashMap<String, StorageMsg>>>,
    /// The runtime-key list this process wrote last.
    ///
    /// `set_extra_keys` is written to disk immediately by the writer task, but the
    /// *next* read (a config reload merging extras) must see the new list even if
    /// the writer has not run yet — the deletion path clears it right before the
    /// reload, and reading the stale list resurrected the key being deleted.
    extras_now: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Read transactions started (test-only, for the batching assertions).
    #[cfg(test)]
    read_txs: Arc<AtomicUsize>,
}

/// One entry of the immediate-read window: the record plus the serialized size it
/// costs, kept so the window's byte budget is a sum and not a re-serialize.
struct RecentEntry {
    rec: StoredResponse,
    bytes: usize,
}

impl Storage {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        // The state file holds OAuth tokens and runtime-added keys: owner-only.
        // Create it with 0600 *before* redb opens it — creating the database and
        // chmod-ing afterwards left a window where the file was 0644 under the
        // process umask (a few ms is plenty for a backup/sync agent), and the
        // chmod error used to be discarded silently.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path);
            if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                tracing::warn!("cannot set 0600 on state file '{path}': {e}");
            }
        }
        let db = Arc::new(Database::create(Path::new(path))?);
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
        let recent: Arc<Mutex<HashMap<String, RecentEntry>>> = Arc::new(Mutex::new(HashMap::new()));
        let pending: Arc<Mutex<HashMap<String, StorageMsg>>> = Arc::new(Mutex::new(HashMap::new()));
        let writer_max = response_max.clone();
        let writer_recent = recent.clone();
        let writer_pending = pending.clone();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StorageMsg>();
        let writer_db = db.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The batch lives behind a mutex so `flush_blocking` can drain it from
            // the caller's thread; the writer is the only other user and never
            // holds it across an await.
            let locked = || match writer_pending.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            loop {
                // The cap can change on a config reload; read it per batch so the
                // writer always evicts against the current value.
                let cap = || writer_max.load(Ordering::Relaxed);
                tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(m) => {
                            let mut batch = locked();
                            dispatch(&writer_db, &mut batch, m, cap(), &writer_recent);
                            while let Ok(m) = rx.try_recv() {
                                dispatch(&writer_db, &mut batch, m, cap(), &writer_recent);
                            }
                        }
                        None => {
                            let mut batch = locked();
                            flush(&writer_db, &mut batch, cap(), &writer_recent);
                            break;
                        }
                    },
                    _ = interval.tick() => {
                        let mut batch = locked();
                        flush(&writer_db, &mut batch, cap(), &writer_recent);
                    }
                }
            }
        });
        Ok(Self {
            db,
            tx,
            response_max,
            recent,
            pending,
            extras_now: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            read_txs: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Start a read transaction, counting it for the batching tests.
    fn begin_read(&self) -> Option<redb::ReadTransaction> {
        #[cfg(test)]
        self.read_txs.fetch_add(1, Ordering::Relaxed);
        self.db.begin_read().ok()
    }

    /// How many read transactions this instance has started (test-only).
    #[cfg(test)]
    fn read_tx_count(&self) -> usize {
        self.read_txs.load(Ordering::Relaxed)
    }

    fn read_json<T: for<'de> Deserialize<'de>>(
        &self,
        table: TableDefinition<&str, &[u8]>,
        key: &str,
    ) -> Option<T> {
        let rtx = self.begin_read()?;
        let t = rtx.open_table(table).ok()?;
        let v = t.get(key).ok()??;
        serde_json::from_slice(v.value()).ok()
    }

    /// Queue a record for the next commit, in the shared batch.
    ///
    /// Used for the records a reload reads back (health/stats): going through the
    /// batch means the read is exact, ordered, and flushable synchronously.
    fn enqueue(&self, m: StorageMsg) {
        // If the writer task died (a panic or a fatal IO error), the receiver is
        // gone: every later write would be accepted silently and nothing would ever
        // reach the file, while reads keep serving stale table contents. Say so
        // once instead of pretending the write landed.
        if self.tx.is_closed() {
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                tracing::error!(
                    "storage: the writer task is gone; state changes are no longer persisted"
                );
            }
            return;
        }
        let key = m.key();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, m);
    }

    /// Send a message to the writer, reporting a dead writer once.
    fn send(&self, m: StorageMsg) {
        if self.tx.send(m).is_err() {
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                tracing::error!(
                    "storage: the writer task is gone; state changes are no longer persisted"
                );
            }
        }
    }

    pub fn save_health(&self, provider: &str, secret: &str, rec: HealthRecord) {
        self.enqueue(StorageMsg::Health {
            key: key_id(provider, secret),
            rec,
        });
    }

    pub fn load_health(&self, provider: &str, secret: &str) -> Option<HealthRecord> {
        let key = key_id(provider, secret);
        // The batch may not have reached the file yet; it always holds the value
        // this process wrote last.
        if let Some(rec) = queued_message(&self.pending, &format!("h:{key}"), |m| match m {
            StorageMsg::Health { rec, .. } => Some(rec.clone()),
            _ => None,
        }) {
            return Some(rec);
        }
        self.read_json(HEALTH, &key)
    }

    pub fn save_oauth(&self, provider: &str, secret: &str, rec: OAuthRecord) {
        self.send(StorageMsg::OAuth {
            key: key_id(provider, secret),
            rec,
        });
    }

    pub fn load_oauth(&self, provider: &str, secret: &str) -> Option<OAuthRecord> {
        self.read_json(OAUTH, &key_id(provider, secret))
    }

    pub fn save_stats(&self, provider: &str, secret: &str, rec: StatsRecord) {
        self.enqueue(StorageMsg::Stats {
            key: key_id(provider, secret),
            rec,
        });
    }

    pub fn load_stats(&self, provider: &str, secret: &str) -> Option<StatsRecord> {
        let key = key_id(provider, secret);
        // Same reason as `load_health`: a pool rebuilt right after a stats save
        // must see the value this process just wrote, not the last commit.
        if let Some(rec) = queued_message(&self.pending, &format!("s:{key}"), |m| match m {
            StorageMsg::Stats { rec, .. } => Some(*rec),
            _ => None,
        }) {
            return Some(rec);
        }
        self.read_json(STATS, &key)
    }

    /// Health and stats of every credential of one provider, in a single read
    /// transaction.
    ///
    /// A reload restores every key of every provider; doing that one table read
    /// per key per table meant `2 × keys` transactions each time. The result is
    /// index-aligned with `secrets`.
    pub fn load_pool_records(&self, provider: &str, secrets: &[String]) -> Vec<RestoredKey> {
        let mut out: Vec<RestoredKey> = secrets.iter().map(|_| RestoredKey::default()).collect();
        {
            // The batch may hold a value the file does not have yet.
            let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            for (i, secret) in secrets.iter().enumerate() {
                let key = key_id(provider, secret);
                if let Some(StorageMsg::Health { rec, .. }) = pending.get(&format!("h:{key}")) {
                    out[i].health = Some(rec.clone());
                }
                if let Some(StorageMsg::Stats { rec, .. }) = pending.get(&format!("s:{key}")) {
                    out[i].stats = Some(*rec);
                }
            }
        }
        let Some(rtx) = self.begin_read() else {
            return out;
        };
        if let Ok(health) = rtx.open_table(HEALTH) {
            for (i, secret) in secrets.iter().enumerate() {
                if out[i].health.is_some() {
                    continue; // the mirror is newer
                }
                let key = key_id(provider, secret);
                if let Ok(Some(v)) = health.get(key.as_str()) {
                    out[i].health = serde_json::from_slice(v.value()).ok();
                }
            }
        }
        if let Ok(stats) = rtx.open_table(STATS) {
            for (i, secret) in secrets.iter().enumerate() {
                if out[i].stats.is_some() {
                    continue;
                }
                let key = key_id(provider, secret);
                if let Ok(Some(v)) = stats.get(key.as_str()) {
                    out[i].stats = serde_json::from_slice(v.value()).ok();
                }
            }
        }
        out
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
        let mut extras = self.extras_now.lock().unwrap_or_else(|e| e.into_inner());
        let list = extras.entry(provider.to_string()).or_default();
        if let Some(i) = list.iter().position(|s| s == secret) {
            list.remove(i);
            let snapshot = list.clone();
            drop(extras);
            self.set_extra_keys(provider, snapshot);
        }
    }

    /// Replace the whole runtime-key list for a provider (empty = clear).
    pub fn set_extra_keys(&self, provider: &str, secrets: Vec<String>) {
        self.extras_now
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(provider.to_string(), secrets.clone());
        self.send(StorageMsg::ExtraKeys {
            provider: provider.to_string(),
            secrets,
        });
    }

    pub fn list_extra_keys(&self, provider: &str) -> Vec<String> {
        // What this process wrote last wins over the table: the write is queued
        // for the writer task and a read in between (the reload that follows a
        // key deletion) must not see the previous list.
        if let Some(list) = self
            .extras_now
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(provider)
        {
            return list.clone();
        }
        self.read_json(EXTRAS, &format!("extra:{provider}"))
            .unwrap_or_default()
    }

    /// Persist a feed buffer (events / requests).
    pub fn save_feed<T: Serialize>(&self, name: &str, value: &T) {
        if let Ok(data) = serde_json::to_vec(value) {
            self.send(StorageMsg::Feed {
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
    ///
    /// A record whose serialized form exceeds [`MAX_RESPONSE_BYTES`] is *not*
    /// stored: it is logged and skipped, and the reply the client already received
    /// is unaffected. Failing the request instead would turn "this conversation is
    /// too long to resume" into "this conversation cannot continue at all".
    pub fn save_response(&self, id: &str, rec: StoredResponse) {
        let data = match serde_json::to_vec(&rec) {
            Ok(data) => data,
            Err(e) => {
                // Cannot happen for a struct of plain serde types, but a record we
                // cannot encode must not poison the batch.
                tracing::debug!(id, error = %e, "storage: response record is not encodable");
                return;
            }
        };
        if data.len() > MAX_RESPONSE_BYTES {
            tracing::debug!(
                id,
                bytes = data.len(),
                cap = MAX_RESPONSE_BYTES,
                "storage: response record is too large to store; the reply is still served"
            );
            return;
        }
        self.remember(id, &rec, data.len());
        if self
            .tx
            .send(StorageMsg::Response {
                id: id.to_string(),
                data,
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
    ///
    /// The window is bounded in both dimensions. Evicting here only drops the
    /// *in-memory* copy: the record is already queued for the state file, so it
    /// becomes readable again (from disk) at the next flush — at worst a couple of
    /// seconds later, which is the same window a fresh process has.
    fn remember(&self, id: &str, rec: &StoredResponse, bytes: usize) {
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        recent.insert(
            id.to_string(),
            RecentEntry {
                rec: rec.clone(),
                bytes,
            },
        );
        // Oldest first (created_at, then id so eviction is deterministic), the
        // same order the disk store evicts in.
        while recent.len() > RECENT_MAX_ENTRIES
            || recent.values().map(|e| e.bytes).sum::<usize>() > RECENT_MAX_BYTES
        {
            let oldest = recent
                .iter()
                .min_by(|a, b| {
                    a.1.rec
                        .created_at
                        .cmp(&b.1.rec.created_at)
                        .then_with(|| a.0.cmp(b.0))
                })
                .map(|(key, _)| key.clone());
            let Some(oldest) = oldest else { break };
            recent.remove(&oldest);
        }
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
            .map(|entry| entry.rec.clone())
    }

    /// `(entries, approximate bytes)` of the immediate-read window (test-only).
    #[cfg(test)]
    fn recent_stats(&self) -> (usize, usize) {
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        (recent.len(), recent.values().map(|e| e.bytes).sum())
    }

    /// Flush all pending writes and wait for the ack (shutdown path).
    pub async fn flush_async(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(StorageMsg::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }

    /// Commit the current batch from the calling thread, without an async round
    /// trip.
    ///
    /// Used by a config reload: it rebuilds pools, which restores their health
    /// from this store, and a write sitting in the 2 s batch would otherwise be
    /// read as "no such state" — a key that just returned 401 would come back
    /// alive, a model cooldown would be forgotten. Blocking here is deliberate
    /// (reloads are rare admin actions) and safe to call from a worker thread:
    /// the batch is behind a mutex the writer task never holds across an await.
    /// [`flush_blocking`], moved off the runtime worker when possible.
    ///
    /// A `commit()` is an fsync: on a slow disk it takes milliseconds, and this is
    /// called from async handlers (config reload). `block_in_place` lets the
    /// multi-threaded runtime hand *other* tasks to a fresh worker meanwhile. It is
    /// illegal on the current-thread runtime (tests, the CLI), so the flavour is
    /// checked first and the plain call kept there.
    pub fn flush_in_place(&self) {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::try_current() {
            Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| self.flush_blocking());
            }
            _ => self.flush_blocking(),
        }
    }

    pub fn flush_blocking(&self) {
        let mut batch = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        flush(
            &self.db,
            &mut batch,
            self.response_max.load(Ordering::Relaxed),
            &self.recent,
        );
    }
}

/// Apply one message: the rare admin writes go to disk immediately, everything
/// else joins the current batch.
fn dispatch(
    db: &Arc<Database>,
    pending: &mut HashMap<String, StorageMsg>,
    m: StorageMsg,
    response_max: usize,
    recent: &Mutex<HashMap<String, RecentEntry>>,
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
            // Through the shared batch: `flush` re-queues a failed commit into the
            // map it was given, and a local map is dropped right afterwards — the
            // rotated refresh token was lost while the log claimed it was retried.
            pending.insert(m.key(), m);
            flush(db, pending, response_max, recent);
        }
        StorageMsg::DeleteResponse { id } => {
            // Drop a queued write for the same id first, otherwise the next
            // flush would resurrect what was just deleted.
            pending.remove(&response_key(&id));
            delete_response_now(db, &id);
        }
        other => {
            // `MAX_PENDING_REQUEUE` used to guard only the requeue path, so when
            // `begin_write` itself kept failing (a full or read-only disk) the map
            // grew by one record per request forever — up to 256 KiB each for a
            // stored `/v1/responses` reply. Bound it here as well: drop the record
            // (a response that cannot be written is already lost) and say so.
            if pending.len() >= MAX_PENDING_REQUEUE {
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "storage: {MAX_PENDING_REQUEUE} writes are already queued for a                          state file that is not accepting them; dropping new records"
                    );
                }
                return;
            }
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
/// inserted, so the request path never scans or deletes. The caller only calls
/// this when the batch grew the store *and* the row count exceeds the cap
/// ([`needs_eviction`]), so the common flush pays nothing at all.
///
/// The scan keeps a bounded candidate list of the `excess` oldest rows instead
/// of collecting and sorting every row: with a 100 k-row store, one inserted
/// record used to mean deserialising 100 k `created_at` values and sorting them
/// all inside the single write transaction.
fn evict_responses(
    t: &mut redb::Table<'_, &'static str, &'static [u8]>,
    max: usize,
) -> Vec<String> {
    let rows = match t.len() {
        Ok(n) => n as usize,
        Err(e) => {
            tracing::warn!("storage: cannot count responses for eviction: {e}");
            return Vec::new();
        }
    };
    if rows <= max {
        // Nothing to do — including the disabled store with no leftovers.
        return Vec::new();
    }
    let excess = rows - max;
    // Max-heap of the candidates: the largest (newest) of the current victims is
    // on top, so a row older than it replaces it. Ordering is (created_at, id),
    // which makes eviction deterministic for equal timestamps and identical to
    // the full sort this replaces.
    let mut victims: std::collections::BinaryHeap<(u64, String)> =
        std::collections::BinaryHeap::with_capacity(excess.min(1024));
    let iter = match t.iter() {
        Ok(iter) => iter,
        Err(e) => {
            tracing::warn!("storage: cannot scan responses for eviction: {e}");
            return Vec::new();
        }
    };
    for entry in iter {
        let Ok((key, value)) = entry else { continue };
        // Only `created_at` matters here; serde skips the rest.
        let created = serde_json::from_slice::<ResponseCreatedAt>(value.value())
            .map(|r| r.created_at)
            .unwrap_or(0);
        let cand = (created, key.value().to_string());
        if victims.len() < excess {
            victims.push(cand);
        } else if victims.peek().is_some_and(|worst| &cand < worst) {
            victims.pop();
            victims.push(cand);
        }
    }
    let mut removed = Vec::with_capacity(victims.len());
    for (_, id) in victims.into_iter() {
        let _ = t.remove(id.as_str());
        removed.push(id);
    }
    removed
}

/// Whether an eviction pass can possibly have work to do.
///
/// The row count is O(1) in redb (the table tracks its length); the scan is
/// O(rows). Skipping it whenever the batch did not grow the store — or the store
/// is still under its cap — keeps a normal flush free of response-table work.
fn needs_eviction(rows: usize, inserted: usize, max: usize) -> bool {
    inserted > 0 && rows > max
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
    recent: &Mutex<HashMap<String, RecentEntry>>,
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
            let mut inserted = 0usize;
            for m in &msgs {
                if let StorageMsg::Response { id, data } = m
                    && t.insert(id.as_str(), data.as_slice()).is_ok()
                {
                    inserted += 1;
                    flushed.push(id.clone());
                }
            }
            // Cheap guard first: only a batch that grew the store can push it over
            // the cap, and the count is O(1) while the scan is O(rows).
            let rows = t.len().map(|n| n as usize).unwrap_or(0);
            if needs_eviction(rows, inserted, response_max) {
                flushed.extend(evict_responses(&mut t, response_max));
            }
        }
    }
    if let Err(e) = wtx.commit() {
        // `pending` was drained above, so the batch is in `msgs` now. Re-queue it:
        // dropping it would silently lose health/stat/feed writes (a dead key would
        // come back active after the next reload), and the batch is the only copy.
        tracing::warn!(
            "storage: commit failed ({e}), re-queuing {} msgs",
            msgs.len()
        );
        requeue(pending, msgs);
        return;
    }
    // These records are on disk now (or were just evicted), so the immediate-read
    // window no longer needs them; `load_response` falls through to the table.
    let mut cache = recent.lock().unwrap_or_else(|e| e.into_inner());
    for id in &flushed {
        cache.remove(id);
    }
}

/// Look a record up in the not-yet-committed batch.
fn queued_message<T>(
    pending: &Mutex<HashMap<String, StorageMsg>>,
    key: &str,
    pick: impl Fn(&StorageMsg) -> Option<T>,
) -> Option<T> {
    let pending = pending.lock().unwrap_or_else(|e| e.into_inner());
    pending.get(key).and_then(pick)
}

/// Cap on the batch kept after a failed commit.
///
/// A commit that keeps failing (a full or read-only state file) would otherwise
/// re-queue the same batch forever and grow it with every new write. Dropping the
/// overflow is the least-bad option: the records are best-effort telemetry, while
/// an unbounded map would take the process down.
const MAX_PENDING_REQUEUE: usize = 50_000;

/// Put a drained batch back so the next tick retries it (bug: a failed commit
/// used to return with the batch already consumed, silently losing it).
fn requeue(pending: &mut HashMap<String, StorageMsg>, msgs: Vec<StorageMsg>) {
    for m in msgs {
        let key = m.key();
        if pending.len() >= MAX_PENDING_REQUEUE && !pending.contains_key(&key) {
            tracing::warn!("storage: batch is full, dropping a record that failed to commit");
            continue;
        }
        // A newer message for the same record may already be queued again.
        pending.entry(key).or_insert(m);
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
            owner: None,
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

    /// A record is a *conversation*: the count cap alone would let one client
    /// write `response_store_max × 32 MiB` of state file. Anything over the
    /// per-record cap is skipped (and the caller keeps serving its reply), while
    /// ordinary records are unaffected.
    #[tokio::test]
    async fn an_oversized_record_is_skipped_instead_of_stored() {
        let (store, path) = open_scratch("oversized").await;
        store.set_response_max(10);

        let ordinary = rec("resp_ok", 1);
        store.save_response("resp_ok", ordinary.clone());

        let mut huge = rec("resp_huge", 2);
        huge.output_text = "x".repeat(MAX_RESPONSE_BYTES);
        assert!(
            serde_json::to_vec(&huge).map(|j| j.len()).unwrap_or(0) > MAX_RESPONSE_BYTES,
            "the fixture must really exceed the cap"
        );
        store.save_response("resp_huge", huge);
        store.flush_async().await;

        assert_eq!(store.load_response("resp_ok"), Some(ordinary));
        assert!(
            store.load_response("resp_huge").is_none(),
            "an over-large record must not be stored"
        );
        assert_eq!(sorted(store.list_responses()), vec!["resp_ok".to_string()]);

        let _ = std::fs::remove_file(&path);
    }

    /// The immediate-read window is a cache for one flush window, so it is capped
    /// by count *and* approximate bytes; evicting only drops the in-memory copy,
    /// the queued disk write still happens.
    #[tokio::test]
    async fn the_recent_window_is_bounded_in_entries_and_bytes() {
        let (store, path) = open_scratch("recent-caps").await;
        store.set_response_max(10_000);

        // Count: many small records, no flush in between.
        for i in 0..(RECENT_MAX_ENTRIES + 20) {
            let id = format!("resp_{i:03}");
            store.save_response(&id, rec(&id, i as u64));
        }
        let (entries, _) = store.recent_stats();
        assert!(
            entries <= RECENT_MAX_ENTRIES,
            "the read window kept {entries} entries"
        );

        // Bytes: 200 KiB records inside the per-record cap, enough of them to
        // overrun the window's byte budget long before the entry count.
        let (store, path2) = open_scratch("recent-byte-cap").await;
        store.set_response_max(10_000);
        for i in 0..40u64 {
            let id = format!("resp_big_{i:03}");
            let mut big = rec(&id, i);
            big.output_text = "y".repeat(200 * 1024);
            store.save_response(&id, big);
        }
        let (entries, bytes) = store.recent_stats();
        assert!(bytes <= RECENT_MAX_BYTES, "{bytes} bytes retained");
        assert!(entries <= RECENT_MAX_ENTRIES, "{entries} entries retained");
        assert!(entries > 0, "the newest record must stay readable");
        // The newest one is the one that survived.
        assert!(
            store.load_response("resp_big_039").is_some(),
            "the most recent record must still be readable"
        );
        // Eviction dropped only the memory copy: the records still reach the file.
        store.flush_async().await;
        assert!(store.load_response("resp_big_000").is_some());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&path2);
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
                ..Default::default()
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

    // ----- D: health written this second must be readable before the batch -----

    /// `save_health` is batched for two seconds. A config reload reads the health
    /// of every key back to rebuild its pool, so reading the *table* at that
    /// moment used to miss the just-written record: a key that returned 401 came
    /// back active. The write-through mirror closes that window.
    #[tokio::test]
    async fn a_health_write_is_readable_before_the_batch_flushes() {
        let (store, path) = open_scratch("health-now").await;
        let dead = HealthRecord {
            status: 2,
            cooldown_until_ms: 0,
            ..Default::default()
        };
        store.save_health("mock", "sk-dead", dead.clone());

        let got = store
            .load_health("mock", "sk-dead")
            .expect("a record written this instant must be readable");
        assert_eq!(got.status, 2, "the dead key must not come back active");
        let _ = std::fs::remove_file(&path);
    }

    /// Per-model cooldowns travel with the record: a reload that rebuilt a pool
    /// used to forget that one model is exhausted.
    #[tokio::test]
    async fn per_model_cooldowns_survive_the_round_trip() {
        let (store, path) = open_scratch("model-cd").await;
        let mut rec = HealthRecord {
            status: 0,
            cooldown_until_ms: 0,
            ..Default::default()
        };
        rec.model_cooldowns.insert("m-1".into(), 4_102_444_800_000);
        store.save_health("mock", "sk-1", rec);
        store.flush_async().await;

        let got = store.load_health("mock", "sk-1").expect("record");
        assert_eq!(
            got.model_cooldowns.get("m-1").copied(),
            Some(4_102_444_800_000),
            "the model cooldown must be persisted, not just the key status"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The config reload path needs a *synchronous* flush: it rebuilds pools right
    /// after, and must not read a stale store. This must work off the tokio
    /// runtime too, so it cannot be an `async fn`.
    #[tokio::test]
    async fn flush_blocking_writes_the_batch_without_awaiting() {
        let (store, path) = open_scratch("flush-blocking").await;
        store.save_health(
            "mock",
            "sk-1",
            HealthRecord {
                status: 2,
                cooldown_until_ms: 0,
                ..Default::default()
            },
        );
        store.flush_blocking();

        // Read the *table*, not the mirror, to prove the bytes reached the file.
        let on_disk: HealthRecord = store
            .read_json(HEALTH, &key_id("mock", "sk-1"))
            .expect("the record must be committed by flush_blocking");
        assert_eq!(on_disk.status, 2);

        // Flushing an empty batch is a no-op, not an error.
        store.flush_blocking();
        let _ = std::fs::remove_file(&path);
    }

    // ----- L: one read transaction per pool, not two per key -----

    #[tokio::test]
    async fn a_pool_restore_reads_every_key_in_one_transaction() {
        let (store, path) = open_scratch("batch-restore").await;
        let secrets: Vec<String> = (0..3).map(|i| format!("sk-{i}")).collect();
        for (i, s) in secrets.iter().enumerate() {
            store.save_health(
                "mock",
                s,
                HealthRecord {
                    status: 2,
                    cooldown_until_ms: 0,
                    ..Default::default()
                },
            );
            store.save_stats(
                "mock",
                s,
                StatsRecord {
                    requests: i as u64,
                    ..Default::default()
                },
            );
        }
        store.flush_async().await;

        let before = store.read_tx_count();
        let recs = store.load_pool_records("mock", &secrets);
        assert_eq!(
            store.read_tx_count() - before,
            1,
            "three keys used to cost six read transactions"
        );
        assert_eq!(recs.len(), 3);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.health.as_ref().map(|h| h.status), Some(2));
            assert_eq!(r.stats.as_ref().map(|s| s.requests), Some(i as u64));
        }
        // An unknown key is simply absent, never invented.
        let missing = store.load_pool_records("mock", &["nope".to_string()]);
        assert!(missing[0].health.is_none() && missing[0].stats.is_none());

        let _ = std::fs::remove_file(&path);
    }

    // ----- J: a failed commit must not eat the batch -----

    /// `key` is the raw record id ("a"), the message key is "h:a".
    fn health_msg(key: &str, status: u8) -> StorageMsg {
        StorageMsg::Health {
            key: key.to_string(),
            rec: HealthRecord {
                status,
                cooldown_until_ms: 0,
                ..Default::default()
            },
        }
    }

    #[test]
    fn a_failed_commit_requeues_every_record() {
        let mut pending = HashMap::new();
        let msgs = vec![health_msg("a", 2), health_msg("b", 1)];
        requeue(&mut pending, msgs);
        assert_eq!(
            pending.len(),
            2,
            "flush() drained the batch before the commit; a failure used to drop it"
        );
        assert!(matches!(
            pending.get("h:a"),
            Some(StorageMsg::Health { rec, .. }) if rec.status == 2
        ));
    }

    #[test]
    fn requeue_keeps_a_newer_record_and_stays_bounded() {
        let mut pending = HashMap::new();
        pending.insert("h:a".to_string(), health_msg("a", 2));
        // A retried older copy must not overwrite the newer queued value.
        requeue(&mut pending, vec![health_msg("a", 0)]);
        assert!(matches!(
            pending.get("h:a"),
            Some(StorageMsg::Health { rec, .. }) if rec.status == 2
        ));

        // A permanently failing state file must not grow memory without bound.
        let mut full = HashMap::new();
        for i in 0..MAX_PENDING_REQUEUE {
            full.insert(format!("h:k{i}"), health_msg(&format!("k{i}"), 0));
        }
        requeue(&mut full, vec![health_msg("overflow", 0)]);
        assert_eq!(full.len(), MAX_PENDING_REQUEUE);
        assert!(!full.contains_key("h:overflow"));
    }

    // ----- K: eviction only scans when it can have work, and never sorts -----

    #[test]
    fn eviction_is_skipped_when_it_cannot_have_work() {
        // The common flush: writes do not touch the response table at all.
        assert!(!needs_eviction(100_000, 0, 100_000));
        // A response was written but the store is still under the cap.
        assert!(!needs_eviction(99_999, 1, 100_000));
        // Over the cap after inserting.
        assert!(needs_eviction(100_001, 1, 100_000));
        // Over the cap, but this batch did not insert: nothing new to evict.
        assert!(!needs_eviction(100_001, 0, 100_000));
        // A disabled store with leftovers must still be emptied.
        assert!(needs_eviction(1, 1, 0));
    }

    /// Lowering the cap evicts exactly the globally oldest rows, even though the
    /// scan sees them in key order — the bounded candidate list must not settle
    /// for the first `excess` rows it meets.
    #[tokio::test]
    async fn a_lowered_cap_evicts_the_globally_oldest_rows() {
        let (store, path) = open_scratch("evict-bounded").await;
        store.set_response_max(10);
        // Insert newest-first so key order is the opposite of age order.
        let ages = [60u64, 50, 40, 30, 20, 10];
        for (i, created) in ages.iter().enumerate() {
            let id = format!("resp_{i:02}");
            store.save_response(&id, rec(&id, *created));
        }
        // Give resp_00 the smallest id but the newest timestamp: a naive
        // "keep the first rows" scan would keep it and drop a newer one.
        store.flush_async().await;
        assert_eq!(store.list_responses().len(), 6);

        store.set_response_max(3);
        store.save_response("resp_new", rec("resp_new", 100));
        store.flush_async().await;

        let left = sorted(store.list_responses());
        assert_eq!(
            left,
            vec![
                "resp_00".to_string(),  // created_at 60
                "resp_01".to_string(),  // 50
                "resp_new".to_string()  // 100
            ],
            "eviction kept the wrong rows: {left:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
