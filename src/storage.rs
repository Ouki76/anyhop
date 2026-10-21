//! Embedded persistence (redb): key health, OAuth token cache, usage stats.
//! Writes are batched through a channel and flushed every 2s in one transaction.
//!
//! Records are keyed by sha256(secret) hashes, but OAuth access tokens and
//! runtime-added provider keys (EXTRAS) are stored in cleartext by necessity —
//! the state file is created with 0600 permissions; treat it as a secret.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::Digest;

const HEALTH: TableDefinition<&str, &[u8]> = TableDefinition::new("health");
const OAUTH: TableDefinition<&str, &[u8]> = TableDefinition::new("oauth");
const STATS: TableDefinition<&str, &[u8]> = TableDefinition::new("stats");
/// Keys added at runtime via the dashboard: "extra:{provider}" -> JSON [secret, ...].
const EXTRAS: TableDefinition<&str, &[u8]> = TableDefinition::new("extras");
/// Feed buffers: "feed:events" / "feed:requests" -> JSON array.
const FEEDS: TableDefinition<&str, &[u8]> = TableDefinition::new("feeds");

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

#[derive(Debug)]
enum StorageMsg {
    Health { key: String, rec: HealthRecord },
    OAuth { key: String, rec: OAuthRecord },
    Stats { key: String, rec: StatsRecord },
    /// Runtime-added keys for a provider, as a complete list (idempotent: the
    /// last writer wins, so add and remove cannot interleave into a wrong state).
    ExtraKeys { provider: String, secrets: Vec<String> },
    Feed { key: String, data: Vec<u8> },
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
            // Flush is handled inline by the writer loop, never queued.
            StorageMsg::Flush(_) => unreachable!("flush messages are not queued"),
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    db: Arc<Database>,
    tx: tokio::sync::mpsc::UnboundedSender<StorageMsg>,
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
        }
        wtx.commit()?;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StorageMsg>();
        let writer_db = db.clone();
        tokio::spawn(async move {
            let mut pending: HashMap<String, StorageMsg> = HashMap::new();
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(StorageMsg::Flush(ack)) => {
                            flush(&writer_db, &mut pending);
                            let _ = ack.send(());
                        }
                        Some(m) => {
                            // Extras are rare (admin actions) and carry their whole
                            // list, so write them immediately instead of batching.
                            if let StorageMsg::ExtraKeys { .. } = m {
                                flush_extras(&writer_db, &m);
                            } else {
                                pending.insert(m.key(), m);
                            }
                            while let Ok(m) = rx.try_recv() {
                                match m {
                                    StorageMsg::Flush(ack) => {
                                        flush(&writer_db, &mut pending);
                                        let _ = ack.send(());
                                    }
                                    StorageMsg::ExtraKeys { .. } => flush_extras(&writer_db, &m),
                                    _ => { pending.insert(m.key(), m); }
                                }
                            }
                        }
                        None => {
                            flush(&writer_db, &mut pending);
                            break;
                        }
                    },
                    _ = interval.tick() => flush(&writer_db, &mut pending),
                }
            }
        });
        Ok(Self { db, tx })
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

    /// Flush all pending writes and wait for the ack (shutdown path).
    pub async fn flush_async(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(StorageMsg::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
    }
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

fn flush(db: &Arc<Database>, pending: &mut HashMap<String, StorageMsg>) {
    if pending.is_empty() {
        return;
    }
    // Open the write tx BEFORE draining: on failure the batch survives to the
    // next tick instead of being silently dropped.
    let wtx = match db.begin_write() {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("storage: flush failed to begin write tx ({e}), {} msgs kept", pending.len());
            return;
        }
    };
    let msgs: Vec<StorageMsg> = pending.drain().map(|(_, m)| m).collect();
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
    }
    if let Err(e) = wtx.commit() {
        tracing::warn!("storage: commit failed: {e}");
    }
}
