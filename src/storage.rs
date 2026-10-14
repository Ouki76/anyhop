//! Embedded persistence (redb): key health, OAuth token cache, usage stats.
//! Writes are batched through a channel and flushed every 2s in one transaction.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
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

/// Storage key for a pool credential: "{provider}:{sha256(secret)[..16]}".
/// Secrets are never persisted, only their hashes.
pub fn key_id(provider: &str, secret: &str) -> String {
    let digest = sha2::Sha256::digest(secret.as_bytes());
    format!("{provider}:{}", hex::encode(&digest[..16]))
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

#[derive(Debug, Clone)]
enum StorageMsg {
    Health { key: String, rec: HealthRecord },
    OAuth { key: String, rec: OAuthRecord },
    Stats { key: String, rec: StatsRecord },
    ExtraKey { provider: String, secret: String },
    Feed { key: String, data: Vec<u8> },
}

impl StorageMsg {
    fn key(&self) -> String {
        match self {
            StorageMsg::Health { key, .. }
            | StorageMsg::OAuth { key, .. }
            | StorageMsg::Stats { key, .. } => key.clone(),
            StorageMsg::ExtraKey { provider, .. } => format!("extra:{provider}"),
            StorageMsg::Feed { key, .. } => key.clone(),
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
                        Some(m) => {
                            // ExtraKey entries must not dedupe — collect them all.
                            if let StorageMsg::ExtraKey { .. } = m {
                                flush_extra(&writer_db, &m);
                            } else {
                                pending.insert(m.key(), m);
                            }
                            while let Ok(m) = rx.try_recv() {
                                if let StorageMsg::ExtraKey { .. } = m {
                                    flush_extra(&writer_db, &m);
                                } else {
                                    pending.insert(m.key(), m);
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
        let _ = self.tx.send(StorageMsg::ExtraKey {
            provider: provider.to_string(),
            secret: secret.to_string(),
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
}

fn flush_extra(db: &Arc<Database>, msg: &StorageMsg) {
    let StorageMsg::ExtraKey { provider, secret } = msg else {
        return;
    };
    let Ok(wtx) = db.begin_write() else { return };
    {
        let Ok(mut t) = wtx.open_table(EXTRAS) else { return };
        let key = format!("extra:{provider}");
        let mut list: Vec<String> = t
            .get(key.as_str())
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(v.value()).ok())
            .unwrap_or_default();
        if !list.contains(secret) {
            list.push(secret.clone());
            if let Ok(j) = serde_json::to_vec(&list) {
                let _ = t.insert(key.as_str(), j.as_slice());
            }
        }
    }
    let _ = wtx.commit();
}

fn flush(db: &Arc<Database>, pending: &mut HashMap<String, StorageMsg>) {
    if pending.is_empty() {
        return;
    }
    let msgs: Vec<StorageMsg> = pending.drain().map(|(_, m)| m).collect();
    let Ok(wtx) = db.begin_write() else {
        return;
    };
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
    let _ = wtx.commit();
}
