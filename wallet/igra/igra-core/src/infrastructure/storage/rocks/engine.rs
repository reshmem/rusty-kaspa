//! RocksDB-backed storage engine.
//!
//! # Lock Semantics
//!
//! RocksDB itself is thread-safe, but we use coarse-grained mutexes to keep higher-level
//! invariants and batch updates consistent.
//!
//! - `crdt_lock`: guards CRDT merge/update operations (`Storage::merge_event_crdt`, signature updates, cleanup).
//! - `phase_lock`: guards two-phase lifecycle/proposal operations (`PhaseStorage`).
//! - `hyperlane_lock`: guards Hyperlane delivery indexing (`Storage::hyperlane_mark_delivered`).
//!
//! Locks are acquired with a bounded timeout (`STORAGE_LOCK_TIMEOUT_SECS`) to avoid
//! indefinite deadlock under contention. When in doubt, acquire at most one lock at a time.
//!
//! # Column Families
//!
//! See `schema.rs` for column family names and key prefixes.

use crate::domain::StoredEventCrdt;
use crate::foundation::ThresholdError;
use crate::foundation::{EventId, ExternalId, GroupId, PeerId, SessionId, TxTemplateHash};
use crate::infrastructure::storage::rocks::migration::open_db_with_cfs;
use crate::infrastructure::storage::rocks::schema::*;
use crate::infrastructure::storage::Storage;
use crate::storage_err;
use bincode::Options;
use log::{debug, info, warn};
use rocksdb::{checkpoint::Checkpoint, ColumnFamily, Direction, IteratorMode, DB};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::{env, fs};

mod batch;
mod phase;
mod storage;

pub struct RocksStorage {
    db: Arc<DB>,
    crdt_lock: std::sync::Mutex<()>,
    phase_lock: std::sync::Mutex<()>,
    hyperlane_lock: std::sync::Mutex<()>,
}

impl RocksStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        Self::open_with_options(path, false)
    }

    pub fn open_with_options(path: impl AsRef<Path>, allow_schema_wipe: bool) -> Result<Self, ThresholdError> {
        let path = path.as_ref();
        debug!("opening RocksStorage path={}", path.display());
        let db = open_db_with_cfs(path)?;
        let storage = Self {
            db: Arc::new(db),
            crdt_lock: std::sync::Mutex::new(()),
            phase_lock: std::sync::Mutex::new(()),
            hyperlane_lock: std::sync::Mutex::new(()),
        };
        if let Err(err) = storage.maybe_run_migrations() {
            if allow_schema_wipe {
                if let ThresholdError::SchemaMismatch { stored, current } = err {
                    warn!("schema mismatch (stored={}, current={}); wiping db path={}", stored, current, path.display());
                    drop(storage);
                    if path.exists() {
                        fs::remove_dir_all(path).map_err(|err| storage_err!("fs::remove_dir_all checkpoint_cleanup", err))?;
                    }
                    return Self::open_with_options(path, false);
                }
            }
            return Err(err);
        }
        info!("RocksStorage opened path={}", path.display());
        Ok(storage)
    }

    pub fn open_default() -> Result<Self, ThresholdError> {
        if let Ok(data_dir) = env::var("KASPA_DATA_DIR") {
            let trimmed = data_dir.trim();
            if !trimmed.is_empty() {
                let dir = Path::new(trimmed);
                fs::create_dir_all(dir).map_err(|err| storage_err!("fs::create_dir_all kaspa_data_dir", err))?;
                let path = dir.join("threshold-signing");
                debug!("opening RocksStorage (KASPA_DATA_DIR) path={}", path.display());
                return Self::open_with_options(path, false);
            }
        }
        let base = env::current_dir().map_err(|err| storage_err!("env::current_dir", err))?;
        let dir = base.join(".igra");
        fs::create_dir_all(&dir).map_err(|err| storage_err!("fs::create_dir_all default_dir", err))?;
        let path = dir.join("threshold-signing");
        debug!("opening RocksStorage (default dir) path={}", path.display());
        Self::open_with_options(path, false)
    }

    pub fn open_in_dir(data_dir: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        Self::open_in_dir_with_options(data_dir, false)
    }

    pub fn open_in_dir_with_options(data_dir: impl AsRef<Path>, allow_schema_wipe: bool) -> Result<Self, ThresholdError> {
        let dir = data_dir.as_ref();
        if dir.as_os_str().is_empty() {
            return Self::open_default();
        }
        fs::create_dir_all(dir).map_err(|err| storage_err!("fs::create_dir_all open_in_dir", err))?;
        let path = dir.join("threshold-signing");
        debug!("opening RocksStorage in dir path={}", path.display());
        Self::open_with_options(path, allow_schema_wipe)
    }

    pub fn create_checkpoint(&self, path: impl AsRef<Path>) -> Result<(), ThresholdError> {
        let path = path.as_ref();
        info!("creating RocksStorage checkpoint path={}", path.display());
        if path.exists() {
            let mut entries = fs::read_dir(path).map_err(|err| storage_err!("fs::read_dir checkpoint", err))?;
            if entries.next().is_some() {
                return Err(ThresholdError::StorageError {
                    operation: "rocksdb checkpoint".to_string(),
                    details: format!("checkpoint directory is not empty: {}", path.display()),
                });
            }
            fs::remove_dir_all(path).map_err(|err| storage_err!("fs::remove_dir_all checkpoint", err))?;
        }
        let checkpoint = Checkpoint::new(&self.db).map_err(|err| storage_err!("rocksdb::Checkpoint::new", err))?;
        checkpoint.create_checkpoint(path).map_err(|err| storage_err!("rocksdb::create_checkpoint", err))?;
        info!("checkpoint created path={}", path.display());
        Ok(())
    }

    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily, ThresholdError> {
        self.db.cf_handle(name).ok_or_else(|| ThresholdError::StorageError {
            operation: "rocksdb cf_handle".to_string(),
            details: format!("missing column family: {}", name),
        })
    }

    fn maybe_run_migrations(&self) -> Result<(), ThresholdError> {
        const SCHEMA_VERSION: u32 = 2;
        match self.schema_version()? {
            None => {
                // Fresh DB
                info!("initializing fresh db schema schema_version={}", SCHEMA_VERSION);
                self.set_schema_version(SCHEMA_VERSION)?;
            }
            Some(v) if v == SCHEMA_VERSION => { /* ok */ }
            Some(v) => return Err(ThresholdError::SchemaMismatch { stored: v, current: SCHEMA_VERSION }),
        }
        Ok(())
    }

    fn schema_version(&self) -> Result<Option<u32>, ThresholdError> {
        let cf = self.cf_handle(CF_METADATA)?;
        match self.db.get_cf(cf, b"schema_version") {
            Ok(Some(bytes)) if bytes.len() == 4 => {
                let array: [u8; 4] = bytes.as_slice().try_into().map_err(|_| ThresholdError::StorageError {
                    operation: "schema_version decode".to_string(),
                    details: "corrupt schema version".to_string(),
                })?;
                Ok(Some(u32::from_be_bytes(array)))
            }
            Ok(Some(_)) => Err(ThresholdError::StorageError {
                operation: "schema_version decode".to_string(),
                details: "corrupt schema version".to_string(),
            }),
            Ok(None) => Ok(None),
            Err(e) => Err(storage_err!("rocksdb get_cf schema_version", e)),
        }
    }

    fn set_schema_version(&self, version: u32) -> Result<(), ThresholdError> {
        let cf = self.cf_handle(CF_METADATA)?;
        self.db.put_cf(cf, b"schema_version", version.to_be_bytes()).map_err(ThresholdError::from)
    }

    fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ThresholdError> {
        bincode::DefaultOptions::new().with_fixint_encoding().serialize(value).map_err(|err| err.into())
    }

    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ThresholdError> {
        bincode::DefaultOptions::new().with_fixint_encoding().deserialize(bytes).map_err(|err| err.into())
    }

    fn key_group(group_id: &GroupId) -> Vec<u8> {
        KeyBuilder::with_capacity(4 + group_id.as_hash().len()).prefix(b"grp:").hash32(group_id.as_hash()).build()
    }

    fn key_event(event_id: &EventId) -> Vec<u8> {
        KeyBuilder::with_capacity(4 + event_id.as_hash().len()).prefix(b"evt:").hash32(event_id.as_hash()).build()
    }

    fn key_event_active_template(event_id: &EventId) -> Vec<u8> {
        KeyBuilder::with_capacity(11 + event_id.as_hash().len()).prefix(b"evt_active:").hash32(event_id.as_hash()).build()
    }

    fn key_event_completion(event_id: &EventId) -> Vec<u8> {
        KeyBuilder::with_capacity(15 + event_id.as_hash().len()).prefix(b"evt_completion:").hash32(event_id.as_hash()).build()
    }

    fn key_event_crdt(event_id: &EventId, tx_template_hash: &TxTemplateHash) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + event_id.as_hash().len() + 1 + tx_template_hash.as_hash().len())
            .prefix(b"evt_crdt:")
            .hash32(event_id.as_hash())
            .sep()
            .hash32(tx_template_hash.as_hash())
            .build()
    }

    fn key_event_crdt_prefix(event_id: &EventId) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + event_id.as_hash().len() + 1).prefix(b"evt_crdt:").hash32(event_id.as_hash()).sep().build()
    }

    fn key_event_phase(event_id: &EventId) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + event_id.as_hash().len()).prefix(b"evt_phase:").hash32(event_id.as_hash()).build()
    }

    fn key_event_signed_hash(event_id: &EventId) -> Vec<u8> {
        KeyBuilder::with_capacity(17 + event_id.as_hash().len()).prefix(b"evt_signed_hash:").hash32(event_id.as_hash()).build()
    }

    fn key_event_proposal_prefix(event_id: &EventId) -> Vec<u8> {
        KeyBuilder::with_capacity(9 + event_id.as_hash().len() + 1).prefix(b"evt_prop:").hash32(event_id.as_hash()).sep().build()
    }

    fn key_event_proposal_round_prefix(event_id: &EventId, round: u32) -> Vec<u8> {
        KeyBuilder::with_capacity(9 + event_id.as_hash().len() + 1 + 4 + 1)
            .prefix(b"evt_prop:")
            .hash32(event_id.as_hash())
            .sep()
            .u32_be(round)
            .sep()
            .build()
    }

    fn key_event_proposal(event_id: &EventId, round: u32, proposer_peer_id: &PeerId) -> Vec<u8> {
        KeyBuilder::with_capacity(9 + event_id.as_hash().len() + 1 + 4 + 1 + proposer_peer_id.len())
            .prefix(b"evt_prop:")
            .hash32(event_id.as_hash())
            .sep()
            .u32_be(round)
            .sep()
            .str(proposer_peer_id.as_str())
            .build()
    }

    fn key_seen(sender_peer_id: &PeerId, session_id: &SessionId, seq_no: u64) -> Vec<u8> {
        KeyBuilder::with_capacity(6 + sender_peer_id.len() + 1 + session_id.as_hash().len() + 1 + 8)
            .prefix(b"seen:")
            .str(sender_peer_id.as_str())
            .sep()
            .bytes(session_id.as_hash())
            .sep()
            .u64_be(seq_no)
            .build()
    }

    fn key_volume(day_start_nanos: u64) -> Vec<u8> {
        KeyBuilder::with_capacity(4 + 8).prefix(b"vol:").u64_be(day_start_nanos).build()
    }

    fn key_hyperlane_delivered_count() -> &'static [u8] {
        b"hyperlane_delivered_count"
    }

    fn key_hyperlane_message(message_id: &ExternalId) -> Vec<u8> {
        KeyBuilder::with_capacity(7 + message_id.as_hash().len()).prefix(b"hl_msg:").hash32(message_id.as_hash()).build()
    }

    fn key_hyperlane_delivery_index(daa_score: u64, message_id: &ExternalId) -> Vec<u8> {
        KeyBuilder::with_capacity(7 + 8 + message_id.as_hash().len())
            .prefix(b"hl_dlv:")
            .u64_be(daa_score)
            .hash32(message_id.as_hash())
            .build()
    }

    fn add_to_daily_volume(&self, amount_sompi: u64, timestamp_nanos: u64) -> Result<(), ThresholdError> {
        let day_start = crate::foundation::day_start_nanos(timestamp_nanos);
        let key = Self::key_volume(day_start);
        debug!("add_to_daily_volume amount_sompi={} day_start={}", amount_sompi, day_start);

        // Use merge operator for atomic accumulation - eliminates race condition
        // The merge operator handles concurrent updates safely without locks
        let value = amount_sompi.to_be_bytes();
        let cf = self.cf_handle(CF_VOLUME)?;
        self.db.merge_cf(cf, key, value).map_err(|err| storage_err!("rocksdb", err))
    }

    fn volume_from_index(&self, since_day_start: u64) -> Result<Option<u64>, ThresholdError> {
        let key = Self::key_volume(since_day_start);
        let cf = self.cf_handle(CF_VOLUME)?;
        let value = self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb", err))?;
        let Some(bytes) = value else {
            return Ok(None);
        };
        let amount_bytes: [u8; 8] = bytes.as_slice().try_into().map_err(|_| ThresholdError::StorageError {
            operation: "volume_from_index decode".to_string(),
            details: "invalid volume value format".to_string(),
        })?;
        Ok(Some(u64::from_be_bytes(amount_bytes)))
    }

    fn volume_from_scan(&self, since_day_start: u64) -> Result<u64, ThresholdError> {
        let mut total = 0u64;
        let mut counted = 0usize;
        let mut seen_events = HashSet::new();
        let prefix = b"evt_crdt:";
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|err| storage_err!("rocksdb", err))?;
            if !key.starts_with(prefix) {
                break;
            }
            let state = Self::decode::<StoredEventCrdt>(&value)?;
            if state.completion.is_none() {
                continue;
            }
            if seen_events.contains(&state.event_id) {
                continue;
            }
            seen_events.insert(state.event_id);

            let Some(event) = self.get_event(&state.event_id)? else { continue };

            let event_day = crate::foundation::day_start_nanos(event.received_at_nanos);
            if event_day == crate::foundation::day_start_nanos(since_day_start) {
                total = total.saturating_add(event.event.amount_sompi);
                counted += 1;
            }
        }
        debug!("volume_from_scan summary since_day_start={} counted={} total={}", since_day_start, counted, total);
        Ok(total)
    }
}

impl RocksStorage {
    pub fn compact(&self) -> Result<(), ThresholdError> {
        debug!("rocksdb compact_range start");
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
        debug!("rocksdb compact_range complete");
        Ok(())
    }
}
