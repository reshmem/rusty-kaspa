use crate::domain::{CrdtSignatureRecord, GroupConfig, SigningEvent, StoredCompletionRecord, StoredEventCrdt};
use crate::foundation::ThresholdError;
use crate::foundation::{Hash32, PeerId, SessionId, TransactionId};
use crate::infrastructure::storage::rocks::migration::open_db_with_cfs;
use crate::infrastructure::storage::rocks::schema::*;
use crate::infrastructure::storage::{BatchTransaction, CrdtStorageStats, Storage};
use crate::infrastructure::transport::messages::{CompletionRecord, EventCrdtState};
use bincode::Options;
use rocksdb::{checkpoint::Checkpoint, ColumnFamily, Direction, IteratorMode, WriteBatch, DB};
use std::collections::{HashMap, HashSet};
use log::{debug, info, trace, warn};
use std::path::Path;
use std::sync::Arc;
use std::{env, fs};

pub struct RocksStorage {
    db: Arc<DB>,
    crdt_lock: std::sync::Mutex<()>,
}

impl RocksStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        let path = path.as_ref();
        debug!("opening RocksStorage path={}", path.display());
        let db = open_db_with_cfs(path)?;
        let storage = Self { db: Arc::new(db), crdt_lock: std::sync::Mutex::new(()) };
        storage.maybe_run_migrations()?;
        info!("RocksStorage opened path={}", path.display());
        Ok(storage)
    }

    pub fn open_default() -> Result<Self, ThresholdError> {
        if let Ok(data_dir) = env::var("KASPA_DATA_DIR") {
            let trimmed = data_dir.trim();
            if !trimmed.is_empty() {
                let dir = Path::new(trimmed);
                fs::create_dir_all(dir).map_err(|err| ThresholdError::Message(err.to_string()))?;
                let path = dir.join("threshold-signing");
                debug!("opening RocksStorage (KASPA_DATA_DIR) path={}", path.display());
                return Self::open(path);
            }
        }
        let base = env::current_dir().map_err(|err| ThresholdError::Message(err.to_string()))?;
        let dir = base.join(".igra");
        fs::create_dir_all(&dir).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let path = dir.join("threshold-signing");
        debug!("opening RocksStorage (default dir) path={}", path.display());
        Self::open(path)
    }

    pub fn open_in_dir(data_dir: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        let dir = data_dir.as_ref();
        if dir.as_os_str().is_empty() {
            return Self::open_default();
        }
        fs::create_dir_all(dir).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let path = dir.join("threshold-signing");
        debug!("opening RocksStorage in dir path={}", path.display());
        Self::open(path)
    }

    pub fn create_checkpoint(&self, path: impl AsRef<Path>) -> Result<(), ThresholdError> {
        let path = path.as_ref();
        info!("creating RocksStorage checkpoint path={}", path.display());
        if path.exists() {
            let mut entries = fs::read_dir(path).map_err(|err| ThresholdError::Message(err.to_string()))?;
            if entries.next().is_some() {
                return Err(ThresholdError::Message(format!("checkpoint directory is not empty: {}", path.display())));
            }
            fs::remove_dir_all(path).map_err(|err| ThresholdError::Message(err.to_string()))?;
        }
        let checkpoint = Checkpoint::new(&self.db).map_err(|err| ThresholdError::Message(err.to_string()))?;
        checkpoint.create_checkpoint(path).map_err(|err| ThresholdError::Message(err.to_string()))?;
        info!("checkpoint created path={}", path.display());
        Ok(())
    }

    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily, ThresholdError> {
        self.db.cf_handle(name).ok_or_else(|| ThresholdError::Message(format!("missing column family: {}", name)))
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
            Some(v) if v < SCHEMA_VERSION => {
                warn!("database schema version {} is older than supported {}; migration not implemented", v, SCHEMA_VERSION);
                return Err(ThresholdError::Message("database schema too old; migration required".to_string()));
            }
            Some(v) => {
                return Err(ThresholdError::Message(format!(
                    "database schema version {} is newer than supported {}; please upgrade software",
                    v, SCHEMA_VERSION
                )));
            }
        }
        Ok(())
    }

    fn schema_version(&self) -> Result<Option<u32>, ThresholdError> {
        let cf = self.cf_handle(CF_METADATA)?;
        match self.db.get_cf(cf, b"schema_version") {
            Ok(Some(bytes)) if bytes.len() == 4 => {
                let array: [u8; 4] =
                    bytes.as_slice().try_into().map_err(|_| ThresholdError::Message("corrupt schema version".to_string()))?;
                Ok(Some(u32::from_be_bytes(array)))
            }
            Ok(Some(_)) => Err(ThresholdError::Message("corrupt schema version".to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(ThresholdError::Message(e.to_string())),
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

    fn key_group(group_id: &Hash32) -> Vec<u8> {
        KeyBuilder::with_capacity(4 + group_id.len()).prefix(b"grp:").hash32(group_id).build()
    }

    fn key_event(event_hash: &Hash32) -> Vec<u8> {
        KeyBuilder::with_capacity(4 + event_hash.len()).prefix(b"evt:").hash32(event_hash).build()
    }

    fn key_event_crdt(event_hash: &Hash32, tx_template_hash: &Hash32) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + event_hash.len() + 1 + tx_template_hash.len())
            .prefix(b"evt_crdt:")
            .hash32(event_hash)
            .sep()
            .hash32(tx_template_hash)
            .build()
    }

    fn key_event_crdt_prefix(event_hash: &Hash32) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + event_hash.len() + 1)
            .prefix(b"evt_crdt:")
            .hash32(event_hash)
            .sep()
            .build()
    }

    fn now_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
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

    fn day_start_nanos(now_nanos: u64) -> u64 {
        let nanos_per_day = 24 * 60 * 60 * 1_000_000_000u64;
        (now_nanos / nanos_per_day) * nanos_per_day
    }

    fn add_to_daily_volume(&self, amount_sompi: u64, timestamp_nanos: u64) -> Result<(), ThresholdError> {
        let day_start = Self::day_start_nanos(timestamp_nanos);
        let key = Self::key_volume(day_start);
        debug!("add_to_daily_volume amount_sompi={} day_start={}", amount_sompi, day_start);

        // Use merge operator for atomic accumulation - eliminates race condition
        // The merge operator handles concurrent updates safely without locks
        let value = amount_sompi.to_be_bytes();
        let cf = self.cf_handle(CF_VOLUME)?;
        self.db.merge_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn volume_from_index(&self, since_day_start: u64) -> Result<Option<u64>, ThresholdError> {
        let key = Self::key_volume(since_day_start);
        let cf = self.cf_handle(CF_VOLUME)?;
        let value = self.db.get_cf(cf, &key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let Some(bytes) = value else {
            return Ok(None);
        };
        let amount_bytes: [u8; 8] =
            bytes.as_slice().try_into().map_err(|_| ThresholdError::Message("invalid volume value format".to_string()))?;
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
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            let state = Self::decode::<StoredEventCrdt>(&value)?;
            if state.completion.is_none() {
                continue;
            }
            if seen_events.contains(&state.event_hash) {
                continue;
            }
            seen_events.insert(state.event_hash);

            let event = match state.signing_event {
                Some(ev) => Some(ev),
                None => self.get_event(&state.event_hash)?,
            };
            let Some(event) = event else { continue };

            let event_day = Self::day_start_nanos(event.timestamp_nanos);
            if event_day == Self::day_start_nanos(since_day_start) {
                total = total.saturating_add(event.amount_sompi);
                counted += 1;
            }
        }
        debug!(
            "volume_from_scan summary since_day_start={} counted={} total={}",
            since_day_start, counted, total
        );
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

impl Storage for RocksStorage {
    fn upsert_group_config(&self, group_id: Hash32, config: GroupConfig) -> Result<(), ThresholdError> {
        trace!("upsert_group_config group_id={}", hex::encode(group_id));
        let key = Self::key_group(&group_id);
        let value = Self::encode(&config)?;
        let cf = self.cf_handle(CF_GROUP)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>, ThresholdError> {
        trace!("get_group_config group_id={}", hex::encode(group_id));
        let key = Self::key_group(group_id);
        let cf = self.cf_handle(CF_GROUP)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<(), ThresholdError> {
        debug!("insert_event event_hash={} event_id={}", hex::encode(event_hash), event.event_id);
        let key = Self::key_event(&event_hash);
        let cf = self.cf_handle(CF_EVENT)?;
        if self.db.get_cf(cf, &key).map_err(|e| ThresholdError::StorageError(e.to_string()))?.is_some() {
            return Ok(());
        }

        let value = Self::encode(&event)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))?;
        debug!("event stored event_hash={}", hex::encode(event_hash));
        Ok(())
    }

    fn get_event(&self, event_hash: &Hash32) -> Result<Option<SigningEvent>, ThresholdError> {
        trace!("get_event event_hash={}", hex::encode(event_hash));
        let key = Self::key_event(event_hash);
        let cf = self.cf_handle(CF_EVENT)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn get_event_crdt(&self, event_hash: &Hash32, tx_template_hash: &Hash32) -> Result<Option<StoredEventCrdt>, ThresholdError> {
        let key = Self::key_event_crdt(event_hash, tx_template_hash);
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn merge_event_crdt(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        incoming: &EventCrdtState,
        signing_event: Option<&SigningEvent>,
        kpsbt_blob: Option<&[u8]>,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let _guard = self
            .crdt_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError("rocks crdt lock poisoned".to_string()))?;

        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let key = Self::key_event_crdt(event_hash, tx_template_hash);
        let now_nanos = Self::now_nanos();

        let mut local: StoredEventCrdt = match self.db.get_cf(cf, &key).map_err(|e| ThresholdError::Message(e.to_string()))? {
            Some(bytes) => Self::decode(&bytes)?,
            None => StoredEventCrdt {
                event_hash: *event_hash,
                tx_template_hash: *tx_template_hash,
                signing_event: None,
                kpsbt_blob: None,
                signatures: Vec::new(),
                completion: None,
                created_at_nanos: now_nanos,
                updated_at_nanos: now_nanos,
            },
        };

        let mut changed = false;

        if local.signing_event.is_none() {
            if let Some(ev) = signing_event {
                local.signing_event = Some(ev.clone());
                changed = true;
            }
        }

        if local.kpsbt_blob.is_none() {
            if let Some(blob) = kpsbt_blob {
                local.kpsbt_blob = Some(blob.to_vec());
                changed = true;
            }
        }

        let mut existing: HashSet<(u32, Vec<u8>)> = HashSet::with_capacity(local.signatures.len());
        for sig in &local.signatures {
            existing.insert((sig.input_index, sig.pubkey.clone()));
        }

        for sig in &incoming.signatures {
            let sig_key = (sig.input_index, sig.pubkey.clone());
            if !existing.contains(&sig_key) {
                local.signatures.push(CrdtSignatureRecord {
                    input_index: sig.input_index,
                    pubkey: sig.pubkey.clone(),
                    signature: sig.signature.clone(),
                    signer_peer_id: sig.signer_peer_id.clone().unwrap_or_else(|| PeerId::from("unknown")),
                    timestamp_nanos: sig.timestamp_nanos,
                });
                existing.insert(sig_key);
                changed = true;
            }
        }

        if let Some(incoming_completion) = &incoming.completion {
            match &local.completion {
                None => {
                    local.completion = Some(StoredCompletionRecord {
                        tx_id: TransactionId::from(incoming_completion.tx_id),
                        submitter_peer_id: incoming_completion.submitter_peer_id.clone(),
                        timestamp_nanos: incoming_completion.timestamp_nanos,
                        blue_score: incoming_completion.blue_score,
                    });
                    changed = true;
                }
                Some(existing_completion) => {
                    if incoming_completion.timestamp_nanos > existing_completion.timestamp_nanos {
                        local.completion = Some(StoredCompletionRecord {
                            tx_id: TransactionId::from(incoming_completion.tx_id),
                            submitter_peer_id: incoming_completion.submitter_peer_id.clone(),
                            timestamp_nanos: incoming_completion.timestamp_nanos,
                            blue_score: incoming_completion.blue_score,
                        });
                        changed = true;
                    }
                }
            }
        }

        if changed {
            local.updated_at_nanos = now_nanos;
            let value = Self::encode(&local)?;
            self.db.put_cf(cf, &key, value).map_err(|e| ThresholdError::Message(e.to_string()))?;
        }

        Ok((local, changed))
    }

    fn add_signature_to_crdt(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        input_index: u32,
        pubkey: &[u8],
        signature: &[u8],
        signer_peer_id: &PeerId,
        timestamp_nanos: u64,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let _guard = self
            .crdt_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError("rocks crdt lock poisoned".to_string()))?;

        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let key = Self::key_event_crdt(event_hash, tx_template_hash);
        let now_nanos = Self::now_nanos();

        let mut local: StoredEventCrdt = match self.db.get_cf(cf, &key).map_err(|e| ThresholdError::Message(e.to_string()))? {
            Some(bytes) => Self::decode(&bytes)?,
            None => StoredEventCrdt {
                event_hash: *event_hash,
                tx_template_hash: *tx_template_hash,
                signing_event: None,
                kpsbt_blob: None,
                signatures: Vec::new(),
                completion: None,
                created_at_nanos: now_nanos,
                updated_at_nanos: now_nanos,
            },
        };

        let already = local
            .signatures
            .iter()
            .any(|s| s.input_index == input_index && s.pubkey.as_slice() == pubkey);

        if already {
            return Ok((local, false));
        }

        local.signatures.push(CrdtSignatureRecord {
            input_index,
            pubkey: pubkey.to_vec(),
            signature: signature.to_vec(),
            signer_peer_id: signer_peer_id.clone(),
            timestamp_nanos,
        });
        local.updated_at_nanos = now_nanos;

        let value = Self::encode(&local)?;
        self.db.put_cf(cf, &key, value).map_err(|e| ThresholdError::Message(e.to_string()))?;
        Ok((local, true))
    }

    fn mark_crdt_completed(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        tx_id: TransactionId,
        submitter_peer_id: &PeerId,
        timestamp_nanos: u64,
        blue_score: Option<u64>,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let incoming = EventCrdtState {
            signatures: vec![],
            completion: Some(CompletionRecord {
                tx_id: *tx_id.as_hash(),
                submitter_peer_id: submitter_peer_id.clone(),
                timestamp_nanos,
                blue_score,
            }),
            signing_event: None,
            kpsbt_blob: None,
            version: 0,
        };
        let (state, changed) = self.merge_event_crdt(event_hash, tx_template_hash, &incoming, None, None)?;
        if changed {
            if let Some(event) = self.get_event(event_hash)? {
                self.add_to_daily_volume(event.amount_sompi, event.timestamp_nanos)?;
            }
        }
        Ok((state, changed))
    }

    fn crdt_has_threshold(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        input_count: usize,
        required: usize,
    ) -> Result<bool, ThresholdError> {
        let state = match self.get_event_crdt(event_hash, tx_template_hash)? {
            Some(s) => s,
            None => return Ok(false),
        };

        if input_count == 0 || required == 0 {
            return Ok(false);
        }

        let mut per_input: HashMap<u32, HashSet<&[u8]>> = HashMap::new();
        for sig in &state.signatures {
            if (sig.input_index as usize) < input_count {
                per_input.entry(sig.input_index).or_default().insert(sig.pubkey.as_slice());
            }
        }

        Ok((0..input_count as u32).all(|idx| per_input.get(&idx).map_or(false, |set| set.len() >= required)))
    }

    fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        let prefix = b"evt_crdt:";
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::Message(e.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            let state: StoredEventCrdt = Self::decode(&value)?;
            if state.completion.is_none() {
                results.push(state);
            }
        }
        Ok(results)
    }

    fn list_event_crdts_for_event(&self, event_hash: &Hash32) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        let prefix = Self::key_event_crdt_prefix(event_hash);
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::Message(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            let state: StoredEventCrdt = Self::decode(&value)?;
            results.push(state);
        }
        Ok(results)
    }

    fn crdt_storage_stats(&self) -> Result<CrdtStorageStats, ThresholdError> {
        let prefix = b"evt_crdt:";
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let mut total = 0u64;
        let mut pending = 0u64;

        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::Message(e.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            total += 1;
            let state: StoredEventCrdt = Self::decode(&value)?;
            if state.completion.is_none() {
                pending += 1;
            }
        }

        let cf_estimated_num_keys = self
            .db
            .property_int_value_cf(cf, "rocksdb.estimate-num-keys")
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let cf_estimated_live_data_size_bytes = self
            .db
            .property_int_value_cf(cf, "rocksdb.estimate-live-data-size")
            .map_err(|err| ThresholdError::Message(err.to_string()))?;

        Ok(CrdtStorageStats {
            total_event_crdts: total,
            pending_event_crdts: pending,
            completed_event_crdts: total.saturating_sub(pending),
            cf_estimated_num_keys,
            cf_estimated_live_data_size_bytes,
        })
    }

    fn cleanup_completed_event_crdts(&self, older_than_nanos: u64) -> Result<usize, ThresholdError> {
        let _guard = self
            .crdt_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError("rocks crdt lock poisoned".to_string()))?;

        let prefix = b"evt_crdt:";
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        let mut batch = WriteBatch::default();
        let mut deleted = 0usize;

        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::Message(e.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            let state: StoredEventCrdt = Self::decode(&value)?;
            let Some(completion) = state.completion.as_ref() else { continue };
            if completion.timestamp_nanos < older_than_nanos {
                batch.delete_cf(cf, key);
                deleted += 1;
            }
        }

        if deleted > 0 {
            self.db.write(batch).map_err(|err| ThresholdError::Message(err.to_string()))?;
        }

        Ok(deleted)
    }

    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64, ThresholdError> {
        trace!("get_volume_since timestamp_nanos={}", timestamp_nanos);
        let day_start = Self::day_start_nanos(timestamp_nanos);
        if let Some(total) = self.volume_from_index(day_start)? {
            debug!("volume_from_index hit day_start={} total={}", day_start, total);
            return Ok(total);
        }
        let total = self.volume_from_scan(day_start)?;
        debug!("volume_from_scan computed day_start={} total={}", day_start, total);
        // Cache the computed total for this day to speed up subsequent reads.
        let cf = self.cf_handle(CF_VOLUME)?;
        let key = Self::key_volume(day_start);
        self.db.put_cf(cf, key, total.to_be_bytes()).map_err(|e| ThresholdError::Message(e.to_string()))?;
        Ok(total)
    }

    fn health_check(&self) -> Result<(), ThresholdError> {
        self.db.property_value("rocksdb.stats").map_err(|err| ThresholdError::Message(err.to_string()))?;
        Ok(())
    }

    fn mark_seen_message(
        &self,
        sender_peer_id: &PeerId,
        session_id: &SessionId,
        seq_no: u64,
        timestamp_nanos: u64,
    ) -> Result<bool, ThresholdError> {
        let key = Self::key_seen(sender_peer_id, session_id, seq_no);
        let cf = self.cf_handle(CF_SEEN)?;
        let existing = self.db.get_cf(cf, &key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        if existing.is_some() {
            return Ok(false);
        }
        self.db.put_cf(cf, key, timestamp_nanos.to_be_bytes()).map_err(|err| ThresholdError::Message(err.to_string()))?;
        debug!(
            "marked message seen sender_peer_id={} session_id={} seq_no={}",
            sender_peer_id,
            hex::encode(session_id.as_hash()),
            seq_no
        );
        Ok(true)
    }

    fn cleanup_seen_messages(&self, older_than_nanos: u64) -> Result<usize, ThresholdError> {
        let prefix = b"seen:";
        let mut deleted = 0usize;
        let mut batch = WriteBatch::default();
        let cf = self.cf_handle(CF_SEEN)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            if value.len() != 8 {
                warn!(
                    "corrupted seen-message timestamp; skipping key={:?} value_len={}",
                    key,
                    value.len()
                );
                continue;
            }
            let timestamp: u64 = match value.as_ref().try_into() {
                Ok(bytes) => u64::from_be_bytes(bytes),
                Err(_) => {
                    warn!("corrupted seen-message timestamp bytes; skipping key={:?}", key);
                    continue;
                }
            };
            if timestamp < older_than_nanos {
                batch.delete_cf(cf, key);
                deleted += 1;
            }
        }

        if deleted > 0 {
            self.db.write(batch).map_err(|err| ThresholdError::Message(err.to_string()))?;
        }
        debug!(
            "cleanup_seen_messages complete older_than_nanos={} deleted={}",
            older_than_nanos, deleted
        );
        Ok(deleted)
    }

    fn begin_batch(&self) -> Result<Box<dyn BatchTransaction + '_>, ThresholdError> {
        Ok(Box::new(RocksBatch { db: &self.db, batch: WriteBatch::default() }))
    }
}

struct RocksBatch<'a> {
    db: &'a DB,
    batch: WriteBatch,
}

impl<'a> BatchTransaction for RocksBatch<'a> {
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), ThresholdError> {
        self.batch.put(key, value);
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), ThresholdError> {
        self.batch.delete(key);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), ThresholdError> {
        self.db.write(self.batch).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn rollback(self: Box<Self>) {
        drop(self);
    }
}
