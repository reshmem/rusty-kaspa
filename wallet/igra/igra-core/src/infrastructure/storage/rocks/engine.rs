use crate::foundation::ThresholdError;
use crate::infrastructure::storage::rocks::migration::open_db_with_cfs;
use crate::infrastructure::storage::rocks::schema::*;
use crate::domain::{
    GroupConfig, PartialSigRecord, RequestDecision, RequestInput, SignerAckRecord, SigningEvent, SigningRequest, StoredProposal,
};
use crate::domain::request::state_machine::validate_transition;
use crate::infrastructure::storage::{BatchTransaction, Storage};
use crate::foundation::{Hash32, PeerId, RequestId, SessionId, TransactionId};
use bincode::Options;
use rocksdb::{checkpoint::Checkpoint, ColumnFamily, Direction, IteratorMode, WriteBatch, DB};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::{env, fs};
use tracing::warn;

pub struct RocksStorage {
    db: Arc<DB>,
}

impl RocksStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        let db = open_db_with_cfs(path)?;
        let storage = Self { db: Arc::new(db) };
        storage.maybe_run_migrations()?;
        Ok(storage)
    }

    pub fn open_default() -> Result<Self, ThresholdError> {
        if let Ok(data_dir) = env::var("KASPA_DATA_DIR") {
            let trimmed = data_dir.trim();
            if !trimmed.is_empty() {
                let dir = Path::new(trimmed);
                fs::create_dir_all(dir).map_err(|err| ThresholdError::Message(err.to_string()))?;
                let path = dir.join("threshold-signing");
                return Self::open(path);
            }
        }
        let base = env::current_dir().map_err(|err| ThresholdError::Message(err.to_string()))?;
        let dir = base.join(".igra");
        fs::create_dir_all(&dir).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let path = dir.join("threshold-signing");
        Self::open(path)
    }

    pub fn open_in_dir(data_dir: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        let dir = data_dir.as_ref();
        if dir.as_os_str().is_empty() {
            return Self::open_default();
        }
        fs::create_dir_all(dir).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let path = dir.join("threshold-signing");
        Self::open(path)
    }

    pub fn create_checkpoint(&self, path: impl AsRef<Path>) -> Result<(), ThresholdError> {
        let path = path.as_ref();
        if path.exists() {
            let mut entries = fs::read_dir(path).map_err(|err| ThresholdError::Message(err.to_string()))?;
            if entries.next().is_some() {
                return Err(ThresholdError::Message(format!(
                    "checkpoint directory is not empty: {}",
                    path.display()
                )));
            }
            fs::remove_dir_all(path).map_err(|err| ThresholdError::Message(err.to_string()))?;
        }
        let checkpoint = Checkpoint::new(&self.db).map_err(|err| ThresholdError::Message(err.to_string()))?;
        checkpoint
            .create_checkpoint(path)
            .map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily, ThresholdError> {
        self.db.cf_handle(name).ok_or_else(|| ThresholdError::Message(format!("missing column family: {}", name)))
    }

    fn maybe_run_migrations(&self) -> Result<(), ThresholdError> {
        const SCHEMA_VERSION: u32 = 1;
        match self.schema_version()? {
            None => {
                // Fresh DB
                self.set_schema_version(SCHEMA_VERSION)?;
            }
            Some(v) if v == SCHEMA_VERSION => { /* ok */ }
            Some(v) if v < SCHEMA_VERSION => {
                warn!(
                    "database schema version {} is older than supported {}; migration not implemented",
                    v, SCHEMA_VERSION
                );
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
                let array: [u8; 4] = bytes.as_slice().try_into().map_err(|_| ThresholdError::Message("corrupt schema version".to_string()))?;
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
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(bytes)
            .map_err(|err| err.into())
    }

    fn key_group(group_id: &Hash32) -> Vec<u8> { KeyBuilder::with_capacity(4 + group_id.len()).prefix(b"grp:").hash32(group_id).build() }

    fn key_event(event_hash: &Hash32) -> Vec<u8> { KeyBuilder::with_capacity(4 + event_hash.len()).prefix(b"evt:").hash32(event_hash).build() }

    fn key_request(request_id: &RequestId) -> Vec<u8> {
        KeyBuilder::with_capacity(4 + request_id.len()).prefix(b"req:").str(request_id.as_str()).build()
    }

    fn key_proposal(request_id: &RequestId) -> Vec<u8> {
        KeyBuilder::with_capacity(9 + request_id.len()).prefix(b"proposal:").str(request_id.as_str()).build()
    }

    fn key_request_input_prefix(request_id: &RequestId) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + request_id.len()).prefix(b"req_input:").str(request_id.as_str()).sep().build()
    }

    fn key_request_input(request_id: &RequestId, input_index: u32) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + request_id.len() + 1 + 4)
            .prefix(b"req_input:")
            .str(request_id.as_str())
            .sep()
            .u32_be(input_index)
            .build()
    }

    fn key_signer_ack_prefix(request_id: &RequestId) -> Vec<u8> {
        KeyBuilder::with_capacity(12 + request_id.len()).prefix(b"req_ack:").str(request_id.as_str()).sep().build()
    }

    fn key_signer_ack(request_id: &RequestId, signer_peer_id: &PeerId) -> Vec<u8> {
        KeyBuilder::with_capacity(12 + request_id.len() + signer_peer_id.len())
            .prefix(b"req_ack:")
            .str(request_id.as_str())
            .sep()
            .str(signer_peer_id.as_str())
            .build()
    }

    fn key_partial_sig_prefix(request_id: &RequestId) -> Vec<u8> {
        KeyBuilder::with_capacity(14 + request_id.len()).prefix(b"req_sig:").str(request_id.as_str()).sep().build()
    }

    fn key_partial_sig(request_id: &RequestId, signer_peer_id: &PeerId, input_index: u32) -> Vec<u8> {
        KeyBuilder::with_capacity(14 + request_id.len() + signer_peer_id.len() + 1 + 4)
            .prefix(b"req_sig:")
            .str(request_id.as_str())
            .sep()
            .str(signer_peer_id.as_str())
            .sep()
            .u32_be(input_index)
            .build()
    }

    #[allow(dead_code)]
    fn key_partial_sig_input_prefix(request_id: &RequestId, input_index: u32) -> Vec<u8> {
        KeyBuilder::with_capacity(14 + request_id.len() + 4 + 1)
            .prefix(b"req_sig:")
            .str(request_id.as_str())
            .sep()
            .u32_be(input_index)
            .sep()
            .build()
    }

    #[allow(dead_code)]
    fn key_partial_sig_input(request_id: &RequestId, input_index: u32, signer_pubkey: &[u8]) -> Vec<u8> {
        KeyBuilder::with_capacity(14 + request_id.len() + 4 + 1 + signer_pubkey.len())
            .prefix(b"req_sig:")
            .str(request_id.as_str())
            .sep()
            .u32_be(input_index)
            .sep()
            .bytes(signer_pubkey)
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

    fn day_start_nanos(now_nanos: u64) -> u64 {
        let nanos_per_day = 24 * 60 * 60 * 1_000_000_000u64;
        (now_nanos / nanos_per_day) * nanos_per_day
    }

    fn add_to_daily_volume(&self, amount_sompi: u64, timestamp_nanos: u64) -> Result<(), ThresholdError> {
        let day_start = Self::day_start_nanos(timestamp_nanos);
        let key = Self::key_volume(day_start);

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
        let amount_bytes: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ThresholdError::Message("invalid volume value format".to_string()))?;
        Ok(Some(u64::from_be_bytes(amount_bytes)))
    }

    fn volume_from_scan(&self, since_day_start: u64) -> Result<u64, ThresholdError> {
        let mut total = 0u64;
        let mut counted = 0usize;
        let mut seen_events = HashSet::new();
        let prefix = b"req:";
        let cf = self.cf_handle(CF_REQUEST)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(prefix) {
                continue;
            }
            let request = Self::decode::<SigningRequest>(&value)?;
            if !matches!(request.decision, RequestDecision::Finalized) {
                continue;
            }
            if seen_events.contains(&request.event_hash) {
                continue;
            }
            seen_events.insert(request.event_hash);
            if let Some(event) = self.get_event(&request.event_hash)? {
                let event_day = Self::day_start_nanos(event.timestamp_nanos);
                if event_day == Self::day_start_nanos(since_day_start) {
                    total = total.saturating_add(event.amount_sompi);
                    counted += 1;
                }
            }
        }
        tracing::debug!(since_day_start, counted, total, "volume_from_scan summary");
        Ok(total)
    }
}

impl RocksStorage {
    pub fn archive_old_requests(&self, before_nanos: u64) -> Result<usize, ThresholdError> {
        let mut archived = 0usize;
        let prefix = b"req:";
        let request_cf = self.cf_handle(CF_REQUEST)?;
        let mut batch = WriteBatch::default();
        let iter = self.db.iterator_cf(request_cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(prefix) {
                continue;
            }
            let request = Self::decode::<SigningRequest>(&value)?;
            if !matches!(request.decision, RequestDecision::Finalized) {
                continue;
            }
            let event = match self.get_event(&request.event_hash)? {
                Some(event) => event,
                None => continue,
            };
            if event.timestamp_nanos >= before_nanos {
                continue;
            }
            let mut archive_key = Vec::with_capacity(8 + key.len());
            archive_key.extend_from_slice(b"archive:");
            archive_key.extend_from_slice(&key);
            batch.put_cf(request_cf, &archive_key, &value);
            batch.delete_cf(request_cf, &key);
            archived += 1;
        }
        if archived > 0 {
            self.db.write(batch).map_err(|err| ThresholdError::Message(err.to_string()))?;
        }
        Ok(archived)
    }

    pub fn delete_old_archives(&self, before_nanos: u64) -> Result<usize, ThresholdError> {
        let mut deleted = 0usize;
        let prefix = b"archive:req:";
        let request_cf = self.cf_handle(CF_REQUEST)?;
        let mut batch = WriteBatch::default();
        let iter = self.db.iterator_cf(request_cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(prefix) {
                continue;
            }
            let request = Self::decode::<SigningRequest>(&value)?;
            let event = match self.get_event(&request.event_hash)? {
                Some(event) => event,
                None => continue,
            };
            if event.timestamp_nanos >= before_nanos {
                continue;
            }
            batch.delete_cf(request_cf, &key);
            deleted += 1;
        }
        if deleted > 0 {
            self.db.write(batch).map_err(|err| ThresholdError::Message(err.to_string()))?;
        }
        Ok(deleted)
    }

    pub fn compact(&self) -> Result<(), ThresholdError> {
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
        Ok(())
    }
}

impl Storage for RocksStorage {
    fn upsert_group_config(&self, group_id: Hash32, config: GroupConfig) -> Result<(), ThresholdError> {
        let key = Self::key_group(&group_id);
        let value = Self::encode(&config)?;
        let cf = self.cf_handle(CF_GROUP)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>, ThresholdError> {
        let key = Self::key_group(group_id);
        let cf = self.cf_handle(CF_GROUP)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<(), ThresholdError> {
        let key = Self::key_event(&event_hash);
        let cf = self.cf_handle(CF_EVENT)?;

        // Check for duplicate before inserting to prevent replay attacks
        if let Some(_) = self.db.get_cf(cf, &key).map_err(|e| ThresholdError::StorageError(e.to_string()))? {
            return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
        }

        let value = Self::encode(&event)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn get_event(&self, event_hash: &Hash32) -> Result<Option<SigningEvent>, ThresholdError> {
        let key = Self::key_event(event_hash);
        let cf = self.cf_handle(CF_EVENT)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn insert_request(&self, request: SigningRequest) -> Result<(), ThresholdError> {
        let key = Self::key_request(&request.request_id);
        let cf = self.cf_handle(CF_REQUEST)?;
        let existing = self.db.get_cf(cf, &key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        if existing.is_some() {
            return Ok(());
        }
        let value = Self::encode(&request)?;
        self.db.put_cf(cf, &key, value).map_err(|err| ThresholdError::Message(err.to_string()))?;

        if request.final_tx_id.is_some() && matches!(request.decision, RequestDecision::Finalized) {
            if let Some(event) = self.get_event(&request.event_hash)? {
                self.add_to_daily_volume(event.amount_sompi, event.timestamp_nanos)?;
            }
        }
        Ok(())
    }

    fn update_request_decision(&self, request_id: &RequestId, decision: RequestDecision) -> Result<(), ThresholdError> {
        let key = Self::key_request(request_id);
        let cf = self.cf_handle(CF_REQUEST)?;
        let value = self.db.get_cf(cf, &key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let mut request = match value {
            Some(bytes) => Self::decode::<SigningRequest>(&bytes)?,
            None => return Err(ThresholdError::KeyNotFound(format!("request {} not found", request_id))),
        };
        validate_transition(&request.decision, &decision)?;
        request.decision = decision;
        let updated = Self::encode(&request)?;
        self.db.put_cf(cf, key, updated).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn get_request(&self, request_id: &RequestId) -> Result<Option<SigningRequest>, ThresholdError> {
        let key = Self::key_request(request_id);
        let cf = self.cf_handle(CF_REQUEST)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn insert_proposal(&self, request_id: &RequestId, proposal: StoredProposal) -> Result<(), ThresholdError> {
        let key = Self::key_proposal(request_id);
        let value = Self::encode(&proposal)?;
        let cf = self.cf_handle(CF_PROPOSAL)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn get_proposal(&self, request_id: &RequestId) -> Result<Option<StoredProposal>, ThresholdError> {
        let key = Self::key_proposal(request_id);
        let cf = self.cf_handle(CF_PROPOSAL)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn insert_request_input(&self, request_id: &RequestId, input: RequestInput) -> Result<(), ThresholdError> {
        let key = Self::key_request_input(request_id, input.input_index);
        let value = Self::encode(&input)?;
        let cf = self.cf_handle(CF_REQUEST_INPUT)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn list_request_inputs(&self, request_id: &RequestId) -> Result<Vec<RequestInput>, ThresholdError> {
        let prefix = Self::key_request_input_prefix(request_id);
        let mut inputs = Vec::new();
        let cf = self.cf_handle(CF_REQUEST_INPUT)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            inputs.push(Self::decode::<RequestInput>(&value)?);
        }
        Ok(inputs)
    }

    fn insert_signer_ack(&self, request_id: &RequestId, ack: SignerAckRecord) -> Result<(), ThresholdError> {
        let key = Self::key_signer_ack(request_id, &ack.signer_peer_id);
        let value = Self::encode(&ack)?;
        let cf = self.cf_handle(CF_SIGNER_ACK)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn list_signer_acks(&self, request_id: &RequestId) -> Result<Vec<SignerAckRecord>, ThresholdError> {
        let prefix = Self::key_signer_ack_prefix(request_id);
        let mut entries = Vec::new();
        let cf = self.cf_handle(CF_SIGNER_ACK)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            entries.push(Self::decode::<SignerAckRecord>(&value)?);
        }
        Ok(entries)
    }

    fn insert_partial_sig(&self, request_id: &RequestId, sig: PartialSigRecord) -> Result<(), ThresholdError> {
        let key = Self::key_partial_sig(request_id, &sig.signer_peer_id, sig.input_index);
        let value = Self::encode(&sig)?;
        let cf = self.cf_handle(CF_PARTIAL_SIG)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn list_partial_sigs(&self, request_id: &RequestId) -> Result<Vec<PartialSigRecord>, ThresholdError> {
        let prefix = Self::key_partial_sig_prefix(request_id);
        let mut entries = Vec::new();
        let cf = self.cf_handle(CF_PARTIAL_SIG)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            entries.push(Self::decode::<PartialSigRecord>(&value)?);
        }
        Ok(entries)
    }

    fn update_request_final_tx(&self, request_id: &RequestId, final_tx_id: TransactionId) -> Result<(), ThresholdError> {
        let key = Self::key_request(request_id);
        let cf = self.cf_handle(CF_REQUEST)?;
        let value = self.db.get_cf(cf, &key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let mut request = match value {
            Some(bytes) => Self::decode::<SigningRequest>(&bytes)?,
            None => return Err(ThresholdError::KeyNotFound(format!("request {} not found", request_id))),
        };
        if request.final_tx_id.is_some() {
            return Ok(());
        }
        validate_transition(&request.decision, &RequestDecision::Finalized)?;
        request.final_tx_id = Some(final_tx_id);
        request.decision = RequestDecision::Finalized;
        let updated = Self::encode(&request)?;
        self.db.put_cf(cf, key, updated).map_err(|err| ThresholdError::Message(err.to_string()))?;
        tracing::info!(
            request_id = %request_id,
            final_tx_id = %hex::encode(final_tx_id.as_hash()),
            "request finalized"
        );
        if let Some(event) = self.get_event(&request.event_hash)? {
            self.add_to_daily_volume(event.amount_sompi, event.timestamp_nanos)?;
        }
        Ok(())
    }

    fn update_request_final_tx_score(&self, request_id: &RequestId, accepted_blue_score: u64) -> Result<(), ThresholdError> {
        let key = Self::key_request(request_id);
        let cf = self.cf_handle(CF_REQUEST)?;
        let value = self.db.get_cf(cf, &key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let mut request = match value {
            Some(bytes) => Self::decode::<SigningRequest>(&bytes)?,
            None => return Err(ThresholdError::KeyNotFound(format!("request {} not found", request_id))),
        };
        request.final_tx_accepted_blue_score = Some(accepted_blue_score);
        let updated = Self::encode(&request)?;
        self.db.put_cf(cf, key, updated).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64, ThresholdError> {
        let day_start = Self::day_start_nanos(timestamp_nanos);
        if let Some(total) = self.volume_from_index(day_start)? {
            tracing::debug!(day_start, total, "volume_from_index hit");
            return Ok(total);
        }
        let total = self.volume_from_scan(day_start)?;
        tracing::debug!(day_start, total, "volume_from_scan computed");
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
                warn!(key = ?key, value_len = value.len(), "corrupted seen-message timestamp; skipping");
                continue;
            }
            let timestamp: u64 = match value.as_ref().try_into() {
                Ok(bytes) => u64::from_be_bytes(bytes),
                Err(_) => {
                    warn!(key = ?key, "corrupted seen-message timestamp bytes; skipping");
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
