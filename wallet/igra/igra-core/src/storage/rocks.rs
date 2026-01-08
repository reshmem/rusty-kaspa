use crate::error::ThresholdError;
use crate::model::{
    GroupConfig, Hash32, PartialSigRecord, RequestDecision, RequestInput, SignerAckRecord, SigningEvent, SigningRequest,
    StoredProposal,
};
use crate::state_machine::validate_transition;
use crate::storage::{BatchTransaction, Storage};
use crate::types::{PeerId, RequestId, SessionId, TransactionId};
use bincode::Options;
use rocksdb::{
    checkpoint::Checkpoint, ColumnFamily, ColumnFamilyDescriptor, Direction, IteratorMode, MergeOperands, Options as RocksOptions,
    WriteBatch, DB,
};
use std::path::Path;
use std::sync::Arc;
use std::{env, fs};

// Merge operator for atomic volume accumulation
// Handles concurrent updates to volume counters without race conditions
fn volume_merge_operator(_key: &[u8], existing_val: Option<&[u8]>, operands: &MergeOperands) -> Option<Vec<u8>> {
    let mut total = match existing_val {
        Some(bytes) if bytes.len() == 8 => {
            let array: [u8; 8] = bytes.try_into().ok()?;
            u64::from_be_bytes(array)
        }
        _ => 0,
    };

    for op in operands {
        if op.len() == 8 {
            if let Ok(array) = TryInto::<[u8; 8]>::try_into(op) {
                let value = u64::from_be_bytes(array);
                total = total.saturating_add(value);
            }
        }
    }

    Some(total.to_be_bytes().to_vec())
}

pub struct RocksStorage {
    db: Arc<DB>,
}

const CF_DEFAULT: &str = "default";
const CF_GROUP: &str = "group";
const CF_EVENT: &str = "event";
const CF_REQUEST: &str = "request";
const CF_PROPOSAL: &str = "proposal";
const CF_REQUEST_INPUT: &str = "request_input";
const CF_SIGNER_ACK: &str = "signer_ack";
const CF_PARTIAL_SIG: &str = "partial_sig";
const CF_VOLUME: &str = "volume";
const CF_SEEN: &str = "seen";

impl RocksStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ThresholdError> {
        let mut options = RocksOptions::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);

        // Enable fsync for durability - ensures data is written to disk before confirming writes
        options.set_use_fsync(true);

        // Enable write-ahead log (WAL) for crash recovery
        options.set_manual_wal_flush(false);

        // Set paranoid checks to detect corruption early
        options.set_paranoid_checks(true);

        let mut volume_options = RocksOptions::default();
        volume_options.set_merge_operator_associative("volume_add", volume_merge_operator);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_DEFAULT, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_GROUP, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_EVENT, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_REQUEST, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_PROPOSAL, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_REQUEST_INPUT, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_SIGNER_ACK, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_PARTIAL_SIG, RocksOptions::default()),
            ColumnFamilyDescriptor::new(CF_VOLUME, volume_options),
            ColumnFamilyDescriptor::new(CF_SEEN, RocksOptions::default()),
        ];

        let db = DB::open_cf_descriptors(&options, path, cfs).map_err(|err| ThresholdError::Message(err.to_string()))?;
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
        let checkpoint = Checkpoint::new(&self.db).map_err(|err| ThresholdError::Message(err.to_string()))?;
        checkpoint.create_checkpoint(path).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily, ThresholdError> {
        self.db.cf_handle(name).ok_or_else(|| ThresholdError::Message(format!("missing column family: {}", name)))
    }

    fn maybe_run_migrations(&self) -> Result<(), ThresholdError> {
        let enabled =
            env::var("KASPA_IGRA_ENABLE_MIGRATIONS").map(|value| value == "1" || value.eq_ignore_ascii_case("true")).unwrap_or(false);
        if !enabled {
            return Ok(());
        }

        // Placeholder for future schema migrations; enabled only when explicitly requested.
        self.migrate_default_to_cfs()
    }

    fn migrate_default_to_cfs(&self) -> Result<(), ThresholdError> {
        let default_cf = self.cf_handle(CF_DEFAULT)?;
        let mut batch = WriteBatch::default();
        let mut moved = 0usize;
        let iter = self.db.iterator_cf(default_cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            let target = if key.starts_with(b"grp:") {
                Some(CF_GROUP)
            } else if key.starts_with(b"evt:") {
                Some(CF_EVENT)
            } else if key.starts_with(b"req:") || key.starts_with(b"archive:req:") {
                Some(CF_REQUEST)
            } else if key.starts_with(b"proposal:") {
                Some(CF_PROPOSAL)
            } else if key.starts_with(b"req_input:") {
                Some(CF_REQUEST_INPUT)
            } else if key.starts_with(b"req_ack:") {
                Some(CF_SIGNER_ACK)
            } else if key.starts_with(b"req_sig:") {
                Some(CF_PARTIAL_SIG)
            } else if key.starts_with(b"vol:") {
                Some(CF_VOLUME)
            } else if key.starts_with(b"seen:") {
                Some(CF_SEEN)
            } else {
                None
            };

            if let Some(cf_name) = target {
                let cf = self.cf_handle(cf_name)?;
                batch.put_cf(cf, &key, &value);
                batch.delete_cf(default_cf, &key);
                moved += 1;
            }
        }

        if moved > 0 {
            self.db.write(batch).map_err(|err| ThresholdError::Message(err.to_string()))?;
        }
        Ok(())
    }

    fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ThresholdError> {
        bincode::DefaultOptions::new().with_fixint_encoding().serialize(value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ThresholdError> {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(bytes)
            .map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn key_group(group_id: &Hash32) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + group_id.len());
        key.extend_from_slice(b"grp:");
        key.extend_from_slice(group_id);
        key
    }

    fn key_event(event_hash: &Hash32) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + event_hash.len());
        key.extend_from_slice(b"evt:");
        key.extend_from_slice(event_hash);
        key
    }

    fn key_request(request_id: &RequestId) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + request_id.len());
        key.extend_from_slice(b"req:");
        key.extend_from_slice(request_id.as_str().as_bytes());
        key
    }

    fn key_proposal(request_id: &RequestId) -> Vec<u8> {
        let mut key = Vec::with_capacity(9 + request_id.len());
        key.extend_from_slice(b"proposal:");
        key.extend_from_slice(request_id.as_str().as_bytes());
        key
    }

    fn key_request_input_prefix(request_id: &RequestId) -> Vec<u8> {
        let mut key = Vec::with_capacity(10 + request_id.len());
        key.extend_from_slice(b"req_input:");
        key.extend_from_slice(request_id.as_str().as_bytes());
        key.push(b':');
        key
    }

    fn key_request_input(request_id: &RequestId, input_index: u32) -> Vec<u8> {
        let mut key = Self::key_request_input_prefix(request_id);
        key.extend_from_slice(&input_index.to_be_bytes());
        key
    }

    fn key_signer_ack_prefix(request_id: &RequestId) -> Vec<u8> {
        let mut key = Vec::with_capacity(12 + request_id.len());
        key.extend_from_slice(b"req_ack:");
        key.extend_from_slice(request_id.as_str().as_bytes());
        key.push(b':');
        key
    }

    fn key_signer_ack(request_id: &RequestId, signer_peer_id: &PeerId) -> Vec<u8> {
        let mut key = Self::key_signer_ack_prefix(request_id);
        key.extend_from_slice(signer_peer_id.as_str().as_bytes());
        key
    }

    fn key_partial_sig_prefix(request_id: &RequestId) -> Vec<u8> {
        let mut key = Vec::with_capacity(14 + request_id.len());
        key.extend_from_slice(b"req_sig:");
        key.extend_from_slice(request_id.as_str().as_bytes());
        key.push(b':');
        key
    }

    fn key_partial_sig(request_id: &RequestId, signer_peer_id: &PeerId, input_index: u32) -> Vec<u8> {
        let mut key = Self::key_partial_sig_prefix(request_id);
        key.extend_from_slice(signer_peer_id.as_str().as_bytes());
        key.push(b':');
        key.extend_from_slice(&input_index.to_be_bytes());
        key
    }

    fn key_seen(sender_peer_id: &PeerId, session_id: &SessionId, seq_no: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(6 + sender_peer_id.len() + 1 + session_id.as_hash().len() + 1 + 8);
        key.extend_from_slice(b"seen:");
        key.extend_from_slice(sender_peer_id.as_str().as_bytes());
        key.push(b':');
        key.extend_from_slice(session_id.as_hash());
        key.push(b':');
        key.extend_from_slice(&seq_no.to_be_bytes());
        key
    }

    fn key_volume(day_start_nanos: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + 8);
        key.extend_from_slice(b"vol:");
        key.extend_from_slice(&day_start_nanos.to_be_bytes());
        key
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
        let mut total = 0u64;
        let mut found = false;
        let prefix = b"vol:";
        let cf = self.cf_handle(CF_VOLUME)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|err| ThresholdError::Message(err.to_string()))?;
            if !key.starts_with(prefix) {
                continue;
            }
            found = true;
            if key.len() != prefix.len() + 8 {
                continue;
            }
            let day_start_bytes: [u8; 8] =
                key[prefix.len()..].try_into().map_err(|_| ThresholdError::Message("invalid volume key format".to_string()))?;
            let day_start = u64::from_be_bytes(day_start_bytes);
            if day_start < since_day_start {
                continue;
            }
            if value.len() != 8 {
                return Err(ThresholdError::Message("invalid volume index entry".to_string()));
            }
            let amount_bytes: [u8; 8] =
                value.as_ref().try_into().map_err(|_| ThresholdError::Message("invalid volume value format".to_string()))?;
            let amount = u64::from_be_bytes(amount_bytes);
            total = total.saturating_add(amount);
        }
        if found {
            Ok(Some(total))
        } else {
            Ok(None)
        }
    }

    fn volume_from_scan(&self, timestamp_nanos: u64) -> Result<u64, ThresholdError> {
        let mut total = 0u64;
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
            if let Some(event) = self.get_event(&request.event_hash)? {
                if event.timestamp_nanos >= timestamp_nanos {
                    total = total.saturating_add(event.amount_sompi);
                }
            }
        }
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
        let value = Self::encode(&request)?;
        let cf = self.cf_handle(CF_REQUEST)?;
        self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn update_request_decision(&self, request_id: &RequestId, decision: RequestDecision) -> Result<(), ThresholdError> {
        let key = Self::key_request(request_id);
        let cf = self.cf_handle(CF_REQUEST)?;
        let value = self.db.get_cf(cf, &key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let mut request = match value {
            Some(bytes) => Self::decode::<SigningRequest>(&bytes)?,
            None => return Ok(()),
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
            None => return Ok(()),
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
            None => return Ok(()),
        };
        request.final_tx_accepted_blue_score = Some(accepted_blue_score);
        let updated = Self::encode(&request)?;
        self.db.put_cf(cf, key, updated).map_err(|err| ThresholdError::Message(err.to_string()))
    }

    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64, ThresholdError> {
        let day_start = Self::day_start_nanos(timestamp_nanos);
        if let Some(total) = self.volume_from_index(day_start)? {
            return Ok(total);
        }
        self.volume_from_scan(timestamp_nanos)
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
                continue;
            }
            let timestamp = u64::from_be_bytes(value.as_ref().try_into().unwrap_or([0u8; 8]));
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
