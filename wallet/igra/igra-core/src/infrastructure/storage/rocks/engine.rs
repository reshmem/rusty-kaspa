use crate::domain::coordination::{EventPhase, EventPhaseState, Proposal};
use crate::domain::{CrdtSignatureRecord, CrdtSigningMaterial, GroupConfig, StoredCompletionRecord, StoredEvent, StoredEventCrdt};
use crate::foundation::ThresholdError;
use crate::foundation::{EventId, ExternalId, GroupId, PeerId, SessionId, TransactionId, TxTemplateHash};
use crate::infrastructure::storage::hyperlane::{HyperlaneDeliveredMessage, HyperlaneDeliveryRecord, HyperlaneMessageRecord};
use crate::infrastructure::storage::phase::{PhaseStorage, RecordSignedHashResult, StoreProposalResult};
use crate::infrastructure::storage::rocks::migration::open_db_with_cfs;
use crate::infrastructure::storage::rocks::schema::*;
use crate::infrastructure::storage::{BatchTransaction, CrdtStorageStats, Storage};
use crate::infrastructure::transport::messages::{CompletionRecord, EventCrdtState};
use crate::storage_err;
use bincode::Options;
use log::{debug, info, trace, warn};
use rocksdb::{checkpoint::Checkpoint, ColumnFamily, Direction, IteratorMode, WriteBatch, DB};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::{env, fs};

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

impl PhaseStorage for RocksStorage {
    fn try_enter_proposing(&self, event_id: &EventId, now_ns: u64) -> Result<bool, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        if let Some(bytes) = self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            let state: EventPhaseState = Self::decode(&bytes)?;
            if state.phase != EventPhase::Unknown {
                return Ok(false);
            }
        }

        let state = EventPhaseState::new(EventPhase::Proposing, now_ns);
        let value = Self::encode(&state)?;
        self.db.put_cf(cf, key, value).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
        Ok(true)
    }

    fn get_phase(&self, event_id: &EventId) -> Result<Option<EventPhaseState>, ThresholdError> {
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        let Some(bytes) = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? else {
            return Ok(None);
        };
        Ok(Some(Self::decode(&bytes)?))
    }

    fn get_signed_hash(&self, event_id: &EventId) -> Result<Option<TxTemplateHash>, ThresholdError> {
        let cf = self.cf_handle(CF_EVENT_SIGNED_HASH)?;
        let key = Self::key_event_signed_hash(event_id);
        let Some(bytes) = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb get_cf evt_signed_hash", err))? else {
            return Ok(None);
        };
        if bytes.len() != 32 {
            return Err(ThresholdError::StorageError {
                operation: "get_signed_hash".to_string(),
                details: "corrupt signed hash record".to_string(),
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(TxTemplateHash::from(out)))
    }

    fn record_signed_hash(
        &self,
        event_id: &EventId,
        tx_template_hash: TxTemplateHash,
        _now_ns: u64,
    ) -> Result<RecordSignedHashResult, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;

        let cf = self.cf_handle(CF_EVENT_SIGNED_HASH)?;
        let key = Self::key_event_signed_hash(event_id);

        if let Some(existing) = self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_signed_hash", err))? {
            if existing.len() != 32 {
                return Err(ThresholdError::StorageError {
                    operation: "record_signed_hash".to_string(),
                    details: "corrupt signed hash record".to_string(),
                });
            }
            let mut existing_hash = [0u8; 32];
            existing_hash.copy_from_slice(&existing);
            let existing_hash = TxTemplateHash::from(existing_hash);
            if existing_hash == tx_template_hash {
                return Ok(RecordSignedHashResult::AlreadySame);
            }
            return Ok(RecordSignedHashResult::Conflict { existing: existing_hash, attempted: tx_template_hash });
        }

        self.db.put_cf(cf, key, tx_template_hash.as_hash()).map_err(|err| storage_err!("rocksdb put_cf evt_signed_hash", err))?;
        Ok(RecordSignedHashResult::Set)
    }

    fn adopt_round_if_behind(&self, event_id: &EventId, new_round: u32, now_ns: u64) -> Result<bool, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);

        let mut state = match self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            Some(bytes) => Self::decode::<EventPhaseState>(&bytes)?,
            None => EventPhaseState::new(EventPhase::Unknown, now_ns),
        };

        if matches!(state.phase, EventPhase::Committed | EventPhase::Completed | EventPhase::Abandoned) {
            return Ok(false);
        }
        if state.round >= new_round {
            return Ok(false);
        }

        state.phase = EventPhase::Proposing;
        state.phase_started_at_ns = now_ns;
        state.round = new_round;
        state.canonical_hash = None;
        state.own_proposal_hash = None;

        self.db.put_cf(cf, key, Self::encode(&state)?).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
        Ok(true)
    }

    fn set_own_proposal_hash(&self, event_id: &EventId, tx_template_hash: TxTemplateHash) -> Result<(), ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        let mut state = match self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            Some(bytes) => Self::decode::<EventPhaseState>(&bytes)?,
            None => EventPhaseState::new(EventPhase::Unknown, crate::foundation::now_nanos()),
        };
        state.own_proposal_hash = Some(tx_template_hash);
        self.db.put_cf(cf, key, Self::encode(&state)?).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
        Ok(())
    }

    fn store_proposal(&self, proposal: &Proposal) -> Result<StoreProposalResult, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;

        let cf_phase = self.cf_handle(CF_EVENT_PHASE)?;
        let cf_prop = self.cf_handle(CF_EVENT_PROPOSAL)?;
        let phase_key = Self::key_event_phase(&proposal.event_id);
        let now_ns = crate::foundation::now_nanos();

        let mut phase = match self.db.get_cf(cf_phase, &phase_key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            Some(bytes) => Self::decode::<EventPhaseState>(&bytes)?,
            None => EventPhaseState::new(EventPhase::Proposing, now_ns),
        };

        if matches!(phase.phase, EventPhase::Committed | EventPhase::Completed | EventPhase::Abandoned) {
            return Ok(StoreProposalResult::PhaseTooLate);
        }
        if phase.round != proposal.round {
            return Ok(StoreProposalResult::RoundMismatch { expected: phase.round, got: proposal.round });
        }

        if matches!(phase.phase, EventPhase::Unknown | EventPhase::Failed) {
            phase.phase = EventPhase::Proposing;
            phase.phase_started_at_ns = now_ns;
        }

        let key = Self::key_event_proposal(&proposal.event_id, proposal.round, &proposal.proposer_peer_id);
        if let Some(existing) = self.db.get_cf(cf_prop, &key).map_err(|err| storage_err!("rocksdb get_cf evt_prop", err))? {
            let existing: Proposal = Self::decode(&existing)?;
            if existing.tx_template_hash != proposal.tx_template_hash {
                // Crash-fault model behavior: detect and record equivocation, but do not attempt to punish
                // or “resolve” it at this layer. We keep the first stored proposal and reject conflicting
                // votes from the same peer for the same (event_id, round).
                crate::infrastructure::audit::audit(crate::infrastructure::audit::AuditEvent::ProposalEquivocationDetected {
                    event_id: hex::encode(proposal.event_id),
                    round: proposal.round,
                    proposer_peer_id: proposal.proposer_peer_id.to_string(),
                    existing_tx_template_hash: hex::encode(existing.tx_template_hash),
                    new_tx_template_hash: hex::encode(proposal.tx_template_hash),
                    timestamp_nanos: now_ns,
                });
                return Ok(StoreProposalResult::Equivocation {
                    existing_hash: existing.tx_template_hash,
                    new_hash: proposal.tx_template_hash,
                });
            }
            return Ok(StoreProposalResult::DuplicateFromPeer);
        }

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_phase, phase_key, Self::encode(&phase)?);
        batch.put_cf(cf_prop, key, Self::encode(proposal)?);
        self.db.write(batch).map_err(|err| storage_err!("rocksdb write store_proposal", err))?;
        Ok(StoreProposalResult::Stored)
    }

    fn get_proposals(&self, event_id: &EventId, round: u32) -> Result<Vec<Proposal>, ThresholdError> {
        let cf = self.cf_handle(CF_EVENT_PROPOSAL)?;
        let prefix = Self::key_event_proposal_round_prefix(event_id, round);
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix.as_slice(), Direction::Forward));
        let mut out = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|err| storage_err!("rocksdb iterator evt_prop", err))?;
            if !key.starts_with(&prefix) {
                break;
            }
            out.push(Self::decode::<Proposal>(&value)?);
        }
        Ok(out)
    }

    fn proposal_count(&self, event_id: &EventId, round: u32) -> Result<usize, ThresholdError> {
        Ok(self.get_proposals(event_id, round)?.len())
    }

    fn get_events_in_phase(&self, phase: EventPhase) -> Result<Vec<EventId>, ThresholdError> {
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|err| storage_err!("rocksdb iterator evt_phase", err))?;
            let state: EventPhaseState = Self::decode(&value)?;
            if state.phase != phase {
                continue;
            }
            if key.len() != b"evt_phase:".len() + 32 {
                continue;
            }
            let start = b"evt_phase:".len();
            let mut id = [0u8; 32];
            id.copy_from_slice(&key[start..start + 32]);
            out.push(EventId::from(id));
        }
        Ok(out)
    }

    fn mark_committed(
        &self,
        event_id: &EventId,
        round: u32,
        canonical_hash: TxTemplateHash,
        now_ns: u64,
    ) -> Result<bool, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        let mut state = match self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            Some(bytes) => Self::decode::<EventPhaseState>(&bytes)?,
            None => EventPhaseState::new(EventPhase::Proposing, now_ns),
        };

        if state.phase == EventPhase::Committed || state.phase == EventPhase::Completed {
            if state.canonical_hash != Some(canonical_hash) {
                return Ok(false);
            }
            // Idempotent: accept replays even if the sender's round differs from ours.
            // Round is informational once committed; the canonical hash is the real commitment.
            state.round = round;
            self.db.put_cf(cf, key, Self::encode(&state)?).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
            return Ok(true);
        }
        if matches!(state.phase, EventPhase::Abandoned) {
            return Ok(false);
        }
        state.phase = EventPhase::Committed;
        state.phase_started_at_ns = now_ns;
        state.round = round;
        state.canonical_hash = Some(canonical_hash);

        self.db.put_cf(cf, key, Self::encode(&state)?).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
        Ok(true)
    }

    fn mark_completed(&self, event_id: &EventId, now_ns: u64) -> Result<(), ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        let mut state = match self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            Some(bytes) => Self::decode::<EventPhaseState>(&bytes)?,
            None => EventPhaseState::new(EventPhase::Unknown, now_ns),
        };
        state.phase = EventPhase::Completed;
        state.phase_started_at_ns = now_ns;
        self.db.put_cf(cf, key, Self::encode(&state)?).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
        Ok(())
    }

    fn fail_and_bump_round(&self, event_id: &EventId, expected_round: u32, now_ns: u64) -> Result<bool, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        let Some(bytes) = self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? else {
            return Ok(false);
        };
        let mut state: EventPhaseState = Self::decode(&bytes)?;
        if state.round != expected_round {
            return Ok(false);
        }
        if matches!(state.phase, EventPhase::Committed | EventPhase::Completed | EventPhase::Abandoned) {
            return Ok(false);
        }
        state.phase = EventPhase::Failed;
        state.phase_started_at_ns = now_ns;
        state.round = state.round.saturating_add(1);
        state.retry_count = state.retry_count.saturating_add(1);
        state.canonical_hash = None;
        state.own_proposal_hash = None;

        self.db.put_cf(cf, key, Self::encode(&state)?).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
        Ok(true)
    }

    fn mark_abandoned(&self, event_id: &EventId, now_ns: u64) -> Result<(), ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        let mut state = match self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            Some(bytes) => Self::decode::<EventPhaseState>(&bytes)?,
            None => EventPhaseState::new(EventPhase::Unknown, now_ns),
        };
        state.phase = EventPhase::Abandoned;
        state.phase_started_at_ns = now_ns;
        self.db.put_cf(cf, key, Self::encode(&state)?).map_err(|err| storage_err!("rocksdb put_cf evt_phase", err))?;
        Ok(())
    }

    fn clear_stale_proposals(&self, event_id: &EventId, before_round: u32) -> Result<usize, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf = self.cf_handle(CF_EVENT_PROPOSAL)?;
        let prefix = Self::key_event_proposal_prefix(event_id);
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix.as_slice(), Direction::Forward));
        let mut batch = WriteBatch::default();
        let mut deleted = 0usize;
        for item in iter {
            let (key, _value) = item.map_err(|err| storage_err!("rocksdb iterator evt_prop", err))?;
            if !key.starts_with(&prefix) {
                break;
            }
            let round_offset = prefix.len();
            if key.len() < round_offset + 4 {
                continue;
            }
            let mut round_bytes = [0u8; 4];
            round_bytes.copy_from_slice(&key[round_offset..round_offset + 4]);
            let round = u32::from_be_bytes(round_bytes);
            if round < before_round {
                batch.delete_cf(cf, key);
                deleted += 1;
            }
        }
        if deleted > 0 {
            self.db.write(batch).map_err(|err| storage_err!("rocksdb write clear_stale_proposals", err))?;
        }
        Ok(deleted)
    }

    fn gc_events_older_than(&self, cutoff_timestamp_ns: u64) -> Result<usize, ThresholdError> {
        let _guard = self
            .phase_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "phase_lock".to_string(), details: "poisoned".to_string() })?;
        let cf_phase = self.cf_handle(CF_EVENT_PHASE)?;
        let cf_prop = self.cf_handle(CF_EVENT_PROPOSAL)?;
        let iter = self.db.iterator_cf(cf_phase, IteratorMode::Start);
        let mut batch = WriteBatch::default();
        let mut deleted = 0usize;
        for item in iter {
            let (key, value) = item.map_err(|err| storage_err!("rocksdb iterator evt_phase", err))?;
            let state: EventPhaseState = Self::decode(&value)?;
            if !state.phase.is_terminal() {
                continue;
            }
            if state.phase_started_at_ns >= cutoff_timestamp_ns {
                continue;
            }
            // phase key contains the event_id bytes.
            if key.len() != b"evt_phase:".len() + 32 {
                continue;
            }
            let start = b"evt_phase:".len();
            let mut event_id = [0u8; 32];
            event_id.copy_from_slice(&key[start..start + 32]);
            let event_id = EventId::from(event_id);

            batch.delete_cf(cf_phase, key);

            // Delete proposals for this event.
            let prop_prefix = Self::key_event_proposal_prefix(&event_id);
            let prop_iter = self.db.iterator_cf(cf_prop, IteratorMode::From(prop_prefix.as_slice(), Direction::Forward));
            for prop_item in prop_iter {
                let (prop_key, _) = prop_item.map_err(|err| storage_err!("rocksdb iterator evt_prop", err))?;
                if !prop_key.starts_with(&prop_prefix) {
                    break;
                }
                batch.delete_cf(cf_prop, prop_key);
            }
            deleted += 1;
        }
        if deleted > 0 {
            self.db.write(batch).map_err(|err| storage_err!("rocksdb write gc_events_older_than", err))?;
        }
        Ok(deleted)
    }

    fn has_proposal_from(&self, event_id: &EventId, round: u32, peer_id: &PeerId) -> Result<bool, ThresholdError> {
        let cf = self.cf_handle(CF_EVENT_PROPOSAL)?;
        let key = Self::key_event_proposal(event_id, round, peer_id);
        Ok(self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb get_cf evt_prop", err))?.is_some())
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
    fn upsert_group_config(&self, group_id: GroupId, config: GroupConfig) -> Result<(), ThresholdError> {
        trace!("upsert_group_config group_id={:#x}", group_id);
        let key = Self::key_group(&group_id);
        let value = Self::encode(&config)?;
        let cf = self.cf_handle(CF_GROUP)?;
        self.db.put_cf(cf, key, value).map_err(|err| storage_err!("rocksdb", err))
    }

    fn get_group_config(&self, group_id: &GroupId) -> Result<Option<GroupConfig>, ThresholdError> {
        trace!("get_group_config group_id={:#x}", group_id);
        let key = Self::key_group(group_id);
        let cf = self.cf_handle(CF_GROUP)?;
        let value = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb", err))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn insert_event(&self, event_id: EventId, event: StoredEvent) -> Result<(), ThresholdError> {
        debug!("insert_event event_id={:#x} external_id={:#x}", event_id, event.event.external_id);
        let key = Self::key_event(&event_id);
        let cf = self.cf_handle(CF_EVENT)?;
        if self.db.get_cf(cf, &key).map_err(|e| storage_err!("rocksdb get_cf event_exists", e))?.is_some() {
            return Ok(());
        }

        let value = Self::encode(&event)?;
        self.db.put_cf(cf, key, value).map_err(|err| storage_err!("rocksdb", err))?;
        debug!("event stored event_id={:#x}", event_id);
        Ok(())
    }

    fn insert_event_if_not_exists(&self, event_id: EventId, event: StoredEvent) -> Result<bool, ThresholdError> {
        let key = Self::key_event(&event_id);
        let cf = self.cf_handle(CF_EVENT)?;
        if self.db.get_cf(cf, &key).map_err(|e| storage_err!("rocksdb get_cf event_exists", e))?.is_some() {
            return Ok(false);
        }

        let value = Self::encode(&event)?;
        self.db.put_cf(cf, key, value).map_err(|err| storage_err!("rocksdb", err))?;
        Ok(true)
    }

    fn get_event(&self, event_id: &EventId) -> Result<Option<StoredEvent>, ThresholdError> {
        trace!("get_event event_id={:#x}", event_id);
        let key = Self::key_event(event_id);
        let cf = self.cf_handle(CF_EVENT)?;
        let value = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb", err))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn get_event_active_template_hash(&self, event_id: &EventId) -> Result<Option<TxTemplateHash>, ThresholdError> {
        let key = Self::key_event_active_template(event_id);
        let cf = self.cf_handle(CF_EVENT_INDEX)?;
        let value = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb", err))?;
        match value {
            None => Ok(None),
            Some(bytes) => {
                let array: [u8; 32] =
                    bytes.as_slice().try_into().map_err(|_| storage_err!("decode active tx_template_hash", "corrupt value"))?;
                Ok(Some(TxTemplateHash::from(array)))
            }
        }
    }

    fn set_event_active_template_hash(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash) -> Result<(), ThresholdError> {
        let key = Self::key_event_active_template(event_id);
        let cf = self.cf_handle(CF_EVENT_INDEX)?;
        if let Some(existing) = self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb", err))? {
            let existing: [u8; 32] =
                existing.as_slice().try_into().map_err(|_| storage_err!("decode active tx_template_hash", "corrupt value"))?;
            let existing = TxTemplateHash::from(existing);
            if existing != *tx_template_hash {
                return Err(ThresholdError::PsktMismatch { expected: existing.to_string(), actual: tx_template_hash.to_string() });
            }
            return Ok(());
        }
        self.db.put_cf(cf, key, tx_template_hash.as_hash()).map_err(|err| storage_err!("rocksdb", err))
    }

    fn get_event_completion(&self, event_id: &EventId) -> Result<Option<StoredCompletionRecord>, ThresholdError> {
        let key = Self::key_event_completion(event_id);
        let cf = self.cf_handle(CF_EVENT_INDEX)?;
        let value = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb", err))?;
        match value {
            None => Ok(None),
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
        }
    }

    fn set_event_completion(&self, event_id: &EventId, completion: &StoredCompletionRecord) -> Result<(), ThresholdError> {
        let key = Self::key_event_completion(event_id);
        let cf = self.cf_handle(CF_EVENT_INDEX)?;
        let value = Self::encode(completion)?;
        self.db.put_cf(cf, key, value).map_err(|err| storage_err!("rocksdb", err))
    }

    fn get_event_crdt(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
    ) -> Result<Option<StoredEventCrdt>, ThresholdError> {
        let key = Self::key_event_crdt(event_id, tx_template_hash);
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let value = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb", err))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn merge_event_crdt(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        incoming: &EventCrdtState,
        signing_material: Option<&CrdtSigningMaterial>,
        kpsbt_blob: Option<&[u8]>,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let _guard = self.crdt_lock.lock().map_err(|_| storage_err!("rocks crdt lock", "poisoned"))?;

        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let key = Self::key_event_crdt(event_id, tx_template_hash);
        let now_nanos = crate::foundation::now_nanos();

        let mut local: StoredEventCrdt = match self.db.get_cf(cf, &key).map_err(|e| storage_err!("rocksdb", e))? {
            Some(bytes) => Self::decode(&bytes)?,
            None => StoredEventCrdt {
                event_id: *event_id,
                tx_template_hash: *tx_template_hash,
                signing_material: None,
                kpsbt_blob: None,
                signatures: Vec::new(),
                completion: None,
                created_at_nanos: now_nanos,
                updated_at_nanos: now_nanos,
            },
        };

        let mut changed = false;
        let had_completion = local.completion.is_some();

        if local.signing_material.is_none() {
            if let Some(ev) = signing_material {
                local.signing_material = Some(ev.clone());
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
            let record =
                <CrdtSignatureRecord as std::convert::TryFrom<&crate::infrastructure::transport::messages::CrdtSignature>>::try_from(
                    sig,
                )?;
            let sig_key = (record.input_index, record.pubkey.clone());
            if !existing.contains(&sig_key) {
                local.signatures.push(record);
                existing.insert(sig_key);
                changed = true;
            }
        }

        if let Some(incoming_completion) = &incoming.completion {
            match &local.completion {
                None => {
                    local.completion = Some(StoredCompletionRecord::from(incoming_completion));
                    changed = true;
                }
                Some(existing_completion) => {
                    if incoming_completion.timestamp_nanos > existing_completion.timestamp_nanos {
                        local.completion = Some(StoredCompletionRecord::from(incoming_completion));
                        changed = true;
                    }
                }
            }
        }

        if changed {
            local.updated_at_nanos = now_nanos;
            let value = Self::encode(&local)?;
            self.db.put_cf(cf, &key, value).map_err(|e| storage_err!("rocksdb", e))?;

            if let Some(completion) = local.completion.as_ref() {
                self.set_event_completion(event_id, completion)?;
                // Update daily volume only once per event (first time we see completion).
                if !had_completion {
                    if let Some(event) = self.get_event(event_id)? {
                        self.add_to_daily_volume(event.event.amount_sompi, event.received_at_nanos)?;
                    }
                }
            }
        }

        Ok((local, changed))
    }

    fn add_signature_to_crdt(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        input_index: u32,
        pubkey: &[u8],
        signature: &[u8],
        signer_peer_id: &PeerId,
        timestamp_nanos: u64,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let _guard = self.crdt_lock.lock().map_err(|_| storage_err!("rocks crdt lock", "poisoned"))?;

        self.set_event_active_template_hash(event_id, tx_template_hash)?;

        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let key = Self::key_event_crdt(event_id, tx_template_hash);
        let now_nanos = crate::foundation::now_nanos();

        let mut local: StoredEventCrdt = match self.db.get_cf(cf, &key).map_err(|e| storage_err!("rocksdb", e))? {
            Some(bytes) => Self::decode(&bytes)?,
            None => StoredEventCrdt {
                event_id: *event_id,
                tx_template_hash: *tx_template_hash,
                signing_material: None,
                kpsbt_blob: None,
                signatures: Vec::new(),
                completion: None,
                created_at_nanos: now_nanos,
                updated_at_nanos: now_nanos,
            },
        };

        let already = local.signatures.iter().any(|s| s.input_index == input_index && s.pubkey.as_slice() == pubkey);

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
        self.db.put_cf(cf, &key, value).map_err(|e| storage_err!("rocksdb", e))?;
        Ok((local, true))
    }

    fn mark_crdt_completed(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        tx_id: TransactionId,
        submitter_peer_id: &PeerId,
        timestamp_nanos: u64,
        blue_score: Option<u64>,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let incoming = EventCrdtState {
            signatures: vec![],
            completion: Some(CompletionRecord { tx_id, submitter_peer_id: submitter_peer_id.clone(), timestamp_nanos, blue_score }),
            signing_material: None,
            kpsbt_blob: None,
            version: 0,
        };
        let (state, changed) = self.merge_event_crdt(event_id, tx_template_hash, &incoming, None, None)?;
        Ok((state, changed))
    }

    fn crdt_has_threshold(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        input_count: usize,
        required: usize,
    ) -> Result<bool, ThresholdError> {
        let state = match self.get_event_crdt(event_id, tx_template_hash)? {
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

        Ok((0..input_count as u32).all(|idx| per_input.get(&idx).is_some_and(|set| set.len() >= required)))
    }

    fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        let prefix = b"evt_crdt:";
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|e| storage_err!("rocksdb", e))?;
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

    fn list_event_crdts_for_event(&self, event_id: &EventId) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        let prefix = Self::key_event_crdt_prefix(event_id);
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|e| storage_err!("rocksdb", e))?;
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
            let (key, value) = item.map_err(|e| storage_err!("rocksdb", e))?;
            if !key.starts_with(prefix) {
                break;
            }
            total += 1;
            let state: StoredEventCrdt = Self::decode(&value)?;
            if state.completion.is_none() {
                pending += 1;
            }
        }

        let cf_estimated_num_keys =
            self.db.property_int_value_cf(cf, "rocksdb.estimate-num-keys").map_err(|err| storage_err!("rocksdb", err))?;
        let cf_estimated_live_data_size_bytes =
            self.db.property_int_value_cf(cf, "rocksdb.estimate-live-data-size").map_err(|err| storage_err!("rocksdb", err))?;

        Ok(CrdtStorageStats {
            total_event_crdts: total,
            pending_event_crdts: pending,
            completed_event_crdts: total.saturating_sub(pending),
            cf_estimated_num_keys,
            cf_estimated_live_data_size_bytes,
        })
    }

    fn cleanup_completed_event_crdts(&self, older_than_nanos: u64) -> Result<usize, ThresholdError> {
        let _guard = self.crdt_lock.lock().map_err(|_| storage_err!("rocks crdt lock", "poisoned"))?;

        let prefix = b"evt_crdt:";
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let cf_index = self.cf_handle(CF_EVENT_INDEX)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        let mut batch = WriteBatch::default();
        let mut deleted = 0usize;

        for item in iter {
            let (key, value) = item.map_err(|e| storage_err!("rocksdb", e))?;
            if !key.starts_with(prefix) {
                break;
            }
            let state: StoredEventCrdt = Self::decode(&value)?;
            let Some(completion) = state.completion.as_ref() else { continue };
            if completion.timestamp_nanos < older_than_nanos {
                batch.delete_cf(cf, key);
                batch.delete_cf(cf_index, Self::key_event_active_template(&state.event_id));
                batch.delete_cf(cf_index, Self::key_event_completion(&state.event_id));
                deleted += 1;
            }
        }

        if deleted > 0 {
            self.db.write(batch).map_err(|err| storage_err!("rocksdb", err))?;
        }

        Ok(deleted)
    }

    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64, ThresholdError> {
        trace!("get_volume_since timestamp_nanos={}", timestamp_nanos);
        let day_start = crate::foundation::day_start_nanos(timestamp_nanos);
        if let Some(total) = self.volume_from_index(day_start)? {
            debug!("volume_from_index hit day_start={} total={}", day_start, total);
            return Ok(total);
        }
        let total = self.volume_from_scan(day_start)?;
        debug!("volume_from_scan computed day_start={} total={}", day_start, total);
        // Cache the computed total for this day to speed up subsequent reads.
        let cf = self.cf_handle(CF_VOLUME)?;
        let key = Self::key_volume(day_start);
        self.db.put_cf(cf, key, total.to_be_bytes()).map_err(|e| storage_err!("rocksdb", e))?;
        Ok(total)
    }

    fn health_check(&self) -> Result<(), ThresholdError> {
        self.db.property_value("rocksdb.stats").map_err(|err| storage_err!("rocksdb", err))?;
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
        let existing = self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb", err))?;
        if existing.is_some() {
            return Ok(false);
        }
        self.db.put_cf(cf, key, timestamp_nanos.to_be_bytes()).map_err(|err| storage_err!("rocksdb", err))?;
        debug!("marked message seen sender_peer_id={} session_id={} seq_no={}", sender_peer_id, session_id, seq_no);
        Ok(true)
    }

    fn cleanup_seen_messages(&self, older_than_nanos: u64) -> Result<usize, ThresholdError> {
        let prefix = b"seen:";
        let mut deleted = 0usize;
        let mut batch = WriteBatch::default();
        let cf = self.cf_handle(CF_SEEN)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|err| storage_err!("rocksdb", err))?;
            if !key.starts_with(prefix) {
                break;
            }
            if value.len() != 8 {
                warn!("corrupted seen-message timestamp; skipping key_hex={} value_len={}", crate::foundation::hx(&key), value.len());
                continue;
            }
            let timestamp: u64 = match value.as_ref().try_into() {
                Ok(bytes) => u64::from_be_bytes(bytes),
                Err(_) => {
                    warn!("corrupted seen-message timestamp bytes; skipping key_hex={}", crate::foundation::hx(&key));
                    continue;
                }
            };
            if timestamp < older_than_nanos {
                batch.delete_cf(cf, key);
                deleted += 1;
            }
        }

        if deleted > 0 {
            self.db.write(batch).map_err(|err| storage_err!("rocksdb", err))?;
        }
        debug!("cleanup_seen_messages complete older_than_nanos={} deleted={}", older_than_nanos, deleted);
        Ok(deleted)
    }

    fn hyperlane_get_delivered_count(&self) -> Result<u32, ThresholdError> {
        let cf = self.cf_handle(CF_METADATA)?;
        let value = self.db.get_cf(cf, Self::key_hyperlane_delivered_count()).map_err(|err| storage_err!("rocksdb", err))?;
        let Some(bytes) = value else { return Ok(0) };
        if bytes.len() != 8 {
            return Err(ThresholdError::StorageError {
                operation: "hyperlane_delivered_count decode".to_string(),
                details: format!("invalid length {}", bytes.len()),
            });
        }
        let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| ThresholdError::StorageError {
            operation: "hyperlane_delivered_count decode".to_string(),
            details: "invalid bytes".to_string(),
        })?;
        let count = u64::from_be_bytes(arr);
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    fn hyperlane_is_message_delivered(&self, message_id: &ExternalId) -> Result<bool, ThresholdError> {
        let cf = self.cf_handle(CF_HYPERLANE_MESSAGE)?;
        let key = Self::key_hyperlane_message(message_id);
        Ok(self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb", err))?.is_some())
    }

    fn hyperlane_get_delivery(&self, message_id: &ExternalId) -> Result<Option<HyperlaneDeliveryRecord>, ThresholdError> {
        let cf = self.cf_handle(CF_HYPERLANE_MESSAGE)?;
        let key = Self::key_hyperlane_message(message_id);
        let value = self.db.get_cf(cf, key).map_err(|err| storage_err!("rocksdb", err))?;
        match value {
            Some(bytes) => {
                let record: HyperlaneDeliveredMessage = Self::decode(&bytes)?;
                Ok(Some(record.delivery))
            }
            None => Ok(None),
        }
    }

    fn hyperlane_get_deliveries_in_range(
        &self,
        from_daa_score: u64,
        to_daa_score: u64,
    ) -> Result<Vec<HyperlaneDeliveryRecord>, ThresholdError> {
        if from_daa_score > to_daa_score {
            return Ok(Vec::new());
        }
        let prefix = b"hl_dlv:";
        let cf = self.cf_handle(CF_HYPERLANE_DELIVERY)?;
        let start_key = KeyBuilder::with_capacity(prefix.len() + 8).prefix(prefix).u64_be(from_daa_score).build();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&start_key, Direction::Forward));
        let mut out = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|err| storage_err!("rocksdb", err))?;
            if !key.starts_with(prefix) {
                break;
            }
            if key.len() < prefix.len() + 8 {
                continue;
            }
            let mut daa_bytes = [0u8; 8];
            daa_bytes.copy_from_slice(&key[prefix.len()..prefix.len() + 8]);
            let daa_score = u64::from_be_bytes(daa_bytes);
            if daa_score > to_daa_score {
                break;
            }
            let record: HyperlaneDeliveryRecord = Self::decode(&value)?;
            out.push(record);
        }
        Ok(out)
    }

    fn hyperlane_get_messages_in_range(
        &self,
        from_daa_score: u64,
        to_daa_score: u64,
    ) -> Result<Vec<HyperlaneMessageRecord>, ThresholdError> {
        if from_daa_score > to_daa_score {
            return Ok(Vec::new());
        }
        let prefix = b"hl_dlv:";
        let cf = self.cf_handle(CF_HYPERLANE_DELIVERY)?;
        let start_key = KeyBuilder::with_capacity(prefix.len() + 8).prefix(prefix).u64_be(from_daa_score).build();
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&start_key, Direction::Forward));
        let mut out = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|err| storage_err!("rocksdb", err))?;
            if !key.starts_with(prefix) {
                break;
            }
            if key.len() < prefix.len() + 8 {
                continue;
            }
            let mut daa_bytes = [0u8; 8];
            daa_bytes.copy_from_slice(&key[prefix.len()..prefix.len() + 8]);
            let daa_score = u64::from_be_bytes(daa_bytes);
            if daa_score > to_daa_score {
                break;
            }
            let delivery: HyperlaneDeliveryRecord = Self::decode(&value)?;
            let cf_msg = self.cf_handle(CF_HYPERLANE_MESSAGE)?;
            let msg_key = Self::key_hyperlane_message(&delivery.message_id);
            let Some(bytes) = self.db.get_cf(cf_msg, msg_key).map_err(|err| storage_err!("rocksdb", err))? else {
                continue;
            };
            let record: HyperlaneDeliveredMessage = Self::decode(&bytes)?;
            out.push(record.message);
        }
        Ok(out)
    }

    fn hyperlane_get_latest_delivery_daa_score(&self) -> Result<Option<u64>, ThresholdError> {
        let prefix = b"hl_dlv:";
        let cf = self.cf_handle(CF_HYPERLANE_DELIVERY)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::End);
        for item in iter {
            let (key, _value) = item.map_err(|err| storage_err!("rocksdb", err))?;
            if !key.starts_with(prefix) {
                continue;
            }
            if key.len() < prefix.len() + 8 {
                continue;
            }
            let mut daa_bytes = [0u8; 8];
            daa_bytes.copy_from_slice(&key[prefix.len()..prefix.len() + 8]);
            return Ok(Some(u64::from_be_bytes(daa_bytes)));
        }
        Ok(None)
    }

    fn hyperlane_mark_delivered(&self, delivered: &HyperlaneDeliveredMessage) -> Result<bool, ThresholdError> {
        let _guard = self
            .hyperlane_lock
            .lock()
            .map_err(|_| ThresholdError::StorageError { operation: "hyperlane_lock".to_string(), details: "poisoned".to_string() })?;

        let cf_msg = self.cf_handle(CF_HYPERLANE_MESSAGE)?;
        let cf_dlv = self.cf_handle(CF_HYPERLANE_DELIVERY)?;
        let cf_meta = self.cf_handle(CF_METADATA)?;

        let message_key = Self::key_hyperlane_message(&delivered.delivery.message_id);
        if self.db.get_cf(cf_msg, &message_key).map_err(|err| storage_err!("rocksdb", err))?.is_some() {
            return Ok(false);
        }

        let delivery_key = Self::key_hyperlane_delivery_index(delivered.delivery.daa_score, &delivered.delivery.message_id);
        let message_value = Self::encode(delivered)?;
        let delivery_value = Self::encode(&delivered.delivery)?;

        let count_key = Self::key_hyperlane_delivered_count();
        let existing = self.db.get_cf(cf_meta, count_key).map_err(|err| storage_err!("rocksdb", err))?;
        let mut count = match existing {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| ThresholdError::StorageError {
                    operation: "hyperlane_delivered_count decode".to_string(),
                    details: "invalid bytes".to_string(),
                })?;
                u64::from_be_bytes(arr)
            }
            _ => 0,
        };
        count = count.saturating_add(1);

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_msg, message_key, message_value);
        batch.put_cf(cf_dlv, delivery_key, delivery_value);
        batch.put_cf(cf_meta, count_key, count.to_be_bytes());
        self.db.write(batch).map_err(|err| storage_err!("rocksdb", err))?;
        Ok(true)
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
        self.db.write(self.batch).map_err(|err| storage_err!("rocksdb", err))
    }

    fn rollback(self: Box<Self>) {
        drop(self);
    }
}
