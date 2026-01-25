use super::RocksStorage;
use crate::domain::coordination::{EventPhase, EventPhaseState, Proposal};
use crate::foundation::{EventId, PeerId, ThresholdError, TxTemplateHash};
use crate::infrastructure::storage::phase::{PhaseStorage, RecordSignedHashResult, StoreProposalResult};
use crate::infrastructure::storage::rocks::schema::*;
use crate::infrastructure::storage::rocks::util::acquire_with_timeout;
use crate::storage_err;
use rocksdb::{Direction, IteratorMode, WriteBatch};

impl PhaseStorage for RocksStorage {
    fn try_enter_proposing(&self, event_id: &EventId, now_ns: u64) -> Result<bool, ThresholdError> {
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;

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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;

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
            if !existing.tx_template_hash.ct_eq(&proposal.tx_template_hash) {
                crate::infrastructure::audit::audit(crate::infrastructure::audit::AuditEvent::ProposalEquivocationDetected {
                    event_id: proposal.event_id.to_string(),
                    round: proposal.round,
                    proposer_peer_id: proposal.proposer_peer_id.to_string(),
                    existing_tx_template_hash: existing.tx_template_hash.to_string(),
                    new_tx_template_hash: proposal.tx_template_hash.to_string(),
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
        let cf = self.cf_handle(CF_EVENT_PHASE)?;
        let key = Self::key_event_phase(event_id);
        let mut state = match self.db.get_cf(cf, &key).map_err(|err| storage_err!("rocksdb get_cf evt_phase", err))? {
            Some(bytes) => Self::decode::<EventPhaseState>(&bytes)?,
            None => EventPhaseState::new(EventPhase::Proposing, now_ns),
        };

        if state.phase == EventPhase::Committed || state.phase == EventPhase::Completed {
            let Some(existing_hash) = state.canonical_hash else {
                return Ok(false);
            };
            if !existing_hash.ct_eq(&canonical_hash) {
                return Ok(false);
            }
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
        let _guard = acquire_with_timeout(&self.phase_lock, "rocks phase lock")?;
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
            if key.len() != b"evt_phase:".len() + 32 {
                continue;
            }
            let start = b"evt_phase:".len();
            let mut event_id = [0u8; 32];
            event_id.copy_from_slice(&key[start..start + 32]);
            let event_id = EventId::from(event_id);

            batch.delete_cf(cf_phase, key);

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
