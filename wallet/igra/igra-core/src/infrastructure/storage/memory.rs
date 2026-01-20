use crate::domain::coordination::{EventPhase, EventPhaseState, Proposal};
use crate::domain::{CrdtSignatureRecord, CrdtSigningMaterial, GroupConfig, StoredCompletionRecord, StoredEvent, StoredEventCrdt};
use crate::foundation::ThresholdError;
use crate::foundation::{day_start_nanos, now_nanos, EventId, ExternalId, GroupId, PeerId, SessionId, TransactionId, TxTemplateHash};
use crate::infrastructure::storage::hyperlane::{HyperlaneDeliveredMessage, HyperlaneDeliveryRecord, HyperlaneMessageRecord};
use crate::infrastructure::storage::phase::{PhaseStorage, RecordSignedHashResult, StoreProposalResult};
use crate::infrastructure::storage::{BatchTransaction, CrdtStorageStats, Storage};
use crate::infrastructure::transport::messages::{CompletionRecord, CrdtSignature, EventCrdtState};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

struct MemoryInner {
    group: HashMap<GroupId, GroupConfig>,
    event: HashMap<EventId, StoredEvent>,
    event_active_template: HashMap<EventId, TxTemplateHash>,
    event_completion: HashMap<EventId, StoredCompletionRecord>,
    event_crdt: HashMap<(EventId, TxTemplateHash), StoredEventCrdt>,
    volume: HashMap<u64, u64>,
    seen: HashMap<(PeerId, SessionId, u64), u64>,

    // Two-phase protocol
    phase: HashMap<EventId, EventPhaseState>,
    proposals: HashMap<(EventId, u32, PeerId), Proposal>,
    signed_hash: HashMap<EventId, TxTemplateHash>,

    hyperlane_delivered_count: u32,
    hyperlane_deliveries: HashMap<ExternalId, HyperlaneDeliveredMessage>,
    hyperlane_deliveries_by_daa: BTreeMap<(u64, ExternalId), HyperlaneDeliveryRecord>,
}

impl MemoryInner {
    fn new() -> Self {
        Self {
            group: HashMap::new(),
            event: HashMap::new(),
            event_active_template: HashMap::new(),
            event_completion: HashMap::new(),
            event_crdt: HashMap::new(),
            volume: HashMap::new(),
            seen: HashMap::new(),
            phase: HashMap::new(),
            proposals: HashMap::new(),
            signed_hash: HashMap::new(),
            hyperlane_delivered_count: 0,
            hyperlane_deliveries: HashMap::new(),
            hyperlane_deliveries_by_daa: BTreeMap::new(),
        }
    }
}

pub struct MemoryStorage {
    inner: Arc<Mutex<MemoryInner>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(MemoryInner::new())) }
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, MemoryInner>, ThresholdError> {
        self.inner.lock().map_err(|_| ThresholdError::StorageError {
            operation: "memory storage lock".to_string(),
            details: "poisoned".to_string(),
        })
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn upsert_group_config(&self, group_id: GroupId, config: GroupConfig) -> Result<(), ThresholdError> {
        self.lock_inner()?.group.insert(group_id, config);
        Ok(())
    }

    fn get_group_config(&self, group_id: &GroupId) -> Result<Option<GroupConfig>, ThresholdError> {
        Ok(self.lock_inner()?.group.get(group_id).cloned())
    }

    fn insert_event(&self, event_id: EventId, event: StoredEvent) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        inner.event.entry(event_id).or_insert(event);
        Ok(())
    }

    fn insert_event_if_not_exists(&self, event_id: EventId, event: StoredEvent) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        if inner.event.contains_key(&event_id) {
            return Ok(false);
        }
        inner.event.insert(event_id, event);
        Ok(true)
    }

    fn get_event(&self, event_id: &EventId) -> Result<Option<StoredEvent>, ThresholdError> {
        Ok(self.lock_inner()?.event.get(event_id).cloned())
    }

    fn get_event_active_template_hash(&self, event_id: &EventId) -> Result<Option<TxTemplateHash>, ThresholdError> {
        Ok(self.lock_inner()?.event_active_template.get(event_id).copied())
    }

    fn set_event_active_template_hash(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        if let Some(existing) = inner.event_active_template.get(event_id) {
            if existing != tx_template_hash {
                return Err(ThresholdError::PsktMismatch { expected: existing.to_string(), actual: tx_template_hash.to_string() });
            }
            return Ok(());
        }
        inner.event_active_template.insert(*event_id, *tx_template_hash);
        Ok(())
    }

    fn get_event_completion(&self, event_id: &EventId) -> Result<Option<StoredCompletionRecord>, ThresholdError> {
        Ok(self.lock_inner()?.event_completion.get(event_id).cloned())
    }

    fn set_event_completion(&self, event_id: &EventId, completion: &StoredCompletionRecord) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        inner.event_completion.insert(*event_id, completion.clone());
        Ok(())
    }

    fn get_event_crdt(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
    ) -> Result<Option<StoredEventCrdt>, ThresholdError> {
        Ok(self.lock_inner()?.event_crdt.get(&(*event_id, *tx_template_hash)).cloned())
    }

    fn merge_event_crdt(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        incoming: &EventCrdtState,
        signing_material: Option<&CrdtSigningMaterial>,
        kpsbt_blob: Option<&[u8]>,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let mut inner = self.lock_inner()?;
        let now_nanos = now_nanos();
        let key = (*event_id, *tx_template_hash);

        let mut changed = false;
        let mut completion_to_index: Option<StoredCompletionRecord> = None;
        let mut completion_first_seen = false;

        let local_snapshot = {
            let local = inner.event_crdt.entry(key).or_insert_with(|| StoredEventCrdt {
                event_id: *event_id,
                tx_template_hash: *tx_template_hash,
                signing_material: None,
                kpsbt_blob: None,
                signatures: Vec::new(),
                completion: None,
                created_at_nanos: now_nanos,
                updated_at_nanos: now_nanos,
            });

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

            let mut existing: std::collections::HashSet<(u32, Vec<u8>)> = std::collections::HashSet::new();
            for sig in &local.signatures {
                existing.insert((sig.input_index, sig.pubkey.clone()));
            }

            for sig in &incoming.signatures {
                let record = <CrdtSignatureRecord as std::convert::TryFrom<&CrdtSignature>>::try_from(sig)?;
                let sig_key = (record.input_index, record.pubkey.clone());
                if !existing.contains(&sig_key) {
                    local.signatures.push(record);
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
                if let Some(completion) = local.completion.as_ref() {
                    completion_to_index = Some(completion.clone());
                    completion_first_seen = !had_completion;
                }
            }

            local.clone()
        };

        if let Some(completion) = completion_to_index {
            inner.event_completion.insert(*event_id, completion);
            if completion_first_seen {
                if let Some(event) = inner.event.get(event_id) {
                    let day_start = day_start_nanos(event.received_at_nanos);
                    let amount = event.event.amount_sompi;
                    inner.volume.entry(day_start).and_modify(|v| *v = v.saturating_add(amount)).or_insert(amount);
                }
            }
        }

        Ok((local_snapshot, changed))
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
        let incoming = EventCrdtState {
            signatures: vec![CrdtSignature {
                input_index,
                pubkey: pubkey.to_vec(),
                signature: signature.to_vec(),
                signer_peer_id: Some(signer_peer_id.clone()),
                timestamp_nanos,
            }],
            completion: None,
            signing_material: None,
            kpsbt_blob: None,
            version: 0,
        };

        let (state, changed) = self.merge_event_crdt(event_id, tx_template_hash, &incoming, None, None)?;
        Ok((state, changed))
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

        let mut per_input: std::collections::HashMap<u32, std::collections::HashSet<&[u8]>> = std::collections::HashMap::new();
        for sig in &state.signatures {
            if (sig.input_index as usize) < input_count {
                per_input.entry(sig.input_index).or_default().insert(sig.pubkey.as_slice());
            }
        }

        Ok((0..input_count as u32).all(|idx| per_input.get(&idx).is_some_and(|set| set.len() >= required)))
    }

    fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        Ok(self.lock_inner()?.event_crdt.values().filter(|s| s.completion.is_none()).cloned().collect())
    }

    fn list_event_crdts_for_event(&self, event_id: &EventId) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        Ok(self.lock_inner()?.event_crdt.values().filter(|s| &s.event_id == event_id).cloned().collect())
    }

    fn crdt_storage_stats(&self) -> Result<CrdtStorageStats, ThresholdError> {
        let inner = self.lock_inner()?;
        let total = inner.event_crdt.len() as u64;
        let pending = inner.event_crdt.values().filter(|s| s.completion.is_none()).count() as u64;
        Ok(CrdtStorageStats {
            total_event_crdts: total,
            pending_event_crdts: pending,
            completed_event_crdts: total.saturating_sub(pending),
            cf_estimated_num_keys: Some(total),
            cf_estimated_live_data_size_bytes: None,
        })
    }

    fn cleanup_completed_event_crdts(&self, older_than_nanos: u64) -> Result<usize, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let before = inner.event_crdt.len();
        inner.event_crdt.retain(|_, state| match state.completion.as_ref() {
            None => true,
            Some(completion) => completion.timestamp_nanos >= older_than_nanos,
        });

        // Rebuild indexes from remaining CRDTs.
        let remaining = inner
            .event_crdt
            .iter()
            .map(|((event_id, tx_template_hash), state)| (*event_id, *tx_template_hash, state.completion.clone()))
            .collect::<Vec<_>>();
        inner.event_active_template.clear();
        inner.event_completion.clear();
        for (event_id, tx_template_hash, completion) in remaining {
            inner.event_active_template.entry(event_id).or_insert(tx_template_hash);
            if let Some(completion) = completion {
                inner.event_completion.insert(event_id, completion);
            }
        }
        Ok(before.saturating_sub(inner.event_crdt.len()))
    }

    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64, ThresholdError> {
        let day_start = day_start_nanos(timestamp_nanos);
        Ok(self.lock_inner()?.volume.get(&day_start).copied().unwrap_or(0))
    }

    fn begin_batch(&self) -> Result<Box<dyn BatchTransaction + '_>, ThresholdError> {
        Err(ThresholdError::Unimplemented("batch transactions are not supported by MemoryStorage".to_string()))
    }

    fn mark_seen_message(
        &self,
        sender_peer_id: &PeerId,
        session_id: &SessionId,
        seq_no: u64,
        timestamp_nanos: u64,
    ) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let key = (sender_peer_id.clone(), *session_id, seq_no);
        Ok(inner.seen.insert(key, timestamp_nanos).is_none())
    }

    fn cleanup_seen_messages(&self, older_than_nanos: u64) -> Result<usize, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let before = inner.seen.len();
        inner.seen.retain(|_, ts| *ts >= older_than_nanos);
        Ok(before - inner.seen.len())
    }

    fn hyperlane_get_delivered_count(&self) -> Result<u32, ThresholdError> {
        Ok(self.lock_inner()?.hyperlane_delivered_count)
    }

    fn hyperlane_is_message_delivered(&self, message_id: &ExternalId) -> Result<bool, ThresholdError> {
        Ok(self.lock_inner()?.hyperlane_deliveries.contains_key(message_id))
    }

    fn hyperlane_get_delivery(&self, message_id: &ExternalId) -> Result<Option<HyperlaneDeliveryRecord>, ThresholdError> {
        Ok(self.lock_inner()?.hyperlane_deliveries.get(message_id).map(|record| record.delivery.clone()))
    }

    fn hyperlane_get_deliveries_in_range(
        &self,
        from_daa_score: u64,
        to_daa_score: u64,
    ) -> Result<Vec<HyperlaneDeliveryRecord>, ThresholdError> {
        let inner = self.lock_inner()?;
        if from_daa_score > to_daa_score {
            return Ok(Vec::new());
        }
        let start = (from_daa_score, ExternalId::new([0u8; 32]));
        let end = (to_daa_score, ExternalId::new([0xffu8; 32]));
        Ok(inner.hyperlane_deliveries_by_daa.range(start..=end).map(|(_, v)| v.clone()).collect())
    }

    fn hyperlane_get_messages_in_range(
        &self,
        from_daa_score: u64,
        to_daa_score: u64,
    ) -> Result<Vec<HyperlaneMessageRecord>, ThresholdError> {
        let inner = self.lock_inner()?;
        if from_daa_score > to_daa_score {
            return Ok(Vec::new());
        }
        let start = (from_daa_score, ExternalId::new([0u8; 32]));
        let end = (to_daa_score, ExternalId::new([0xffu8; 32]));
        let mut out = Vec::new();
        for ((_daa_score, message_id), _delivery) in inner.hyperlane_deliveries_by_daa.range(start..=end) {
            if let Some(record) = inner.hyperlane_deliveries.get(message_id) {
                out.push(record.message.clone());
            }
        }
        Ok(out)
    }

    fn hyperlane_get_latest_delivery_daa_score(&self) -> Result<Option<u64>, ThresholdError> {
        Ok(self.lock_inner()?.hyperlane_deliveries_by_daa.iter().next_back().map(|(k, _)| k.0))
    }

    fn hyperlane_mark_delivered(&self, delivered: &HyperlaneDeliveredMessage) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let message_id = delivered.delivery.message_id;
        if inner.hyperlane_deliveries.contains_key(&message_id) {
            return Ok(false);
        }
        inner.hyperlane_deliveries.insert(message_id, delivered.clone());
        inner.hyperlane_deliveries_by_daa.insert((delivered.delivery.daa_score, message_id), delivered.delivery.clone());
        inner.hyperlane_delivered_count = inner.hyperlane_delivered_count.saturating_add(1);
        Ok(true)
    }
}

impl PhaseStorage for MemoryStorage {
    fn try_enter_proposing(&self, event_id: &EventId, now_ns: u64) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        match inner.phase.get(event_id) {
            None => {
                inner.phase.insert(*event_id, EventPhaseState::new(EventPhase::Proposing, now_ns));
                Ok(true)
            }
            Some(state) if state.phase == EventPhase::Unknown => {
                inner.phase.insert(*event_id, EventPhaseState::new(EventPhase::Proposing, now_ns));
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    fn get_phase(&self, event_id: &EventId) -> Result<Option<EventPhaseState>, ThresholdError> {
        Ok(self.lock_inner()?.phase.get(event_id).cloned())
    }

    fn get_signed_hash(&self, event_id: &EventId) -> Result<Option<TxTemplateHash>, ThresholdError> {
        Ok(self.lock_inner()?.signed_hash.get(event_id).copied())
    }

    fn record_signed_hash(
        &self,
        event_id: &EventId,
        tx_template_hash: TxTemplateHash,
        _now_ns: u64,
    ) -> Result<RecordSignedHashResult, ThresholdError> {
        let mut inner = self.lock_inner()?;
        match inner.signed_hash.get(event_id) {
            None => {
                inner.signed_hash.insert(*event_id, tx_template_hash);
                Ok(RecordSignedHashResult::Set)
            }
            Some(existing) if *existing == tx_template_hash => Ok(RecordSignedHashResult::AlreadySame),
            Some(existing) => Ok(RecordSignedHashResult::Conflict { existing: *existing, attempted: tx_template_hash }),
        }
    }

    fn adopt_round_if_behind(&self, event_id: &EventId, new_round: u32, now_ns: u64) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let state = inner.phase.entry(*event_id).or_insert_with(|| EventPhaseState::new(EventPhase::Unknown, now_ns));

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
        Ok(true)
    }

    fn set_own_proposal_hash(&self, event_id: &EventId, tx_template_hash: TxTemplateHash) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        let state = inner.phase.entry(*event_id).or_insert_with(|| EventPhaseState::new(EventPhase::Unknown, now_nanos()));
        state.own_proposal_hash = Some(tx_template_hash);
        Ok(())
    }

    fn store_proposal(&self, proposal: &Proposal) -> Result<StoreProposalResult, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let state = inner.phase.entry(proposal.event_id).or_insert_with(|| EventPhaseState::new(EventPhase::Proposing, now_nanos()));

        if state.phase == EventPhase::Committed || state.phase == EventPhase::Completed || state.phase == EventPhase::Abandoned {
            return Ok(StoreProposalResult::PhaseTooLate);
        }
        if state.round != proposal.round {
            return Ok(StoreProposalResult::RoundMismatch { expected: state.round, got: proposal.round });
        }

        // Ensure phase is Proposing for this round.
        if state.phase == EventPhase::Unknown || state.phase == EventPhase::Failed {
            state.phase = EventPhase::Proposing;
            state.phase_started_at_ns = now_nanos();
        }

        let key = (proposal.event_id, proposal.round, proposal.proposer_peer_id.clone());
        if let Some(existing) = inner.proposals.get(&key) {
            if existing.tx_template_hash != proposal.tx_template_hash {
                // Crash-fault model behavior: detect and record equivocation, but do not attempt to punish
                // or “resolve” it at this layer. We keep the first stored proposal and reject conflicting
                // votes from the same peer for the same (event_id, round).
                crate::infrastructure::audit::audit(crate::infrastructure::audit::AuditEvent::ProposalEquivocationDetected {
                    event_id: proposal.event_id.to_string(),
                    round: proposal.round,
                    proposer_peer_id: proposal.proposer_peer_id.to_string(),
                    existing_tx_template_hash: existing.tx_template_hash.to_string(),
                    new_tx_template_hash: proposal.tx_template_hash.to_string(),
                    timestamp_nanos: now_nanos(),
                });
                return Ok(StoreProposalResult::Equivocation {
                    existing_hash: existing.tx_template_hash,
                    new_hash: proposal.tx_template_hash,
                });
            }
            return Ok(StoreProposalResult::DuplicateFromPeer);
        }

        inner.proposals.insert(key, proposal.clone());
        Ok(StoreProposalResult::Stored)
    }

    fn get_proposals(&self, event_id: &EventId, round: u32) -> Result<Vec<Proposal>, ThresholdError> {
        let inner = self.lock_inner()?;
        Ok(inner.proposals.iter().filter(|((eid, r, _), _)| eid == event_id && *r == round).map(|(_, p)| p.clone()).collect())
    }

    fn proposal_count(&self, event_id: &EventId, round: u32) -> Result<usize, ThresholdError> {
        Ok(self.get_proposals(event_id, round)?.len())
    }

    fn get_events_in_phase(&self, phase: EventPhase) -> Result<Vec<EventId>, ThresholdError> {
        let inner = self.lock_inner()?;
        Ok(inner.phase.iter().filter(|(_, s)| s.phase == phase).map(|(id, _)| *id).collect())
    }

    fn mark_committed(
        &self,
        event_id: &EventId,
        round: u32,
        canonical_hash: TxTemplateHash,
        now_ns: u64,
    ) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let state = inner.phase.entry(*event_id).or_insert_with(|| EventPhaseState::new(EventPhase::Proposing, now_ns));

        if state.phase == EventPhase::Committed || state.phase == EventPhase::Completed {
            if state.canonical_hash != Some(canonical_hash) {
                return Ok(false);
            }
            state.round = round;
            return Ok(true);
        }
        if !state.phase.can_transition_to(EventPhase::Committed)
            && state.phase != EventPhase::Proposing
            && state.phase != EventPhase::Unknown
        {
            return Ok(false);
        }
        state.phase = EventPhase::Committed;
        state.phase_started_at_ns = now_ns;
        state.round = round;
        state.canonical_hash = Some(canonical_hash);
        Ok(true)
    }

    fn mark_completed(&self, event_id: &EventId, now_ns: u64) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        let state = inner.phase.entry(*event_id).or_insert_with(|| EventPhaseState::new(EventPhase::Unknown, now_ns));
        state.phase = EventPhase::Completed;
        state.phase_started_at_ns = now_ns;
        Ok(())
    }

    fn fail_and_bump_round(&self, event_id: &EventId, expected_round: u32, now_ns: u64) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let Some(state) = inner.phase.get_mut(event_id) else {
            return Ok(false);
        };
        if state.round != expected_round {
            return Ok(false);
        }
        if state.phase == EventPhase::Committed || state.phase == EventPhase::Completed || state.phase == EventPhase::Abandoned {
            return Ok(false);
        }
        state.phase = EventPhase::Failed;
        state.phase_started_at_ns = now_ns;
        state.round = state.round.saturating_add(1);
        state.retry_count = state.retry_count.saturating_add(1);
        state.canonical_hash = None;
        state.own_proposal_hash = None;
        Ok(true)
    }

    fn mark_abandoned(&self, event_id: &EventId, now_ns: u64) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        let state = inner.phase.entry(*event_id).or_insert_with(|| EventPhaseState::new(EventPhase::Unknown, now_ns));
        state.phase = EventPhase::Abandoned;
        state.phase_started_at_ns = now_ns;
        Ok(())
    }

    fn clear_stale_proposals(&self, event_id: &EventId, before_round: u32) -> Result<usize, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let keys =
            inner.proposals.keys().filter(|(eid, round, _)| eid == event_id && *round < before_round).cloned().collect::<Vec<_>>();
        let deleted = keys.len();
        for key in keys {
            inner.proposals.remove(&key);
        }
        Ok(deleted)
    }

    fn gc_events_older_than(&self, cutoff_timestamp_ns: u64) -> Result<usize, ThresholdError> {
        let mut inner = self.lock_inner()?;
        let ids = inner
            .phase
            .iter()
            .filter(|(_, state)| state.phase_started_at_ns < cutoff_timestamp_ns && state.phase.is_terminal())
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let deleted = ids.len();
        for id in ids {
            inner.phase.remove(&id);
            inner.proposals.retain(|(eid, _, _), _| eid != &id);
        }
        Ok(deleted)
    }

    fn has_proposal_from(&self, event_id: &EventId, round: u32, peer_id: &PeerId) -> Result<bool, ThresholdError> {
        let inner = self.lock_inner()?;
        Ok(inner.proposals.contains_key(&(*event_id, round, peer_id.clone())))
    }
}

// Time helpers are in `foundation::util::time`.
