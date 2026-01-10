use crate::domain::{
    GroupConfig, PartialSigRecord, RequestDecision, RequestInput, SignerAckRecord, SigningEvent, SigningRequest, StoredProposal,
};
use crate::foundation::ThresholdError;
use crate::foundation::{Hash32, PeerId, RequestId, SessionId, TransactionId};
use crate::infrastructure::storage::{BatchTransaction, Storage};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

struct MemoryInner {
    group: HashMap<Hash32, GroupConfig>,
    event: HashMap<Hash32, SigningEvent>,
    request: HashMap<RequestId, SigningRequest>,
    proposal: HashMap<RequestId, StoredProposal>,
    request_input: HashMap<RequestId, Vec<RequestInput>>,
    signer_ack: HashMap<RequestId, Vec<SignerAckRecord>>,
    partial_sig: HashMap<RequestId, Vec<PartialSigRecord>>,
    volume: HashMap<u64, u64>,
    seen: HashMap<(PeerId, SessionId, u64), u64>,
}

impl MemoryInner {
    fn new() -> Self {
        Self {
            group: HashMap::new(),
            event: HashMap::new(),
            request: HashMap::new(),
            proposal: HashMap::new(),
            request_input: HashMap::new(),
            signer_ack: HashMap::new(),
            partial_sig: HashMap::new(),
            volume: HashMap::new(),
            seen: HashMap::new(),
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
        self.inner.lock().map_err(|_| ThresholdError::StorageError("memory storage lock poisoned".to_string()))
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn upsert_group_config(&self, group_id: Hash32, config: GroupConfig) -> Result<(), ThresholdError> {
        self.lock_inner()?.group.insert(group_id, config);
        Ok(())
    }

    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>, ThresholdError> {
        Ok(self.lock_inner()?.group.get(group_id).cloned())
    }

    fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        if inner.event.contains_key(&event_hash) {
            return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
        }
        inner.event.insert(event_hash, event);
        Ok(())
    }

    fn get_event(&self, event_hash: &Hash32) -> Result<Option<SigningEvent>, ThresholdError> {
        Ok(self.lock_inner()?.event.get(event_hash).cloned())
    }

    fn insert_request(&self, request: SigningRequest) -> Result<(), ThresholdError> {
        self.lock_inner()?.request.insert(request.request_id.clone(), request);
        Ok(())
    }

    fn update_request_decision(&self, request_id: &RequestId, decision: RequestDecision) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        if let Some(req) = inner.request.get_mut(request_id) {
            crate::domain::request::state_machine::ensure_valid_transition(&req.decision, &decision)?;
            req.decision = decision;
        }
        Ok(())
    }

    fn get_request(&self, request_id: &RequestId) -> Result<Option<SigningRequest>, ThresholdError> {
        Ok(self.lock_inner()?.request.get(request_id).cloned())
    }

    fn insert_proposal(&self, request_id: &RequestId, proposal: StoredProposal) -> Result<(), ThresholdError> {
        self.lock_inner()?.proposal.insert(request_id.clone(), proposal);
        Ok(())
    }

    fn get_proposal(&self, request_id: &RequestId) -> Result<Option<StoredProposal>, ThresholdError> {
        Ok(self.lock_inner()?.proposal.get(request_id).cloned())
    }

    fn insert_request_input(&self, request_id: &RequestId, input: RequestInput) -> Result<(), ThresholdError> {
        self.lock_inner()?.request_input.entry(request_id.clone()).or_default().push(input);
        Ok(())
    }

    fn list_request_inputs(&self, request_id: &RequestId) -> Result<Vec<RequestInput>, ThresholdError> {
        Ok(self.lock_inner()?.request_input.get(request_id).cloned().unwrap_or_default())
    }

    fn insert_signer_ack(&self, request_id: &RequestId, ack: SignerAckRecord) -> Result<(), ThresholdError> {
        self.lock_inner()?.signer_ack.entry(request_id.clone()).or_default().push(ack);
        Ok(())
    }

    fn list_signer_acks(&self, request_id: &RequestId) -> Result<Vec<SignerAckRecord>, ThresholdError> {
        Ok(self.lock_inner()?.signer_ack.get(request_id).cloned().unwrap_or_default())
    }

    fn insert_partial_sig(&self, request_id: &RequestId, sig: PartialSigRecord) -> Result<(), ThresholdError> {
        self.lock_inner()?.partial_sig.entry(request_id.clone()).or_default().push(sig);
        Ok(())
    }

    fn list_partial_sigs(&self, request_id: &RequestId) -> Result<Vec<PartialSigRecord>, ThresholdError> {
        Ok(self.lock_inner()?.partial_sig.get(request_id).cloned().unwrap_or_default())
    }

    fn update_request_final_tx(&self, request_id: &RequestId, final_tx_id: TransactionId) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;

        // Step 1: Update request and extract event_hash (borrow ends at block close)
        let event_hash = {
            let req = match inner.request.get_mut(request_id) {
                Some(req) if req.final_tx_id.is_none() => req,
                _ => return Ok(()),
            };
            crate::domain::request::state_machine::ensure_valid_transition(&req.decision, &RequestDecision::Finalized)?;
            req.final_tx_id = Some(final_tx_id);
            req.decision = RequestDecision::Finalized;
            req.event_hash // Copy out before borrow ends
        };

        // Step 2: Update volume (request borrow is now dropped)
        if let Some(event) = inner.event.get(&event_hash) {
            let day_start = day_start_nanos(event.timestamp_nanos);
            let amount = event.amount_sompi;
            inner.volume.entry(day_start).and_modify(|v| *v = v.saturating_add(amount)).or_insert(amount);
        }

        Ok(())
    }

    fn update_request_final_tx_score(&self, request_id: &RequestId, accepted_blue_score: u64) -> Result<(), ThresholdError> {
        if let Some(req) = self.lock_inner()?.request.get_mut(request_id) {
            req.final_tx_accepted_blue_score = Some(accepted_blue_score);
        }
        Ok(())
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
}

fn day_start_nanos(timestamp_nanos: u64) -> u64 {
    const NANOS_PER_DAY: u64 = 24 * 60 * 60 * 1_000_000_000u64;
    (timestamp_nanos / NANOS_PER_DAY) * NANOS_PER_DAY
}
