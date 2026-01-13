use crate::domain::pskt::multisig as pskt_multisig;
use crate::domain::{CrdtSignatureRecord, CrdtSigningMaterial, GroupConfig, StoredCompletionRecord, StoredEvent, StoredEventCrdt};
use crate::foundation::ThresholdError;
use crate::foundation::{day_start_nanos, now_nanos};
use crate::foundation::{Hash32, PeerId, SessionId, TransactionId};
use crate::infrastructure::storage::{BatchTransaction, CrdtStorageStats, Storage};
use crate::infrastructure::transport::messages::{CompletionRecord, CrdtSignature, EventCrdtState};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

struct MemoryInner {
    group: HashMap<Hash32, GroupConfig>,
    event: HashMap<Hash32, StoredEvent>,
    event_active_template: HashMap<Hash32, Hash32>,
    event_completion: HashMap<Hash32, StoredCompletionRecord>,
    event_crdt: HashMap<(Hash32, Hash32), StoredEventCrdt>,
    volume: HashMap<u64, u64>,
    seen: HashMap<(PeerId, SessionId, u64), u64>,
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
    fn upsert_group_config(&self, group_id: Hash32, config: GroupConfig) -> Result<(), ThresholdError> {
        self.lock_inner()?.group.insert(group_id, config);
        Ok(())
    }

    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>, ThresholdError> {
        Ok(self.lock_inner()?.group.get(group_id).cloned())
    }

    fn insert_event(&self, event_id: Hash32, event: StoredEvent) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        inner.event.entry(event_id).or_insert(event);
        Ok(())
    }

    fn insert_event_if_not_exists(&self, event_id: Hash32, event: StoredEvent) -> Result<bool, ThresholdError> {
        let mut inner = self.lock_inner()?;
        if inner.event.contains_key(&event_id) {
            return Ok(false);
        }
        inner.event.insert(event_id, event);
        Ok(true)
    }

    fn get_event(&self, event_id: &Hash32) -> Result<Option<StoredEvent>, ThresholdError> {
        Ok(self.lock_inner()?.event.get(event_id).cloned())
    }

    fn get_event_active_template_hash(&self, event_id: &Hash32) -> Result<Option<Hash32>, ThresholdError> {
        Ok(self.lock_inner()?.event_active_template.get(event_id).copied())
    }

    fn set_event_active_template_hash(&self, event_id: &Hash32, tx_template_hash: &Hash32) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        if let Some(existing) = inner.event_active_template.get(event_id) {
            if existing != tx_template_hash {
                return Err(ThresholdError::PsktMismatch { expected: hex::encode(existing), actual: hex::encode(tx_template_hash) });
            }
            return Ok(());
        }
        inner.event_active_template.insert(*event_id, *tx_template_hash);
        Ok(())
    }

    fn get_event_completion(&self, event_id: &Hash32) -> Result<Option<StoredCompletionRecord>, ThresholdError> {
        Ok(self.lock_inner()?.event_completion.get(event_id).cloned())
    }

    fn set_event_completion(&self, event_id: &Hash32, completion: &StoredCompletionRecord) -> Result<(), ThresholdError> {
        let mut inner = self.lock_inner()?;
        inner.event_completion.insert(*event_id, completion.clone());
        Ok(())
    }

    fn get_event_crdt(&self, event_id: &Hash32, tx_template_hash: &Hash32) -> Result<Option<StoredEventCrdt>, ThresholdError> {
        Ok(self.lock_inner()?.event_crdt.get(&(*event_id, *tx_template_hash)).cloned())
    }

    fn merge_event_crdt(
        &self,
        event_id: &Hash32,
        tx_template_hash: &Hash32,
        incoming: &EventCrdtState,
        signing_material: Option<&CrdtSigningMaterial>,
        kpsbt_blob: Option<&[u8]>,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let mut inner = self.lock_inner()?;
        let now_nanos = now_nanos();
        let key = (*event_id, *tx_template_hash);
        let mut should_lock_active_template = false;

        if let Some(existing) = inner.event_active_template.get(event_id) {
            if existing != tx_template_hash {
                return Err(ThresholdError::PsktMismatch { expected: hex::encode(existing), actual: hex::encode(tx_template_hash) });
            }
        }

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
                    crate::domain::normalization::validate_source_data(&ev.audit.source_data)?;
                    let computed_event_id = crate::domain::hashes::compute_event_id(&ev.event);
                    if computed_event_id == *event_id {
                        local.signing_material = Some(ev.clone());
                        changed = true;
                    }
                }
            }

            if local.kpsbt_blob.is_none() {
                if let Some(blob) = kpsbt_blob {
                    let signer_pskt = pskt_multisig::deserialize_pskt_signer(blob)?;
                    let computed_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;
                    if computed_hash == *tx_template_hash {
                        should_lock_active_template = true;
                        local.kpsbt_blob = Some(blob.to_vec());
                        changed = true;
                    }
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

        if should_lock_active_template {
            inner.event_active_template.insert(*event_id, *tx_template_hash);
        }

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
        event_id: &Hash32,
        tx_template_hash: &Hash32,
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
        event_id: &Hash32,
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
            signing_material: None,
            kpsbt_blob: None,
            version: 0,
        };
        let (state, changed) = self.merge_event_crdt(event_id, tx_template_hash, &incoming, None, None)?;
        Ok((state, changed))
    }

    fn crdt_has_threshold(
        &self,
        event_id: &Hash32,
        tx_template_hash: &Hash32,
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

        Ok((0..input_count as u32).all(|idx| per_input.get(&idx).map_or(false, |set| set.len() >= required)))
    }

    fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        Ok(self.lock_inner()?.event_crdt.values().filter(|s| s.completion.is_none()).cloned().collect())
    }

    fn list_event_crdts_for_event(&self, event_id: &Hash32) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
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
}

// Time helpers are in `foundation::util::time`.
