use super::batch::RocksBatch;
use super::RocksStorage;
use crate::domain::{CrdtSignatureRecord, CrdtSigningMaterial, GroupConfig, StoredCompletionRecord, StoredEvent, StoredEventCrdt};
use crate::foundation::{EventId, ExternalId, GroupId, PeerId, SessionId, ThresholdError, TransactionId, TxTemplateHash};
use crate::infrastructure::storage::hyperlane::{HyperlaneDeliveredMessage, HyperlaneDeliveryRecord, HyperlaneMessageRecord};
use crate::infrastructure::storage::rocks::schema::*;
use crate::infrastructure::storage::rocks::util::acquire_with_timeout;
use crate::infrastructure::storage::{BatchTransaction, CrdtStorageStats, Storage};
use crate::infrastructure::transport::messages::{CompletionRecord, EventCrdtState};
use crate::storage_err;
use log::{debug, trace, warn};
use rocksdb::{Direction, IteratorMode, WriteBatch};
use std::collections::{HashMap, HashSet};

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
        let _guard = acquire_with_timeout(&self.crdt_lock, "rocks crdt lock")?;

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
        let _guard = acquire_with_timeout(&self.crdt_lock, "rocks crdt lock")?;

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
        let _guard = acquire_with_timeout(&self.crdt_lock, "rocks crdt lock")?;

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
        let _guard = acquire_with_timeout(&self.hyperlane_lock, "rocks hyperlane lock")?;

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
