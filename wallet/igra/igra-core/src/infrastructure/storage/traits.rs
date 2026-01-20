use crate::domain::{CrdtSigningMaterial, GroupConfig, StoredCompletionRecord, StoredEvent, StoredEventCrdt};
use crate::foundation::ThresholdError;
use crate::foundation::{EventId, ExternalId, GroupId, PeerId, SessionId, TransactionId, TxTemplateHash};
use crate::infrastructure::storage::hyperlane::{HyperlaneDeliveredMessage, HyperlaneDeliveryRecord, HyperlaneMessageRecord};
use crate::infrastructure::transport::messages::EventCrdtState;

pub type Result<T> = std::result::Result<T, ThresholdError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CrdtStorageStats {
    pub total_event_crdts: u64,
    pub pending_event_crdts: u64,
    pub completed_event_crdts: u64,
    pub cf_estimated_num_keys: Option<u64>,
    pub cf_estimated_live_data_size_bytes: Option<u64>,
}

pub trait Storage: Send + Sync {
    fn upsert_group_config(&self, group_id: GroupId, config: GroupConfig) -> Result<()>;
    fn get_group_config(&self, group_id: &GroupId) -> Result<Option<GroupConfig>>;

    fn insert_event(&self, event_id: EventId, event: StoredEvent) -> Result<()>;
    fn get_event(&self, event_id: &EventId) -> Result<Option<StoredEvent>>;

    /// Insert event only if it doesn't already exist.
    /// Returns `Ok(true)` if inserted, `Ok(false)` if it already existed.
    fn insert_event_if_not_exists(&self, event_id: EventId, event: StoredEvent) -> Result<bool> {
        if self.get_event(&event_id)?.is_some() {
            return Ok(false);
        }
        self.insert_event(event_id, event)?;
        Ok(true)
    }

    /// Fast-path index: for a given event_id, which tx template hash is active.
    fn get_event_active_template_hash(&self, event_id: &EventId) -> Result<Option<TxTemplateHash>>;
    fn set_event_active_template_hash(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash) -> Result<()>;

    /// Fast-path index: completion status keyed by event_id.
    fn get_event_completion(&self, event_id: &EventId) -> Result<Option<StoredCompletionRecord>>;
    fn set_event_completion(&self, event_id: &EventId, completion: &StoredCompletionRecord) -> Result<()>;

    fn get_event_crdt(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash) -> Result<Option<StoredEventCrdt>>;

    fn merge_event_crdt(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        incoming: &EventCrdtState,
        signing_material: Option<&CrdtSigningMaterial>,
        kpsbt_blob: Option<&[u8]>,
    ) -> Result<(StoredEventCrdt, bool)>;

    fn add_signature_to_crdt(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        input_index: u32,
        pubkey: &[u8],
        signature: &[u8],
        signer_peer_id: &PeerId,
        timestamp_nanos: u64,
    ) -> Result<(StoredEventCrdt, bool)>;

    fn mark_crdt_completed(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        tx_id: TransactionId,
        submitter_peer_id: &PeerId,
        timestamp_nanos: u64,
        blue_score: Option<u64>,
    ) -> Result<(StoredEventCrdt, bool)>;

    fn crdt_has_threshold(
        &self,
        event_id: &EventId,
        tx_template_hash: &TxTemplateHash,
        input_count: usize,
        required: usize,
    ) -> Result<bool>;

    fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>>;

    fn list_event_crdts_for_event(&self, event_id: &EventId) -> Result<Vec<StoredEventCrdt>>;

    fn crdt_storage_stats(&self) -> Result<CrdtStorageStats>;

    fn cleanup_completed_event_crdts(&self, older_than_nanos: u64) -> Result<usize>;

    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64>;

    fn begin_batch(&self) -> Result<Box<dyn BatchTransaction + '_>>;

    fn health_check(&self) -> Result<()> {
        Ok(())
    }

    fn mark_seen_message(&self, sender_peer_id: &PeerId, session_id: &SessionId, seq_no: u64, timestamp_nanos: u64) -> Result<bool>;

    fn cleanup_seen_messages(&self, older_than_nanos: u64) -> Result<usize>;

    // =====================================================================
    // Hyperlane indexing (for hyperlane-kaspa destination integration)
    // =====================================================================
    fn hyperlane_get_delivered_count(&self) -> Result<u32>;
    fn hyperlane_is_message_delivered(&self, message_id: &ExternalId) -> Result<bool>;
    fn hyperlane_get_delivery(&self, message_id: &ExternalId) -> Result<Option<HyperlaneDeliveryRecord>>;
    fn hyperlane_get_deliveries_in_range(&self, from_daa_score: u64, to_daa_score: u64) -> Result<Vec<HyperlaneDeliveryRecord>>;
    fn hyperlane_get_messages_in_range(&self, from_daa_score: u64, to_daa_score: u64) -> Result<Vec<HyperlaneMessageRecord>>;
    fn hyperlane_get_latest_delivery_daa_score(&self) -> Result<Option<u64>>;
    /// Returns `Ok(true)` if the delivery was newly inserted, `Ok(false)` if it already existed.
    fn hyperlane_mark_delivered(&self, delivered: &HyperlaneDeliveredMessage) -> Result<bool>;
}

pub trait BatchTransaction {
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&mut self, key: &[u8]) -> Result<()>;
    fn commit(self: Box<Self>) -> Result<()>;
    fn rollback(self: Box<Self>);
}
