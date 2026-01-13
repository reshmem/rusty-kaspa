use crate::domain::{GroupConfig, SigningEvent, StoredEventCrdt};
use crate::foundation::ThresholdError;
use crate::foundation::{Hash32, PeerId, SessionId, TransactionId};
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
    fn upsert_group_config(&self, group_id: Hash32, config: GroupConfig) -> Result<()>;
    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>>;

    fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<()>;
    fn get_event(&self, event_hash: &Hash32) -> Result<Option<SigningEvent>>;

    fn get_event_crdt(&self, event_hash: &Hash32, tx_template_hash: &Hash32) -> Result<Option<StoredEventCrdt>>;

    fn merge_event_crdt(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        incoming: &EventCrdtState,
        signing_event: Option<&SigningEvent>,
        kpsbt_blob: Option<&[u8]>,
    ) -> Result<(StoredEventCrdt, bool)>;

    fn add_signature_to_crdt(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        input_index: u32,
        pubkey: &[u8],
        signature: &[u8],
        signer_peer_id: &PeerId,
        timestamp_nanos: u64,
    ) -> Result<(StoredEventCrdt, bool)>;

    fn mark_crdt_completed(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        tx_id: TransactionId,
        submitter_peer_id: &PeerId,
        timestamp_nanos: u64,
        blue_score: Option<u64>,
    ) -> Result<(StoredEventCrdt, bool)>;

    fn crdt_has_threshold(&self, event_hash: &Hash32, tx_template_hash: &Hash32, input_count: usize, required: usize) -> Result<bool>;

    fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>>;

    fn list_event_crdts_for_event(&self, event_hash: &Hash32) -> Result<Vec<StoredEventCrdt>>;

    fn crdt_storage_stats(&self) -> Result<CrdtStorageStats>;

    fn cleanup_completed_event_crdts(&self, older_than_nanos: u64) -> Result<usize>;

    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64>;

    fn begin_batch(&self) -> Result<Box<dyn BatchTransaction + '_>>;

    fn health_check(&self) -> Result<()> {
        Ok(())
    }

    fn mark_seen_message(&self, sender_peer_id: &PeerId, session_id: &SessionId, seq_no: u64, timestamp_nanos: u64) -> Result<bool>;

    fn cleanup_seen_messages(&self, older_than_nanos: u64) -> Result<usize>;
}

pub trait BatchTransaction {
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&mut self, key: &[u8]) -> Result<()>;
    fn commit(self: Box<Self>) -> Result<()>;
    fn rollback(self: Box<Self>);
}
