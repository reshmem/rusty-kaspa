use crate::foundation::ThresholdError;
use crate::domain::{
    GroupConfig, PartialSigRecord, RequestDecision, RequestInput, SignerAckRecord, SigningEvent, SigningRequest, StoredProposal,
};
use crate::foundation::{Hash32, PeerId, RequestId, SessionId, TransactionId};

pub type Result<T> = std::result::Result<T, ThresholdError>;

pub trait Storage: Send + Sync {
    fn upsert_group_config(&self, group_id: Hash32, config: GroupConfig) -> Result<()>;
    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>>;

    fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<()>;
    fn get_event(&self, event_hash: &Hash32) -> Result<Option<SigningEvent>>;

    fn insert_request(&self, request: SigningRequest) -> Result<()>;
    fn update_request_decision(&self, request_id: &RequestId, decision: RequestDecision) -> Result<()>;
    fn get_request(&self, request_id: &RequestId) -> Result<Option<SigningRequest>>;

    fn insert_proposal(&self, request_id: &RequestId, proposal: StoredProposal) -> Result<()>;
    fn get_proposal(&self, request_id: &RequestId) -> Result<Option<StoredProposal>>;

    fn insert_request_input(&self, request_id: &RequestId, input: RequestInput) -> Result<()>;
    fn list_request_inputs(&self, request_id: &RequestId) -> Result<Vec<RequestInput>>;

    fn insert_signer_ack(&self, request_id: &RequestId, ack: SignerAckRecord) -> Result<()>;
    fn list_signer_acks(&self, request_id: &RequestId) -> Result<Vec<SignerAckRecord>>;

    fn insert_partial_sig(&self, request_id: &RequestId, sig: PartialSigRecord) -> Result<()>;
    fn list_partial_sigs(&self, request_id: &RequestId) -> Result<Vec<PartialSigRecord>>;

    fn update_request_final_tx(&self, request_id: &RequestId, final_tx_id: TransactionId) -> Result<()>;
    fn update_request_final_tx_score(&self, request_id: &RequestId, accepted_blue_score: u64) -> Result<()>;

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
