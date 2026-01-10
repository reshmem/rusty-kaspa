pub use crate::domain::signing::PartialSigSubmit;
use crate::domain::SigningEvent;
use crate::foundation::{Hash32, PeerId, RequestId, SessionId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageEnvelope {
    pub sender_peer_id: PeerId,
    pub group_id: Hash32,
    pub session_id: SessionId,
    pub seq_no: u64,
    pub timestamp_nanos: u64,
    pub payload: TransportMessage,
    pub payload_hash: Hash32,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TransportMessage {
    SigningEventPropose(SigningEventPropose),
    SignerAck(SignerAck),
    PartialSigSubmit(PartialSigSubmit),
    FinalizeNotice(FinalizeNotice),
    FinalizeAck(FinalizeAck),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningEventPropose {
    pub request_id: RequestId,
    pub event_hash: Hash32,
    pub validation_hash: Hash32,
    pub coordinator_peer_id: PeerId,
    pub expires_at_nanos: u64,
    pub signing_event: SigningEvent,
    pub kpsbt_blob: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerAck {
    pub request_id: RequestId,
    pub event_hash: Hash32,
    pub validation_hash: Hash32,
    pub accept: bool,
    pub reason: Option<String>,
    pub signer_peer_id: PeerId,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalizeNotice {
    pub request_id: RequestId,
    pub final_tx_id: Hash32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalizeAck {
    pub request_id: RequestId,
    pub final_tx_id: Hash32,
    pub accept: bool,
    pub reason: Option<String>,
    pub signer_peer_id: PeerId,
}
