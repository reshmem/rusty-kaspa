use crate::domain::SigningEvent;
use crate::foundation::{Hash32, PeerId, SessionId};
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
    /// CRDT state broadcast - the main message type.
    EventStateBroadcast(EventStateBroadcast),
    /// Anti-entropy sync request.
    StateSyncRequest(StateSyncRequest),
    /// Anti-entropy sync response.
    StateSyncResponse(StateSyncResponse),
}

/// CRDT-based event state broadcast.
/// Contains full state for an (event_hash, tx_template_hash) pair - receivers merge with local state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventStateBroadcast {
    /// The cross-chain event being processed (for grouping/audit).
    pub event_hash: Hash32,
    /// The specific transaction being signed (for signature compatibility).
    pub tx_template_hash: Hash32,
    /// The CRDT state.
    pub state: EventCrdtState,
    /// Who sent this broadcast (redundant with envelope, but helpful for debug/audit).
    pub sender_peer_id: PeerId,
}

/// The actual CRDT state that gets merged.
/// Key: (event_hash, tx_template_hash) - signatures only merge if both match.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventCrdtState {
    /// G-Set of signatures, keyed by (input_index, pubkey).
    pub signatures: Vec<CrdtSignature>,
    /// LWW-Register for completion status.
    pub completion: Option<CompletionRecord>,
    /// The canonical signing event used to build/validate the tx template.
    ///
    /// Leaderless requirement: any signer must be able to join mid-flight and sign the
    /// already-selected tx template without reconstructing it locally.
    pub signing_event: Option<SigningEvent>,
    /// The PSKT blob for the tx template (signer view).
    ///
    /// This can be large; transport enforces a global max message size.
    pub kpsbt_blob: Option<Vec<u8>>,
    /// Monotonic version for efficient sync.
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct CrdtSignature {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: Option<PeerId>,
    pub timestamp_nanos: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletionRecord {
    pub tx_id: Hash32,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub blue_score: Option<u64>,
}

/// Request state for specific events (anti-entropy).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncRequest {
    pub event_hashes: Vec<Hash32>,
    pub requester_peer_id: PeerId,
}

/// Response with full CRDT states.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncResponse {
    pub states: Vec<(Hash32, Hash32, EventCrdtState)>, // (event_hash, tx_template_hash, state)
}
