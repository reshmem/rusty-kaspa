use crate::domain::coordination::PhaseContext;
use crate::domain::{
    coordination::ProposalBroadcast, CrdtSignatureRecord, CrdtSigningMaterial, StoredCompletionRecord, StoredEventCrdt,
};
use crate::foundation::{EventId, GroupId, PayloadHash, PeerId, SessionId, TransactionId, TxTemplateHash};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MessageEnvelope {
    pub sender_peer_id: PeerId,
    pub group_id: GroupId,
    pub session_id: SessionId,
    pub seq_no: u64,
    pub timestamp_nanos: u64,
    pub payload: TransportMessage,
    pub payload_hash: PayloadHash,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TransportMessage {
    /// CRDT state broadcast - the main message type.
    EventStateBroadcast(EventStateBroadcast),
    /// Two-phase protocol proposal broadcast (non-signing).
    ProposalBroadcast(ProposalBroadcast),
    /// Anti-entropy sync request.
    StateSyncRequest(StateSyncRequest),
    /// Anti-entropy sync response.
    StateSyncResponse(StateSyncResponse),
}

/// CRDT-based event state broadcast.
/// Contains full state for an (event_id, tx_template_hash) pair - receivers merge with local state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventStateBroadcast {
    /// The cross-chain event being processed (for grouping/audit).
    pub event_id: EventId,
    /// The specific transaction being signed (for signature compatibility).
    pub tx_template_hash: TxTemplateHash,
    /// The CRDT state.
    pub state: EventCrdtState,
    /// Who sent this broadcast (redundant with envelope, but helpful for debug/audit).
    pub sender_peer_id: PeerId,
    /// Optional phase context for two-phase protocol (fast-forward support).
    #[serde(default)]
    pub phase_context: Option<PhaseContext>,
}

/// The actual CRDT state that gets merged.
/// Key: (event_id, tx_template_hash) - signatures only merge if both match.
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
    pub signing_material: Option<CrdtSigningMaterial>,
    /// The PSKT blob for the tx template (signer view).
    ///
    /// This can be large; transport enforces a global max message size.
    pub kpsbt_blob: Option<Vec<u8>>,
    /// Monotonic version for efficient sync.
    pub version: u64,
}

impl From<&StoredEventCrdt> for EventCrdtState {
    fn from(state: &StoredEventCrdt) -> Self {
        Self {
            signatures: state.signatures.iter().map(CrdtSignature::from).collect(),
            completion: state.completion.as_ref().map(CompletionRecord::from),
            signing_material: state.signing_material.clone(),
            kpsbt_blob: state.kpsbt_blob.clone(),
            version: state.updated_at_nanos,
        }
    }
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
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub blue_score: Option<u64>,
}

impl From<&StoredCompletionRecord> for CompletionRecord {
    fn from(value: &StoredCompletionRecord) -> Self {
        Self {
            tx_id: value.tx_id,
            submitter_peer_id: value.submitter_peer_id.clone(),
            timestamp_nanos: value.timestamp_nanos,
            blue_score: value.blue_score,
        }
    }
}

impl From<&CompletionRecord> for StoredCompletionRecord {
    fn from(value: &CompletionRecord) -> Self {
        Self {
            tx_id: value.tx_id,
            submitter_peer_id: value.submitter_peer_id.clone(),
            timestamp_nanos: value.timestamp_nanos,
            blue_score: value.blue_score,
        }
    }
}

impl From<&CrdtSignatureRecord> for CrdtSignature {
    fn from(value: &CrdtSignatureRecord) -> Self {
        Self {
            input_index: value.input_index,
            pubkey: value.pubkey.clone(),
            signature: value.signature.clone(),
            signer_peer_id: Some(value.signer_peer_id.clone()),
            timestamp_nanos: value.timestamp_nanos,
        }
    }
}

impl std::convert::TryFrom<&CrdtSignature> for CrdtSignatureRecord {
    type Error = crate::foundation::ThresholdError;

    fn try_from(value: &CrdtSignature) -> Result<Self, Self::Error> {
        let signer_peer_id = value.signer_peer_id.clone().ok_or_else(|| crate::foundation::ThresholdError::SerializationError {
            format: "crdt_signature".to_string(),
            details: format!("missing signer_peer_id input_index={}", value.input_index),
        })?;

        Ok(Self {
            input_index: value.input_index,
            pubkey: value.pubkey.clone(),
            signature: value.signature.clone(),
            signer_peer_id,
            timestamp_nanos: value.timestamp_nanos,
        })
    }
}

/// Request state for specific events (anti-entropy).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncRequest {
    pub event_ids: Vec<EventId>,
    pub requester_peer_id: PeerId,
}

/// Response with full CRDT states.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncResponse {
    pub states: Vec<(EventId, TxTemplateHash, EventCrdtState)>, // (event_id, tx_template_hash, state)
}
