use crate::foundation::{Hash32, PeerId, TransactionId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GroupConfig {
    pub network_id: u8,
    pub threshold_m: u16,
    pub threshold_n: u16,
    pub member_pubkeys: Vec<Vec<u8>>,
    pub fee_rate_sompi_per_gram: u64,
    pub finality_blue_score_threshold: u64,
    pub dust_threshold_sompi: u64,
    pub min_recipient_amount_sompi: u64,
    pub session_timeout_seconds: u64,
    pub group_metadata: GroupMetadata,
    pub policy: GroupPolicy,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GroupMetadata {
    pub creation_timestamp_nanos: u64,
    pub group_name: Option<String>,
    pub policy_version: u32,
    pub extra: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct GroupPolicy {
    pub allowed_destinations: Vec<String>,
    pub min_amount_sompi: Option<u64>,
    pub max_amount_sompi: Option<u64>,
    pub max_daily_volume_sompi: Option<u64>,
    pub require_reason: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningEvent {
    pub event_id: String,
    pub event_source: EventSource,
    pub derivation_path: String,
    pub derivation_index: Option<u32>,
    pub destination_address: String,
    pub amount_sompi: u64,
    pub metadata: BTreeMap<String, String>,
    pub timestamp_nanos: u64,
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EventSource {
    Hyperlane { domain: String, sender: String },
    LayerZero { endpoint: String, sender: String },
    Api { issuer: String },
    Manual { operator: String },
    Other { kind: String, payload: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PartialSigRecord {
    pub signer_peer_id: PeerId,
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_nanos: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePaymentMode {
    #[default]
    RecipientPays,
    SignersPay,
    Split {
        recipient_parts: u32,
        signer_parts: u32,
    },
}

/// CRDT state for an event/transaction pair - used in storage.
/// Key: (event_hash, tx_template_hash).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StoredEventCrdt {
    /// The cross-chain event being processed.
    pub event_hash: Hash32,
    /// The specific transaction being signed (deterministically constructed).
    pub tx_template_hash: Hash32,
    /// The original signing event (for reference).
    pub signing_event: Option<SigningEvent>,
    /// The KPSBT blob (for finalization).
    pub kpsbt_blob: Option<Vec<u8>>,
    /// G-Set of signatures (keyed by input_index + pubkey).
    pub signatures: Vec<CrdtSignatureRecord>,
    /// LWW-Register for completion status.
    pub completion: Option<StoredCompletionRecord>,
    /// When this CRDT was first created locally.
    pub created_at_nanos: u64,
    /// When this CRDT was last updated.
    pub updated_at_nanos: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CrdtSignatureRecord {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: PeerId,
    pub timestamp_nanos: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredCompletionRecord {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub blue_score: Option<u64>,
}
