use crate::foundation::{EventId, ExternalId, PeerId, TransactionId, TxTemplateHash};
use kaspa_consensus_core::tx::ScriptPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Canonical external event - deterministic across all signers.
///
/// This struct must only contain externally-derived fields and must remain stable
/// (breaking changes require a new versioned encoding + schema).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Event {
    /// External identifier in canonical bytes (e.g. Hyperlane message_id).
    pub external_id: ExternalId,
    /// External source type + parameters.
    pub source: SourceType,
    /// Destination script (canonical bytes).
    pub destination: ScriptPublicKey,
    /// Amount in sompi.
    pub amount_sompi: u64,
}

/// Source type enum - append only.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    Hyperlane { origin_domain: u32 },
    LayerZero { src_eid: u32 },
    Api,
    Manual,
}

/// Stored event with local metadata for audit and re-verification.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredEvent {
    pub event: Event,
    /// Local receipt timestamp.
    pub received_at_nanos: u64,
    /// Original string forms and source-specific metadata for debugging/audit.
    pub audit: EventAuditData,
    /// Optional source signature/proof bytes (not part of canonical Event).
    pub proof: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventAuditData {
    pub external_id_raw: String,
    pub destination_raw: String,
    #[serde(default)]
    pub source_data: BTreeMap<String, String>,
}

/// Deterministic event payload shared via CRDT (no local timestamps).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrdtSigningMaterial {
    pub event: Event,
    pub audit: EventAuditData,
    pub proof: Option<Vec<u8>>,
}

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
pub struct PartialSigRecord {
    /// Who produced this signature (used for audit and duplicate suppression).
    pub signer_peer_id: PeerId,
    /// Which transaction input this signature applies to.
    pub input_index: u32,
    /// Signer public key bytes (canonical encoding is defined by PSKT layer).
    pub pubkey: Vec<u8>,
    /// Signature bytes for the corresponding input/pubkey.
    pub signature: Vec<u8>,
    /// Timestamp used for auditing and to support deterministic "last write wins" merging.
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
/// Key: (event_id, tx_template_hash).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StoredEventCrdt {
    /// The cross-chain event being processed.
    pub event_id: EventId,
    /// The specific transaction being signed (deterministically constructed).
    pub tx_template_hash: TxTemplateHash,
    /// The canonical event payload (for reference / mid-flight joiners).
    pub signing_material: Option<CrdtSigningMaterial>,
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

/// Signature record persisted as part of `StoredEventCrdt`.
///
/// This is separate from `PartialSigRecord` even though the fields overlap:
/// - The persisted CRDT schema must stay stable for storage compatibility.
/// - CRDT merge operations always require a `signer_peer_id` (no anonymous signatures).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CrdtSignatureRecord {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: PeerId,
    pub timestamp_nanos: u64,
}

/// Completion record persisted as part of `StoredEventCrdt`.
///
/// - `submitter_peer_id` is audit/debug metadata about who first submitted the transaction.
/// - `timestamp_nanos` is the CRDT LWW timestamp, used to converge if multiple completion
///   updates race (e.g. competing submissions or later `blue_score` updates).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredCompletionRecord {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub blue_score: Option<u64>,
}
