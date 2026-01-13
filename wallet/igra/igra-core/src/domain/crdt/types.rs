//! CRDT-specific types used across the module.

use crate::foundation::PeerId;
use serde::{Deserialize, Serialize};

/// Unique identifier for a signature within a CRDT.
///
/// Key: (input_index, pubkey) - one signature per signer per input.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SignatureKey {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
}

impl SignatureKey {
    pub fn new(input_index: u32, pubkey: Vec<u8>) -> Self {
        Self { input_index, pubkey }
    }
}

/// A signature record stored in the in-memory CRDT G-Set.
///
/// This type is optimized for CRDT merging and uses `Option<PeerId>` for protocol compatibility
/// (older/partial broadcasts may omit the peer id). Persisted CRDT state uses
/// `crate::domain::CrdtSignatureRecord`, which always requires a `signer_peer_id`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SignatureRecord {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: Option<PeerId>,
    pub timestamp_nanos: u64,
}

/// Completion info stored in the CRDT LWW-register.
///
/// This is intentionally the same schema as the persisted completion record so the value can be
/// round-tripped without conversions.
pub type CompletionInfo = crate::domain::model::StoredCompletionRecord;
