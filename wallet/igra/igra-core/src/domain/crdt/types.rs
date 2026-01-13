//! CRDT-specific types used across the module.

use crate::foundation::{PeerId, TransactionId};
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

/// A signature record stored in the CRDT G-Set.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SignatureRecord {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: Option<PeerId>,
    pub timestamp_nanos: u64,
}

/// Completion record for LWW-Register (who submitted the transaction).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletionInfo {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub blue_score: Option<u64>,
}

