//! Event-level CRDT state for signature collection.

use super::{LWWRegister, SignatureKey, SignatureRecord};
use crate::foundation::Hash32;
use crate::foundation::ThresholdError;
use hex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::CompletionInfo;

/// The main Event CRDT combining signature G-Set with completion LWW-Register.
/// Keyed by (event_id, tx_template_hash) - signatures only merge if both match.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EventCrdt {
    /// The cross-chain event being processed (for grouping/audit).
    pub event_id: Hash32,

    /// The specific transaction being signed (for signature compatibility).
    pub tx_template_hash: Hash32,

    /// G-Set of signatures keyed by (input_index, pubkey).
    signatures: HashMap<SignatureKey, SignatureRecord>,

    /// LWW-Register for completion status.
    completion: LWWRegister<CompletionInfo>,

    /// Monotonic version for efficient sync.
    version: u64,
}

impl EventCrdt {
    /// Create a new EventCrdt for the given (event_id, tx_template_hash) pair.
    pub fn new(event_id: Hash32, tx_template_hash: Hash32) -> Self {
        Self { event_id, tx_template_hash, signatures: HashMap::new(), completion: LWWRegister::new(), version: 0 }
    }

    /// Add a signature to the G-Set.
    /// Returns true if signature was newly added.
    pub fn add_signature(&mut self, record: SignatureRecord) -> bool {
        let key = SignatureKey::new(record.input_index, record.pubkey.clone());
        if let std::collections::hash_map::Entry::Vacant(entry) = self.signatures.entry(key) {
            entry.insert(record);
            self.version += 1;
            true
        } else {
            false
        }
    }

    /// Set completion status (LWW semantics).
    /// Returns true if status was updated.
    pub fn set_completed(&mut self, info: CompletionInfo, timestamp: u64) -> bool {
        if self.completion.set(info, timestamp) {
            self.version += 1;
            true
        } else {
            false
        }
    }

    /// Check if event is marked as completed.
    pub fn is_completed(&self) -> bool {
        self.completion.value().is_some()
    }

    /// Get completion info if available.
    pub fn completion(&self) -> Option<&CompletionInfo> {
        self.completion.value()
    }

    /// Get all signatures.
    pub fn signatures(&self) -> impl Iterator<Item = &SignatureRecord> {
        self.signatures.values()
    }

    /// Get signature count.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Check if we have threshold signatures for all inputs.
    pub fn has_threshold(&self, input_count: usize, required: usize) -> bool {
        if input_count == 0 || required == 0 {
            return false;
        }

        let mut per_input: HashMap<u32, HashSet<&[u8]>> = HashMap::new();
        for sig in self.signatures.values() {
            if (sig.input_index as usize) < input_count {
                per_input.entry(sig.input_index).or_default().insert(sig.pubkey.as_slice());
            }
        }

        (0..input_count as u32).all(|idx| per_input.get(&idx).is_some_and(|set| set.len() >= required))
    }

    /// Merge another EventCrdt into this one.
    /// CRITICAL: Only merges if BOTH event_id AND tx_template_hash match.
    /// Returns the number of changes made.
    pub fn merge(&mut self, other: &EventCrdt) -> usize {
        if self.event_id != other.event_id || self.tx_template_hash != other.tx_template_hash {
            return 0;
        }

        let mut changes = 0usize;
        for (key, record) in &other.signatures {
            if !self.signatures.contains_key(key) {
                self.signatures.insert(key.clone(), record.clone());
                changes += 1;
            }
        }

        if self.completion.merge(&other.completion) {
            changes += 1;
        }

        if changes > 0 {
            self.version += 1;
        }
        changes
    }

    /// Get current version (for sync optimization).
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Validate that the CRDT is self-consistent.
    pub fn validate(&self) -> Result<(), ThresholdError> {
        if self.event_id == [0u8; 32] {
            return Err(ThresholdError::SerializationError {
                format: "crdt".to_string(),
                details: format!("missing event_id, tx_template_hash={}", hex::encode(self.tx_template_hash)),
            });
        }
        if self.tx_template_hash == [0u8; 32] {
            return Err(ThresholdError::SerializationError {
                format: "crdt".to_string(),
                details: format!("missing tx_template_hash, event_id={}", hex::encode(self.event_id)),
            });
        }
        Ok(())
    }
}

/// Merge two event states, returning a new merged state.
pub fn merge_event_states(a: &EventCrdt, b: &EventCrdt) -> EventCrdt {
    let mut result = a.clone();
    result.merge(b);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{PeerId, TransactionId};

    fn make_sig(input_index: u32, pubkey: u8, sig: u8) -> SignatureRecord {
        SignatureRecord {
            input_index,
            pubkey: vec![pubkey],
            signature: vec![sig],
            signer_peer_id: Some(PeerId::from(format!("peer-{}", pubkey))),
            timestamp_nanos: 1000,
        }
    }

    const EVENT_HASH: Hash32 = [1u8; 32];
    const TX_HASH: Hash32 = [2u8; 32];
    const DIFFERENT_TX_HASH: Hash32 = [3u8; 32];

    #[test]
    fn test_add_signature() {
        let mut crdt = EventCrdt::new(EVENT_HASH, TX_HASH);

        assert!(crdt.add_signature(make_sig(0, 1, 10)));
        assert!(crdt.add_signature(make_sig(0, 2, 20)));
        assert!(!crdt.add_signature(make_sig(0, 1, 10)));

        assert_eq!(crdt.signature_count(), 2);
    }

    #[test]
    fn test_has_threshold() {
        let mut crdt = EventCrdt::new(EVENT_HASH, TX_HASH);

        let input_count = 2;
        let required = 2;

        crdt.add_signature(make_sig(0, 1, 10));
        crdt.add_signature(make_sig(0, 2, 20));

        assert!(!crdt.has_threshold(input_count, required));

        crdt.add_signature(make_sig(1, 1, 11));
        crdt.add_signature(make_sig(1, 2, 21));

        assert!(crdt.has_threshold(input_count, required));
    }

    #[test]
    fn test_merge_signatures_same_tx() {
        let mut a = EventCrdt::new(EVENT_HASH, TX_HASH);
        let mut b = EventCrdt::new(EVENT_HASH, TX_HASH);

        a.add_signature(make_sig(0, 1, 10));
        a.add_signature(make_sig(0, 2, 20));

        b.add_signature(make_sig(0, 2, 20));
        b.add_signature(make_sig(0, 3, 30));

        let changes = a.merge(&b);

        assert_eq!(changes, 1);
        assert_eq!(a.signature_count(), 3);
    }

    #[test]
    fn test_merge_different_tx_template_fails() {
        let mut a = EventCrdt::new(EVENT_HASH, TX_HASH);
        let mut b = EventCrdt::new(EVENT_HASH, DIFFERENT_TX_HASH);

        a.add_signature(make_sig(0, 1, 10));
        b.add_signature(make_sig(0, 2, 20));

        let changes = a.merge(&b);

        assert_eq!(changes, 0);
        assert_eq!(a.signature_count(), 1);
    }

    #[test]
    fn test_completion_lww() {
        let mut crdt = EventCrdt::new(EVENT_HASH, TX_HASH);

        let info1 = CompletionInfo {
            tx_id: TransactionId::from([1u8; 32]),
            submitter_peer_id: PeerId::from("peer1"),
            timestamp_nanos: 100,
            blue_score: Some(100),
        };

        let info2 = CompletionInfo {
            tx_id: TransactionId::from([2u8; 32]),
            submitter_peer_id: PeerId::from("peer2"),
            timestamp_nanos: 200,
            blue_score: Some(200),
        };

        assert!(crdt.set_completed(info1, 100));
        assert_eq!(crdt.completion().unwrap().submitter_peer_id.as_str(), "peer1");

        assert!(!crdt.set_completed(info2.clone(), 50));
        assert_eq!(crdt.completion().unwrap().submitter_peer_id.as_str(), "peer1");

        assert!(crdt.set_completed(info2, 200));
        assert_eq!(crdt.completion().unwrap().submitter_peer_id.as_str(), "peer2");
    }

    #[test]
    fn test_merge_is_commutative() {
        let mut a = EventCrdt::new(EVENT_HASH, TX_HASH);
        a.add_signature(make_sig(0, 1, 10));

        let mut b = EventCrdt::new(EVENT_HASH, TX_HASH);
        b.add_signature(make_sig(0, 2, 20));

        let ab = merge_event_states(&a, &b);
        let ba = merge_event_states(&b, &a);

        assert_eq!(ab.signature_count(), ba.signature_count());
    }
}
