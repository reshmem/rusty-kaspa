# CRDT-Based Coordination: Implementation Guide for Developers

## Table of Contents

1. [Overview](#1-overview)
2. [Understanding CRDTs](#2-understanding-crdts)
3. [Current Architecture vs CRDT Architecture](#3-current-architecture-vs-crdt-architecture)
4. [Architecture & File Organization](#4-architecture--file-organization)
5. [Domain Layer](#5-domain-layer) - `igra-core/src/domain/crdt/`
6. [Infrastructure Layer](#6-infrastructure-layer) - `igra-core/src/infrastructure/`
7. [Application Layer](#7-application-layer) - `igra-core/src/application/`
8. [Service Layer](#8-service-layer) - `igra-service/src/service/`
9. [Tests](#9-tests) - Unit, Integration, E2E
10. [Verification Checklist](#10-verification-checklist)
11. [Implementation Plan](#11-implementation-plan)

---

## 1. Overview

### What We're Building

We're replacing the current proposal-ack-based coordination with a CRDT (Conflict-free Replicated Data Type) based system. This eliminates:
- **Proposals** (unnecessary - event is the input)
- **Acknowledgments** (unnecessary - signing is the ack)
- **Coordinator election** (unnecessary - all signers are coordinators)

### Why CRDTs?

Our system has these properties that make CRDTs ideal:
1. **Same input** → All signers receive the same Hyperlane event
2. **Deterministic processing** → Same event produces same signature
3. **Idempotent output** → UTXO model prevents double-spend

CRDTs give us:
- **Eventual consistency** without coordination
- **Partition tolerance** - signers can be offline
- **Minimal messages** - O(N) instead of O(N²)

### Key Insight

```
Current:  Event → Propose → Ack → Sign → Submit → Finalize
CRDT:     Event → Sign → Gossip → Submit (when threshold)
```

---

## 2. Understanding CRDTs

### G-Set (Grow-only Set)

A G-Set is the simplest CRDT. Elements can only be added, never removed.

```rust
// Pseudo-code for G-Set
struct GSet<T> {
    elements: HashSet<T>,
}

impl<T> GSet<T> {
    fn add(&mut self, element: T) {
        self.elements.insert(element);
    }

    // The merge operation is union
    fn merge(&mut self, other: &GSet<T>) {
        self.elements = self.elements.union(&other.elements).collect();
    }
}
```

**Mathematical Properties:**
- **Commutative**: A ∪ B = B ∪ A (order doesn't matter)
- **Associative**: (A ∪ B) ∪ C = A ∪ (B ∪ C) (grouping doesn't matter)
- **Idempotent**: A ∪ A = A (applying same data twice is safe)

### Why Signatures Form a G-Set

Each signature is uniquely identified by `(event_hash, tx_template_hash, input_index, signer_pubkey)`:
- `event_hash` - The cross-chain event being processed (for grouping/audit)
- `tx_template_hash` - The specific Kaspa transaction structure (for signature compatibility)
- `input_index` - Which input of the transaction
- `signer_pubkey` - Which signer produced this signature

Properties:
- Once created, a signature is immutable
- Same signer + same input + same tx_template = same signature (deterministic)
- Adding the same signature twice changes nothing (idempotent)

**Critical**: Signatures are only compatible if they share the same `tx_template_hash`. This is ensured by deterministic KPSBT construction (see Section 3.1).

### LWW-Register (Last-Writer-Wins Register)

For tracking completion status (which signer submitted the TX):

```rust
struct LWWRegister<T> {
    value: T,
    timestamp: u64,
}

impl<T> LWWRegister<T> {
    fn set(&mut self, value: T, timestamp: u64) {
        if timestamp > self.timestamp {
            self.value = value;
            self.timestamp = timestamp;
        }
    }

    fn merge(&mut self, other: &LWWRegister<T>) {
        if other.timestamp > self.timestamp {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
        }
    }
}
```

---

## 3. Current Architecture vs CRDT Architecture

### Current Message Flow (O(N²))

```
Signer1 receives event from local Hyperlane
    │
    ├─► Creates proposal, publishes to iroh topic
    │
    ├─► All N signers receive proposal
    │   └─► Each sends SignerAck (N messages)
    │
    ├─► Signer1 waits for M acks
    │
    ├─► All signers sign and send PartialSigSubmit
    │   └─► N messages to session topic
    │
    ├─► First to reach M sigs submits TX
    │
    └─► Sends FinalizeNotice (N messages)
        └─► Each responds FinalizeAck (N messages)

Total: ~4N messages minimum
```

### CRDT Message Flow (O(N))

```
Each Signer receives event from local Hyperlane
    │
    ├─► Computes event_hash (deterministic - same for all)
    │
    ├─► Builds KPSBT deterministically (same for all - see 3.1)
    │   └─► Computes tx_template_hash
    │
    ├─► Signs immediately (no proposal needed)
    │
    ├─► Publishes EventState CRDT to topic
    │   └─► Contains: event_hash, tx_template_hash, signatures
    │
    ├─► Receives EventState from other signers
    │   └─► Merges into local CRDT (union of signatures with same tx_template_hash)
    │
    ├─► When local CRDT has M signatures per input:
    │   └─► Submits TX to local Kaspa node
    │       └─► First submission wins (UTXO model)
    │
    └─► Broadcasts completion status (optional, for audit)

Total: N messages (each signer broadcasts once)
```

### 3.1 Deterministic KPSBT Construction

**Critical Insight**: For signatures to be compatible, all signers must construct the **exact same transaction**. This is achieved through deterministic KPSBT construction.

#### Why It Works

All signers have:
1. **Same event** - From Hyperlane (event_hash is deterministic)
2. **Same UTXO view** - Their local Kaspa node sees the same multisig address UTXOs
3. **Same algorithm** - Deterministic selection and construction

#### Deterministic UTXO Selection

UTXOs are already sorted deterministically in the codebase. The algorithm:

```rust
fn select_utxos_deterministic(
    multisig_address: &Address,
    amount_needed: u64,
    fee_rate: u64,
) -> Result<Vec<Utxo>, Error> {
    // 1. Query UTXOs for multisig address from local Kaspa node
    let mut utxos = rpc.get_utxos_by_address(multisig_address)?;

    // 2. Sort deterministically by (txid, output_index)
    utxos.sort_by(|a, b| {
        match a.outpoint.txid.cmp(&b.outpoint.txid) {
            std::cmp::Ordering::Equal => a.outpoint.index.cmp(&b.outpoint.index),
            other => other,
        }
    });

    // 3. Greedy selection until amount + fee covered
    let mut selected = Vec::new();
    let mut total = 0u64;

    for utxo in utxos {
        selected.push(utxo);
        total += utxo.value;

        let estimated_fee = estimate_fee(selected.len(), 2, fee_rate); // 2 outputs typical
        if total >= amount_needed + estimated_fee {
            break;
        }
    }

    Ok(selected)
}
```

#### Deterministic Transaction Construction

| Component | How It's Deterministic |
|-----------|----------------------|
| **Inputs** | Sorted UTXOs, greedy selection |
| **Output (recipient)** | From event's `destination_address` |
| **Output (change)** | Derived from event's `derivation_path` |
| **Output ordering** | Lexicographic by script (BIP69 style) |
| **Fee rate** | From shared config (`fee_rate_sompi_per_gram`) |
| **Lock time** | 0 (standard) |

#### Edge Case: Node Out of Sync

If one signer's Kaspa node is behind:
- They see stale/different UTXOs
- They construct different `tx_template_hash`
- Their signatures **don't merge** with others (different key)
- **No harm**: Other M signers (synced) still reach threshold
- The out-of-sync signer's work is orphaned but system proceeds

```
Signer1 (synced):     tx_template_hash = 0xAAA...  ─┐
Signer2 (synced):     tx_template_hash = 0xAAA...  ─┼─► Signatures merge, threshold reached
Signer3 (synced):     tx_template_hash = 0xAAA...  ─┘
Signer4 (out of sync): tx_template_hash = 0xBBB... ─► Orphaned (different tx), no harm
```

#### Verification

Each signer can verify they constructed the same transaction:

```rust
fn verify_same_transaction(local_kpsbt: &Pskt, received_state: &EventState) -> bool {
    let local_hash = tx_template_hash(local_kpsbt);
    local_hash == received_state.tx_template_hash
}
```

If hashes don't match, the signer knows something is wrong (likely sync issue) and can:
1. Wait and retry after syncing
2. Log warning for investigation
3. Still participate if they eventually sync

### Current vs CRDT: Message Types

| Current | CRDT Replacement | Notes |
|---------|-----------------|-------|
| `SigningEventPropose` | **Removed** | Event is the proposal |
| `SignerAck` | **Removed** | Signing IS the ack |
| `PartialSigSubmit` | `EventState` | Contains all signatures |
| `FinalizeNotice` | `EventState` | completion field |
| `FinalizeAck` | **Removed** | Unnecessary |

---

## 4. Architecture & File Organization

### 4.1 Layer Responsibilities

Following the existing architecture pattern:

| Layer | Location | Responsibility |
|-------|----------|----------------|
| **Foundation** | `igra-core/src/foundation/` | Basic types (Hash32, PeerId, etc.) |
| **Domain** | `igra-core/src/domain/` | Pure business logic, no I/O |
| **Infrastructure** | `igra-core/src/infrastructure/` | Storage, transport, config |
| **Application** | `igra-core/src/application/` | Orchestration across domain+infra |
| **Service** | `igra-service/src/service/` | Service-specific coordination |

### 4.2 New Files to Create

```
igra-core/
├── src/
│   ├── domain/
│   │   └── crdt/                    # NEW MODULE
│   │       ├── mod.rs               # Module exports
│   │       ├── gset.rs              # G-Set implementation
│   │       ├── lww.rs               # LWW-Register implementation
│   │       ├── event_state.rs       # EventCrdt combining both
│   │       └── types.rs             # CRDT-specific types
│   ├── application/
│   │   └── crdt_coordinator.rs      # NEW: CRDT event orchestration
│   └── infrastructure/
│       ├── storage/rocks/
│       │   ├── engine.rs            # MODIFY: Add CRDT storage methods
│       │   └── schema.rs            # MODIFY: Add CF_EVENT_CRDT
│       └── transport/iroh/
│           └── messages.rs          # MODIFY: Add CRDT message types
├── tests/
│   ├── unit/
│   │   └── domain_crdt.rs           # NEW: Unit tests for domain/crdt
│   └── integration/
│       └── crdt_storage.rs          # NEW: Storage integration tests

igra-service/
├── src/service/coordination/
│   ├── mod.rs                       # MODIFY: Export crdt_handler
│   └── crdt_handler.rs              # NEW: Wire CRDT into coordination loop
└── tests/integration/
    ├── crdt_e2e.rs                  # NEW: End-to-end CRDT tests
    └── crdt_partition.rs            # NEW: Network partition tests
```

### 4.3 Implementation Phases

**Phase 1: Domain Layer**
1. Create `igra-core/src/domain/crdt/` module
2. Implement pure CRDT types (no I/O dependencies)
3. Add unit tests: `igra-core/tests/unit/domain_crdt.rs`

**Phase 2: Infrastructure Layer**
1. Update `messages.rs` - Add CRDT message types
2. Update `schema.rs` - Add `CF_EVENT_CRDT` column family
3. Update `engine.rs` - Add CRDT storage methods
4. Add integration tests: `igra-core/tests/integration/crdt_storage.rs`

**Phase 3: Application Layer**
1. Create `crdt_coordinator.rs` - Orchestration logic
2. Wire into existing `event_processor.rs` or `coordinator.rs`

**Phase 4: Service Layer**
1. Create `crdt_handler.rs` in `igra-service`
2. Replace `coordination/loop.rs` with CRDT-based loop
3. Delete old coordination files (see Section 6.6)

**Phase 5: Testing & Deploy**
1. E2E tests: `igra-service/tests/integration/crdt_e2e.rs`
2. Chaos tests: `igra-service/tests/integration/crdt_partition.rs`
3. Deploy to testnet, then mainnet

---

## 5. Domain Layer

**Location:** `igra-core/src/domain/crdt/`

This layer contains **pure business logic with no I/O dependencies**. All CRDT types are serializable and testable in isolation.

### 5.1 `igra-core/src/domain/crdt/mod.rs`

```rust
//! CRDT (Conflict-free Replicated Data Type) implementations for distributed coordination.
//!
//! This module provides pure CRDT data structures with no I/O dependencies.
//! These are used for leaderless signature collection across distributed signers.
//!
//! # Key Types
//! - `GSet<T>`: Grow-only set for signature collection
//! - `LWWRegister<T>`: Last-writer-wins register for completion status
//! - `EventCrdt`: Combined CRDT for a signing event
//!
//! # Key Properties
//! - Commutative: merge(A, B) = merge(B, A)
//! - Associative: merge(merge(A, B), C) = merge(A, merge(B, C))
//! - Idempotent: merge(A, A) = A

mod gset;
mod lww;
mod event_state;
mod types;

pub use gset::GSet;
pub use lww::LWWRegister;
pub use event_state::{EventCrdt, merge_event_states};
pub use types::{SignatureKey, SignatureRecord, CompletionInfo};
```

### 5.2 `igra-core/src/domain/crdt/types.rs`

```rust
//! CRDT-specific types used across the module

use crate::foundation::{Hash32, PeerId, TransactionId};
use serde::{Deserialize, Serialize};

/// Unique identifier for a signature within a CRDT
/// Key: (input_index, pubkey) - one signature per signer per input
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

/// A signature record stored in the CRDT G-Set
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SignatureRecord {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: Option<PeerId>,
    pub timestamp_nanos: u64,
}

/// Completion record for LWW-Register (who submitted the transaction)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletionInfo {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub blue_score: Option<u64>,
}
```

### 5.3 `igra-core/src/domain/crdt/gset.rs`

```rust
//! G-Set (Grow-only Set) CRDT implementation

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::Hash;

/// A Grow-only Set CRDT.
///
/// Elements can only be added, never removed.
/// Merge operation is set union.
///
/// Properties:
/// - Commutative: merge(A, B) = merge(B, A)
/// - Associative: merge(merge(A, B), C) = merge(A, merge(B, C))
/// - Idempotent: merge(A, A) = A
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GSet<T: Clone + Eq + Hash> {
    elements: HashSet<T>,
}

impl<T: Clone + Eq + Hash> GSet<T> {
    /// Create a new empty G-Set
    pub fn new() -> Self {
        Self { elements: HashSet::new() }
    }

    /// Create a G-Set from an iterator
    pub fn from_iter(iter: impl IntoIterator<Item = T>) -> Self {
        Self { elements: iter.into_iter().collect() }
    }

    /// Add an element to the set
    /// Returns true if the element was newly inserted
    pub fn add(&mut self, element: T) -> bool {
        self.elements.insert(element)
    }

    /// Check if the set contains an element
    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains(element)
    }

    /// Get the number of elements
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Iterate over elements
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    /// Merge another G-Set into this one (union operation)
    /// Returns the number of new elements added
    pub fn merge(&mut self, other: &GSet<T>) -> usize {
        let before = self.elements.len();
        self.elements.extend(other.elements.iter().cloned());
        self.elements.len() - before
    }

    /// Create a merged G-Set without mutating either input
    pub fn merged_with(&self, other: &GSet<T>) -> GSet<T> {
        let mut result = self.clone();
        result.merge(other);
        result
    }
}

impl<T: Clone + Eq + Hash> IntoIterator for GSet<T> {
    type Item = T;
    type IntoIter = std::collections::hash_set::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_contains() {
        let mut set = GSet::new();
        assert!(set.add(1));
        assert!(set.add(2));
        assert!(!set.add(1)); // Already exists

        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(!set.contains(&3));
    }

    #[test]
    fn test_merge_is_commutative() {
        let mut a = GSet::from_iter(vec![1, 2, 3]);
        let b = GSet::from_iter(vec![3, 4, 5]);

        let mut c = GSet::from_iter(vec![3, 4, 5]);
        let d = GSet::from_iter(vec![1, 2, 3]);

        a.merge(&b);
        c.merge(&d);

        // merge(A, B) should equal merge(B, A)
        assert_eq!(a.len(), c.len());
        for elem in a.iter() {
            assert!(c.contains(elem));
        }
    }

    #[test]
    fn test_merge_is_idempotent() {
        let mut a = GSet::from_iter(vec![1, 2, 3]);
        let b = a.clone();

        let added = a.merge(&b);

        // merge(A, A) should not change A
        assert_eq!(added, 0);
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn test_merge_is_associative() {
        let a = GSet::from_iter(vec![1, 2]);
        let b = GSet::from_iter(vec![2, 3]);
        let c = GSet::from_iter(vec![3, 4]);

        // (A merge B) merge C
        let mut ab = a.clone();
        ab.merge(&b);
        ab.merge(&c);

        // A merge (B merge C)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        // Results should be equal
        assert_eq!(ab.len(), a_bc.len());
        for elem in ab.iter() {
            assert!(a_bc.contains(elem));
        }
    }
}
```

### 5.4 `igra-core/src/domain/crdt/lww.rs`

```rust
//! LWW-Register (Last-Writer-Wins Register) CRDT implementation

use serde::{Deserialize, Serialize};

/// A Last-Writer-Wins Register CRDT.
///
/// Stores a single value with a timestamp. During merge,
/// the value with the higher timestamp wins.
///
/// Useful for tracking "completion" status where we want
/// to know who submitted the transaction first.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LWWRegister<T: Clone> {
    value: Option<T>,
    timestamp: u64,
}

impl<T: Clone> Default for LWWRegister<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> LWWRegister<T> {
    /// Create a new empty LWW-Register
    pub fn new() -> Self {
        Self {
            value: None,
            timestamp: 0,
        }
    }

    /// Create a LWW-Register with an initial value
    pub fn with_value(value: T, timestamp: u64) -> Self {
        Self {
            value: Some(value),
            timestamp,
        }
    }

    /// Get the current value
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Get the current timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Set a new value if timestamp is greater than current
    /// Returns true if the value was updated
    pub fn set(&mut self, value: T, timestamp: u64) -> bool {
        if timestamp > self.timestamp {
            self.value = Some(value);
            self.timestamp = timestamp;
            true
        } else {
            false
        }
    }

    /// Merge another register into this one
    /// Returns true if this register was updated
    pub fn merge(&mut self, other: &LWWRegister<T>) -> bool {
        if other.timestamp > self.timestamp {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_with_higher_timestamp() {
        let mut reg = LWWRegister::new();

        assert!(reg.set("first", 100));
        assert_eq!(reg.value(), Some(&"first"));

        assert!(reg.set("second", 200));
        assert_eq!(reg.value(), Some(&"second"));
    }

    #[test]
    fn test_set_with_lower_timestamp_ignored() {
        let mut reg = LWWRegister::with_value("initial", 200);

        // Lower timestamp should be ignored
        assert!(!reg.set("older", 100));
        assert_eq!(reg.value(), Some(&"initial"));
    }

    #[test]
    fn test_merge() {
        let mut a = LWWRegister::with_value("a", 100);
        let b = LWWRegister::with_value("b", 200);

        assert!(a.merge(&b));
        assert_eq!(a.value(), Some(&"b"));
        assert_eq!(a.timestamp(), 200);
    }

    #[test]
    fn test_merge_older_ignored() {
        let mut a = LWWRegister::with_value("a", 200);
        let b = LWWRegister::with_value("b", 100);

        assert!(!a.merge(&b));
        assert_eq!(a.value(), Some(&"a"));
    }

    #[test]
    fn test_merge_is_commutative_idempotent() {
        let a = LWWRegister::with_value("a", 100);
        let b = LWWRegister::with_value("b", 200);

        // Merge A into B
        let mut ab = a.clone();
        ab.merge(&b);

        // Merge B into A
        let mut ba = b.clone();
        ba.merge(&a);

        // Results should have same value (the one with higher timestamp)
        assert_eq!(ab.value(), ba.value());
        assert_eq!(ab.value(), Some(&"b"));
    }
}
```

### 5.5 `igra-core/src/domain/crdt/event_state.rs`

```rust
//! Event-level CRDT state for signature collection

use super::{GSet, LWWRegister};
use crate::domain::PartialSigRecord;
use crate::foundation::{Hash32, PeerId, TransactionId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a signature
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SignatureKey {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
}

/// A signature record within the CRDT
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SignatureRecord {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: Option<PeerId>,
    pub timestamp_nanos: u64,
}

/// Completion record for an event (LWW-Register value)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletionInfo {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub blue_score: Option<u64>,
}

/// The main Event CRDT combining signature G-Set with completion LWW-Register
/// Keyed by (event_hash, tx_template_hash) - signatures only merge if both match
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EventCrdt {
    /// The cross-chain event being signed (for grouping/audit)
    pub event_hash: Hash32,

    /// The specific transaction being signed (for signature compatibility)
    /// All signatures in this CRDT are for this exact transaction
    pub tx_template_hash: Hash32,

    /// G-Set of signatures indexed by (input_index, pubkey)
    /// Using HashMap for efficient lookup, but semantically a G-Set
    signatures: HashMap<SignatureKey, SignatureRecord>,

    /// LWW-Register for completion status
    completion: LWWRegister<CompletionInfo>,

    /// Monotonic version for efficient sync
    version: u64,
}

impl EventCrdt {
    /// Create a new EventCrdt for the given (event_hash, tx_template_hash) pair
    pub fn new(event_hash: Hash32, tx_template_hash: Hash32) -> Self {
        Self {
            event_hash,
            tx_template_hash,
            signatures: HashMap::new(),
            completion: LWWRegister::new(),
            version: 0,
        }
    }

    /// Add a signature to the G-Set
    /// Returns true if signature was newly added
    pub fn add_signature(&mut self, record: SignatureRecord) -> bool {
        let key = SignatureKey {
            input_index: record.input_index,
            pubkey: record.pubkey.clone(),
        };

        if self.signatures.contains_key(&key) {
            false
        } else {
            self.signatures.insert(key, record);
            self.version += 1;
            true
        }
    }

    /// Set completion status (LWW semantics)
    /// Returns true if status was updated
    pub fn set_completed(&mut self, info: CompletionInfo, timestamp: u64) -> bool {
        if self.completion.set(info, timestamp) {
            self.version += 1;
            true
        } else {
            false
        }
    }

    /// Check if event is marked as completed
    pub fn is_completed(&self) -> bool {
        self.completion.value().is_some()
    }

    /// Get completion info if available
    pub fn completion(&self) -> Option<&CompletionInfo> {
        self.completion.value()
    }

    /// Get all signatures
    pub fn signatures(&self) -> impl Iterator<Item = &SignatureRecord> {
        self.signatures.values()
    }

    /// Get signature count
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Check if we have threshold signatures for all inputs
    pub fn has_threshold(&self, input_count: usize, required: usize) -> bool {
        if input_count == 0 || required == 0 {
            return false;
        }

        let mut per_input: HashMap<u32, usize> = HashMap::new();
        for sig in self.signatures.values() {
            if (sig.input_index as usize) < input_count {
                *per_input.entry(sig.input_index).or_default() += 1;
            }
        }

        (0..input_count as u32).all(|idx| {
            per_input.get(&idx).map_or(false, |&count| count >= required)
        })
    }

    /// Convert to PartialSigRecord list (for compatibility)
    pub fn to_partial_sig_records(&self) -> Vec<PartialSigRecord> {
        self.signatures.values().map(|sig| PartialSigRecord {
            signer_peer_id: sig.signer_peer_id.clone().unwrap_or_else(|| PeerId::from("unknown")),
            input_index: sig.input_index,
            pubkey: sig.pubkey.clone(),
            signature: sig.signature.clone(),
            timestamp_nanos: sig.timestamp_nanos,
        }).collect()
    }

    /// Merge another EventCrdt into this one
    /// CRITICAL: Only merges if BOTH event_hash AND tx_template_hash match!
    /// Returns the number of changes made
    pub fn merge(&mut self, other: &EventCrdt) -> usize {
        // Signatures are only compatible if they're for the same transaction
        if self.event_hash != other.event_hash || self.tx_template_hash != other.tx_template_hash {
            return 0; // Can't merge - different event or different transaction
        }

        let mut changes = 0;

        // Merge signatures (G-Set union)
        for (key, record) in &other.signatures {
            if !self.signatures.contains_key(key) {
                self.signatures.insert(key.clone(), record.clone());
                changes += 1;
            }
        }

        // Merge completion (LWW)
        if self.completion.merge(&other.completion) {
            changes += 1;
        }

        if changes > 0 {
            self.version += 1;
        }

        changes
    }

    /// Get current version (for sync optimization)
    pub fn version(&self) -> u64 {
        self.version
    }
}

/// Merge two event states, returning a new merged state
pub fn merge_event_states(a: &EventCrdt, b: &EventCrdt) -> EventCrdt {
    let mut result = a.clone();
    result.merge(b);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sig(input_index: u32, pubkey: u8, sig: u8) -> SignatureRecord {
        SignatureRecord {
            input_index,
            pubkey: vec![pubkey],
            signature: vec![sig],
            signer_peer_id: Some(PeerId::from(format!("peer-{}", pubkey))),
            timestamp_nanos: 1000,
        }
    }

    // Common test values
    const EVENT_HASH: Hash32 = [1u8; 32];
    const TX_HASH: Hash32 = [2u8; 32];
    const DIFFERENT_TX_HASH: Hash32 = [3u8; 32];

    #[test]
    fn test_add_signature() {
        let mut crdt = EventCrdt::new(EVENT_HASH, TX_HASH);

        assert!(crdt.add_signature(make_sig(0, 1, 10)));
        assert!(crdt.add_signature(make_sig(0, 2, 20)));
        assert!(!crdt.add_signature(make_sig(0, 1, 10))); // Duplicate

        assert_eq!(crdt.signature_count(), 2);
    }

    #[test]
    fn test_has_threshold() {
        let mut crdt = EventCrdt::new(EVENT_HASH, TX_HASH);

        // 2-of-3 threshold, 2 inputs
        let input_count = 2;
        let required = 2;

        // Add 2 sigs for input 0
        crdt.add_signature(make_sig(0, 1, 10));
        crdt.add_signature(make_sig(0, 2, 20));

        // Not enough yet (missing input 1)
        assert!(!crdt.has_threshold(input_count, required));

        // Add 2 sigs for input 1
        crdt.add_signature(make_sig(1, 1, 11));
        crdt.add_signature(make_sig(1, 2, 21));

        // Now we have threshold
        assert!(crdt.has_threshold(input_count, required));
    }

    #[test]
    fn test_merge_signatures_same_tx() {
        // Same event AND same tx_template - should merge
        let mut a = EventCrdt::new(EVENT_HASH, TX_HASH);
        let mut b = EventCrdt::new(EVENT_HASH, TX_HASH);

        a.add_signature(make_sig(0, 1, 10));
        a.add_signature(make_sig(0, 2, 20));

        b.add_signature(make_sig(0, 2, 20)); // Overlap
        b.add_signature(make_sig(0, 3, 30));

        let changes = a.merge(&b);

        assert_eq!(changes, 1); // Only sig 3 was new
        assert_eq!(a.signature_count(), 3);
    }

    #[test]
    fn test_merge_different_tx_template_fails() {
        // Same event but DIFFERENT tx_template - should NOT merge
        let mut a = EventCrdt::new(EVENT_HASH, TX_HASH);
        let mut b = EventCrdt::new(EVENT_HASH, DIFFERENT_TX_HASH);

        a.add_signature(make_sig(0, 1, 10));
        b.add_signature(make_sig(0, 2, 20));

        let changes = a.merge(&b);

        // No merge happened - different transactions
        assert_eq!(changes, 0);
        assert_eq!(a.signature_count(), 1); // Still only has original sig
    }

    #[test]
    fn test_completion_lww() {
        let mut crdt = EventCrdt::new(EVENT_HASH, TX_HASH);

        let info1 = CompletionInfo {
            tx_id: TransactionId::from([1u8; 32]),
            submitter_peer_id: PeerId::from("peer1"),
            blue_score: Some(100),
        };

        let info2 = CompletionInfo {
            tx_id: TransactionId::from([2u8; 32]),
            submitter_peer_id: PeerId::from("peer2"),
            blue_score: Some(200),
        };

        // Set with timestamp 100
        assert!(crdt.set_completed(info1.clone(), 100));
        assert_eq!(crdt.completion().unwrap().submitter_peer_id.as_str(), "peer1");

        // Try to set with earlier timestamp - should fail
        assert!(!crdt.set_completed(info2.clone(), 50));
        assert_eq!(crdt.completion().unwrap().submitter_peer_id.as_str(), "peer1");

        // Set with later timestamp - should succeed
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
```

### 5.6 `igra-core/src/domain/crdt/tests.rs`

Additional integration-style tests for the domain CRDT module (still pure logic, no I/O).

```rust
//! Integration tests for CRDT module

use super::*;
use crate::foundation::{Hash32, PeerId, TransactionId};

/// Simulates a network of signers using CRDTs
/// Key insight: All signers construct the same tx_template_hash via deterministic KPSBT
#[test]
fn test_distributed_signing_simulation() {
    let event_hash: Hash32 = [42u8; 32];
    // All signers construct the SAME transaction deterministically
    let tx_template_hash: Hash32 = [99u8; 32];
    let input_count = 2;
    let required = 2; // 2-of-3

    // Create 3 signers, each with their own CRDT
    // They all have the same (event_hash, tx_template_hash) because KPSBT is deterministic
    let mut signer1 = EventCrdt::new(event_hash, tx_template_hash);
    let mut signer2 = EventCrdt::new(event_hash, tx_template_hash);
    let mut signer3 = EventCrdt::new(event_hash, tx_template_hash);

    // Each signer signs locally
    // Signer 1 signs both inputs
    signer1.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![1],
        signature: vec![10],
        signer_peer_id: Some(PeerId::from("signer1")),
        timestamp_nanos: 1000,
    });
    signer1.add_signature(event_state::SignatureRecord {
        input_index: 1,
        pubkey: vec![1],
        signature: vec![11],
        signer_peer_id: Some(PeerId::from("signer1")),
        timestamp_nanos: 1001,
    });

    // Signer 2 signs both inputs
    signer2.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![2],
        signature: vec![20],
        signer_peer_id: Some(PeerId::from("signer2")),
        timestamp_nanos: 1002,
    });
    signer2.add_signature(event_state::SignatureRecord {
        input_index: 1,
        pubkey: vec![2],
        signature: vec![21],
        signer_peer_id: Some(PeerId::from("signer2")),
        timestamp_nanos: 1003,
    });

    // Signer 3 is slow, only signs later
    signer3.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![3],
        signature: vec![30],
        signer_peer_id: Some(PeerId::from("signer3")),
        timestamp_nanos: 2000,
    });

    // Before merge: no one has threshold
    assert!(!signer1.has_threshold(input_count, required));
    assert!(!signer2.has_threshold(input_count, required));
    assert!(!signer3.has_threshold(input_count, required));

    // Simulate gossip: signer1 receives signer2's state
    signer1.merge(&signer2);

    // Now signer1 has threshold (2 sigs per input)
    assert!(signer1.has_threshold(input_count, required));

    // Signer1 submits and marks complete
    let completion = event_state::CompletionInfo {
        tx_id: TransactionId::from([99u8; 32]),
        submitter_peer_id: PeerId::from("signer1"),
        blue_score: Some(12345),
    };
    signer1.set_completed(completion.clone(), 3000);

    // Gossip completion to others
    signer2.merge(&signer1);
    signer3.merge(&signer1);

    // Everyone knows it's complete
    assert!(signer1.is_completed());
    assert!(signer2.is_completed());
    assert!(signer3.is_completed());

    // All have the same completion info
    assert_eq!(
        signer1.completion().unwrap().tx_id.as_hash(),
        signer2.completion().unwrap().tx_id.as_hash()
    );
}

/// Test that partition and reconnect works correctly
#[test]
fn test_network_partition_recovery() {
    let event_hash: Hash32 = [42u8; 32];
    let tx_template_hash: Hash32 = [99u8; 32];

    // Two partitions, each with signers that constructed the same tx_template
    let mut partition_a = EventCrdt::new(event_hash, tx_template_hash);
    let mut partition_b = EventCrdt::new(event_hash, tx_template_hash);

    // Partition A adds signatures
    partition_a.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![1],
        signature: vec![10],
        signer_peer_id: Some(PeerId::from("a1")),
        timestamp_nanos: 1000,
    });
    partition_a.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![2],
        signature: vec![20],
        signer_peer_id: Some(PeerId::from("a2")),
        timestamp_nanos: 1001,
    });

    // Partition B adds different signatures
    partition_b.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![3],
        signature: vec![30],
        signer_peer_id: Some(PeerId::from("b1")),
        timestamp_nanos: 1002,
    });
    partition_b.add_signature(event_state::SignatureRecord {
        input_index: 1,
        pubkey: vec![3],
        signature: vec![31],
        signer_peer_id: Some(PeerId::from("b1")),
        timestamp_nanos: 1003,
    });

    // Network heals - partitions merge
    partition_a.merge(&partition_b);
    partition_b.merge(&partition_a);

    // Both partitions now have all signatures
    assert_eq!(partition_a.signature_count(), partition_b.signature_count());
    assert_eq!(partition_a.signature_count(), 4);
}

/// Test concurrent completion (race condition)
#[test]
fn test_concurrent_completion_race() {
    let event_hash: Hash32 = [42u8; 32];
    let tx_template_hash: Hash32 = [99u8; 32];

    let mut signer1 = EventCrdt::new(event_hash, tx_template_hash);
    let mut signer2 = EventCrdt::new(event_hash, tx_template_hash);

    // Both try to mark complete at same time
    // Signer1's timestamp is 1000
    signer1.set_completed(
        event_state::CompletionInfo {
            tx_id: TransactionId::from([1u8; 32]),
            submitter_peer_id: PeerId::from("signer1"),
            blue_score: Some(100),
        },
        1000,
    );

    // Signer2's timestamp is 1001 (later)
    signer2.set_completed(
        event_state::CompletionInfo {
            tx_id: TransactionId::from([2u8; 32]),
            submitter_peer_id: PeerId::from("signer2"),
            blue_score: Some(101),
        },
        1001,
    );

    // Merge both ways
    signer1.merge(&signer2);
    signer2.merge(&signer1);

    // LWW: later timestamp wins
    // Both should agree on signer2's completion
    assert_eq!(
        signer1.completion().unwrap().submitter_peer_id.as_str(),
        "signer2"
    );
    assert_eq!(
        signer2.completion().unwrap().submitter_peer_id.as_str(),
        "signer2"
    );
}

/// Test scenario: One signer is out of sync and constructs different tx_template
/// This simulates when a node's Kaspa view has different UTXOs
#[test]
fn test_out_of_sync_signer_different_tx_template() {
    let event_hash: Hash32 = [42u8; 32];
    let tx_template_synced: Hash32 = [99u8; 32];    // Synced nodes' transaction
    let tx_template_stale: Hash32 = [88u8; 32];     // Out-of-sync node's transaction

    // 3 signers: 2 synced, 1 out-of-sync
    let mut signer1 = EventCrdt::new(event_hash, tx_template_synced);
    let mut signer2 = EventCrdt::new(event_hash, tx_template_synced);
    let mut signer3_stale = EventCrdt::new(event_hash, tx_template_stale); // Different tx!

    // Synced signers sign
    signer1.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![1],
        signature: vec![10],
        signer_peer_id: Some(PeerId::from("signer1")),
        timestamp_nanos: 1000,
    });
    signer2.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![2],
        signature: vec![20],
        signer_peer_id: Some(PeerId::from("signer2")),
        timestamp_nanos: 1001,
    });

    // Out-of-sync signer signs (different tx_template!)
    signer3_stale.add_signature(event_state::SignatureRecord {
        input_index: 0,
        pubkey: vec![3],
        signature: vec![30],
        signer_peer_id: Some(PeerId::from("signer3")),
        timestamp_nanos: 1002,
    });

    // Try to merge stale signer into synced signer - should NOT merge!
    let changes = signer1.merge(&signer3_stale);
    assert_eq!(changes, 0); // Different tx_template_hash, no merge

    // Synced signers can still merge with each other
    let changes = signer1.merge(&signer2);
    assert_eq!(changes, 1); // signer2's signature added

    // signer1 now has 2 signatures (from synced signers only)
    assert_eq!(signer1.signature_count(), 2);

    // The stale signer's signature is orphaned but doesn't break anything
    assert_eq!(signer3_stale.signature_count(), 1);
}
```

### 6.6 Create `igra-service/src/service/coordination/crdt_handler.rs`

```rust
//! CRDT-based event handling for the coordination loop

use crate::service::flow::ServiceFlow;
use igra_core::domain::crdt::{EventCrdt, SignatureRecord, CompletionInfo};
use igra_core::domain::hashes::event_hash;
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::signing::threshold::ThresholdSigner;
use igra_core::domain::signing::SignerBackend;
use igra_core::domain::validation::CompositeVerifier;
use igra_core::foundation::hd::derive_keypair_from_key_data;
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::transport::iroh::messages::{EventStateBroadcast, EventCrdtState};
use igra_core::infrastructure::transport::iroh::traits::Transport;
use kaspa_wallet_core::prelude::Secret;
use log::{debug, info, warn};
use std::sync::Arc;

/// Handle an incoming CRDT event state broadcast
pub async fn handle_crdt_event(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<RocksStorage>,
    local_peer_id: &PeerId,
    message_verifier: &CompositeVerifier,
    broadcast: EventStateBroadcast,
) -> Result<(), ThresholdError> {
    let event_hash = broadcast.event_hash;
    let tx_template_hash = broadcast.tx_template_hash;

    info!(
        "received CRDT broadcast event_hash={} tx_template_hash={} from_peer={} sig_count={}",
        hex::encode(event_hash),
        hex::encode(tx_template_hash),
        broadcast.sender_peer_id,
        broadcast.state.signatures.len()
    );

    // Step 1: Merge incoming state with local CRDT
    // Key: (event_hash, tx_template_hash) - only merges if both match
    let (local_state, changed) = storage.merge_event_crdt(
        &event_hash,
        &tx_template_hash,
        &broadcast.state,
        None,
        None,
    )?;

    if !changed {
        debug!(
            "no new data from broadcast event_hash={} tx_template_hash={}",
            hex::encode(event_hash),
            hex::encode(tx_template_hash)
        );
        return Ok(());
    }

    info!(
        "merged CRDT state event_hash={} tx_template_hash={} local_sig_count={} changed={}",
        hex::encode(event_hash),
        hex::encode(tx_template_hash),
        local_state.signatures.len(),
        changed
    );

    // Step 2: If not completed and we haven't signed yet, sign and broadcast
    if local_state.completion.is_none() {
        let has_my_sig = local_state.signatures.iter().any(|s| {
            s.signer_peer_id == *local_peer_id
        });

        if !has_my_sig {
            // We need the signing event and KPSBT to sign
            if let (Some(signing_event), Some(kpsbt_blob)) =
                (&local_state.signing_event, &local_state.kpsbt_blob)
            {
                // Validate the event before signing
                if !validate_event(app_config, signing_event, message_verifier)? {
                    warn!(
                        "event validation failed, not signing event_hash={}",
                        hex::encode(event_hash)
                    );
                    return Ok(());
                }

                // CRITICAL: Build our own KPSBT deterministically and verify tx_template_hash matches
                // If it doesn't match, we're out of sync - don't sign incompatible transaction
                let our_tx_template_hash = pskt_multisig::tx_template_hash(
                    &pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?
                )?;

                if our_tx_template_hash != tx_template_hash {
                    warn!(
                        "tx_template_hash mismatch - our node may be out of sync event_hash={} received={} computed={}",
                        hex::encode(event_hash),
                        hex::encode(tx_template_hash),
                        hex::encode(our_tx_template_hash)
                    );
                    // Don't sign - our signatures would be incompatible
                    return Ok(());
                }

                // Sign and add to local CRDT
                if let Ok(signatures) = sign_event(app_config, signing_event, kpsbt_blob) {
                    for (input_index, pubkey, signature) in signatures {
                        storage.add_signature_to_crdt(
                            &event_hash,
                            &tx_template_hash,
                            input_index,
                            &pubkey,
                            &signature,
                            local_peer_id,
                        )?;
                    }

                    // Broadcast our updated state
                    broadcast_local_state(transport, storage, &event_hash, &tx_template_hash, local_peer_id).await?;
                }
            }
        }
    }

    // Step 3: Check if we have threshold and can submit
    if local_state.completion.is_none() {
        let required = usize::from(app_config.service.pskt.sig_op_count);
        if let Some(kpsbt_blob) = &local_state.kpsbt_blob {
            let pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
            let input_count = pskt.inputs.len();

            if storage.crdt_has_threshold(&event_hash, input_count, required)? {
                info!(
                    "threshold reached, attempting submission event_hash={} sigs={} required={}",
                    hex::encode(event_hash),
                    local_state.signatures.len(),
                    required
                );

                // Attempt to submit transaction
                match attempt_submission(app_config, flow, storage, &event_hash).await {
                    Ok(tx_id) => {
                        info!(
                            "transaction submitted successfully event_hash={} tx_id={}",
                            hex::encode(event_hash),
                            tx_id
                        );

                        // Mark as completed
                        let blue_score = flow.rpc().get_virtual_selected_parent_blue_score().await.ok();
                        storage.mark_crdt_completed(
                            &event_hash,
                            tx_id,
                            local_peer_id,
                            blue_score,
                        )?;

                        // Broadcast completion
                        broadcast_local_state(transport, storage, &event_hash, local_peer_id).await?;
                    }
                    Err(err) => {
                        // Submission failed - likely someone else beat us
                        // This is expected behavior, not an error
                        debug!(
                            "submission failed (likely already submitted) event_hash={} error={}",
                            hex::encode(event_hash),
                            err
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validate an event according to policy and message signatures
fn validate_event(
    app_config: &AppConfig,
    signing_event: &igra_core::domain::SigningEvent,
    message_verifier: &CompositeVerifier,
) -> Result<bool, ThresholdError> {
    // TODO: Implement full validation
    // - Check policy (amounts, destinations)
    // - Verify Hyperlane/LayerZero signatures
    // - Check event hasn't been replayed
    Ok(true)
}

/// Sign an event and return signatures for all inputs
fn sign_event(
    app_config: &AppConfig,
    signing_event: &igra_core::domain::SigningEvent,
    kpsbt_blob: &[u8],
) -> Result<Vec<(u32, Vec<u8>, Vec<u8>)>, ThresholdError> {
    let hd = app_config.service.hd.as_ref()
        .ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;

    let key_data = hd.decrypt_mnemonics()?;
    let key_data = key_data.first()
        .ok_or_else(|| ThresholdError::ConfigError("missing mnemonic".to_string()))?;

    let payment_secret = hd.passphrase.as_deref().map(Secret::from);
    let keypair = derive_keypair_from_key_data(
        key_data,
        &signing_event.derivation_path,
        payment_secret.as_ref(),
    )?;

    let signer = ThresholdSigner::new(keypair);
    let pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;

    let mut signatures = Vec::new();
    for (input_index, input) in pskt.inputs.iter().enumerate() {
        if let Some(sighash) = input.sighash_type {
            // Sign this input
            let sig_result = signer.sign_input(input_index as u32, &pskt)?;
            signatures.push((
                input_index as u32,
                signer.pubkey().serialize().to_vec(),
                sig_result,
            ));
        }
    }

    Ok(signatures)
}

/// Attempt to finalize and submit transaction
async fn attempt_submission(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    storage: &Arc<RocksStorage>,
    event_hash: &Hash32,
    tx_template_hash: &Hash32,
) -> Result<igra_core::foundation::TransactionId, ThresholdError> {
    let state = storage.get_event_crdt(event_hash, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;

    let kpsbt_blob = state.kpsbt_blob
        .ok_or_else(|| ThresholdError::Message("missing KPSBT".to_string()))?;

    let signing_event = state.signing_event
        .ok_or_else(|| ThresholdError::Message("missing signing event".to_string()))?;

    // Convert CRDT signatures to PartialSigRecord format
    let partials: Vec<igra_core::domain::PartialSigRecord> = state.signatures
        .iter()
        .map(|s| igra_core::domain::PartialSigRecord {
            signer_peer_id: s.signer_peer_id.clone(),
            input_index: s.input_index,
            pubkey: s.pubkey.clone(),
            signature: s.signature.clone(),
            timestamp_nanos: s.timestamp_nanos,
        })
        .collect();

    // Apply signatures and finalize
    let pskt = pskt_multisig::apply_partial_sigs(&kpsbt_blob, &partials)?;

    let required = usize::from(app_config.service.pskt.sig_op_count);
    let ordered_pubkeys = crate::service::coordination::finalization::derive_ordered_pubkeys(
        &app_config.service,
        &signing_event,
    )?;
    let params = crate::service::coordination::finalization::params_for_network_id(
        app_config.iroh.network_id,
    );

    // Create a dummy request_id for compatibility
    let request_id = igra_core::foundation::RequestId::from(hex::encode(event_hash));

    flow.finalize_and_submit(&request_id, pskt, required, &ordered_pubkeys, params).await
}

/// Broadcast local CRDT state to the network
async fn broadcast_local_state(
    transport: &Arc<dyn Transport>,
    storage: &Arc<RocksStorage>,
    event_hash: &Hash32,
    tx_template_hash: &Hash32,
    local_peer_id: &PeerId,
) -> Result<(), ThresholdError> {
    let state = storage.get_event_crdt(event_hash, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;

    let crdt_state = EventCrdtState {
        signatures: state.signatures.iter().map(|s| {
            igra_core::infrastructure::transport::iroh::messages::CrdtSignature {
                input_index: s.input_index,
                pubkey: s.pubkey.clone(),
                signature: s.signature.clone(),
                timestamp_nanos: s.timestamp_nanos,
            }
        }).collect(),
        completion: state.completion.map(|c| {
            igra_core::infrastructure::transport::iroh::messages::CompletionRecord {
                tx_id: *c.tx_id.as_hash(),
                submitter_peer_id: c.submitter_peer_id,
                timestamp_nanos: c.timestamp_nanos,
                blue_score: c.blue_score,
            }
        }),
        version: 0,
    };

    let broadcast = EventStateBroadcast {
        event_hash: *event_hash,
        tx_template_hash: *tx_template_hash,
        state: crdt_state,
        sender_peer_id: local_peer_id.clone(),
    };

    // TODO: Publish to appropriate topic
    // transport.publish_crdt_state(broadcast).await?;

    Ok(())
}

/// Anti-entropy: periodically sync state with random peers
pub async fn run_anti_entropy_loop(
    storage: Arc<RocksStorage>,
    transport: Arc<dyn Transport>,
    local_peer_id: PeerId,
    interval_secs: u64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        // Get all pending (incomplete) events
        match storage.list_pending_event_crdts() {
            Ok(pending) => {
                for state in pending {
                    // Broadcast state to help other nodes catch up
                    if let Err(err) = broadcast_local_state(
                        &transport,
                        &storage,
                        &state.event_hash,
                        &state.tx_template_hash,
                        &local_peer_id,
                    ).await {
                        debug!(
                            "anti-entropy broadcast failed event_hash={} tx_template_hash={} error={}",
                            hex::encode(state.event_hash),
                            hex::encode(state.tx_template_hash),
                            err
                        );
                    }
                }
            }
            Err(err) => {
                warn!("failed to list pending events for anti-entropy: {}", err);
            }
        }
    }
}
```

### 5.7 Update `igra-core/src/domain/mod.rs`

Add the new CRDT module to domain exports:

```rust
// Add this line among the other module declarations
pub mod crdt;

// Re-export commonly used items
pub use crdt::{EventCrdt, GSet, LWWRegister};
```

---

## 6. Infrastructure Layer

**Location:** `igra-core/src/infrastructure/`

This layer handles I/O operations: storage, transport, and configuration.

### 6.1 `igra-core/src/infrastructure/transport/iroh/messages.rs`

**Replace** the existing message types with CRDT-only messages:

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TransportMessage {
    /// CRDT state broadcast - the main message type
    EventStateBroadcast(EventStateBroadcast),
    /// Anti-entropy sync request
    StateSyncRequest(StateSyncRequest),
    /// Anti-entropy sync response
    StateSyncResponse(StateSyncResponse),
}

// DELETE these old types entirely:
// - SigningEventPropose
// - SignerAck
// - PartialSigSubmit
// - FinalizeNotice
// - FinalizeAck

/// CRDT-based event state broadcast
/// Contains full state for an event - receivers merge with local state
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventStateBroadcast {
    /// The cross-chain event being processed (for grouping/audit)
    pub event_hash: Hash32,
    /// The specific transaction being signed (for signature compatibility)
    pub tx_template_hash: Hash32,
    /// The CRDT state
    pub state: EventCrdtState,
    /// Who sent this broadcast
    pub sender_peer_id: PeerId,
}

/// The actual CRDT state that gets merged
/// Key: (event_hash, tx_template_hash) - signatures only merge if both match
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventCrdtState {
    /// G-Set of signatures, keyed by (input_index, pubkey)
    /// Only compatible with same tx_template_hash
    pub signatures: Vec<CrdtSignature>,
    /// LWW-Register for completion status
    pub completion: Option<CompletionRecord>,
    /// Monotonic version for efficient sync
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct CrdtSignature {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_nanos: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletionRecord {
    pub tx_id: Hash32,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub blue_score: Option<u64>,
}

/// Request state for specific events (anti-entropy)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncRequest {
    pub event_hashes: Vec<Hash32>,
    pub requester_peer_id: PeerId,
}

/// Response with full CRDT states
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateSyncResponse {
    pub states: Vec<(Hash32, Hash32, EventCrdtState)>, // (event_hash, tx_template_hash, state)
}
```

### 6.2 `igra-core/src/infrastructure/storage/rocks/schema.rs`

**Replace** the column families - remove old proposal/ack/partial_sig CFs:

```rust
// Column families for CRDT-based storage
pub const CF_METADATA: &str = "metadata";
pub const CF_DEFAULT: &str = "default";
pub const CF_GROUP: &str = "group";
pub const CF_EVENT: &str = "event";
pub const CF_EVENT_CRDT: &str = "event_crdt";  // Main CRDT storage
pub const CF_VOLUME: &str = "volume";
pub const CF_SEEN: &str = "seen";

// DELETE these old column families:
// - CF_REQUEST (replaced by CF_EVENT_CRDT)
// - CF_PROPOSAL (not needed - no proposals)
// - CF_REQUEST_INPUT (not needed)
// - CF_SIGNER_ACK (not needed - no acks)
// - CF_PARTIAL_SIG (replaced by signatures in CF_EVENT_CRDT)
```

### 6.3 `igra-core/src/infrastructure/storage/rocks/db.rs`

Update `open_db_with_cfs` function with cleaned-up CFs:

```rust
let cf_names = vec![
    CF_METADATA,
    CF_DEFAULT,
    CF_GROUP,
    CF_EVENT,
    CF_EVENT_CRDT,
    CF_VOLUME,
    CF_SEEN,
];
```

### 6.4 `igra-core/src/domain/model.rs`

Add storage model types at the end of the file:

```rust
/// CRDT state for an event/transaction pair - used in storage
/// Key: (event_hash, tx_template_hash)
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StoredEventCrdt {
    /// The cross-chain event being processed
    pub event_hash: Hash32,
    /// The specific transaction being signed (deterministically constructed)
    pub tx_template_hash: Hash32,
    /// The original signing event (for reference)
    pub signing_event: Option<SigningEvent>,
    /// The KPSBT blob (for finalization)
    pub kpsbt_blob: Option<Vec<u8>>,
    /// G-Set of signatures (keyed by input_index + pubkey)
    pub signatures: Vec<CrdtSignatureRecord>,
    /// LWW-Register for completion status
    pub completion: Option<StoredCompletionRecord>,
    /// When this CRDT was first created locally
    pub created_at_nanos: u64,
    /// When this CRDT was last updated
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
```

### 6.5 `igra-core/src/infrastructure/storage/rocks/engine.rs`

Add these methods to `RocksStorage`:

```rust
impl RocksStorage {
    // ... existing methods ...

    // ========== CRDT Storage Methods ==========

    /// Storage key includes BOTH event_hash AND tx_template_hash
    /// This ensures signatures only merge if they're for the same transaction
    fn key_event_crdt(event_hash: &Hash32, tx_template_hash: &Hash32) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + event_hash.len() + 1 + tx_template_hash.len())
            .prefix(b"evt_crdt:")
            .hash32(event_hash)
            .sep()
            .hash32(tx_template_hash)
            .build()
    }

    /// Prefix for listing all CRDTs for a given event (may have multiple tx_template_hash)
    fn key_event_crdt_prefix(event_hash: &Hash32) -> Vec<u8> {
        KeyBuilder::with_capacity(10 + event_hash.len() + 1)
            .prefix(b"evt_crdt:")
            .hash32(event_hash)
            .sep()
            .build()
    }

    /// Get CRDT state for a specific (event_hash, tx_template_hash) pair
    pub fn get_event_crdt(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
    ) -> Result<Option<StoredEventCrdt>, ThresholdError> {
        let key = Self::key_event_crdt(event_hash, tx_template_hash);
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let value = self.db.get_cf(cf, key).map_err(|err| ThresholdError::Message(err.to_string()))?;
        match value {
            Some(bytes) => Ok(Some(Self::decode(&bytes)?)),
            None => Ok(None),
        }
    }

    /// List all CRDT states for a given event (different tx_template_hash values)
    /// Useful for debugging when signers constructed different transactions
    pub fn list_event_crdts(&self, event_hash: &Hash32) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        let prefix = Self::key_event_crdt_prefix(event_hash);
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(&prefix, Direction::Forward));

        let mut results = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::Message(e.to_string()))?;
            if !key.starts_with(&prefix) {
                break;
            }
            results.push(Self::decode(&value)?);
        }
        Ok(results)
    }

    /// Merge incoming CRDT state with local state
    /// CRITICAL: Only merges if tx_template_hash matches!
    /// Returns (merged_state, is_new_data) - is_new_data is true if merge added anything
    pub fn merge_event_crdt(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        incoming: &EventCrdtState,
        signing_event: Option<&SigningEvent>,
        kpsbt_blob: Option<&[u8]>,
    ) -> Result<(StoredEventCrdt, bool), ThresholdError> {
        let key = Self::key_event_crdt(event_hash, tx_template_hash);
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Get existing state or create new
        let mut local = match self.db.get_cf(cf, &key).map_err(|e| ThresholdError::Message(e.to_string()))? {
            Some(bytes) => Self::decode::<StoredEventCrdt>(&bytes)?,
            None => StoredEventCrdt {
                event_hash: *event_hash,
                tx_template_hash: *tx_template_hash,
                signing_event: None,
                kpsbt_blob: None,
                signatures: Vec::new(),
                completion: None,
                created_at_nanos: now_nanos,
                updated_at_nanos: now_nanos,
            },
        };

        let mut changed = false;

        // Update signing_event if we have it and local doesn't
        if local.signing_event.is_none() {
            if let Some(event) = signing_event {
                local.signing_event = Some(event.clone());
                changed = true;
            }
        }

        // Update kpsbt_blob if we have it and local doesn't
        if local.kpsbt_blob.is_none() {
            if let Some(blob) = kpsbt_blob {
                local.kpsbt_blob = Some(blob.to_vec());
                changed = true;
            }
        }

        // G-Set merge for signatures
        let existing_sigs: std::collections::HashSet<(u32, &[u8])> = local.signatures
            .iter()
            .map(|s| (s.input_index, s.pubkey.as_slice()))
            .collect();

        for sig in &incoming.signatures {
            let sig_key = (sig.input_index, sig.pubkey.as_slice());
            if !existing_sigs.contains(&sig_key) {
                local.signatures.push(CrdtSignatureRecord {
                    input_index: sig.input_index,
                    pubkey: sig.pubkey.clone(),
                    signature: sig.signature.clone(),
                    signer_peer_id: PeerId::from("unknown"),
                    timestamp_nanos: sig.timestamp_nanos,
                });
                changed = true;
            }
        }

        // LWW-Register merge for completion
        if let Some(incoming_completion) = &incoming.completion {
            match &local.completion {
                None => {
                    local.completion = Some(StoredCompletionRecord {
                        tx_id: TransactionId::from(incoming_completion.tx_id),
                        submitter_peer_id: incoming_completion.submitter_peer_id.clone(),
                        timestamp_nanos: incoming_completion.timestamp_nanos,
                        blue_score: incoming_completion.blue_score,
                    });
                    changed = true;
                }
                Some(local_completion) => {
                    // LWW: later timestamp wins
                    if incoming_completion.timestamp_nanos > local_completion.timestamp_nanos {
                        local.completion = Some(StoredCompletionRecord {
                            tx_id: TransactionId::from(incoming_completion.tx_id),
                            submitter_peer_id: incoming_completion.submitter_peer_id.clone(),
                            timestamp_nanos: incoming_completion.timestamp_nanos,
                            blue_score: incoming_completion.blue_score,
                        });
                        changed = true;
                    }
                }
            }
        }

        if changed {
            local.updated_at_nanos = now_nanos;
            let value = Self::encode(&local)?;
            self.db.put_cf(cf, key, value).map_err(|e| ThresholdError::Message(e.to_string()))?;
        }

        Ok((local, changed))
    }

    /// Add a single signature to CRDT (convenience method)
    pub fn add_signature_to_crdt(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        input_index: u32,
        pubkey: &[u8],
        signature: &[u8],
        signer_peer_id: &PeerId,
    ) -> Result<StoredEventCrdt, ThresholdError> {
        let incoming = EventCrdtState {
            signatures: vec![CrdtSignature {
                input_index,
                pubkey: pubkey.to_vec(),
                signature: signature.to_vec(),
                timestamp_nanos: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0),
            }],
            completion: None,
            version: 0,
        };
        let (mut state, _) = self.merge_event_crdt(event_hash, tx_template_hash, &incoming, None, None)?;
        // Update peer_id for the signature we just added
        if let Some(sig) = state.signatures.iter_mut().find(|s| s.input_index == input_index && s.pubkey == pubkey) {
            sig.signer_peer_id = signer_peer_id.clone();
        }
        Ok(state)
    }

    /// Mark event as completed in CRDT
    pub fn mark_crdt_completed(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        tx_id: TransactionId,
        submitter_peer_id: &PeerId,
        blue_score: Option<u64>,
    ) -> Result<(), ThresholdError> {
        let incoming = EventCrdtState {
            signatures: vec![],
            completion: Some(CompletionRecord {
                tx_id: *tx_id.as_hash(),
                submitter_peer_id: submitter_peer_id.clone(),
                timestamp_nanos: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0),
                blue_score,
            }),
            version: 0,
        };
        self.merge_event_crdt(event_hash, tx_template_hash, &incoming, None, None)?;
        Ok(())
    }

    /// Check if event has reached signature threshold
    pub fn crdt_has_threshold(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        input_count: usize,
        required: usize,
    ) -> Result<bool, ThresholdError> {
        let state = match self.get_event_crdt(event_hash, tx_template_hash)? {
            Some(s) => s,
            None => return Ok(false),
        };

        if input_count == 0 || required == 0 {
            return Ok(false);
        }

        // Count unique pubkeys per input
        let mut per_input: std::collections::HashMap<u32, std::collections::HashSet<&[u8]>> =
            std::collections::HashMap::new();

        for sig in &state.signatures {
            if (sig.input_index as usize) < input_count {
                per_input.entry(sig.input_index).or_default().insert(&sig.pubkey);
            }
        }

        // Check all inputs have required signatures
        Ok((0..input_count as u32).all(|idx| {
            per_input.get(&idx).map_or(false, |set| set.len() >= required)
        }))
    }

    /// List all pending (incomplete) event CRDTs
    pub fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>, ThresholdError> {
        let prefix = b"evt_crdt:";
        let mut results = Vec::new();
        let cf = self.cf_handle(CF_EVENT_CRDT)?;
        let iter = self.db.iterator_cf(cf, IteratorMode::From(prefix, Direction::Forward));

        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::Message(e.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            let state: StoredEventCrdt = Self::decode(&value)?;
            if state.completion.is_none() {
                results.push(state);
            }
        }

        Ok(results)
    }
}
```

### 6.6 Files to Delete

Remove these files/modules that are no longer needed:

```
igra-core/src/application/signer.rs        # Old proposal validation
igra-core/src/application/coordinator.rs   # Old coordinator logic (if separate)
igra-core/src/domain/coordination/         # Old coordination module
igra-service/src/service/coordination/finalization.rs  # Replace with CRDT handler
igra-service/src/service/coordination/session.rs       # No more sessions
```

Also remove from `engine.rs`:
- `insert_proposal()`, `get_proposal()`
- `insert_signer_ack()`, `list_signer_acks()`
- `insert_partial_sig()`, `list_partial_sigs()`
- `insert_request()`, `get_request()`, `update_request_*()`

---

## 7. Application Layer

**Location:** `igra-core/src/application/`

This layer provides orchestration logic that ties domain and infrastructure together.

### 7.1 `igra-core/src/application/crdt_coordinator.rs`

```rust
//! CRDT-based event coordination
//!
//! This module provides the main orchestration logic for processing events
//! using CRDT-based coordination instead of the proposal-ack flow.

use crate::domain::crdt::{EventCrdt, SignatureRecord};
use crate::domain::pskt::multisig as pskt_multisig;
use crate::foundation::{Hash32, PeerId, ThresholdError};
use crate::infrastructure::storage::rocks::RocksStorage;
use crate::infrastructure::transport::iroh::messages::{EventCrdtState, EventStateBroadcast};
use log::{debug, info, warn};
use std::sync::Arc;

/// CRDT-based event coordinator
pub struct CrdtCoordinator {
    storage: Arc<RocksStorage>,
    local_peer_id: PeerId,
}

impl CrdtCoordinator {
    pub fn new(storage: Arc<RocksStorage>, local_peer_id: PeerId) -> Self {
        Self { storage, local_peer_id }
    }

    /// Process an incoming event - determines what action to take
    pub fn process_event(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
    ) -> Result<CrdtAction, ThresholdError> {
        let state = self.storage.get_event_crdt(event_hash, tx_template_hash)?;

        match state {
            Some(s) if s.completion.is_some() => {
                Ok(CrdtAction::AlreadyComplete)
            }
            Some(s) => {
                let has_my_sig = s.signatures.iter()
                    .any(|sig| sig.signer_peer_id == self.local_peer_id);

                if has_my_sig {
                    Ok(CrdtAction::WaitForThreshold)
                } else {
                    Ok(CrdtAction::SignAndBroadcast)
                }
            }
            None => {
                Ok(CrdtAction::InitializeAndSign)
            }
        }
    }

    /// Check if an event has reached threshold
    pub fn check_threshold(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        input_count: usize,
        required: usize,
    ) -> Result<bool, ThresholdError> {
        self.storage.crdt_has_threshold(event_hash, tx_template_hash, input_count, required)
    }
}

/// Actions the coordinator can recommend
#[derive(Debug, Clone, PartialEq)]
pub enum CrdtAction {
    /// Event is already complete, no action needed
    AlreadyComplete,
    /// We've signed, waiting for other signers
    WaitForThreshold,
    /// Need to sign and broadcast
    SignAndBroadcast,
    /// New event, initialize CRDT and sign
    InitializeAndSign,
}
```

---

## 8. Service Layer

**Location:** `igra-service/src/service/`

This layer integrates CRDT coordination into the existing service.

### 8.1 `igra-service/src/service/coordination/crdt_handler.rs`

```rust
//! CRDT-based event handling for the coordination loop

use crate::service::flow::ServiceFlow;
use igra_core::domain::crdt::{EventCrdt, SignatureRecord, CompletionInfo};
use igra_core::domain::hashes::event_hash;
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::signing::threshold::ThresholdSigner;
use igra_core::domain::signing::SignerBackend;
use igra_core::domain::validation::CompositeVerifier;
use igra_core::foundation::hd::derive_keypair_from_key_data;
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::transport::iroh::messages::{EventStateBroadcast, EventCrdtState};
use igra_core::infrastructure::transport::iroh::traits::Transport;
use kaspa_wallet_core::prelude::Secret;
use log::{debug, info, warn};
use std::sync::Arc;

/// Handle an incoming CRDT event state broadcast
pub async fn handle_crdt_event(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<RocksStorage>,
    local_peer_id: &PeerId,
    message_verifier: &CompositeVerifier,
    broadcast: EventStateBroadcast,
) -> Result<(), ThresholdError> {
    let event_hash = broadcast.event_hash;
    let tx_template_hash = broadcast.tx_template_hash;

    info!(
        "received CRDT broadcast event_hash={} tx_template_hash={} from_peer={} sig_count={}",
        hex::encode(event_hash),
        hex::encode(tx_template_hash),
        broadcast.sender_peer_id,
        broadcast.state.signatures.len()
    );

    // Step 1: Merge incoming state with local CRDT
    let (local_state, changed) = storage.merge_event_crdt(
        &event_hash,
        &tx_template_hash,
        &broadcast.state,
        None,
        None,
    )?;

    if !changed {
        debug!(
            "no new data from broadcast event_hash={} tx_template_hash={}",
            hex::encode(event_hash),
            hex::encode(tx_template_hash)
        );
        return Ok(());
    }

    info!(
        "merged CRDT state event_hash={} tx_template_hash={} local_sig_count={} changed={}",
        hex::encode(event_hash),
        hex::encode(tx_template_hash),
        local_state.signatures.len(),
        changed
    );

    // Step 2: Check if completed
    if local_state.completion.is_some() {
        debug!(
            "event already completed event_hash={} tx_template_hash={}",
            hex::encode(event_hash),
            hex::encode(tx_template_hash)
        );
        return Ok(());
    }

    // Step 3: If we haven't signed yet, sign and broadcast
    let has_my_sig = local_state.signatures.iter()
        .any(|s| s.signer_peer_id == *local_peer_id);

    if !has_my_sig {
        if let (Some(signing_event), Some(kpsbt_blob)) =
            (&local_state.signing_event, &local_state.kpsbt_blob)
        {
            // Verify our tx_template matches
            let our_tx_template_hash = pskt_multisig::tx_template_hash(
                &pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?
            )?;

            if our_tx_template_hash != tx_template_hash {
                warn!(
                    "tx_template_hash mismatch - node may be out of sync event_hash={} received={} computed={}",
                    hex::encode(event_hash),
                    hex::encode(tx_template_hash),
                    hex::encode(our_tx_template_hash)
                );
                return Ok(());
            }

            // Sign and add to CRDT
            if let Ok(signatures) = sign_event(app_config, signing_event, kpsbt_blob) {
                for (input_index, pubkey, signature) in signatures {
                    storage.add_signature_to_crdt(
                        &event_hash,
                        &tx_template_hash,
                        input_index,
                        &pubkey,
                        &signature,
                        local_peer_id,
                    )?;
                }

                // Broadcast updated state
                broadcast_local_state(transport, storage, &event_hash, &tx_template_hash, local_peer_id).await?;
            }
        }
    }

    // Step 4: Check threshold and attempt submission
    let required = usize::from(app_config.service.pskt.sig_op_count);
    if let Some(kpsbt_blob) = &local_state.kpsbt_blob {
        let pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
        let input_count = pskt.inputs.len();

        if storage.crdt_has_threshold(&event_hash, &tx_template_hash, input_count, required)? {
            info!(
                "threshold reached, attempting submission event_hash={} sigs={} required={}",
                hex::encode(event_hash),
                local_state.signatures.len(),
                required
            );

            match attempt_submission(app_config, flow, storage, &event_hash, &tx_template_hash).await {
                Ok(tx_id) => {
                    info!(
                        "transaction submitted event_hash={} tx_id={}",
                        hex::encode(event_hash),
                        tx_id
                    );

                    let blue_score = flow.rpc().get_virtual_selected_parent_blue_score().await.ok();
                    storage.mark_crdt_completed(
                        &event_hash,
                        &tx_template_hash,
                        tx_id,
                        local_peer_id,
                        blue_score,
                    )?;

                    broadcast_local_state(transport, storage, &event_hash, &tx_template_hash, local_peer_id).await?;
                }
                Err(err) => {
                    debug!(
                        "submission failed (likely already submitted) event_hash={} error={}",
                        hex::encode(event_hash),
                        err
                    );
                }
            }
        }
    }

    Ok(())
}

fn sign_event(
    app_config: &AppConfig,
    signing_event: &igra_core::domain::SigningEvent,
    kpsbt_blob: &[u8],
) -> Result<Vec<(u32, Vec<u8>, Vec<u8>)>, ThresholdError> {
    let hd = app_config.service.hd.as_ref()
        .ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;

    let key_data = hd.decrypt_mnemonics()?;
    let key_data = key_data.first()
        .ok_or_else(|| ThresholdError::ConfigError("missing mnemonic".to_string()))?;

    let payment_secret = hd.passphrase.as_deref().map(Secret::from);
    let keypair = igra_core::foundation::hd::derive_keypair_from_key_data(
        key_data,
        &signing_event.derivation_path,
        payment_secret.as_ref(),
    )?;

    let signer = ThresholdSigner::new(keypair);
    let pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;

    let mut signatures = Vec::new();
    for (input_index, _input) in pskt.inputs.iter().enumerate() {
        let sig_result = signer.sign_input(input_index as u32, &pskt)?;
        signatures.push((
            input_index as u32,
            signer.pubkey().serialize().to_vec(),
            sig_result,
        ));
    }

    Ok(signatures)
}

async fn attempt_submission(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    storage: &Arc<RocksStorage>,
    event_hash: &Hash32,
    tx_template_hash: &Hash32,
) -> Result<igra_core::foundation::TransactionId, ThresholdError> {
    let state = storage.get_event_crdt(event_hash, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;

    let kpsbt_blob = state.kpsbt_blob
        .ok_or_else(|| ThresholdError::Message("missing KPSBT".to_string()))?;

    let signing_event = state.signing_event
        .ok_or_else(|| ThresholdError::Message("missing signing event".to_string()))?;

    let partials: Vec<igra_core::domain::PartialSigRecord> = state.signatures
        .iter()
        .map(|s| igra_core::domain::PartialSigRecord {
            signer_peer_id: s.signer_peer_id.clone(),
            input_index: s.input_index,
            pubkey: s.pubkey.clone(),
            signature: s.signature.clone(),
            timestamp_nanos: s.timestamp_nanos,
        })
        .collect();

    let pskt = pskt_multisig::apply_partial_sigs(&kpsbt_blob, &partials)?;

    let required = usize::from(app_config.service.pskt.sig_op_count);
    let ordered_pubkeys = crate::service::coordination::finalization::derive_ordered_pubkeys(
        &app_config.service,
        &signing_event,
    )?;
    let params = crate::service::coordination::finalization::params_for_network_id(
        app_config.iroh.network_id,
    );

    let request_id = igra_core::foundation::RequestId::from(hex::encode(event_hash));

    flow.finalize_and_submit(&request_id, pskt, required, &ordered_pubkeys, params).await
}

async fn broadcast_local_state(
    transport: &Arc<dyn Transport>,
    storage: &Arc<RocksStorage>,
    event_hash: &Hash32,
    tx_template_hash: &Hash32,
    local_peer_id: &PeerId,
) -> Result<(), ThresholdError> {
    let state = storage.get_event_crdt(event_hash, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;

    let crdt_state = EventCrdtState {
        signatures: state.signatures.iter().map(|s| {
            igra_core::infrastructure::transport::iroh::messages::CrdtSignature {
                input_index: s.input_index,
                pubkey: s.pubkey.clone(),
                signature: s.signature.clone(),
                timestamp_nanos: s.timestamp_nanos,
            }
        }).collect(),
        completion: state.completion.map(|c| {
            igra_core::infrastructure::transport::iroh::messages::CompletionRecord {
                tx_id: *c.tx_id.as_hash(),
                submitter_peer_id: c.submitter_peer_id,
                timestamp_nanos: c.timestamp_nanos,
                blue_score: c.blue_score,
            }
        }),
        version: 0,
    };

    let _broadcast = EventStateBroadcast {
        event_hash: *event_hash,
        tx_template_hash: *tx_template_hash,
        state: crdt_state,
        sender_peer_id: local_peer_id.clone(),
    };

    // TODO: transport.publish_crdt_state(broadcast).await?;

    Ok(())
}
```

### 8.2 `igra-service/src/service/coordination/loop.rs`

**Replace** the entire coordination loop with CRDT-based handling:

```rust
//! CRDT-based coordination loop
//!
//! This replaces the old proposal-ack based loop.

use crate::service::coordination::crdt_handler::handle_crdt_event;

pub async fn run_coordination_loop(
    app_config: Arc<AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<RocksStorage>,
    local_peer_id: PeerId,
    group_id: Hash32,
) -> Result<(), ThresholdError> {
    let message_verifier = Arc::new(CompositeVerifier::new(/* ... */));
    let mut subscription = transport.subscribe_group(group_id).await?;

    info!("coordination loop started group_id={} peer_id={}", hex::encode(group_id), local_peer_id);

    loop {
        let Some(item) = subscription.next().await else { break; };
        let envelope = match item {
            Ok(envelope) => envelope,
            Err(err) => {
                warn!("message stream error: {}", err);
                continue;
            }
        };

        match envelope.payload {
            TransportMessage::EventStateBroadcast(broadcast) => {
                if let Err(err) = handle_crdt_event(
                    &app_config,
                    &flow,
                    &transport,
                    &storage,
                    &local_peer_id,
                    &message_verifier,
                    broadcast,
                ).await {
                    warn!(
                        "CRDT event handling error event_hash={} error={}",
                        hex::encode(broadcast.event_hash),
                        err
                    );
                }
            }
            TransportMessage::StateSyncRequest(req) => {
                // Handle anti-entropy request
                // TODO: implement
            }
            TransportMessage::StateSyncResponse(resp) => {
                // Handle anti-entropy response
                // TODO: implement
            }
        }
    }

    Ok(())
}
```

### 8.3 Anti-entropy Loop

Add periodic state synchronization:

```rust
/// Anti-entropy: periodically sync state with peers
pub async fn run_anti_entropy_loop(
    storage: Arc<RocksStorage>,
    transport: Arc<dyn Transport>,
    local_peer_id: PeerId,
    interval_secs: u64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        match storage.list_pending_event_crdts() {
            Ok(pending) => {
                for state in pending {
                    if let Err(err) = broadcast_local_state(
                        &transport,
                        &storage,
                        &state.event_hash,
                        &state.tx_template_hash,
                        &local_peer_id,
                    ).await {
                        debug!(
                            "anti-entropy broadcast failed event_hash={} error={}",
                            hex::encode(state.event_hash),
                            err
                        );
                    }
                }
            }
            Err(err) => {
                warn!("failed to list pending events for anti-entropy: {}", err);
            }
        }
    }
}
```

---

## 9. Tests

Tests are organized by location and scope, following the existing test structure.

### 9.1 Unit Tests: `igra-core/tests/unit/domain_crdt.rs`

Pure domain logic tests with no I/O dependencies.

```rust
//! Unit tests for CRDT domain logic

use igra_core::domain::crdt::{GSet, LWWRegister, EventCrdt, SignatureRecord, merge_event_states};
use igra_core::foundation::{Hash32, PeerId, TransactionId};

// Test GSet CRDT properties
#[test]
fn test_gset_merge_properties() {
    // Test commutativity
    let mut a = GSet::from_iter(vec![1, 2, 3]);
    let b = GSet::from_iter(vec![3, 4, 5]);
    let mut c = GSet::from_iter(vec![3, 4, 5]);
    let d = GSet::from_iter(vec![1, 2, 3]);
    a.merge(&b);
    c.merge(&d);
    assert_eq!(a.len(), c.len()); // Commutative

    // Test idempotency
    let before = a.len();
    a.merge(&a.clone());
    assert_eq!(before, a.len()); // Idempotent
}

// Test EventCrdt threshold detection
#[test]
fn test_threshold_detection() {
    let event_hash: Hash32 = [1u8; 32];
    let tx_hash: Hash32 = [2u8; 32];
    let mut crdt = EventCrdt::new(event_hash, tx_hash);

    // 2-of-3 threshold, 2 inputs
    let input_count = 2;
    let required = 2;

    // Add signatures for input 0
    crdt.add_signature(SignatureRecord {
        input_index: 0,
        pubkey: vec![1],
        signature: vec![10],
        signer_peer_id: Some(PeerId::from("signer1")),
        timestamp_nanos: 1000,
    });
    crdt.add_signature(SignatureRecord {
        input_index: 0,
        pubkey: vec![2],
        signature: vec![20],
        signer_peer_id: Some(PeerId::from("signer2")),
        timestamp_nanos: 1001,
    });

    // Not enough yet (missing input 1)
    assert!(!crdt.has_threshold(input_count, required));

    // Add signatures for input 1
    crdt.add_signature(SignatureRecord {
        input_index: 1,
        pubkey: vec![1],
        signature: vec![11],
        signer_peer_id: Some(PeerId::from("signer1")),
        timestamp_nanos: 1002,
    });
    crdt.add_signature(SignatureRecord {
        input_index: 1,
        pubkey: vec![2],
        signature: vec![21],
        signer_peer_id: Some(PeerId::from("signer2")),
        timestamp_nanos: 1003,
    });

    // Now we have threshold
    assert!(crdt.has_threshold(input_count, required));
}

// Test that different tx_template_hash prevents merge
#[test]
fn test_incompatible_tx_template_no_merge() {
    let event_hash: Hash32 = [1u8; 32];
    let tx_hash_a: Hash32 = [2u8; 32];
    let tx_hash_b: Hash32 = [3u8; 32];

    let mut crdt_a = EventCrdt::new(event_hash, tx_hash_a);
    let crdt_b = EventCrdt::new(event_hash, tx_hash_b);

    crdt_a.add_signature(SignatureRecord {
        input_index: 0,
        pubkey: vec![1],
        signature: vec![10],
        signer_peer_id: Some(PeerId::from("signer1")),
        timestamp_nanos: 1000,
    });

    // Merge should not add anything (different tx_template_hash)
    let changes = crdt_a.merge(&crdt_b);
    assert_eq!(changes, 0);
}
```

### 9.2 Integration Tests: `igra-core/tests/integration/crdt_storage.rs`

Storage layer integration tests.

```rust
//! Integration tests for CRDT storage operations

use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::transport::iroh::messages::{EventCrdtState, CrdtSignature};
use tempfile::tempdir;
use std::sync::Arc;

#[tokio::test]
async fn test_crdt_storage_roundtrip() {
    let dir = tempdir().unwrap();
    let storage = RocksStorage::open(dir.path()).unwrap();

    let event_hash = [1u8; 32];
    let tx_hash = [2u8; 32];
    let incoming = EventCrdtState {
        signatures: vec![CrdtSignature {
            input_index: 0,
            pubkey: vec![1],
            signature: vec![10],
            timestamp_nanos: 1000,
        }],
        completion: None,
        version: 0,
    };

    let (state, changed) = storage.merge_event_crdt(&event_hash, &tx_hash, &incoming, None, None).unwrap();
    assert!(changed);
    assert_eq!(state.signatures.len(), 1);

    // Retrieve and verify
    let retrieved = storage.get_event_crdt(&event_hash, &tx_hash).unwrap().unwrap();
    assert_eq!(state.signatures.len(), retrieved.signatures.len());
}

#[tokio::test]
async fn test_concurrent_crdt_updates() {
    let dir = tempdir().unwrap();
    let storage = Arc::new(RocksStorage::open(dir.path()).unwrap());
    let event_hash = [1u8; 32];
    let tx_hash = [2u8; 32];

    let mut handles = vec![];
    for i in 0..10u32 {
        let storage = storage.clone();
        handles.push(tokio::spawn(async move {
            let incoming = EventCrdtState {
                signatures: vec![CrdtSignature {
                    input_index: 0,
                    pubkey: vec![i as u8],
                    signature: vec![i as u8 * 10],
                    timestamp_nanos: 1000 + i as u64,
                }],
                completion: None,
                version: 0,
            };
            storage.merge_event_crdt(&event_hash, &tx_hash, &incoming, None, None)
        }));
    }

    for h in handles {
        h.await.unwrap().unwrap();
    }

    let final_state = storage.get_event_crdt(&event_hash, &tx_hash).unwrap().unwrap();
    assert_eq!(final_state.signatures.len(), 10);
}
```

### 9.3 E2E Tests: `igra-service/tests/integration/crdt_e2e.rs`

Service-level end-to-end tests.

```rust
//! End-to-end tests for CRDT coordination

/// Simulate 3 signers with network delays
#[tokio::test]
async fn test_three_signer_convergence() {
    // Create 3 in-memory storages (simulating 3 nodes)
    // Each adds their signature
    // Simulate gossip with random delays
    // Verify all converge to same state
}

/// Simulate network partition and recovery
#[tokio::test]
async fn test_partition_recovery() {
    // Create partition A (2 nodes) and partition B (1 node)
    // Each partition evolves independently
    // Simulate partition heal
    // Verify convergence
}

/// Simulate a slow/offline node rejoining
#[tokio::test]
async fn test_slow_node_catchup() {
    // 2 nodes complete signing
    // 1 node is offline
    // Event completes
    // Offline node comes back
    // Verify it catches up via anti-entropy
}
```

### 9.4 Chaos Tests: `igra-service/tests/integration/crdt_partition.rs`

Network partition and chaos testing.

```rust
//! Chaos tests for CRDT resilience

/// Random message loss
#[tokio::test]
async fn test_random_message_loss() {
    // 50% message drop rate
    // Verify eventual convergence
}

/// Random node crashes
#[tokio::test]
async fn test_random_node_crashes() {
    // Random node restarts
    // Verify no data loss (persistence)
    // Verify convergence after restart
}

/// Out of order message delivery
#[tokio::test]
async fn test_out_of_order_messages() {
    // Deliver messages in random order
    // Verify convergence (CRDT property)
}
```

### 9.5 Property-Based Tests: `igra-core/tests/unit/domain_crdt_proptest.rs`

Using proptest for property verification.

```rust
use proptest::prelude::*;
use igra_core::domain::crdt::{EventCrdt, SignatureRecord, merge_event_states};
use igra_core::foundation::Hash32;

proptest! {
    /// Merge is commutative
    #[test]
    fn merge_commutative(
        sigs_a in prop::collection::vec(any::<SignatureRecord>(), 0..10),
        sigs_b in prop::collection::vec(any::<SignatureRecord>(), 0..10),
    ) {
        let event_hash: Hash32 = [0u8; 32];
        let tx_hash: Hash32 = [1u8; 32];
        let mut a = EventCrdt::new(event_hash, tx_hash);
        let mut b = EventCrdt::new(event_hash, tx_hash);

        for s in &sigs_a { a.add_signature(s.clone()); }
        for s in &sigs_b { b.add_signature(s.clone()); }

        let ab = merge_event_states(&a, &b);
        let ba = merge_event_states(&b, &a);

        prop_assert_eq!(ab.signature_count(), ba.signature_count());
    }

    /// Merge is idempotent
    #[test]
    fn merge_idempotent(
        sigs in prop::collection::vec(any::<SignatureRecord>(), 0..10),
    ) {
        let event_hash: Hash32 = [0u8; 32];
        let tx_hash: Hash32 = [1u8; 32];
        let mut crdt = EventCrdt::new(event_hash, tx_hash);
        for s in &sigs { crdt.add_signature(s.clone()); }

        let before = crdt.signature_count();
        crdt.merge(&crdt.clone());
        let after = crdt.signature_count();

        prop_assert_eq!(before, after);
    }
}
```

### 9.6 Running Tests

```bash
# Unit tests only
cargo test -p igra-core crdt

# Integration tests
cargo test -p igra-service --test crdt_integration

# All tests with verbose output
cargo test --workspace -- --nocapture

# With nextest (faster)
cargo nextest run -p igra-core -p igra-service
```

---

## 10. Verification Checklist

### Pre-Implementation

- [ ] Read and understand this document
- [ ] Understand CRDT properties (commutativity, associativity, idempotency)
- [ ] Review current codebase structure
- [ ] Set up development environment

### Phase 1: CRDT Data Structures

- [ ] `gset.rs` created with all tests passing
- [ ] `lww.rs` created with all tests passing
- [ ] `event_state.rs` created with all tests passing
- [ ] `mod.rs` exports all types correctly
- [ ] Unit tests cover all edge cases
- [ ] Property-based tests pass

### Phase 2: Transport Layer

- [ ] Old message types deleted from `messages.rs`
- [ ] New CRDT message types added
- [ ] Serialization/deserialization tested
- [ ] Message size is reasonable (< 64KB typical)

### Phase 3: Storage Layer

- [ ] Old column families deleted
- [ ] New `CF_EVENT_CRDT` column family added
- [ ] `merge_event_crdt` is atomic and correct
- [ ] Concurrent access tested
- [ ] Performance acceptable (< 10ms per merge)

### Phase 4: Coordination Loop

- [ ] Old coordination files deleted (see Section 6.6)
- [ ] CRDT handler integrated
- [ ] Anti-entropy loop running
- [ ] Logging is comprehensive
- [ ] Metrics updated

### Phase 5: Testing

- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Network simulation tests pass
- [ ] Chaos tests pass
- [ ] Performance benchmarks acceptable

### Pre-Deployment

- [ ] Code reviewed
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Logging/metrics in place

---

## 11. Implementation Plan

Since this is a new product (not in production), we do a **clean replacement**:

### Step 1: Delete Old Code

Remove files listed in Section 6.6:
- Old message types (Propose, Ack, PartialSig, Finalize)
- Old storage methods (proposals, acks, partial_sigs)
- Old coordination loop logic
- Old column families

### Step 2: Implement CRDT

Following the order in this document:
1. Domain layer (Section 5) - pure CRDT types
2. Infrastructure layer (Section 6) - storage and transport
3. Application layer (Section 7) - coordinator
4. Service layer (Section 8) - handler and loop

### Step 3: Test

Run test suite (Section 9):
- Unit tests for CRDT properties
- Integration tests for storage
- E2E tests for multi-signer scenarios

### Step 4: Deploy

Deploy to testnet, then mainnet. No gradual migration needed since there's no existing data to migrate

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **CRDT** | Conflict-free Replicated Data Type - data structure that can be replicated and merged without conflicts |
| **G-Set** | Grow-only Set - CRDT where elements can only be added |
| **LWW-Register** | Last-Writer-Wins Register - CRDT for single values, later timestamp wins |
| **Gossip** | Protocol where nodes randomly share state with peers |
| **Anti-entropy** | Periodic background synchronization to ensure consistency |
| **Eventual consistency** | All replicas will eventually have the same state |
| **Threshold** | Minimum number of signatures required (M in M-of-N) |

## Appendix B: References

1. Shapiro et al., "A comprehensive study of Convergent and Commutative Replicated Data Types" (2011)
2. [CRDT.tech](https://crdt.tech/) - Community resources
3. Kaspa UTXO model documentation
4. Existing igra codebase documentation

## Appendix C: Contact

For questions about this implementation:
- Create an issue in the repository
- Tag with `crdt-implementation` label
- Include relevant code snippets and test failures

---

*Document Version: 1.0*
*Created: 2026-01-12*
*Author: Development Team*
