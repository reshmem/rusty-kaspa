# Two-Phase Protocol Implementation

Step-by-step implementation plan for the Two-Phase UTXO Consensus Protocol.

This plan follows CODE-GUIDELINE.md and implements docs/protocol/two-phase-consensus.md specification v1.1.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Phase 1: Domain Types](#2-phase-1-domain-types)
3. [Phase 2: Storage Layer](#3-phase-2-storage-layer)
4. [Phase 3: Transport Layer](#4-phase-3-transport-layer)
5. [Phase 4: Protocol Handlers](#5-phase-4-protocol-handlers)
6. [Phase 5: Event Processor Integration](#6-phase-5-event-processor-integration)
7. [Phase 6: Testing](#7-phase-6-testing)
8. [Configuration](#8-configuration)
9. [File Change Summary](#9-file-change-summary)
10. [Verification Checklist](#10-verification-checklist)

---

## 1. Overview

### 1.1 What We're Building

A two-phase consensus protocol that:
- **Phase 1 (Propose)**: Signers exchange `tx_template_hash` proposals without signing
- **Phase 2 (Commit)**: Once quorum is reached, signers lock and sign the canonical hash

### 1.2 Key Safety Properties

- At most ONE signature per signer per event
- No commit without quorum (`>= COMMIT_QUORUM`)
- **v1 (Profile A)**: `COMMIT_QUORUM = group.threshold_m` and assumes non-equivocation (crash-fault tolerant).
- **vNext (Profile B)**: `COMMIT_QUORUM = 2f+1` and the commit object is a `LockCert` over `(event_id, round, kaspa_anchor, outpoints, tx_template_hash)` (BFT).
- Explicit failure (Abandoned) instead of silent stalls

### 1.3 Implementation Order

```
Phase 1: Domain Types (pure, no I/O)
    ↓
Phase 2: Storage Layer (PhaseStorage trait + implementations)
    ↓
Phase 3: Transport Layer (ProposalBroadcast message)
    ↓
Phase 4: Protocol Handlers (free functions)
    ↓
Phase 5: Event Processor Integration
    ↓
Phase 6: Testing
```

---

## 2. Phase 1: Domain Types

**Goal**: Define pure types and algorithms in `igra-core/src/domain/`.

### 2.1 Create Module Structure

```
igra-core/src/domain/coordination/
├── mod.rs              # Public exports
├── phase.rs            # EventPhase enum, EventPhaseState struct
├── proposal.rs         # Proposal struct, ProposalError, validation
├── selection.rs        # quorum_hash() algorithm
└── config.rs           # Configuration constants and structs
```

### 2.2 File: `igra-core/src/domain/coordination/config.rs`

```rust
//! Configuration constants and structs for two-phase protocol.

use serde::{Deserialize, Serialize};

/// Maximum UTXOs allowed per proposal (DoS bound)
pub const MAX_UTXOS_PER_PROPOSAL: usize = 100;

/// Maximum outputs allowed per proposal
pub const MAX_OUTPUTS_PER_PROPOSAL: usize = 16;

/// Maximum KPSBT blob size in bytes
pub const MAX_KPSBT_SIZE: usize = 64 * 1024;

/// Maximum proposal size in bytes (serialized)
pub const MAX_PROPOSAL_SIZE_BYTES: usize = 64 * 1024;

/// Default proposal timeout in milliseconds
pub const DEFAULT_PROPOSAL_TIMEOUT_MS: u64 = 5000;

/// Default minimum input depth (blue score)
pub const DEFAULT_MIN_INPUT_SCORE_DEPTH: u64 = 300;

/// Anti-entropy: max events per sync request
pub const MAX_SYNC_EVENTS_PER_TICK: usize = 64;

/// Anti-entropy: max proposals per event per response
pub const MAX_PROPOSALS_PER_EVENT_PER_RESPONSE: usize = 20;

/// Cooldown for state sync requests per (peer, event_id)
pub const STATE_SYNC_COOLDOWN_MS: u64 = 2000;

/// Retry configuration for Failed → Proposing transitions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub jitter_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 5000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter_ms: 250,
        }
    }
}

impl RetryConfig {
    /// Calculate delay for a given retry count
    pub fn delay_for_retry(&self, retry_count: u32) -> u64 {
        // First retry uses base_delay_ms, then exponential backoff.
        let exponent = retry_count.saturating_sub(1) as i32;
        let base = (self.base_delay_ms as f64)
            * self.backoff_multiplier.powi(exponent);
        let clamped = base.min(self.max_delay_ms as f64) as u64;
        // Jitter is applied by caller using random
        clamped
    }
}

/// Two-phase protocol configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoPhaseConfig {
    /// Timeout for proposal collection phase
    pub proposal_timeout_ms: u64,

    /// Votes required to commit.
    ///
    /// v1: derive from `GroupConfig.threshold_m` (do not hardcode).
    pub commit_quorum: u16,

    /// Minimum depth for UTXO inputs.
    ///
    /// If `0`, derive from `max(DEFAULT_MIN_INPUT_SCORE_DEPTH, group.finality_blue_score_threshold)`.
    pub min_input_score_depth: u64,

    /// Retry configuration
    pub retry: RetryConfig,

    /// Revalidate inputs before signing (mandatory in production)
    pub revalidate_inputs_on_commit: bool,
}

impl Default for TwoPhaseConfig {
    fn default() -> Self {
        Self {
            proposal_timeout_ms: DEFAULT_PROPOSAL_TIMEOUT_MS,
            commit_quorum: 0, // Must be derived from GroupConfig.threshold_m
            min_input_score_depth: 0, // Auto (derive from group)
            retry: RetryConfig::default(),
            revalidate_inputs_on_commit: true,
        }
    }
}
```

### 2.3 File: `igra-core/src/domain/coordination/phase.rs`

```rust
//! Event phase definitions and state machine.

use serde::{Deserialize, Serialize};

use crate::foundation::Hash32;

/// Event phase in the two-phase protocol
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventPhase {
    /// No knowledge of this event
    #[default]
    Unknown = 0,
    /// Collecting proposals, NOT signing
    Proposing = 1,
    /// Canonical hash locked, signing in progress
    Committed = 2,
    /// Event fully processed (terminal success)
    Completed = 3,
    /// No quorum / invalid inputs; retryable
    Failed = 4,
    /// Max retries exceeded (terminal failure)
    Abandoned = 5,
}

impl EventPhase {
    /// Check if transition from self to target is valid
    pub fn can_transition_to(&self, target: EventPhase) -> bool {
        use EventPhase::*;
        matches!(
            (*self, target),
            (Unknown, Proposing)
                | (Unknown, Committed)  // Fast-forward from commit broadcast
                | (Proposing, Committed)
                | (Proposing, Failed)
                | (Committed, Completed)
                | (Failed, Proposing)   // Retry
                | (Failed, Abandoned)   // Max retries exceeded
        )
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, EventPhase::Completed | EventPhase::Abandoned)
    }

    /// Check if this phase accepts proposals
    pub fn accepts_proposals(&self) -> bool {
        matches!(self, EventPhase::Proposing)
    }
}

/// Persistent state for event phase tracking
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPhaseState {
    /// Current phase
    pub phase: EventPhase,

    /// Timestamp when current phase started (nanoseconds)
    pub phase_started_at_ns: u64,

    /// Current proposal round (monotonic, starts at 0)
    pub round: u32,

    /// Canonical hash (set when Committed)
    pub canonical_hash: Option<Hash32>,

    /// Hash we proposed (if any)
    pub own_proposal_hash: Option<Hash32>,

    /// Number of retries (for backoff/abandonment)
    pub retry_count: u32,
}

impl EventPhaseState {
    /// Create new state at Proposing phase
    pub fn new_proposing(now_ns: u64) -> Self {
        Self {
            phase: EventPhase::Proposing,
            phase_started_at_ns: now_ns,
            round: 0,
            canonical_hash: None,
            own_proposal_hash: None,
            retry_count: 0,
        }
    }

    /// Create new state at a specific round (for late joiners)
    pub fn new_at_round(round: u32, now_ns: u64) -> Self {
        Self {
            phase: EventPhase::Proposing,
            phase_started_at_ns: now_ns,
            round,
            canonical_hash: None,
            own_proposal_hash: None,
            retry_count: 0,
        }
    }

    /// Check if timeout has expired
    pub fn is_timeout_expired(&self, now_ns: u64, timeout_ms: u64) -> bool {
        let elapsed_ms = (now_ns.saturating_sub(self.phase_started_at_ns)) / 1_000_000;
        elapsed_ms >= timeout_ms
    }
}

/// Context attached to commit broadcasts (PhaseContext in spec)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseContext {
    pub round: u32,
    pub phase: EventPhase,
    /// Optional Kaspa anchor for audit/recovery
    pub kaspa_anchor: Option<KaspaAnchorRef>,
}

/// Reference to Kaspa chain state at proposal time
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KaspaAnchorRef {
    /// Tip score observed when building the proposal (DAA/blue score)
    pub tip_score: u64,
    /// Optional block hash
    pub tip_hash: Option<Hash32>,
}
```

### 2.4 File: `igra-core/src/domain/coordination/proposal.rs`

```rust
//! Proposal structure and validation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::pskt::multisig as pskt_multisig;
use crate::domain::pskt::PsktOutputParams;
use crate::domain::CrdtSigningMaterial;
use crate::foundation::{Hash32, PeerId, ThresholdError};

use super::config::{MAX_KPSBT_SIZE, MAX_OUTPUTS_PER_PROPOSAL, MAX_UTXOS_PER_PROPOSAL};
use super::phase::KaspaAnchorRef;

/// UTXO input reference for proposal reproducibility
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInput {
    /// Transaction ID
    pub txid: Hash32,
    /// Output index
    pub index: u32,
    /// Amount in sompi
    pub amount: u64,
    /// Script public key version
    pub script_public_key_version: u16,
    /// Script public key bytes (for validation)
    pub script_public_key_script: Vec<u8>,
    /// Block DAA score when this UTXO was created
    pub block_daa_score: u64,
}

/// Outpoint reference (for Profile B lock certificates)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutpointRef {
    pub txid: Hash32,
    pub index: u32,
}

impl From<&UtxoInput> for OutpointRef {
    fn from(utxo: &UtxoInput) -> Self {
        Self {
            txid: utxo.txid,
            index: utxo.index,
        }
    }
}

/// A proposal for a transaction template
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique event identifier
    pub event_id: Hash32,

    /// Proposal round (monotonic)
    pub round: u32,

    /// Hash of the proposed transaction template
    pub tx_template_hash: Hash32,

    /// Serialized PSKT for verification and signing
    pub kpsbt_blob: Vec<u8>,

    /// UTXOs used to build the template
    pub utxos_used: Vec<UtxoInput>,

    /// Outputs for verification (destination + change)
    pub outputs: Vec<PsktOutputParams>,

    /// Event data (destination, amount, proof)
    pub signing_material: CrdtSigningMaterial,

    /// Peer ID of proposer (must match the transport envelope sender)
    pub proposer_peer_id: PeerId,

    /// Wall-clock timestamp (nanoseconds, for audit only)
    pub timestamp_ns: u64,

    /// Optional Kaspa anchor reference
    pub kaspa_anchor: Option<KaspaAnchorRef>,
}

impl Proposal {
    /// Compute `tx_template_hash` from the PSKT blob using the same logic as the signing path.
    pub fn computed_hash(&self) -> Result<Hash32, ThresholdError> {
        let signer_pskt = pskt_multisig::deserialize_pskt_signer(&self.kpsbt_blob)?;
        pskt_multisig::tx_template_hash(&signer_pskt)
    }

    /// Verify `tx_template_hash` matches the PSKT-derived hash.
    pub fn verify_hash_consistency(&self) -> Result<bool, ThresholdError> {
        Ok(self.tx_template_hash == self.computed_hash()?)
    }

    /// Validate proposal structure (pure, no I/O)
    pub fn validate_structure(&self) -> Result<(), ProposalValidationError> {
        // Check UTXOs
        if self.utxos_used.is_empty() {
            return Err(ProposalValidationError::NoUtxos);
        }
        if self.utxos_used.len() > MAX_UTXOS_PER_PROPOSAL {
            return Err(ProposalValidationError::TooManyUtxos {
                count: self.utxos_used.len(),
                max: MAX_UTXOS_PER_PROPOSAL,
            });
        }

        // Check outputs
        if self.outputs.is_empty() {
            return Err(ProposalValidationError::NoOutputs);
        }
        if self.outputs.len() > MAX_OUTPUTS_PER_PROPOSAL {
            return Err(ProposalValidationError::TooManyOutputs {
                count: self.outputs.len(),
                max: MAX_OUTPUTS_PER_PROPOSAL,
            });
        }

        // Check KPSBT size
        if self.kpsbt_blob.is_empty() {
            return Err(ProposalValidationError::EmptyKpsbt);
        }
        if self.kpsbt_blob.len() > MAX_KPSBT_SIZE {
            return Err(ProposalValidationError::KpsbtTooLarge {
                size: self.kpsbt_blob.len(),
                max: MAX_KPSBT_SIZE,
            });
        }

        // Check hash consistency
        if !self.verify_hash_consistency() {
            return Err(ProposalValidationError::HashMismatch);
        }

        Ok(())
    }

    /// Get all outpoints used in this proposal
    pub fn outpoints(&self) -> Vec<OutpointRef> {
        self.utxos_used.iter().map(OutpointRef::from).collect()
    }

    /// Calculate total input amount
    pub fn total_input_amount(&self) -> u64 {
        self.utxos_used.iter().map(|u| u.amount).sum()
    }
}

/// Errors during proposal validation
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProposalValidationError {
    #[error("proposal has no UTXOs")]
    NoUtxos,

    #[error("too many UTXOs: {count} > {max}")]
    TooManyUtxos { count: usize, max: usize },

    #[error("proposal has no outputs")]
    NoOutputs,

    #[error("too many outputs: {count} > {max}")]
    TooManyOutputs { count: usize, max: usize },

    #[error("KPSBT is empty")]
    EmptyKpsbt,

    #[error("KPSBT too large: {size} > {max} bytes")]
    KpsbtTooLarge { size: usize, max: usize },

    // NOTE: group membership, signing-material proofs, and output/policy checks are
    // application-level validation (service layer) and should not live in this pure struct validator.
}

/// Transport wrapper for proposal broadcast
pub type ProposalBroadcast = Proposal;
```

### 2.5 File: `igra-core/src/domain/coordination/selection.rs`

```rust
//! Canonical hash selection algorithm.

use std::cmp::Reverse;
use std::collections::HashMap;

use crate::foundation::Hash32;

use super::proposal::Proposal;

/// Vote statistics for a single hash
#[derive(Debug, Clone)]
struct HashVoteStats {
    hash: Hash32,
    vote_count: usize,
    /// Lowest proposer ID for deterministic tie-breaking
    lowest_proposer_id: String,
}

impl HashVoteStats {
    /// Deterministic ordering key: higher votes wins, then lower hash, then lower proposer
    fn canonical_key(&self) -> (Reverse<usize>, Hash32, String) {
        (Reverse(self.vote_count), self.hash, self.lowest_proposer_id.clone())
    }
}

/// Select canonical hash if quorum is reached.
///
/// Returns `Some(hash)` if at least one hash has >= commit_quorum votes.
/// Returns `None` if no hash has reached quorum.
///
/// # Arguments
/// * `proposals` - All proposals for the current round
/// * `commit_quorum` - Minimum votes required to commit
///
/// # Safety
/// This function enforces the core safety rule: NO commit without quorum.
pub fn quorum_hash(proposals: &[Proposal], commit_quorum: usize) -> Option<Hash32> {
    if proposals.is_empty() || commit_quorum == 0 {
        return None;
    }

    // Aggregate votes per hash
    let mut stats_by_hash: HashMap<Hash32, HashVoteStats> = HashMap::new();

    for p in proposals {
        let stats = stats_by_hash
            .entry(p.tx_template_hash)
            .or_insert_with(|| HashVoteStats {
                hash: p.tx_template_hash,
                vote_count: 0,
                lowest_proposer_id: p.proposer_peer_id.as_str().to_string(),
            });
        stats.vote_count += 1;

        // Track lowest proposer for tie-breaking
        if p.proposer_peer_id.as_str() < stats.lowest_proposer_id.as_str() {
            stats.lowest_proposer_id = p.proposer_peer_id.as_str().to_string();
        }
    }

    // Find hash with quorum (if any)
    stats_by_hash
        .values()
        .filter(|s| s.vote_count >= commit_quorum)
        .min_by_key(|s| s.canonical_key())
        .map(|s| s.hash)
}

/// Select the winning proposal instance for a given canonical hash.
///
/// Returns the proposal with the lowest proposer_peer_id for determinism.
pub fn select_winning_proposal<'a>(
    proposals: &'a [Proposal],
    canonical_hash: Hash32,
) -> Option<&'a Proposal> {
    proposals
        .iter()
        .filter(|p| p.tx_template_hash == canonical_hash)
        .min_by_key(|p| p.proposer_peer_id.as_str())
}

/// Count unique hashes in proposals (for metrics)
pub fn unique_hash_count(proposals: &[Proposal]) -> usize {
    proposals
        .iter()
        .map(|p| p.tx_template_hash)
        .collect::<std::collections::HashSet<_>>()
        .len()
}

/// Count votes for each hash (for debugging/metrics)
pub fn vote_counts(proposals: &[Proposal]) -> HashMap<Hash32, usize> {
    let mut counts = HashMap::new();
    for p in proposals {
        *counts.entry(p.tx_template_hash).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep selection tests independent of the full Proposal schema (which is large and has
    /// non-trivial fixture requirements like valid `CrdtSigningMaterial`).
    #[derive(Clone, Debug)]
    struct Vote {
        tx_template_hash: Hash32,
        proposer_id: &'static str,
    }

    fn quorum_hash_votes(votes: &[Vote], commit_quorum: usize) -> Option<Hash32> {
        if votes.is_empty() || commit_quorum == 0 {
            return None;
        }

        let mut stats_by_hash: HashMap<Hash32, (usize, &str)> = HashMap::new();
        for v in votes {
            let entry = stats_by_hash.entry(v.tx_template_hash).or_insert((0, v.proposer_id));
            entry.0 += 1;
            if v.proposer_id < entry.1 {
                entry.1 = v.proposer_id;
            }
        }

        stats_by_hash
            .into_iter()
            .filter(|(_, (count, _))| *count >= commit_quorum)
            .min_by_key(|(hash, (count, proposer))| (Reverse(*count), *hash, *proposer))
            .map(|(hash, _)| hash)
    }

    #[test]
    fn test_quorum_hash_with_quorum() {
        let hash_a = [2u8; 32];

        let votes = vec![
            Vote { tx_template_hash: hash_a, proposer_id: "peer1" },
            Vote { tx_template_hash: hash_a, proposer_id: "peer2" },
            Vote { tx_template_hash: hash_a, proposer_id: "peer3" },
        ];

        let result = quorum_hash_votes(&votes, 2);
        assert_eq!(result, Some(hash_a));
    }

    #[test]
    fn test_quorum_hash_without_quorum() {
        let hash_a = [2u8; 32];
        let hash_b = [3u8; 32];

        let votes = vec![
            Vote { tx_template_hash: hash_a, proposer_id: "peer1" },
            Vote { tx_template_hash: hash_b, proposer_id: "peer2" },
        ];

        let result = quorum_hash_votes(&votes, 2);
        assert_eq!(result, None); // No hash has 2 votes
    }

    #[test]
    fn test_quorum_hash_tie_break_by_hash() {
        let hash_a = [2u8; 32]; // Lower
        let hash_b = [3u8; 32]; // Higher

        let votes = vec![
            Vote { tx_template_hash: hash_a, proposer_id: "peer1" },
            Vote { tx_template_hash: hash_a, proposer_id: "peer2" },
            Vote { tx_template_hash: hash_b, proposer_id: "peer3" },
            Vote { tx_template_hash: hash_b, proposer_id: "peer4" },
        ];

        let result = quorum_hash_votes(&votes, 2);
        assert_eq!(result, Some(hash_a)); // Lower hash wins
    }

    #[test]
    fn test_quorum_hash_empty() {
        let result = quorum_hash_votes(&[], 2);
        assert_eq!(result, None);
    }
}
```

### 2.6 File: `igra-core/src/domain/coordination/mod.rs`

```rust
//! Two-phase coordination protocol types.
//!
//! This module contains pure domain types and algorithms for the two-phase
//! UTXO consensus protocol. NO I/O is allowed in this module.

pub mod config;
pub mod phase;
pub mod proposal;
pub mod selection;

// Re-export commonly used types
pub use config::{RetryConfig, TwoPhaseConfig};
pub use phase::{EventPhase, EventPhaseState, KaspaAnchorRef, PhaseContext};
pub use proposal::{OutpointRef, Proposal, ProposalBroadcast, ProposalValidationError, UtxoInput};
pub use selection::{quorum_hash, select_winning_proposal, unique_hash_count, vote_counts};
```

### 2.7 Update: `igra-core/src/domain/mod.rs`

Add the new module export:

```rust
// Add to existing exports
pub mod coordination;

// Re-export commonly used types
pub use coordination::{EventPhase, EventPhaseState, Proposal};
```

### 2.8 Update: `igra-core/src/foundation/error.rs`

**Correction**: `ThresholdError` already has structured variants used across the codebase (`InvalidPeerIdentity`, `PsktMismatch`, `InvalidStateTransition`, `MessageTooLarge`, `StorageError { operation, details }`, etc.).

For the v1 implementation, prefer:
- `ThresholdError::InvalidPeerIdentity` for “unknown proposer” (after verifying envelope sender)
- `ThresholdError::InvalidStateTransition { from, to }` for illegal phase transitions
- `ThresholdError::PsktMismatch { expected, actual }` for conflicting template locks / mismatched hashes
- `ThresholdError::Message(...)` for miscellaneous handler rejections that don’t warrant a new error code

If you add new two-phase-specific `ThresholdError` variants, you must also:
- update `ErrorCode` in `igra-core/src/foundation/error.rs`,
- update `ThresholdError::code()` mapping,
- and keep the new variants aligned with the existing style (`{ operation, details }` fields instead of `source: String`).

---

## 3. Phase 2: Storage Layer

**Goal**: Implement `PhaseStorage` trait and RocksDB column families.

### 3.1 Create Storage Trait

**File**: `igra-core/src/infrastructure/storage/phase.rs`

```rust
//! Phase storage trait for two-phase consensus.

use crate::domain::coordination::{EventPhase, EventPhaseState, Proposal};
use crate::foundation::{Hash32, PeerId, ThresholdError};

/// Result of attempting to store a proposal
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreProposalResult {
    /// Proposal stored successfully
    Stored,
    /// Duplicate proposal from same peer (idempotent)
    DuplicateFromPeer,
    /// Phase has progressed past Proposing
    PhaseTooLate,
    /// Proposal round doesn't match current round
    RoundMismatch { expected: u32, got: u32 },
    /// Equivocation: peer sent different proposal for same round
    Equivocation,
}

/// Storage trait for two-phase consensus phase state and proposals.
///
/// This trait is separate from the main `Storage` trait to avoid bloating.
/// Implementations must ensure atomicity for proposal storage with phase checks.
/// Keep this trait synchronous to match the existing `Storage` trait in this codebase.
/// It is called from async contexts, but the underlying RocksDB access is synchronous.
pub trait PhaseStorage: Send + Sync {
    // === Phase State ===

    /// Get phase state for an event
    fn get_phase(&self, event_id: &Hash32) -> Result<Option<EventPhaseState>, ThresholdError>;

    /// Get all events currently in a specific phase
    fn get_events_in_phase(&self, phase: EventPhase) -> Result<Vec<Hash32>, ThresholdError>;

    /// Atomically enter Proposing phase for a new event (initialize round=0).
    ///
    /// Returns `false` if the event already exists in a later phase.
    fn try_enter_proposing(
        &self,
        event_id: &Hash32,
        now_ns: u64,
    ) -> Result<bool, ThresholdError>;

    /// Atomically transition to Committed if still Proposing and round matches.
    ///
    /// Returns `false` if already committed or phase/round don't match.
    fn try_commit(
        &self,
        event_id: &Hash32,
        round: u32,
        canonical_hash: Hash32,
        now_ns: u64,
    ) -> Result<bool, ThresholdError>;

    /// Transition to Failed and increment round.
    ///
    /// Called when proposal timeout expires without quorum.
    fn fail_and_bump_round(
        &self,
        event_id: &Hash32,
        round: u32,
        now_ns: u64,
    ) -> Result<(), ThresholdError>;

    /// Transition to Abandoned (terminal failure).
    fn mark_abandoned(
        &self,
        event_id: &Hash32,
    ) -> Result<(), ThresholdError>;

    /// Transition to Completed (terminal success).
    fn mark_completed(
        &self,
        event_id: &Hash32,
    ) -> Result<(), ThresholdError>;

    /// Update own_proposal_hash
    fn set_own_proposal_hash(
        &self,
        event_id: &Hash32,
        hash: Hash32,
    ) -> Result<(), ThresholdError>;

    // === Proposals ===

    /// Store a proposal with phase/round enforcement.
    ///
    /// Semantics:
    /// - If event is Unknown, initializes phase state to Proposing at proposal.round
    /// - If local round != proposal.round, returns RoundMismatch
    /// - If phase is Committed/Completed/Abandoned, returns PhaseTooLate
    /// - If peer already has a different proposal for this round, returns Equivocation
    fn store_proposal(&self, proposal: &Proposal) -> Result<StoreProposalResult, ThresholdError>;

    /// Get all proposals for an event at a specific round
    fn get_proposals(
        &self,
        event_id: &Hash32,
        round: u32,
    ) -> Result<Vec<Proposal>, ThresholdError>;

    /// Check if we have a proposal from a specific peer for a round
    fn has_proposal_from(
        &self,
        event_id: &Hash32,
        round: u32,
        peer_id: &PeerId,
    ) -> Result<bool, ThresholdError>;

    /// Count proposals for an event at a round
    fn proposal_count(
        &self,
        event_id: &Hash32,
        round: u32,
    ) -> Result<usize, ThresholdError>;

    // === Cleanup ===

    /// Clear proposals for rounds before the specified round
    fn clear_stale_proposals(
        &self,
        event_id: &Hash32,
        before_round: u32,
    ) -> Result<usize, ThresholdError>;

    /// Garbage collect phase/proposal data older than cutoff
    fn gc_events_older_than(
        &self,
        cutoff_timestamp_ns: u64,
    ) -> Result<usize, ThresholdError>;
}
```

### 3.2 RocksDB Storage (PhaseStorage)

**Correction (architecture)**: Prefer implementing `PhaseStorage` directly for `RocksStorage` so `Arc<RocksStorage>` can be used as both `Arc<dyn Storage>` and `Arc<dyn PhaseStorage>` without exposing the internal `Arc<DB>`.

**Files**:
- `igra-core/src/infrastructure/storage/rocks/schema.rs` (add CF constants)
- RocksDB open path: extend `open_db_with_cfs()` with the new CFs (locate via `rg open_db_with_cfs`)
- `igra-core/src/infrastructure/storage/rocks/engine.rs` (add a `phase_lock: Mutex<()>` and `impl PhaseStorage for RocksStorage`)

The code below is illustrative of the key layout / WriteBatch patterns (adapt it to the actual `RocksStorage` implementation style).
Also adapt error mapping to the actual `ThresholdError::StorageError { operation, details }` shape used in this codebase.

```rust
//! RocksDB implementation of PhaseStorage.

use rocksdb::{ColumnFamily, WriteBatch, DB};
use std::sync::Arc;

use crate::domain::coordination::{EventPhase, EventPhaseState, Proposal};
use crate::foundation::{Hash32, PeerId, ThresholdError};
use crate::infrastructure::storage::phase::{PhaseStorage, StoreProposalResult};

/// Column family for event phase state
pub const CF_EVENT_PHASE: &str = "event_phase";

/// Column family for proposals: key = (event_id, round, proposer_peer_id)
pub const CF_EVENT_PROPOSAL: &str = "event_proposal";

/// Column family for phase index (phase -> event_ids)
pub const CF_PHASE_INDEX: &str = "phase_index";

pub struct RocksPhaseStorage {
    db: Arc<DB>,
}

impl RocksPhaseStorage {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    /// Create column families for phase storage
    pub fn column_families() -> Vec<&'static str> {
        vec![CF_EVENT_PHASE, CF_EVENT_PROPOSAL, CF_PHASE_INDEX]
    }

    fn cf_phase(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_EVENT_PHASE).expect("CF_EVENT_PHASE missing")
    }

    fn cf_proposal(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_EVENT_PROPOSAL).expect("CF_EVENT_PROPOSAL missing")
    }

    fn cf_phase_index(&self) -> &ColumnFamily {
        self.db.cf_handle(CF_PHASE_INDEX).expect("CF_PHASE_INDEX missing")
    }

    /// Build proposal key: event_id || round (4 bytes BE) || proposer_peer_id
    fn proposal_key(event_id: &Hash32, round: u32, proposer: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(32 + 4 + proposer.len());
        key.extend_from_slice(event_id);
        key.extend_from_slice(&round.to_be_bytes());
        key.extend_from_slice(proposer.as_bytes());
        key
    }

    /// Build proposal prefix for iteration: event_id || round
    fn proposal_prefix(event_id: &Hash32, round: u32) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(36);
        prefix.extend_from_slice(event_id);
        prefix.extend_from_slice(&round.to_be_bytes());
        prefix
    }

    /// Build phase index key
    fn phase_index_key(phase: EventPhase, event_id: &Hash32) -> Vec<u8> {
        let mut key = Vec::with_capacity(33);
        key.push(phase as u8);
        key.extend_from_slice(event_id);
        key
    }
}

impl PhaseStorage for RocksPhaseStorage {
    fn get_phase(&self, event_id: &Hash32) -> Result<Option<EventPhaseState>, ThresholdError> {
        match self.db.get_cf(self.cf_phase(), event_id) {
            Ok(Some(bytes)) => {
                let state: EventPhaseState = bincode::deserialize(&bytes)
                    .map_err(|e| ThresholdError::StorageError {
                        reason: format!("failed to deserialize phase state: {}", e),
                    })?;
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ThresholdError::StorageError {
                reason: format!("failed to get phase: {}", e),
            }),
        }
    }

    fn get_events_in_phase(&self, phase: EventPhase) -> Result<Vec<Hash32>, ThresholdError> {
        let prefix = vec![phase as u8];
        let mut events = Vec::new();

        let iter = self.db.prefix_iterator_cf(self.cf_phase_index(), &prefix);
        for item in iter {
            let (key, _) = item.map_err(|e| ThresholdError::StorageError {
                reason: format!("iterator error: {}", e),
            })?;

            if key.len() != 33 || key[0] != phase as u8 {
                break; // End of prefix
            }

            let mut event_id = [0u8; 32];
            event_id.copy_from_slice(&key[1..33]);
            events.push(event_id);
        }

        Ok(events)
    }

    fn try_enter_proposing(
        &self,
        event_id: &Hash32,
        now_ns: u64,
    ) -> Result<bool, ThresholdError> {
        // Check existing phase
        if let Some(existing) = self.get_phase(event_id)? {
            if existing.phase != EventPhase::Unknown {
                return Ok(false);
            }
        }

        let state = EventPhaseState::new_proposing(now_ns);
        let state_bytes = bincode::serialize(&state)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to serialize phase state: {}", e),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf_phase(), event_id, &state_bytes);
        batch.put_cf(
            self.cf_phase_index(),
            Self::phase_index_key(EventPhase::Proposing, event_id),
            &[],
        );

        self.db.write(batch).map_err(|e| ThresholdError::StorageError {
            reason: format!("failed to write phase: {}", e),
        })?;

        Ok(true)
    }

    fn try_commit(
        &self,
        event_id: &Hash32,
        round: u32,
        canonical_hash: Hash32,
        now_ns: u64,
    ) -> Result<bool, ThresholdError> {
        let Some(mut state) = self.get_phase(event_id)? else {
            return Ok(false);
        };

        // Can only commit from Proposing at matching round
        if state.phase != EventPhase::Proposing || state.round != round {
            return Ok(false);
        }

        // Already committed?
        if state.canonical_hash.is_some() {
            return Ok(false);
        }

        let old_phase = state.phase;
        state.phase = EventPhase::Committed;
        state.canonical_hash = Some(canonical_hash);
        state.phase_started_at_ns = now_ns;

        let state_bytes = bincode::serialize(&state)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to serialize phase state: {}", e),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf_phase(), event_id, &state_bytes);
        // Update phase index
        batch.delete_cf(self.cf_phase_index(), Self::phase_index_key(old_phase, event_id));
        batch.put_cf(
            self.cf_phase_index(),
            Self::phase_index_key(EventPhase::Committed, event_id),
            &[],
        );

        self.db.write(batch).map_err(|e| ThresholdError::StorageError {
            reason: format!("failed to commit phase: {}", e),
        })?;

        Ok(true)
    }

    fn fail_and_bump_round(
        &self,
        event_id: &Hash32,
        round: u32,
        now_ns: u64,
    ) -> Result<(), ThresholdError> {
        let Some(mut state) = self.get_phase(event_id)? else {
            return Err(ThresholdError::StorageError {
                reason: "event not found".to_string(),
            });
        };

        if state.phase != EventPhase::Proposing || state.round != round {
            return Ok(()); // Already moved on
        }

        let old_phase = state.phase;
        state.phase = EventPhase::Failed;
        state.round += 1;
        state.retry_count += 1;
        state.phase_started_at_ns = now_ns;
        state.own_proposal_hash = None; // Clear for new round

        let state_bytes = bincode::serialize(&state)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to serialize phase state: {}", e),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf_phase(), event_id, &state_bytes);
        batch.delete_cf(self.cf_phase_index(), Self::phase_index_key(old_phase, event_id));
        batch.put_cf(
            self.cf_phase_index(),
            Self::phase_index_key(EventPhase::Failed, event_id),
            &[],
        );

        self.db.write(batch).map_err(|e| ThresholdError::StorageError {
            reason: format!("failed to fail phase: {}", e),
        })?;

        Ok(())
    }

    fn store_proposal(&self, proposal: &Proposal) -> Result<StoreProposalResult, ThresholdError> {
        // Get or create phase state
        let mut state = match self.get_phase(&proposal.event_id)? {
            Some(s) => s,
            None => {
                // Initialize at proposal's round
                EventPhaseState::new_at_round(proposal.round, proposal.timestamp_ns)
            }
        };

        // Check phase allows proposals
        if !state.phase.accepts_proposals() && state.phase != EventPhase::Unknown {
            return Ok(StoreProposalResult::PhaseTooLate);
        }

        // Check round matches
        if state.phase != EventPhase::Unknown && state.round != proposal.round {
            return Ok(StoreProposalResult::RoundMismatch {
                expected: state.round,
                got: proposal.round,
            });
        }

        // Check for existing proposal from this peer
        let key = Self::proposal_key(&proposal.event_id, proposal.round, proposal.proposer_peer_id.as_str());
        if let Some(existing_bytes) = self.db.get_cf(self.cf_proposal(), &key)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to check existing proposal: {}", e),
            })?
        {
            let existing: Proposal = bincode::deserialize(&existing_bytes)
                .map_err(|e| ThresholdError::StorageError {
                    reason: format!("failed to deserialize existing proposal: {}", e),
                })?;

            if existing.tx_template_hash == proposal.tx_template_hash {
                return Ok(StoreProposalResult::DuplicateFromPeer);
            } else {
                // Equivocation: same peer, same round, different hash
                return Ok(StoreProposalResult::Equivocation);
            }
        }

        // Update phase if Unknown
        if state.phase == EventPhase::Unknown {
            state.phase = EventPhase::Proposing;
            state.round = proposal.round;
        }

        let proposal_bytes = bincode::serialize(proposal)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to serialize proposal: {}", e),
            })?;
        let state_bytes = bincode::serialize(&state)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to serialize phase state: {}", e),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf_proposal(), &key, &proposal_bytes);
        batch.put_cf(self.cf_phase(), &proposal.event_id, &state_bytes);
        batch.put_cf(
            self.cf_phase_index(),
            Self::phase_index_key(EventPhase::Proposing, &proposal.event_id),
            &[],
        );

        self.db.write(batch).map_err(|e| ThresholdError::StorageError {
            reason: format!("failed to store proposal: {}", e),
        })?;

        Ok(StoreProposalResult::Stored)
    }

    fn get_proposals(
        &self,
        event_id: &Hash32,
        round: u32,
    ) -> Result<Vec<Proposal>, ThresholdError> {
        let prefix = Self::proposal_prefix(event_id, round);
        let mut proposals = Vec::new();

        let iter = self.db.prefix_iterator_cf(self.cf_proposal(), &prefix);
        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::StorageError {
                reason: format!("iterator error: {}", e),
            })?;

            // Check key still matches prefix
            if !key.starts_with(&prefix) {
                break;
            }

            let proposal: Proposal = bincode::deserialize(&value)
                .map_err(|e| ThresholdError::StorageError {
                    reason: format!("failed to deserialize proposal: {}", e),
                })?;
            proposals.push(proposal);
        }

        Ok(proposals)
    }

    fn has_proposal_from(
        &self,
        event_id: &Hash32,
        round: u32,
        peer_id: &PeerId,
    ) -> Result<bool, ThresholdError> {
        let key = Self::proposal_key(event_id, round, peer_id.as_str());
        self.db.get_cf(self.cf_proposal(), &key)
            .map(|opt| opt.is_some())
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to check proposal: {}", e),
            })
    }

    fn proposal_count(
        &self,
        event_id: &Hash32,
        round: u32,
    ) -> Result<usize, ThresholdError> {
        let proposals = self.get_proposals(event_id, round)?;
        Ok(proposals.len())
    }

    fn clear_stale_proposals(
        &self,
        event_id: &Hash32,
        before_round: u32,
    ) -> Result<usize, ThresholdError> {
        let mut batch = WriteBatch::default();
        let mut count = 0;

        for round in 0..before_round {
            let prefix = Self::proposal_prefix(event_id, round);
            let iter = self.db.prefix_iterator_cf(self.cf_proposal(), &prefix);

            for item in iter {
                let (key, _) = item.map_err(|e| ThresholdError::StorageError {
                    reason: format!("iterator error: {}", e),
                })?;

                if !key.starts_with(&prefix) {
                    break;
                }

                batch.delete_cf(self.cf_proposal(), &key);
                count += 1;
            }
        }

        if count > 0 {
            self.db.write(batch).map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to clear stale proposals: {}", e),
            })?;
        }

        Ok(count)
    }

    fn gc_events_older_than(
        &self,
        cutoff_timestamp_ns: u64,
    ) -> Result<usize, ThresholdError> {
        // Implementation: iterate CF_EVENT_PHASE, find terminal events older than cutoff
        // Delete phase state, proposals, and index entries
        // This is a background operation
        let mut count = 0;

        let iter = self.db.iterator_cf(self.cf_phase(), rocksdb::IteratorMode::Start);
        let mut batch = WriteBatch::default();

        for item in iter {
            let (key, value) = item.map_err(|e| ThresholdError::StorageError {
                reason: format!("iterator error: {}", e),
            })?;

            let state: EventPhaseState = bincode::deserialize(&value)
                .map_err(|e| ThresholdError::StorageError {
                    reason: format!("failed to deserialize: {}", e),
                })?;

            if state.phase.is_terminal() && state.phase_started_at_ns < cutoff_timestamp_ns {
                let mut event_id = [0u8; 32];
                event_id.copy_from_slice(&key[..32]);

                // Delete phase
                batch.delete_cf(self.cf_phase(), &key);

                // Delete index
                batch.delete_cf(
                    self.cf_phase_index(),
                    Self::phase_index_key(state.phase, &event_id),
                );

                // Delete all proposals (all rounds)
                for round in 0..=state.round {
                    let prefix = Self::proposal_prefix(&event_id, round);
                    let prop_iter = self.db.prefix_iterator_cf(self.cf_proposal(), &prefix);
                    for prop_item in prop_iter {
                        let (prop_key, _) = prop_item.map_err(|e| ThresholdError::StorageError {
                            reason: format!("iterator error: {}", e),
                        })?;
                        if !prop_key.starts_with(&prefix) {
                            break;
                        }
                        batch.delete_cf(self.cf_proposal(), &prop_key);
                    }
                }

                count += 1;
            }
        }

        if count > 0 {
            self.db.write(batch).map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to GC: {}", e),
            })?;
        }

        Ok(count)
    }

    // ... implement remaining methods similarly ...

    fn mark_abandoned(&self, event_id: &Hash32) -> Result<(), ThresholdError> {
        self.transition_to_terminal(event_id, EventPhase::Abandoned)
    }

    fn mark_completed(&self, event_id: &Hash32) -> Result<(), ThresholdError> {
        self.transition_to_terminal(event_id, EventPhase::Completed)
    }

    fn set_own_proposal_hash(
        &self,
        event_id: &Hash32,
        hash: Hash32,
    ) -> Result<(), ThresholdError> {
        let Some(mut state) = self.get_phase(event_id)? else {
            return Err(ThresholdError::StorageError {
                reason: "event not found".to_string(),
            });
        };

        state.own_proposal_hash = Some(hash);

        let state_bytes = bincode::serialize(&state)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to serialize: {}", e),
            })?;

        self.db.put_cf(self.cf_phase(), event_id, &state_bytes)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to update: {}", e),
            })
    }
}

impl RocksPhaseStorage {
    fn transition_to_terminal(
        &self,
        event_id: &Hash32,
        target_phase: EventPhase,
    ) -> Result<(), ThresholdError> {
        let Some(mut state) = self.get_phase(event_id)? else {
            return Err(ThresholdError::StorageError {
                reason: "event not found".to_string(),
            });
        };

        let old_phase = state.phase;
        state.phase = target_phase;

        let state_bytes = bincode::serialize(&state)
            .map_err(|e| ThresholdError::StorageError {
                reason: format!("failed to serialize: {}", e),
            })?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.cf_phase(), event_id, &state_bytes);
        batch.delete_cf(self.cf_phase_index(), Self::phase_index_key(old_phase, event_id));
        batch.put_cf(
            self.cf_phase_index(),
            Self::phase_index_key(target_phase, event_id),
            &[],
        );

        self.db.write(batch).map_err(|e| ThresholdError::StorageError {
            reason: format!("failed to transition: {}", e),
        })
    }
}
```

### 3.3 Add Memory Implementation for Testing

**File**: `igra-core/src/infrastructure/storage/memory_phase.rs`

```rust
//! In-memory PhaseStorage implementation for testing.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::domain::coordination::{EventPhase, EventPhaseState, Proposal};
use crate::foundation::{Hash32, PeerId, ThresholdError};
use crate::infrastructure::storage::phase::{PhaseStorage, StoreProposalResult};

pub struct MemoryPhaseStorage {
    phases: RwLock<HashMap<Hash32, EventPhaseState>>,
    // Key: (event_id, round, proposer_peer_id)
    proposals: RwLock<HashMap<(Hash32, u32, String), Proposal>>,
}

impl MemoryPhaseStorage {
    pub fn new() -> Self {
        Self {
            phases: RwLock::new(HashMap::new()),
            proposals: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryPhaseStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl PhaseStorage for MemoryPhaseStorage {
    // Implementation mirrors RocksPhaseStorage but uses in-memory HashMap
    // ... (similar to RocksDB implementation but with HashMap operations)
}
```

### 3.4 Update Storage Module Exports

**File**: `igra-core/src/infrastructure/storage/mod.rs`

```rust
// Add to existing exports
pub mod phase;
pub mod memory_phase;

pub use phase::{PhaseStorage, StoreProposalResult};
pub use memory_phase::MemoryPhaseStorage;
```

---

## 4. Phase 3: Transport Layer

**Goal**: Add `ProposalBroadcast` message type and transport methods.

### 4.1 Extend Transport Messages

**File**: `igra-core/src/infrastructure/transport/iroh/messages.rs`

Add to `TransportMessage` enum:

```rust
use crate::domain::coordination::{PhaseContext, ProposalBroadcast};
use crate::foundation::PeerId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransportMessage {
    EventStateBroadcast(EventStateBroadcast),
    StateSyncRequest(StateSyncRequest),
    StateSyncResponse(StateSyncResponse),
    // NEW: Two-phase proposal broadcast
    ProposalBroadcast(ProposalBroadcast),
}

// Update EventStateBroadcast to include optional PhaseContext
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventStateBroadcast {
    pub event_id: Hash32,
    pub tx_template_hash: Hash32,
    pub state: EventCrdtState,
    pub sender_peer_id: PeerId,
    /// NEW: Phase context for commit signals (late joiners, gating)
    #[serde(default)]
    pub phase_context: Option<PhaseContext>,
}
```

### 4.2 Extend Transport Trait

**File**: `igra-core/src/infrastructure/transport/iroh/traits.rs`

```rust
use crate::domain::coordination::ProposalBroadcast;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    // Existing methods
    async fn publish_event_state(&self, broadcast: EventStateBroadcast) -> Result<()>;
    async fn publish_state_sync_request(&self, request: StateSyncRequest) -> Result<()>;
    async fn publish_state_sync_response(&self, response: StateSyncResponse) -> Result<()>;

    // NEW: Publish proposal
    async fn publish_proposal(&self, proposal: ProposalBroadcast) -> Result<()>;
}
```

### 4.3 Implement in IrohTransport

**File**: `igra-core/src/infrastructure/transport/iroh/client.rs`

```rust
impl Transport for IrohTransport {
    // ... existing methods ...

    async fn publish_proposal(&self, proposal: ProposalBroadcast) -> Result<(), ThresholdError> {
        let topic = Self::group_topic_id(&self.config.group_id, self.config.network_id);
        let stream_id = SessionId::from(topic);
        debug!(
            "publishing proposal event_id={} round={} proposer={} hash={}",
            hex::encode(proposal.event_id),
            proposal.round,
            proposal.proposer_peer_id,
            hex::encode(proposal.tx_template_hash)
        );
        let payload = TransportMessage::ProposalBroadcast(proposal);
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = crate::foundation::now_nanos();
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id: stream_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };
        let bytes = encoding::encode_envelope(&envelope)?;
        self.publish_bytes(topic, bytes, "proposal").await
    }
}
```

### 4.4 Update Message Routing

**File**: `igra-service/src/service/coordination/loop.rs`

Routing is performed in the service coordination loop (the core `subscription.rs` only yields envelopes; it does not dispatch).

Add a match arm for `TransportMessage::ProposalBroadcast` and pass the **envelope sender** into the handler so we can enforce:
`proposal.proposer_peer_id == envelope.sender_peer_id`.
Do the same consistency check for `EventStateBroadcast.sender_peer_id` before calling `handle_crdt_broadcast`.

```rust
match envelope.payload {
    TransportMessage::ProposalBroadcast(proposal) => {
        if let Err(err) = handle_proposal_broadcast(
            &app_config,
            &flow,
            &transport,
            &storage,
            &phase_storage,
            &local_peer_id,
            &envelope.sender_peer_id,
            proposal,
        ).await {
            warn!("two-phase proposal handler error error={}", err);
        }
    }
    // ... existing arms ...
}
```

---

## 5. Phase 4: Protocol Handlers

**Goal**: Implement handler functions in `igra-service`.

### 5.1 Create Two-Phase Handler Module

**File**: `igra-service/src/service/coordination/two_phase_handler.rs`

```rust
//! Two-phase protocol handlers.
//!
//! Free functions following CODE-GUIDELINE.md patterns.

use std::sync::Arc;

use log::{debug, info, warn};

use igra_core::domain::coordination::{
    quorum_hash, select_winning_proposal, EventPhase, EventPhaseState,
    PhaseContext, Proposal, ProposalBroadcast, TwoPhaseConfig,
};
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::storage::phase::{PhaseStorage, StoreProposalResult};
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::Transport;

use crate::service::flow::ServiceFlow;
use igra_core::infrastructure::config::AppConfig;

/// Handle incoming proposal broadcast from gossip.
pub async fn handle_proposal_broadcast(
    app_config: &AppConfig,
    config: &TwoPhaseConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    sender_peer_id: &PeerId,
    proposal: ProposalBroadcast,
) -> Result<(), ThresholdError> {
    // 1) Identity binding: proposal must match envelope sender (membership is enforced by signature verification)
    if proposal.proposer_peer_id != *sender_peer_id {
        return Err(ThresholdError::InvalidPeerIdentity);
    }

    // 2) Validate structure (cheap)
    proposal.validate_structure().map_err(|e| ThresholdError::Message(e.to_string()))?;

    // 3) Hash consistency (medium) - reject if tx_template_hash doesn't match PSKT-derived hash
    let computed = proposal.computed_hash()?;
    if computed != proposal.tx_template_hash {
        flow.metrics().inc_tx_template_hash_mismatch("proposal_hash_mismatch");
        return Err(ThresholdError::PsktMismatch {
            expected: hex::encode(proposal.tx_template_hash),
            actual: hex::encode(computed),
        });
    }

    // 4) Check round rules
    let local_phase = phase_storage.get_phase(&proposal.event_id)?;

    if let Some(phase) = &local_phase {
        // Ignore stale rounds
        if proposal.round < phase.round {
            debug!(
                "ignoring stale proposal event_id={} proposal_round={} local_round={}",
                hex::encode(proposal.event_id),
                proposal.round,
                phase.round
            );
            return Ok(());
        }

        // Future round: trigger anti-entropy but don't store
        if proposal.round > phase.round {
            if proposal.round == phase.round + 1 {
                // Trigger targeted state sync here (rate-limited by STATE_SYNC_COOLDOWN_MS)
                debug!(
                    "received future-round proposal event_id={} round={}",
                    hex::encode(proposal.event_id),
                    proposal.round
                );
                // transport.publish_state_sync_request(...) (see Section 7.4 / anti-entropy)
            }
            return Ok(());
        }
    }

    // 5) Store proposal (atomic with phase/round check)
    let store_result = phase_storage.store_proposal(&proposal)?;

    match store_result {
        StoreProposalResult::Stored => {
            info!(
                "proposal stored event_id={} round={} proposer={} hash={}",
                hex::encode(proposal.event_id),
                proposal.round,
                proposal.proposer_peer_id,
                hex::encode(proposal.tx_template_hash)
            );
        }
        StoreProposalResult::DuplicateFromPeer => {
            debug!("duplicate proposal from same peer, ignoring");
            return Ok(());
        }
        StoreProposalResult::PhaseTooLate => {
            debug!("proposal arrived after phase progressed, ignoring");
            return Ok(());
        }
        StoreProposalResult::RoundMismatch { expected, got } => {
            debug!(
                "proposal round mismatch: expected {}, got {}",
                expected, got
            );
            return Ok(());
        }
        StoreProposalResult::Equivocation => {
            warn!(
                "equivocation detected from peer {} for event {}",
                proposal.proposer_peer_id,
                hex::encode(proposal.event_id)
            );
            return Ok(());
        }
    }

    // 6) Try to commit if quorum reached
    try_commit_and_sign(
        config,
        flow,
        transport,
        storage,
        phase_storage,
        local_peer_id,
        &proposal.event_id,
        proposal.round,
    )
    .await?;

    // Optional: record metrics (existing metric is stage-based)
    flow.metrics().inc_session_stage("proposal_received");

    Ok(())
}

/// Commit signals are carried via `EventStateBroadcast.phase_context`.
///
/// Keep commit fast-forward logic inside `crdt_handler::handle_crdt_broadcast` so all
/// `EventStateBroadcast` routing stays in one place:
/// - If `broadcast.phase_context.phase == Committed`, fast-forward the local phase state if needed.
/// - If two-phase is enabled and the local phase is still Proposing, ignore broadcasts without
///   `phase_context` to avoid pre-commit signing.

/// Try to commit and sign if quorum is reached.
pub async fn try_commit_and_sign(
    config: &TwoPhaseConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    event_id: &Hash32,
    round: u32,
) -> Result<(), ThresholdError> {
    // Get all proposals for this round
    let proposals = phase_storage.get_proposals(event_id, round)?;

    // Check for quorum
    let Some(canonical_hash) = quorum_hash(&proposals, config.commit_quorum) else {
        debug!(
            "no quorum yet event_id={} round={} proposals={}",
            hex::encode(event_id),
            round,
            proposals.len()
        );
        return Ok(());
    };

    // Select winning proposal
    let Some(winning) = select_winning_proposal(&proposals, canonical_hash) else {
        return Err(ThresholdError::Message(
            "winning proposal not found".to_string(),
        ));
    };

    // Optional: validate commit candidate before committing.
    // In v1 we can rely on the existing CRDT signing path to do mandatory validation before signing:
    // - verify source proof + policy
    // - rebuild PSKT locally and confirm `tx_template_hash` matches
    // - (optional) revalidate UTXOs / depth

    // Lock to canonical hash
    storage.set_event_active_template_hash(event_id, &canonical_hash)?;

    let committed = phase_storage
        .try_commit(event_id, round, canonical_hash, now_ns())?;

    if !committed {
        debug!("commit race lost, someone else committed first");
        return Ok(());
    }

    info!(
        "committed event_id={} round={} hash={} votes={}",
        hex::encode(event_id),
        round,
        hex::encode(canonical_hash),
        proposals
            .iter()
            .filter(|p| p.tx_template_hash == canonical_hash)
            .count()
    );

    // Commit broadcast + signing should reuse existing CRDT pipeline:
    // 1) Broadcast an EventStateBroadcast that includes `phase_context=Committed` and carries
    //    `signing_material` + `kpsbt_blob` from the winning proposal in `EventCrdtState`.
    // 2) Call into the existing CRDT handler to merge/sign/broadcast partial signatures.
    //
    // See: `igra-service/src/service/coordination/crdt_handler.rs` (signing path).

    flow.metrics().inc_two_phase_canonical_selection("quorum");

    Ok(())
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
```

### 5.1.1 CRDT Handler Phase Gate (Commit-Only Signing)

**Goal**: Ensure signers never sign based on a pre-commit CRDT broadcast.

**File**: `igra-service/src/service/coordination/crdt_handler.rs`

**Required behavior when two-phase is enabled**:
- If local phase is `Unknown`/`Proposing`/`Failed`, **do not sign** any `EventStateBroadcast` unless it carries `phase_context=Committed`.
- If an `EventStateBroadcast` carries `phase_context=Committed`, treat it as a commit signal:
  - fast-forward local phase (via `phase_storage.try_commit(event_id, round, tx_template_hash, now)`),
  - set `storage.set_event_active_template_hash(event_id, tx_template_hash)`,
  - then proceed with normal CRDT merge/sign pipeline.
- If local phase is already `Committed`, accept/merge only if `broadcast.tx_template_hash == canonical_hash`; ignore conflicts and alert.

**Implementation note**:
- Keep all `EventStateBroadcast` handling in `handle_crdt_broadcast` to avoid duplicating routing logic in `run_coordination_loop`.
- This requires passing `phase_storage` (and two-phase config) into `handle_crdt_broadcast`.

### 5.2 Create Timeout Handler

**File**: `igra-service/src/service/coordination/two_phase_timeout.rs`

```rust
//! Timeout handling for two-phase protocol.

use std::sync::Arc;

use log::{info, warn};

use igra_core::domain::coordination::{quorum_hash, EventPhase, TwoPhaseConfig};
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::Transport;

use super::two_phase_handler::try_commit_and_sign;
use crate::service::flow::ServiceFlow;

/// Periodic two-phase tick (timeouts + retries).
///
/// Runs in a background task (see Section 5.3). PhaseStorage calls are synchronous; transport/RPC calls are async.
pub async fn on_two_phase_tick(
    app_config: &AppConfig,
    config: &TwoPhaseConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
) -> Result<(), ThresholdError> {
    let now_ns = now_ns();

    // Get all events in Proposing phase
    let proposing_events = phase_storage.get_events_in_phase(EventPhase::Proposing)?;

    for event_id in proposing_events {
        let Some(phase) = phase_storage.get_phase(&event_id)? else {
            continue;
        };

        // Check if timeout expired
        if !phase.is_timeout_expired(now_ns, config.proposal_timeout_ms) {
            continue;
        }

        // Last-chance quorum check
        let proposals = phase_storage.get_proposals(&event_id, phase.round)?;

        if quorum_hash(&proposals, config.commit_quorum).is_some() {
            // Quorum reached at timeout boundary - commit
            try_commit_and_sign(
                config,
                flow,
                transport,
                storage,
                phase_storage,
                local_peer_id,
                &event_id,
                phase.round,
            )
            .await?;
            continue;
        }

        // No quorum: fail and retry (or abandon)
        if phase.retry_count >= config.retry.max_retries {
            warn!(
                "event abandoned after {} retries event_id={}",
                phase.retry_count,
                hex::encode(event_id)
            );
            phase_storage.mark_abandoned(&event_id)?;
            // metrics: events_abandoned_total += 1
            continue;
        }

        info!(
            "proposal timeout without quorum event_id={} round={} proposals={} retrying",
            hex::encode(event_id),
            phase.round,
            proposals.len()
        );

        phase_storage.fail_and_bump_round(&event_id, phase.round, now_ns)?;
        phase_storage.clear_stale_proposals(&event_id, phase.round)?;
        // metrics: proposal_timeouts_without_quorum_total += 1
    }

    // Retry path: for Failed events, attempt to propose again after backoff
    let failed_events = phase_storage.get_events_in_phase(EventPhase::Failed)?;
    for event_id in failed_events {
        let Some(phase) = phase_storage.get_phase(&event_id)? else {
            continue;
        };
        let delay_ms = config.retry.delay_for_retry(phase.retry_count);
        let elapsed_ms = now_ns.saturating_sub(phase.phase_started_at_ns) / 1_000_000;
        if elapsed_ms < delay_ms {
            continue;
        }

        // Re-broadcast our local proposal for the current round (best-effort).
        // This requires the event to exist locally. If it doesn't, we can't retry safely.
        let Some(event) = storage.get_event(&event_id)? else { continue; };

        // Build + store + broadcast proposal (see Section 6 for the proposal builder).
        // NOTE: `store_proposal` should set phase back to Proposing for this round if needed.
        let proposal = igra_core::application::two_phase::build_local_proposal_for_round(
            flow.rpc().as_ref(),
            &app_config.service,
            &event,
            local_peer_id,
            phase.round,
            now_ns,
        ).await?;
        let _ = phase_storage.store_proposal(&proposal)?;
        phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
        transport.publish_proposal(proposal.clone()).await?;

        // Opportunistically try to commit after rebroadcast
        try_commit_and_sign(config, flow, transport, storage, phase_storage, local_peer_id, &event_id, phase.round).await?;
    }

    Ok(())
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
```

### 5.3 Update Coordination Loop

**File**: `igra-service/src/service/coordination/loop.rs`

**Correction**: `run_coordination_loop` does not have a single `tick()` method. It spawns background tasks (anti-entropy, GC) and then blocks on the gossip subscription stream.

Add a new background task for the two-phase periodic tick:
- Update `run_coordination_loop(...)` signature to accept `phase_storage: Arc<dyn PhaseStorage>` and pass it from `kaspa-threshold-service.rs`.

```rust
use super::two_phase_timeout::on_two_phase_tick;

let app_config_for_two_phase = app_config.clone();
let two_phase_cfg = app_config_for_two_phase.two_phase.clone(); // see config section
let flow_for_two_phase = flow.clone();
let transport_for_two_phase = transport.clone();
let storage_for_two_phase = storage.clone();
let phase_storage_for_two_phase = phase_storage.clone();
let local_peer_for_two_phase = local_peer_id.clone();

let two_phase = tokio::spawn(async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if let Err(err) = on_two_phase_tick(
            &app_config_for_two_phase,
            &two_phase_cfg,
            &flow_for_two_phase,
            &transport_for_two_phase,
            &storage_for_two_phase,
            &phase_storage_for_two_phase,
            &local_peer_for_two_phase,
        ).await {
            warn!("two-phase tick failed error={}", err);
        }
    }
});
```

### 5.4 Metrics Additions

**File**: `igra-service/src/service/metrics.rs`

Add minimal counters for ops visibility:
- `two_phase_canonical_selection_total{method}` (method = `quorum`)
- `two_phase_proposal_timeouts_total`
- `two_phase_events_abandoned_total`
- `two_phase_fast_forwards_total`

Expose small helpers on `Metrics` (consistent with existing `inc_*` style), e.g.:
- `inc_two_phase_canonical_selection(method: &str)`
- `inc_two_phase_proposal_timeout()`
- `inc_two_phase_event_abandoned()`
- `inc_two_phase_fast_forward()`

---

## 6. Phase 5: Event Processor Integration

**Goal**: Modify event submission to enter Proposing instead of immediate signing.

### 6.1 Update Event Submission

**Correction**: Event ingestion and initial tx-template building currently live in the **core application layer**:
- `igra-core/src/application/event_processor.rs` (`submit_signing_event`)

Two-phase “start proposing” must integrate there (so RPC/file watcher/Hyperlane watcher all behave consistently).

This requires `EventContext` to carry `phase_storage: Arc<dyn PhaseStorage>` (separate from `storage: Arc<dyn Storage>`).

**File**: `igra-core/src/application/event_processor.rs`

```rust
use crate::domain::coordination::ProposalBroadcast;
use crate::infrastructure::storage::phase::PhaseStorage;

// Pseudocode sketch: inside the existing submit_signing_event after event validation+storage insert
let now = crate::foundation::now_nanos();

// Enter proposing (idempotent)
if !ctx.phase_storage.try_enter_proposing(&event_id, now)? {
    return Ok(SigningEventResult { /* already in progress */ });
}

// Build proposal for round=0 using the same PSKT+hash logic as the signing path
let proposal: ProposalBroadcast = crate::application::two_phase::build_local_proposal_for_round(
    ctx.rpc.as_ref(),
    &ctx.config,
    &stored_event,
    &ctx.local_peer_id,
    /* round */ 0,
    now,
).await?;

// Store + broadcast (proposal phase never signs)
let _ = ctx.phase_storage.store_proposal(&proposal)?;
ctx.phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
ctx.transport.publish_proposal(proposal).await?;

// Note: signing happens only after commit via the existing CRDT path.
return Ok(SigningEventResult { /* tx_template_hash omitted until committed */ });
```

### 6.2 Proposal Builder Helper (shared)

**File**: `igra-core/src/application/two_phase.rs` (new)

Implement a single source of truth for proposal building so both:
- local event ingestion (`submit_signing_event`), and
- retry tick (`on_two_phase_tick`)
produce identical proposals.

Requirements:
- Use `resolve_pskt_config` + `build_pskt_from_rpc` to build PSKT.
- Compute `tx_template_hash` via `pskt_multisig::tx_template_hash` (blake3 over signable tx; do not hash the blob directly).
- Populate `kaspa_anchor.tip_score` via `rpc.get_virtual_selected_parent_blue_score()` (best-effort).
- Populate `utxos_used` either by extracting from the PSKT inputs (preferred) or by re-querying the node if needed.

---

## 7. Phase 6: Testing

### 7.1 Unit Tests

**File**: `igra-core/tests/unit/domain_coordination.rs`

```rust
//! Unit tests for two-phase coordination domain types.

mod tests {
    use igra_core::domain::coordination::*;

    #[test]
    fn test_phase_transitions_valid() {
        use EventPhase::*;

        assert!(Unknown.can_transition_to(Proposing));
        assert!(Unknown.can_transition_to(Committed)); // Fast-forward
        assert!(Proposing.can_transition_to(Committed));
        assert!(Proposing.can_transition_to(Failed));
        assert!(Committed.can_transition_to(Completed));
        assert!(Failed.can_transition_to(Proposing)); // Retry
        assert!(Failed.can_transition_to(Abandoned));
    }

    #[test]
    fn test_phase_transitions_invalid() {
        use EventPhase::*;

        assert!(!Completed.can_transition_to(Proposing));
        assert!(!Completed.can_transition_to(Committed));
        assert!(!Abandoned.can_transition_to(Proposing));
        assert!(!Unknown.can_transition_to(Completed));
    }

    #[test]
    fn test_quorum_hash_with_quorum() {
        // See selection.rs tests
    }

    #[test]
    fn test_proposal_validation() {
        let mut proposal = make_valid_proposal();

        // Valid
        assert!(proposal.validate_structure().is_ok());

        // Too many UTXOs
        proposal.utxos_used = vec![make_utxo(); MAX_UTXOS_PER_PROPOSAL + 1];
        assert!(matches!(
            proposal.validate_structure(),
            Err(ProposalValidationError::TooManyUtxos { .. })
        ));
    }

    #[test]
    fn test_retry_config_delay() {
        let config = RetryConfig::default();

        assert_eq!(config.delay_for_retry(0), 5000);
        assert_eq!(config.delay_for_retry(1), 10000);
        assert_eq!(config.delay_for_retry(2), 20000);
        assert_eq!(config.delay_for_retry(3), 30000); // Capped at max
        assert_eq!(config.delay_for_retry(10), 30000); // Still capped
    }
}
```

### 7.2 Integration Tests

**File**: `igra-core/tests/integration/phase_storage.rs`

```rust
//! Integration tests for PhaseStorage.

use igra_core::domain::coordination::*;
use igra_core::infrastructure::storage::memory_phase::MemoryPhaseStorage;
use igra_core::infrastructure::storage::phase::*;

#[test]
fn test_proposal_storage_roundtrip() {
    let storage = MemoryPhaseStorage::new();
    let proposal = make_test_proposal([1u8; 32], 0);

    let result = storage.store_proposal(&proposal).unwrap();
    assert_eq!(result, StoreProposalResult::Stored);

    let proposals = storage.get_proposals(&proposal.event_id, 0).unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].tx_template_hash, proposal.tx_template_hash);
}

#[test]
fn test_proposal_duplicate_is_idempotent() {
    let storage = MemoryPhaseStorage::new();
    let proposal = make_test_proposal([1u8; 32], 0);

    storage.store_proposal(&proposal).unwrap();
    let result = storage.store_proposal(&proposal).unwrap();

    assert_eq!(result, StoreProposalResult::DuplicateFromPeer);
}

#[test]
fn test_proposal_equivocation_detected() {
    let storage = MemoryPhaseStorage::new();
    let proposal1 = make_test_proposal([1u8; 32], 0);
    let mut proposal2 = proposal1.clone();
    proposal2.tx_template_hash = [2u8; 32]; // Different hash!

    storage.store_proposal(&proposal1).unwrap();
    let result = storage.store_proposal(&proposal2).unwrap();

    assert_eq!(result, StoreProposalResult::Equivocation);
}

#[test]
fn test_phase_transitions() {
    let storage = MemoryPhaseStorage::new();
    let event_id = [1u8; 32];
    let now = 1000000000u64;

    // Enter proposing
    assert!(storage.try_enter_proposing(&event_id, now).unwrap());

    let phase = storage.get_phase(&event_id).unwrap().unwrap();
    assert_eq!(phase.phase, EventPhase::Proposing);
    assert_eq!(phase.round, 0);

    // Commit
    let hash = [2u8; 32];
    assert!(storage.try_commit(&event_id, 0, hash, now + 1000).unwrap());

    let phase = storage.get_phase(&event_id).unwrap().unwrap();
    assert_eq!(phase.phase, EventPhase::Committed);
    assert_eq!(phase.canonical_hash, Some(hash));
}

#[test]
fn test_fail_and_retry() {
    let storage = MemoryPhaseStorage::new();
    let event_id = [1u8; 32];
    let now = 1000000000u64;

    storage.try_enter_proposing(&event_id, now).unwrap();
    storage.fail_and_bump_round(&event_id, 0, now + 5000).unwrap();

    let phase = storage.get_phase(&event_id).unwrap().unwrap();
    assert_eq!(phase.phase, EventPhase::Failed);
    assert_eq!(phase.round, 1);
    assert_eq!(phase.retry_count, 1);
}
```

### 7.3 End-to-End Tests

**File**: `igra-service/tests/integration/two_phase_e2e.rs`

```rust
//! End-to-end tests for two-phase protocol.

#[tokio::test]
async fn test_three_signers_same_proposal_commits() {
    // Setup 3 signers with same UTXO view
    // Submit event to all 3
    // Verify all 3 produce same proposal hash
    // Verify commit happens after 2 proposals received
}

#[tokio::test]
async fn test_divergent_proposals_selects_quorum() {
    // Setup 3 signers with divergent UTXO views
    // Signer 1+2 produce hash A, Signer 3 produces hash B
    // Verify hash A is selected (has quorum)
}

#[tokio::test]
async fn test_late_joiner_fast_forwards() {
    // Setup 3 signers, one offline
    // Two online signers commit
    // Bring third signer online
    // Verify third signer receives commit broadcast and signs
}

#[tokio::test]
async fn test_timeout_without_quorum_retries() {
    // Setup 3 signers, two offline
    // Submit event to one signer
    // Verify timeout fires without quorum
    // Verify round increments
    // Bring second signer online
    // Verify commit on retry
}

#[tokio::test]
async fn test_max_retries_abandons() {
    // Setup 3 signers, only 1 online
    // Submit event
    // Wait for max_retries timeouts
    // Verify event marked Abandoned
}
```

---

## 8. Configuration

### 8.1 Configuration Updates

Add to `igra.toml`:

```toml
[two_phase]
enabled = true
proposal_timeout_ms = 5000
# commit_quorum = 0  # 0 (default) means derive from `group.threshold_m`
min_input_score_depth = 0  # 0 (default) means derive from `max(300, group.finality_blue_score_threshold)`
revalidate_inputs_on_commit = true

[two_phase.retry]
max_retries = 3
base_delay_ms = 5000
max_delay_ms = 30000
backoff_multiplier = 2.0
jitter_ms = 250
```

**Config plumbing**:
- Add `#[serde(default)] pub two_phase: crate::domain::coordination::TwoPhaseConfig` to `AppConfig` in `igra-core/src/infrastructure/config/types.rs`.
- Add `pub two_phase: crate::domain::coordination::TwoPhaseConfig` to `EventContext` in `igra-core/src/application/event_processor.rs` (constructed from `app_config.two_phase` in the service binary).
- Derive effective values once at startup (avoid `0` footguns):
  - `commit_quorum = if two_phase.commit_quorum == 0 { group.threshold_m } else { two_phase.commit_quorum }`
  - `min_input_score_depth = if two_phase.min_input_score_depth == 0 { max(300, group.finality_blue_score_threshold) } else { two_phase.min_input_score_depth }`

---

## 9. File Change Summary

### New Files

| File | Description |
|------|-------------|
| `igra-core/src/application/two_phase.rs` | Shared proposal builder helper |
| `igra-core/src/domain/coordination/mod.rs` | Module exports |
| `igra-core/src/domain/coordination/config.rs` | Configuration |
| `igra-core/src/domain/coordination/phase.rs` | EventPhase, EventPhaseState |
| `igra-core/src/domain/coordination/proposal.rs` | Proposal struct |
| `igra-core/src/domain/coordination/selection.rs` | quorum_hash algorithm |
| `igra-core/src/infrastructure/storage/phase.rs` | PhaseStorage trait |
| `igra-core/src/infrastructure/storage/memory_phase.rs` | Memory implementation |
| `igra-service/src/service/coordination/two_phase_handler.rs` | Protocol handlers |
| `igra-service/src/service/coordination/two_phase_timeout.rs` | Timeout handling |
| `igra-core/tests/unit/domain_coordination.rs` | Unit tests |
| `igra-core/tests/integration/phase_storage.rs` | Integration tests |
| `igra-service/tests/integration/two_phase_e2e.rs` | E2E tests |

### Modified Files

| File | Changes |
|------|---------|
| `igra-core/src/domain/mod.rs` | Add `coordination` module export |
| `igra-core/src/infrastructure/config/types.rs` | Add `two_phase: TwoPhaseConfig` to `AppConfig` |
| `igra-core/src/application/event_processor.rs` | Start proposing instead of immediate signing |
| `igra-core/src/application/event_processor.rs` | Add `phase_storage` + `two_phase` to `EventContext` |
| `igra-core/src/infrastructure/storage/mod.rs` | Add phase storage exports |
| `igra-core/src/infrastructure/storage/rocks/schema.rs` | Add CF constants for phase/proposals |
| RocksDB open path (`open_db_with_cfs`) | Open DB with new CFs |
| `igra-core/src/infrastructure/storage/rocks/engine.rs` | Implement `PhaseStorage` for `RocksStorage` (+ `phase_lock`) |
| `igra-core/src/infrastructure/transport/iroh/messages.rs` | Add ProposalBroadcast |
| `igra-core/src/infrastructure/transport/iroh/traits.rs` | Add publish_proposal |
| `igra-core/src/infrastructure/transport/iroh/client.rs` | Implement publish_proposal |
| `igra-service/src/service/coordination/loop.rs` | Route ProposalBroadcast + spawn two-phase tick task |
| `igra-service/src/service/coordination/crdt_handler.rs` | Add commit-only phase gate when two-phase enabled |
| `igra-service/src/bin/kaspa-threshold-service.rs` | Wire `phase_storage` + `two_phase` into `EventContext` and coordination loop |
| `igra-service/src/service/metrics.rs` | Add two-phase metrics |

### Estimated Lines of Code

| Component | LOC |
|-----------|-----|
| Domain types | ~400 |
| Storage layer | ~500 |
| Transport | ~100 |
| Handlers | ~400 |
| Tests | ~600 |
| **Total** | **~2000** |

---

## 10. Verification Checklist

### Before Merge

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace` has no warnings
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] E2E tests pass with 3 signers

### Architecture Compliance (CODE-GUIDELINE.md)

- [ ] Domain code has no I/O imports
- [ ] PhaseStorage is a separate trait (not bloating Storage)
- [ ] Handlers are free functions (not OOP)
- [ ] Error variants added to ThresholdError
- [ ] Logs include context (event_id, round, peer_id)
- [ ] `From` traits used for conversions

### Safety Verification

- [ ] `quorum_hash` returns None without quorum
- [ ] Phase transitions are validated
- [ ] One proposal per peer per round enforced
- [ ] Equivocation is detected and logged
- [ ] Conflicting commits are rejected
- [ ] UTXO revalidation before signing

### Metrics Verification

- [ ] `two_phase_proposal_timeouts_total` incremented on timeout-without-quorum
- [ ] `two_phase_events_abandoned_total` incremented on abandon
- [ ] `two_phase_fast_forwards_total` incremented on late joiner fast-forward
- [ ] `two_phase_canonical_selection_total{method=\"quorum\"}` incremented on commit

---

*Implementation Plan Version: 1.0*
*Based on: docs/protocol/two-phase-consensus.md v1.1*
*Following: CODE-GUIDELINE.md v1.0*
*Created: 2026-01-15*
