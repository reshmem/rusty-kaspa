# CODE-GUIDELINE.md

Practical guidelines for contributing to the Igra codebase. Follow these rules to maintain consistency and quality.

---

## 1. Architecture Overview

### 1.1 Crate Structure

```
igra/
├── igra-core/          # Library crate - reusable logic, no runtime
│   ├── src/
│   │   ├── domain/         # Business logic (NO I/O)
│   │   ├── application/    # Orchestration (coordinates domain + infra)
│   │   ├── infrastructure/ # I/O: storage, transport, RPC
│   │   └── foundation/     # Shared primitives: errors, types, constants
│   └── tests/
│       ├── unit/           # Unit tests for domain logic
│       └── integration/    # Integration tests with real storage/transport
│
└── igra-service/       # Binary crate - runtime, CLI, HTTP server
    ├── src/
    │   ├── api/            # HTTP handlers, middleware
    │   ├── service/        # Runtime coordination, main loops
    │   └── bin/            # Binary entry points
    └── tests/
        └── integration/    # End-to-end tests
```

### 1.2 Layer Rules

| Layer | Can Import | Cannot Import | I/O Allowed |
|-------|-----------|---------------|-------------|
| `domain/` | `foundation/` only | `application/`, `infrastructure/` | **NO** |
| `application/` | `domain/`, `foundation/`, `infrastructure/` traits | concrete implementations | Via traits only |
| `infrastructure/` | `domain/`, `foundation/` | `application/` | **YES** |
| `foundation/` | std, external crates | any igra modules | **NO** |

**Golden Rule:** Domain logic must be pure. If you need I/O in domain code, you're doing it wrong.

### 1.3 Dependency Direction

```
igra-service (binary)
      │
      ▼
igra-core (library)
      │
      ├── application/
      │       │
      │       ▼
      ├── domain/  ◄──── infrastructure/ (implements domain traits)
      │       │
      │       ▼
      └── foundation/
```

---

## 2. Adding New Features

### 2.1 Decision Tree: Where Does My Code Go?

```
Is it a pure algorithm or data structure?
├── YES → domain/
│         └── Does it need I/O to work?
│             ├── YES → You designed it wrong. Refactor.
│             └── NO  → Correct. Put it in domain/
│
└── NO → Does it orchestrate multiple components?
         ├── YES → application/
         └── NO  → Does it do I/O (network, disk, RPC)?
                   ├── YES → infrastructure/
                   └── NO  → Is it a shared primitive (error, type)?
                             ├── YES → foundation/
                             └── NO  → Probably domain/
```

### 2.2 Adding a New Domain Module

Example: Adding a "coordination" module for two-phase protocol.

**Step 1:** Create module structure
```
igra-core/src/domain/
└── coordination/
    ├── mod.rs          # Public exports only
    ├── phase.rs        # EventPhase enum, EventPhaseState
    ├── proposal.rs     # Proposal struct, validation
    └── selection.rs    # Canonical selection algorithm
```

**Step 2:** Keep types pure
```rust
// GOOD: Pure data + pure functions
pub struct Proposal {
    pub event_id: Hash32,
    pub tx_template_hash: Hash32,
    pub round: u32,
    // ...
}

impl Proposal {
    /// Pure validation - no I/O
    pub fn validate_structure(&self) -> Result<(), ProposalError> {
        if self.round > MAX_ROUND {
            return Err(ProposalError::RoundTooHigh { max: MAX_ROUND });
        }
        Ok(())
    }
}

// BAD: I/O in domain
impl Proposal {
    pub async fn validate(&self, rpc: &RpcClient) -> Result<()> {  // WRONG!
        rpc.check_utxos(&self.utxos).await?;  // I/O in domain = bad
        Ok(())
    }
}
```

**Step 3:** Export in mod.rs
```rust
// domain/coordination/mod.rs
mod phase;
mod proposal;
mod selection;

pub use phase::{EventPhase, EventPhaseState};
pub use proposal::{Proposal, ProposalError};
pub use selection::select_canonical_hash;
```

**Step 4:** Export from domain/mod.rs
```rust
// domain/mod.rs
pub mod coordination;
// Re-export commonly used types
pub use coordination::{EventPhase, Proposal};
```

### 2.3 Adding Storage Functionality

**Rule:** Don't bloat the main `Storage` trait. Use trait composition.

```rust
// BAD: Adding to mega-trait
pub trait Storage: Send + Sync {
    // ... 30 existing methods ...
    fn store_proposal(&self, ...) -> Result<()>;  // DON'T add here
}

// GOOD: Separate trait
pub trait PhaseStorage: Send + Sync {
    fn store_proposal(&self, event_id: &Hash32, proposal: &Proposal) -> Result<StoreResult>;
    fn get_proposals(&self, event_id: &Hash32, round: u32) -> Result<Vec<Proposal>>;
    fn get_phase(&self, event_id: &Hash32) -> Result<Option<EventPhaseState>>;
    fn transition_phase(&self, event_id: &Hash32, to: EventPhase) -> Result<bool>;
}

// Composition in service
pub struct ServiceFlow {
    storage: Arc<dyn Storage>,
    phase_storage: Arc<dyn PhaseStorage>,  // Composed, not inherited
}
```

### 2.4 Adding Transport Messages

**Step 1:** Add variant to existing enum
```rust
// infrastructure/transport/messages.rs
pub enum TransportMessage {
    EventStateBroadcast(EventStateBroadcast),
    StateSyncRequest(StateSyncRequest),
    StateSyncResponse(StateSyncResponse),
    ProposalBroadcast(ProposalBroadcast),  // ADD HERE
}
```

**Step 2:** Add method to Transport trait
```rust
// infrastructure/transport/iroh/traits.rs
pub trait Transport: Send + Sync {
    async fn publish_event_state(&self, broadcast: EventStateBroadcast) -> Result<()>;
    async fn publish_proposal(&self, proposal: ProposalBroadcast) -> Result<()>;  // ADD
}
```

**Step 3:** Implement in client
```rust
// infrastructure/transport/iroh/client.rs
impl Transport for IrohTransport {
    async fn publish_proposal(&self, proposal: ProposalBroadcast) -> Result<()> {
        self.publish(TransportMessage::ProposalBroadcast(proposal)).await
    }
}
```

### 2.5 Adding Service Handlers

Follow the existing free-function pattern:

```rust
// service/coordination/two_phase_handler.rs

/// Handle incoming proposal broadcast.
///
/// Validates proposal, stores it, checks quorum, and triggers commit if ready.
pub async fn handle_proposal_broadcast(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    proposal: ProposalBroadcast,
) -> Result<(), ThresholdError> {
    // 1. Validate
    // 2. Store
    // 3. Check transition
    // 4. Act
}
```

**Do NOT** use methods on handler structs:
```rust
// BAD: Object-oriented handler
struct ProposalHandler { ... }
impl ProposalHandler {
    async fn handle(&self, proposal: ProposalBroadcast) -> Result<()> { ... }
}
```

---

## 3. Rust Standards

### 3.1 Required Tooling

```bash
# Format before commit
cargo fmt --all

# Lint check
cargo clippy --workspace --tests --benches

# Run the full check script
./check
```

### 3.2 Struct Design

**Always derive in this order:**
```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MyType { ... }
```

**Use `#[derive]` order:** Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize

**Public fields for data structs:**
```rust
// GOOD: Data struct with public fields
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub event_id: Hash32,
    pub round: u32,
}

// BAD: Unnecessary getters for simple data
pub struct Proposal {
    event_id: Hash32,
}
impl Proposal {
    pub fn event_id(&self) -> &Hash32 { &self.event_id }  // Pointless
}
```

**Use private fields + methods when invariants must be maintained:**
```rust
// GOOD: Encapsulation protects invariants
pub struct EventCrdt {
    signatures: HashMap<SignatureKey, SignatureRecord>,  // Private
    version: u64,                                         // Private
}

impl EventCrdt {
    pub fn add_signature(&mut self, record: SignatureRecord) -> bool {
        // Maintains version invariant
        if self.signatures.insert(...).is_none() {
            self.version += 1;
            true
        } else {
            false
        }
    }
}
```

### 3.3 Error Handling

**Use the existing `ThresholdError` enum:**
```rust
// foundation/error.rs - add variants here
pub enum ThresholdError {
    // Group related errors together
    ProposalRoundMismatch { expected: u32, got: u32 },
    ProposalFromUnknownPeer { peer_id: String },
}
```

**Error messages: include context, no periods:**
```rust
// GOOD
return Err(ThresholdError::Message(format!(
    "proposal round mismatch: expected {}, got {}", expected, got
)));

// BAD
return Err(ThresholdError::Message("error".to_string()));  // No context
return Err(ThresholdError::Message("Invalid round.".to_string()));  // Period
```

**Use `?` operator, avoid `.unwrap()` in production code:**
```rust
// GOOD
let phase = storage.get_phase(&event_id)?
    .ok_or_else(|| ThresholdError::Message("missing phase state".into()))?;

// BAD
let phase = storage.get_phase(&event_id).unwrap().unwrap();
```

### 3.4 Logging

**Use appropriate levels:**
```rust
use log::{debug, info, warn, error};

error!("critical failure, cannot continue: {}", err);  // Service will degrade
warn!("unexpected state, continuing: {}", msg);        // Something wrong but recoverable
info!("significant operation completed");              // Normal operation milestones
debug!("detailed internal state");                     // Development/troubleshooting
```

**Always include context in logs:**
```rust
// GOOD
info!(
    "proposal stored event_id={} round={} proposer={}",
    hex::encode(event_id),
    round,
    proposer_peer_id
);

// BAD
info!("stored proposal");  // No context
```

**Use `hex::encode()` for Hash32:**
```rust
// GOOD
info!("event_id={}", hex::encode(event_id));

// BAD
info!("event_id={:?}", event_id);  // Unreadable array output
```

### 3.5 Async Code

**Prefer `async fn` over `-> impl Future`:**
```rust
// GOOD
pub async fn handle_proposal(...) -> Result<(), ThresholdError> { ... }

// BAD (unless required for trait objects)
pub fn handle_proposal(...) -> impl Future<Output = Result<(), ThresholdError>> { ... }
```

**Don't hold locks across await points:**
```rust
// BAD: Lock held across await
let guard = self.state.lock().await;
some_async_operation().await;  // DANGER: lock still held
drop(guard);

// GOOD: Release lock before await
let data = {
    let guard = self.state.lock().await;
    guard.clone()
};
some_async_operation().await;
```

### 3.6 Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Types | PascalCase | `EventPhase`, `ProposalBroadcast` |
| Functions | snake_case | `select_canonical_hash` |
| Constants | SCREAMING_SNAKE | `MAX_PROPOSAL_SIZE` |
| Modules | snake_case | `two_phase_handler` |
| Type parameters | Single uppercase | `T`, `E`, `S` |
| Lifetimes | Short lowercase | `'a`, `'ctx` |

**Avoid abbreviations except well-known ones:**
```rust
// GOOD
tx_template_hash    // "tx" is well-known for transaction
event_id            // "id" is well-known for identifier
kpsbt_blob          // "pskt" is domain-specific, acceptable

// BAD
evt_tmpl_hsh        // Unreadable
prop_brdcst         // Just write ProposalBroadcast
```

---

## 4. Common Patterns

### 4.1 Type Conversions

**Implement `From` traits in the target module:**
```rust
// infrastructure/transport/messages.rs
impl From<&StoredEventCrdt> for EventCrdtState {
    fn from(state: &StoredEventCrdt) -> Self {
        Self {
            signatures: state.signatures.iter().map(CrdtSignature::from).collect(),
            completion: state.completion.as_ref().map(CompletionRecord::from),
            signing_material: state.signing_material.clone(),
            kpsbt_blob: state.kpsbt_blob.clone(),
            version: state.version,
        }
    }
}
```

**Use `From`/`Into` instead of manual conversion:**
```rust
// GOOD
let crdt_state: EventCrdtState = (&stored_state).into();

// BAD: Duplicate conversion code
let crdt_state = EventCrdtState {
    signatures: stored_state.signatures.iter().map(|s| CrdtSignature {
        input_index: s.input_index,
        // ... 10 more fields
    }).collect(),
};
```

### 4.2 Builder Pattern for Complex Structs

```rust
pub struct ProposalBuilder {
    event_id: Option<Hash32>,
    round: u32,
    // ...
}

impl ProposalBuilder {
    pub fn new() -> Self {
        Self { event_id: None, round: 0 }
    }

    pub fn event_id(mut self, id: Hash32) -> Self {
        self.event_id = Some(id);
        self
    }

    pub fn round(mut self, round: u32) -> Self {
        self.round = round;
        self
    }

    pub fn build(self) -> Result<Proposal, ProposalError> {
        let event_id = self.event_id
            .ok_or(ProposalError::MissingField("event_id"))?;
        Ok(Proposal { event_id, round: self.round })
    }
}
```

### 4.3 Validation Pattern

**Separate structure validation from semantic validation:**
```rust
impl Proposal {
    /// Fast structural validation (no I/O, no crypto)
    pub fn validate_structure(&self) -> Result<(), ProposalError> {
        if self.utxos_used.len() > MAX_UTXOS {
            return Err(ProposalError::TooManyUtxos { count: self.utxos_used.len() });
        }
        if self.kpsbt_blob.len() > MAX_KPSBT_SIZE {
            return Err(ProposalError::KpsbtTooLarge { size: self.kpsbt_blob.len() });
        }
        Ok(())
    }
}

// Semantic validation in application layer (may need I/O)
pub async fn validate_proposal_semantic(
    proposal: &Proposal,
    verifier: &dyn MessageVerifier,
    policy: &GroupPolicy,
) -> Result<(), ThresholdError> {
    // Verify source proof (crypto)
    let report = verifier.verify(&proposal.signing_material)?;
    if !report.valid {
        return Err(ThresholdError::EventSignatureInvalid);
    }
    // Policy check
    // ...
}
```

### 4.4 State Machine Pattern

**Use enums for states, pure functions for transitions:**
```rust
// domain/coordination/phase.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventPhase {
    Unknown,
    Proposing,
    Committed,
    Completed,
    Failed,
}

impl EventPhase {
    /// Check if transition is valid
    pub fn can_transition_to(&self, target: EventPhase) -> bool {
        use EventPhase::*;
        matches!(
            (self, target),
            (Unknown, Proposing)
                | (Proposing, Committed)
                | (Proposing, Failed)
                | (Committed, Completed)
                | (Failed, Proposing)  // Retry
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, EventPhase::Completed)
    }
}
```

### 4.5 Metrics Pattern

**Add metrics to existing `ServiceMetrics`:**
```rust
// service/metrics.rs
impl ServiceMetrics {
    pub fn record_proposal_phase_duration(&self, duration_ms: u64) {
        self.proposal_phase_duration_histogram
            .observe(duration_ms as f64);
    }

    pub fn inc_canonical_selection(&self, method: &str) {
        self.canonical_selection_counter
            .with_label_values(&[method])
            .inc();
    }
}
```

**Use metrics in handlers:**
```rust
pub async fn handle_proposal_broadcast(...) -> Result<(), ThresholdError> {
    let start = Instant::now();

    // ... handle proposal ...

    flow.metrics().record_proposal_phase_duration(start.elapsed().as_millis() as u64);
    Ok(())
}
```

---

## 5. Testing

### 5.1 Test File Locations

| Test Type | Location | Purpose |
|-----------|----------|---------|
| Unit | `igra-core/tests/unit/` | Test domain logic in isolation |
| Integration | `igra-core/tests/integration/` | Test with real storage |
| E2E | `igra-service/tests/integration/` | Full service tests |

### 5.2 Unit Test Pattern

```rust
// igra-core/tests/unit/domain_coordination.rs

#[cfg(test)]
mod tests {
    use super::*;

    // Test helpers at top
    fn make_proposal(event_id: Hash32, round: u32) -> Proposal {
        Proposal {
            event_id,
            round,
            tx_template_hash: [2u8; 32],
            // ... minimal valid data
        }
    }

    const TEST_EVENT_ID: Hash32 = [1u8; 32];

    #[test]
    fn test_canonical_selection_prefers_quorum() {
        let proposals = vec![
            make_proposal(TEST_EVENT_ID, 0),
            make_proposal(TEST_EVENT_ID, 0),
        ];

        let result = select_canonical_hash(&proposals, 2);

        assert!(result.is_some());
    }

    #[test]
    fn test_phase_transition_valid() {
        assert!(EventPhase::Unknown.can_transition_to(EventPhase::Proposing));
        assert!(EventPhase::Proposing.can_transition_to(EventPhase::Committed));
    }

    #[test]
    fn test_phase_transition_invalid() {
        assert!(!EventPhase::Completed.can_transition_to(EventPhase::Proposing));
        assert!(!EventPhase::Unknown.can_transition_to(EventPhase::Committed));
    }
}
```

### 5.3 Integration Test Pattern

```rust
// igra-core/tests/integration/phase_storage.rs

use igra_core::infrastructure::storage::memory::MemoryStorage;
use igra_core::infrastructure::storage::PhaseStorage;

#[tokio::test]
async fn test_proposal_storage_roundtrip() {
    let storage = MemoryStorage::new();
    let proposal = make_test_proposal();

    // Store
    let result = storage.store_proposal(&proposal.event_id, &proposal).await?;
    assert_eq!(result, StoreResult::Stored);

    // Retrieve
    let proposals = storage.get_proposals(&proposal.event_id, 0).await?;
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].tx_template_hash, proposal.tx_template_hash);
}

#[tokio::test]
async fn test_proposal_duplicate_rejected() {
    let storage = MemoryStorage::new();
    let proposal = make_test_proposal();

    storage.store_proposal(&proposal.event_id, &proposal).await?;
    let result = storage.store_proposal(&proposal.event_id, &proposal).await?;

    assert_eq!(result, StoreResult::DuplicateFromPeer);
}
```

### 5.4 Test Naming

```rust
// Pattern: test_<unit>_<scenario>_<expected>

#[test]
fn test_canonical_selection_with_quorum_returns_majority_hash() { ... }

#[test]
fn test_canonical_selection_without_quorum_returns_lowest_hash() { ... }

#[test]
fn test_phase_transition_from_proposing_to_committed_succeeds() { ... }

#[test]
fn test_phase_transition_from_completed_to_proposing_fails() { ... }
```

---

## 6. Code Review Checklist

Before submitting PR, verify:

### Architecture
- [ ] Domain code has no I/O imports (`tokio`, `std::fs`, `reqwest`, etc.)
- [ ] New traits are focused (< 10 methods)
- [ ] No circular dependencies between modules
- [ ] Storage trait not bloated (use composition)

### Code Quality
- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace` has no warnings
- [ ] No `.unwrap()` in production code (except tests)
- [ ] Error messages include context
- [ ] Logs include relevant identifiers (event_id, peer_id, etc.)

### Patterns
- [ ] `From` traits used instead of duplicate conversion code
- [ ] Public data structs use public fields
- [ ] Encapsulated structs maintain invariants
- [ ] State machines use enum + pure transition functions

### Testing
- [ ] Unit tests for domain logic
- [ ] Integration tests for storage/transport
- [ ] Test names describe scenario and expected outcome
- [ ] No `#[ignore]` without explanation

### Documentation
- [ ] Public items have doc comments
- [ ] Complex algorithms have explanation comments
- [ ] No commented-out code

---

## 7. Quick Reference

### File Naming
```
domain/coordination/phase.rs       # Types: EventPhase
domain/coordination/selection.rs   # Functions: select_canonical_hash
infrastructure/storage/phase.rs    # Trait: PhaseStorage
service/coordination/two_phase_handler.rs  # Handler functions
```

### Import Order
```rust
// 1. std
use std::collections::HashMap;
use std::sync::Arc;

// 2. External crates
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// 3. Crate imports
use crate::domain::{EventPhase, Proposal};
use crate::foundation::{Hash32, ThresholdError};
use crate::infrastructure::storage::Storage;
```

### Common Types
```rust
type Hash32 = [u8; 32];
type Result<T> = std::result::Result<T, ThresholdError>;
```

### Useful Commands
```bash
# Format
cargo fmt --all

# Lint
cargo clippy --workspace --tests --benches

# Test specific module
cargo test -p igra-core domain_coordination

# Test with output
cargo test -- --nocapture

# Check everything
./check
```

---

*Version: 1.0*
*Last Updated: 2025-01-14*
