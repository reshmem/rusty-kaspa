# CODE-GUIDELINE.md

Practical guidelines for contributing to the Igra codebase. Follow these rules to maintain consistency and quality.

---

## ⛔ STOP! READ THIS FIRST - Common Mistakes

> **Before writing any code**, review these recurring issues that cause rework every release cycle.
> PRs containing these patterns will be rejected.

### Mistake #1: Using `ThresholdError::Message` Instead of Structured Variants

This is our **#1 recurring issue** (154 violations in last audit).

```rust
// ❌ BAD - Gets rejected in code review
return Err(ThresholdError::Message("missing CRDT state".to_string()));
return Err(ThresholdError::Message(format!("invalid round: {}", round)));
.map_err(|e| ThresholdError::Message(e.to_string()))?;

// ✅ GOOD - Use structured error variants
return Err(ThresholdError::MissingCrdtState { event_id });
return Err(ThresholdError::InvalidRound { got: round, max: MAX_ROUND });
.map_err(ThresholdError::PrometheusError)?;  // Add new variant if needed
```

**Rule:** `ThresholdError::Message` is ONLY acceptable at the outermost edge (CLI argument parsing, final HTTP response formatting). Everywhere else, create a structured variant.

**If you need a new error variant**, add it to `foundation/error.rs`:
```rust
#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    // ... existing variants ...

    #[error("missing CRDT state for event_id={}", hex::encode(.event_id))]
    MissingCrdtState { event_id: Hash32 },
}
```

---

### Mistake #2: Error Messages Without Context

```rust
// ❌ BAD - Impossible to debug in production logs
return Err(ThresholdError::Message("missing CRDT state".to_string()));
return Err(ThresholdError::Message("proposal validation failed".to_string()));
warn!("failed to process message");

// ✅ GOOD - Always include identifiers
return Err(ThresholdError::MissingCrdtState { event_id });
// Or if you must use Message (edge case only):
return Err(ThresholdError::Message(format!(
    "proposal validation failed: event_id={} round={} reason={}",
    hex::encode(event_id), round, reason
)));
warn!("failed to process message event_id={} peer_id={} error={}",
    hex::encode(event_id), peer_id, err);
```

**Required context for common scenarios:**
| Scenario | Required Context |
|----------|-----------------|
| CRDT operations | `event_id`, `tx_template_hash` |
| Proposal operations | `event_id`, `round`, `proposer_peer_id` |
| Phase transitions | `event_id`, `from_phase`, `to_phase` |
| RPC calls | `method`, `target_address` |
| Storage errors | `key` (hex-encoded), `column_family` |

---

### Mistake #3: Magic Numbers

```rust
// ❌ BAD - What does 600 mean? 5000? 4?
if timeout_secs > 600 { ... }
tokio::time::sleep(Duration::from_millis(5000)).await;
for attempt in 1..=4 { ... }

// ✅ GOOD - Named constants with units
pub const MAX_SESSION_TIMEOUT_SECS: u64 = 600;
pub const PROPOSAL_TIMEOUT_MS: u64 = 5_000;
pub const MAX_SUBMIT_TX_ATTEMPTS: u32 = 4;

if timeout_secs > MAX_SESSION_TIMEOUT_SECS { ... }
tokio::time::sleep(Duration::from_millis(PROPOSAL_TIMEOUT_MS)).await;
for attempt in 1..=MAX_SUBMIT_TX_ATTEMPTS { ... }
```

**Where to put constants:**
- Domain policy constants → `igra-core/src/foundation/constants.rs`
- Module-specific constants → Top of the module file
- Configuration defaults → `igra-core/src/infrastructure/config/mod.rs`

---

### Mistake #4: `.unwrap()` / `.expect()` in Production Code

```rust
// ❌ BAD - Panics in production
let phase = storage.get_phase(&event_id).unwrap().unwrap();
let hash = hex::decode(input).expect("valid hex");

// ✅ GOOD - Propagate errors
let phase = storage.get_phase(&event_id)?
    .ok_or(ThresholdError::MissingPhaseState { event_id })?;
let hash = hex::decode(input)
    .map_err(|_| ThresholdError::InvalidHexInput { input: input.to_string() })?;

// ✅ ACCEPTABLE - Only in tests with context
let phase = storage.get_phase(&event_id)
    .expect("test setup: phase must exist after insert");
```

**Simple rule:** If it's not inside `#[cfg(test)]` or `#[test]`, don't use `.unwrap()` or `.expect()`.

---

### Mistake #5: Logging Hash32/Binary Data with `{:?}`

```rust
// ❌ BAD - Produces unreadable output like [1, 2, 3, 4, 5, ...]
info!("processing event event_id={:?}", event_id);
warn!("corrupted key key={:?}", key);

// ✅ GOOD - Human-readable hex
info!("processing event event_id={}", hex::encode(event_id));
warn!("corrupted key key={}", hex::encode(&key));
```

---

### Mistake #6: Logs Without Sufficient Context

```rust
// ❌ BAD - Useless in production
info!("done");
warn!("failed to decrypt");
debug!("processing message");

// ✅ GOOD - Actionable logs
info!("proposal committed event_id={} round={} canonical_hash={}",
    hex::encode(event_id), round, hex::encode(canonical_hash));
warn!("failed to decrypt hd.mnemonics config_path={} error={}", config_path, err);
debug!("processing gossip message msg_type={} sender={} size={}",
    msg_type, sender_peer_id, payload.len());
```

---

### Pre-Commit Checklist

Before submitting a PR, verify:

- [ ] **No `ThresholdError::Message`** outside CLI/HTTP edge (grep for it!)
- [ ] **All error messages include identifiers** (event_id, peer_id, round, etc.)
- [ ] **No magic numbers** - all literals have named constants
- [ ] **No `.unwrap()`/`.expect()`** in non-test code
- [ ] **All Hash32 values logged with `hex::encode()`**
- [ ] **All logs include actionable context**

**Quick grep commands to check your changes:**
```bash
# Find ThresholdError::Message usage
grep -rn "ThresholdError::Message" igra-core/src igra-service/src

# Find unwrap/expect in non-test code
grep -rn "\.unwrap()" igra-core/src igra-service/src | grep -v "_test\|#\[test\]\|#\[cfg(test)\]"
grep -rn "\.expect(" igra-core/src igra-service/src | grep -v "_test\|#\[test\]\|#\[cfg(test)\]"

# Find debug format on potential Hash32
grep -rn "{:?}" igra-core/src igra-service/src | grep -i "event_id\|hash\|key"
```

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

**Error type rules (by layer):**
- `domain/`: use precise, structured error enums (prefer `thiserror::Error`), no I/O errors and no opaque strings
- `application/`: map domain errors + infrastructure errors into a small set of actionable errors (typically `ThresholdError`)
- `infrastructure/`: keep raw dependency errors local; convert to a domain/application error at the boundary

**Prefer structured variants over `Message(String)`:**
```rust
// GOOD: machine-checkable + carries the right data
#[derive(Debug, thiserror::Error)]
pub enum ProposalError {
    #[error("round too high: got {got}, max {max}")]
    RoundTooHigh { got: u32, max: u32 },
}

// OK only at the very edge (CLI / HTTP) where you must return text
return Err(ThresholdError::Message(format!(
    "invalid proposal: event_id={} round={} reason={}",
    hex::encode(event_id),
    round,
    err
)));
```

**Add context where the error is handled, not where it is created:**
- Create errors with structured fields (ids, counts, limits)
- Add human-readable context at the boundary (API response, top-level handler log)

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

### 3.7 Constraints & Invariants

**Encode constraints in types when possible, validate at the boundaries otherwise:**
- Prefer *construction-time validation* (`TryFrom`, `new(...) -> Result<...>`) over scattered `if` checks
- Validate external inputs at boundaries: HTTP/CLI parsing, transport decoding, storage reads
- Keep invariants local: if a field must never be empty/zero/too-large, make it impossible to construct incorrectly

**Use newtypes for domain concepts (avoid “naked” primitives):**
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Round(u32);

impl Round {
    pub const MAX: u32 = 1_000;
    pub fn get(self) -> u32 { self.0 }
}

impl TryFrom<u32> for Round {
    type Error = ProposalError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::MAX {
            return Err(ProposalError::RoundTooHigh { got: value, max: Self::MAX });
        }
        Ok(Self(value))
    }
}
```

**Prefer domain-specific enums over booleans/strings:**
```rust
// GOOD
pub enum SelectionMode { Quorum, LowestHash }

// BAD
pub fn select(..., prefer_quorum: bool) -> ...
```

### 3.8 Constants & Magic Numbers

**No magic numbers in production code:**
- Replace numeric literals (limits, timeouts, sizes) with named `const` values
- Include units in names (`*_MS`, `*_BYTES`) or use strong types (`Duration`, `NonZeroUsize`)
- Keep constants close to the code that uses them (module-level `config.rs` is preferred for domain policy)

```rust
// GOOD
pub const MAX_KPSBT_SIZE_BYTES: usize = 64 * 1024;
pub const DEFAULT_PROPOSAL_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5_000);

// BAD
if blob.len() > 65536 { ... }
tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
```

**Exceptions:**
- `0`/`1` and small index offsets are acceptable when obvious
- Tests may use literals, but prefer named `const TEST_*` for anything policy-like

### 3.9 Modern Runtime (“Run Loop”) Patterns

**Service loops must be cancellable and bounded:**
- Use structured concurrency (`tokio::task::JoinSet`) instead of “fire-and-forget” `tokio::spawn`
- Provide a shutdown signal (e.g. `CancellationToken`) and `select!` on it
- Add timeouts around network/storage calls that can hang
- Use backoff for retry loops; never busy-loop on errors

```rust
loop {
    tokio::select! {
        _ = shutdown.cancelled() => break,
        result = transport.next_message() => {
            let msg = result?;
            handle_message(msg).await?;
        }
    }
}
```

### 3.10 Option/Result Combinators

**Prefer combinators over match/if-let chains:**
```rust
// GOOD: Concise and expressive
let value = storage.get_phase(&event_id)?
    .filter(|p| p.phase == EventPhase::Proposing)
    .map(|p| p.round)
    .unwrap_or(0);

// GOOD: Early return with ok_or_else
let phase = storage.get_phase(&event_id)?
    .ok_or_else(|| ThresholdError::Message("missing phase".into()))?;

// BAD: Verbose match chains
let value = match storage.get_phase(&event_id)? {
    Some(p) => {
        if p.phase == EventPhase::Proposing {
            p.round
        } else {
            0
        }
    }
    None => 0,
};
```

**Common combinator patterns:**
```rust
// Option → Result
opt.ok_or(Error::Missing)?
opt.ok_or_else(|| Error::Context { id })?

// Result → Option (discard error)
result.ok()

// Transform inner value
opt.map(|x| x.field)
result.map(|x| x.into())

// Chain fallible operations
opt.and_then(|x| x.validate())
result.and_then(|x| process(x))

// Provide defaults
opt.unwrap_or(default)
opt.unwrap_or_else(|| compute_default())
result.unwrap_or_default()

// Filter Options
opt.filter(|x| x.is_valid())

// Convert Option<Result<T>> to Result<Option<T>>
opt.transpose()
```

**Avoid `unwrap()` and `expect()` in production:**
```rust
// GOOD: Propagate errors
let data = storage.get(&key)?.ok_or(Error::NotFound)?;

// GOOD: In tests, expect() with context is acceptable
let data = storage.get(&key).expect("test setup: key must exist");

// BAD: Panics in production
let data = storage.get(&key).unwrap().unwrap();
```

### 3.11 Iterator Patterns

**Prefer iterators over indexed loops:**
```rust
// GOOD: Expressive, no off-by-one errors
let total: u64 = utxos.iter().map(|u| u.entry.amount).sum();

let valid_sigs: Vec<_> = signatures
    .iter()
    .filter(|s| s.is_valid())
    .cloned()
    .collect();

// BAD: Manual indexing
let mut total = 0u64;
for i in 0..utxos.len() {
    total += utxos[i].entry.amount;
}
```

**Common iterator patterns:**
```rust
// Collect into specific types
let vec: Vec<_> = iter.collect();
let map: HashMap<_, _> = iter.map(|x| (x.key, x.value)).collect();
let set: HashSet<_> = iter.collect();

// Find first match
iter.find(|x| x.matches(criteria))
iter.position(|x| x.id == target_id)

// Check conditions
iter.any(|x| x.is_invalid())
iter.all(|x| x.is_valid())

// Enumerate with index
for (idx, item) in items.iter().enumerate() { ... }

// Zip parallel iterators
for (a, b) in left.iter().zip(right.iter()) { ... }

// Chain iterators
first.iter().chain(second.iter())

// Flatten nested iterators
nested.iter().flatten()

// Take/skip
iter.take(10)
iter.skip(offset)
iter.take_while(|x| x.is_valid())

// Partition
let (valid, invalid): (Vec<_>, Vec<_>) = items.iter().partition(|x| x.is_valid());
```

**Use `Iterator::try_fold` for fallible accumulation:**
```rust
// GOOD: Early exit on error
let total = amounts.iter().try_fold(0u64, |acc, &x| {
    acc.checked_add(x).ok_or(ThresholdError::Overflow)
})?;

// BAD: Collects all errors, no early exit
let results: Result<Vec<_>, _> = items.iter().map(|x| process(x)).collect();
```

### 3.12 Lifetime Annotations

**Elision rules - don't annotate when the compiler can infer:**
```rust
// GOOD: Elision works
fn get_name(&self) -> &str { &self.name }
fn process(data: &[u8]) -> Result<(), Error> { ... }

// BAD: Unnecessary annotation
fn get_name<'a>(&'a self) -> &'a str { &self.name }
```

**When to annotate:**
```rust
// Multiple input lifetimes - must specify output relationship
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str { ... }

// Struct holding references
struct Parser<'input> {
    data: &'input [u8],
    position: usize,
}

// Trait bounds with lifetimes
fn process<'a, T: AsRef<[u8]> + 'a>(data: &'a T) -> &'a [u8] { ... }
```

**Prefer owned types over complex lifetimes:**
```rust
// GOOD: Simple, no lifetime tracking
pub struct Proposal {
    pub event_id: Hash32,
    pub kpsbt_blob: Vec<u8>,  // Owned
}

// AVOID: Complex lifetime propagation (unless performance-critical)
pub struct Proposal<'a> {
    pub event_id: &'a Hash32,
    pub kpsbt_blob: &'a [u8],
}
```

### 3.13 Smart Pointers & Interior Mutability

**Choose the right pointer type:**

| Type | Use Case |
|------|----------|
| `Box<T>` | Heap allocation, recursive types, trait objects |
| `Rc<T>` | Single-threaded shared ownership |
| `Arc<T>` | Multi-threaded shared ownership |
| `Cow<'a, T>` | Clone-on-write, avoid allocation when possible |

**Interior mutability patterns:**

| Type | Thread-Safe | Use Case |
|------|-------------|----------|
| `Cell<T>` | No | Copy types, single-threaded mutation |
| `RefCell<T>` | No | Runtime borrow checking, single-threaded |
| `Mutex<T>` | Yes | Exclusive access across threads |
| `RwLock<T>` | Yes | Multiple readers OR single writer |
| `AtomicU64` etc. | Yes | Lock-free counters, flags |
| `OnceCell<T>` | Depends | Lazy initialization |

```rust
// GOOD: Arc<Mutex<T>> for shared mutable state
let state = Arc::new(Mutex::new(State::new()));

// GOOD: RwLock for read-heavy workloads
let cache = Arc::new(RwLock::new(HashMap::new()));

// GOOD: Atomics for counters
let request_count = Arc::new(AtomicU64::new(0));
request_count.fetch_add(1, Ordering::Relaxed);

// GOOD: OnceCell for lazy init
static CONFIG: OnceCell<Config> = OnceCell::new();
let config = CONFIG.get_or_init(|| load_config());
```

### 3.14 Generics & Trait Bounds

**Prefer impl Trait in argument position for simple cases:**
```rust
// GOOD: Clear and concise
pub fn process(data: impl AsRef<[u8]>) -> Result<(), Error> { ... }
pub fn log_items(items: impl IntoIterator<Item = &str>) { ... }

// EQUIVALENT but more verbose
pub fn process<T: AsRef<[u8]>>(data: T) -> Result<(), Error> { ... }
```

**Use where clauses for complex bounds:**
```rust
// GOOD: Readable
pub fn merge<S, T>(storage: &S, transport: &T) -> Result<(), Error>
where
    S: Storage + Send + Sync,
    T: Transport + Clone,
{
    ...
}

// BAD: Cluttered signature
pub fn merge<S: Storage + Send + Sync, T: Transport + Clone>(
    storage: &S, transport: &T
) -> Result<(), Error> { ... }
```

**Avoid over-generic code:**
```rust
// GOOD: Concrete type when there's only one implementation
pub fn handle_proposal(storage: &RocksStorage, proposal: Proposal) { ... }

// BAD: Unnecessary generic (only one impl exists)
pub fn handle_proposal<S: Storage>(storage: &S, proposal: Proposal) { ... }
```

---

## 3.15 Database & Storage Patterns

### 3.15.1 Schema Design

**Use typed column family prefixes:**
```rust
// Column family constants
pub const CF_EVENTS: &str = "events";
pub const CF_CRDT: &str = "crdt";
pub const CF_PHASE: &str = "phase";
pub const CF_PROPOSALS: &str = "proposals";
pub const CF_SIGNED_HASH: &str = "event_signed_hash";

// Key format: {prefix}:{primary_key}:{secondary_key}
// Examples:
//   "evt:0x1234...abcd"                    → Event record
//   "crdt:0x1234...abcd:0x5678...efgh"     → CRDT state (event_id:tx_hash)
//   "phase:0x1234...abcd"                  → Phase state
//   "prop:0x1234...abcd:0:peer-1"          → Proposal (event_id:round:peer_id)
```

**Key encoding rules:**
```rust
// GOOD: Fixed-width keys for range scans
fn encode_proposal_key(event_id: &Hash32, round: u32, peer_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 4 + peer_id.len() + 2);
    key.extend_from_slice(event_id);
    key.extend_from_slice(&round.to_be_bytes());  // Big-endian for sort order
    key.push(b':');
    key.extend_from_slice(peer_id.as_bytes());
    key
}

// GOOD: Use big-endian for numeric keys (correct sort order)
let key = round.to_be_bytes();  // 0x00000001 < 0x00000002

// BAD: Little-endian breaks range scans
let key = round.to_le_bytes();  // 0x01000000 > 0x02000000 (wrong!)
```

**Value serialization:**
```rust
// GOOD: Use a single serialization format consistently
// We use JSON for human-debuggable data, Borsh for performance-critical paths

// JSON for configs, audit data
let bytes = serde_json::to_vec(&config)?;

// Borsh for high-volume data (CRDT state, proposals)
let bytes = borsh::to_vec(&crdt_state)?;

// Always version your schemas
#[derive(Serialize, Deserialize)]
pub struct StoredEventV1 {
    pub version: u8,  // = 1
    pub event: Event,
    pub received_at_nanos: u64,
}
```

### 3.15.2 Transaction Patterns

**Atomic multi-key updates:**
```rust
// GOOD: Use WriteBatch for atomic updates
let mut batch = rocksdb::WriteBatch::default();
batch.put_cf(&cf_phase, &phase_key, &phase_bytes);
batch.put_cf(&cf_crdt, &crdt_key, &crdt_bytes);
batch.put_cf(&cf_signed_hash, &signed_key, &hash_bytes);
db.write(batch)?;  // Atomic commit

// BAD: Non-atomic (can leave inconsistent state on crash)
db.put_cf(&cf_phase, &phase_key, &phase_bytes)?;
db.put_cf(&cf_crdt, &crdt_key, &crdt_bytes)?;  // Crash here = inconsistent
```

**Idempotent writes:**
```rust
// GOOD: Check-then-write with atomic semantics
pub fn record_signed_hash(
    &self,
    event_id: &Hash32,
    tx_hash: Hash32,
) -> Result<RecordSignedHashResult, Error> {
    let key = self.signed_hash_key(event_id);

    // Read existing
    if let Some(existing) = self.db.get_cf(&self.cf_signed_hash, &key)? {
        let existing_hash: Hash32 = deserialize(&existing)?;
        if existing_hash == tx_hash {
            return Ok(RecordSignedHashResult::AlreadyRecorded);
        } else {
            return Ok(RecordSignedHashResult::Conflict { existing: existing_hash });
        }
    }

    // Write new
    self.db.put_cf(&self.cf_signed_hash, &key, &tx_hash)?;
    Ok(RecordSignedHashResult::Recorded)
}
```

### 3.15.3 Range Queries & Iteration

**Prefix scans:**
```rust
// GOOD: Efficient prefix iteration
pub fn get_proposals(&self, event_id: &Hash32, round: u32) -> Result<Vec<Proposal>> {
    let prefix = self.proposal_prefix(event_id, round);
    let mut proposals = Vec::new();

    let iter = self.db.prefix_iterator_cf(&self.cf_proposals, &prefix);
    for item in iter {
        let (key, value) = item?;
        if !key.starts_with(&prefix) {
            break;  // Past our prefix
        }
        proposals.push(deserialize(&value)?);
    }
    Ok(proposals)
}
```

**Bounded iteration:**
```rust
// GOOD: Always bound iterations to prevent OOM
pub fn list_events(&self, limit: usize) -> Result<Vec<Hash32>> {
    let mut events = Vec::with_capacity(limit.min(1000));
    let iter = self.db.iterator_cf(&self.cf_events, IteratorMode::Start);

    for item in iter.take(limit) {
        let (key, _) = item?;
        events.push(parse_event_id(&key)?);
    }
    Ok(events)
}
```

### 3.15.4 Storage Trait Design

**Compose traits, don't bloat:**
```rust
// GOOD: Focused traits
pub trait EventStorage: Send + Sync {
    fn get_event(&self, id: &Hash32) -> Result<Option<StoredEvent>>;
    fn insert_event(&self, id: Hash32, event: StoredEvent) -> Result<()>;
    fn get_event_completion(&self, id: &Hash32) -> Result<Option<CompletionInfo>>;
}

pub trait PhaseStorage: Send + Sync {
    fn get_phase(&self, id: &Hash32) -> Result<Option<EventPhaseState>>;
    fn store_proposal(&self, proposal: &Proposal) -> Result<StoreProposalResult>;
    fn get_signed_hash(&self, id: &Hash32) -> Result<Option<Hash32>>;
}

pub trait CrdtStorage: Send + Sync {
    fn get_event_crdt(&self, id: &Hash32, tx_hash: &Hash32) -> Result<Option<StoredEventCrdt>>;
    fn merge_event_crdt(&self, id: &Hash32, tx_hash: &Hash32, state: &EventCrdtState) -> Result<bool>;
}

// Implementations can implement all traits
impl EventStorage for RocksStorage { ... }
impl PhaseStorage for RocksStorage { ... }
impl CrdtStorage for RocksStorage { ... }
```

---

## 3.16 Async, Concurrency & Synchronization

### 3.16.1 Choosing Sync Primitives

| Scenario | Use |
|----------|-----|
| Read-heavy, rare writes | `RwLock<T>` |
| Frequent writes | `Mutex<T>` |
| Simple counters/flags | `AtomicU64`, `AtomicBool` |
| One-time initialization | `OnceCell<T>` / `OnceLock<T>` |
| Cross-task communication | `mpsc::channel`, `broadcast::channel` |
| Shared state across tasks | `Arc<Mutex<T>>` or `Arc<RwLock<T>>` |
| Wait for condition | `tokio::sync::Notify` |

### 3.16.2 Lock Discipline

**Never hold locks across await points:**
```rust
// BAD: Deadlock risk, blocks executor
async fn bad_example(state: Arc<Mutex<State>>) {
    let guard = state.lock().await;
    some_async_call().await;  // Lock held across await!
    guard.do_something();
}

// GOOD: Clone/extract data, release lock, then await
async fn good_example(state: Arc<Mutex<State>>) {
    let data = {
        let guard = state.lock().await;
        guard.data.clone()
    };  // Lock released here
    let result = process_data(data).await;

    // Re-acquire if needed
    let mut guard = state.lock().await;
    guard.apply_result(result);
}
```

**Minimize critical section size:**
```rust
// GOOD: Lock only for the minimum necessary operation
let proposal = {
    let guard = proposals.lock().await;
    guard.get(&event_id).cloned()
};  // Lock released immediately

// Process outside lock
if let Some(p) = proposal {
    validate_proposal(&p).await?;
}

// BAD: Holding lock during expensive operations
let guard = proposals.lock().await;
for (id, proposal) in guard.iter() {
    validate_proposal(proposal).await?;  // Lock held entire loop!
}
```

**Lock ordering to prevent deadlocks:**
```rust
// GOOD: Document and enforce consistent ordering
// Rule: Always acquire locks in order: phase_storage → crdt_storage → transport

async fn commit_and_broadcast(
    phase: &Mutex<PhaseState>,
    crdt: &Mutex<CrdtState>,
    transport: &Mutex<Transport>,
) {
    let _phase_guard = phase.lock().await;      // 1st
    let _crdt_guard = crdt.lock().await;        // 2nd
    let _transport_guard = transport.lock().await; // 3rd
}

// BAD: Inconsistent ordering across call sites
```

### 3.16.3 Channel Patterns

**Use channels for cross-task communication:**
```rust
// GOOD: mpsc for many-to-one
let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(100);

// Producer tasks
let tx1 = tx.clone();
tokio::spawn(async move {
    tx1.send(Message::Proposal(p)).await.ok();
});

// Consumer task
tokio::spawn(async move {
    while let Some(msg) = rx.recv().await {
        handle_message(msg).await;
    }
});

// GOOD: oneshot for request-response
let (tx, rx) = tokio::sync::oneshot::channel();
task.send(Request { response_tx: tx }).await?;
let response = rx.await?;

// GOOD: broadcast for fan-out
let (tx, _) = tokio::sync::broadcast::channel::<Event>(100);
let mut rx1 = tx.subscribe();
let mut rx2 = tx.subscribe();
```

**Bounded channels to prevent unbounded growth:**
```rust
// GOOD: Bounded channel with backpressure
let (tx, rx) = mpsc::channel::<Proposal>(100);

// Sender will wait if channel is full
tx.send(proposal).await?;

// Or use try_send for non-blocking
match tx.try_send(proposal) {
    Ok(()) => { /* sent */ }
    Err(TrySendError::Full(_)) => { /* apply backpressure */ }
    Err(TrySendError::Closed(_)) => { /* receiver dropped */ }
}

// BAD: Unbounded channel (memory leak risk)
let (tx, rx) = mpsc::unbounded_channel();
```

### 3.16.4 Structured Concurrency

**Use JoinSet for managed task groups:**
```rust
// GOOD: Structured concurrency with JoinSet
let mut tasks = tokio::task::JoinSet::new();

for peer in peers {
    tasks.spawn(async move {
        send_to_peer(peer, message.clone()).await
    });
}

// Wait for all with timeout
let results = tokio::time::timeout(
    Duration::from_secs(5),
    async {
        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            results.push(result);
        }
        results
    }
).await;

// BAD: Fire-and-forget spawns (no tracking, no cleanup)
for peer in peers {
    tokio::spawn(send_to_peer(peer, message.clone()));
}
// No way to know when done or handle errors
```

**Cancellation with CancellationToken:**
```rust
use tokio_util::sync::CancellationToken;

let token = CancellationToken::new();
let child_token = token.child_token();

let handle = tokio::spawn(async move {
    loop {
        tokio::select! {
            _ = child_token.cancelled() => {
                info!("task cancelled, cleaning up");
                break;
            }
            result = do_work() => {
                handle_result(result);
            }
        }
    }
});

// Later: graceful shutdown
token.cancel();
handle.await?;
```

### 3.16.5 Async Trait Patterns

**Use `async_trait` for trait object safety:**
```rust
use async_trait::async_trait;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn publish(&self, msg: Message) -> Result<(), Error>;
    async fn subscribe(&self) -> Result<Subscription, Error>;
}

// Implementations
#[async_trait]
impl Transport for IrohTransport {
    async fn publish(&self, msg: Message) -> Result<(), Error> {
        self.inner.send(msg).await
    }
}

// Can use as trait object
fn create_service(transport: Arc<dyn Transport>) -> Service { ... }
```

---

## 3.17 Networking & RPC Patterns

### 3.17.1 Connection Management

**Use connection pools:**
```rust
// GOOD: Reuse connections
pub struct GrpcNodeRpc {
    client: RpcClient,  // Maintains connection pool internally
}

impl GrpcNodeRpc {
    pub async fn connect(url: String) -> Result<Self, Error> {
        let client = RpcClient::connect(&url).await?;
        Ok(Self { client })
    }
}

// BAD: New connection per request
pub async fn submit_tx(url: &str, tx: Transaction) -> Result<TxId, Error> {
    let client = RpcClient::connect(url).await?;  // Expensive!
    client.submit(tx).await
}
```

**Circuit breaker for failing services:**
```rust
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    last_failure: AtomicU64,
    threshold: u32,
    reset_timeout_ms: u64,
}

impl CircuitBreaker {
    pub fn is_open(&self) -> bool {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.threshold {
            return false;
        }
        // Check if reset timeout has passed
        let last = self.last_failure.load(Ordering::Relaxed);
        let now = current_time_ms();
        now - last < self.reset_timeout_ms
    }

    pub fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(current_time_ms(), Ordering::Relaxed);
    }
}
```

### 3.17.2 Timeouts & Retries

**Always set timeouts:**
```rust
// GOOD: Explicit timeout
let result = tokio::time::timeout(
    Duration::from_secs(5),
    rpc.get_utxos(&addresses)
).await??;

// GOOD: Configurable timeout
pub struct RpcConfig {
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
}

// BAD: No timeout (can hang forever)
let result = rpc.get_utxos(&addresses).await?;
```

**Exponential backoff with jitter:**
```rust
pub fn backoff_delay(attempt: u32, base_ms: u64, max_ms: u64, jitter_ms: u64) -> Duration {
    let exp_delay = base_ms.saturating_mul(2u64.saturating_pow(attempt.saturating_sub(1)));
    let capped = exp_delay.min(max_ms);

    // Add deterministic jitter
    let jitter = (hash_for_jitter(attempt) % (jitter_ms * 2 + 1)) as i64 - jitter_ms as i64;
    let with_jitter = (capped as i64 + jitter).max(0) as u64;

    Duration::from_millis(with_jitter)
}

// Usage
for attempt in 1..=max_retries {
    match rpc.submit_transaction(tx.clone()).await {
        Ok(id) => return Ok(id),
        Err(e) if is_retryable(&e) => {
            let delay = backoff_delay(attempt, 100, 30_000, 50);
            tokio::time::sleep(delay).await;
        }
        Err(e) => return Err(e),
    }
}
```

### 3.17.3 Request Validation

**Validate at the boundary:**
```rust
// GOOD: Validate and convert to domain types at API boundary
pub async fn handle_signing_request(
    req: SigningRequestJson,  // External type
) -> Result<Json<SigningResponse>, ApiError> {
    // Validate structure
    let event_id = parse_hex_hash32(&req.event_id_hex)
        .map_err(|_| ApiError::InvalidEventId)?;

    if req.amount_sompi == 0 {
        return Err(ApiError::InvalidAmount("amount must be > 0"));
    }

    // Convert to domain type (already validated)
    let params = SigningParams {
        event_id,
        amount_sompi: req.amount_sompi,
        // ...
    };

    // Domain logic works with validated types
    let result = process_signing(params).await?;
    Ok(Json(result.into()))
}
```

**Size limits on incoming data:**
```rust
// GOOD: Reject oversized requests early
pub const MAX_KPSBT_SIZE: usize = 64 * 1024;
pub const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

pub fn validate_proposal_size(proposal: &Proposal) -> Result<(), Error> {
    if proposal.kpsbt_blob.len() > MAX_KPSBT_SIZE {
        return Err(Error::KpsbtTooLarge {
            size: proposal.kpsbt_blob.len(),
            max: MAX_KPSBT_SIZE,
        });
    }
    if proposal.utxos_used.len() > MAX_UTXOS_PER_PROPOSAL {
        return Err(Error::TooManyUtxos { ... });
    }
    Ok(())
}
```

### 3.17.4 Idempotency

**Design idempotent operations:**
```rust
// GOOD: Idempotent submission (same input → same output, no side effects on replay)
pub async fn submit_transaction(&self, tx: Transaction) -> Result<TxId, Error> {
    let expected_id = tx.id();

    match self.rpc.submit(tx).await {
        Ok(id) => Ok(id),
        Err(e) if is_duplicate_error(&e) => {
            // Already submitted - return success
            info!("tx already in mempool, treating as success: {}", expected_id);
            Ok(expected_id)
        }
        Err(e) => Err(e),
    }
}

fn is_duplicate_error(e: &Error) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("already") && (
        msg.contains("mempool") ||
        msg.contains("known") ||
        msg.contains("exists")
    )
}
```

### 3.17.5 Gossip & P2P Patterns

**Message deduplication:**
```rust
pub struct MessageDeduplicator {
    seen: Mutex<LruCache<Hash32, Instant>>,
    ttl: Duration,
}

impl MessageDeduplicator {
    pub fn check_and_mark(&self, msg_hash: Hash32) -> bool {
        let mut seen = self.seen.lock().unwrap();

        // Prune expired entries
        let now = Instant::now();
        seen.retain(|_, &mut t| now.duration_since(t) < self.ttl);

        // Check if seen
        if seen.contains(&msg_hash) {
            return false;  // Duplicate
        }

        seen.put(msg_hash, now);
        true  // New message
    }
}
```

**Sender identity verification:**
```rust
// GOOD: Verify sender identity in envelope
pub fn validate_proposal_sender(
    proposal: &Proposal,
    envelope_sender: &PeerId,
) -> Result<(), Error> {
    if proposal.proposer_peer_id != *envelope_sender {
        return Err(Error::SenderMismatch {
            claimed: proposal.proposer_peer_id.clone(),
            actual: envelope_sender.clone(),
        });
    }
    Ok(())
}
```

---

## 3.18 Performance Considerations

### 3.18.1 Allocation Patterns

**Reuse allocations:**
```rust
// GOOD: Pre-allocate with capacity
let mut results = Vec::with_capacity(items.len());
for item in items {
    results.push(process(item)?);
}

// GOOD: Reuse buffer across iterations
let mut buffer = Vec::with_capacity(1024);
for msg in messages {
    buffer.clear();
    serialize_into(&mut buffer, &msg)?;
    send(&buffer).await?;
}

// BAD: Allocation per iteration
for msg in messages {
    let buffer = serialize(&msg)?;  // New allocation each time
    send(&buffer).await?;
}
```

**Use `Cow<T>` for conditional ownership:**
```rust
use std::borrow::Cow;

pub fn normalize_address(addr: &str) -> Cow<'_, str> {
    if addr.starts_with("kaspa:") {
        Cow::Borrowed(addr)  // No allocation
    } else {
        Cow::Owned(format!("kaspa:{}", addr))  // Allocation only when needed
    }
}
```

### 3.18.2 Serialization

**Choose format based on use case:**

| Format | Use Case | Pros | Cons |
|--------|----------|------|------|
| JSON | Config, API responses, debugging | Human-readable | Slow, verbose |
| Borsh | Storage, wire protocol | Fast, compact | Binary |
| Bincode | Internal serialization | Very fast | Not stable across versions |

```rust
// High-volume path: use Borsh
let bytes = borsh::to_vec(&crdt_state)?;
let state: CrdtState = borsh::from_slice(&bytes)?;

// Config/debugging: use JSON
let config: Config = serde_json::from_str(&json)?;
```

### 3.18.3 Hashing

**Use appropriate hash functions:**
```rust
// Cryptographic (for security): blake3 or sha256
let hash = blake3::hash(data);

// Non-cryptographic (for hash maps): use default hasher or ahash
use std::collections::HashMap;  // Uses SipHash by default

// For deterministic ordering across instances
use std::collections::BTreeMap;  // No hashing, uses Ord
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

### 5.1 Test Directory Structure

```
igra-core/
├── tests/
│   ├── unit.rs                    # Entry point → wires up tests/unit/*.rs
│   ├── integration.rs             # Entry point → wires up tests/integration/*.rs
│   ├── architecture.rs            # Layer enforcement tests (standalone)
│   ├── fixtures/                  # Shared test utilities
│   │   ├── mod.rs                 # Re-exports all fixtures
│   │   ├── constants.rs           # TEST_* constants (addresses, IDs)
│   │   ├── builders.rs            # Builder pattern (StoredEventBuilder)
│   │   ├── factories.rs           # Factory functions (stored_event(), group_config_2_of_3())
│   │   └── sample_data.rs         # Sample test data
│   ├── unit/
│   │   ├── mod.rs                 # Declares all unit test modules
│   │   ├── domain_crdt.rs         # Tests for domain/crdt
│   │   ├── domain_crdt_proptest.rs# Property-based tests
│   │   ├── domain_policy.rs       # Tests for domain/policy
│   │   ├── domain_event.rs        # Tests for domain/event
│   │   ├── domain_hashing.rs      # Tests for domain/hashes
│   │   ├── domain_signing.rs      # Tests for domain/signing
│   │   ├── domain_pskt.rs         # Tests for domain/pskt
│   │   └── domain_audit.rs        # Tests for domain/audit
│   └── integration/
│       ├── mod.rs                 # Declares all integration test modules
│       ├── crdt_storage.rs        # RocksDB CRDT storage tests
│       ├── config_loading.rs      # Configuration loading tests
│       ├── serialization.rs       # Serialization roundtrip tests
│       ├── rpc_kaspa.rs           # Kaspa RPC integration tests
│       └── hyperlane_client.rs    # Hyperlane client tests

igra-service/
└── tests/
    ├── api.rs                     # Entry point → wires up tests/api/*.rs
    ├── integration.rs             # Entry point → wires up tests/integration/*.rs
    ├── api/
    │   ├── mod.rs                 # Shared API test utilities (call_rpc, basic_state)
    │   ├── auth_test.rs           # Authentication tests
    │   ├── batch_test.rs          # Batch request tests
    │   └── rate_limit_test.rs     # Rate limiting tests
    └── integration/
        ├── mod.rs                 # Declares all integration test modules
        ├── crdt_e2e.rs            # Full 3-signer CRDT convergence test
        ├── crdt_partition.rs      # Network partition simulation
        └── crdt_gossip_validation.rs # Gossip validation tests
```

**Why this structure?**
- Cargo only discovers test files that are direct children of `tests/`
- We use entry-point files (`unit.rs`, `integration.rs`) with `#[path = "..."]` to maintain a prescriptive subdirectory structure

### 5.2 Test File Naming Conventions

| Test Type | File Name Pattern | Example |
|-----------|------------------|---------|
| Unit tests (domain) | `domain_<module>.rs` | `domain_crdt.rs`, `domain_policy.rs` |
| Unit tests (proptest) | `domain_<module>_proptest.rs` | `domain_crdt_proptest.rs` |
| Integration tests | `<feature>_<aspect>.rs` | `crdt_storage.rs`, `config_loading.rs` |
| API tests | `<feature>_test.rs` | `auth_test.rs`, `batch_test.rs` |
| E2E tests | `<feature>_e2e.rs` or descriptive | `crdt_e2e.rs`, `crdt_partition.rs` |
| Architecture tests | `architecture.rs` | Single file at `tests/architecture.rs` |

### 5.3 Test Function Naming

**Pattern:** `test_<what>_<scenario>` or `test_<what>_when_<condition>_then_<expected>`

```rust
// Simple scenario
#[test]
fn test_gset_merge_properties() { ... }

#[test]
fn test_lww_register_basic() { ... }

#[test]
fn test_event_crdt_threshold_and_merge() { ... }

// When/then pattern for edge cases
#[test]
fn test_policy_enforcement_when_destination_not_allowed_then_rejects() { ... }

#[test]
fn test_policy_enforcement_when_amount_below_min_then_rejects() { ... }

#[test]
fn test_policy_enforcement_when_daily_volume_exceeded_then_rejects() { ... }

// Async tests
#[tokio::test]
async fn test_concurrent_crdt_updates() { ... }

#[tokio::test]
async fn crdt_three_signer_converges_and_completes() { ... }
```

### 5.4 Test Fixtures

**Constants** (`fixtures/constants.rs`):
```rust
pub const TEST_NETWORK_PREFIX: Prefix = Prefix::Testnet;
pub const TEST_DESTINATION_ADDRESS: &str = "kaspatest:qz0hz8jkn6ptfhq3v9fg...";
pub const TEST_COORDINATOR_PEER_ID: &str = "peer-1";
pub const TEST_SESSION_ID_HEX: &str = "0x1111111111111111...";
pub const TEST_EXTERNAL_ID_RAW: &str = "0x4242424242424242...";
```

**Builders** (`fixtures/builders.rs`) - for customizable test data:
```rust
pub struct StoredEventBuilder {
    external_id_raw: String,
    source: SourceType,
    destination_raw: String,
    amount_sompi: u64,
    // ...
}

impl StoredEventBuilder {
    pub fn amount_sompi(mut self, amount_sompi: u64) -> Self {
        self.amount_sompi = amount_sompi;
        self
    }

    pub fn destination_address(mut self, addr: impl Into<String>) -> Self {
        self.destination_raw = addr.into();
        self
    }

    pub fn build(self) -> StoredEvent { ... }
}

// Usage in tests:
let event = StoredEventBuilder::default()
    .amount_sompi(100)
    .destination_address("kaspatest:...")
    .build();
```

**Factories** (`fixtures/factories.rs`) - for common default objects:
```rust
pub fn stored_event() -> StoredEvent { ... }
pub fn group_policy_allow_all() -> GroupPolicy { ... }
pub fn group_config_2_of_3() -> GroupConfig { ... }
pub fn coordinator_peer_id() -> String { ... }
```

### 5.5 Inline Tests (cfg(test) modules)

For simple, tightly-coupled tests, use inline `#[cfg(test)]` modules:

```rust
// domain/crdt/event_state.rs

impl EventCrdt {
    pub fn add_signature(&mut self, record: SignatureRecord) -> bool { ... }
    // ...
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only helpers
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

    #[test]
    fn test_add_signature() {
        let mut crdt = EventCrdt::new(EVENT_HASH, TX_HASH);
        assert!(crdt.add_signature(make_sig(0, 1, 10)));
        assert!(crdt.add_signature(make_sig(0, 2, 20)));
        assert!(!crdt.add_signature(make_sig(0, 1, 10))); // Duplicate
        assert_eq!(crdt.signature_count(), 2);
    }
}
```

**When to use inline vs external tests:**
- **Inline (`#[cfg(test)]`):** Simple unit tests for a single struct/function, test helpers that need private access
- **External (`tests/unit/`):** Tests that span multiple modules, need fixtures, or benefit from separation

### 5.6 Property-Based Testing (Proptest)

For CRDT invariants and other properties that should hold across many inputs:

```rust
// tests/unit/domain_crdt_proptest.rs

fn next_u64(state: &mut u64) -> u64 {
    // Deterministic LCG for reproducible "random" tests
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
    *state
}

#[test]
fn merge_commutative_for_signatures_and_completion() {
    for seed in 0u64..100u64 {
        let mut a = EventCrdt::new(event_hash, tx_hash);
        let mut b = EventCrdt::new(event_hash, tx_hash);

        // Generate random signatures
        let mut rng = seed ^ 0xA5A5_5A5A_DEAD_BEEF;
        for _ in 0..20 {
            a.add_signature(sig_record(&mut rng, 3, ((next_u64(&mut rng) % 5) as u8) + 1));
        }
        for _ in 0..20 {
            b.add_signature(sig_record(&mut rng, 3, ((next_u64(&mut rng) % 5) as u8) + 1));
        }

        // Verify commutativity: merge(a, b) == merge(b, a)
        let ab = merge_event_states(&a, &b);
        let ba = merge_event_states(&b, &a);
        assert_eq!(sig_key_set(&ab), sig_key_set(&ba));
    }
}

#[test]
fn merge_idempotent_for_signatures_and_completion() {
    for seed in 0u64..100u64 {
        let mut crdt = EventCrdt::new(event_hash, tx_hash);
        // ... add signatures ...

        let before = sig_key_set(&crdt);
        let mut mutated = crdt.clone();
        mutated.merge(&crdt.clone());
        assert_eq!(before, sig_key_set(&mutated)); // Idempotent
    }
}
```

### 5.7 Architecture Tests

Enforce layer rules at compile/test time (`tests/architecture.rs`):

```rust
#[test]
fn domain_does_not_depend_on_infrastructure() {
    check_no_import(DOMAIN_PATH, "crate::infrastructure", "domain/", "infrastructure/");
}

#[test]
fn domain_does_not_depend_on_application() {
    check_no_import(DOMAIN_PATH, "crate::application", "domain/", "application/");
}

#[test]
fn domain_does_not_use_tokio() {
    check_no_import(DOMAIN_PATH, "tokio", "domain/", "tokio (async runtime is infrastructure concern)");
}

#[test]
fn domain_functions_are_synchronous() {
    // Scans for `async fn` in domain/ and fails if found
}

#[test]
fn domain_error_types_are_debug() {
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<igra_core::foundation::ThresholdError>();
}
```

### 5.8 Mock Implementations

For service integration tests, use mock implementations:

```rust
// MockTransport for gossip testing
let hub = Arc::new(MockHub::new());
let transports = [
    Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-1"), group_id, 2)),
    Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-2"), group_id, 2)),
    Arc::new(MockTransport::new(hub.clone(), PeerId::from("signer-3"), group_id, 2)),
];

// UnimplementedRpc for controlled RPC responses
let rpc = Arc::new(UnimplementedRpc::new());
rpc.push_utxo(UtxoWithOutpoint { ... });

// MemoryStorage for fast in-memory tests
let storage = Arc::new(MemoryStorage::new());

// NoopVerifier to skip signature verification
let verifier = Arc::new(NoopVerifier);
```

### 5.9 E2E Test Pattern

Full integration tests with multiple simulated signers:

```rust
#[tokio::test]
async fn crdt_three_signer_converges_and_completes() -> Result<(), ThresholdError> {
    // 1. Setup: Create key material, mock transport hub, storage per signer
    let hub = Arc::new(MockHub::new());
    let key_data = create_test_keys();
    let transports = create_mock_transports(&hub, 3);
    let storages = create_memory_storages(3);

    // 2. Start coordination loops for each signer
    let loops = start_coordination_loops(&configs, &transports, &storages);
    tokio::time::sleep(LOOP_STARTUP_GRACE).await;

    // 3. Submit same event to all signers
    for i in 0..3 {
        submit_signing_event(&contexts[i], signing_event("event-1")).await?;
    }

    // 4. Wait for completion with timeout
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if all_completed(&storages, &event_id)? { break; }
        if tokio::time::Instant::now() > deadline {
            return Err(ThresholdError::Message("timeout".into()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 5. Cleanup
    for handle in loops { handle.abort(); }
    Ok(())
}
```

### 5.10 Test Commands

```bash
# Run all tests
cargo test --workspace

# Run specific test file
cargo test --test unit                    # igra-core/tests/unit.rs
cargo test --test integration             # igra-core/tests/integration.rs
cargo test --test architecture            # Architecture enforcement

# Run specific test module
cargo test -p igra-core domain_crdt       # Tests containing "domain_crdt"
cargo test -p igra-service crdt_e2e       # E2E CRDT tests

# Run specific test function
cargo test -p igra-core test_gset_merge_properties

# Run with output (for debugging)
cargo test -- --nocapture

# Run ignored tests
cargo test -- --ignored

# Run with nextest (faster)
cargo nextest run --workspace
```

### 5.11 Test Checklist

Before submitting:

- [ ] Unit tests for new domain logic
- [ ] Integration tests for storage/transport changes
- [ ] Test names follow `test_<what>_<scenario>` pattern
- [ ] Fixtures used for reusable test data
- [ ] No `#[ignore]` without explanation in comment
- [ ] Async tests use `#[tokio::test]`
- [ ] Architecture tests still pass (`cargo test --test architecture`)

---

## 6. Code Review Checklist

Before submitting PR, verify:

### AI-Assisted Workflow (Default Prompt)

When using an LLM/AI while working on this repo, follow this process by default:

1. **Decompose**: break the task into small, testable sub-problems
2. **Cross-check**: validate each sub-result from multiple perspectives (spec vs code, safety vs liveness, edge cases, performance/ops)
3. **Confidence-score**: attach a confidence score to each non-trivial claim/decision (e.g., `high/medium/low` or `0.0–1.0`)
4. **Reflect & repair**: explicitly revisit weak/low-confidence parts and improve them (or mark them as open questions)
5. **Finalize only when high-confidence**: only “commit” (finalize a patch/PR-ready change or a definitive recommendation) once the remaining key claims are high-confidence; otherwise, ask for missing data, run checks, or narrow scope

**Copy/paste prompt template**
```text
Follow this workflow:
1) Decompose the problem into 3–7 sub-tasks.
2) For each sub-task, cross-check from at least 2 perspectives (e.g., correctness + edge cases).
3) For each important claim/assumption/decision, include a confidence score (high/medium/low).
4) If confidence is not high, propose how to verify (tests, logs, grep, cargo commands) and revise.
5) Only finalize the implementation plan/patch when confidence on key items is high.
```

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
- [ ] No magic numbers (named constants + units)
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

*Version: 1.4*
*Last Updated: 2026-01-16*

---

## Appendix: Audit History

| Date | Version | Violations Found | Key Issues |
|------|---------|------------------|------------|
| 2026-01-16 | 1.4 | 198 | `ThresholdError::Message` overuse (154), magic numbers (30), missing context (11) |
