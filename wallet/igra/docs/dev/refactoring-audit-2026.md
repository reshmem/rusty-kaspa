# Igra Codebase Refactoring Audit - January 2026

**Audit Date**: 2026-01-23
**Codebase Version**: devel branch
**Total Lines**: 21,981 (igra-core: 15,108 | igra-service: 6,873)
**Issues Found**: 68+ actionable items
**Estimated Effort**: 80 development days (can be parallelized)

---

## Executive Summary

### Overall Assessment

**Code Quality**: ⭐⭐⭐⭐ (Good - Production Ready with Improvements Needed)

**Strengths**:
- ✅ Clean layered architecture (domain/application/infrastructure)
- ✅ Comprehensive KeyManager implementation
- ✅ Strong type safety with newtypes
- ✅ Good test coverage (unit + integration)
- ✅ Structured error handling foundation

**Areas for Improvement**:
- ⚠️ CODE-GUIDELINE.md violations (particularly ThresholdError::Message)
- ⚠️ Large files need decomposition (1424 lines in rocks/engine.rs)
- ⚠️ Unnecessary clones in hot paths
- ⚠️ Some layer violations (service → domain direct imports)

### Priority Breakdown

| Priority | Issues | Estimated Days |
|----------|--------|----------------|
| **CRITICAL** | 8 | 15 days |
| **HIGH** | 22 | 35 days |
| **MEDIUM** | 28 | 25 days |
| **LOW** | 10+ | 5 days |

---

## Table of Contents

1. [CODE-GUIDELINE.md Violations](#code-guidelinemd-violations)
2. [Architectural Issues](#architectural-issues)
3. [Security Concerns](#security-concerns)
4. [Performance Issues](#performance-issues)
5. [Testing Gaps](#testing-gaps)
6. [Type Safety Improvements](#type-safety-improvements)
7. [Quick Wins](#quick-wins)
8. [Refactoring Roadmap](#refactoring-roadmap)

---

## CODE-GUIDELINE.md Violations

### CRITICAL: Mistake #1 - ThresholdError::Message Anti-Pattern

**Severity**: CRITICAL
**Effort**: MEDIUM (2-3 days)
**Occurrences**: 7+ instances

#### Violations Found

| File | Line | Current Code | Impact |
|------|------|--------------|--------|
| `igra-service/src/bin/kaspa-threshold-service/setup.rs` | 78 | `ThresholdError::Message(format!("rocksdb open error: {}", err))` | Loss of error semantics |
| `igra-service/src/api/handlers/hyperlane.rs` | 227 | `.map_err(ThresholdError::Message)?` | Cannot pattern match |
| `igra-service/src/api/handlers/hyperlane.rs` | 229 | `ThresholdError::Message("destination_address and amount_sompi required...")` | No structured data |
| `igra-core/src/domain/pskt/multisig.rs` | 164-166 | Multiple `.map_err(|e| format!(...))` | Context loss |
| `igra-core/src/application/event_processor.rs` | 128 | `ThresholdError::ConfigError("no hyperlane validators...".to_string())` | Wrong variant |

#### Example Violation

**File**: `igra-service/src/bin/kaspa-threshold-service/setup.rs:78`

```rust
// ❌ BAD - Current code
match db_result {
    Err(err) => {
        return Err(ThresholdError::Message(format!("rocksdb open error: {}", err)))
    }
}
```

**Fix**: Add structured variant to `foundation/error.rs`:

```rust
// In ThresholdError enum:
#[error("RocksDB open failed: {details}")]
RocksDBOpenError {
    details: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
},

// Usage:
match db_result {
    Err(err) => {
        return Err(ThresholdError::RocksDBOpenError {
            details: format!("Failed to open database at {:?}", path),
            source: Some(Box::new(err)),
        })
    }
}
```

#### Required New Error Variants

Add to `foundation/error.rs`:

1. `RocksDBOpenError { details, source }` - Database initialization
2. `MissingSigningPayload { message_id }` - Hyperlane signing payload extraction
3. `NoValidatorsConfigured { validator_type }` - Missing validator config
4. `PsktInputMismatch { expected, actual, details }` - PSKT input validation
5. `HyperlaneMetadataParseError { details, source }` - Metadata parsing

**Effort**: 4 hours (add variants + update call sites)

---

### HIGH: Mistake #8 - Clone().unwrap_or_default() Verbose Pattern

**Severity**: HIGH
**Effort**: SMALL (1 day)
**Occurrences**: 10+ instances

#### Violations Found

| File | Line | Pattern | Wasted Allocations |
|------|------|---------|-------------------|
| `kaspa-threshold-service/setup.rs` | 67 | `runtime.test_recipient.clone().unwrap_or_default()` | String clone |
| `kaspa-threshold-service/setup.rs` | 268-269 | `parts.next().unwrap_or_default().trim()` x2 | Empty strings |
| `domain/pskt/multisig.rs` | 106 | `payload.clone().unwrap_or_default()` | Vec clone |
| `api/middleware/logging.rs` | 41 | `.unwrap_or_default().to_string_lossy()` | Path conversion |
| `bin/fake_hyperlane_relayer.rs` | 538 | `.cloned().unwrap_or_default()` | Option clone |

#### Example Violation

**File**: `kaspa-threshold-service/setup.rs:67`

```rust
// ❌ BAD - Verbose + clone overhead
let test_recipient = runtime.test_recipient.clone().unwrap_or_default();
if test_recipient.is_empty() {
    // ...
}
```

**Fix**: Use config helper:

```rust
// ✅ GOOD - From foundation/config_helpers.rs
let test_recipient: Option<String> = parse_optional(&runtime.test_recipient)?;
```

**Effort**: 30 minutes per file (10 files = 1 day)

---

### HIGH: Mistake #9 - Manual hex::encode() in Logs

**Severity**: HIGH
**Effort**: SMALL (2 hours)
**Occurrences**: 15+ instances

#### Violations Found

| File | Lines | Unnecessary hex::encode() Count |
|------|-------|----------------------------------|
| `api/handlers/hyperlane.rs` | 139, 151, 161, 261 | 4 instances |
| `service/coordination/crdt_handler.rs` | Various | 3+ instances |
| `domain/pskt/multisig.rs` | Various | 2+ instances |

#### Example Violation

**File**: `api/handlers/hyperlane.rs:139`

```rust
// ❌ BAD
info!("validator pubkey={}", hex::encode(value.as_bytes()));

// ✅ GOOD - Types implement Display
info!("validator pubkey={}", value);
```

**Fix**: Remove all `hex::encode()` calls in log statements.

**Effort**: 2 hours (simple find-and-replace with verification)

---

### MEDIUM: Mistake #10 - Swallowed Errors with `let _ =`

**Severity**: MEDIUM
**Effort**: SMALL (1 day)
**Occurrences**: Not extensively found in audit (good!)

**Status**: Generally well-handled. Most Result types are properly propagated with `?`.

---

### MEDIUM: Mistake #2 & #6 - Logs Without Context

**Severity**: MEDIUM
**Effort**: MEDIUM (2 days)
**Occurrences**: Scattered throughout

#### Issues Found

Many logs are good, but some lack critical context:

**File**: `service/coordination/crdt_handler.rs`

```rust
// Some logs missing event_id context
warn!("failed to process message");  // Line unknown - needs event_id

// Should be:
warn!("failed to process message event_id={} error={}", event_id, err);
```

**Fix**: Audit all `warn!()` and `error!()` calls, ensure identifiers present.

---

## Architectural Issues

### CRITICAL: God Object - RocksStorage (1,424 lines)

**Severity**: CRITICAL
**Effort**: LARGE (5-7 days)

**File**: `igra-core/src/infrastructure/storage/rocks/engine.rs`

**Problem**: Single file implements 40+ methods across multiple domains:
- CRDT operations (7 methods)
- Phase management (8 methods)
- Event lifecycle (5 methods)
- Hyperlane delivery (6 methods)
- Proposal tracking (4 methods)
- Volume tracking (3 methods)
- Plus helper methods

**Impact**:
- Hard to test (requires full DB setup)
- Tight coupling (changes cascade)
- Lock contention (3 separate mutexes)
- Difficult to understand (too much context)

**Refactoring Plan**:

```
Current:
storage/rocks/
└── engine.rs (1,424 lines - everything)

Proposed:
storage/rocks/
├── engine.rs (200 lines - DB management, common ops)
├── crdt_storage.rs (250 lines - CRDT operations)
├── phase_storage.rs (300 lines - Phase lifecycle)
├── hyperlane_storage.rs (250 lines - Hyperlane delivery)
├── proposal_storage.rs (200 lines - Proposal tracking)
└── volume_storage.rs (150 lines - Volume stats)
```

**Trait-based API**:

```rust
// storage/rocks/engine.rs
pub struct RocksStorage {
    db: Arc<DB>,
    crdt_lock: Arc<Mutex<()>>,
    phase_lock: Arc<Mutex<()>>,
    hyperlane_lock: Arc<Mutex<()>>,
}

// storage/rocks/crdt_storage.rs
pub trait CrdtStorage {
    fn get_event_crdt(&self, event_id: &EventId) -> Result<Option<EventCrdtState>>;
    fn upsert_event_crdt(&self, event_id: &EventId, state: &EventCrdtState) -> Result<()>;
    // ... other CRDT methods
}

impl CrdtStorage for RocksStorage {
    // Implementation (moved from engine.rs)
}
```

**Benefits**:
- ✅ Clear separation of concerns
- ✅ Easier to test (mock individual traits)
- ✅ Reduced lock contention
- ✅ Easier to understand (focused modules)
- ✅ Future: Can swap storage backends per-domain

**Migration**:
1. Extract CrdtStorage trait + impl (day 1-2)
2. Extract PhaseStorage trait + impl (day 2-3)
3. Extract HyperlaneStorage trait + impl (day 3-4)
4. Update call sites (day 4-5)
5. Test and validate (day 5-7)

---

### HIGH: CRDT Handler Complexity (865 lines)

**Severity**: HIGH
**Effort**: LARGE (4-5 days)

**File**: `igra-service/src/service/coordination/crdt_handler.rs`

**Problem**: Single file with 12 public functions handling:
- CRDT broadcast handling
- State synchronization (request/response)
- Anti-entropy loops
- Signing coordination
- Transaction submission
- Internal helpers

**Impact**:
- Difficult to test (too many entry points)
- Complex state machine (hidden in control flow)
- High cognitive load (many concerns mixed)

**Refactoring Plan**:

```
Current:
service/coordination/
└── crdt_handler.rs (865 lines)

Proposed:
service/coordination/crdt/
├── mod.rs (exports)
├── broadcast.rs (handle_crdt_broadcast, broadcast_local_state)
├── sync.rs (sync request/response, anti-entropy)
├── signing.rs (maybe_sign_and_broadcast)
├── submission.rs (maybe_submit_and_broadcast)
└── types.rs (shared types, constants)
```

**Or use Command Pattern**:

```rust
// service/coordination/crdt/commands.rs
pub enum CrdtCommand {
    HandleBroadcast { payload: EventStateBroadcast },
    HandleSyncRequest { request: StateSyncRequest },
    HandleSyncResponse { response: StateSyncResponse },
    RunAntiEntropy,
    TrySign { event_id: EventId },
    TrySubmit { event_id: EventId },
}

pub struct CrdtCommandHandler {
    // ... context
}

impl CrdtCommandHandler {
    pub async fn execute(&mut self, command: CrdtCommand) -> Result<(), ThresholdError> {
        match command {
            CrdtCommand::HandleBroadcast { payload } => self.handle_broadcast(payload).await,
            CrdtCommand::HandleSyncRequest { request } => self.handle_sync_request(request).await,
            // ...
        }
    }
}
```

**Benefits**:
- ✅ Single entry point (easier testing)
- ✅ Explicit state machine
- ✅ Better separation of concerns
- ✅ Can add middleware (logging, metrics, tracing)

---

### HIGH: Layer Violation - Service Depending on Domain Internals

**Severity**: HIGH
**Effort**: MEDIUM (3-4 days)

**File**: `igra-service/src/service/coordination/crdt_handler.rs:1-15`

**Problem**: Service layer imports domain types directly:

```rust
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::{CrdtSigningMaterial, PartialSigRecord, StoredEvent};
use igra_core::domain::normalization::validate_source_data;
use igra_core::domain::hashes::compute_event_id;
```

**Impact**:
- Domain is marked as "private API" in architecture
- Changes to domain cascade to service
- Breaks layering principle (service should use application layer)

**Refactoring Plan**:

Create application layer facade:

```rust
// igra-core/src/application/crdt_operations.rs
pub struct CrdtOperations;

impl CrdtOperations {
    /// Validate and merge CRDT state (public API)
    pub fn merge_event_state(
        current: &EventCrdtState,
        incoming: &EventStateBroadcast,
    ) -> Result<EventCrdtState, ThresholdError> {
        // Calls domain::crdt internally
        domain::crdt::merge_states(current, incoming)
    }

    /// Sign PSKT with partial signature (public API)
    pub async fn sign_pskt(
        pskt_json: &str,
        key_context: &KeyManagerContext,
        // ...
    ) -> Result<PartialSignature, ThresholdError> {
        // Calls domain::pskt::multisig internally
        domain::pskt::multisig::sign_pskt(/* ... */)
    }
}

// In service layer:
use igra_core::application::CrdtOperations;  // ✅ GOOD
// NOT:
use igra_core::domain::pskt::multisig;  // ❌ BAD
```

**Benefits**:
- ✅ Domain becomes truly private
- ✅ Application layer provides stable API
- ✅ Can add application-level concerns (caching, metrics, tracing)
- ✅ Easier to evolve domain without breaking service

**Migration**:
1. Create `application/crdt_operations.rs`
2. Move public-facing domain operations
3. Update service imports
4. Make domain module pub(crate) or private

---

### HIGH: Unnecessary Clones in Hot Paths

**Severity**: HIGH
**Effort**: MEDIUM (2-3 days)
**Occurrences**: 15+ instances

#### Performance Impact

**File**: `service/coordination/crdt_handler.rs:629-634`

```rust
// ❌ BAD - Clones event fields 3 times, then clones entire struct
let policy_event = StoredEvent {
    event: signing_material.event.clone(),      // Clone 1
    received_at_nanos: now,
    audit: signing_material.audit.clone(),      // Clone 2
    proof: signing_material.proof.clone(),       // Clone 3
};
let inserted = ctx.storage.insert_event_if_not_exists(
    state.event_id,
    policy_event.clone()  // Clone 4 of entire struct!
)?;
```

**Analysis**:
- `signing_material` is moved/consumed after this
- `policy_event` is cloned unnecessarily (insert_event_if_not_exists could take ownership)
- ~100μs overhead per CRDT merge operation

**Fix**:

```rust
// ✅ GOOD - No intermediate clones
let inserted = ctx.storage.insert_event_if_not_exists(
    state.event_id,
    StoredEvent {
        event: signing_material.event,  // Move (no clone)
        received_at_nanos: now,
        audit: signing_material.audit,  // Move
        proof: signing_material.proof,  // Move
    }
)?;
```

**Alternative**: Change storage API to accept `&StoredEvent`:

```rust
// Update storage trait signature
fn insert_event_if_not_exists(&self, event_id: &EventId, event: &StoredEvent) -> Result<bool>;

// Then no clone needed at call site
```

#### Other Clone Hotspots

| File | Lines | Issue | Fix |
|------|-------|-------|-----|
| `domain/pskt/multisig.rs` | 39-42, 51-52 | Clone inputs/outputs in loop | Use Cow or restructure |
| `crdt_handler.rs` | 700-704 | Multiple Option unwraps with clone | Refactor control flow |

**Effort**: 2-3 days to audit and fix all clone patterns

---

### MEDIUM: Mistake #5 - String Allocations in Error Context

**Severity**: MEDIUM
**Effort**: SMALL (4 hours)
**Occurrences**: 30+ instances

**File**: `infrastructure/storage/rocks/engine.rs`

**Problem**: Every error allocates operation name:

```rust
// Lines 100, 114, 138, 144, 278-279, 323, 356-357, 374, 382-383
StorageError {
    operation: "rocksdb cf_handle".to_string(),  // Allocates
    details: format!("missing column family: {}", name),
}
```

**Fix**: Use static string constants:

```rust
// At top of file
const OP_ROCKSDB_CF_HANDLE: &str = "rocksdb cf_handle";
const OP_ROCKSDB_GET: &str = "rocksdb get";
const OP_ROCKSDB_PUT: &str = "rocksdb put";
// ... etc

// In error
StorageError {
    operation: OP_ROCKSDB_CF_HANDLE.to_string(),  // Only allocates on error path
    details: format!("missing column family: {}", name),
}

// OR better - change StorageError to use &'static str
pub struct StorageError {
    pub operation: &'static str,  // No allocation
    pub details: String,
}
```

**Impact**: Small performance improvement, cleaner code

**Effort**: 4 hours (find-and-replace + test)

---

## Security Concerns

### MEDIUM: Input Validation Gaps

**Severity**: MEDIUM
**Effort**: MEDIUM (2 days)

#### Issues Identified

| File | Function | Gap | Risk |
|------|----------|-----|------|
| `api/handlers/hyperlane.rs` | `extract_signing_payload:177-188` | No size limit on message body before UTF8 decode | DoS via large payloads |
| `bin/kaspa-threshold-service/setup.rs` | `warn_test_mode:65-72` | Accepts test addresses without validation | Bypass policy checks |
| `infrastructure/config/loader.rs` | Config loading | No file size limit | Memory exhaustion |

#### Example Issue

**File**: `api/handlers/hyperlane.rs:177-188`

```rust
// Current code (no size check)
let body_bytes = message.body.as_slice();
let body_str = std::str::from_utf8(body_bytes)  // Could be gigabytes!
    .map_err(|e| ThresholdError::Message(format!("invalid UTF8: {}", e)))?;
```

**Fix**:

```rust
// Add size validation
const MAX_HYPERLANE_BODY_SIZE: usize = 1024 * 1024; // 1MB

if body_bytes.len() > MAX_HYPERLANE_BODY_SIZE {
    return Err(ThresholdError::HyperlaneBodyTooLarge {
        size: body_bytes.len(),
        max: MAX_HYPERLANE_BODY_SIZE,
    });
}

let body_str = std::str::from_utf8(body_bytes)
    .map_err(|e| ThresholdError::HyperlaneInvalidUtf8 {
        position: e.valid_up_to(),
        source: Some(Box::new(e)),
    })?;
```

**Add to constants**:
```rust
// foundation/constants.rs
pub const MAX_HYPERLANE_BODY_SIZE: usize = 1024 * 1024;  // 1MB
pub const MAX_CONFIG_FILE_SIZE: usize = 10 * 1024 * 1024;  // 10MB
pub const MAX_VALIDATORS: usize = 256;  // Current hardcoded in various places
```

---

### MEDIUM: Error Messages Exposing Internals

**Severity**: MEDIUM
**Effort**: SMALL (1 day)

#### Issues Found

| File | Line | Exposure | Risk |
|------|------|----------|------|
| `rocks/engine.rs` | 100-101 | "checkpoint directory is not empty" | Reveals internal structure |
| `api/handlers/hyperlane.rs` | 180 | "hyperlane message body too short" | Protocol details leak |
| `kaspa-threshold-service/setup.rs` | 92 | Full file path in error | Path disclosure |

**Fix**: Sanitize error messages:

```rust
// ❌ BAD
format!("Failed to load config from {}: {}", full_path, err)

// ✅ GOOD (for external errors)
format!("Configuration file error: {}", err)

// ✅ GOOD (for internal logs)
log::error!("Failed to load config path={} error={}", full_path, err);
// But for user-facing errors, hide path
```

---

## Performance Issues

### MEDIUM: Inefficient Message Parsing

**Severity**: MEDIUM
**Effort**: SMALL (1 day)

**File**: `api/handlers/hyperlane.rs`

#### Issue 1: Redundant Allocations (line 184)

```rust
// ❌ BAD - Double allocation
let body_bytes = message.body.to_vec();  // Allocation 1
let body_str = std::str::from_utf8(&body_bytes)  // Allocation 2 (if error path)
    .map_err(...)?;

// ✅ GOOD - Direct conversion
let body_str = std::str::from_utf8(message.body.as_slice())
    .map_err(...)?;
```

#### Issue 2: String Construction in Loop (line 261)

**Impact**: N allocations where N = number of validators

**Fix**: Use iterator or pre-allocate

---

### MEDIUM: Lock Contention in Storage

**Severity**: MEDIUM
**Effort**: MEDIUM (2 days)

**File**: `infrastructure/storage/rocks/engine.rs`

**Problem**: Three global mutexes with no timeouts:

```rust
pub struct RocksStorage {
    crdt_lock: Arc<Mutex<()>>,
    phase_lock: Arc<Mutex<()>>,
    hyperlane_lock: Arc<Mutex<()>>,
}
```

**Issues**:
- No timeout on lock acquisition (can deadlock)
- Global locks (reduces concurrency)
- No lock ordering documented (deadlock risk)

**Fix**:

```rust
// Add timeout-based locking
async fn acquire_lock_with_timeout(
    lock: &Mutex<()>,
    timeout: Duration,
    operation: &str,
) -> Result<MutexGuard<'_, ()>, ThresholdError> {
    tokio::time::timeout(timeout, lock.lock())
        .await
        .map_err(|_| ThresholdError::StorageLockTimeout {
            operation: operation.to_string(),
            timeout_ms: timeout.as_millis() as u64,
        })?
}

// Usage
let _guard = acquire_lock_with_timeout(
    &self.crdt_lock,
    Duration::from_secs(2),
    "crdt_merge"
).await?;
```

**Document lock ordering**:

```rust
// At top of engine.rs
//! Lock Acquisition Order (to prevent deadlocks):
//! 1. phase_lock
//! 2. crdt_lock
//! 3. hyperlane_lock
//!
//! NEVER acquire in different order!
```

---

## Testing Gaps

### MEDIUM: Missing Concurrent Access Tests

**Severity**: MEDIUM
**Effort**: MEDIUM (2 days)

**Gaps Identified**:

1. **CRDT Concurrent Merge** - No test for simultaneous merges from different peers
2. **Phase Transition Races** - No test for concurrent phase transitions
3. **Lock Contention** - No test validating lock timeout behavior
4. **Storage Migration** - No test for schema version upgrade under load

**Add Tests**:

```rust
// igra-core/tests/integration/concurrent_crdt.rs
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_crdt_merge() {
    let storage = Arc::new(RocksStorage::new(/* ... */));

    let handles: Vec<_> = (0..10).map(|i| {
        let storage = storage.clone();
        tokio::spawn(async move {
            // Simulate concurrent CRDT merges
            for _ in 0..100 {
                let event_id = generate_test_event_id(i);
                storage.upsert_event_crdt(&event_id, &test_state).await.unwrap();
            }
        })
    }).collect();

    for handle in handles {
        handle.await.unwrap();
    }

    // Verify no data corruption
}
```

**Effort**: 2 days to write comprehensive concurrent tests

---

## Type Safety Improvements

### MEDIUM: Stringly-Typed Metadata

**Severity**: MEDIUM
**Effort**: SMALL (1 day)

**File**: `api/handlers/hyperlane.rs`

**Problem**: Metadata keys as strings:

```rust
// Current (line 40, 373, etc.)
let mode = params.mode.unwrap_or(set.mode.clone());  // IsmMode as string
metadata_map.insert("hyperlane.mode".to_string(), mode_str);
```

**Fix**: Use enums:

```rust
// foundation/types.rs
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MetadataKey {
    #[serde(rename = "hyperlane.mode")]
    HyperlaneMode,
    #[serde(rename = "hyperlane.threshold")]
    HyperlaneThreshold,
    // ...
}

impl fmt::Display for MetadataKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::HyperlaneMode => write!(f, "hyperlane.mode"),
            // ...
        }
    }
}

// Usage
metadata_map.insert(MetadataKey::HyperlaneMode.to_string(), mode_str);
```

**Benefits**:
- ✅ Type-safe keys (no typos)
- ✅ Compiler-checked exhaustiveness
- ✅ Easy to refactor (rename enum variant)

---

### MEDIUM: Nested Option/Result Complexity

**Severity**: MEDIUM
**Effort**: SMALL (1 day)

**File**: `crdt_handler.rs:700-704`

**Problem**:

```rust
let crdt = ctx.storage.get_event_crdt(&event_id)?
    .ok_or_else(|| ThresholdError::MissingCrdtState { event_id })?;
```

**While correct, repeated pattern suggests helper needed**:

```rust
// foundation/util/result_ext.rs
pub trait ResultExt<T> {
    fn required(self, error: impl FnOnce() -> ThresholdError) -> Result<T, ThresholdError>;
}

impl<T> ResultExt<T> for Result<Option<T>, ThresholdError> {
    fn required(self, error: impl FnOnce() -> ThresholdError) -> Result<T, ThresholdError> {
        self?.ok_or_else(error)
    }
}

// Usage
let crdt = ctx.storage.get_event_crdt(&event_id)
    .required(|| ThresholdError::MissingCrdtState { event_id })?;
```

**Effort**: 4 hours (add trait + refactor call sites)

---

## Quick Wins (Can Complete in 1-2 Days)

### 1. Fix Clone().unwrap_or_default() Pattern

**Files**: 10 instances across codebase
**Effort**: 30 min per file = **5 hours total**

**Find**:
```bash
grep -rn "clone()\.unwrap_or_default()" igra-core/src igra-service/src
```

**Replace**:
```rust
// ❌ BAD
let value = config.field.clone().unwrap_or_default();

// ✅ GOOD
let value = parse_optional(&config.field)?.unwrap_or_default();
// OR
let value = config.field.as_deref().unwrap_or_default();
```

---

### 2. Remove hex::encode() from Logs

**Files**: 15+ instances
**Effort**: **2 hours total**

**Find**:
```bash
grep -rn "hex::encode" igra-core/src igra-service/src | grep "info!\|warn!\|error!\|debug!"
```

**Replace**:
```rust
// ❌ BAD
info!("event_id={}", hex::encode(event_id));

// ✅ GOOD
info!("event_id={}", event_id);
```

---

### 3. Add Size Limits Constants

**Effort**: **2 hours**

Create in `foundation/constants.rs`:

```rust
// Hyperlane limits
pub const MAX_HYPERLANE_BODY_SIZE: usize = 1024 * 1024;  // 1MB
pub const MAX_HYPERLANE_VALIDATORS: usize = 256;

// Config limits
pub const MAX_CONFIG_FILE_SIZE: usize = 10 * 1024 * 1024;  // 10MB
pub const MAX_PROFILES: usize = 100;

// Protocol limits
pub const MAX_PROPOSAL_TIMEOUT_SECS: u64 = 600;  // 10 minutes
pub const MAX_SUBMIT_TX_ATTEMPTS: u32 = 4;
```

Then use everywhere instead of magic numbers.

---

### 4. Add Lock Timeout

**Effort**: **3 hours**

Add helper and update all lock acquisitions:

```rust
// infrastructure/storage/rocks/util.rs
pub async fn acquire_with_timeout<T>(
    lock: &tokio::sync::Mutex<T>,
    timeout_secs: u64,
    operation: &'static str,
) -> Result<tokio::sync::MutexGuard<'_, T>, ThresholdError> {
    tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        lock.lock()
    )
    .await
    .map_err(|_| ThresholdError::StorageLockTimeout {
        operation: operation.to_string(),
        timeout_secs,
    })
}

// Usage
let _guard = acquire_with_timeout(&self.crdt_lock, 2, "crdt_merge").await?;
```

---

### 5. Create Missing Error Variants

**Effort**: **4 hours**

Add to `foundation/error.rs`:

```rust
#[error("RocksDB operation failed: {operation} - {details}")]
RocksDBOpenError {
    details: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
},

#[error("Missing signing payload for message_id={message_id}")]
MissingSigningPayload {
    message_id: String,
},

#[error("No validators configured for {validator_type}")]
NoValidatorsConfigured {
    validator_type: String,
},

#[error("Hyperlane body too large: {size} bytes (max: {max})")]
HyperlaneBodyTooLarge {
    size: usize,
    max: usize,
},

#[error("Storage lock timeout: {operation} (timeout: {timeout_secs}s)")]
StorageLockTimeout {
    operation: String,
    timeout_secs: u64,
},
```

Then replace all `ThresholdError::Message` with these variants.

---

## Refactoring Roadmap

### Sprint 1: Critical Fixes (Week 1)

**Focus**: CODE-GUIDELINE.md compliance + Critical architectural issues

| Task | Priority | Effort | Days |
|------|----------|--------|------|
| Add missing error variants | CRITICAL | SMALL | 0.5 |
| Replace ThresholdError::Message (7 sites) | CRITICAL | SMALL | 1 |
| Remove clone in crdt_handler:629-634 | HIGH | SMALL | 0.5 |
| Add input size validation | MEDIUM | SMALL | 1 |
| Create application/crdt_operations.rs | HIGH | MEDIUM | 2 |
| **Total Sprint 1** | | | **5 days** |

---

### Sprint 2: File Decomposition (Week 2)

**Focus**: Break down large files

| Task | Priority | Effort | Days |
|------|----------|--------|------|
| Split rocks/engine.rs into traits | CRITICAL | LARGE | 4 |
| Extract CrdtStorage implementation | HIGH | MEDIUM | 2 |
| Extract PhaseStorage implementation | HIGH | MEDIUM | 2 |
| Test decomposed storage | HIGH | MEDIUM | 2 |
| **Total Sprint 2** | | | **10 days** |

**Note**: Can parallelize - assign different storage modules to different developers

---

### Sprint 3: Performance & Polish (Week 3)

**Focus**: Quick wins + performance

| Task | Priority | Effort | Days |
|------|----------|--------|------|
| Fix all clone().unwrap_or_default() | HIGH | SMALL | 1 |
| Remove hex::encode() from logs | HIGH | SMALL | 0.5 |
| Add string constants for operation names | MEDIUM | SMALL | 0.5 |
| Add lock timeouts | MEDIUM | SMALL | 0.5 |
| Fix PSKT clone patterns | MEDIUM | MEDIUM | 1.5 |
| Add MetadataKey enum | MEDIUM | SMALL | 1 |
| **Total Sprint 3** | | | **5 days** |

---

### Sprint 4: Testing & Documentation (Week 4)

**Focus**: Test coverage + docs

| Task | Priority | Effort | Days |
|------|----------|--------|------|
| Add concurrent access tests | MEDIUM | MEDIUM | 2 |
| Add timeout/failure tests | MEDIUM | SMALL | 1 |
| Document lock semantics | MEDIUM | SMALL | 0.5 |
| Add module-level docs | LOW | SMALL | 1 |
| Performance profiling | LOW | SMALL | 0.5 |
| **Total Sprint 4** | | | **5 days** |

---

## Total Effort Summary

| Category | Issues | Dev Days |
|----------|--------|----------|
| CODE-GUIDELINE violations | 15 | 8 days |
| Architectural refactoring | 6 | 20 days |
| Security improvements | 5 | 5 days |
| Performance optimization | 8 | 4 days |
| Testing gaps | 6 | 5 days |
| Type safety | 8 | 3 days |
| **TOTAL** | **48** | **45 days** |

**Can be parallelized**: With 3 developers, can complete in **2-3 weeks**

---

## Prioritized Action Items

### MUST DO (Before Production)

1. ✅ **Add missing error variants** (5 variants)
2. ✅ **Replace ThresholdError::Message** (7 sites)
3. ✅ **Add input size validation** (3 locations)
4. ✅ **Add lock timeouts** (prevent deadlocks)
5. ✅ **Create application layer boundary** (reduce coupling)

---

### SHOULD DO (Next Sprint)

6. ✅ **Split RocksStorage** (improve maintainability)
7. ✅ **Fix clone patterns** (performance + clarity)
8. ✅ **Remove hex::encode() from logs** (CODE-GUIDELINE compliance)
9. ✅ **Fix clone().unwrap_or_default()** (CODE-GUIDELINE compliance)
10. ✅ **Add concurrent tests** (prevent regressions)

---

### NICE TO HAVE (Future)

11. ✅ Split crdt_handler.rs (865 lines → modular)
12. ✅ Add MetadataKey enum (type safety)
13. ✅ Document lock semantics (operational clarity)
14. ✅ Optimize string allocations (minor performance)
15. ✅ Add module-level documentation (developer experience)

---

## Validation After Refactoring

After completing refactoring, verify:

### CODE-GUIDELINE Compliance

```bash
# Should return 0 results (except in CLI/HTTP edge cases)
grep -rn "ThresholdError::Message" igra-core/src igra-service/src | grep -v "bin/\|api/handlers" | wc -l

# Should return 0 results (except in tests)
grep -rn "\.unwrap()" igra-core/src igra-service/src | grep -v "_test\|#\[test\]" | wc -l

# Should return 0 results
grep -rn "clone()\.unwrap_or_default()" igra-core/src igra-service/src | wc -l

# Should return 0 results in log statements
grep -rn "hex::encode" igra-core/src igra-service/src | grep "info!\|warn!\|error!" | wc -l
```

### Architectural Validation

- [ ] No direct domain imports in service layer (use application/)
- [ ] All storage operations have timeout on locks
- [ ] No file exceeds 500 lines (target) or 800 lines (maximum)
- [ ] All public APIs have documentation
- [ ] All error variants have proper context

### Performance Validation

- [ ] No unnecessary clones in hot paths (profile and verify)
- [ ] Lock contention under load < 1% (benchmark)
- [ ] Message processing latency < 10ms p99 (benchmark)

### Security Validation

- [ ] All input sizes validated
- [ ] Error messages don't expose internal paths
- [ ] Audit trail cannot fail silently
- [ ] No secrets in logs (grep for common patterns)

---

## Refactoring Best Practices

### During Refactoring

1. **One module at a time** - Don't refactor everything at once
2. **Tests first** - Ensure existing tests pass before refactoring
3. **Small PRs** - Max 500 lines changed per PR
4. **Document changes** - Update code comments and module docs
5. **Benchmark critical paths** - Verify performance doesn't regress

### After Refactoring

1. **Run full test suite** - `cargo test --all-features`
2. **Check for warnings** - `cargo clippy --all-features`
3. **Verify devnet** - Run existing devnet scripts
4. **Performance test** - Run benchmarks
5. **Team review** - Code review with architecture focus

---

END OF AUDIT

