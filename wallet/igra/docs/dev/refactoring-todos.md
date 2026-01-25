# Igra Refactoring TODOs - Complete Implementation Guide

**Created**: 2026-01-23
**Status**: Ready for Implementation
**Total Tasks**: 48 tasks across 6 categories
**Estimated Effort**: 45 development days (can parallelize)

---

## Table of Contents

1. [How to Use This Document](#how-to-use-this-document)
2. [Task Priority Legend](#task-priority-legend)
3. [Quick Wins (Start Here)](#quick-wins-start-here)
4. [Critical Tasks](#critical-tasks)
5. [High Priority Tasks](#high-priority-tasks)
6. [Medium Priority Tasks](#medium-priority-tasks)
7. [Low Priority Tasks](#low-priority-tasks)
8. [Validation Checklist](#validation-checklist)

---

## How to Use This Document

### For Team Leads

1. **Assign tasks** from different categories to different developers (can parallelize)
2. **Start with Quick Wins** - builds momentum, immediate improvements
3. **Critical tasks** must be done before production
4. **Track progress** using checkboxes in each section

### For Developers

1. **Pick a task** from your assigned category
2. **Read the detailed implementation** for that task
3. **Follow step-by-step instructions** (code examples provided)
4. **Run tests** after each change
5. **Update checkbox** when complete

### Task Format

Each task includes:
- **Priority**: CRITICAL/HIGH/MEDIUM/LOW
- **Effort**: SMALL (< 1 day) / MEDIUM (1-3 days) / LARGE (4-7 days)
- **Files to change**: Exact file paths
- **Before/After code**: Complete examples
- **Testing**: How to verify the fix
- **Validation**: Checklist for completion

---

## Task Priority Legend

| Priority | Definition | Timeline |
|----------|------------|----------|
| **CRITICAL** | Must fix before production | Week 1 |
| **HIGH** | Should fix next sprint | Week 2-3 |
| **MEDIUM** | Nice to have, improves quality | Week 4+ |
| **LOW** | Optional polish | Future |

| Effort | Time Estimate |
|--------|---------------|
| **SMALL** | < 1 day (2-8 hours) |
| **MEDIUM** | 1-3 days |
| **LARGE** | 4-7 days |

---

## Quick Wins (Start Here)

**Total Effort**: 16 hours (2 days)
**Impact**: Immediate CODE-GUIDELINE compliance + performance boost

These tasks are independent and can be done in parallel by different team members.

---

### TASK-QW-1: Remove hex::encode() from Log Statements

**Priority**: HIGH
**Effort**: SMALL (2 hours)
**Files**: 15+ instances across codebase

#### Problem

Hash types already implement Display trait - no need for manual hex::encode():

```rust
// ❌ BAD - Found in multiple files
info!("event processed event_id={}", hex::encode(event_id));
warn!("failed event_id={} tx_hash={}",
      hex::encode(event_id),
      hex::encode(tx_template_hash));
```

#### Implementation Steps

**Step 1**: Find all instances

```bash
cd /path/to/igra
grep -rn "hex::encode" igra-core/src igra-service/src | grep "info!\|warn!\|error!\|debug!" > /tmp/hex_encode_logs.txt
```

**Step 2**: Review list and identify log statements (not other uses)

**Step 3**: For each file, replace:

```rust
// ❌ BEFORE
info!("event processed event_id={}", hex::encode(event_id));

// ✅ AFTER
info!("event processed event_id={}", event_id);
```

#### Files to Update

Based on audit findings:
- `igra-service/src/api/handlers/hyperlane.rs` - Lines 139, 151, 161, 261
- `igra-service/src/service/coordination/crdt_handler.rs` - Multiple instances
- `igra-core/src/domain/pskt/multisig.rs` - 2+ instances

#### Testing

```bash
# After changes, verify no hex::encode in logs
grep -rn "hex::encode" igra-core/src igra-service/src | grep "info!\|warn!\|error!" | wc -l
# Should return: 0

# Run tests to ensure formatting still works
cargo test --all-features
```

#### Validation Checklist

- [ ] Found all hex::encode() in log statements
- [ ] Replaced with Display trait (just `{}`)
- [ ] Verified output is still readable
- [ ] No test failures
- [ ] Logs still show hex-formatted hashes

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-QW-2: Fix clone().unwrap_or_default() Verbose Pattern

**Priority**: HIGH
**Effort**: SMALL (5 hours)
**Files**: 10 instances

#### Problem

Verbose config parsing pattern violates CODE-GUIDELINE Mistake #8:

```rust
// ❌ BAD - 4 lines of boilerplate
let group_id_hex = config.iroh.group_id.clone().unwrap_or_default();
if group_id_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing group_id".to_string()));
}
let group_id = GroupId::from(parse_hash32_hex(&group_id_hex)?);
```

#### Implementation Steps

**Step 1**: Find all instances

```bash
grep -rn "clone()\.unwrap_or_default()" igra-core/src igra-service/src
```

**Step 2**: For each instance, use config helper:

```rust
// ✅ GOOD - 1 line
use crate::foundation::parse_required;
let group_id: GroupId = parse_required(&config.iroh.group_id, "iroh.group_id")?;
```

#### Files to Update

- `igra-service/src/bin/kaspa-threshold-service/setup.rs:67, 268, 269`
- `igra-core/src/domain/pskt/multisig.rs:106`
- `igra-service/src/api/middleware/logging.rs:41`
- `igra-service/src/bin/fake_hyperlane_relayer.rs:538`

#### Available Helpers

From `foundation/config_helpers.rs`:

```rust
// Required field (error if None or empty)
let value: T = parse_required(&config.field, "field_name")?;

// Optional field (Ok(None) if None or empty)
let value: Option<T> = parse_optional(&config.field)?;

// With default value
let value: T = parse_or_default(&config.field, default_value);
```

#### Testing

```bash
# Verify pattern is gone
grep -rn "clone()\.unwrap_or_default()" igra-core/src igra-service/src | wc -l
# Should return: 0

# Run tests
cargo test --package igra-core --lib infrastructure::config
cargo test --package igra-service
```

#### Validation Checklist

- [ ] All instances found and replaced
- [ ] Using appropriate helper (parse_required/parse_optional)
- [ ] Tests pass
- [ ] No clone overhead remains

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-QW-3: Add Size Limit Constants

**Priority**: MEDIUM
**Effort**: SMALL (2 hours)
**Files**: 1 file (foundation/constants.rs)

#### Problem

Magic numbers scattered throughout codebase with no named constants.

#### Implementation Steps

**Step 1**: Add constants to `foundation/constants.rs`

```rust
// Add to existing constants.rs

// === Hyperlane Protocol Limits ===

/// Maximum size of Hyperlane message body (1MB)
pub const MAX_HYPERLANE_BODY_SIZE: usize = 1024 * 1024;

/// Maximum number of Hyperlane validators
pub const MAX_HYPERLANE_VALIDATORS: usize = 256;

// === Configuration Limits ===

/// Maximum config file size (10MB)
pub const MAX_CONFIG_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of profiles
pub const MAX_PROFILES: usize = 100;

// === Protocol Timeouts ===

/// Maximum proposal timeout (10 minutes)
pub const MAX_PROPOSAL_TIMEOUT_SECS: u64 = 600;

/// Maximum transaction submit attempts
pub const MAX_SUBMIT_TX_ATTEMPTS: u32 = 4;

// === Storage Limits ===

/// RocksDB lock acquisition timeout (2 seconds)
pub const STORAGE_LOCK_TIMEOUT_SECS: u64 = 2;

/// Minimum required disk space (10GB)
pub const MIN_DISK_SPACE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Minimum open file limit
pub const MIN_OPEN_FILE_LIMIT: u64 = 4096;
```

**Step 2**: Replace magic numbers in code

```bash
# Find magic numbers
grep -rn "600\|5000\|4096\|256" igra-core/src igra-service/src | grep -v "//\|test"
```

**Step 3**: Update usages:

```rust
// ❌ BEFORE
if timeout_secs > 600 { ... }

// ✅ AFTER
use crate::foundation::constants::MAX_PROPOSAL_TIMEOUT_SECS;
if timeout_secs > MAX_PROPOSAL_TIMEOUT_SECS { ... }
```

#### Testing

```bash
cargo test --package igra-core --lib foundation::constants
cargo build --all-features
```

#### Validation Checklist

- [ ] All constants added to foundation/constants.rs
- [ ] Constants have doc comments with units/meaning
- [ ] Magic numbers replaced with named constants
- [ ] Code compiles
- [ ] Constants exported in foundation/mod.rs

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-QW-4: Add Storage Lock Timeouts

**Priority**: HIGH
**Effort**: SMALL (3 hours)
**Files**: 2 files

#### Problem

Storage mutexes have no timeout - can deadlock indefinitely.

**File**: `infrastructure/storage/rocks/engine.rs`

#### Implementation Steps

**Step 1**: Create lock helper

**File**: `infrastructure/storage/rocks/util.rs` (NEW)

```rust
//! Storage utility functions

use crate::foundation::{constants::STORAGE_LOCK_TIMEOUT_SECS, error::ThresholdError};
use std::time::Duration;
use tokio::sync::{Mutex, MutexGuard};

/// Acquire mutex with timeout
///
/// Prevents indefinite blocking if lock contention occurs.
/// Timeout configurable via constants.
pub async fn acquire_with_timeout<T>(
    lock: &Mutex<T>,
    operation: &'static str,
) -> Result<MutexGuard<'_, T>, ThresholdError> {
    tokio::time::timeout(
        Duration::from_secs(STORAGE_LOCK_TIMEOUT_SECS),
        lock.lock(),
    )
    .await
    .map_err(|_| ThresholdError::StorageLockTimeout {
        operation: operation.to_string(),
        timeout_secs: STORAGE_LOCK_TIMEOUT_SECS,
    })
}
```

**Step 2**: Add error variant

**File**: `foundation/error.rs`

```rust
#[error("Storage lock timeout: {operation} (waited {timeout_secs}s)")]
StorageLockTimeout {
    operation: String,
    timeout_secs: u64,
},
```

**Step 3**: Update lock acquisitions in engine.rs

```rust
// ❌ BEFORE
let _guard = self.crdt_lock.lock().await;

// ✅ AFTER
use crate::infrastructure::storage::rocks::util::acquire_with_timeout;
let _guard = acquire_with_timeout(&self.crdt_lock, "crdt_merge").await?;
```

**Step 4**: Update all lock sites

Find all lock acquisitions:
```bash
grep -n "\.lock().await" igra-core/src/infrastructure/storage/rocks/engine.rs
```

Replace each with timeout version.

#### Testing

```rust
// Add test in rocks/util.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_acquire_with_timeout_success() {
        let lock = Arc::new(Mutex::new(()));
        let guard = acquire_with_timeout(&lock, "test").await;
        assert!(guard.is_ok());
    }

    #[tokio::test]
    async fn test_acquire_with_timeout_fails() {
        let lock = Arc::new(Mutex::new(()));
        let _guard = lock.lock().await; // Hold lock

        let result = acquire_with_timeout(&lock, "test").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout"));
    }
}
```

#### Validation Checklist

- [ ] util.rs created with acquire_with_timeout()
- [ ] StorageLockTimeout error variant added
- [ ] All lock acquisitions updated (search for `.lock().await`)
- [ ] Tests added and passing
- [ ] No deadlocks in integration tests

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-QW-5: Add Missing Error Variants

**Priority**: CRITICAL
**Effort**: SMALL (4 hours)
**Files**: 1 file + multiple call sites

#### Problem

Using ThresholdError::Message instead of structured variants.

#### Implementation Steps

**Step 1**: Add variants to `foundation/error.rs`

**File**: `igra-core/src/foundation/error.rs`

Add after existing variants:

```rust
// === Storage Errors ===

#[error("RocksDB operation failed: {details}")]
RocksDBOpenError {
    details: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
},

#[error("Storage lock timeout: {operation} (waited {timeout_secs}s)")]
StorageLockTimeout {
    operation: String,
    timeout_secs: u64,
},

// === Hyperlane Errors ===

#[error("Missing signing payload for message_id={message_id}")]
MissingSigningPayload {
    message_id: String,
},

#[error("Hyperlane body too large: {size} bytes (max: {max})")]
HyperlaneBodyTooLarge {
    size: usize,
    max: usize,
},

#[error("Hyperlane invalid UTF-8 at position {position}")]
HyperlaneInvalidUtf8 {
    position: usize,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
},

#[error("Hyperlane metadata parse error: {details}")]
HyperlaneMetadataParseError {
    details: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
},

// === Configuration Errors ===

#[error("No {validator_type} validators configured")]
NoValidatorsConfigured {
    validator_type: String,
},

// === PSKT Errors ===

#[error("PSKT input mismatch: expected {expected}, got {actual} - {details}")]
PsktInputMismatch {
    expected: usize,
    actual: usize,
    details: String,
},
```

**Step 2**: Export error codes

Update ErrorCode enum:

```rust
pub enum ErrorCode {
    // ... existing codes ...

    // Add new codes
    RocksDBOpenError,
    StorageLockTimeout,
    MissingSigningPayload,
    HyperlaneBodyTooLarge,
    HyperlaneInvalidUtf8,
    HyperlaneMetadataParseError,
    NoValidatorsConfigured,
    PsktInputMismatch,
}
```

#### Testing

```rust
// Add to foundation/error.rs tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_error_variants() {
        let err = ThresholdError::RocksDBOpenError {
            details: "test".to_string(),
            source: None,
        };
        assert!(err.to_string().contains("RocksDB"));

        let err = ThresholdError::MissingSigningPayload {
            message_id: "0xabc".to_string(),
        };
        assert!(err.to_string().contains("message_id"));
    }
}
```

#### Validation Checklist

- [ ] All 8 new error variants added to ThresholdError enum
- [ ] All 8 error codes added to ErrorCode enum
- [ ] Tests added for new variants
- [ ] Documentation comments added
- [ ] Code compiles

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-QW-6: Add Input Size Validation

**Priority**: MEDIUM
**Effort**: SMALL (3 hours)
**Files**: 3 files

#### Problem

No size limits on input data - risk of DoS or memory exhaustion.

#### Implementation Steps

**Step 1**: Use constants from TASK-QW-3

**Step 2**: Add validation to Hyperlane handler

**File**: `igra-service/src/api/handlers/hyperlane.rs:177-188`

```rust
use crate::foundation::constants::MAX_HYPERLANE_BODY_SIZE;

// ❌ BEFORE
let body_bytes = message.body.as_slice();
let body_str = std::str::from_utf8(body_bytes)
    .map_err(|e| ThresholdError::Message(format!("invalid UTF8: {}", e)))?;

// ✅ AFTER
let body_bytes = message.body.as_slice();

// Validate size
if body_bytes.len() > MAX_HYPERLANE_BODY_SIZE {
    return Err(ThresholdError::HyperlaneBodyTooLarge {
        size: body_bytes.len(),
        max: MAX_HYPERLANE_BODY_SIZE,
    });
}

// Validate UTF-8
let body_str = std::str::from_utf8(body_bytes)
    .map_err(|e| ThresholdError::HyperlaneInvalidUtf8 {
        position: e.valid_up_to(),
        source: Some(Box::new(e)),
    })?;
```

**Step 3**: Add validation to config loader

**File**: `igra-core/src/infrastructure/config/loader.rs`

Add at start of `load_config_from_file()`:

```rust
use crate::foundation::constants::MAX_CONFIG_FILE_SIZE;

// Check file size before reading
let metadata = std::fs::metadata(path)
    .map_err(|e| ThresholdError::ConfigError {
        details: format!("Cannot read config file metadata: {}", e),
    })?;

if metadata.len() > MAX_CONFIG_FILE_SIZE as u64 {
    return Err(ThresholdError::ConfigError {
        details: format!(
            "Config file too large: {} bytes (max: {} bytes)",
            metadata.len(),
            MAX_CONFIG_FILE_SIZE
        ),
    });
}
```

#### Testing

```rust
// Add test in hyperlane handler tests
#[test]
fn test_rejects_oversized_body() {
    let huge_body = vec![0u8; 2 * 1024 * 1024]; // 2MB (over limit)
    let message = HyperlaneMessage {
        body: huge_body.into(),
        // ... other fields
    };

    let result = extract_signing_payload(&message);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too large"));
}
```

#### Validation Checklist

- [ ] Constants defined (from TASK-QW-3)
- [ ] Hyperlane body size validated
- [ ] Config file size validated
- [ ] Error variants used (from TASK-QW-5)
- [ ] Tests added
- [ ] Large input rejected correctly

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

## Critical Tasks

**Total Effort**: 15 days (can parallelize)

---

### TASK-C-1: Replace ThresholdError::Message with Structured Variants

**Priority**: CRITICAL
**Effort**: SMALL (1 day)
**Files**: 7+ call sites

**Depends On**: TASK-QW-5 (error variants must be added first)

#### Problem

ThresholdError::Message loses error semantics and violates CODE-GUIDELINE Mistake #1.

#### Violations to Fix

**File 1**: `igra-service/src/bin/kaspa-threshold-service/setup.rs:78`

```rust
// ❌ BEFORE
match db_result {
    Err(err) => {
        return Err(ThresholdError::Message(format!("rocksdb open error: {}", err)))
    }
}

// ✅ AFTER
match db_result {
    Err(err) => {
        return Err(ThresholdError::RocksDBOpenError {
            details: format!("Failed to open database at {:?}", path),
            source: Some(Box::new(err)),
        })
    }
}
```

**File 2**: `igra-service/src/api/handlers/hyperlane.rs:227`

```rust
// ❌ BEFORE
let payload = extract_signing_payload(message)
    .map_err(ThresholdError::Message)?;

// ✅ AFTER
let payload = extract_signing_payload(message)?;
// (extract_signing_payload already returns ThresholdError with proper variants)
```

**File 3**: `igra-service/src/api/handlers/hyperlane.rs:229`

```rust
// ❌ BEFORE
return Err(ThresholdError::Message(
    "destination_address and amount_sompi are required for kaspa-transfer".to_string()
));

// ✅ AFTER
return Err(ThresholdError::MissingSigningPayload {
    message_id: hex::encode(message_id),
});
```

**File 4**: `igra-core/src/domain/pskt/multisig.rs:164-166`

```rust
// ❌ BEFORE
.map_err(|e| format!("input {} script mismatch: {}", i, e))?;

// ✅ AFTER
.map_err(|e| ThresholdError::PsktInputMismatch {
    expected: expected_inputs,
    actual: i,
    details: format!("Script mismatch: {}", e),
})?;
```

**File 5**: `igra-core/src/application/event_processor.rs:128`

```rust
// ❌ BEFORE
return Err(ThresholdError::ConfigError(
    "no hyperlane validators configured".to_string()
));

// ✅ AFTER
return Err(ThresholdError::NoValidatorsConfigured {
    validator_type: "hyperlane".to_string(),
});
```

#### Finding All Instances

```bash
# Find all ThresholdError::Message usage
grep -rn "ThresholdError::Message" igra-core/src igra-service/src | grep -v "test\|//"

# Should only appear in:
# - bin/*.rs (CLI argument parsing)
# - api/handlers/*.rs (HTTP error conversion - edge cases)
```

#### Testing

```bash
# Verify all replaced
grep -rn "ThresholdError::Message" igra-core/src igra-service/src | \
    grep -v "bin/\|api/handlers/\|test" | \
    wc -l
# Should return: 0

cargo test --all-features
```

#### Validation Checklist

- [ ] All 7 instances identified
- [ ] Each replaced with appropriate structured variant
- [ ] Error variants from TASK-QW-5 used
- [ ] Tests pass
- [ ] Error messages still informative
- [ ] Can pattern match on errors now

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-C-2: Create Application Layer CRDT Boundary

**Priority**: CRITICAL
**Effort**: MEDIUM (2-3 days)
**Files**: 3 new files + 1 update

**Depends On**: None

#### Problem

Service layer imports domain directly, violating layered architecture:

```rust
// igra-service/src/service/coordination/crdt_handler.rs:1-15
use igra_core::domain::pskt::multisig as pskt_multisig;  // ❌ BAD
use igra_core::domain::{CrdtSigningMaterial, ...};       // ❌ BAD
```

#### Implementation Steps

**Step 1**: Create application module structure

```bash
cd igra-core/src/application
touch crdt_operations.rs
touch pskt_operations.rs
```

**Step 2**: Implement CRDT operations facade

**File**: `igra-core/src/application/crdt_operations.rs` (NEW)

```rust
//! CRDT operations - application layer public API
//!
//! This module provides the public API for CRDT operations,
//! abstracting over domain internals.

use crate::domain::{
    crdt::{EventCrdtState, EventStateBroadcast},
    event_state::StoredEvent,
    normalization::validate_source_data,
    hashes::compute_event_id,
};
use crate::foundation::{error::ThresholdError, types::*};

/// CRDT operations coordinator
pub struct CrdtOperations;

impl CrdtOperations {
    /// Merge incoming CRDT state with current state
    ///
    /// Returns updated state or error if invalid.
    pub fn merge_event_state(
        current: &EventCrdtState,
        incoming: &EventStateBroadcast,
    ) -> Result<EventCrdtState, ThresholdError> {
        // Delegate to domain layer
        crate::domain::crdt::merge_states(current, incoming)
    }

    /// Validate source data for event
    pub fn validate_source_data(
        source_addresses: &[String],
        amount: u64,
    ) -> Result<(), ThresholdError> {
        crate::domain::normalization::validate_source_data(source_addresses, amount)
    }

    /// Compute event ID from event data
    pub fn compute_event_id(
        tx_template_hash: &TxTemplateHash,
        external_id: &ExternalId,
    ) -> EventId {
        crate::domain::hashes::compute_event_id(tx_template_hash, external_id)
    }

    /// Create stored event from signing material
    pub fn create_stored_event(
        signing_material: CrdtSigningMaterial,
        received_at_nanos: u64,
    ) -> StoredEvent {
        StoredEvent {
            event: signing_material.event,
            received_at_nanos,
            audit: signing_material.audit,
            proof: signing_material.proof,
        }
    }
}

// Re-export domain types that service layer needs
pub use crate::domain::{
    CrdtSigningMaterial,
    PartialSigRecord,
    StoredEvent,
    EventCrdtState,
    EventStateBroadcast,
};
```

**Step 3**: Implement PSKT operations facade

**File**: `igra-core/src/application/pskt_operations.rs` (NEW)

```rust
//! PSKT operations - application layer public API

use crate::domain::pskt::multisig;
use crate::foundation::{error::ThresholdError, types::*};
use crate::infrastructure::keys::KeyManagerContext;

/// PSKT operations coordinator
pub struct PsktOperations;

impl PsktOperations {
    /// Sign PSKT with KeyManager
    pub async fn sign_pskt(
        pskt_json: &str,
        key_context: &KeyManagerContext,
        config: &crate::infrastructure::config::types::ServiceConfig,
        profile: &str,
    ) -> Result<multisig::SignedPskt, ThresholdError> {
        multisig::sign_pskt_with_key_manager(
            key_context,
            pskt_json,
            config,
            profile,
        ).await
    }

    /// Finalize PSKT with partial signatures
    pub fn finalize_pskt(
        pskt_json: &str,
        partial_sigs: Vec<multisig::PartialSignature>,
    ) -> Result<Vec<u8>, ThresholdError> {
        multisig::finalize_pskt(pskt_json, partial_sigs)
    }
}

// Re-export PSKT types
pub use crate::domain::pskt::multisig::{
    SignedPskt,
    PartialSignature,
};
```

**Step 4**: Update application/mod.rs

**File**: `igra-core/src/application/mod.rs`

```rust
pub mod context;
pub mod crdt_operations;  // NEW
pub mod event_processor;
pub mod pskt_operations;  // NEW
pub mod pskt_signing;
pub mod two_phase;

// Re-export public APIs
pub use crdt_operations::CrdtOperations;
pub use pskt_operations::PsktOperations;
```

**Step 5**: Update service layer imports

**File**: `igra-service/src/service/coordination/crdt_handler.rs`

```rust
// ❌ BEFORE
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::{CrdtSigningMaterial, PartialSigRecord, StoredEvent};
use igra_core::domain::normalization::validate_source_data;
use igra_core::domain::hashes::compute_event_id;

// ✅ AFTER
use igra_core::application::{
    CrdtOperations,
    PsktOperations,
    CrdtSigningMaterial,
    PartialSigRecord,
    StoredEvent,
};

// In code, replace:
// ❌ BEFORE
let event_id = compute_event_id(&tx_template_hash, &external_id);
validate_source_data(&source_addresses, amount)?;

// ✅ AFTER
let event_id = CrdtOperations::compute_event_id(&tx_template_hash, &external_id);
CrdtOperations::validate_source_data(&source_addresses, amount)?;
```

#### Testing

```bash
# Verify no direct domain imports in service
grep -rn "use igra_core::domain::" igra-service/src | grep -v "test"
# Should return: 0 results

cargo test --all-features
```

#### Validation Checklist

- [ ] crdt_operations.rs created
- [ ] pskt_operations.rs created
- [ ] application/mod.rs updated
- [ ] service layer imports updated
- [ ] No direct domain imports in service
- [ ] All tests pass
- [ ] Functionality unchanged

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

## High Priority Tasks

**Total Effort**: 35 days (can parallelize)

---

### TASK-H-1: Decompose RocksStorage (1,424 lines)

**Priority**: CRITICAL
**Effort**: LARGE (5-7 days)
**Files**: 7 new files + updates

**NOTE**: This is a large task - can be split among 2-3 developers

#### Problem

Single 1,424-line file with too many responsibilities.

#### Implementation Plan

This task is broken into 6 sub-tasks that can be done in parallel after Step 1.

##### Sub-Task H-1A: Extract CrdtStorage Trait

**Effort**: 1-2 days
**Assignee**: Developer A

**Step 1**: Create trait

**File**: `infrastructure/storage/rocks/crdt_storage.rs` (NEW)

```rust
//! CRDT storage operations

use crate::domain::crdt::EventCrdtState;
use crate::foundation::{error::ThresholdError, types::EventId};

/// Storage operations for CRDT state
pub trait CrdtStorage {
    /// Get CRDT state for event
    fn get_event_crdt(&self, event_id: &EventId) -> Result<Option<EventCrdtState>, ThresholdError>;

    /// Insert or update CRDT state
    fn upsert_event_crdt(
        &self,
        event_id: &EventId,
        state: &EventCrdtState,
    ) -> Result<(), ThresholdError>;

    /// List all event IDs with CRDT state
    fn list_event_crdt_ids(&self) -> Result<Vec<EventId>, ThresholdError>;

    /// Delete CRDT state (for cleanup)
    fn delete_event_crdt(&self, event_id: &EventId) -> Result<(), ThresholdError>;

    /// Get CRDT states by IDs (batch operation)
    fn get_event_crdt_batch(
        &self,
        event_ids: &[EventId],
    ) -> Result<Vec<Option<EventCrdtState>>, ThresholdError>;
}
```

**Step 2**: Implement for RocksStorage

Move implementation from engine.rs to crdt_storage.rs:

```rust
use super::engine::RocksStorage;
use crate::infrastructure::storage::rocks::util::acquire_with_timeout;

impl CrdtStorage for RocksStorage {
    fn get_event_crdt(&self, event_id: &EventId) -> Result<Option<EventCrdtState>, ThresholdError> {
        // Move existing implementation from engine.rs
        // (Copy lines from get_event_crdt method)

        let cf = self.db.cf_handle(CF_EVENT_CRDT)
            .ok_or_else(|| ThresholdError::StorageError {
                operation: "rocksdb cf_handle".to_string(),
                details: format!("missing column family: {}", CF_EVENT_CRDT),
            })?;

        let key = event_id.as_bytes();
        let value = self.db.get_cf(&cf, key)
            .map_err(|e| ThresholdError::StorageError {
                operation: "rocksdb get".to_string(),
                details: format!("key={} error={}", event_id, e),
            })?;

        match value {
            Some(bytes) => {
                let state = bincode::deserialize(&bytes)
                    .map_err(|e| ThresholdError::StorageError {
                        operation: "bincode deserialize".to_string(),
                        details: format!("key={} error={}", event_id, e),
                    })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    // Implement other methods...
}
```

**Step 3**: Update engine.rs

Remove CRDT methods, keep only struct definition and common operations.

**Step 4**: Update call sites

```rust
// In crdt_handler.rs
use igra_core::infrastructure::storage::CrdtStorage;  // Trait
// Call as before - transparent to callers
let state = storage.get_event_crdt(&event_id)?;
```

---

##### Sub-Task H-1B: Extract PhaseStorage Trait

**Effort**: 1-2 days
**Assignee**: Developer B

**File**: `infrastructure/storage/rocks/phase_storage.rs` (NEW)

```rust
//! Phase management storage operations

use crate::domain::phase::{EventPhase, EventPhaseState};
use crate::foundation::{error::ThresholdError, types::EventId};

/// Storage operations for event phase lifecycle
pub trait PhaseStorage {
    /// Get phase state for event
    fn get_phase(&self, event_id: &EventId) -> Result<Option<EventPhaseState>, ThresholdError>;

    /// Update phase state
    fn update_phase(
        &self,
        event_id: &EventId,
        state: &EventPhaseState,
    ) -> Result<(), ThresholdError>;

    /// Transition to new phase (with validation)
    fn transition_phase(
        &self,
        event_id: &EventId,
        from_phase: EventPhase,
        to_phase: EventPhase,
    ) -> Result<(), ThresholdError>;

    /// List events in specific phase
    fn list_events_in_phase(&self, phase: EventPhase) -> Result<Vec<EventId>, ThresholdError>;

    /// Mark phase as completed
    fn mark_phase_completed(
        &self,
        event_id: &EventId,
        timestamp: u64,
    ) -> Result<(), ThresholdError>;
}

impl PhaseStorage for RocksStorage {
    // Move implementation from engine.rs
    // (8 methods related to phase management)
}
```

---

##### Sub-Task H-1C: Extract HyperlaneStorage Trait

**Effort**: 1-2 days
**Assignee**: Developer C

**File**: `infrastructure/storage/rocks/hyperlane_storage.rs` (NEW)

```rust
//! Hyperlane delivery tracking storage

use crate::domain::hyperlane::DeliveryStatus;
use crate::foundation::{error::ThresholdError, types::*};

/// Storage operations for Hyperlane delivery tracking
pub trait HyperlaneStorage {
    /// Record hyperlane message delivery
    fn record_hyperlane_delivery(
        &self,
        message_id: &ExternalId,
        tx_id: &TransactionId,
        status: DeliveryStatus,
    ) -> Result<(), ThresholdError>;

    /// Get delivery status for message
    fn get_hyperlane_delivery(
        &self,
        message_id: &ExternalId,
    ) -> Result<Option<DeliveryStatus>, ThresholdError>;

    /// List pending deliveries
    fn list_pending_deliveries(&self) -> Result<Vec<ExternalId>, ThresholdError>;

    /// Update delivery status
    fn update_delivery_status(
        &self,
        message_id: &ExternalId,
        status: DeliveryStatus,
    ) -> Result<(), ThresholdError>;
}

impl HyperlaneStorage for RocksStorage {
    // Move implementation from engine.rs
    // (6 methods related to Hyperlane delivery)
}
```

---

##### Sub-Task H-1D: Update Storage Trait

**Effort**: 1 day
**Assignee**: Original developer of H-1A/B/C

**File**: `infrastructure/storage/mod.rs`

Update Storage trait to compose sub-traits:

```rust
// ❌ BEFORE
pub trait Storage: Send + Sync {
    // 40+ methods mixed together
}

// ✅ AFTER
pub trait Storage:
    CrdtStorage +
    PhaseStorage +
    HyperlaneStorage +
    Send +
    Sync
{
    // Common operations only
    fn close(&self) -> Result<(), ThresholdError>;
    fn checkpoint(&self) -> Result<(), ThresholdError>;
}
```

---

##### Sub-Task H-1E: Integration Testing

**Effort**: 1 day
**Assignee**: QA/Test specialist

**File**: `igra-core/tests/integration/storage_decomposed.rs` (NEW)

```rust
//! Test decomposed storage traits

use igra_core::infrastructure::storage::{
    CrdtStorage, PhaseStorage, HyperlaneStorage,
    RocksStorage,
};

#[tokio::test]
async fn test_crdt_storage_operations() {
    let storage = RocksStorage::new_temp().unwrap();

    // Test CRDT operations
    let event_id = EventId::random();
    let state = create_test_crdt_state();

    storage.upsert_event_crdt(&event_id, &state).unwrap();
    let retrieved = storage.get_event_crdt(&event_id).unwrap();

    assert_eq!(retrieved, Some(state));
}

#[tokio::test]
async fn test_phase_storage_operations() {
    // Test phase operations independently
}

#[tokio::test]
async fn test_hyperlane_storage_operations() {
    // Test Hyperlane operations independently
}
```

---

#### Testing Overall Decomposition

```bash
# All tests should still pass
cargo test --package igra-core --lib infrastructure::storage

# No performance regression
cargo bench --package igra-core storage_ops
```

#### Validation Checklist

- [ ] CrdtStorage trait created and implemented
- [ ] PhaseStorage trait created and implemented
- [ ] HyperlaneStorage trait created and implemented
- [ ] ProposalStorage trait created and implemented (if needed)
- [ ] VolumeStorage trait created and implemented (if needed)
- [ ] Storage trait updated to compose sub-traits
- [ ] RocksStorage implements all traits
- [ ] engine.rs reduced to < 400 lines
- [ ] All existing tests pass
- [ ] New integration tests added
- [ ] No performance regression

**Assignee**: Team (split among developers)
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-H-2: Fix Unnecessary Clones in CRDT Handler

**Priority**: HIGH
**Effort**: SMALL (4 hours)
**Files**: 1 file

#### Problem

Cloning event fields multiple times in hot path.

**File**: `igra-service/src/service/coordination/crdt_handler.rs:629-634`

```rust
// ❌ BEFORE - 4 clones!
let policy_event = StoredEvent {
    event: signing_material.event.clone(),      // Clone 1
    received_at_nanos: now,
    audit: signing_material.audit.clone(),      // Clone 2
    proof: signing_material.proof.clone(),       // Clone 3
};
let inserted = ctx.storage.insert_event_if_not_exists(
    state.event_id,
    policy_event.clone()  // Clone 4!
)?;
```

#### Implementation Steps

**Step 1**: Analyze usage of signing_material after this block

If signing_material is not used after, we can move instead of clone.

**Step 2**: Remove intermediate clones

```rust
// ✅ AFTER - Zero clones (move semantics)
let inserted = ctx.storage.insert_event_if_not_exists(
    state.event_id,
    StoredEvent {
        event: signing_material.event,      // Move
        received_at_nanos: now,
        audit: signing_material.audit,      // Move
        proof: signing_material.proof,      // Move
    }
)?;

// If signing_material is used later, only clone what's needed:
let event_copy = signing_material.event.clone();  // Explicit, intentional clone
let stored = StoredEvent {
    event: event_copy,
    // ... rest moved
};
```

**Step 3**: Check storage API signature

If `insert_event_if_not_exists` clones internally, consider changing to accept reference:

```rust
// Current signature
fn insert_event_if_not_exists(&self, event_id: EventId, event: StoredEvent) -> Result<bool>;

// Better signature (if possible)
fn insert_event_if_not_exists(&self, event_id: &EventId, event: &StoredEvent) -> Result<bool>;
```

#### Testing

```bash
# Run CRDT tests
cargo test --package igra-service coordination::crdt

# Benchmark (if available)
cargo bench crdt_merge
```

#### Validation Checklist

- [ ] Analyzed signing_material usage
- [ ] Removed unnecessary clones
- [ ] Verified functionality unchanged
- [ ] Tests pass
- [ ] Benchmarked (if possible) - should be ~100μs faster

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-H-3: Split crdt_handler.rs (865 lines)

**Priority**: HIGH
**Effort**: LARGE (4-5 days)
**Files**: 1 file → 6 files

#### Problem

Single file with 12 public functions, mixing multiple concerns.

#### Implementation Plan

**Option A: Modular Approach** (Recommended)

Split into focused modules:

```
service/coordination/crdt/
├── mod.rs (exports)
├── broadcast.rs (handle_crdt_broadcast, broadcast_local_state)
├── sync.rs (sync request/response, anti-entropy)
├── signing.rs (maybe_sign_and_broadcast)
├── submission.rs (maybe_submit_and_broadcast)
└── types.rs (shared types, constants)
```

**Option B: Command Pattern**

Keep single file but use command enum for clarity:

```rust
pub enum CrdtCommand {
    HandleBroadcast { payload: EventStateBroadcast },
    HandleSyncRequest { request: StateSyncRequest },
    HandleSyncResponse { response: StateSyncResponse },
    RunAntiEntropy,
    TrySign { event_id: EventId },
    TrySubmit { event_id: EventId },
}

pub struct CrdtCommandHandler { /* context */ }

impl CrdtCommandHandler {
    pub async fn execute(&mut self, command: CrdtCommand) -> Result<(), ThresholdError> {
        match command {
            CrdtCommand::HandleBroadcast { payload } => self.handle_broadcast(payload).await,
            // ...
        }
    }
}
```

#### Detailed Steps for Option A (Recommended)

**Step 1**: Create directory structure

```bash
cd igra-service/src/service/coordination
mkdir crdt
touch crdt/mod.rs
touch crdt/broadcast.rs
touch crdt/sync.rs
touch crdt/signing.rs
touch crdt/submission.rs
touch crdt/types.rs
```

**Step 2**: Extract types and constants

**File**: `service/coordination/crdt/types.rs`

```rust
//! Shared types for CRDT coordination

use igra_core::application::*;
use std::sync::Arc;

/// Context for CRDT operations
pub struct CrdtContext {
    pub storage: Arc<dyn Storage>,
    pub key_manager: Arc<dyn KeyManager>,
    pub transport: Arc<dyn Transport>,
    pub config: Arc<ServiceConfig>,
}

// Constants
pub const ANTI_ENTROPY_INTERVAL_SECS: u64 = 30;
pub const SYNC_BATCH_SIZE: usize = 100;
```

**Step 3**: Extract broadcast operations

**File**: `service/coordination/crdt/broadcast.rs`

```rust
//! CRDT broadcast handling

use super::types::CrdtContext;
use igra_core::application::*;
use igra_core::foundation::error::ThresholdError;

pub async fn handle_crdt_broadcast(
    ctx: &CrdtContext,
    payload: EventStateBroadcast,
) -> Result<(), ThresholdError> {
    // Move implementation from crdt_handler.rs
    // (Lines related to handle_crdt_broadcast)
}

pub async fn broadcast_local_state(
    ctx: &CrdtContext,
    event_id: &EventId,
) -> Result<(), ThresholdError> {
    // Move implementation from crdt_handler.rs
}
```

**Step 4**: Extract sync operations

**File**: `service/coordination/crdt/sync.rs`

```rust
//! CRDT synchronization (anti-entropy)

use super::types::CrdtContext;
use igra_core::application::*;
use igra_core::foundation::error::ThresholdError;

pub async fn handle_state_sync_request(
    ctx: &CrdtContext,
    request: StateSyncRequest,
) -> Result<(), ThresholdError> {
    // Move from crdt_handler.rs
}

pub async fn handle_state_sync_response(
    ctx: &CrdtContext,
    response: StateSyncResponse,
) -> Result<(), ThresholdError> {
    // Move from crdt_handler.rs
}

pub async fn run_anti_entropy_loop(
    ctx: &CrdtContext,
) -> Result<(), ThresholdError> {
    // Move from crdt_handler.rs
}
```

**Step 5**: Extract signing operations

**File**: `service/coordination/crdt/signing.rs`

```rust
//! CRDT signing coordination

use super::types::CrdtContext;
use igra_core::application::*;
use igra_core::foundation::error::ThresholdError;

pub async fn maybe_sign_and_broadcast(
    ctx: &CrdtContext,
    event_id: &EventId,
) -> Result<(), ThresholdError> {
    // Move from crdt_handler.rs
}
```

**Step 6**: Extract submission operations

**File**: `service/coordination/crdt/submission.rs`

```rust
//! Transaction submission coordination

use super::types::CrdtContext;
use igra_core::application::*;
use igra_core::foundation::error::ThresholdError;

pub async fn maybe_submit_and_broadcast(
    ctx: &CrdtContext,
    event_id: &EventId,
) -> Result<(), ThresholdError> {
    // Move from crdt_handler.rs
}
```

**Step 7**: Create module exports

**File**: `service/coordination/crdt/mod.rs`

```rust
//! CRDT coordination module

mod broadcast;
mod signing;
mod submission;
mod sync;
mod types;

pub use broadcast::*;
pub use signing::*;
pub use submission::*;
pub use sync::*;
pub use types::CrdtContext;
```

**Step 8**: Update coordination/mod.rs

```rust
pub mod crdt;  // NEW modular structure
// Remove: pub mod crdt_handler;
pub mod two_phase_handler;
pub mod unfinalized_reporter;

pub use crdt::*;  // Re-export for backwards compatibility
```

#### Testing

```bash
# All coordination tests should pass
cargo test --package igra-service coordination

# Integration tests
cargo test --package igra-service --test integration
```

#### Validation Checklist

- [ ] All 6 files created
- [ ] Functions moved to appropriate modules
- [ ] CrdtContext shared across modules
- [ ] mod.rs exports public API
- [ ] coordination/mod.rs updated
- [ ] All tests pass
- [ ] No functionality changed
- [ ] Each file < 300 lines

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

## Medium Priority Tasks

**Total Effort**: 25 days

---

### TASK-M-1: Add MetadataKey Type Safety

**Priority**: MEDIUM
**Effort**: SMALL (1 day)
**Files**: 2 files

#### Problem

Metadata keys are strings - prone to typos, no compiler checking.

**File**: `api/handlers/hyperlane.rs`

```rust
// ❌ BEFORE
metadata_map.insert("hyperlane.mode".to_string(), mode_str);
metadata_map.insert("hyperlane.threshold".to_string(), threshold.to_string());
```

#### Implementation Steps

**Step 1**: Create enum

**File**: `foundation/types.rs`

Add after existing type definitions:

```rust
/// Metadata keys for external integrations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataKey {
    #[serde(rename = "hyperlane.mode")]
    HyperlaneMode,

    #[serde(rename = "hyperlane.threshold")]
    HyperlaneThreshold,

    #[serde(rename = "hyperlane.validators")]
    HyperlaneValidators,

    #[serde(rename = "hyperlane.domain")]
    HyperlaneDomain,
}

impl MetadataKey {
    /// Get key as string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HyperlaneMode => "hyperlane.mode",
            Self::HyperlaneThreshold => "hyperlane.threshold",
            Self::HyperlaneValidators => "hyperlane.validators",
            Self::HyperlaneDomain => "hyperlane.domain",
        }
    }
}

impl std::fmt::Display for MetadataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_key_display() {
        assert_eq!(MetadataKey::HyperlaneMode.to_string(), "hyperlane.mode");
    }

    #[test]
    fn test_metadata_key_serde() {
        let key = MetadataKey::HyperlaneMode;
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, r#""hyperlane.mode""#);
    }
}
```

**Step 2**: Update usage in hyperlane handler

**File**: `api/handlers/hyperlane.rs`

```rust
use igra_core::foundation::types::MetadataKey;

// ❌ BEFORE
metadata_map.insert("hyperlane.mode".to_string(), mode_str);

// ✅ AFTER
metadata_map.insert(MetadataKey::HyperlaneMode.to_string(), mode_str);
```

#### Testing

```bash
cargo test --package igra-core --lib foundation::types
cargo test --package igra-service --lib api::handlers::hyperlane
```

#### Validation Checklist

- [ ] MetadataKey enum created
- [ ] All keys defined
- [ ] Display trait implemented
- [ ] Serde serialization works
- [ ] All string literals replaced
- [ ] Tests pass

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-M-2: Document Lock Semantics

**Priority**: MEDIUM
**Effort**: SMALL (2 hours)
**Files**: 1 file

#### Problem

No documentation of lock acquisition order - deadlock risk.

**File**: `infrastructure/storage/rocks/engine.rs`

#### Implementation Steps

**Step 1**: Add module-level documentation

Add at top of engine.rs (after imports):

```rust
//! RocksDB storage engine
//!
//! # Lock Acquisition Order
//!
//! To prevent deadlocks, locks MUST be acquired in this order:
//! 1. `phase_lock` - Event phase transitions
//! 2. `crdt_lock` - CRDT state merging
//! 3. `hyperlane_lock` - Hyperlane delivery tracking
//!
//! **NEVER acquire locks in a different order!**
//!
//! # Lock Timeout
//!
//! All locks use a 2-second timeout (see `STORAGE_LOCK_TIMEOUT_SECS`).
//! If a lock cannot be acquired within timeout, operation fails with
//! `StorageLockTimeout` error.
//!
//! # Examples
//!
//! ```ignore
//! // Correct - acquire phase_lock first, then crdt_lock
//! let _phase_guard = acquire_with_timeout(&self.phase_lock, "phase_transition").await?;
//! let _crdt_guard = acquire_with_timeout(&self.crdt_lock, "crdt_merge").await?;
//! // ... operation
//!
//! // WRONG - will deadlock if another thread acquires in correct order!
//! let _crdt_guard = self.crdt_lock.lock().await;  // Acquired first
//! let _phase_guard = self.phase_lock.lock().await;  // Acquired second - DEADLOCK RISK
//! ```
//!
//! # Lock Scope
//!
//! Each lock protects specific operations:
//! - `phase_lock`: Phase transitions, proposal lifecycle
//! - `crdt_lock`: CRDT event state, partial signature merging
//! - `hyperlane_lock`: Hyperlane message delivery tracking
```

**Step 2**: Add inline comments at lock definitions

```rust
pub struct RocksStorage {
    db: Arc<DB>,

    /// Phase transition lock - ACQUIRE FIRST in multi-lock operations
    phase_lock: Arc<Mutex<()>>,

    /// CRDT merge lock - ACQUIRE SECOND (after phase_lock)
    crdt_lock: Arc<Mutex<()>>,

    /// Hyperlane delivery lock - ACQUIRE THIRD (after crdt_lock)
    hyperlane_lock: Arc<Mutex<()>>,
}
```

**Step 3**: Add lock order validation (debug mode)

```rust
#[cfg(debug_assertions)]
thread_local! {
    static ACQUIRED_LOCKS: std::cell::RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
}

#[cfg(debug_assertions)]
fn validate_lock_order(lock_name: &'static str) {
    ACQUIRED_LOCKS.with(|locks| {
        let mut locks = locks.borrow_mut();

        // Check order: phase -> crdt -> hyperlane
        match lock_name {
            "phase_lock" => {
                // OK - always allowed first
            }
            "crdt_lock" => {
                if locks.contains(&"hyperlane_lock") {
                    panic!("DEADLOCK RISK: crdt_lock acquired after hyperlane_lock");
                }
            }
            "hyperlane_lock" => {
                // OK - always acquired last
            }
            _ => {}
        }

        locks.push(lock_name);
    });
}
```

#### Validation Checklist

- [ ] Module-level documentation added
- [ ] Lock order documented
- [ ] Lock timeout documented
- [ ] Examples provided
- [ ] Inline comments on lock fields
- [ ] Debug assertion added (optional)

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-M-3: Add Concurrent Access Tests

**Priority**: MEDIUM
**Effort**: MEDIUM (2 days)
**Files**: 3 new test files

#### Problem

No tests for concurrent access to storage, potential race conditions.

#### Implementation Steps

**Step 1**: Create concurrent CRDT test

**File**: `igra-core/tests/integration/concurrent_crdt.rs` (NEW)

```rust
//! Concurrent CRDT operation tests

use igra_core::infrastructure::storage::{CrdtStorage, RocksStorage};
use igra_core::domain::crdt::EventCrdtState;
use igra_core::foundation::types::EventId;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_crdt_merge() {
    let storage = Arc::new(RocksStorage::new_temp().unwrap());

    // Spawn 10 tasks concurrently
    let handles: Vec<_> = (0..10).map(|i| {
        let storage = storage.clone();
        tokio::spawn(async move {
            // Each task performs 100 CRDT merges
            for j in 0..100 {
                let event_id = EventId::from_bytes([i as u8; 32]);
                let state = create_test_crdt_state(j);

                storage.upsert_event_crdt(&event_id, &state).await
                    .expect("CRDT upsert should succeed");
            }
        })
    }).collect();

    // Wait for all tasks
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify: 10 events x 100 versions = all merged correctly
    for i in 0..10 {
        let event_id = EventId::from_bytes([i as u8; 32]);
        let state = storage.get_event_crdt(&event_id).await.unwrap();
        assert!(state.is_some());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_lock_contention() {
    let storage = Arc::new(RocksStorage::new_temp().unwrap());

    // 20 tasks trying to acquire same lock
    let handles: Vec<_> = (0..20).map(|_| {
        let storage = storage.clone();
        tokio::spawn(async move {
            let event_id = EventId::from_bytes([1u8; 32]);

            // Should not timeout (2 sec timeout, 20 tasks < 40 sec)
            storage.upsert_event_crdt(&event_id, &create_test_crdt_state(0)).await
                .expect("Should acquire lock within timeout");
        })
    }).collect();

    for handle in handles {
        handle.await.unwrap();
    }
}

fn create_test_crdt_state(version: usize) -> EventCrdtState {
    // Helper to create test state
    EventCrdtState {
        // ... fields
    }
}
```

**Step 2**: Create concurrent phase transition test

**File**: `igra-core/tests/integration/concurrent_phase.rs` (NEW)

```rust
//! Concurrent phase transition tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_phase_transitions() {
    // Test multiple events transitioning phases concurrently
}

#[tokio::test]
async fn test_phase_transition_race_condition() {
    // Test that only one thread can transition a specific event's phase
}
```

**Step 3**: Create storage stress test

**File**: `igra-core/tests/integration/storage_stress.rs` (NEW)

```rust
//! Storage stress tests

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]  // Run manually for stress testing
async fn test_storage_stress_1000_events() {
    // Insert/update/query 1000 events from 8 threads
}
```

#### Testing

```bash
# Run concurrent tests
cargo test --package igra-core --test concurrent_crdt -- --test-threads=4
cargo test --package igra-core --test concurrent_phase -- --test-threads=4

# Run stress test manually
cargo test --package igra-core --test storage_stress -- --ignored --test-threads=8
```

#### Validation Checklist

- [ ] concurrent_crdt.rs created with 2+ tests
- [ ] concurrent_phase.rs created with 2+ tests
- [ ] storage_stress.rs created
- [ ] Tests pass with multiple threads
- [ ] No deadlocks detected
- [ ] Lock timeout errors logged correctly

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-M-4: Optimize PSKT Clone Patterns

**Priority**: MEDIUM
**Effort**: MEDIUM (1.5 days)
**Files**: 1 file

**File**: `igra-core/src/domain/pskt/multisig.rs:39-42, 51-52`

#### Problem

Cloning PSKT inputs/outputs in loops.

```rust
// Current code (lines 39-42)
for (i, input) in pskt.inputs.iter().enumerate() {
    // Clones input fields
}

for (i, output) in pskt.outputs.iter().enumerate() {
    // Clones output fields
}
```

#### Implementation Steps

**Step 1**: Analyze what's being cloned and why

**Step 2**: Refactor to use references or Cow

```rust
use std::borrow::Cow;

// If occasional clone needed, use Cow
for (i, input) in pskt.inputs.iter().enumerate() {
    let input_ref: Cow<PsktInput> = if needs_modification {
        Cow::Owned(input.clone())  // Only clone if needed
    } else {
        Cow::Borrowed(input)  // Just reference
    };

    // Use input_ref
}
```

**Step 3**: Benchmark before/after

```rust
// Add benchmark
#[cfg(test)]
mod benches {
    #[bench]
    fn bench_sign_pskt_no_clone(b: &mut Bencher) {
        // Measure performance after optimization
    }
}
```

#### Testing

```bash
cargo test --package igra-core --lib domain::pskt::multisig
cargo bench pskt_signing  # If benchmarks exist
```

#### Validation Checklist

- [ ] Analyzed clone necessity
- [ ] Used Cow or references where possible
- [ ] Tests pass
- [ ] Benchmarked (if possible)
- [ ] No performance regression

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-M-5: Add Module-Level Documentation

**Priority**: LOW
**Effort**: SMALL (1 day)
**Files**: 8 modules

#### Problem

Some modules lack module-level documentation explaining their purpose.

#### Modules Needing Documentation

1. `service/coordination/` - CRDT consensus flow
2. `infrastructure/storage/rocks/` - Lock semantics, column families
3. `api/handlers/hyperlane.rs` - Metadata transformation logic
4. `domain/validation/` - Validation strategies
5. `application/two_phase.rs` - Two-phase commit protocol
6. `infrastructure/transport/iroh/` - P2P transport architecture
7. `domain/crdt/` - CRDT merge algorithm
8. `infrastructure/hyperlane/` - Hyperlane integration

#### Implementation Steps

**Step 1**: Add module documentation

For each module, add at the top:

```rust
//! Module purpose and architecture
//!
//! # Overview
//!
//! [Brief description of what this module does]
//!
//! # Architecture
//!
//! [How components interact, data flow]
//!
//! # Examples
//!
//! ```ignore
//! [Usage example]
//! ```
//!
//! # Implementation Notes
//!
//! [Important details, gotchas, design decisions]
```

**Example**:

**File**: `service/coordination/mod.rs`

```rust
//! Service coordination layer
//!
//! # Overview
//!
//! Coordinates threshold signing using CRDT-based consensus and
//! two-phase commit protocol.
//!
//! # Architecture
//!
//! ```text
//! Incoming Events
//!     ↓
//! CRDT Handler (gossip, merge, anti-entropy)
//!     ↓
//! Signing Phase (collect m-of-n signatures)
//!     ↓
//! Two-Phase Commit (propose, commit canonical tx)
//!     ↓
//! Submission (broadcast to Kaspa network)
//! ```
//!
//! # Consensus Flow
//!
//! 1. Events arrive via Hyperlane/LayerZero
//! 2. CRDT merges all signers' views
//! 3. Each signer signs independently
//! 4. Two-phase commit selects canonical transaction
//! 5. Submitter broadcasts to Kaspa network
//!
//! # Lock Semantics
//!
//! - CRDT operations hold `crdt_lock`
//! - Phase transitions hold `phase_lock`
//! - See storage module for lock ordering
```

#### Validation Checklist

- [ ] All 8 modules have //! documentation
- [ ] Overview section explains purpose
- [ ] Architecture/flow documented
- [ ] Examples provided (where applicable)
- [ ] cargo doc generates readable documentation

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

## Low Priority Tasks (Optional)

**Total Effort**: 5 days

---

### TASK-L-1: Extract ResultExt Trait for Nested Option/Result

**Priority**: LOW
**Effort**: SMALL (4 hours)
**Files**: 2 files

#### Problem

Repeated pattern of `Result<Option<T>> → Result<T>` conversion.

```rust
// Found in multiple places
let value = storage.get_something(&id)?
    .ok_or_else(|| ThresholdError::NotFound { id })?;
```

#### Implementation Steps

**Step 1**: Create extension trait

**File**: `foundation/util/result_ext.rs` (NEW)

```rust
//! Result and Option extension traits

use crate::foundation::error::ThresholdError;

/// Extension for Result<Option<T>> to simplify required() pattern
pub trait ResultExt<T> {
    /// Convert Result<Option<T>> to Result<T>, with error if None
    fn required(self, error: impl FnOnce() -> ThresholdError) -> Result<T, ThresholdError>;
}

impl<T> ResultExt<T> for Result<Option<T>, ThresholdError> {
    fn required(self, error: impl FnOnce() -> ThresholdError) -> Result<T, ThresholdError> {
        self?.ok_or_else(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_ext_some() {
        let result: Result<Option<i32>, ThresholdError> = Ok(Some(42));
        let value = result.required(|| ThresholdError::Message("missing".to_string()));
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    fn test_result_ext_none() {
        let result: Result<Option<i32>, ThresholdError> = Ok(None);
        let value = result.required(|| ThresholdError::Message("missing".to_string()));
        assert!(value.is_err());
    }
}
```

**Step 2**: Update foundation/util/mod.rs

```rust
pub mod encoding;
pub mod hex_fmt;
pub mod result_ext;  // NEW
pub mod time;

pub use result_ext::ResultExt;
```

**Step 3**: Use in codebase

```rust
use crate::foundation::util::ResultExt;

// ❌ BEFORE
let value = storage.get_something(&id)?
    .ok_or_else(|| ThresholdError::NotFound { id })?;

// ✅ AFTER
let value = storage.get_something(&id)
    .required(|| ThresholdError::NotFound { id })?;
```

#### Validation Checklist

- [ ] result_ext.rs created
- [ ] ResultExt trait implemented
- [ ] Tests added
- [ ] Updated call sites (optional - can be gradual)
- [ ] Cleaner code

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

### TASK-L-2: Performance Profiling and Optimization

**Priority**: LOW
**Effort**: MEDIUM (2 days)
**Files**: Various

#### Problem

No performance baseline or profiling.

#### Implementation Steps

**Step 1**: Add benchmark suite

**File**: `igra-core/benches/crdt_operations.rs` (NEW)

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use igra_core::infrastructure::storage::{CrdtStorage, RocksStorage};

fn benchmark_crdt_merge(c: &mut Criterion) {
    let storage = RocksStorage::new_temp().unwrap();
    let event_id = EventId::random();

    c.bench_function("crdt_merge", |b| {
        b.iter(|| {
            let state = create_test_state();
            storage.upsert_event_crdt(black_box(&event_id), black_box(&state))
        })
    });
}

criterion_group!(benches, benchmark_crdt_merge);
criterion_main!(benches);
```

**Step 2**: Profile with flamegraph

```bash
# Install profiling tools
cargo install flamegraph

# Profile CRDT operations
sudo cargo flamegraph --bench crdt_operations

# Profile full service
sudo cargo flamegraph --bin kaspa-threshold-service -- --network devnet
```

**Step 3**: Identify hot paths and optimize

Document findings and create optimization tasks.

#### Validation Checklist

- [ ] Benchmark suite created
- [ ] Baseline performance measured
- [ ] Hot paths identified
- [ ] Flamegraph generated
- [ ] Optimization opportunities documented

**Assignee**: ____________
**Status**: [ ] Not Started [ ] In Progress [ ] Complete
**Completion Date**: ____________

---

## Validation Checklist

### After All Quick Wins (Week 1)

```bash
# CODE-GUIDELINE compliance
grep -rn "ThresholdError::Message" igra-core/src igra-service/src | grep -v "bin/\|api/handlers\|test" | wc -l
# Expected: 0

grep -rn "hex::encode" igra-core/src igra-service/src | grep "info!\|warn!\|error!" | wc -l
# Expected: 0

grep -rn "clone()\.unwrap_or_default()" igra-core/src igra-service/src | wc -l
# Expected: 0

# Build succeeds
cargo build --all-features
cargo clippy --all-features
cargo test --all-features
```

### After Critical Tasks (Week 2)

```bash
# No service → domain direct imports
grep -rn "use igra_core::domain::" igra-service/src | grep -v "test" | wc -l
# Expected: 0

# All storage operations have timeouts
grep -rn "\.lock().await" igra-core/src/infrastructure/storage | grep -v "test\|acquire_with_timeout" | wc -l
# Expected: 0

# Run full test suite
cargo test --all-features --all-targets
```

### After High Priority Tasks (Week 3)

```bash
# No file exceeds 800 lines (strict) or 500 lines (target)
find igra-core/src igra-service/src -name "*.rs" -exec wc -l {} \; | awk '$1 > 800 {print}'
# Expected: 0 results

# All traits properly separated
cargo doc --no-deps --open
# Verify: CrdtStorage, PhaseStorage, HyperlaneStorage in docs
```

---

## Summary

### Task Breakdown

| Category | Tasks | Est. Days | Can Parallelize? |
|----------|-------|-----------|------------------|
| **Quick Wins** | 6 | 2 | ✅ Yes (6 parallel) |
| **Critical** | 2 | 6 | ⚠️ Partial (2 parallel) |
| **High Priority** | 3 | 15 | ✅ Yes (3 parallel) |
| **Medium Priority** | 5 | 8 | ✅ Yes (5 parallel) |
| **Low Priority** | 2 | 4 | ✅ Yes (2 parallel) |
| **TOTAL** | **18** | **35** | **With 3 devs: 2-3 weeks** |

### Recommended Approach

**Week 1**: All Quick Wins (parallel)
- 6 developers can work independently
- 2 days total
- Immediate improvements

**Week 2**: Critical + High Priority (parallel)
- Developer A: RocksStorage decomposition
- Developer B: CRDT handler split
- Developer C: Application layer boundary
- 5 days total

**Week 3**: Medium Priority + Testing
- Remaining tasks + comprehensive testing
- 5 days total

**Week 4**: Low Priority + Documentation
- Optional tasks + polish
- 3 days total

### Success Criteria

After completing refactoring:

✅ Zero ThresholdError::Message (except edges)
✅ Zero .unwrap() in production code
✅ Zero clone().unwrap_or_default()
✅ Zero hex::encode() in logs
✅ All files < 500 lines (target) or < 800 lines (max)
✅ No service → domain imports
✅ Lock timeouts on all mutexes
✅ Comprehensive test coverage
✅ Full documentation

---

END OF GUIDE
