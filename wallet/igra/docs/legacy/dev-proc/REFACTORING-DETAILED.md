# Igra Refactoring - Detailed Implementation Guide

**Document ID**: REFACTOR-DETAILED-001
**Purpose**: Provide EXACT, step-by-step instructions for each refactoring task
**Audience**: Developers implementing refactorings (assumes minimal initiative - be explicit!)

---

## How to Use This Document

**FOR EACH REFACTORING:**
1. Follow steps IN ORDER (numbered 1, 2, 3...)
2. DO NOT skip steps
3. DO NOT improvise - if something is not listed, DO NOT change it
4. Run verification after each step
5. If a step fails verification, STOP and report the issue

**IMPORTANT**: This document is EXHAUSTIVE. If a file/function is not explicitly listed, DO NOT modify it.

---

## Table of Contents

- [REFACTOR-001: Centralize Timestamp Utilities](#refactor-001-centralize-timestamp-utilities)
- [REFACTOR-002: Add From Trait Implementations for Errors](#refactor-002-add-from-trait-implementations-for-errors)
- [REFACTOR-003: Centralize Hex Encoding/Decoding](#refactor-003-centralize-hex-encodingdecoding)
- [REFACTOR-004: Safe Type Conversions](#refactor-004-safe-type-conversions)
- [REFACTOR-005: Storage Key Construction Builder](#refactor-005-storage-key-construction-builder)
- [REFACTOR-011: Expand Error Type Variants](#refactor-011-expand-error-type-variants)
- [REFACTOR-012: Result Type Alias](#refactor-012-result-type-alias)
- [REFACTOR-013: Builder Pattern for Complex Constructors](#refactor-013-builder-pattern-for-complex-constructors)
- [REFACTOR-023: Extract Magic Numbers to Constants](#refactor-023-extract-magic-numbers-to-constants)

---

## REFACTOR-001: Centralize Timestamp Utilities

### Status
✅ ALREADY COMPLETED - `util/time.rs` exists

### What Was Done
- Created `igra-core/src/util/time.rs`
- Added `current_timestamp_nanos_env()` function
- Added `day_start_nanos()` function

### Current State Verification

**Run this command:**
```bash
ls -la igra-core/src/util/time.rs
grep -n "pub fn current_timestamp_nanos" igra-core/src/util/time.rs
```

**Expected output:**
```
igra-core/src/util/time.rs exists
Line showing: pub fn current_timestamp_nanos_env(...)
```

### No Action Required
This refactoring is complete. Move to REFACTOR-002.

---

## REFACTOR-002: Add From Trait Implementations for Errors

### Goal
Eliminate 100+ instances of `.map_err(|err| ThresholdError::Message(err.to_string()))` by implementing `From` traits.

### Current Problem

**File**: Multiple files across the codebase

**Pattern (appears ~100 times)**:
```rust
hex::decode(value).map_err(|err| ThresholdError::Message(err.to_string()))?
serde_json::from_str(s).map_err(|err| ThresholdError::Message(err.to_string()))?
bincode::serialize(data).map_err(|err| ThresholdError::Message(err.to_string()))?
```

### Step 1: Add From Implementations to error.rs

**File**: `igra-core/src/error.rs`

**Action**: ADD the following implementations AT THE END of the file (after the existing `ThresholdError` enum):

```rust
// ============================================================================
// From Trait Implementations (REFACTOR-002)
// ============================================================================

impl From<hex::FromHexError> for ThresholdError {
    fn from(err: hex::FromHexError) -> Self {
        ThresholdError::Message(format!("hex decode error: {}", err))
    }
}

impl From<serde_json::Error> for ThresholdError {
    fn from(err: serde_json::Error) -> Self {
        ThresholdError::Message(format!("JSON error: {}", err))
    }
}

impl From<bincode::Error> for ThresholdError {
    fn from(err: bincode::Error) -> Self {
        ThresholdError::StorageError(format!("serialization error: {}", err))
    }
}

impl From<std::io::Error> for ThresholdError {
    fn from(err: std::io::Error) -> Self {
        ThresholdError::Message(format!("IO error: {}", err))
    }
}

impl From<secp256k1::Error> for ThresholdError {
    fn from(err: secp256k1::Error) -> Self {
        ThresholdError::Message(format!("secp256k1 error: {}", err))
    }
}

impl From<kaspa_addresses::AddressError> for ThresholdError {
    fn from(err: kaspa_addresses::AddressError) -> Self {
        ThresholdError::Message(format!("address error: {}", err))
    }
}
```

**Verification**:
```bash
cargo build --package igra-core 2>&1 | grep -i error
# Should compile without errors
```

### Step 2: Replace hex::decode Boilerplate

**EXACT FILES TO MODIFY** (8 files total):

#### File 1: `igra-core/src/pskt/builder.rs`

**Line 33** (find this EXACT line):
```rust
let redeem_script = hex::decode(&config.redeem_script_hex).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Replace with**:
```rust
let redeem_script = hex::decode(&config.redeem_script_hex)?;
```

#### File 2: `igra-core/src/util/encoding.rs`

**Line 12** (find this EXACT line):
```rust
hex::decode(s).map_err(|e| ThresholdError::Message(format!("invalid hex: {}", e)))
```

**Replace with**:
```rust
hex::decode(s).map_err(|e| e.into())
```

#### File 3: `igra-core/src/bin/devnet-keygen.rs`

**Line 75** (find this EXACT line):
```rust
let bytes = hex::decode(seed_hex).map_err(|e| ThresholdError::Message(format!("seed hex decode: {e}")))?;
```

**Replace with**:
```rust
let bytes = hex::decode(seed_hex)?;
```

**Line 232** (find this EXACT pattern):
```rust
.map(|hex_pk| hex::decode(hex_pk).map_err(|e| ThresholdError::Message(format!("pubkey hex decode: {e}"))))
```

**Replace with**:
```rust
.map(|hex_pk| hex::decode(hex_pk).map_err(|e| e.into()))
```

#### File 4: `igra-core/src/config/loader.rs`

**Line 283** (find this EXACT line):
```rust
let bytes = hex::decode(hex_key.trim()).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Replace with**:
```rust
let bytes = hex::decode(hex_key.trim())?;
```

#### File 5: `igra-core/src/hyperlane/ism.rs`

**Line 199** (find this EXACT line):
```rust
let bytes = hex::decode(stripped).map_err(|_| ThresholdError::ConfigError("invalid hyperlane validator hex".to_string()))?;
```

**Replace with** (NOTE: Keep custom error message):
```rust
let bytes = hex::decode(stripped)
    .map_err(|_| ThresholdError::ConfigError("invalid hyperlane validator hex".to_string()))?;
```

**DO NOT change this one** - it has a custom error message we want to preserve.

#### File 6: `igra-core/src/event/mod.rs`

**Line 123** (find this EXACT line):
```rust
let bytes = hex::decode(value.trim()).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Replace with**:
```rust
let bytes = hex::decode(value.trim())?;
```

**Line 133** (find this EXACT line):
```rust
let bytes = hex::decode(hex_value.trim()).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Replace with**:
```rust
let bytes = hex::decode(hex_value.trim())?;
```

### Step 3: Verification

**Run this command to find remaining map_err patterns**:
```bash
grep -rn "hex::decode.*map_err.*ThresholdError::Message" igra-core/src --include="*.rs"
```

**Expected**: Should show ONLY `hyperlane/ism.rs:199` (the one we kept intentionally)

**Run tests**:
```bash
cargo test --package igra-core
```

**Expected**: All tests pass

### Step 4: Replace serde_json Boilerplate

**Search pattern**:
```bash
grep -rn "serde_json.*map_err.*ThresholdError::Message" igra-core/src --include="*.rs"
```

**For EACH result**:
1. Note the file and line number
2. Replace `.map_err(|err| ThresholdError::Message(err.to_string()))?` with `?`
3. Verify it compiles

**Files likely affected** (check each):
- `igra-core/src/config/loader.rs`
- `igra-core/src/event/mod.rs`
- `igra-service/src/api/json_rpc.rs`

### Step 5: Replace bincode Boilerplate

**Search pattern**:
```bash
grep -rn "bincode.*map_err.*ThresholdError" igra-core/src --include="*.rs"
```

**For EACH result**:
1. Note the file and line number
2. Replace `.map_err(|err| ThresholdError::Message(err.to_string()))?` with `?`
3. Verify it compiles

**Files likely affected**:
- `igra-core/src/storage/rocks.rs`

### Final Verification

```bash
# Count remaining map_err boilerplate
grep -rn "\.map_err(|err| ThresholdError::Message(err.to_string()))" igra-core/src --include="*.rs" | wc -l
```

**Expected**: < 20 (down from ~100)

**Acceptable exceptions**:
- Custom error messages (like hyperlane/ism.rs)
- Complex error transformations

---

## REFACTOR-003: Centralize Hex Encoding/Decoding

### Status
✅ ALREADY COMPLETED - `util/encoding.rs` exists

### Current State Verification

**Run this command:**
```bash
ls -la igra-core/src/util/encoding.rs
grep -n "pub fn decode_hex" igra-core/src/util/encoding.rs
```

**Expected**: File exists with `decode_hex`, `decode_hex_exact`, `decode_hex_array` functions

### No Action Required
This refactoring is complete. Move to REFACTOR-004.

---

## REFACTOR-004: Safe Type Conversions

### Status
✅ ALREADY COMPLETED - `util/conversion.rs` exists

### Current State Verification

**Run this command:**
```bash
ls -la igra-core/src/util/conversion.rs
grep -n "pub fn u64_to_u32" igra-core/src/util/conversion.rs
```

**Expected**: File exists with conversion functions

### No Action Required
This refactoring is complete. Move to REFACTOR-005.

---

## REFACTOR-005: Storage Key Construction Builder

### Goal
Replace manual key construction in `storage/rocks.rs` with a builder pattern.

### Current Problem

**File**: `igra-core/src/storage/rocks.rs`

**Pattern (appears 15+ times)**:
```rust
fn key_group(group_id: &Hash32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + group_id.len());
    key.extend_from_slice(b"grp:");
    key.extend_from_slice(group_id);
    key
}

fn key_event(event_hash: &Hash32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + event_hash.len());
    key.extend_from_slice(b"evt:");
    key.extend_from_slice(event_hash);
    key
}
```

### Step 1: Add KeyBuilder to storage/rocks.rs

**File**: `igra-core/src/storage/rocks.rs`

**Location**: Add IMMEDIATELY AFTER the imports, BEFORE `pub struct RocksStorage`

**Code to add**:

```rust
// ============================================================================
// KeyBuilder - Centralized key construction (REFACTOR-005)
// ============================================================================

/// Builder for RocksDB keys with type safety and consistency.
struct KeyBuilder {
    buf: Vec<u8>,
}

impl KeyBuilder {
    fn new() -> Self {
        Self { buf: Vec::with_capacity(64) }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self { buf: Vec::with_capacity(capacity) }
    }

    fn prefix(mut self, prefix: &[u8]) -> Self {
        self.buf.extend_from_slice(prefix);
        self
    }

    fn hash32(mut self, hash: &Hash32) -> Self {
        self.buf.extend_from_slice(hash);
        self
    }

    fn str(mut self, s: &str) -> Self {
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    fn bytes(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    fn u32_be(mut self, value: u32) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn u64_be(mut self, value: u64) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn separator(mut self) -> Self {
        self.buf.push(b':');
        self
    }

    fn build(self) -> Vec<u8> {
        self.buf
    }
}
```

**Verification**:
```bash
cargo build --package igra-core 2>&1 | grep -i "KeyBuilder"
# Should compile without errors about KeyBuilder
```

### Step 2: Find All Key Functions in rocks.rs

**Run this command**:
```bash
grep -n "fn key_" igra-core/src/storage/rocks.rs
```

**Expected output** (approximately):
```
Line XXX: fn key_group(...)
Line XXX: fn key_event(...)
Line XXX: fn key_request(...)
Line XXX: fn key_proposal(...)
Line XXX: fn key_request_input(...)
Line XXX: fn key_signer_ack(...)
Line XXX: fn key_partial_sig(...)
Line XXX: fn key_volume(...)
... (more key functions)
```

### Step 3: Replace Each Key Function

**FOR EACH key function found in Step 2**, replace using the pattern below.

#### Example 1: key_group

**Find this**:
```rust
fn key_group(group_id: &Hash32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + group_id.len());
    key.extend_from_slice(b"grp:");
    key.extend_from_slice(group_id);
    key
}
```

**Replace with**:
```rust
fn key_group(group_id: &Hash32) -> Vec<u8> {
    KeyBuilder::new()
        .prefix(b"grp:")
        .hash32(group_id)
        .build()
}
```

#### Example 2: key_event

**Find this**:
```rust
fn key_event(event_hash: &Hash32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + event_hash.len());
    key.extend_from_slice(b"evt:");
    key.extend_from_slice(event_hash);
    key
}
```

**Replace with**:
```rust
fn key_event(event_hash: &Hash32) -> Vec<u8> {
    KeyBuilder::new()
        .prefix(b"evt:")
        .hash32(event_hash)
        .build()
}
```

#### Example 3: key_request

**Find this**:
```rust
fn key_request(request_id: &RequestId) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + request_id.len());
    key.extend_from_slice(b"req:");
    key.extend_from_slice(request_id.as_bytes());
    key
}
```

**Replace with**:
```rust
fn key_request(request_id: &RequestId) -> Vec<u8> {
    KeyBuilder::new()
        .prefix(b"req:")
        .str(request_id.as_str())
        .build()
}
```

#### Example 4: key_partial_sig (complex key with multiple parts)

**Find this**:
```rust
fn key_partial_sig(request_id: &RequestId, signer_peer_id: &PeerId, input_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(b"req_sig:");
    key.extend_from_slice(request_id.as_bytes());
    key.push(b':');
    key.extend_from_slice(signer_peer_id.as_bytes());
    key.push(b':');
    key.extend_from_slice(&input_index.to_be_bytes());
    key
}
```

**Replace with**:
```rust
fn key_partial_sig(request_id: &RequestId, signer_peer_id: &PeerId, input_index: u32) -> Vec<u8> {
    KeyBuilder::new()
        .prefix(b"req_sig:")
        .str(request_id.as_str())
        .separator()
        .str(signer_peer_id.as_str())
        .separator()
        .u32_be(input_index)
        .build()
}
```

### Step 4: Complete List of Key Functions to Replace

**EXACT LIST** (replace ALL of these if they exist):

1. `key_group` → Use `.prefix(b"grp:").hash32(group_id)`
2. `key_event` → Use `.prefix(b"evt:").hash32(event_hash)`
3. `key_request` → Use `.prefix(b"req:").str(request_id.as_str())`
4. `key_proposal` → Use `.prefix(b"prop:").str(request_id.as_str())`
5. `key_request_input` → Use `.prefix(b"req_in:").str(request_id.as_str()).separator().u32_be(index)`
6. `key_signer_ack` → Use `.prefix(b"req_ack:").str(request_id.as_str()).separator().str(signer_peer_id.as_str())`
7. `key_partial_sig` → Use `.prefix(b"req_sig:").str(request_id.as_str()).separator().str(signer_peer_id.as_str()).separator().u32_be(input_index)`
8. `key_volume` → Use `.prefix(b"vol:").hash32(group_id).separator().u64_be(day_start_nanos)`

**If you find other key_ functions NOT in this list**:
1. DO NOT modify them yet
2. Note them in a comment
3. Report them for review

### Verification

```bash
# Compile
cargo build --package igra-core

# Run storage tests
cargo test --package igra-core storage::

# Check that all key functions now use KeyBuilder
grep -A 3 "fn key_" igra-core/src/storage/rocks.rs | grep -c "KeyBuilder"
```

**Expected**: Count should match number of key functions

---

## REFACTOR-011: Expand Error Type Variants

### Goal
Replace generic `ThresholdError::Message(String)` with specific error variants for common cases.

### Current Problem

**File**: `igra-core/src/error.rs`

Currently has:
```rust
#[derive(Debug, Error)]
pub enum ThresholdError {
    // ... existing variants
    #[error("{0}")]
    Message(String),  // Used for EVERYTHING
}
```

### Step 1: Add Specific Error Variants

**File**: `igra-core/src/error.rs`

**Location**: In the `ThresholdError` enum, ADD these variants BEFORE the `Message(String)` variant:

```rust
    // ============================================================================
    // Specific Error Variants (REFACTOR-011)
    // ============================================================================

    #[error("insufficient funds: required {required} sompi, available {available} sompi")]
    InsufficientFunds { required: u64, available: u64 },

    #[error("invalid input index: {index} (transaction has {max} inputs)")]
    InvalidInputIndex { index: u32, max: u32 },

    #[error("invalid output index: {index} (transaction has {max} outputs)")]
    InvalidOutputIndex { index: u32, max: u32 },

    #[error("invalid expiry: expires at {expires_at} but current time is {current}")]
    InvalidExpiry { expires_at: u64, current: u64 },

    #[error("request expired: expired at {expired_at}, current time {current}")]
    RequestExpired { expired_at: u64, current: u64 },

    #[error("timeout after {duration_secs} seconds")]
    Timeout { duration_secs: u64 },

    #[error("rate limited for peer {peer_id}: {reason}")]
    RateLimited { peer_id: String, reason: String },

    #[error("message too large: {size} bytes exceeds maximum {max} bytes")]
    MessageTooLarge { size: usize, max: usize },

    #[error("too many inputs: {count} exceeds maximum {max}")]
    TooManyInputs { count: usize, max: usize },

    #[error("too many outputs: {count} exceeds maximum {max}")]
    TooManyOutputs { count: usize, max: usize },

    #[error("destination not allowed: {destination}")]
    DestinationNotAllowed { destination: String },

    #[error("daily volume limit exceeded: current {current} + requested {requested} exceeds limit {limit}")]
    DailyVolumeLimitExceeded { current: u64, requested: u64, limit: u64 },

    #[error("per-transaction limit exceeded: requested {requested} exceeds limit {limit}")]
    PerTransactionLimitExceeded { requested: u64, limit: u64 },

    #[error("arithmetic overflow in {operation}")]
    ArithmeticOverflow { operation: String },

    #[error("signature verification failed: {reason}")]
    SignatureVerificationFailed { reason: String },

    #[error("threshold not met: received {received} signatures, required {required}")]
    ThresholdNotMet { received: usize, required: usize },

    #[error("duplicate signature from peer {peer_id}")]
    DuplicateSignature { peer_id: String },

    #[error("group not found: {group_id}")]
    GroupNotFound { group_id: String },

    #[error("request not found: {request_id}")]
    RequestNotFound { request_id: String },

    #[error("event not found: {event_hash}")]
    EventNotFound { event_hash: String },

    #[error("invalid state transition: from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },
```

**Verification**:
```bash
cargo build --package igra-core 2>&1 | grep -i error
# Should compile successfully
```

### Step 2: Replace Usage in Policy Enforcement

**File**: `igra-core/src/coordination/signer.rs` (or wherever policy checks are)

**Find code like this**:
```rust
if !policy.allowed_destinations.contains(&event.destination_address) {
    return Err(ThresholdError::Message("destination not allowed".to_string()));
}
```

**Replace with**:
```rust
if !policy.allowed_destinations.contains(&event.destination_address) {
    return Err(ThresholdError::DestinationNotAllowed {
        destination: event.destination_address.clone(),
    });
}
```

**Find code like this**:
```rust
if new_volume > policy.daily_limit {
    return Err(ThresholdError::Message(format!("daily limit exceeded")));
}
```

**Replace with**:
```rust
if new_volume > policy.daily_limit {
    return Err(ThresholdError::DailyVolumeLimitExceeded {
        current: current_volume,
        requested: event.amount_sompi,
        limit: policy.daily_limit,
    });
}
```

### Step 3: Replace Usage in PSKT Builder

**File**: `igra-core/src/pskt/builder.rs`

**Find code like this**:
```rust
if total_input < required {
    return Err(ThresholdError::Message("insufficient inputs for fee".to_string()));
}
```

**Replace with**:
```rust
if total_input < required {
    return Err(ThresholdError::InsufficientFunds {
        required,
        available: total_input,
    });
}
```

### Step 4: Replace Usage in Timeout Checks

**Search pattern**:
```bash
grep -rn "expires.*ThresholdError::Message" igra-core/src --include="*.rs"
```

**For each result**, replace with:
```rust
ThresholdError::RequestExpired {
    expired_at: expires_at_nanos,
    current: current_timestamp,
}
```

### Step 5: Replace Usage in Rate Limiting

**File**: `igra-core/src/rate_limit.rs`

**Find code like this**:
```rust
return Err(ThresholdError::Message("rate limited".to_string()));
```

**Replace with**:
```rust
return Err(ThresholdError::RateLimited {
    peer_id: peer_id.to_string(),
    reason: "too many requests".to_string(),
});
```

### Verification

```bash
# Count remaining generic Message errors
grep -rn "ThresholdError::Message" igra-core/src --include="*.rs" | wc -l
```

**Expected**: Reduced by at least 30-50 instances

**Test**:
```bash
cargo test --package igra-core
```

**Expected**: All tests pass, better error messages in failures

---

## REFACTOR-012: Result Type Alias

### Goal
Replace `Result<T, ThresholdError>` with `Result<T>` throughout the codebase.

### Step 1: Check if Already Exists

**Run**:
```bash
grep -n "pub type Result" igra-core/src/error.rs
```

**If found**: Skip to Step 3
**If not found**: Continue to Step 2

### Step 2: Add Result Type Alias

**File**: `igra-core/src/error.rs`

**Location**: AFTER the `ThresholdError` enum definition and its implementations

**Code to add**:
```rust
// ============================================================================
// Result Type Alias (REFACTOR-012)
// ============================================================================

/// Convenience Result type that uses ThresholdError as the error type.
pub type Result<T> = std::result::Result<T, ThresholdError>;
```

**Verification**:
```bash
cargo build --package igra-core
```

### Step 3: Export in lib.rs

**File**: `igra-core/src/lib.rs`

**Find this line**:
```rust
pub mod error;
```

**Change to**:
```rust
pub mod error;
pub use error::{ThresholdError, Result};
```

**Verification**:
```bash
cargo build --package igra-core
```

### Step 4: Replace in ALL Files

**AUTOMATED APPROACH** (recommended):

Create a script `replace_result.sh`:
```bash
#!/bin/bash

# Find all .rs files in igra-core/src
find igra-core/src -name "*.rs" -type f | while read file; do
    echo "Processing: $file"

    # Replace Result<T, ThresholdError> with Result<T>
    sed -i.bak 's/Result<\([^>]*\), ThresholdError>/Result<\1>/g' "$file"

    # Remove backup file
    rm "${file}.bak"
done

echo "Done. Now run: cargo build --package igra-core"
```

**Run**:
```bash
chmod +x replace_result.sh
./replace_result.sh
cargo build --package igra-core
```

**MANUAL APPROACH** (if script fails):

For each file in `igra-core/src/*.rs`:
1. Open file
2. Find all occurrences of `Result<XXX, ThresholdError>`
3. Replace with `Result<XXX>`
4. Save and compile

**Priority files** (do these first):
1. `igra-core/src/storage/mod.rs` - has ~20 occurrences
2. `igra-core/src/coordination/signer.rs` - has ~15 occurrences
3. `igra-core/src/coordination/coordinator.rs` - has ~10 occurrences
4. `igra-core/src/pskt/builder.rs` - has ~8 occurrences
5. `igra-core/src/rpc/mod.rs` - has ~10 occurrences

### Step 5: Fix Import Conflicts

**After replacement, you may see errors like**:
```
error: `Result` is ambiguous
```

**This happens when a file has**:
```rust
use std::result::Result;  // Conflicts with our Result
```

**Fix by**:
```rust
// Remove or comment out:
// use std::result::Result;

// Or qualify it:
use std::result::Result as StdResult;
```

### Verification

```bash
# Count replacements
grep -rn "Result<.*ThresholdError>" igra-core/src --include="*.rs" | wc -l
```

**Expected**: 0 (all replaced)

```bash
# Test
cargo test --package igra-core
```

**Expected**: All tests pass

---

## REFACTOR-013: Builder Pattern for Complex Constructors

### Goal
Replace functions with 5+ parameters with builder pattern.

### Step 1: Identify Functions to Refactor

**Run this to find functions with many parameters**:
```bash
# Find function signatures (this is a heuristic)
grep -rn "pub fn.*(" igra-core/src --include="*.rs" | grep -E ".*,.*,.*,.*,.*," | head -20
```

**EXACT FUNCTIONS TO REFACTOR** (only these, no others):

1. ✅ `Coordinator::propose_session` - 8 parameters (igra-core/src/coordination/coordinator.rs:35)
2. ✅ `Signer::validate_proposal` - ALREADY uses ProposalValidationRequest (SKIP)
3. ✅ `build_pskt_with_client` - Uses config struct (SKIP)

**DECISION**: Only #1 needs refactoring. #2 and #3 already use request/config objects.

### Step 2: Create Builder for propose_session

**File**: `igra-core/src/coordination/coordinator.rs`

**Location**: ADD immediately BEFORE the `impl Coordinator` block

**Code to add**:

```rust
// ============================================================================
// ProposeSessionRequest Builder (REFACTOR-013)
// ============================================================================

/// Request to propose a new signing session.
pub struct ProposeSessionRequest {
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub signing_event: SigningEvent,
    pub kpsbt_blob: Vec<u8>,
    pub tx_template_hash: Hash32,
    pub per_input_hashes: Vec<Hash32>,
    pub expires_at_nanos: u64,
    pub coordinator_peer_id: PeerId,
}

impl ProposeSessionRequest {
    pub fn builder() -> ProposeSessionRequestBuilder {
        ProposeSessionRequestBuilder::default()
    }
}

#[derive(Default)]
pub struct ProposeSessionRequestBuilder {
    session_id: Option<SessionId>,
    request_id: Option<RequestId>,
    signing_event: Option<SigningEvent>,
    kpsbt_blob: Option<Vec<u8>>,
    tx_template_hash: Option<Hash32>,
    per_input_hashes: Option<Vec<Hash32>>,
    expires_at_nanos: Option<u64>,
    coordinator_peer_id: Option<PeerId>,
}

impl ProposeSessionRequestBuilder {
    pub fn session_id(mut self, id: SessionId) -> Self {
        self.session_id = Some(id);
        self
    }

    pub fn request_id(mut self, id: RequestId) -> Self {
        self.request_id = Some(id);
        self
    }

    pub fn signing_event(mut self, event: SigningEvent) -> Self {
        self.signing_event = Some(event);
        self
    }

    pub fn kpsbt_blob(mut self, blob: Vec<u8>) -> Self {
        self.kpsbt_blob = Some(blob);
        self
    }

    pub fn tx_template_hash(mut self, hash: Hash32) -> Self {
        self.tx_template_hash = Some(hash);
        self
    }

    pub fn per_input_hashes(mut self, hashes: Vec<Hash32>) -> Self {
        self.per_input_hashes = Some(hashes);
        self
    }

    pub fn expires_at_nanos(mut self, nanos: u64) -> Self {
        self.expires_at_nanos = Some(nanos);
        self
    }

    pub fn coordinator_peer_id(mut self, peer_id: PeerId) -> Self {
        self.coordinator_peer_id = Some(peer_id);
        self
    }

    pub fn build(self) -> Result<ProposeSessionRequest, ThresholdError> {
        Ok(ProposeSessionRequest {
            session_id: self.session_id
                .ok_or_else(|| ThresholdError::Message("session_id required".to_string()))?,
            request_id: self.request_id
                .ok_or_else(|| ThresholdError::Message("request_id required".to_string()))?,
            signing_event: self.signing_event
                .ok_or_else(|| ThresholdError::Message("signing_event required".to_string()))?,
            kpsbt_blob: self.kpsbt_blob
                .ok_or_else(|| ThresholdError::Message("kpsbt_blob required".to_string()))?,
            tx_template_hash: self.tx_template_hash
                .ok_or_else(|| ThresholdError::Message("tx_template_hash required".to_string()))?,
            per_input_hashes: self.per_input_hashes
                .ok_or_else(|| ThresholdError::Message("per_input_hashes required".to_string()))?,
            expires_at_nanos: self.expires_at_nanos
                .ok_or_else(|| ThresholdError::Message("expires_at_nanos required".to_string()))?,
            coordinator_peer_id: self.coordinator_peer_id
                .ok_or_else(|| ThresholdError::Message("coordinator_peer_id required".to_string()))?,
        })
    }
}
```

### Step 3: Update propose_session Signature

**File**: `igra-core/src/coordination/coordinator.rs`

**Find**:
```rust
pub async fn propose_session(
    &self,
    session_id: SessionId,
    request_id: RequestId,
    signing_event: SigningEvent,
    kpskt_blob: Vec<u8>,
    tx_template_hash: Hash32,
    per_input_hashes: &[Hash32],
    expires_at_nanos: u64,
    coordinator_peer_id: PeerId,
) -> Result<Hash32, ThresholdError> {
```

**Replace with**:
```rust
pub async fn propose_session(&self, req: ProposeSessionRequest) -> Result<Hash32, ThresholdError> {
```

### Step 4: Update propose_session Implementation

**In the SAME function body**, update all parameter references:

**Find**: `session_id`
**Replace with**: `req.session_id`

**Find**: `request_id`
**Replace with**: `req.request_id`

**Find**: `signing_event`
**Replace with**: `req.signing_event`

**Find**: `kpskt_blob` or `kpsbt_blob`
**Replace with**: `req.kpsbt_blob`

**Find**: `tx_template_hash`
**Replace with**: `req.tx_template_hash`

**Find**: `per_input_hashes`
**Replace with**: `&req.per_input_hashes`

**Find**: `expires_at_nanos`
**Replace with**: `req.expires_at_nanos`

**Find**: `coordinator_peer_id`
**Replace with**: `req.coordinator_peer_id`

**NOTE**: Be careful with borrowing - use `&req.field` where references are needed.

### Step 5: Update ALL Call Sites

**Find all calls to propose_session**:
```bash
grep -rn "propose_session(" igra-core igra-service --include="*.rs"
```

**For EACH call site found**:

**OLD CODE**:
```rust
coordinator.propose_session(
    session_id,
    request_id,
    signing_event,
    kpsbt_blob,
    tx_template_hash,
    &per_input_hashes,
    expires_at_nanos,
    coordinator_peer_id,
).await?
```

**NEW CODE**:
```rust
let request = ProposeSessionRequest::builder()
    .session_id(session_id)
    .request_id(request_id)
    .signing_event(signing_event)
    .kpskt_blob(kpsbt_blob)
    .tx_template_hash(tx_template_hash)
    .per_input_hashes(per_input_hashes.to_vec())
    .expires_at_nanos(expires_at_nanos)
    .coordinator_peer_id(coordinator_peer_id)
    .build()?;

coordinator.propose_session(request).await?
```

**Files likely to update** (check each):
1. `igra-service/src/api/json_rpc.rs`
2. `igra-core/src/bin/devnet-*.rs`
3. Test files in `igra-core/tests/`
4. Test files in `igra-service/tests/`

### Verification

```bash
cargo build --package igra-core --package igra-service
cargo test --package igra-core --package igra-service
```

**Expected**: All compile, all tests pass

---

## REFACTOR-023: Extract Magic Numbers to Constants

### Goal
Replace magic numbers throughout the codebase with named constants.

### Step 1: Create constants.rs

**File**: `igra-core/src/constants.rs` (CREATE NEW FILE)

**Full contents**:

```rust
//! System-wide constants for Igra threshold signing.
//!
//! All magic numbers should be defined here for:
//! - Discoverability (one place to find all limits)
//! - Documentation (explain WHY each constant has its value)
//! - Easy tuning (change in one place)

// ============================================================================
// Time Constants
// ============================================================================

/// Nanoseconds per second (10^9).
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Nanoseconds per day (24 * 60 * 60 * 10^9).
///
/// Used for volume limit calculations aligned to UTC days.
pub const NANOS_PER_DAY: u64 = 24 * 60 * 60 * NANOS_PER_SECOND;

/// Minimum session timeout in nanoseconds (10 seconds).
///
/// Sessions shorter than this are rejected to prevent timing attacks
/// and give signers time to validate proposals.
pub const MIN_SESSION_DURATION_NS: u64 = 10 * NANOS_PER_SECOND;

/// Maximum session timeout in nanoseconds (1 hour).
///
/// Sessions longer than this are rejected to prevent indefinite resource holds.
pub const MAX_SESSION_DURATION_NS: u64 = 60 * 60 * NANOS_PER_SECOND;

/// Default session timeout in nanoseconds (5 minutes).
pub const DEFAULT_SESSION_TIMEOUT_NS: u64 = 5 * 60 * NANOS_PER_SECOND;

// ============================================================================
// Size Limits
// ============================================================================

/// Maximum message size for gossip transport (10 MB).
///
/// Prevents DoS attacks via oversized messages. This limit applies to:
/// - Serialized proposals
/// - Serialized signatures
/// - Any other gossip message
pub const MAX_MESSAGE_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of UTXOs/inputs in a single PSKT.
///
/// Kaspa consensus limit for transaction inputs.
pub const MAX_PSKT_INPUTS: usize = 1000;

/// Maximum number of outputs in a single PSKT.
///
/// Kaspa consensus limit for transaction outputs.
pub const MAX_PSKT_OUTPUTS: usize = 1000;

/// Maximum size of event metadata in bytes (10 KB).
///
/// Prevents bloat in event records stored in database.
pub const MAX_EVENT_METADATA_SIZE: usize = 10 * 1024;

/// Maximum length of event ID string.
pub const MAX_EVENT_ID_LENGTH: usize = 256;

/// Maximum length of destination address string.
pub const MAX_ADDRESS_LENGTH: usize = 256;

// ============================================================================
// Cryptographic Constants
// ============================================================================

/// Schnorr signature size in bytes (64 bytes).
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;

/// Schnorr public key size in bytes (32 bytes, x-only).
pub const SCHNORR_PUBKEY_SIZE: usize = 32;

/// Blake3 hash size in bytes (32 bytes).
pub const HASH_SIZE: usize = 32;

/// ECDSA signature size in compact format (64 bytes).
pub const ECDSA_SIGNATURE_SIZE: usize = 64;

/// ECDSA recovery ID size (1 byte).
pub const ECDSA_RECOVERY_ID_SIZE: usize = 1;

// ============================================================================
// Fee Calculation
// ============================================================================

/// Fee calculation precision scale (10^6).
///
/// Allows fee portions to be specified as fractions (e.g., 0.25 = 250,000 / 1,000,000).
/// Using fixed-point arithmetic ensures determinism across platforms.
pub const FEE_PRECISION_SCALE: u64 = 1_000_000;

/// Default fee in sompi (0.001 KAS = 100,000 sompi).
///
/// Typical Kaspa transaction fee for standard-sized transactions.
pub const DEFAULT_FEE_SOMPI: u64 = 100_000;

// ============================================================================
// Network and Gossip
// ============================================================================

/// Maximum number of bootstrap peers for gossip.
///
/// Prevents configuration errors where too many bootstrap peers
/// slow down connection establishment.
pub const MAX_BOOTSTRAP_PEERS: usize = 10;

/// Gossip publish retry attempts.
///
/// Number of times to retry failed gossip publish operations.
pub const GOSSIP_PUBLISH_RETRIES: usize = 3;

/// Delay between gossip publish retries in milliseconds.
pub const GOSSIP_RETRY_DELAY_MS: u64 = 200;

/// Maximum gossip topic length in bytes.
pub const MAX_GOSSIP_TOPIC_LENGTH: usize = 256;

// ============================================================================
// Rate Limiting
// ============================================================================

/// Rate limiter burst capacity (requests).
///
/// Maximum number of requests a peer can make in a burst before being throttled.
pub const RATE_LIMIT_CAPACITY: f64 = 100.0;

/// Rate limiter refill rate (requests per second).
///
/// Steady-state rate at which request quota is replenished.
pub const RATE_LIMIT_REFILL_RATE: f64 = 10.0;

/// Rate limiter cleanup interval in seconds.
///
/// How often to clean up old peer entries from the rate limiter cache.
pub const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

// ============================================================================
// Storage
// ============================================================================

/// RocksDB write batch size (number of operations).
///
/// Batching improves write performance for bulk operations.
pub const ROCKSDB_WRITE_BATCH_SIZE: usize = 100;

/// RocksDB cache size in bytes (128 MB).
pub const ROCKSDB_CACHE_SIZE: usize = 128 * 1024 * 1024;

// ============================================================================
// Threshold Signing
// ============================================================================

/// Maximum threshold N (total signers).
pub const MAX_THRESHOLD_N: u16 = 100;

/// Minimum threshold M (required signatures).
pub const MIN_THRESHOLD_M: u16 = 1;

// ============================================================================
// Test Constants
// ============================================================================

#[cfg(test)]
pub mod test {
    use super::*;

    /// Test session timeout (1 minute).
    pub const TEST_SESSION_TIMEOUT_NS: u64 = 60 * NANOS_PER_SECOND;

    /// Test event amount (1 KAS).
    pub const TEST_EVENT_AMOUNT: u64 = 100_000_000;
}
```

### Step 2: Add to lib.rs

**File**: `igra-core/src/lib.rs`

**Add this line**:
```rust
pub mod constants;
```

**Location**: Alphabetically with other `pub mod` declarations

**Verification**:
```bash
cargo build --package igra-core
```

### Step 3: Replace Magic Numbers - Time Constants

**Search pattern**:
```bash
grep -rn "60 \* 60 \* 1_000_000_000" igra-core/src --include="*.rs"
```

**For EACH occurrence**:
- Add import: `use crate::constants::*;`
- Replace `60 * 60 * 1_000_000_000` with `MAX_SESSION_DURATION_NS`

**Files likely affected**:
- `igra-core/src/coordination/signer.rs`
- Test files

### Step 4: Replace Magic Numbers - Size Limits

**Pattern**: Look for `10 * 1024 * 1024` (10 MB)

**Search**:
```bash
grep -rn "10 \* 1024 \* 1024" igra-core/src --include="*.rs"
```

**Replace with**: `MAX_MESSAGE_SIZE_BYTES`

**Pattern**: Look for `1000` in context of PSKT/inputs/outputs

**Search**:
```bash
grep -rn "\.len() > 1000\|count > 1000" igra-core/src --include="*.rs"
```

**Replace with**: `MAX_PSKT_INPUTS` or `MAX_PSKT_OUTPUTS`

### Step 5: Replace Magic Numbers - Fee Calculation

**Pattern**: Look for `1_000_000` in fee context

**File**: `igra-core/src/pskt/builder.rs`

**Line 70** (find this):
```rust
const FEE_SCALE: u64 = 1_000_000;
```

**Replace with**:
```rust
use crate::constants::FEE_PRECISION_SCALE;
// Then use FEE_PRECISION_SCALE instead of FEE_SCALE
```

### Step 6: Replace Magic Numbers - Crypto Sizes

**Pattern**: Look for `64` in signature context

**Search**:
```bash
grep -rn "signature.*64\|64.*signature" igra-core/src --include="*.rs"
```

**For EACH occurrence**:
- Replace `64` with `SCHNORR_SIGNATURE_SIZE` or `ECDSA_SIGNATURE_SIZE` (context-dependent)

**Pattern**: Look for `32` in hash/pubkey context

**Search**:
```bash
grep -rn "Hash32\|hash.*32\|32.*hash" igra-core/src --include="*.rs" | grep "= 32"
```

**Replace with**: `HASH_SIZE` or `SCHNORR_PUBKEY_SIZE`

### Step 7: Replace Magic Numbers - Rate Limiting

**File**: `igra-core/src/rate_limit.rs`

**Find**:
```rust
capacity: 100.0
refill_rate: 10.0
```

**Replace with**:
```rust
use crate::constants::{RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_RATE};

// Then use the constants
capacity: RATE_LIMIT_CAPACITY
refill_rate: RATE_LIMIT_REFILL_RATE
```

### Verification

```bash
# Build
cargo build --package igra-core

# Test
cargo test --package igra-core

# Check imports (should see many files importing constants)
grep -rn "use crate::constants" igra-core/src --include="*.rs" | wc -l
```

**Expected**: At least 5-10 files now import constants

---

## Final Checklist

After completing ALL refactorings:

```bash
# 1. Clean build
cargo clean
cargo build --package igra-core --package igra-service

# 2. All tests pass
cargo test --package igra-core --package igra-service

# 3. Clippy happy
cargo clippy --package igra-core --package igra-service -- -D warnings

# 4. Format check
cargo fmt --check

# 5. Measure improvements
echo "=== Code Quality Metrics ==="
echo "Total lines:"
find igra-core/src -name "*.rs" -exec wc -l {} + | tail -1

echo "map_err boilerplate remaining:"
grep -rn "\.map_err(|err| ThresholdError::Message" igra-core/src --include="*.rs" | wc -l

echo "Generic Message errors:"
grep -rn "ThresholdError::Message" igra-core/src --include="*.rs" | wc -l

echo "Magic numbers (rough estimate):"
grep -rn "[0-9]\+ \* [0-9]\+ \* [0-9]" igra-core/src --include="*.rs" | wc -l
```

---

## Reporting

After completing refactorings, create a summary:

**File**: `REFACTORING-COMPLETED.md`

**Template**:
```markdown
# Refactoring Completion Report

**Date**: [YYYY-MM-DD]
**Completed by**: [Your Name]

## Completed Refactorings

- [ ] REFACTOR-001: Timestamp utilities (ALREADY DONE)
- [ ] REFACTOR-002: Error From traits
- [ ] REFACTOR-003: Hex encoding (ALREADY DONE)
- [ ] REFACTOR-004: Type conversions (ALREADY DONE)
- [ ] REFACTOR-005: Storage key builder
- [ ] REFACTOR-011: Specific error variants
- [ ] REFACTOR-012: Result type alias
- [ ] REFACTOR-013: Builder pattern
- [ ] REFACTOR-023: Constants extraction

## Metrics

### Before
- Total lines: [X]
- map_err boilerplate: [~100]
- Generic errors: [~150]

### After
- Total lines: [X]
- map_err boilerplate: [<50]
- Generic errors: [<100]

### Improvements
- Lines removed: [X]
- Boilerplate reduced: [X%]
- Specific error types added: [25]

## Issues Encountered

[List any problems, unexpected changes, or deviations from the plan]

## Next Steps

[What should be done next, if anything]
```

---

**END OF DETAILED REFACTORING GUIDE**
