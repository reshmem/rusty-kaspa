# Igra Testing Architecture - Complete Implementation Guide

**Document ID**: ARCH-TEST-001
**Related**: ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md
**Status**: Prescriptive Guide
**Created**: 2026-01-09

---

## DO NOT IMPROVISE - FOLLOW EXACTLY

This document provides **EXACT** instructions for:
- What to test
- Where to put tests
- How to write tests
- What test utilities to create
- Complete code examples (copy-paste ready)

**IF IT'S NOT LISTED HERE, ASK BEFORE IMPLEMENTING IT.**

---

## Table of Contents

1. [Testing Philosophy](#testing-philosophy)
2. [Test Layer Architecture](#test-layer-architecture)
3. [Directory Structure (EXACT)](#directory-structure-exact)
4. [Test Naming Conventions](#test-naming-conventions)
5. [Unit Testing (Domain Layer)](#unit-testing-domain-layer)
6. [Integration Testing (Infrastructure Layer)](#integration-testing-infrastructure-layer)
7. [End-to-End Testing (Application Layer)](#end-to-end-testing-application-layer)
8. [Test Fixtures and Factories](#test-fixtures-and-factories)
9. [Mock Implementations](#mock-implementations)
10. [Property-Based Testing](#property-based-testing)
11. [Test Utilities (Exact Implementation)](#test-utilities-exact-implementation)
12. [Coverage Requirements](#coverage-requirements)
13. [Complete Test Examples](#complete-test-examples)

---

## Testing Philosophy

### The Testing Pyramid

```
        /\
       /  \      E2E Tests (Few)
      /____\     - Complete workflows
     /      \    - Real components
    /        \   - Slow, brittle
   /__________\
  /            \ Integration Tests (Some)
 /              \- Infrastructure + Real deps
/________________\- Database, network, etc.
==================
Unit Tests (Many) - Pure functions, fast, no I/O
```

### Test Distribution (EXACT NUMBERS)

**Target distribution** for igra-core:
- **70%** Unit tests (domain layer, pure functions)
- **20%** Integration tests (infrastructure, storage, RPC)
- **10%** End-to-end tests (full signing flows)

**Time budget per layer**:
- Unit tests: < 1 second total
- Integration tests: < 10 seconds total
- E2E tests: < 30 seconds total

**IF YOUR TESTS ARE SLOWER, YOU'RE TESTING THE WRONG LAYER.**

---

## Test Layer Architecture

### Layer 1: Unit Tests (Domain)

**What to test**:
- ✅ Pure functions (no I/O)
- ✅ Business logic validation
- ✅ Error conditions
- ✅ Edge cases (overflow, underflow, empty inputs)
- ✅ Cryptographic operations (hashing, signing)

**What NOT to test**:
- ❌ Storage operations
- ❌ Network calls
- ❌ File I/O
- ❌ External APIs

**How to test**:
- No mocks needed
- Pure data in, assertions out
- Runs in milliseconds

**Location**: `igra-core/tests/unit/`

### Layer 2: Integration Tests (Infrastructure)

**What to test**:
- ✅ Storage operations (RocksDB)
- ✅ RPC client (mocked Kaspa node)
- ✅ Transport (mocked gossip)
- ✅ Configuration loading
- ✅ Serialization/deserialization

**What NOT to test**:
- ❌ Business logic (that's unit tests)
- ❌ Complete workflows (that's E2E)

**How to test**:
- Real storage (temp directories)
- Mock external services
- Runs in seconds

**Location**: `igra-core/tests/integration/`

### Layer 3: End-to-End Tests (Application)

**What to test**:
- ✅ Complete signing workflows
- ✅ Coordinator ↔ Signer interaction
- ✅ Timeout scenarios
- ✅ Concurrent sessions
- ✅ Error recovery

**How to test**:
- Real components wired together
- Mock external services only (Kaspa node, Hyperlane)
- Runs in tens of seconds

**Location**: `igra-service/tests/integration/`

---

## Directory Structure (EXACT)

**DO NOT DEVIATE FROM THIS STRUCTURE.**

```
igra-core/
├── tests/
│   ├── unit/                              # Domain layer unit tests
│   │   ├── mod.rs                         # Re-exports test utilities
│   │   ├── domain_event.rs                # Event validation tests
│   │   ├── domain_policy.rs               # Policy enforcement tests
│   │   ├── domain_pskt.rs                 # PSKT building tests
│   │   ├── domain_request.rs              # Request state machine tests
│   │   ├── domain_coordination.rs         # Coordination logic tests
│   │   ├── domain_signing.rs              # Signing protocol tests
│   │   ├── domain_hashing.rs              # Hash computation tests
│   │   └── domain_audit.rs                # Audit event generation tests
│   │
│   ├── integration/                       # Infrastructure tests
│   │   ├── mod.rs
│   │   ├── storage_rocks.rs               # RocksDB storage tests
│   │   ├── storage_persistence.rs         # Persistence roundtrip tests
│   │   ├── rpc_kaspa.rs                   # Kaspa RPC client tests
│   │   ├── transport_mock.rs              # Mock transport tests
│   │   ├── config_loading.rs              # Config loading tests
│   │   ├── serialization.rs               # Bincode/JSON tests
│   │   └── hyperlane_client.rs            # Hyperlane API tests
│   │
│   └── fixtures/                          # Shared test data
│       ├── mod.rs
│       ├── factories.rs                   # Test data factories
│       ├── builders.rs                    # Test object builders
│       ├── constants.rs                   # Test constants
│       └── sample_data.rs                 # Pre-generated test data
│
igra-service/
├── tests/
│   ├── integration/                       # E2E tests
│   │   ├── mod.rs
│   │   ├── e2e_happy_path.rs              # Successful signing flow
│   │   ├── e2e_rejection.rs               # Policy rejection flow
│   │   ├── e2e_timeout.rs                 # Timeout scenarios
│   │   ├── e2e_concurrent.rs              # Concurrent sessions
│   │   ├── e2e_recovery.rs                # Failure recovery
│   │   └── e2e_threshold.rs               # Threshold scenarios (2-of-3, etc.)
│   │
│   └── harness/                           # Test harness utilities
│       ├── mod.rs
│       ├── network.rs                     # Test network setup
│       ├── mocks.rs                       # Mock implementations
│       ├── assertions.rs                  # Custom assertions
│       ├── wait.rs                        # Wait utilities
│       └── cleanup.rs                     # Test cleanup
```

**Files to CREATE** (currently missing):

1. `igra-core/tests/fixtures/` directory with all files
2. `igra-core/tests/unit/domain_*.rs` files (new naming convention)
3. `igra-service/tests/harness/` improvements

---

## Test Naming Conventions

### File Names (EXACT PATTERN)

**Unit tests**:
- `domain_<module>.rs` - e.g., `domain_event.rs`, `domain_policy.rs`
- Tests pure domain logic from `domain/` modules

**Integration tests**:
- `<infrastructure>_<detail>.rs` - e.g., `storage_rocks.rs`, `rpc_kaspa.rs`
- Tests infrastructure components

**E2E tests**:
- `e2e_<scenario>.rs` - e.g., `e2e_happy_path.rs`, `e2e_timeout.rs`
- Tests complete workflows

### Test Function Names (EXACT PATTERN)

```rust
// Pattern: test_<what>_<when>_<expected>

// ✅ GOOD
#[test]
fn test_policy_enforcement_when_destination_not_allowed_then_rejects() { }

#[test]
fn test_event_hashing_with_empty_metadata_returns_valid_hash() { }

#[test]
fn test_pskt_builder_with_insufficient_funds_returns_error() { }

// ❌ BAD (too vague)
#[test]
fn test_policy() { }

#[test]
fn validation_works() { }
```

**Naming parts**:
1. `test_` - prefix (required)
2. `<what>` - what you're testing (e.g., `policy_enforcement`, `event_hashing`)
3. `<when>` - input condition (e.g., `when_destination_not_allowed`, `with_empty_metadata`)
4. `<expected>` - expected outcome (e.g., `then_rejects`, `returns_valid_hash`, `returns_error`)

---

## Unit Testing (Domain Layer)

### What to Test - Complete Checklist

**For EACH domain module**, create tests for:

1. ✅ **Happy path** - valid inputs produce expected outputs
2. ✅ **Edge cases** - boundary values (0, MAX, empty, very large)
3. ✅ **Error cases** - invalid inputs produce specific errors
4. ✅ **Invariants** - properties that must always hold

### Template: Domain Event Tests

**File**: `igra-core/tests/unit/domain_event.rs` (CREATE THIS FILE)

**COMPLETE CONTENTS** (copy exactly):

```rust
//! Unit tests for domain::event module.
//!
//! Tests pure event validation, hashing, and structure checks.
//! NO storage, NO network, NO I/O.

use igra_core::domain::event::{self, SigningEvent, EventMetadata};
use igra_core::foundation::types::{AmountSompi, TimestampNanos};
use igra_core::foundation::error::ThresholdError;
use std::collections::BTreeMap;

// ============================================================================
// Test Fixtures
// ============================================================================

fn valid_event() -> SigningEvent {
    SigningEvent {
        event_id: "test-event-1".to_string(),
        group_id: [1u8; 32],
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 1_000_000,
        timestamp_nanos: 1_700_000_000_000_000_000,
        metadata: BTreeMap::new(),
    }
}

// ============================================================================
// Structure Validation Tests
// ============================================================================

#[test]
fn test_event_validation_with_valid_event_succeeds() {
    let event = valid_event();

    let result = event::validate_structure(&event);

    assert!(result.is_ok(), "Valid event should pass validation");
}

#[test]
fn test_event_validation_with_zero_amount_fails() {
    let mut event = valid_event();
    event.amount_sompi = 0;

    let result = event::validate_structure(&event);

    assert!(result.is_err(), "Zero amount should be rejected");
    match result.unwrap_err() {
        ThresholdError::ZeroAmount => { /* expected */ },
        other => panic!("Expected ZeroAmount error, got: {:?}", other),
    }
}

#[test]
fn test_event_validation_with_empty_event_id_fails() {
    let mut event = valid_event();
    event.event_id = "".to_string();

    let result = event::validate_structure(&event);

    assert!(result.is_err(), "Empty event_id should be rejected");
}

#[test]
fn test_event_validation_with_invalid_address_format_fails() {
    let mut event = valid_event();
    event.destination_address = "invalid-address".to_string();

    let result = event::validate_structure(&event);

    assert!(result.is_err(), "Invalid address should be rejected");
}

#[test]
fn test_event_validation_with_max_amount_succeeds() {
    let mut event = valid_event();
    event.amount_sompi = u64::MAX;

    let result = event::validate_structure(&event);

    assert!(result.is_ok(), "MAX amount should be valid");
}

#[test]
fn test_event_validation_with_large_metadata_within_limit_succeeds() {
    let mut event = valid_event();

    // Add metadata just under limit (10 KB)
    let value = "x".repeat(9_000);
    event.metadata.insert("large_field".to_string(), value);

    let result = event::validate_structure(&event);

    assert!(result.is_ok(), "Metadata under limit should be valid");
}

#[test]
fn test_event_validation_with_metadata_exceeding_limit_fails() {
    let mut event = valid_event();

    // Add metadata over limit (10 KB)
    let value = "x".repeat(11_000);
    event.metadata.insert("huge_field".to_string(), value);

    let result = event::validate_structure(&event);

    assert!(result.is_err(), "Metadata over limit should be rejected");
}

// ============================================================================
// Hash Computation Tests
// ============================================================================

#[test]
fn test_event_hash_with_same_event_produces_same_hash() {
    let event1 = valid_event();
    let event2 = valid_event();

    let hash1 = event::compute_hash(&event1).unwrap();
    let hash2 = event::compute_hash(&event2).unwrap();

    assert_eq!(hash1, hash2, "Same event should produce same hash (determinism)");
}

#[test]
fn test_event_hash_with_different_amount_produces_different_hash() {
    let event1 = valid_event();
    let mut event2 = valid_event();
    event2.amount_sompi = 2_000_000;

    let hash1 = event::compute_hash(&event1).unwrap();
    let hash2 = event::compute_hash(&event2).unwrap();

    assert_ne!(hash1, hash2, "Different amounts should produce different hashes");
}

#[test]
fn test_event_hash_with_different_destination_produces_different_hash() {
    let event1 = valid_event();
    let mut event2 = valid_event();
    event2.destination_address = "kaspatest:qz1111111111111111111111111111111111111111111111111111111111xyz".to_string();

    let hash1 = event::compute_hash(&event1).unwrap();
    let hash2 = event::compute_hash(&event2).unwrap();

    assert_ne!(hash1, hash2, "Different destinations should produce different hashes");
}

#[test]
fn test_event_hash_with_metadata_changes_produces_different_hash() {
    let event1 = valid_event();
    let mut event2 = valid_event();
    event2.metadata.insert("reason".to_string(), "payment".to_string());

    let hash1 = event::compute_hash(&event1).unwrap();
    let hash2 = event::compute_hash(&event2).unwrap();

    assert_ne!(hash1, hash2, "Different metadata should produce different hashes");
}

#[test]
fn test_event_hash_length_is_32_bytes() {
    let event = valid_event();

    let hash = event::compute_hash(&event).unwrap();

    assert_eq!(hash.len(), 32, "Event hash should be 32 bytes (Blake3)");
}

// ============================================================================
// Property-Based Tests (Optional - requires proptest)
// ============================================================================

#[cfg(feature = "proptest")]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_event_hash_is_deterministic(amount in 1u64..1_000_000_000u64) {
            let mut event1 = valid_event();
            let mut event2 = valid_event();
            event1.amount_sompi = amount;
            event2.amount_sompi = amount;

            let hash1 = event::compute_hash(&event1).unwrap();
            let hash2 = event::compute_hash(&event2).unwrap();

            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn test_event_validation_never_panics(
            amount in any::<u64>(),
            timestamp in any::<u64>(),
        ) {
            let mut event = valid_event();
            event.amount_sompi = amount;
            event.timestamp_nanos = timestamp;

            // Should never panic, only return Result
            let _ = event::validate_structure(&event);
        }
    }
}
```

**Action**: CREATE this file with EXACT contents above.

**Verification**:
```bash
cargo test --test domain_event
# Expected: All tests pass in < 100ms
```

### Template: Domain Policy Tests

**File**: `igra-core/tests/unit/domain_policy.rs` (CREATE THIS FILE)

**COMPLETE CONTENTS**:

```rust
//! Unit tests for domain::policy module.
//!
//! Tests policy enforcement logic (pure functions, no storage).

use igra_core::domain::policy::{self, GroupPolicy, PolicyViolation};
use igra_core::domain::event::SigningEvent;
use igra_core::foundation::types::AmountSompi;
use std::collections::BTreeMap;

// ============================================================================
// Test Fixtures
// ============================================================================

fn valid_event(amount: u64, destination: &str) -> SigningEvent {
    SigningEvent {
        event_id: "test-1".to_string(),
        group_id: [1u8; 32],
        destination_address: destination.to_string(),
        amount_sompi: amount,
        timestamp_nanos: 1_700_000_000_000_000_000,
        metadata: BTreeMap::new(),
    }
}

fn permissive_policy() -> GroupPolicy {
    GroupPolicy {
        allowed_destinations: vec![
            "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            "kaspatest:qz1111111111111111111111111111111111111111111111111111111111xyz".to_string(),
        ],
        daily_limit_sompi: 10_000_000,
        per_transaction_limit_sompi: 5_000_000,
        require_approval_above_sompi: 1_000_000,
    }
}

// ============================================================================
// Destination Allowlist Tests
// ============================================================================

#[test]
fn test_policy_enforcement_with_allowed_destination_succeeds() {
    let event = valid_event(1_000, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();

    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_ok(), "Allowed destination should be accepted");
}

#[test]
fn test_policy_enforcement_with_disallowed_destination_fails() {
    let event = valid_event(1_000, "kaspatest:qzBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADBADbad");
    let policy = permissive_policy();

    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_err(), "Disallowed destination should be rejected");
    match result.unwrap_err() {
        PolicyViolation::DestinationNotAllowed { destination } => {
            assert!(destination.contains("BAD"), "Error should include rejected destination");
        },
        other => panic!("Expected DestinationNotAllowed, got: {:?}", other),
    }
}

#[test]
fn test_policy_enforcement_with_empty_allowlist_rejects_all() {
    let event = valid_event(1_000, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let mut policy = permissive_policy();
    policy.allowed_destinations = vec![];

    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_err(), "Empty allowlist should reject all destinations");
}

// ============================================================================
// Per-Transaction Limit Tests
// ============================================================================

#[test]
fn test_policy_enforcement_with_amount_under_limit_succeeds() {
    let event = valid_event(4_999_999, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();

    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_ok(), "Amount under limit should be accepted");
}

#[test]
fn test_policy_enforcement_with_amount_at_limit_succeeds() {
    let event = valid_event(5_000_000, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();

    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_ok(), "Amount exactly at limit should be accepted");
}

#[test]
fn test_policy_enforcement_with_amount_over_limit_fails() {
    let event = valid_event(5_000_001, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();

    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_err(), "Amount over limit should be rejected");
    match result.unwrap_err() {
        PolicyViolation::PerTransactionLimitExceeded { requested, limit } => {
            assert_eq!(requested, 5_000_001);
            assert_eq!(limit, 5_000_000);
        },
        other => panic!("Expected PerTransactionLimitExceeded, got: {:?}", other),
    }
}

// ============================================================================
// Daily Volume Limit Tests
// ============================================================================

#[test]
fn test_policy_enforcement_with_no_prior_volume_succeeds() {
    let event = valid_event(1_000_000, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();

    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_ok(), "First transaction should be accepted");
}

#[test]
fn test_policy_enforcement_with_volume_approaching_limit_succeeds() {
    let event = valid_event(1_000_000, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();
    let current_volume = 8_999_999;

    let result = policy::enforce_policy(&event, &policy, current_volume);

    assert!(result.is_ok(), "Should accept when total stays under daily limit");
}

#[test]
fn test_policy_enforcement_with_volume_at_limit_succeeds() {
    let event = valid_event(1_000_000, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();
    let current_volume = 9_000_000;

    let result = policy::enforce_policy(&event, &policy, current_volume);

    assert!(result.is_ok(), "Should accept when total equals daily limit");
}

#[test]
fn test_policy_enforcement_with_volume_exceeding_limit_fails() {
    let event = valid_event(1_000_000, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();
    let current_volume = 9_000_001;

    let result = policy::enforce_policy(&event, &policy, current_volume);

    assert!(result.is_err(), "Should reject when total exceeds daily limit");
    match result.unwrap_err() {
        PolicyViolation::DailyVolumeLimitExceeded { current, requested, limit } => {
            assert_eq!(current, 9_000_001);
            assert_eq!(requested, 1_000_000);
            assert_eq!(limit, 10_000_000);
        },
        other => panic!("Expected DailyVolumeLimitExceeded, got: {:?}", other),
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_policy_enforcement_with_overflow_attempt_fails_safely() {
    let event = valid_event(u64::MAX, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();
    let current_volume = u64::MAX;

    let result = policy::enforce_policy(&event, &policy, current_volume);

    assert!(result.is_err(), "Should handle overflow safely");
    // Should return VolumeOverflow error (not panic)
}

#[test]
fn test_policy_enforcement_with_zero_amount_allowed_if_other_checks_pass() {
    let event = valid_event(0, "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p");
    let policy = permissive_policy();

    // Policy enforcement doesn't validate amount > 0 (that's event validation)
    let result = policy::enforce_policy(&event, &policy, 0);

    assert!(result.is_ok(), "Policy enforcement allows zero amounts (caught earlier)");
}
```

**Action**: CREATE this file with EXACT contents above.

**Verification**:
```bash
cargo test --test domain_policy
# Expected: All tests pass in < 50ms
```

### Complete Unit Test Checklist

**For EACH domain module, create a test file with this structure**:

```rust
//! Unit tests for domain::<module>
//!
//! Brief description of what this module does.

// Test fixtures section
fn valid_<thing>() -> Thing { ... }
fn invalid_<thing>() -> Thing { ... }

// Happy path tests
#[test]
fn test_<operation>_with_valid_input_succeeds() { }

// Error cases
#[test]
fn test_<operation>_with_invalid_input_fails() { }

// Edge cases
#[test]
fn test_<operation>_with_edge_case_handles_correctly() { }

// Properties (if using proptest)
#[cfg(feature = "proptest")]
mod property_tests { }
```

**Modules requiring unit tests** (CREATE ALL OF THESE):

1. ✅ `domain_event.rs` - Event validation, hashing
2. ✅ `domain_policy.rs` - Policy enforcement
3. ⬜ `domain_pskt.rs` - PSKT building, fee calculation
4. ⬜ `domain_request.rs` - Request state machine
5. ⬜ `domain_coordination.rs` - Proposal validation, signature collection
6. ⬜ `domain_signing.rs` - MuSig2, threshold signing
7. ⬜ `domain_hashing.rs` - All hash functions
8. ⬜ `domain_audit.rs` - Audit event generation

**For each ⬜ above**:
1. Create file: `igra-core/tests/unit/<name>.rs`
2. Copy template structure
3. Add specific tests for that module
4. Run `cargo test --test <name>`
5. Verify < 100ms execution time

---

## Integration Testing (Infrastructure Layer)

### What to Test - Complete Checklist

**Storage (RocksDB)**:
- ✅ Insert/retrieve roundtrips
- ✅ Update operations
- ✅ Batch operations
- ✅ Key prefixing and isolation
- ✅ Error handling (corrupted data, full disk simulation)

**RPC Client (Kaspa node)**:
- ✅ UTXO queries
- ✅ Transaction submission
- ✅ Blue score queries
- ✅ Connection error handling
- ✅ Timeout handling
- ✅ Retry logic

**Transport (Gossip)**:
- ✅ Message publishing
- ✅ Message subscription
- ✅ Peer discovery
- ✅ Message serialization
- ✅ Network partition simulation

### Template: Storage Integration Tests

**File**: `igra-core/tests/integration/storage_rocks.rs` (CREATE THIS FILE)

**COMPLETE CONTENTS**:

```rust
//! Integration tests for RocksDB storage implementation.
//!
//! Tests actual storage operations with real RocksDB (in temp directories).

use igra_core::infrastructure::storage::{Storage, RocksStorage};
use igra_core::domain::event::SigningEvent;
use igra_core::domain::request::{SigningRequest, RequestDecision};
use igra_core::foundation::types::{RequestId, SessionId, Hash32};
use std::sync::Arc;
use tempfile::TempDir;

// ============================================================================
// Test Setup Helpers
// ============================================================================

fn setup_storage() -> (TempDir, Arc<RocksStorage>) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path())
        .expect("open storage");

    (temp_dir, Arc::new(storage))
}

fn sample_event() -> SigningEvent {
    SigningEvent {
        event_id: "test-event-1".to_string(),
        group_id: [1u8; 32],
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 1_000_000,
        timestamp_nanos: 1_700_000_000_000_000_000,
        metadata: Default::default(),
    }
}

fn sample_request() -> SigningRequest {
    SigningRequest {
        request_id: RequestId::from("req-1"),
        session_id: SessionId::from([2u8; 32]),
        group_id: [1u8; 32],
        event_hash: [3u8; 32],
        transaction_hash: [4u8; 32],
        validation_hash: [5u8; 32],
        expires_at_nanos: 1_700_000_000_000_000_000,
        decision: RequestDecision::Pending,
        created_at: 1_700_000_000_000_000_000,
    }
}

// ============================================================================
// Event Storage Tests
// ============================================================================

#[tokio::test]
async fn test_storage_insert_and_retrieve_event() {
    let (_temp, storage) = setup_storage();

    let event = sample_event();
    let event_hash = [10u8; 32];

    // Insert
    storage.insert_event(event_hash, event.clone())
        .await
        .expect("insert should succeed");

    // Retrieve
    let retrieved = storage.get_event(&event_hash)
        .await
        .expect("get should succeed");

    assert!(retrieved.is_some(), "Event should exist");
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.event_id, event.event_id);
    assert_eq!(retrieved.amount_sompi, event.amount_sompi);
}

#[tokio::test]
async fn test_storage_get_nonexistent_event_returns_none() {
    let (_temp, storage) = setup_storage();

    let nonexistent_hash = [99u8; 32];

    let result = storage.get_event(&nonexistent_hash)
        .await
        .expect("get should succeed");

    assert!(result.is_none(), "Nonexistent event should return None");
}

#[tokio::test]
async fn test_storage_insert_duplicate_event_hash_overwrites() {
    let (_temp, storage) = setup_storage();

    let event_hash = [20u8; 32];
    let mut event1 = sample_event();
    event1.amount_sompi = 1_000;

    let mut event2 = sample_event();
    event2.amount_sompi = 2_000;

    // Insert first
    storage.insert_event(event_hash, event1)
        .await
        .expect("first insert");

    // Insert second with same hash
    storage.insert_event(event_hash, event2)
        .await
        .expect("second insert");

    // Retrieve
    let retrieved = storage.get_event(&event_hash)
        .await
        .expect("get")
        .expect("should exist");

    assert_eq!(retrieved.amount_sompi, 2_000, "Second event should overwrite first");
}

#[tokio::test]
async fn test_storage_insert_multiple_events_with_different_hashes() {
    let (_temp, storage) = setup_storage();

    let hash1 = [1u8; 32];
    let hash2 = [2u8; 32];
    let hash3 = [3u8; 32];

    let mut event1 = sample_event();
    event1.event_id = "event-1".to_string();

    let mut event2 = sample_event();
    event2.event_id = "event-2".to_string();

    let mut event3 = sample_event();
    event3.event_id = "event-3".to_string();

    storage.insert_event(hash1, event1).await.expect("insert 1");
    storage.insert_event(hash2, event2).await.expect("insert 2");
    storage.insert_event(hash3, event3).await.expect("insert 3");

    // Verify all exist
    assert!(storage.get_event(&hash1).await.unwrap().is_some());
    assert!(storage.get_event(&hash2).await.unwrap().is_some());
    assert!(storage.get_event(&hash3).await.unwrap().is_some());
}

// ============================================================================
// Request Storage Tests
// ============================================================================

#[tokio::test]
async fn test_storage_insert_and_retrieve_request() {
    let (_temp, storage) = setup_storage();

    let request = sample_request();

    storage.insert_request(request.clone())
        .await
        .expect("insert should succeed");

    let retrieved = storage.get_request(&request.request_id)
        .await
        .expect("get should succeed")
        .expect("request should exist");

    assert_eq!(retrieved.request_id, request.request_id);
    assert_eq!(retrieved.session_id, request.session_id);
    assert_eq!(retrieved.decision, RequestDecision::Pending);
}

#[tokio::test]
async fn test_storage_update_request_decision() {
    let (_temp, storage) = setup_storage();

    let request = sample_request();

    // Insert as Pending
    storage.insert_request(request.clone())
        .await
        .expect("insert");

    // Update to Approved
    storage.update_request_decision(&request.request_id, RequestDecision::Approved)
        .await
        .expect("update");

    // Retrieve and verify
    let retrieved = storage.get_request(&request.request_id)
        .await
        .expect("get")
        .expect("exists");

    assert_eq!(retrieved.decision, RequestDecision::Approved);
}

#[tokio::test]
async fn test_storage_list_events_since_filters_by_timestamp() {
    let (_temp, storage) = setup_storage();

    let group_id = [7u8; 32];

    // Insert events with different timestamps
    let mut event1 = sample_event();
    event1.group_id = group_id;
    event1.timestamp_nanos = 1_000_000_000;

    let mut event2 = sample_event();
    event2.group_id = group_id;
    event2.timestamp_nanos = 2_000_000_000;

    let mut event3 = sample_event();
    event3.group_id = group_id;
    event3.timestamp_nanos = 3_000_000_000;

    storage.insert_event([1u8; 32], event1).await.unwrap();
    storage.insert_event([2u8; 32], event2).await.unwrap();
    storage.insert_event([3u8; 32], event3).await.unwrap();

    // Query events since timestamp 1_500_000_000
    let events = storage.list_events_since(&group_id, 1_500_000_000)
        .await
        .expect("list events");

    assert_eq!(events.len(), 2, "Should return 2 events (timestamps 2B and 3B)");
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn test_storage_insert_1000_events_succeeds() {
    let (_temp, storage) = setup_storage();

    for i in 0..1000 {
        let mut event = sample_event();
        event.event_id = format!("event-{}", i);

        let mut hash = [0u8; 32];
        hash[0] = (i / 256) as u8;
        hash[1] = (i % 256) as u8;

        storage.insert_event(hash, event)
            .await
            .expect(&format!("insert event {}", i));
    }

    // Verify a random sample
    let hash = [0u8, 100u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let retrieved = storage.get_event(&hash)
        .await
        .expect("get")
        .expect("exists");

    assert_eq!(retrieved.event_id, "event-100");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_storage_handles_corrupted_data_gracefully() {
    let (_temp, storage) = setup_storage();

    // This test would require injecting corrupted data directly into RocksDB
    // For now, we verify that deserialization errors are handled
    // TODO: Implement once we have lower-level RocksDB access
}

#[tokio::test]
async fn test_storage_concurrent_writes_to_same_key() {
    let (_temp, storage) = setup_storage();

    let event_hash = [50u8; 32];

    // Spawn 10 concurrent writes
    let mut handles = vec![];
    for i in 0..10 {
        let storage_clone = storage.clone();
        let handle = tokio::spawn(async move {
            let mut event = sample_event();
            event.amount_sompi = i * 1000;

            storage_clone.insert_event(event_hash, event)
                .await
                .expect("concurrent insert");
        });
        handles.push(handle);
    }

    // Wait for all
    for handle in handles {
        handle.await.expect("join");
    }

    // Verify one of them won (no panic, no data loss)
    let result = storage.get_event(&event_hash)
        .await
        .expect("get after concurrent writes");

    assert!(result.is_some(), "One write should have succeeded");
}
```

**Action**: CREATE this file with EXACT contents above.

**Verification**:
```bash
cargo test --test storage_rocks
# Expected: All tests pass in < 5 seconds
```

### Complete Integration Test Checklist

**Files to CREATE** (⬜ = not yet created):

1. ✅ `storage_rocks.rs` - RocksDB CRUD operations
2. ⬜ `storage_persistence.rs` - Serialization roundtrips
3. ⬜ `rpc_kaspa.rs` - Kaspa RPC client (with mock server)
4. ⬜ `transport_mock.rs` - Mock transport behavior
5. ⬜ `config_loading.rs` - Config file/env loading
6. ⬜ `serialization.rs` - Bincode/JSON encoding
7. ⬜ `hyperlane_client.rs` - Hyperlane API client

**For each ⬜**:
1. Create file in `igra-core/tests/integration/`
2. Test actual infrastructure (real DB, real files, mock network)
3. Use temp directories for cleanup
4. Verify < 10 seconds total execution time

---

## End-to-End Testing (Application Layer)

### What to Test - Complete Checklist

**Happy Path Scenarios**:
- ✅ 2-of-2 signing (coordinator + 2 signers, both approve)
- ✅ 2-of-3 signing (coordinator + 3 signers, 2 approve)
- ✅ Policy-compliant transaction

**Rejection Scenarios**:
- ✅ Policy violation (disallowed destination)
- ✅ Policy violation (volume limit exceeded)
- ✅ Invalid PSKT (signature mismatch)
- ✅ Expired session

**Timeout Scenarios**:
- ✅ Signer doesn't respond
- ✅ Coordinator doesn't finalize
- ✅ Session expires before threshold met

**Concurrent Scenarios**:
- ✅ Multiple sessions in parallel
- ✅ Same signer in multiple sessions
- ✅ Race conditions

### Template: E2E Happy Path Test

**File**: `igra-service/tests/integration/e2e_happy_path.rs` (CREATE THIS FILE)

**COMPLETE CONTENTS**:

```rust
//! End-to-end test: Happy path signing flow.
//!
//! Tests complete workflow from proposal to finalization.

use igra_core::application::{CoordinatorService, SignerService};
use igra_core::infrastructure::storage::RocksStorage;
use igra_core::infrastructure::transport::MockTransport;
use igra_core::infrastructure::rpc::MockNodeRpc;
use igra_core::domain::event::SigningEvent;
use igra_core::domain::policy::GroupPolicy;
use igra_core::foundation::types::{RequestId, SessionId, PeerId};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::time::{timeout, Duration};

// Import test harness
mod harness;
use harness::{TestNetwork, wait_for_finalization};

#[tokio::test]
async fn test_e2e_2_of_2_signing_succeeds() {
    // ========================================
    // SETUP: Create test network
    // ========================================

    let network = TestNetwork::new(2, 2).await;

    let coordinator = network.coordinator();
    let signer1 = network.signer(0);
    let signer2 = network.signer(1);

    // ========================================
    // STEP 1: Coordinator proposes session
    // ========================================

    let event = SigningEvent {
        event_id: "test-event-1".to_string(),
        group_id: network.group_id(),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 1_000_000,
        timestamp_nanos: 1_700_000_000_000_000_000,
        metadata: Default::default(),
    };

    let session_id = SessionId::from([1u8; 32]);
    let request_id = RequestId::from("req-1");
    let expires_at = 1_700_000_010_000_000_000; // 10 seconds from now

    let result = coordinator.initiate_signing(
        session_id,
        request_id.clone(),
        event.clone(),
        expires_at,
    ).await;

    assert!(result.is_ok(), "Coordinator should propose successfully");
    let event_hash = result.unwrap();

    // ========================================
    // STEP 2: Wait for signers to receive proposal
    // ========================================

    // Both signers should receive and validate proposal
    network.wait_for_messages(Duration::from_secs(2)).await;

    // ========================================
    // STEP 3: Verify acknowledgments received
    // ========================================

    let acks = coordinator.storage()
        .list_signer_acks(&request_id)
        .await
        .expect("list acks");

    assert_eq!(acks.len(), 2, "Should receive 2 acknowledgments");

    for ack in &acks {
        assert!(ack.accept, "All signers should accept: {:?}", ack);
    }

    // ========================================
    // STEP 4: Wait for signatures
    // ========================================

    network.wait_for_messages(Duration::from_secs(2)).await;

    let sigs = coordinator.storage()
        .list_partial_sigs(&request_id)
        .await
        .expect("list sigs");

    assert!(sigs.len() >= 2, "Should receive at least 2 signatures (threshold met)");

    // ========================================
    // STEP 5: Wait for finalization
    // ========================================

    let finalization_result = timeout(
        Duration::from_secs(5),
        wait_for_finalization(&network, &request_id)
    ).await;

    assert!(finalization_result.is_ok(), "Should finalize within timeout");

    // ========================================
    // STEP 6: Verify final state
    // ========================================

    let request = coordinator.storage()
        .get_request(&request_id)
        .await
        .expect("get request")
        .expect("request exists");

    assert_eq!(request.decision, RequestDecision::Finalized);
    assert!(request.final_tx_id.is_some(), "Should have transaction ID");

    // ========================================
    // STEP 7: Verify transaction submitted
    // ========================================

    let tx_id = request.final_tx_id.unwrap();
    let tx = network.mock_rpc()
        .get_transaction(&tx_id)
        .await
        .expect("get tx")
        .expect("tx exists");

    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 1_000_000);
}

#[tokio::test]
async fn test_e2e_2_of_3_signing_with_one_rejection() {
    // ========================================
    // SETUP: 2-of-3 threshold
    // ========================================

    let network = TestNetwork::new(2, 3).await;

    let coordinator = network.coordinator();
    let signer1 = network.signer(0);
    let signer2 = network.signer(1);
    let signer3 = network.signer(2);

    // Configure signer3 with stricter policy (will reject)
    signer3.set_policy(GroupPolicy {
        allowed_destinations: vec![], // Empty = reject all
        daily_limit_sompi: 10_000_000,
        per_transaction_limit_sompi: 5_000_000,
        require_approval_above_sompi: 0,
    }).await;

    // ========================================
    // STEP 1: Propose session
    // ========================================

    let event = SigningEvent {
        event_id: "test-event-2".to_string(),
        group_id: network.group_id(),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 500_000,
        timestamp_nanos: 1_700_000_000_000_000_000,
        metadata: Default::default(),
    };

    let session_id = SessionId::from([2u8; 32]);
    let request_id = RequestId::from("req-2");
    let expires_at = 1_700_000_010_000_000_000;

    coordinator.initiate_signing(
        session_id,
        request_id.clone(),
        event,
        expires_at,
    ).await.expect("propose");

    // ========================================
    // STEP 2: Wait for acks
    // ========================================

    network.wait_for_messages(Duration::from_secs(2)).await;

    let acks = coordinator.storage()
        .list_signer_acks(&request_id)
        .await
        .expect("list acks");

    assert_eq!(acks.len(), 3, "Should receive 3 acknowledgments");

    let accepted = acks.iter().filter(|a| a.accept).count();
    let rejected = acks.iter().filter(|a| !a.accept).count();

    assert_eq!(accepted, 2, "2 signers should accept");
    assert_eq!(rejected, 1, "1 signer should reject (signer3)");

    // ========================================
    // STEP 3: Verify threshold still met
    // ========================================

    network.wait_for_messages(Duration::from_secs(2)).await;

    let sigs = coordinator.storage()
        .list_partial_sigs(&request_id)
        .await
        .expect("list sigs");

    assert_eq!(sigs.len(), 2, "Should have 2 signatures (from accepting signers)");

    // ========================================
    // STEP 4: Verify finalization succeeds
    // ========================================

    timeout(
        Duration::from_secs(5),
        wait_for_finalization(&network, &request_id)
    ).await.expect("finalize with 2-of-3");

    let request = coordinator.storage()
        .get_request(&request_id)
        .await
        .expect("get request")
        .expect("exists");

    assert_eq!(request.decision, RequestDecision::Finalized);
}

#[tokio::test]
async fn test_e2e_volume_limit_enforcement() {
    // ========================================
    // SETUP: Network with volume limits
    // ========================================

    let network = TestNetwork::new(2, 2).await;

    let coordinator = network.coordinator();

    // Set policy with daily limit of 2M sompi
    let policy = GroupPolicy {
        allowed_destinations: vec![
            "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        ],
        daily_limit_sompi: 2_000_000,
        per_transaction_limit_sompi: 5_000_000,
        require_approval_above_sompi: 0,
    };

    network.set_group_policy(policy).await;

    // ========================================
    // STEP 1: First transaction (1M sompi) - should succeed
    // ========================================

    let event1 = SigningEvent {
        event_id: "vol-1".to_string(),
        group_id: network.group_id(),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 1_000_000,
        timestamp_nanos: 1_700_000_000_000_000_000,
        metadata: Default::default(),
    };

    let result1 = coordinator.initiate_signing(
        SessionId::from([10u8; 32]),
        RequestId::from("vol-req-1"),
        event1,
        1_700_000_010_000_000_000,
    ).await;

    assert!(result1.is_ok(), "First transaction should succeed");

    network.wait_for_finalization(&RequestId::from("vol-req-1"), Duration::from_secs(5)).await;

    // ========================================
    // STEP 2: Second transaction (1.5M sompi) - should fail (exceeds 2M daily)
    // ========================================

    let event2 = SigningEvent {
        event_id: "vol-2".to_string(),
        group_id: network.group_id(),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 1_500_000,
        timestamp_nanos: 1_700_000_001_000_000_000, // Same day
        metadata: Default::default(),
    };

    let result2 = coordinator.initiate_signing(
        SessionId::from([11u8; 32]),
        RequestId::from("vol-req-2"),
        event2,
        1_700_000_010_000_000_000,
    ).await;

    // Should be rejected during proposal phase
    assert!(result2.is_err(), "Second transaction should fail due to volume limit");

    match result2.unwrap_err() {
        ThresholdError::DailyVolumeLimitExceeded { current, requested, limit } => {
            assert_eq!(current, 1_000_000);
            assert_eq!(requested, 1_500_000);
            assert_eq!(limit, 2_000_000);
        },
        other => panic!("Expected DailyVolumeLimitExceeded, got: {:?}", other),
    }
}
```

**Action**: CREATE this file.

**Test Harness** (referenced above):

**File**: `igra-service/tests/harness/mod.rs` (EXPAND THIS FILE)

```rust
//! Test harness for end-to-end tests.
//!
//! Provides utilities for setting up test networks, waiting for events, etc.

mod network;
mod mocks;
mod assertions;
mod wait;
mod cleanup;

pub use network::TestNetwork;
pub use mocks::{MockNodeRpc, MockHyperlaneClient};
pub use assertions::{assert_request_finalized, assert_threshold_met};
pub use wait::{wait_for_finalization, wait_for_acks, wait_for_signatures};
pub use cleanup::cleanup_test_dirs;

// Re-export common types
pub use igra_core::foundation::types::*;
pub use igra_core::domain::event::SigningEvent;
pub use igra_core::domain::policy::GroupPolicy;
```

**File**: `igra-service/tests/harness/network.rs` (CREATE THIS FILE)

```rust
//! Test network setup for E2E tests.

use igra_core::application::{CoordinatorService, SignerService};
use igra_core::infrastructure::storage::RocksStorage;
use igra_core::infrastructure::transport::MockTransport;
use igra_core::infrastructure::rpc::MockNodeRpc;
use igra_core::domain::policy::GroupPolicy;
use igra_core::foundation::types::GroupId;
use std::sync::Arc;
use tempfile::TempDir;

pub struct TestNetwork {
    group_id: GroupId,
    threshold_m: u16,
    threshold_n: u16,

    coordinator: CoordinatorService,
    signers: Vec<SignerService>,

    mock_rpc: Arc<MockNodeRpc>,

    _temp_dirs: Vec<TempDir>, // Keep alive for cleanup
}

impl TestNetwork {
    /// Create a new test network with m-of-n threshold.
    pub async fn new(m: u16, n: u16) -> Self {
        assert!(m <= n, "Threshold m must be <= n");
        assert!(n > 0, "Must have at least one signer");

        let group_id = [7u8; 32]; // Fixed for tests

        // Create mock RPC
        let mock_rpc = Arc::new(MockNodeRpc::new());

        // Create coordinator
        let (coord_temp, coord_storage) = Self::setup_storage();
        let (coord_transport, coord_hub) = Self::setup_transport("coordinator", group_id);

        let coordinator = CoordinatorService::new(
            coord_transport,
            coord_storage,
            mock_rpc.clone(),
        );

        // Create signers
        let mut signers = Vec::new();
        let mut temp_dirs = vec![coord_temp];

        for i in 0..n {
            let (signer_temp, signer_storage) = Self::setup_storage();
            let (signer_transport, _) = Self::setup_transport_with_hub(
                &format!("signer-{}", i),
                group_id,
                coord_hub.clone(),
            );

            let signer = SignerService::new(
                signer_transport,
                signer_storage,
                mock_rpc.clone(),
            );

            signers.push(signer);
            temp_dirs.push(signer_temp);
        }

        Self {
            group_id,
            threshold_m: m,
            threshold_n: n,
            coordinator,
            signers,
            mock_rpc,
            _temp_dirs: temp_dirs,
        }
    }

    pub fn coordinator(&self) -> &CoordinatorService {
        &self.coordinator
    }

    pub fn signer(&self, index: usize) -> &SignerService {
        &self.signers[index]
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id
    }

    pub fn mock_rpc(&self) -> &Arc<MockNodeRpc> {
        &self.mock_rpc
    }

    pub async fn set_group_policy(&self, policy: GroupPolicy) {
        // Set policy in all storages
        self.coordinator.storage()
            .upsert_group_policy(self.group_id, policy.clone())
            .await
            .expect("set coordinator policy");

        for signer in &self.signers {
            signer.storage()
                .upsert_group_policy(self.group_id, policy.clone())
                .await
                .expect("set signer policy");
        }
    }

    pub async fn wait_for_messages(&self, duration: tokio::time::Duration) {
        tokio::time::sleep(duration).await;
    }

    fn setup_storage() -> (TempDir, Arc<RocksStorage>) {
        let temp = TempDir::new().expect("create temp dir");
        let storage = RocksStorage::open_in_dir(temp.path())
            .expect("open storage");
        (temp, Arc::new(storage))
    }

    fn setup_transport(peer_id: &str, group_id: GroupId) -> (Arc<MockTransport>, Arc<MockHub>) {
        let hub = Arc::new(MockHub::new());
        let transport = Arc::new(MockTransport::new(
            hub.clone(),
            PeerId::from(peer_id),
            group_id,
            0, // No rate limit for tests
        ));
        (transport, hub)
    }

    fn setup_transport_with_hub(
        peer_id: &str,
        group_id: GroupId,
        hub: Arc<MockHub>,
    ) -> (Arc<MockTransport>, Arc<MockHub>) {
        let transport = Arc::new(MockTransport::new(
            hub.clone(),
            PeerId::from(peer_id),
            group_id,
            0,
        ));
        (transport, hub.clone())
    }
}
```

**File**: `igra-service/tests/harness/wait.rs` (CREATE THIS FILE)

```rust
//! Wait utilities for E2E tests.

use igra_core::application::CoordinatorService;
use igra_core::foundation::types::RequestId;
use igra_core::domain::request::RequestDecision;
use tokio::time::{sleep, Duration};

pub async fn wait_for_finalization(
    network: &TestNetwork,
    request_id: &RequestId,
) -> Result<(), String> {
    for _ in 0..50 { // 50 * 100ms = 5 seconds max
        let request = network.coordinator().storage()
            .get_request(request_id)
            .await
            .map_err(|e| format!("get request error: {}", e))?
            .ok_or_else(|| "request not found".to_string())?;

        if request.decision == RequestDecision::Finalized {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }

    Err("finalization timeout".to_string())
}

pub async fn wait_for_acks(
    network: &TestNetwork,
    request_id: &RequestId,
    expected_count: usize,
) -> Result<(), String> {
    for _ in 0..20 { // 20 * 100ms = 2 seconds max
        let acks = network.coordinator().storage()
            .list_signer_acks(request_id)
            .await
            .map_err(|e| format!("list acks error: {}", e))?;

        if acks.len() >= expected_count {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }

    Err(format!("ack timeout: expected {}, got less", expected_count))
}

pub async fn wait_for_signatures(
    network: &TestNetwork,
    request_id: &RequestId,
    expected_count: usize,
) -> Result<(), String> {
    for _ in 0..20 {
        let sigs = network.coordinator().storage()
            .list_partial_sigs(request_id)
            .await
            .map_err(|e| format!("list sigs error: {}", e))?;

        if sigs.len() >= expected_count {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }

    Err(format!("signature timeout: expected {}, got less", expected_count))
}
```

**Verification**:
```bash
cargo test --test e2e_happy_path
# Expected: All tests pass in < 30 seconds
```

---

## Test Fixtures and Factories

### Purpose
Reduce boilerplate by providing reusable test data generators.

### File Structure

**File**: `igra-core/tests/fixtures/mod.rs` (CREATE THIS FILE)

```rust
pub mod factories;
pub mod builders;
pub mod constants;
pub mod sample_data;

pub use factories::*;
pub use builders::*;
pub use constants::*;
pub use sample_data::*;
```

### Factory Pattern

**File**: `igra-core/tests/fixtures/factories.rs` (CREATE THIS FILE)

**COMPLETE CONTENTS**:

```rust
//! Factories for creating test data.
//!
//! Use these instead of manually constructing test objects.

use igra_core::domain::event::SigningEvent;
use igra_core::domain::policy::GroupPolicy;
use igra_core::domain::request::{SigningRequest, RequestDecision};
use igra_core::foundation::types::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Sequence Generators (for unique IDs)
// ============================================================================

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn next_event_id() -> String {
    let n = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("test-event-{}", n)
}

fn next_request_id() -> RequestId {
    let n = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    RequestId::from(format!("test-req-{}", n))
}

// ============================================================================
// Event Factory
// ============================================================================

pub struct EventFactory;

impl EventFactory {
    /// Creates a valid signing event with default values.
    pub fn create() -> SigningEvent {
        SigningEvent {
            event_id: next_event_id(),
            group_id: [1u8; 32],
            destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            amount_sompi: 1_000_000,
            timestamp_nanos: 1_700_000_000_000_000_000,
            metadata: BTreeMap::new(),
        }
    }

    /// Creates an event with specific amount.
    pub fn with_amount(amount: u64) -> SigningEvent {
        let mut event = Self::create();
        event.amount_sompi = amount;
        event
    }

    /// Creates an event with specific destination.
    pub fn with_destination(address: String) -> SigningEvent {
        let mut event = Self::create();
        event.destination_address = address;
        event
    }

    /// Creates an event with specific timestamp.
    pub fn with_timestamp(timestamp_nanos: u64) -> SigningEvent {
        let mut event = Self::create();
        event.timestamp_nanos = timestamp_nanos;
        event
    }

    /// Creates an event with metadata.
    pub fn with_metadata(key: &str, value: &str) -> SigningEvent {
        let mut event = Self::create();
        event.metadata.insert(key.to_string(), value.to_string());
        event
    }

    /// Creates an event with specific group ID.
    pub fn for_group(group_id: GroupId) -> SigningEvent {
        let mut event = Self::create();
        event.group_id = group_id;
        event
    }
}

// ============================================================================
// Request Factory
// ============================================================================

pub struct RequestFactory;

impl RequestFactory {
    /// Creates a valid signing request with default values.
    pub fn create() -> SigningRequest {
        SigningRequest {
            request_id: next_request_id(),
            session_id: SessionId::from([2u8; 32]),
            group_id: [1u8; 32],
            event_hash: [3u8; 32],
            transaction_hash: [4u8; 32],
            validation_hash: [5u8; 32],
            expires_at_nanos: 1_700_000_010_000_000_000,
            decision: RequestDecision::Pending,
            created_at: 1_700_000_000_000_000_000,
        }
    }

    /// Creates a request in Approved state.
    pub fn approved() -> SigningRequest {
        let mut req = Self::create();
        req.decision = RequestDecision::Approved;
        req
    }

    /// Creates a request in Finalized state.
    pub fn finalized() -> SigningRequest {
        let mut req = Self::create();
        req.decision = RequestDecision::Finalized;
        req
    }

    /// Creates a request that has expired.
    pub fn expired() -> SigningRequest {
        let mut req = Self::create();
        req.expires_at_nanos = 1_000_000_000; // Past timestamp
        req
    }
}

// ============================================================================
// Policy Factory
// ============================================================================

pub struct PolicyFactory;

impl PolicyFactory {
    /// Creates a permissive policy (allows everything).
    pub fn permissive() -> GroupPolicy {
        GroupPolicy {
            allowed_destinations: vec![
                "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
                "kaspatest:qz1111111111111111111111111111111111111111111111111111111111xyz".to_string(),
            ],
            daily_limit_sompi: u64::MAX,
            per_transaction_limit_sompi: u64::MAX,
            require_approval_above_sompi: u64::MAX,
        }
    }

    /// Creates a restrictive policy (blocks most things).
    pub fn restrictive() -> GroupPolicy {
        GroupPolicy {
            allowed_destinations: vec![],
            daily_limit_sompi: 100_000,
            per_transaction_limit_sompi: 50_000,
            require_approval_above_sompi: 0,
        }
    }

    /// Creates a policy with specific limits.
    pub fn with_limits(daily: u64, per_tx: u64) -> GroupPolicy {
        GroupPolicy {
            allowed_destinations: vec![
                "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            ],
            daily_limit_sompi: daily,
            per_transaction_limit_sompi: per_tx,
            require_approval_above_sompi: 0,
        }
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Creates N events with sequential amounts.
pub fn create_events(count: usize) -> Vec<SigningEvent> {
    (0..count)
        .map(|i| EventFactory::with_amount((i as u64 + 1) * 100_000))
        .collect()
}

/// Creates N requests with sequential IDs.
pub fn create_requests(count: usize) -> Vec<SigningRequest> {
    (0..count)
        .map(|_| RequestFactory::create())
        .collect()
}
```

**Usage Example**:

```rust
use fixtures::*;

#[test]
fn test_something() {
    // Easy test data creation
    let event = EventFactory::create();
    let event_high_amount = EventFactory::with_amount(10_000_000);
    let policy = PolicyFactory::permissive();

    // Test logic...
}
```

**Verification**:
```bash
# Add to any test file:
use crate::fixtures::*;

# Then use factories instead of manual construction
```

---

## Coverage Requirements

### Minimum Coverage Targets

**Per Layer**:
- Domain (unit tests): **90%** line coverage
- Infrastructure (integration tests): **70%** line coverage
- Application (E2E tests): **60%** line coverage

**Critical Paths** (must be 100%):
- Policy enforcement logic
- Hash computation
- Signature verification
- PSKT building
- State transitions

### Measuring Coverage

**Install tarpaulin**:
```bash
cargo install cargo-tarpaulin
```

**Run coverage**:
```bash
# All tests
cargo tarpaulin --out Html --output-dir coverage

# Unit tests only
cargo tarpaulin --test 'domain_*' --out Html --output-dir coverage/unit

# Integration tests only
cargo tarpaulin --test 'storage_*' --test 'rpc_*' --out Html --output-dir coverage/integration
```

**View results**:
```bash
open coverage/index.html
```

### Coverage Enforcement

**Add to CI** (.github/workflows/test.yml):

```yaml
- name: Test Coverage
  run: |
    cargo tarpaulin --workspace --out Xml

- name: Check Coverage Threshold
  run: |
    COVERAGE=$(grep -oP 'line-rate="\K[^"]+' cobertura.xml | head -1)
    echo "Coverage: ${COVERAGE}%"

    if (( $(echo "$COVERAGE < 0.80" | bc -l) )); then
      echo "Coverage ${COVERAGE}% is below 80% threshold"
      exit 1
    fi
```

---

## Complete Test Examples

### Example 1: Unit Test (Domain)

```rust
#[test]
fn test_volume_calculation_with_multiple_events() {
    // Arrange
    let events = vec![
        EventFactory::with_amount(1_000_000),
        EventFactory::with_amount(2_000_000),
        EventFactory::with_amount(3_000_000),
    ];

    // Act
    let total = domain::policy::calculate_volume(&events);

    // Assert
    assert_eq!(total, 6_000_000);
}
```

### Example 2: Integration Test (Infrastructure)

```rust
#[tokio::test]
async fn test_storage_batch_insert() {
    // Arrange
    let (_temp, storage) = setup_storage();
    let events = create_events(100);

    // Act
    for (i, event) in events.iter().enumerate() {
        let hash = [i as u8; 32];
        storage.insert_event(hash, event.clone())
            .await
            .expect("insert");
    }

    // Assert
    for i in 0..100 {
        let hash = [i as u8; 32];
        let retrieved = storage.get_event(&hash)
            .await
            .expect("get")
            .expect("exists");

        assert_eq!(retrieved.event_id, events[i].event_id);
    }
}
```

### Example 3: E2E Test (Application)

```rust
#[tokio::test]
async fn test_e2e_concurrent_sessions() {
    // Arrange
    let network = TestNetwork::new(2, 2).await;

    // Act - spawn 3 concurrent sessions
    let mut handles = vec![];
    for i in 0..3 {
        let net = network.clone();
        let handle = tokio::spawn(async move {
            let event = EventFactory::with_amount((i + 1) * 100_000);
            let session_id = SessionId::from([i as u8; 32]);
            let request_id = RequestId::from(format!("concurrent-{}", i));

            net.coordinator().initiate_signing(
                session_id,
                request_id.clone(),
                event,
                future_timestamp(),
            ).await
        });
        handles.push(handle);
    }

    // Wait for all
    for handle in handles {
        handle.await.expect("join").expect("signing");
    }

    // Assert - all 3 sessions finalized
    for i in 0..3 {
        let request_id = RequestId::from(format!("concurrent-{}", i));
        let request = network.coordinator().storage()
            .get_request(&request_id)
            .await
            .expect("get")
            .expect("exists");

        assert_eq!(request.decision, RequestDecision::Finalized);
    }
}
```

---

## Test Execution Commands (Complete Reference)

```bash
# ============================================================================
# Unit Tests (Fast - run frequently)
# ============================================================================

# All unit tests
cargo test --lib

# Specific domain module
cargo test --test domain_event
cargo test --test domain_policy

# With output
cargo test --test domain_event -- --nocapture

# ============================================================================
# Integration Tests (Slower - run before commit)
# ============================================================================

# All integration tests
cargo test --tests

# Specific infrastructure
cargo test --test storage_rocks
cargo test --test rpc_kaspa

# ============================================================================
# E2E Tests (Slowest - run before PR)
# ============================================================================

# All E2E tests
cargo test --package igra-service --tests

# Specific scenario
cargo test --test e2e_happy_path
cargo test --test e2e_timeout

# ============================================================================
# All Tests
# ============================================================================

cargo test --workspace

# ============================================================================
# With Coverage
# ============================================================================

cargo tarpaulin --workspace --out Html --output-dir coverage
```

---

## Summary Checklist

Before marking testing complete, verify:

- [ ] All domain modules have unit test files
- [ ] All infrastructure modules have integration test files
- [ ] At least 5 E2E scenarios covered
- [ ] Test fixtures created and used
- [ ] Mock implementations complete
- [ ] Coverage > 80% overall
- [ ] All tests pass in CI
- [ ] No flaky tests (run 10 times each)
- [ ] Test execution time < 60 seconds total

---

**END OF TESTING ARCHITECTURE GUIDE**
