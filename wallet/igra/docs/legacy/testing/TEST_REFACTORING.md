# Integration Test Refactoring Plan

## Executive Summary

The igra test suite is **functionally comprehensive** (67+ tests, ~8,000 lines, 1.67:1 test-to-production ratio) but **organizationally messy**. Key issues:

- ❌ **Test utilities duplicated across 13+ files** (`test_keypair()`, `build_test_pskt()`, etc.)
- ❌ **Unclear file organization** (root-level files mixed with categorized tests)
- ❌ **Hard to find tests** for specific features (scattered across multiple locations)
- ❌ **Large monolithic test files** (982 lines, 512 lines)
- ❌ **Missing documentation** (no README files, no module docs)

**Goal**: Reorganize tests to be **easy to navigate**, **maintainable**, and **audit-friendly** while eliminating duplication.

---

## Part 1: Current State Assessment

### Current Directory Structure

```
igra-core/tests/
├── unit/ (9 files, ~20 tests)
│   └── [Well organized ✅]
└── integration/ (6 files)
    └── [Well organized ✅]

igra-service/tests/
├── [ROOT LEVEL - 16 files] ⚠️ MESSY
│   ├── Actual tests: concurrent_sessions.rs, timeout_scenarios.rs, etc. (8 files)
│   └── Module wrappers: integration_*.rs (8 files) ⚠️ ANTI-PATTERN
├── integration/ [Well organized ✅]
│   ├── cryptography/ (1 file)
│   ├── determinism/ (1 file)
│   ├── flows/ (3 files) ⚠️ One is 982 lines
│   ├── performance/ (4 files)
│   ├── policy/ (1 file)
│   ├── rpc/ (3 files)
│   ├── security/ (4 files)
│   └── storage/ (4 files)
└── integration_harness/ (7 files) ✅ Good foundation
```

### Critical Issues

#### Issue 1: Duplicated Test Utilities (13+ files)

**`test_keypair()` function duplicated in**:
1. `igra-core/tests/unit/pskt_building.rs`
2. `igra-core/tests/unit/multisig_signing.rs`
3. `igra-core/tests/unit/policy_enforcement.rs`
4. `igra-core/tests/integration/policy_rejection.rs`
5. `igra-core/tests/integration/full_signing_flow.rs`
6. `igra-service/tests/timeout_scenarios.rs`
7. `igra-service/tests/concurrent_sessions.rs`
8. `igra-service/tests/coordinator_failure.rs`
9. `igra-service/tests/integration/security/malicious_coordinator.rs`
10. `igra-service/tests/integration/performance/pskt_build_latency.rs`
11. `igra-service/tests/integration/flows/failure_scenarios.rs`
12. `igra-service/benches/integration_perf.rs`

**Other duplicated utilities**:
- `build_test_pskt()` - 6+ files
- `test_event()` / `sample_event()` - 8+ files
- `config_root()` - 3 files
- `lock_env()` - 4 files
- `load_from_ini()` - 3 files

#### Issue 2: Root-Level Test Confusion

**Problem**: Tests at different abstraction levels mixed together

```
tests/concurrent_sessions.rs (144 lines)          # Root-level e2e test
tests/integration/flows/concurrent_sessions.rs (166 lines)  # Categorized integration test
```

Two different "concurrent_sessions" tests exist! Confusing for developers.

#### Issue 3: Module Wrapper Anti-Pattern

**Files like `integration_flows.rs` contain only**:
```rust
#[path = "integration_harness/mod.rs"]
mod integration_harness;
#[path = "integration/flows/happy_path.rs"]
mod happy_path;
#[path = "integration/flows/failure_scenarios.rs"]
mod failure_scenarios;
```

**Why this is bad**:
- Adds unnecessary indirection
- Makes `cargo test --test integration_flows` non-obvious
- Harder to discover tests
- Maintenance burden (must update wrapper when adding tests)

#### Issue 4: Large Monolithic Test Files

- `integration/flows/failure_scenarios.rs` - **982 lines, 6 tests** 😱
- `integration/flows/happy_path.rs` - **512 lines, 4 tests** 😱
- `hyperlane_iroh_flow.rs` - **353 lines, 1 test**

Should be split into focused test files.

#### Issue 5: Hard to Find Tests

**Example: Where are PSKT building tests?**
- `igra-core/tests/unit/pskt_building.rs` - Basic serialization
- `igra-service/tests/integration/performance/pskt_build_latency.rs` - Performance
- `igra-service/benches/integration_perf.rs` - Benchmarks
- Inline PSKT building in 20+ other tests

No single place to look for PSKT tests!

---

## Part 2: Proposed Directory Structure

### Target Structure

```
igra-core/
├── src/                                    # Production code
│   └── ...
└── tests/                                  # Test code
    ├── common/                             # 🆕 Shared test utilities
    │   ├── mod.rs                          # Re-exports
    │   ├── keys.rs                         # Key generation utilities
    │   ├── events.rs                       # Event factories
    │   ├── pskt.rs                         # PSKT builders
    │   ├── storage.rs                      # Storage helpers
    │   └── env.rs                          # Environment variable locking
    ├── unit/                               # Unit tests (unchanged)
    │   ├── README.md                       # 🆕 Documentation
    │   ├── coordination/                   # 🆕 Grouped by module
    │   │   ├── hashes.rs
    │   │   └── monitoring.rs
    │   ├── pskt/                           # 🆕 Grouped by module
    │   │   ├── building.rs
    │   │   └── multisig_signing.rs
    │   ├── storage.rs
    │   ├── event_validation.rs
    │   ├── fee_payment_modes.rs
    │   ├── group_id.rs
    │   └── policy_enforcement.rs
    └── integration/                        # Integration tests (unchanged)
        ├── README.md                       # 🆕 Documentation
        ├── event_ingestion.rs
        ├── full_signing_flow.rs
        ├── policy_rejection.rs
        ├── replay_protection.rs
        └── threshold_detection.rs

igra-service/
├── src/                                    # Production code
│   └── ...
├── tests/                                  # Test code
│   ├── README.md                           # 🆕 Top-level test documentation
│   ├── common/                             # 🆕 Shared utilities (re-exported from harness)
│   │   └── mod.rs                          # Re-exports from harness
│   ├── harness/                            # 🆕 Renamed from integration_harness
│   │   ├── README.md                       # 🆕 Harness documentation
│   │   ├── mod.rs
│   │   ├── assertions.rs
│   │   ├── mocks/                          # 🆕 Grouped mocks
│   │   │   ├── mod.rs
│   │   │   ├── node.rs                     # Renamed from mock_node.rs
│   │   │   └── hyperlane.rs                # Renamed from mock_hyperlane.rs
│   │   ├── factories/                      # 🆕 Grouped factories
│   │   │   ├── mod.rs
│   │   │   ├── data.rs                     # Renamed from test_data.rs
│   │   │   └── keys.rs                     # Renamed from test_keys.rs
│   │   └── network.rs                      # Renamed from test_network.rs
│   ├── unit/                               # 🆕 Unit tests (currently missing)
│   │   ├── README.md
│   │   └── [service-level unit tests]
│   ├── integration/                        # Integration tests (flattened)
│   │   ├── README.md                       # 🆕 Documentation
│   │   ├── coordination/                   # 🆕 Renamed from flows/
│   │   │   ├── README.md
│   │   │   ├── happy_path_2of3.rs          # 🆕 Split from happy_path.rs
│   │   │   ├── happy_path_3of5.rs          # 🆕 Split from happy_path.rs
│   │   │   ├── concurrent_sessions.rs      # Moved from root
│   │   │   ├── coordinator_failure.rs      # Moved from root
│   │   │   ├── coordinator_crash.rs        # 🆕 Split from failure_scenarios.rs
│   │   │   ├── coordinator_partition.rs    # 🆕 Split from failure_scenarios.rs
│   │   │   ├── redundant_proposers.rs      # 🆕 Split from failure_scenarios.rs
│   │   │   ├── timeout_insufficient_sigs.rs # 🆕 Split from failure_scenarios.rs
│   │   │   ├── timeout_scenarios.rs        # Moved from root
│   │   │   └── malformed_proposals.rs      # 🆕 Split from failure_scenarios.rs
│   │   ├── cryptography/
│   │   │   ├── README.md
│   │   │   └── transport_auth.rs
│   │   ├── determinism/
│   │   │   ├── README.md
│   │   │   └── pskt_cross_signer.rs
│   │   ├── e2e/                            # 🆕 End-to-end tests
│   │   │   ├── README.md
│   │   │   ├── hyperlane_iroh_full.rs      # Moved from root (hyperlane_iroh_flow.rs)
│   │   │   ├── two_of_three_full.rs        # Moved from root (two_of_three_flow.rs)
│   │   │   ├── iroh_transport.rs           # Moved from root
│   │   │   └── v1_service_full.rs          # Moved from root (v1_service_integration.rs)
│   │   ├── performance/
│   │   │   ├── README.md
│   │   │   ├── concurrent_capacity.rs
│   │   │   ├── memory_usage.rs
│   │   │   ├── pskt_build_latency.rs
│   │   │   └── signature_throughput.rs
│   │   ├── policy/
│   │   │   ├── README.md
│   │   │   └── volume_limits.rs
│   │   ├── rpc/
│   │   │   ├── README.md
│   │   │   ├── authentication.rs
│   │   │   ├── event_submission.rs
│   │   │   ├── health_ready_metrics.rs
│   │   │   └── integration_full.rs          # Moved from root (rpc_integration.rs)
│   │   ├── security/
│   │   │   ├── README.md
│   │   │   ├── dos_resistance.rs
│   │   │   ├── malicious_coordinator.rs
│   │   │   ├── replay_attack.rs
│   │   │   └── timing_attacks.rs
│   │   └── storage/
│   │       ├── README.md
│   │       ├── audit_trail.rs
│   │       ├── persistence.rs
│   │       ├── replay_prevention.rs
│   │       └── volume_tracking.rs
│   └── fixtures/                           # 🆕 Test data files
│       ├── configs/                        # Moved from integration/
│       │   ├── signer-1.ini
│       │   ├── signer-2.ini
│       │   └── signer-3.ini
│       └── events/                         # 🆕 Sample event files
│           ├── hyperlane_valid.json
│           └── hyperlane_invalid.json
└── benches/                                # Benchmarks (unchanged)
    └── integration_perf.rs
```

### Key Changes

1. ✅ **Remove module wrapper files** (`integration_*.rs`)
2. ✅ **Create `common/` directories** for shared utilities
3. ✅ **Rename `integration_harness/` to `harness/`** (clearer naming)
4. ✅ **Group harness components** (mocks/, factories/)
5. ✅ **Add README.md files** in every test directory
6. ✅ **Move root-level tests** into appropriate categories
7. ✅ **Create `e2e/` subdirectory** for end-to-end tests
8. ✅ **Split large test files** into focused files
9. ✅ **Create `fixtures/` directory** for test data

---

## Part 3: Eliminating Code Duplication

### Step 1: Create Shared Test Utilities Module

**New file: `igra-core/tests/common/mod.rs`**

```rust
// igra-core/tests/common/mod.rs

pub mod keys;
pub mod events;
pub mod pskt;
pub mod storage;
pub mod env;

// Re-export commonly used items
pub use keys::test_keypair;
pub use events::create_test_event;
pub use pskt::build_test_pskt;
pub use storage::setup_test_storage;
pub use env::{lock_env, with_env_var};
```

**New file: `igra-core/tests/common/keys.rs`**

```rust
// igra-core/tests/common/keys.rs

use secp256k1::{Keypair, Secp256k1, SecretKey};

/// Generate deterministic test keypair from seed byte
pub fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
    Keypair::from_secret_key(&secp, &secret)
}

/// Generate multiple test keypairs
pub fn test_keypairs(count: usize) -> Vec<Keypair> {
    (0..count).map(|i| test_keypair(i as u8)).collect()
}

/// Get public key from test keypair
pub fn test_pubkey(seed: u8) -> secp256k1::PublicKey {
    test_keypair(seed).public_key()
}
```

**New file: `igra-core/tests/common/events.rs`**

```rust
// igra-core/tests/common/events.rs

use igra_core::model::{EventSource, SigningEvent};
use kaspa_addresses::Address;

/// Create a basic test event
pub fn create_test_event(
    recipient: Address,
    amount_sompi: u64,
    nonce: u64,
) -> SigningEvent {
    SigningEvent {
        source: EventSource::Api,
        recipient_address: recipient.to_string(),
        amount_sompi,
        nonce: Some(nonce.to_string()),
        memo: None,
        hyperlane_signatures: None,
        layerzero_signatures: None,
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    }
}

/// Create Hyperlane event with signatures
pub fn create_hyperlane_event(
    recipient: Address,
    amount_sompi: u64,
    nonce: u64,
    signatures: Vec<String>,
) -> SigningEvent {
    SigningEvent {
        source: EventSource::Hyperlane,
        recipient_address: recipient.to_string(),
        amount_sompi,
        nonce: Some(nonce.to_string()),
        memo: None,
        hyperlane_signatures: Some(signatures),
        layerzero_signatures: None,
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    }
}
```

**New file: `igra-core/tests/common/pskt.rs`**

```rust
// igra-core/tests/common/pskt.rs

use igra_core::pskt::{Pskt, PsktBuilder};
use kaspa_addresses::Address;

/// Build a simple test PSKT
pub fn build_test_pskt(
    recipient: Address,
    amount: u64,
    num_inputs: usize,
) -> Pskt {
    let mut builder = PsktBuilder::new();

    // Add dummy inputs
    for i in 0..num_inputs {
        builder.add_input(/* ... */);
    }

    // Add recipient output
    builder.add_output(recipient, amount);

    builder.build().expect("valid PSKT")
}
```

**New file: `igra-core/tests/common/storage.rs`**

```rust
// igra-core/tests/common/storage.rs

use igra_core::storage::RocksStorage;
use std::sync::{Arc, RwLock};
use tempfile::TempDir;

/// Setup test storage with temporary directory
pub fn setup_test_storage() -> (Arc<RwLock<RocksStorage>>, TempDir) {
    let temp_dir = TempDir::new().expect("create temp dir");
    let db_path = temp_dir.path().join("test-db");
    let storage = RocksStorage::new(&db_path).expect("open storage");
    (Arc::new(RwLock::new(storage)), temp_dir)
}

/// Setup storage without keeping TempDir (auto-cleanup)
pub fn setup_test_storage_auto_cleanup() -> Arc<RwLock<RocksStorage>> {
    let (storage, _temp_dir) = setup_test_storage();
    // _temp_dir is dropped here, but storage remains valid until test ends
    storage
}
```

**New file: `igra-core/tests/common/env.rs`**

```rust
// igra-core/tests/common/env.rs

use std::sync::{Mutex, OnceLock, MutexGuard};

/// Global lock for environment variable access
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Lock environment variables for exclusive access
pub fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock")
}

/// Execute function with temporary environment variable
pub fn with_env_var<F, R>(key: &str, value: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    let _lock = lock_env();

    // Save old value
    let old_value = std::env::var(key).ok();

    // Set new value
    std::env::set_var(key, value);

    // Execute function
    let result = f();

    // Restore old value
    match old_value {
        Some(old) => std::env::set_var(key, old),
        None => std::env::remove_var(key),
    }

    result
}

/// Execute function with multiple temporary environment variables
pub fn with_env_vars<F, R>(vars: &[(&str, &str)], f: F) -> R
where
    F: FnOnce() -> R,
{
    let _lock = lock_env();

    // Save old values
    let old_values: Vec<_> = vars
        .iter()
        .map(|(key, _)| (*key, std::env::var(key).ok()))
        .collect();

    // Set new values
    for (key, value) in vars {
        std::env::set_var(key, value);
    }

    // Execute function
    let result = f();

    // Restore old values
    for (key, old_value) in old_values {
        match old_value {
            Some(old) => std::env::set_var(key, old),
            None => std::env::remove_var(key),
        }
    }

    result
}
```

### Step 2: Update Existing Tests to Use Common Utilities

**Before** (duplicated in every test file):
```rust
// tests/unit/pskt_building.rs

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

#[test]
fn test_pskt_serialization() {
    let kp = test_keypair(1);
    // ...
}
```

**After** (uses common utilities):
```rust
// tests/unit/pskt/building.rs

mod common;
use common::keys::test_keypair;

#[test]
fn test_pskt_serialization() {
    let kp = test_keypair(1);
    // ...
}
```

### Step 3: Create Service-Level Common Module

**New file: `igra-service/tests/common/mod.rs`**

```rust
// igra-service/tests/common/mod.rs

// Re-export harness for convenience
pub use crate::harness::{
    mocks::{MockKaspaNode, MockHyperlaneValidator},
    factories::{TestDataFactory, TestKeyGenerator},
    network::TestIrohNetwork,
    assertions::*,
};

// Re-export common utilities from igra-core tests
// Note: This requires igra-core test utilities to be in a separate crate
// or we duplicate them here
pub mod keys;
pub mod events;
pub mod pskt;
pub mod storage;
pub mod env;
```

### Step 4: Consolidate Test Data Factories

**Before**: Scattered factory methods in `test_data.rs`

**After**: Organized in `harness/factories/`

```rust
// tests/harness/factories/mod.rs

pub mod data;
pub mod keys;

pub use data::TestDataFactory;
pub use keys::TestKeyGenerator;
```

---

## Part 4: Splitting Large Test Files

### Split `failure_scenarios.rs` (982 lines)

**Current structure** (1 file, 6 tests):
```rust
// integration/flows/failure_scenarios.rs (982 lines)

#[tokio::test]
async fn coordinator_failure_after_proposal() { ... }  // 150 lines

#[tokio::test]
async fn redundant_proposers_deduplicate() { ... }     // 130 lines

#[tokio::test]
async fn partitioned_signer_recovers_after_rebroadcast() { ... }  // 180 lines

#[tokio::test]
async fn invalid_partials_do_not_finalize() { ... }   // 120 lines

#[tokio::test]
async fn malformed_proposal_rejected_by_signers() { ... }  // 150 lines

#[tokio::test]
async fn timeout_with_insufficient_signatures() { ... }  // 200 lines
```

**Proposed structure** (6 files):

```
integration/coordination/
├── coordinator_crash.rs              # coordinator_failure_after_proposal
├── redundant_proposers.rs            # redundant_proposers_deduplicate
├── coordinator_partition.rs          # partitioned_signer_recovers_after_rebroadcast
├── invalid_signatures.rs             # invalid_partials_do_not_finalize
├── malformed_proposals.rs            # malformed_proposal_rejected_by_signers
└── timeout_insufficient_sigs.rs      # timeout_with_insufficient_signatures
```

**Benefits**:
- Each file has a single, clear purpose
- Easier to navigate with `cargo test coordinator_crash`
- Easier to review in PRs (one file, one test)
- Parallel test execution more granular

### Split `happy_path.rs` (512 lines)

**Current structure** (1 file, 4 tests):
```rust
// integration/flows/happy_path.rs (512 lines)

#[tokio::test]
async fn happy_path_hyperlane_2_of_3() { ... }         // 150 lines

#[tokio::test]
async fn happy_path_threshold_3_of_5_all_signers() { ... }  // 130 lines

#[tokio::test]
async fn happy_path_threshold_3_of_5_exactly_three_signers() { ... }  // 120 lines

#[tokio::test]
async fn happy_path_threshold_3_of_5_insufficient_signers() { ... }  // 112 lines
```

**Proposed structure** (3 files):

```
integration/coordination/
├── happy_path_2of3.rs                # happy_path_hyperlane_2_of_3
└── happy_path_3of5.rs                # All 3-of-5 tests in one file
```

**Rationale**: 3-of-5 tests are related variations, can stay together.

---

## Part 5: Adding Documentation

### Test Directory README Files

**File: `igra-service/tests/README.md`**

```markdown
# Igra Service Tests

This directory contains the test suite for the igra-service crate.

## Directory Structure

- `harness/` - Test infrastructure (mocks, factories, network setup)
- `common/` - Shared test utilities (re-exports from harness)
- `unit/` - Unit tests for service-level components
- `integration/` - Integration tests organized by concern
- `fixtures/` - Test data files (configs, events)

## Test Categories

### Integration Tests (`integration/`)

- **coordination/** - Multi-node coordination flows
  - Happy path scenarios (2-of-3, 3-of-5)
  - Failure scenarios (crashes, partitions, timeouts)
  - Concurrent sessions

- **cryptography/** - Cryptographic operations
  - Transport authentication (Ed25519)
  - Signature verification

- **determinism/** - Cross-signer consistency
  - PSKT determinism tests

- **e2e/** - End-to-end tests with real Iroh transport
  - Full Hyperlane + Iroh flow
  - Two-of-three complete flow

- **performance/** - Performance and load tests
  - PSKT build latency
  - Signature throughput
  - Memory usage
  - Concurrent capacity

- **policy/** - Policy enforcement
  - Volume limits
  - Destination allowlists
  - Amount limits

- **rpc/** - JSON-RPC API tests
  - Event submission
  - Authentication
  - Health checks
  - Metrics

- **security/** - Security-focused tests
  - DoS resistance
  - Malicious coordinator detection
  - Replay attack prevention
  - Timing attack resistance

- **storage/** - Database operations
  - Audit trail completeness
  - Persistence across restarts
  - Replay prevention
  - Volume tracking

## Running Tests

```bash
# Run all tests
cargo test -p igra-service

# Run specific category
cargo test --test 'integration_coordination_*'
cargo test --test 'integration_security_*'

# Run specific test
cargo test coordinator_crash

# Run with output
cargo test coordinator_crash -- --nocapture

# Run ignored tests (slow e2e tests)
cargo test -- --ignored

# Run benchmarks
cargo bench
```

## Test Naming Convention

Test functions follow the pattern: `<feature>_<scenario>_<expectation>`

Examples:
- `coordinator_crash_recovers_successfully`
- `volume_limit_exceeded_rejects_request`
- `malicious_coordinator_tampered_pskt_rejected`

## Test Isolation

- All tests use temporary directories (`TempDir`)
- Environment variables are locked with mutex (`lock_env()`)
- Mock transports use unique identifiers
- No shared mutable state between tests

## Adding New Tests

1. Choose appropriate category directory
2. Create new file or add to existing file
3. Use common utilities from `common/` module
4. Add documentation comment explaining test purpose
5. Follow naming convention
6. Ensure test can run in parallel

## Test Harness

The test harness provides:

- **Mocks**: MockKaspaNode, MockHyperlaneValidator
- **Factories**: TestDataFactory, TestKeyGenerator
- **Network**: TestIrohNetwork for P2P testing
- **Assertions**: Custom assertion helpers

See `harness/README.md` for details.
```

**File: `igra-service/tests/harness/README.md`**

```markdown
# Test Harness

This directory contains the test infrastructure for igra-service integration tests.

## Components

### Mocks (`mocks/`)

**MockKaspaNode** (`mocks/node.rs`)
- Simulates Kaspa node gRPC interface
- Manages UTXO set for testing
- Tracks submitted transactions
- Provides assertion helpers

Usage:
```rust
let mut mock_node = MockKaspaNode::new();
mock_node.add_utxo(address, amount);
mock_node.submit_transaction(tx).await?;
mock_node.assert_transaction_submitted(&tx_id);
```

**MockHyperlaneValidator** (`mocks/hyperlane.rs`)
- Generates Hyperlane validator signatures
- Configurable quorum (m-of-n)
- Supports valid and invalid signature generation

Usage:
```rust
let validators = MockHyperlaneValidator::new(3, 2); // 2-of-3
let signatures = validators.sign_with_quorum(&event);
```

### Factories (`factories/`)

**TestDataFactory** (`factories/data.rs`)
- Creates test events, UTXOs, configurations
- Provides common test data patterns

Usage:
```rust
let event = TestDataFactory::create_hyperlane_event(recipient, amount, nonce);
let utxos = TestDataFactory::create_utxo_set(address, count, amount_per_utxo);
let config = TestDataFactory::create_config_2of3(data_dir);
```

**TestKeyGenerator** (`factories/keys.rs`)
- Deterministic key generation from seeds
- Supports Kaspa, Hyperlane, and Iroh keys
- Generates redeem scripts

Usage:
```rust
let keygen = TestKeyGenerator::new("test-seed");
let (secret, public) = keygen.generate_kaspa_keypair(0);
let address = keygen.generate_kaspa_address(0, Prefix::Testnet);
```

### Network (`network.rs`)

**TestIrohNetwork**
- Sets up multi-node Iroh P2P network
- Manages gossip subscriptions
- Handles node connections

Usage:
```rust
let network = TestIrohNetwork::new(3).await?;
network.connect_all().await?;
network.join_group(&group_id).await?;
```

### Assertions (`assertions.rs`)

Custom assertion helpers for common patterns:

```rust
assert_request_finalized(storage, request_id);
```

## Design Principles

1. **Reusability**: All components designed for reuse across tests
2. **Isolation**: Each component is self-contained
3. **Simplicity**: Simple API for common test patterns
4. **Flexibility**: Extensible for new test scenarios
```

### Test Category README Files

**File: `igra-service/tests/integration/coordination/README.md`**

```markdown
# Coordination Tests

Tests for multi-node coordination flows, including proposal broadcasting, signature collection, and transaction finalization.

## Test Files

### Happy Path Tests
- `happy_path_2of3.rs` - Complete 2-of-3 threshold signing flow
- `happy_path_3of5.rs` - Complete 3-of-5 threshold signing flows

### Failure Scenarios
- `coordinator_crash.rs` - Coordinator crashes after proposal, recovers
- `coordinator_partition.rs` - Network partition during coordination
- `redundant_proposers.rs` - Multiple coordinators propose same event
- `invalid_signatures.rs` - Invalid partial signatures rejected
- `malformed_proposals.rs` - Malformed proposals rejected by signers
- `timeout_insufficient_sigs.rs` - Session timeout without threshold

### Concurrency Tests
- `concurrent_sessions.rs` - Multiple sessions in parallel
- `concurrent_timeout.rs` - Timeouts don't affect other sessions

## Common Patterns

All coordination tests follow this pattern:

1. Setup test network (2-of-3, 3-of-5, etc.)
2. Submit event to coordinator
3. Wait for proposal broadcast
4. Signers validate and sign
5. Coordinator collects signatures
6. Transaction finalized and submitted
7. Verify final state

## Running These Tests

```bash
# All coordination tests
cargo test --test 'integration_coordination_*'

# Specific test
cargo test coordinator_crash
```
```

---

## Part 6: Implementation Roadmap

### Phase 1: Create Common Utilities (Week 1, Days 1-2)

**Priority: CRITICAL**

1. **Create `igra-core/tests/common/`** (4 hours)
   - Create mod.rs, keys.rs, events.rs, pskt.rs, storage.rs, env.rs
   - Move duplicated functions
   - Add comprehensive documentation

2. **Update igra-core tests** (4 hours)
   - Update imports in all unit tests
   - Update imports in all integration tests
   - Run tests to verify no breakage

### Phase 2: Reorganize Service Tests (Week 1, Days 3-5)

**Priority: HIGH**

3. **Rename and restructure harness** (4 hours)
   - Rename `integration_harness/` → `harness/`
   - Create `mocks/`, `factories/` subdirectories
   - Move files appropriately
   - Update imports

4. **Create service common module** (2 hours)
   - Create `tests/common/mod.rs`
   - Re-export harness components
   - Create convenience aliases

5. **Move root-level tests** (6 hours)
   - Create `integration/e2e/` directory
   - Move appropriate tests from root
   - Update imports and paths
   - Remove module wrapper files (`integration_*.rs`)
   - Run tests to verify

### Phase 3: Split Large Files (Week 2, Days 1-3)

**Priority: HIGH**

6. **Split failure_scenarios.rs** (8 hours)
   - Extract 6 tests into separate files
   - Update imports
   - Verify all tests pass
   - Update documentation

7. **Split happy_path.rs** (4 hours)
   - Extract into 2 files
   - Update imports
   - Verify all tests pass

8. **Reorganize by category** (4 hours)
   - Ensure all tests in correct category
   - Add missing categories if needed

### Phase 4: Documentation (Week 2, Days 4-5)

**Priority: MEDIUM**

9. **Add README files** (8 hours)
   - `tests/README.md` (top-level)
   - `harness/README.md`
   - `integration/*/README.md` for each category
   - Document test naming conventions
   - Document how to run tests

10. **Add module documentation** (4 hours)
    - Add module-level doc comments
    - Add test function doc comments
    - Add inline comments for complex setups

### Phase 5: Final Cleanup (Week 3, Days 1-2)

**Priority: LOW**

11. **Organize fixtures** (2 hours)
    - Create `fixtures/` directory
    - Move config files
    - Add sample event files

12. **Final verification** (6 hours)
    - Run full test suite
    - Fix any broken tests
    - Update CI/CD if needed
    - Update contributing documentation

---

## Part 7: Migration Strategy

### Incremental Migration Plan

**Goal**: Minimize disruption, allow incremental adoption

#### Step 1: Add Common Utilities (No Breaking Changes)

```bash
# Create new common module
mkdir -p igra-core/tests/common
touch igra-core/tests/common/{mod.rs,keys.rs,events.rs,pskt.rs,storage.rs,env.rs}

# Implement utilities
# ... (copy from examples above)

# Tests can start using common utilities incrementally
# Old code still works (duplicated functions remain)
```

#### Step 2: Update Tests One-by-One

```bash
# Update one test file at a time
# Replace duplicated functions with imports

# Before:
fn test_keypair(seed: u8) -> Keypair { ... }

# After:
use common::keys::test_keypair;

# Run test to verify
cargo test -p igra-core specific_test

# Commit when test passes
git add igra-core/tests/unit/specific_test.rs
git commit -m "refactor(tests): use common test utilities in specific_test"
```

#### Step 3: Remove Duplicated Code

```bash
# After all tests updated, remove duplicated functions
# Search for "fn test_keypair" and verify all removed except in common/

# Run full test suite
cargo test

# Commit
git commit -m "refactor(tests): remove duplicated test utilities"
```

#### Step 4: Reorganize Files

```bash
# Move files one at a time
git mv igra-service/tests/concurrent_sessions.rs \
       igra-service/tests/integration/coordination/concurrent_sessions.rs

# Update imports if needed
# Run tests
cargo test concurrent_sessions

# Commit
git commit -m "refactor(tests): move concurrent_sessions to coordination/"
```

#### Step 5: Split Large Files

```bash
# Create new files first
touch igra-service/tests/integration/coordination/coordinator_crash.rs

# Copy test function from failure_scenarios.rs
# Add imports
# Run test
cargo test coordinator_crash

# Once new test works, remove from old file
# Commit both changes together
git add integration/coordination/coordinator_crash.rs
git add integration/flows/failure_scenarios.rs
git commit -m "refactor(tests): extract coordinator_crash test"
```

### Rollback Strategy

**If something breaks**:

1. **Isolated change**: Revert specific commit
   ```bash
   git revert <commit-hash>
   ```

2. **Multiple related commits**: Revert range
   ```bash
   git revert <start-commit>..<end-commit>
   ```

3. **Large refactor**: Create feature branch
   ```bash
   git checkout -b test-refactor
   # Make changes
   # If it works, merge
   git checkout main
   git merge test-refactor
   # If it doesn't work, abandon branch
   ```

### Testing During Migration

**After each step**:

```bash
# Run full test suite
cargo test --workspace

# Run with verbose output to catch warnings
cargo test --workspace -- --nocapture

# Run ignored tests (e2e)
cargo test --workspace -- --ignored

# Check for compilation warnings
cargo clippy --workspace --tests

# Verify benchmarks still compile
cargo bench --no-run
```

---

## Part 8: Success Metrics

### Before Refactoring

| Metric | Value |
|--------|-------|
| Test files | 60 |
| Duplicate utilities | 13+ files |
| Large files (>400 lines) | 3 files |
| Root-level confusion | 16 files mixed |
| Module wrappers | 8 files |
| Documentation | 0 README files |
| Average file size | ~140 lines |

### After Refactoring

| Metric | Target |
|--------|--------|
| Test files | ~65 (after splitting) |
| Duplicate utilities | 0 ✅ |
| Large files (>400 lines) | 0 ✅ |
| Root-level confusion | 0 (all categorized) ✅ |
| Module wrappers | 0 ✅ |
| Documentation | 10+ README files ✅ |
| Average file size | ~100 lines ✅ |

### Quality Improvements

- ✅ **Navigability**: Easy to find tests for specific features
- ✅ **Maintainability**: No code duplication, clear structure
- ✅ **Auditability**: Clear documentation, organized by concern
- ✅ **Discoverability**: README files explain test categories
- ✅ **Parallel execution**: Smaller files enable finer-grained parallelism

---

## Part 9: Best Practices Going Forward

### Adding New Tests

**Checklist**:

1. ✅ Use utilities from `common/` module (no duplication)
2. ✅ Place in appropriate category directory
3. ✅ Follow naming convention: `<feature>_<scenario>_<expectation>`
4. ✅ Add doc comment explaining test purpose
5. ✅ Use descriptive test function name
6. ✅ Keep test files focused (<200 lines)
7. ✅ Use test fixtures from `fixtures/` directory
8. ✅ Ensure test can run in parallel

### Test Naming Examples

**Good names**:
```rust
#[tokio::test]
async fn coordinator_crash_after_proposal_recovers_successfully()

#[tokio::test]
async fn volume_limit_exceeded_rejects_request()

#[tokio::test]
async fn malicious_coordinator_tampered_pskt_rejected_by_signers()
```

**Bad names**:
```rust
#[tokio::test]
async fn test_1()  // Too generic

#[tokio::test]
async fn coordinator_test()  // Not descriptive

#[tokio::test]
async fn it_works()  // No context
```

### Test Structure Template

```rust
// tests/integration/coordination/my_new_test.rs

//! Test description: Explain what this test verifies and why it's important
//!
//! Scenario: Describe the test scenario
//! Expected: Describe expected behavior

use crate::common::{test_keypair, create_test_event};
use crate::harness::{MockKaspaNode, TestIrohNetwork};

#[tokio::test]
async fn feature_scenario_expectation() {
    // Setup: Create test environment
    let mut mock_node = MockKaspaNode::new();
    let mut network = TestIrohNetwork::new(3).await.unwrap();

    // Given: Setup preconditions
    mock_node.add_utxo(address, 100_000_000_000);
    let event = create_test_event(recipient, 50_000_000_000, 1);

    // When: Perform action
    let request_id = network.submit_event(event).await.unwrap();

    // Then: Verify expected outcome
    network.wait_for_finalization(&request_id, Duration::from_secs(30))
        .await
        .expect("request should finalize");

    // Assert: Check postconditions
    let tx = mock_node.get_submitted_transaction(&request_id).unwrap();
    assert_eq!(tx.outputs[0].value, 50_000_000_000);
}
```

### Documentation Requirements

**Every test category must have**:
- `README.md` explaining category purpose
- List of test files and what they test
- How to run tests in category
- Common patterns used

**Every test file should have**:
- Module-level doc comment
- Test function doc comments for complex tests
- Inline comments for non-obvious setup

---

## Part 10: Estimated Effort

### Time Breakdown

| Phase | Tasks | Effort | Risk |
|-------|-------|--------|------|
| **Phase 1** | Create common utilities | 8 hours | Low |
| **Phase 2** | Reorganize service tests | 16 hours | Medium |
| **Phase 3** | Split large files | 16 hours | Medium |
| **Phase 4** | Documentation | 12 hours | Low |
| **Phase 5** | Final cleanup | 8 hours | Low |

**Total: 60 hours (~1.5 weeks)**

### Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Tests break during refactor | Medium | High | Incremental migration, run tests after each change |
| Missed duplication | Low | Low | Code review, grep for patterns |
| Import path confusion | Medium | Low | Clear documentation, consistent naming |
| CI/CD breaks | Low | Medium | Test locally first, update CI config |

### Benefits vs. Effort

**Benefits**:
- 🚀 **Much easier to navigate** - Clear structure, no confusion
- 🛡️ **Zero duplication** - Single source of truth for utilities
- 📚 **Well documented** - README files for auditors/developers
- 🔍 **Easy to find tests** - Logical categorization
- ⚡ **Better parallelism** - Smaller files
- 🧹 **Maintainable** - Clear structure, easy to extend

**Effort**: 60 hours (1.5 weeks)

**ROI**: High - One-time investment with lasting benefits

---

## Summary

### Current State
- ❌ Duplicated utilities across 13+ files
- ❌ Confusing root-level organization
- ❌ Large monolithic test files (982 lines!)
- ❌ No documentation
- ❌ Hard to find tests for specific features

### Target State
- ✅ Zero duplication (common utilities module)
- ✅ Clear categorization (coordination, security, performance, etc.)
- ✅ Focused test files (<200 lines each)
- ✅ Comprehensive documentation (10+ README files)
- ✅ Easy test discovery and navigation

### Key Changes
1. Create `common/` utilities module
2. Rename `integration_harness/` to `harness/`
3. Move root-level tests to categories
4. Remove module wrapper anti-pattern
5. Split large test files
6. Add README files everywhere

### Implementation
- **Incremental migration** (safe, low risk)
- **Run tests after each step** (catch issues early)
- **60 hours total effort** (~1.5 weeks)
- **High ROI** (lasting benefits)

---

**Document Version**: 1.0
**Last Updated**: 2025-12-31
**Status**: Ready for Implementation
**Next Steps**: Begin Phase 1 (Create common utilities)
