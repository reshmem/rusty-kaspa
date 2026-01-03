# Architecture Improvements and Refactoring Recommendations

**Date**: 2025-12-31
**Status**: Post-Security Audit Analysis
**Scope**: Architecture, simplification, performance, maintainability

---

## Executive Summary

After comprehensive security fixes and code analysis, this document proposes architectural improvements and simplifications to enhance maintainability, performance, and developer experience. The codebase is already well-structured with excellent separation of concerns. These recommendations focus on incremental improvements rather than major rewrites.

**Overall Assessment**: 🟢 **Solid Foundation** (8.5/10)
- ✅ Excellent security posture post-fixes
- ✅ Good module organization
- ✅ Clean separation between core logic and service layer
- ⚠️ Some opportunities for simplification
- ⚠️ Performance optimizations available
- ⚠️ Developer experience improvements possible

---

## Table of Contents

1. [Architecture Simplifications](#1-architecture-simplifications)
2. [Performance Optimizations](#2-performance-optimizations)
3. [Code Organization](#3-code-organization)
4. [Type System Improvements](#4-type-system-improvements)
5. [Error Handling Enhancements](#5-error-handling-enhancements)
6. [Testing Infrastructure](#6-testing-infrastructure)
7. [Developer Experience](#7-developer-experience)
8. [Operational Improvements](#8-operational-improvements)
9. [Documentation](#9-documentation)
10. [Implementation Roadmap](#10-implementation-roadmap)

---

## 1. Architecture Simplifications

### 1.1 Reduce Dynamic Dispatch Overhead

**Current State**: 55 instances of `Arc<dyn Trait>` throughout codebase

**Issue**: Dynamic dispatch adds runtime overhead and prevents compiler optimizations

**Recommendation**: Convert frequently-used traits to generic parameters with monomorphization

**Example - Storage Trait**:
```rust
// Current (dynamic dispatch):
pub struct Coordinator {
    storage: Arc<dyn Storage>,
    transport: Arc<dyn Transport>,
}

// Proposed (monomorphization):
pub struct Coordinator<S: Storage, T: Transport> {
    storage: Arc<S>,
    transport: Arc<T>,
}

// Benefits:
// - Zero-cost abstraction (no vtable lookups)
// - Compiler can inline and optimize aggressively
// - Better CPU cache utilization
// - Type-safe at compile time
```

**Implementation Priority**: MEDIUM
**Effort**: 3-4 days
**Impact**: 5-10% performance improvement in hot paths

**Files to Modify**:
- `igra-core/src/coordination/*.rs` - Add generic parameters
- `igra-service/src/service/flow.rs` - Update ServiceFlow
- All trait consumers

---

### 1.2 Simplify ServiceFlow Architecture

**Current State**: ServiceFlow wraps Coordinator and duplicates some responsibilities

**Issue**: Unclear separation between ServiceFlow and Coordinator

**Recommendation**: Merge ServiceFlow into Coordinator or clarify responsibilities

**Option A - Merge** (Recommended):
```rust
// Eliminate ServiceFlow, extend Coordinator
pub struct Coordinator<S: Storage, T: Transport, R: NodeRpc> {
    storage: Arc<S>,
    transport: Arc<T>,
    rpc: Arc<R>,
    metrics: Arc<Metrics>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl<S, T, R> Coordinator<S, T, R> {
    // Move all ServiceFlow methods here
    pub async fn propose_from_rpc(&self, ...) { }
    pub async fn finalize_and_submit(&self, ...) { }
}
```

**Option B - Clarify**:
- **Coordinator**: Pure coordination logic (proposal, signing, finalization)
- **ServiceFlow**: Service-level orchestration (RPC, metrics, lifecycle)

**Implementation Priority**: LOW
**Effort**: 2-3 days
**Impact**: Improved code clarity, reduced indirection

---

### 1.3 Consolidate Configuration Types

**Current State**: Configuration split across 7 files (good), but some overlap

**Files**:
```
igra-core/src/config/
├── mod.rs          (2.1 KB)
├── types.rs        (3.7 KB)
├── loader.rs       (17 KB)  ⚠️ Large
├── validation.rs   (3.5 KB)
├── persistence.rs  (4.4 KB)
├── encryption.rs   (2.2 KB)
└── env.rs          (2.4 KB)
```

**Recommendation**: Extract common patterns into config builder

**Example**:
```rust
// New: igra-core/src/config/builder.rs
pub struct AppConfigBuilder {
    // Fluent API for configuration
    service: Option<ServiceConfig>,
    iroh: Option<IrohConfig>,
    policy: Option<GroupPolicy>,
}

impl AppConfigBuilder {
    pub fn with_service(mut self, config: ServiceConfig) -> Self {
        self.service = Some(config);
        self
    }

    pub fn with_defaults(self) -> Self {
        // Apply sensible defaults
        self
    }

    pub fn validate_and_build(self) -> Result<AppConfig, ThresholdError> {
        // Validate and construct
        Ok(AppConfig { /* ... */ })
    }
}

// Usage:
let config = AppConfigBuilder::new()
    .from_env()
    .with_defaults()
    .validate_and_build()?;
```

**Implementation Priority**: LOW
**Effort**: 2 days
**Impact**: Improved configuration ergonomics

---

## 2. Performance Optimizations

### 2.1 Reduce Clone Operations

**Current State**: 135 `clone()` calls throughout codebase

**Issue**: Excessive cloning of Arc-wrapped data and large structures

**High-Impact Targets**:

**A. SigningEvent Cloning** (appears 15+ times):
```rust
// Current: Clone entire event multiple times
let event = signing_event.clone();
storage.insert_event(event_hash, event.clone())?;
audit_log(event.clone());

// Proposed: Use references or Arc
let event = Arc::new(signing_event);
storage.insert_event(event_hash, Arc::clone(&event))?;
audit_log(&event);  // Or keep Arc
```

**B. Configuration Cloning**:
```rust
// Current in coordination.rs:76-79
let app_config_for_loop = app_config.clone();
let flow_for_loop = flow.clone();
// ... etc

// Proposed: Already Arc-wrapped, just clone the Arc pointer
// (This is actually fine - Arc::clone is cheap)
// But consider sharing references in single-threaded contexts
```

**C. PSKT Blob Cloning**:
```rust
// Current: kpsbt_blob cloned multiple times
proposal.kpsbt_blob.clone()

// Proposed: Use Cow or Arc<[u8]>
use std::borrow::Cow;
pub struct StoredProposal {
    // ...
    pub kpsbt_blob: Arc<[u8]>,  // Or Cow<'static, [u8]>
}
```

**Implementation Priority**: MEDIUM
**Effort**: 2-3 days
**Impact**: 3-8% reduction in memory allocations

---

### 2.2 Optimize Database Operations

**Current State**: Column families recently added (excellent!), but more optimizations available

**A. Batch Writes Already Implemented** ✅:
```rust
// rocks.rs:543-576: cleanup_seen_messages uses batch
let mut batch = WriteBatch::default();
// ...
self.db.write(batch)
```

**B. Add Read Caching for Hot Paths**:
```rust
// Frequently accessed: GroupConfig, Policies
// Add LRU cache layer

use lru::LruCache;

pub struct CachedStorage<S: Storage> {
    inner: S,
    group_cache: Arc<Mutex<LruCache<Hash32, GroupConfig>>>,
}

impl<S: Storage> Storage for CachedStorage<S> {
    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>, ThresholdError> {
        // Check cache first
        if let Some(cached) = self.group_cache.lock().unwrap().get(group_id) {
            return Ok(Some(cached.clone()));
        }

        // Cache miss - fetch and store
        let config = self.inner.get_group_config(group_id)?;
        if let Some(ref cfg) = config {
            self.group_cache.lock().unwrap().put(*group_id, cfg.clone());
        }
        Ok(config)
    }
}
```

**C. Use RocksDB Bloom Filters**:
```rust
// rocks.rs:59-62: Add bloom filter options
let mut options = RocksOptions::default();
options.create_if_missing(true);
options.create_missing_column_families(true);

// Add bloom filters for point lookups
let mut block_opts = BlockBasedOptions::default();
block_opts.set_bloom_filter(10.0, false);  // 10 bits per key
options.set_block_based_table_factory(&block_opts);

// Add for each column family with frequent lookups
let mut event_options = RocksOptions::default();
event_options.set_block_based_table_factory(&block_opts);
```

**Implementation Priority**: MEDIUM
**Effort**: 3-4 days
**Impact**: 10-20% improvement in read-heavy workloads

---

### 2.3 Optimize Serialization

**Current State**: Using bincode for all serialization

**Issue**: Bincode is good but not optimized for specific data patterns

**A. Use Zero-Copy Deserialization**:
```rust
// Current:
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ThresholdError>

// Proposed for hot paths (event validation):
use zerocopy::{AsBytes, FromBytes};

#[derive(FromBytes, AsBytes)]
#[repr(C)]
struct EventHeaderWire {
    event_id_len: u32,
    timestamp_nanos: u64,
    amount_sompi: u64,
    // Fixed-size header for quick validation
}

fn quick_validate_event(bytes: &[u8]) -> bool {
    if let Some(header) = EventHeaderWire::read_from_prefix(bytes) {
        header.timestamp_nanos > 0 && header.amount_sompi > 0
    } else {
        false
    }
}
```

**B. Profile and Optimize Hot Structures**:
```rust
// Use cargo flamegraph to identify serialization hotspots
// Then optimize those specific types

// Example: SigningEvent is serialized frequently
// Consider custom serialization for performance-critical paths
impl SigningEvent {
    pub fn to_bytes_fast(&self) -> Vec<u8> {
        // Custom, optimized serialization
        let mut buf = Vec::with_capacity(512);  // Pre-allocate
        // ... write fields directly
        buf
    }
}
```

**Implementation Priority**: LOW
**Effort**: 3-5 days
**Impact**: 2-5% overall performance improvement

---

### 2.4 Reduce Allocations in Hot Paths

**Current State**: Many small allocations in message processing

**Recommendation**: Use object pools and pre-allocation

```rust
// New: igra-core/src/util/pool.rs
use crossbeam_queue::ArrayQueue;

pub struct ByteBufferPool {
    pool: ArrayQueue<Vec<u8>>,
    default_capacity: usize,
}

impl ByteBufferPool {
    pub fn new(pool_size: usize, buffer_capacity: usize) -> Self {
        let pool = ArrayQueue::new(pool_size);
        for _ in 0..pool_size {
            let _ = pool.push(Vec::with_capacity(buffer_capacity));
        }
        Self {
            pool,
            default_capacity: buffer_capacity,
        }
    }

    pub fn acquire(&self) -> Vec<u8> {
        self.pool.pop()
            .map(|mut buf| { buf.clear(); buf })
            .unwrap_or_else(|| Vec::with_capacity(self.default_capacity))
    }

    pub fn release(&self, buf: Vec<u8>) {
        let _ = self.pool.push(buf);
    }
}

// Usage in encoding/decoding:
static BUFFER_POOL: Lazy<ByteBufferPool> =
    Lazy::new(|| ByteBufferPool::new(100, 4096));

fn encode_envelope(envelope: &MessageEnvelope) -> Result<Vec<u8>, ThresholdError> {
    let mut buf = BUFFER_POOL.acquire();
    // ... encode into buf
    Ok(buf)  // Transfer ownership
}
```

**Implementation Priority**: LOW
**Effort**: 2-3 days
**Impact**: Reduced GC pressure in high-throughput scenarios

---

## 3. Code Organization

### 3.1 Create Domain-Specific Modules

**Current State**: Some files are still large

**Large Files**:
- `failure_scenarios.rs` - 992 lines
- `rocks.rs` - 745 lines (acceptable after column family refactor)
- `loader.rs` - 446 lines
- `coordination.rs` - 375 lines

**Recommendation**: Split `failure_scenarios.rs` by failure type

```
igra-service/tests/integration/flows/
├── happy_path.rs               (515 lines - OK)
└── failures/
    ├── mod.rs                  (shared test utilities)
    ├── network_failures.rs     (~200 lines)
    ├── Byzantine_faults.rs     (~200 lines)
    ├── policy_violations.rs    (~200 lines)
    ├── timeout_scenarios.rs    (~200 lines)
    └── malformed_messages.rs   (~200 lines)
```

**Implementation Priority**: MEDIUM
**Effort**: 1 day
**Impact**: Improved test organization and discoverability

---

### 3.2 Extract Common Test Utilities

**Current State**: No common test module found (0 files use it)

**Issue**: Likely duplicated test helpers across files

**Recommendation**: Create comprehensive test utilities

```rust
// New: igra-service/tests/common/mod.rs
pub mod fixtures;
pub mod harness;
pub mod assertions;

// igra-service/tests/common/fixtures.rs
pub fn test_signing_event() -> SigningEvent {
    SigningEvent {
        event_id: "test-event-001".to_string(),
        event_source: EventSource::Manual {
            operator: "test".to_string(),
        },
        derivation_path: "m/44'/111111'/0'/0/0".to_string(),
        // ... standard test values
    }
}

pub fn test_group_config() -> GroupConfig {
    // Standard test group config
}

pub fn test_keypair() -> (SecretKey, PublicKey) {
    // Single canonical implementation
}

// igra-service/tests/common/harness.rs
pub struct TestHarness {
    pub storage: Arc<RocksStorage>,
    pub transport: Arc<MockTransport>,
    pub coordinator: Coordinator,
}

impl TestHarness {
    pub async fn new() -> Self {
        // Standard setup
    }

    pub async fn propose_and_sign(&self, event: SigningEvent) -> Result<Hash32, ThresholdError> {
        // Common test flow
    }
}

// igra-service/tests/common/assertions.rs
pub fn assert_finalized(storage: &dyn Storage, request_id: &RequestId) {
    let request = storage.get_request(request_id).unwrap().unwrap();
    assert!(matches!(request.decision, RequestDecision::Finalized));
}

pub fn assert_partial_sig_count(storage: &dyn Storage, request_id: &RequestId, expected: usize) {
    let sigs = storage.list_partial_sigs(request_id).unwrap();
    assert_eq!(sigs.len(), expected);
}
```

**Implementation Priority**: HIGH
**Effort**: 2-3 days
**Impact**: Reduced test duplication, improved maintainability

---

### 3.3 Standardize Module Structure

**Current State**: Good module organization, but some inconsistencies

**Recommendation**: Enforce standard module pattern

**Standard Pattern**:
```
module_name/
├── mod.rs          # Public API and re-exports
├── types.rs        # Type definitions (structs, enums)
├── impl.rs         # Core implementation
├── builder.rs      # Builder patterns (if applicable)
├── validation.rs   # Validation logic
└── tests.rs        # Unit tests
```

**Example - Refactor `coordination/` module**:
```
igra-core/src/coordination/
├── mod.rs              # ✅ Public API
├── coordinator.rs      # ✅ Main implementation
├── signer.rs           # ✅ Signer logic
├── hashes.rs           # ✅ Hash computations
├── threshold.rs        # ✅ Threshold logic
└── monitoring.rs       # ✅ Transaction monitoring

# Could add:
├── types.rs            # Extract shared types
└── validation.rs       # Extract validation logic from coordinator
```

**Implementation Priority**: LOW
**Effort**: 2-3 days
**Impact**: Improved code navigation

---

## 4. Type System Improvements

### 4.1 Use Newtypes for Type Safety

**Current State**: Using type aliases which don't provide compile-time safety

```rust
// model.rs:5
pub type Hash32 = [u8; 32];
```

**Issue**: Easy to mix up different hash types (event hash, validation hash, tx hash)

**Recommendation**: Use newtype pattern with strong typing

```rust
// New: igra-core/src/types/hashes.rs
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! define_hash_type {
    ($name:ident, $purpose:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(#[serde(with = "hex_serde")] [u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }
    };
}

// Define specific hash types
define_hash_type!(EventHash, "Hash of SigningEvent");
define_hash_type!(ValidationHash, "Combined validation hash");
define_hash_type!(TxTemplateHash, "PSKT transaction template hash");
define_hash_type!(GroupIdHash, "Group identifier hash");

// Usage - compile-time type safety:
fn store_event(event_hash: EventHash, event: SigningEvent) { }
fn validate(event_hash: EventHash, validation_hash: ValidationHash) { }

// This won't compile (type safety):
let tx_hash: TxTemplateHash = compute_tx_hash();
store_event(tx_hash, event);  // ❌ Type error - can't use TxTemplateHash as EventHash
```

**Benefits**:
- Prevents mixing up different hash types
- Self-documenting code
- Zero runtime cost (newtype optimization)
- Better error messages

**Implementation Priority**: MEDIUM
**Effort**: 3-4 days
**Impact**: Improved type safety and code clarity

---

### 4.2 Use Builder Pattern for Complex Types

**Current State**: Complex structs constructed directly

**Example - GroupConfig**:
```rust
// Current: Direct construction (error-prone)
let config = GroupConfig {
    network_id: 1,
    threshold_m: 2,
    threshold_n: 3,
    member_pubkeys: vec![],  // Easy to forget
    fee_rate_sompi_per_gram: 1000,
    finality_blue_score_threshold: 10,
    dust_threshold_sompi: 1000,
    min_recipient_amount_sompi: 10000,
    session_timeout_seconds: 300,
    group_metadata: GroupMetadata::default(),
    policy: GroupPolicy::default(),
};
```

**Recommendation**: Implement builder pattern

```rust
// New implementation in model.rs
impl GroupConfig {
    pub fn builder() -> GroupConfigBuilder {
        GroupConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct GroupConfigBuilder {
    network_id: Option<u8>,
    threshold_m: Option<u16>,
    threshold_n: Option<u16>,
    member_pubkeys: Vec<Vec<u8>>,
    fee_rate: Option<u64>,
    finality_threshold: Option<u64>,
    dust_threshold: Option<u64>,
    min_recipient: Option<u64>,
    timeout_seconds: Option<u64>,
    metadata: GroupMetadata,
    policy: GroupPolicy,
}

impl GroupConfigBuilder {
    pub fn network_id(mut self, id: u8) -> Self {
        self.network_id = Some(id);
        self
    }

    pub fn threshold(mut self, m: u16, n: u16) -> Self {
        self.threshold_m = Some(m);
        self.threshold_n = Some(n);
        self
    }

    pub fn member_pubkeys(mut self, pubkeys: Vec<Vec<u8>>) -> Self {
        self.member_pubkeys = pubkeys;
        self
    }

    pub fn with_mainnet_defaults(mut self) -> Self {
        self.fee_rate = Some(1000);
        self.finality_threshold = Some(10);
        self.dust_threshold = Some(1000);
        self.min_recipient = Some(10000);
        self.timeout_seconds = Some(300);
        self
    }

    pub fn build(self) -> Result<GroupConfig, ThresholdError> {
        // Validate required fields
        let network_id = self.network_id
            .ok_or_else(|| ThresholdError::ConfigError("network_id required".into()))?;
        let threshold_m = self.threshold_m
            .ok_or_else(|| ThresholdError::ConfigError("threshold_m required".into()))?;
        let threshold_n = self.threshold_n
            .ok_or_else(|| ThresholdError::ConfigError("threshold_n required".into()))?;

        // Validate threshold logic
        if threshold_m == 0 || threshold_n == 0 {
            return Err(ThresholdError::ConfigError("thresholds must be > 0".into()));
        }
        if threshold_m > threshold_n {
            return Err(ThresholdError::ConfigError("m must be <= n".into()));
        }

        Ok(GroupConfig {
            network_id,
            threshold_m,
            threshold_n,
            member_pubkeys: self.member_pubkeys,
            fee_rate_sompi_per_gram: self.fee_rate.unwrap_or(1000),
            finality_blue_score_threshold: self.finality_threshold.unwrap_or(10),
            dust_threshold_sompi: self.dust_threshold.unwrap_or(1000),
            min_recipient_amount_sompi: self.min_recipient.unwrap_or(10000),
            session_timeout_seconds: self.timeout_seconds.unwrap_or(300),
            group_metadata: self.metadata,
            policy: self.policy,
        })
    }
}

// Usage:
let config = GroupConfig::builder()
    .network_id(1)
    .threshold(2, 3)
    .member_pubkeys(pubkeys)
    .with_mainnet_defaults()
    .build()?;
```

**Implementation Priority**: LOW
**Effort**: 2-3 days
**Impact**: Improved API ergonomics and validation

---

### 4.3 Add Phantom Types for State Machines

**Current State**: RequestDecision is an enum, state transitions validated at runtime

**Recommendation**: Use type-state pattern for compile-time state validation

```rust
// New: igra-core/src/model/request_state.rs
use std::marker::PhantomData;

// State markers (zero-sized types)
pub struct Pending;
pub struct Approved;
pub struct Finalized;
pub struct Rejected;

// Generic request with type-state
pub struct TypedSigningRequest<State> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub event_hash: EventHash,
    // ... common fields
    _state: PhantomData<State>,
}

// State-specific data and transitions
impl TypedSigningRequest<Pending> {
    pub fn approve(self) -> TypedSigningRequest<Approved> {
        // Transition to Approved
        TypedSigningRequest {
            request_id: self.request_id,
            // ... copy fields
            _state: PhantomData,
        }
    }

    pub fn reject(self, reason: String) -> TypedSigningRequest<Rejected> {
        // Transition to Rejected
        // Store reason somehow...
        TypedSigningRequest {
            request_id: self.request_id,
            _state: PhantomData,
        }
    }
}

impl TypedSigningRequest<Approved> {
    pub fn finalize(self, tx_id: TransactionId) -> TypedSigningRequest<Finalized> {
        // Only Approved requests can be finalized
        TypedSigningRequest {
            request_id: self.request_id,
            _state: PhantomData,
        }
    }
}

// This won't compile (type safety):
let request: TypedSigningRequest<Pending> = create_request();
let finalized = request.finalize(tx_id);  // ❌ Type error
```

**Benefits**:
- Impossible states are unrepresentable
- State transitions checked at compile time
- Self-documenting state machine

**Trade-offs**:
- More complex type signatures
- Harder to store heterogeneous collections
- May need trait objects for storage

**Implementation Priority**: LOW (Nice-to-have)
**Effort**: 4-5 days
**Impact**: Compile-time correctness guarantees

---

## 5. Error Handling Enhancements

### 5.1 Add Error Context Chain

**Current State**: Errors lose context as they propagate

**Issue**: Hard to diagnose root cause in production

**Recommendation**: Implement error context chaining

```rust
// New: igra-core/src/error/context.rs
use std::fmt;

pub struct ErrorChain {
    errors: Vec<String>,
}

impl ErrorChain {
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    pub fn push(&mut self, msg: String) {
        self.errors.push(msg);
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.errors.iter().map(|s| s.as_str())
    }
}

impl fmt::Display for ErrorChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, error) in self.errors.iter().enumerate() {
            if i > 0 {
                write!(f, "\n  caused by: ")?;
            }
            write!(f, "{}", error)?;
        }
        Ok(())
    }
}

// Extend ThresholdError
#[derive(Debug, Error)]
pub enum ThresholdError {
    // ... existing variants

    #[error("{msg}\n{chain}")]
    Chained {
        msg: String,
        chain: ErrorChain,
    },
}

// Helper trait
pub trait ErrorContext<T> {
    fn context(self, msg: impl Into<String>) -> Result<T, ThresholdError>;
}

impl<T, E: std::error::Error> ErrorContext<T> for Result<T, E> {
    fn context(self, msg: impl Into<String>) -> Result<T, ThresholdError> {
        self.map_err(|e| {
            let mut chain = ErrorChain::new();
            chain.push(e.to_string());
            ThresholdError::Chained {
                msg: msg.into(),
                chain,
            }
        })
    }
}

// Usage:
fn store_event(event: SigningEvent) -> Result<(), ThresholdError> {
    let serialized = serialize(&event)
        .context("failed to serialize event")?;

    db.put(key, serialized)
        .context(format!("failed to store event {}", event.event_id))?;

    Ok(())
}

// Error output:
// failed to store event test-event-001
//   caused by: database write failed
//   caused by: disk full
```

**Implementation Priority**: MEDIUM
**Effort**: 2-3 days
**Impact**: Dramatically improved error diagnostics

---

### 5.2 Structured Error Reporting

**Current State**: Errors converted to strings, losing structure

**Recommendation**: Preserve error structure for better observability

```rust
// New: igra-core/src/error/structured.rs
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StructuredError {
    pub code: ErrorCode,
    pub message: String,
    pub timestamp_nanos: u64,
    pub context: ErrorDetails,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ErrorDetails {
    EventReplayed {
        event_hash: String,
        first_seen: u64,
    },
    PolicyViolation {
        rule: String,
        actual_value: String,
        expected_value: String,
    },
    StorageError {
        operation: String,
        key: String,
        inner_error: String,
    },
    NetworkError {
        peer_id: String,
        failure_reason: String,
    },
    // ... other variants
}

impl From<ThresholdError> for StructuredError {
    fn from(err: ThresholdError) -> Self {
        let code = err.code();
        let message = err.to_string();
        let timestamp_nanos = now_nanos();
        let context = match err {
            ThresholdError::EventReplayed(hash) => {
                ErrorDetails::EventReplayed {
                    event_hash: hash,
                    first_seen: 0,  // Could track this
                }
            }
            ThresholdError::VelocityLimitExceeded { current, limit } => {
                ErrorDetails::PolicyViolation {
                    rule: "max_daily_volume".to_string(),
                    actual_value: current.to_string(),
                    expected_value: format!("<= {}", limit),
                }
            }
            // ... other mappings
            _ => ErrorDetails::Generic { message: message.clone() },
        };

        StructuredError {
            code,
            message,
            timestamp_nanos,
            context,
        }
    }
}

// Usage in RPC/API responses:
#[derive(Serialize)]
struct ErrorResponse {
    success: false,
    error: StructuredError,
}

// Client can parse and handle specific error types
```

**Implementation Priority**: MEDIUM
**Effort**: 2 days
**Impact**: Better observability and error handling for clients

---

## 6. Testing Infrastructure

### 6.1 Property-Based Testing

**Current State**: Unit and integration tests are comprehensive

**Recommendation**: Add property-based tests for critical invariants

```rust
// New: igra-core/tests/proptest/coordination.rs
use proptest::prelude::*;

// Generate arbitrary valid SigningEvents
fn arb_signing_event() -> impl Strategy<Value = SigningEvent> {
    (
        any::<String>(),
        1u64..1_000_000_000,
        any::<String>(),
    ).prop_map(|(event_id, amount, destination)| {
        SigningEvent {
            event_id,
            event_source: EventSource::Manual {
                operator: "test".to_string(),
            },
            derivation_path: "m/44'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: destination,
            amount_sompi: amount,
            metadata: BTreeMap::new(),
            timestamp_nanos: now_nanos(),
            signature: None,
        }
    })
}

proptest! {
    #[test]
    fn event_hash_is_deterministic(event in arb_signing_event()) {
        // Property: Hashing same event twice produces same hash
        let hash1 = event_hash(&event).unwrap();
        let hash2 = event_hash(&event).unwrap();
        prop_assert_eq!(hash1, hash2);
    }

    #[test]
    fn volume_tracking_never_overflows(events in prop::collection::vec(arb_signing_event(), 1..100)) {
        // Property: Volume accumulation never panics, uses saturating_add
        let storage = RocksStorage::open_in_memory().unwrap();
        let timestamp = now_nanos();

        for event in events {
            let _ = storage.add_to_daily_volume(event.amount_sompi, timestamp);
        }

        let total = storage.get_volume_since(timestamp).unwrap();
        prop_assert!(total < u64::MAX);  // Never overflowed
    }

    #[test]
    fn threshold_counting_is_consistent(
        sigs in prop::collection::vec(arb_partial_sig(), 1..50),
        threshold in 1u16..10,
        input_count in 1usize..20,
    ) {
        // Property: has_threshold is monotonic
        // More signatures => can only go from false to true, never reverse

        let mut met = false;
        for i in 0..sigs.len() {
            let partial_sigs = &sigs[..=i];
            let current = has_threshold(partial_sigs, input_count, threshold as usize);

            if met {
                prop_assert!(current, "threshold should remain met");
            }
            met = current;
        }
    }
}
```

**Implementation Priority**: MEDIUM
**Effort**: 3-4 days
**Impact**: Find edge cases and invariant violations

---

### 6.2 Chaos Engineering Tests

**Current State**: Byzantine fault tests exist

**Recommendation**: Add systematic chaos testing

```rust
// New: igra-service/tests/chaos/mod.rs
pub struct ChaosScenario {
    network_partition: bool,
    packet_loss_percent: u8,
    clock_skew_ms: i64,
    peer_crash_probability: f64,
}

#[tokio::test]
async fn chaos_test_coordinator_resilience() {
    let scenarios = vec![
        ChaosScenario {
            network_partition: true,
            packet_loss_percent: 30,
            clock_skew_ms: 1000,
            peer_crash_probability: 0.1,
        },
        // ... more scenarios
    ];

    for scenario in scenarios {
        let mut harness = ChaosHarness::new(scenario).await;

        // Run coordination through chaos
        let result = harness.run_coordination_with_chaos(Duration::from_secs(60)).await;

        // Assert safety properties maintained
        assert!(result.no_double_spend);
        assert!(result.all_finalized_txs_valid);
        assert!(result.threshold_respected);
    }
}
```

**Implementation Priority**: LOW
**Effort**: 5-7 days
**Impact**: Confidence in production resilience

---

### 6.3 Benchmark Suite

**Current State**: No systematic benchmarks

**Recommendation**: Add criterion.rs benchmarks

```rust
// New: igra-core/benches/coordination.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_event_hash(c: &mut Criterion) {
    let event = create_test_event();
    c.bench_function("event_hash", |b| {
        b.iter(|| {
            event_hash(black_box(&event))
        });
    });
}

fn benchmark_signature_verification(c: &mut Criterion) {
    let (keypair, message) = setup_signature_test();
    let signature = sign(&keypair, &message);

    c.bench_function("signature_verify", |b| {
        b.iter(|| {
            verify(black_box(&keypair.public), black_box(&message), black_box(&signature))
        });
    });
}

fn benchmark_storage_operations(c: &mut Criterion) {
    let storage = RocksStorage::open_in_memory().unwrap();
    let event = create_test_event();
    let event_hash = compute_hash(&event);

    let mut group = c.benchmark_group("storage");

    group.bench_function("insert_event", |b| {
        b.iter(|| {
            storage.insert_event(black_box(event_hash), black_box(event.clone()))
        });
    });

    group.bench_function("get_event", |b| {
        b.iter(|| {
            storage.get_event(black_box(&event_hash))
        });
    });

    group.finish();
}

criterion_group!(benches, benchmark_event_hash, benchmark_signature_verification, benchmark_storage_operations);
criterion_main!(benches);
```

**Add to Cargo.toml**:
```toml
[[bench]]
name = "coordination"
harness = false

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
```

**Implementation Priority**: MEDIUM
**Effort**: 2-3 days
**Impact**: Performance regression detection

---

## 7. Developer Experience

### 7.1 Comprehensive Examples

**Current State**: Limited examples

**Recommendation**: Add examples/ directory with complete workflows

```
igra-core/examples/
├── basic_coordination.rs      # Simple 2-of-3 signing
├── policy_enforcement.rs      # Policy configuration
├── custom_transport.rs        # Implementing Transport trait
├── storage_migration.rs       # Database migration example
└── monitoring_integration.rs  # Metrics and observability

igra-service/examples/
├── standalone_service.rs      # Running as standalone service
├── embedded_coordinator.rs    # Embedding in larger application
├── custom_event_source.rs     # Integrating custom bridge
└── ha_deployment.rs           # High-availability setup
```

**Example Structure**:
```rust
// igra-core/examples/basic_coordination.rs
//! Basic threshold signing example
//!
//! This example demonstrates:
//! - Creating a 2-of-3 threshold group
//! - Proposing a transaction
//! - Collecting signatures
//! - Finalizing the transaction
//!
//! Run with: cargo run --example basic_coordination

use igra_core::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic Threshold Coordination ===\n");

    // Step 1: Initialize storage
    println!("1. Creating in-memory storage...");
    let storage = storage::in_memory::InMemoryStorage::new();

    // Step 2: Create test keypairs
    println!("2. Generating 3 keypairs for 2-of-3 signing...");
    let keypairs = generate_test_keypairs(3);

    // Step 3: Configure group
    println!("3. Configuring threshold group...");
    let group_config = GroupConfig::builder()
        .threshold(2, 3)
        .network_id(11)  // Testnet
        .member_pubkeys(extract_pubkeys(&keypairs))
        .with_testnet_defaults()
        .build()?;

    // ... continue with full example

    Ok(())
}
```

**Implementation Priority**: HIGH
**Effort**: 3-4 days
**Impact**: Reduced onboarding time for new developers

---

### 7.2 Interactive Debugging Tools

**Current State**: CLI has audit mode, but limited

**Recommendation**: Enhanced debugging commands

```rust
// Extend igra-service/src/bin/kaspa-threshold-service/cli.rs

#[derive(Parser)]
pub enum DebugCommand {
    /// Inspect a specific request
    InspectRequest {
        #[arg(long)]
        request_id: String,
    },

    /// List all active sessions
    ListSessions,

    /// Show volume tracking data
    ShowVolume {
        #[arg(long)]
        since_days: Option<u64>,
    },

    /// Verify database integrity
    VerifyDatabase,

    /// Export request as JSON for replay
    ExportRequest {
        #[arg(long)]
        request_id: String,

        #[arg(long)]
        output: PathBuf,
    },

    /// Replay a request from JSON
    ReplayRequest {
        #[arg(long)]
        input: PathBuf,
    },
}

// Implementation
async fn handle_debug_command(cmd: DebugCommand, storage: &dyn Storage) -> Result<(), Error> {
    match cmd {
        DebugCommand::InspectRequest { request_id } => {
            let request = storage.get_request(&RequestId::from(request_id))?;
            let inputs = storage.list_request_inputs(&request.request_id)?;
            let acks = storage.list_signer_acks(&request.request_id)?;
            let sigs = storage.list_partial_sigs(&request.request_id)?;

            println!("Request Details:");
            println!("  ID: {}", request.request_id);
            println!("  Decision: {:?}", request.decision);
            println!("  Inputs: {}", inputs.len());
            println!("  Acks: {} / {}", acks.iter().filter(|a| a.accept).count(), acks.len());
            println!("  Signatures: {}", sigs.len());

            // ... detailed output
        }
        // ... other commands
    }
}
```

**Implementation Priority**: MEDIUM
**Effort**: 2-3 days
**Impact**: Faster debugging in production

---

### 7.3 Development Docker Compose

**Current State**: No docker-compose for development

**Recommendation**: Add docker-compose.yml for local testing

```yaml
# New: docker-compose.yml
version: '3.8'

services:
  kaspad:
    image: kaspanet/kaspad:latest
    ports:
      - "16110:16110"  # RPC
      - "16111:16111"  # gRPC
    command: >
      --testnet
      --rpclisten=0.0.0.0:16110
      --grpclisten=0.0.0.0:16111
      --utxoindex
    volumes:
      - kaspad-data:/app/data

  coordinator-1:
    build: .
    environment:
      - KASPA_IGRA_PEER_ID=coord1
      - KASPA_NODE_RPC_URL=grpc://kaspad:16111
      - KASPA_IROH_BIND_PORT=9001
      - KASPA_IROH_BOOTSTRAP=coord2:9002,coord3:9003
    depends_on:
      - kaspad
    volumes:
      - coord1-data:/data

  coordinator-2:
    build: .
    environment:
      - KASPA_IGRA_PEER_ID=coord2
      - KASPA_NODE_RPC_URL=grpc://kaspad:16111
      - KASPA_IROH_BIND_PORT=9002
    depends_on:
      - kaspad
    volumes:
      - coord2-data:/data

  coordinator-3:
    build: .
    environment:
      - KASPA_IGRA_PEER_ID=coord3
      - KASPA_NODE_RPC_URL=grpc://kaspad:16111
      - KASPA_IROH_BIND_PORT=9003
    depends_on:
      - kaspad
    volumes:
      - coord3-data:/data

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards

volumes:
  kaspad-data:
  coord1-data:
  coord2-data:
  coord3-data:
  prometheus-data:
  grafana-data:
```

**Usage**:
```bash
# Start full development environment
docker-compose up -d

# View logs
docker-compose logs -f coordinator-1

# Shut down
docker-compose down
```

**Implementation Priority**: MEDIUM
**Effort**: 2 days
**Impact**: Simplified local development and testing

---

## 8. Operational Improvements

### 8.1 Prometheus Metrics

**Current State**: Basic metrics exist in `metrics.rs`

**Recommendation**: Comprehensive Prometheus metrics

```rust
// Extend igra-service/src/service/metrics.rs
use prometheus::{
    Registry, Counter, Gauge, Histogram, HistogramOpts,
    Opts, core::Collector,
};

pub struct Metrics {
    registry: Registry,

    // Counters
    proposals_total: Counter,
    proposals_accepted: Counter,
    proposals_rejected: Counter,
    signatures_created: Counter,
    transactions_finalized: Counter,
    errors_total: Counter,

    // Gauges
    active_sessions: Gauge,
    pending_requests: Gauge,
    storage_size_bytes: Gauge,

    // Histograms
    proposal_validation_duration: Histogram,
    signature_creation_duration: Histogram,
    finalization_duration: Histogram,
    rpc_request_duration: Histogram,
}

impl Metrics {
    pub fn new() -> Result<Self, MetricsError> {
        let registry = Registry::new();

        let proposals_total = Counter::with_opts(
            Opts::new("igra_proposals_total", "Total number of proposals")
        )?;
        registry.register(Box::new(proposals_total.clone()))?;

        let proposal_validation_duration = Histogram::with_opts(
            HistogramOpts::new(
                "igra_proposal_validation_duration_seconds",
                "Time to validate proposal"
            ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
        )?;
        registry.register(Box::new(proposal_validation_duration.clone()))?;

        // ... register all metrics

        Ok(Self {
            registry,
            proposals_total,
            // ... initialize all fields
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    // Timed helper
    pub fn time_proposal_validation<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let timer = self.proposal_validation_duration.start_timer();
        let result = f();
        timer.observe_duration();
        result
    }
}

// Expose metrics endpoint in JSON RPC server
async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> String {
    use prometheus::Encoder;

    let encoder = prometheus::TextEncoder::new();
    let metric_families = metrics.registry().gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
```

**Grafana Dashboard**:
```json
// grafana/dashboards/igra-coordination.json
{
  "dashboard": {
    "title": "Igra Threshold Signing",
    "panels": [
      {
        "title": "Proposal Rate",
        "targets": [
          {
            "expr": "rate(igra_proposals_total[5m])"
          }
        ]
      },
      {
        "title": "Success Rate",
        "targets": [
          {
            "expr": "rate(igra_transactions_finalized[5m]) / rate(igra_proposals_total[5m])"
          }
        ]
      },
      {
        "title": "P95 Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, igra_proposal_validation_duration_seconds_bucket)"
          }
        ]
      }
    ]
  }
}
```

**Implementation Priority**: HIGH
**Effort**: 3 days
**Impact**: Production observability

---

### 8.2 Health Check Endpoint

**Current State**: Basic health check exists

**Recommendation**: Comprehensive health checks

```rust
// New: igra-service/src/api/health.rs
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub checks: Vec<HealthCheck>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

pub async fn health_check(
    storage: Arc<dyn Storage>,
    rpc: Arc<dyn NodeRpc>,
    transport: Arc<dyn Transport>,
) -> HealthResponse {
    let mut checks = Vec::new();

    // Check storage
    let storage_check = check_storage(storage.as_ref()).await;
    checks.push(storage_check);

    // Check RPC connection
    let rpc_check = check_rpc(rpc.as_ref()).await;
    checks.push(rpc_check);

    // Check transport
    let transport_check = check_transport(transport.as_ref()).await;
    checks.push(transport_check);

    // Determine overall status
    let status = if checks.iter().any(|c| matches!(c.status, CheckStatus::Fail)) {
        HealthStatus::Unhealthy
    } else if checks.iter().any(|c| matches!(c.status, CheckStatus::Warn)) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    HealthResponse {
        status,
        checks,
        timestamp: now_nanos(),
    }
}

async fn check_storage(storage: &dyn Storage) -> HealthCheck {
    let start = Instant::now();
    let result = storage.health_check().await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(()) => HealthCheck {
            name: "storage".to_string(),
            status: CheckStatus::Pass,
            message: None,
            latency_ms: Some(latency_ms),
        },
        Err(e) => HealthCheck {
            name: "storage".to_string(),
            status: CheckStatus::Fail,
            message: Some(e.to_string()),
            latency_ms: Some(latency_ms),
        },
    }
}

// Kubernetes liveness probe:
// GET /health -> 200 if Healthy, 503 if Degraded/Unhealthy

// Kubernetes readiness probe:
// GET /health/ready -> 200 if Healthy, 503 otherwise
```

**Implementation Priority**: HIGH
**Effort**: 1-2 days
**Impact**: Better Kubernetes integration

---

### 8.3 Structured Logging

**Current State**: Using tracing crate (good), but could be more structured

**Recommendation**: Add structured logging context

```rust
// Use tracing spans and fields more consistently
use tracing::{info_span, instrument};

#[instrument(
    skip(storage, transport),
    fields(
        request_id = %request_id,
        session_id = %session_id,
        coordinator = %coordinator_peer_id
    )
)]
async fn process_proposal(
    storage: Arc<dyn Storage>,
    transport: Arc<dyn Transport>,
    request_id: RequestId,
    session_id: SessionId,
    coordinator_peer_id: PeerId,
    proposal: SigningEventPropose,
) -> Result<(), ThresholdError> {
    let span = info_span!("validate_proposal");
    let _enter = span.enter();

    tracing::info!(
        event_hash = %hex::encode(proposal.event_hash),
        amount_sompi = proposal.signing_event.amount_sompi,
        "processing proposal"
    );

    // ... processing

    tracing::info!(
        accepted = ack.accept,
        validation_time_ms = elapsed.as_millis(),
        "proposal validated"
    );

    Ok(())
}

// Configure JSON logging for production
// Add to setup.rs:
pub fn init_logging(level: &str) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::{fmt, EnvFilter};

    let format = if std::env::var("KASPA_LOG_FORMAT").unwrap_or_default() == "json" {
        fmt::format().json()
    } else {
        fmt::format()
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level))
        .event_format(format)
        .init();

    Ok(())
}
```

**Implementation Priority**: MEDIUM
**Effort**: 2 days
**Impact**: Better log aggregation and analysis

---

## 9. Documentation

### 9.1 Architecture Decision Records (ADRs)

**Recommendation**: Document key architectural decisions

```
docs/adr/
├── 0001-use-rocksdb-for-storage.md
├── 0002-iroh-gossip-for-transport.md
├── 0003-column-families-for-data-separation.md
├── 0004-merge-operator-for-volume-tracking.md
└── 0005-rate-limiting-strategy.md
```

**Template**:
```markdown
# ADR-0003: Use RocksDB Column Families for Data Separation

## Status
Accepted (2025-12-31)

## Context
Initially, all data was stored in the default RocksDB column family using key prefixes (grp:, evt:, req:, etc.). This approach:
- Made it difficult to tune performance per data type
- Limited ability to apply different compression/bloom filter settings
- Made backup/restore more complex

## Decision
Implement separate column families for each data type:
- CF_GROUP: Group configurations
- CF_EVENT: Signing events
- CF_REQUEST: Signing requests
- CF_VOLUME: Volume tracking (with merge operator)
- etc.

## Consequences
### Positive
- Better performance tuning per data type
- Easier to implement retention policies
- Cleaner separation of concerns
- Migration path implemented for existing data

### Negative
- Slightly more complex initialization
- Need to handle migration from old format

### Neutral
- Minimal API changes due to abstraction layer
```

**Implementation Priority**: LOW
**Effort**: 2-3 days
**Impact**: Knowledge preservation

---

### 9.2 API Documentation

**Recommendation**: Generate and publish API docs

```bash
# Add to Makefile or scripts/
.PHONY: docs
docs:
	cargo doc --workspace --no-deps --open

.PHONY: docs-private
docs-private:
	cargo doc --workspace --no-deps --document-private-items --open

# Publish to GitHub Pages
.PHONY: docs-publish
docs-publish:
	cargo doc --workspace --no-deps
	echo '<meta http-equiv="refresh" content="0;url=igra_core/index.html">' > target/doc/index.html
	gh-pages -d target/doc
```

**Add comprehensive module docs**:
```rust
//! # igra-core
//!
//! Core library for Kaspa threshold signing coordination.
//!
//! ## Overview
//!
//! This library implements a decentralized threshold signing protocol for Kaspa blockchain.
//! It provides the core building blocks for coordinating m-of-n multisig transactions.
//!
//! ## Architecture
//!
//! The library is organized into several modules:
//!
//! - [`coordination`]: Core coordination logic (proposals, signing, finalization)
//! - [`storage`]: Persistent storage abstraction with RocksDB implementation
//! - [`transport`]: P2P message transport abstraction
//! - [`pskt`]: PSKT (Partially Signed Kaspa Transaction) handling
//! - [`config`]: Configuration management
//! - [`model`]: Core data structures
//! - [`error`]: Error types and handling
//!
//! ## Quick Start
//!
//! ```rust
//! use igra_core::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create storage
//! let storage = storage::rocks::RocksStorage::open("./data")?;
//!
//! // Create transport (implement Transport trait)
//! let transport = create_transport()?;
//!
//! // Create coordinator
//! let coordinator = coordination::Coordinator::new(
//!     Arc::new(transport),
//!     Arc::new(storage),
//! );
//!
//! // Propose a transaction
//! let event_hash = coordinator.propose_session(
//!     rpc,
//!     &pskt_config,
//!     session_id,
//!     request_id,
//!     signing_event,
//!     expires_at_nanos,
//!     coordinator_peer_id,
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - **Threshold Signing**: m-of-n Schnorr signatures
//! - **Replay Protection**: Three-layer defense (event hash, sequence numbers, transport)
//! - **Policy Enforcement**: Configurable transaction policies
//! - **Rate Limiting**: DoS protection with token bucket algorithm
//! - **Audit Trail**: Comprehensive audit logging
//!
//! ## Security
//!
//! See [docs/security/SECURITY_AUDIT.md](../../security/SECURITY_AUDIT.md) for security analysis and
//! [docs/security/SECURITY_FIXES_IMPLEMENTED.md](../../security/SECURITY_FIXES_IMPLEMENTED.md) for implemented fixes.

pub mod coordination;
pub mod storage;
// ... etc
```

**Implementation Priority**: MEDIUM
**Effort**: 3-4 days
**Impact**: Easier onboarding, better API discoverability

---

### 9.3 Runbook for Operations

**Recommendation**: Create operational runbook

```markdown
# Igra Operations Runbook

## Common Operations

### Checking System Health
```bash
# Check service health
curl http://localhost:8080/health | jq

# Check metrics
curl http://localhost:8080/metrics | grep igra_

# View recent logs
journalctl -u igra-coordinator -n 100 -f
```

### Debugging a Stuck Request
```bash
# Inspect request status
igra-service debug inspect-request --request-id req_abc123

# Check signatures received
igra-service debug list-signatures --request-id req_abc123

# View audit trail
igra-service audit --request-id req_abc123
```

### Database Maintenance
```bash
# Create backup
igra-service debug backup --output /backups/igra-$(date +%Y%m%d).bak

# Compact database
igra-service debug compact

# Check database size
du -sh /var/lib/igra/threshold-signing/
```

## Incident Response

### Service Won't Start
1. Check logs: `journalctl -u igra-coordinator -n 50`
2. Verify configuration: `igra-service config validate`
3. Check database: `igra-service debug verify-database`
4. Verify connectivity to kaspad: `grpcurl kaspad:16111 list`

### High Error Rate
1. Check Grafana dashboard for error types
2. Review recent audit events: `igra-service audit --since 1h`
3. Check rate limiting: Look for `RateLimitExceeded` events
4. Verify peer connectivity

### Performance Degradation
1. Check database size and compact if needed
2. Review metrics: CPU, memory, disk I/O
3. Check for slow queries in logs
4. Verify network latency to peers

## Recovery Procedures

### Restore from Backup
```bash
# Stop service
systemctl stop igra-coordinator

# Restore database
rm -rf /var/lib/igra/threshold-signing/*
tar xzf /backups/igra-20251231.tar.gz -C /var/lib/igra/

# Verify restoration
igra-service debug verify-database

# Start service
systemctl start igra-coordinator
```
```

**Implementation Priority**: HIGH
**Effort**: 2 days
**Impact**: Reduced incident response time

---

## 10. Implementation Roadmap

### Phase 1: High Priority (Weeks 1-2)
**Total Effort**: ~7-8 days

1. **Create Common Test Utilities** (2-3 days)
   - Extract test helpers into `tests/common/`
   - Reduce duplication across test files

2. **Add Comprehensive Examples** (3-4 days)
   - Basic coordination example
   - Policy enforcement example
   - Custom transport example

3. **Implement Health Check Endpoint** (1-2 days)
   - Comprehensive health checks
   - Kubernetes integration

4. **Add Prometheus Metrics** (3 days)
   - Complete metrics suite
   - Grafana dashboards

### Phase 2: Medium Priority (Weeks 3-4)
**Total Effort**: ~10-12 days

1. **Reduce Dynamic Dispatch** (3-4 days)
   - Convert traits to generics
   - Benchmark performance improvements

2. **Split Large Test Files** (1 day)
   - Reorganize `failure_scenarios.rs`
   - Group by failure type

3. **Add Property-Based Tests** (3-4 days)
   - Test invariants
   - Edge case discovery

4. **Implement Error Context Chain** (2-3 days)
   - Better error diagnostics
   - Structured error reporting

5. **Add Strong Hash Types** (3-4 days)
   - Convert Hash32 to newtypes
   - Compile-time type safety

### Phase 3: Low Priority (Weeks 5-6)
**Total Effort**: ~12-15 days

1. **Add Benchmark Suite** (2-3 days)
   - Criterion.rs benchmarks
   - Performance tracking

2. **Simplify ServiceFlow** (2-3 days)
   - Merge or clarify responsibilities
   - Reduce indirection

3. **Optimize Clone Operations** (2-3 days)
   - Use Arc and Cow where appropriate
   - Reduce allocations

4. **Add Configuration Builder** (2 days)
   - Fluent configuration API
   - Better validation

5. **Create ADR Documentation** (2-3 days)
   - Document key decisions
   - Knowledge preservation

6. **Add Docker Compose** (2 days)
   - Development environment
   - Integration testing

### Phase 4: Optional Enhancements (Weeks 7-8)
**Total Effort**: ~10-12 days

1. **Optimize Database Operations** (3-4 days)
   - Add caching layer
   - Bloom filters

2. **Add Chaos Tests** (5-7 days)
   - Network partitions
   - Byzantine faults

3. **Implement Type-State Pattern** (4-5 days)
   - Compile-time state machine
   - Zero invalid states

4. **Zero-Copy Serialization** (3-5 days)
   - Profile hot paths
   - Optimize critical structures

---

## Summary of Recommendations

### Immediate Actions (Do First)
1. ✅ **Create common test utilities** - Eliminate duplication
2. ✅ **Add comprehensive examples** - Improve onboarding
3. ✅ **Implement health checks** - Production readiness
4. ✅ **Add Prometheus metrics** - Observability

### High Value (Do Soon)
1. **Reduce dynamic dispatch** - Performance improvement
2. **Add property-based tests** - Find edge cases
3. **Implement error context** - Better debugging
4. **Strong hash types** - Type safety

### Nice to Have (Do Later)
1. **Benchmark suite** - Performance tracking
2. **Configuration builder** - Better DX
3. **ADR documentation** - Knowledge preservation
4. **Docker compose** - Simplified development

### Optional Enhancements
1. **Database caching** - Performance optimization
2. **Chaos testing** - Resilience validation
3. **Type-state pattern** - Compile-time correctness
4. **Zero-copy serialization** - Performance optimization

---

## Metrics for Success

### Code Quality
- **Test Coverage**: Maintain > 80%
- **Documentation**: All public APIs documented
- **Code Duplication**: < 5% (currently higher in tests)
- **Cyclomatic Complexity**: < 10 per function average

### Performance
- **Proposal Validation**: < 10ms p95
- **Signature Creation**: < 50ms p95
- **Finalization**: < 100ms p95
- **Database Operations**: < 5ms p95

### Reliability
- **Uptime**: > 99.9%
- **Error Rate**: < 0.1%
- **Recovery Time**: < 5 minutes
- **Data Durability**: 100%

### Developer Experience
- **Onboarding Time**: < 1 day for basic contribution
- **Build Time**: < 2 minutes (clean build)
- **Test Run Time**: < 5 minutes (full suite)
- **Documentation Coverage**: 100% of public APIs

---

## Conclusion

The igra threshold signing codebase is already well-architected with excellent security posture post-fixes. These recommendations focus on incremental improvements to:

1. **Simplify architecture** - Reduce complexity where possible
2. **Improve performance** - Optimize hot paths and reduce allocations
3. **Enhance maintainability** - Better organization and documentation
4. **Boost developer experience** - Examples, tools, and utilities
5. **Strengthen operations** - Observability and operational tooling

The phased approach allows for incremental implementation while maintaining system stability. Priority should be given to high-value improvements that provide immediate benefits.

**Overall Assessment**: The codebase is production-ready with the security fixes implemented. These improvements will make it more maintainable, performant, and developer-friendly over time.

---

**Document Version**: 1.0
**Date**: 2025-12-31
**Status**: Review Ready
**Next Review**: 2025-Q2
