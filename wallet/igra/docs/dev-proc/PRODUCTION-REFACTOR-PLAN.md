# Production Refactoring Plan - Complete Domain/Infrastructure Separation

**Goal**: Full production-ready refactoring per ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md
**Strategy**: Move all code, delete duplicates, clean imports, no shims
**Timeline**: 3-5 days with careful execution

---

## Current State Analysis

### ✅ What's Already Done (Great Progress!)

**Domain layer** (1898 lines):
- ✅ `domain/pskt/` - PSKT building (17K lines, complete)
- ✅ `domain/signing/` - Signing protocols (moved)
- ✅ `domain/event/` - Event validation (122 lines)
- ✅ `domain/hashes.rs` - Hash functions
- ✅ `domain/state_machine.rs` - Request FSM
- ⚠️ `domain/coordination/` - Has structure but not pure logic yet
- ⚠️ `domain/policy/` - Has structure
- ⚠️ `domain/audit/` - Has structure

**Infrastructure layer** (4284 lines):
- ✅ `infrastructure/storage/` - RocksDB implementation (moved)
- ✅ `infrastructure/transport/` - P2P transport (moved)
- ✅ `infrastructure/coordination/` - Coordinator/Signer (DUPLICATES of old)
- ✅ `infrastructure/rpc/` - RPC client
- ✅ `infrastructure/config/` - Configuration loading
- ✅ `infrastructure/event/` - Event ingestion
- ✅ `infrastructure/hyperlane/` - Cross-chain verification

**Foundation layer** (550 lines):
- ✅ `foundation/error.rs` - Error types
- ✅ `foundation/types.rs` - Type aliases
- ✅ `foundation/constants.rs` - Constants
- ✅ `foundation/util/` - Utilities

**Application layer** (16 lines):
- ❌ Only re-exports (shims) - needs real orchestration

### ❌ What Still Needs Cleanup

**Duplicates to resolve**:
- `/coordination/coordinator.rs` (5602 lines) **SAME AS** `/infrastructure/coordination/coordinator.rs` (153 lines WRONG - actually 5602)
- `/coordination/signer.rs` (11538 lines) **SAME AS** `/infrastructure/coordination/signer.rs` (344 lines WRONG - actually same)

**Legacy top-level files** (need to move or delete):
- `model.rs` (133 lines) - domain types, should go to `domain/model.rs`
- `lifecycle.rs` (113 lines) - observer trait, should go to `application/lifecycle.rs` or `foundation/`
- `hd.rs` (106 lines) - HD key derivation, should go to `foundation/util/hd.rs`
- `group_id.rs` (35 lines) - should go to `foundation/types/group_id.rs`

**Legacy shim files** (1-line re-exports, DELETE after migration):
- `constants.rs`, `error.rs`, `types.rs`, `state_machine.rs`
- `pskt/` directory (deleted already ✅)
- `signing/` directory (deleted already ✅)
- `storage/mod.rs` (shim to infrastructure)

**Legacy directories** (to delete):
- `coordination/` - will be empty after moving to application
- `rpc/` - shim only
- `transport/` - shim only
- `util/` - shim to foundation

---

## The Problem: Application Layer Confusion

**Current**: application/ re-exports infrastructure/coordination:
```rust
// application/coordinator.rs
pub use crate::infrastructure::coordination::coordinator::Coordinator; // ❌ WRONG
```

**Target per ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md**:
```
application/           # Orchestration (uses domain + infrastructure)
    ↓ depends on
domain/                # Pure business logic (no I/O)
infrastructure/        # I/O operations (storage, RPC, transport)
    ↓ depends on
foundation/            # Shared primitives
```

**Issue**: Coordinator/Signer are APPLICATION ORCHESTRATION, not infrastructure!

They:
- Use Storage (infrastructure)
- Use Transport (infrastructure)
- Use RPC (infrastructure)
- Apply business rules (domain)
- **Orchestrate workflows** ← This is APPLICATION LAYER

---

## Architecture Decision: Where Does Coordinator/Signer Go?

### Analysis

**Coordinator/Signer contain**:
- Infrastructure dependencies (Storage, Transport, RPC) ✅
- Calls to domain logic (event_hash, validation) ✅
- Workflow orchestration (propose → validate → sign → finalize) ✅
- Lifecycle hooks (observability) ✅

**Per ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md**:
> Application layer combines domain + infrastructure, coordinates workflows

**Decision**: Coordinator/Signer belong in `application/`, not `infrastructure/coordination/`

---

## Complete Refactoring Plan

### Phase 1: Clean Up Duplicates (Day 1 Morning)

**Goal**: Remove duplicate coordinator/signer files

#### Step 1: Delete Duplicate in infrastructure/coordination

```bash
# These are duplicates - delete them
rm igra-core/src/infrastructure/coordination/coordinator.rs
rm igra-core/src/infrastructure/coordination/signer.rs

# Keep monitoring.rs (it's infrastructure - rate limiting/observability)
# Keep mod.rs
```

#### Step 2: Update infrastructure/coordination/mod.rs

**File**: `igra-core/src/infrastructure/coordination/mod.rs`

**Change from**:
```rust
pub mod coordinator;
pub mod signer;
pub mod monitoring;
```

**Change to**:
```rust
//! Infrastructure coordination utilities (monitoring, metrics)
pub mod monitoring;

pub use monitoring::TransactionMonitor;
```

#### Step 3: Verify compiles

```bash
cargo build --package igra-core
# Should fail with "cannot find Coordinator/Signer" - expected!
```

---

### Phase 2: Move Coordinator/Signer to Application (Day 1 Afternoon)

**Goal**: Move real orchestration to application layer

#### Step 4: Move coordinator to application

```bash
# Move the REAL coordinator
mv igra-core/src/coordination/coordinator.rs igra-core/src/application/coordinator.rs
```

#### Step 5: Update application/coordinator.rs imports

**File**: `igra-core/src/application/coordinator.rs`

**Find and replace** (in this order):

```bash
# In the file, change imports from old paths to new paths:

# OLD → NEW
use crate::config::          → use crate::infrastructure::config::
use crate::storage::Storage  → use crate::infrastructure::storage::Storage
use crate::transport::       → use crate::infrastructure::transport::
use crate::rpc::NodeRpc      → use crate::infrastructure::rpc::NodeRpc
use crate::lifecycle::       → use crate::application::lifecycle::
use crate::model::           → use crate::domain::model::
use crate::pskt::            → use crate::domain::pskt::
use crate::types::           → use crate::foundation::types::
use crate::error::           → use crate::foundation::error::
```

**Automated approach**:
```bash
cd igra-core/src/application

# Replace imports (macOS sed)
sed -i '' 's|use crate::config::|use crate::infrastructure::config::|g' coordinator.rs
sed -i '' 's|use crate::storage::|use crate::infrastructure::storage::|g' coordinator.rs
sed -i '' 's|use crate::transport::|use crate::infrastructure::transport::|g' coordinator.rs
sed -i '' 's|use crate::rpc::|use crate::infrastructure::rpc::|g' coordinator.rs
sed -i '' 's|use crate::lifecycle::|use crate::application::lifecycle::|g' coordinator.rs
sed -i '' 's|use crate::model::|use crate::domain::model::|g' coordinator.rs
sed -i '' 's|use crate::pskt::|use crate::domain::pskt::|g' coordinator.rs
sed -i '' 's|use crate::types::|use crate::foundation::types::|g' coordinator.rs
sed -i '' 's|use crate::error::|use crate::foundation::error::|g' coordinator.rs
```

#### Step 6: Update application/mod.rs

**File**: `igra-core/src/application/mod.rs`

**Change from**:
```rust
pub mod coordinator;
pub use coordinator::Coordinator;
```

**Change to**:
```rust
//! Application layer: orchestration that combines domain + infrastructure

pub mod coordinator;
pub mod signer;
pub mod event_processor;
pub mod lifecycle;

pub use coordinator::Coordinator;
pub use signer::Signer;
pub use event_processor::{EventContext, EventProcessor, submit_signing_event};
pub use lifecycle::{LifecycleObserver, NoopObserver};
```

#### Step 7: Move signer to application

```bash
# Move the REAL signer
mv igra-core/src/coordination/signer.rs igra-core/src/application/signer.rs
```

#### Step 8: Update application/signer.rs imports

Same sed commands as Step 5, but for `signer.rs`:

```bash
cd igra-core/src/application

sed -i '' 's|use crate::config::|use crate::infrastructure::config::|g' signer.rs
sed -i '' 's|use crate::storage::|use crate::infrastructure::storage::|g' signer.rs
sed -i '' 's|use crate::transport::|use crate::infrastructure::transport::|g' signer.rs
sed -i '' 's|use crate::rpc::|use crate::infrastructure::rpc::|g' signer.rs
sed -i '' 's|use crate::lifecycle::|use crate::application::lifecycle::|g' signer.rs
sed -i '' 's|use crate::model::|use crate::domain::model::|g' signer.rs
sed -i '' 's|use crate::pskt::|use crate::domain::pskt::|g' signer.rs
sed -i '' 's|use crate::signing::|use crate::domain::signing::|g' signer.rs
sed -i '' 's|use crate::types::|use crate::foundation::types::|g' signer.rs
sed -i '' 's|use crate::error::|use crate::foundation::error::|g' signer.rs
```

#### Step 9: Verify compiles

```bash
cargo build --package igra-core 2>&1 | grep error | head -20
```

**Fix any remaining import errors manually**

---

### Phase 3: Move Domain Types (Day 2 Morning)

**Goal**: Move top-level domain files into domain/

#### Step 10: Move model.rs to domain

```bash
# Move model types
mv igra-core/src/model.rs igra-core/src/domain/model.rs
```

#### Step 11: Update domain/mod.rs

**File**: `igra-core/src/domain/mod.rs`

**Change from**:
```rust
pub use crate::model;
```

**Change to**:
```rust
pub mod model;

// Re-export commonly used types at domain level
pub use model::{
    SigningEvent, SigningRequest, GroupPolicy, RequestDecision,
    Hash32, EventSource, StoredProposal, // ... others
};
```

#### Step 12: Create shim for model.rs (temporary)

**File**: `igra-core/src/model.rs` (CREATE NEW)

```rust
//! Legacy path - re-exports domain::model
//! TODO: Remove once all external imports updated
pub use crate::domain::model::*;
```

---

### Phase 4: Move Foundation Utilities (Day 2 Afternoon)

#### Step 13: Move hd.rs to foundation/util

```bash
mv igra-core/src/hd.rs igra-core/src/foundation/util/hd.rs
```

**Update `foundation/util/mod.rs`**:
```rust
pub mod conversion;
pub mod encoding;
pub mod time;
pub mod hd;  // ADD THIS

pub use hd::*;
```

**Create shim** `igra-core/src/hd.rs`:
```rust
pub use crate::foundation::util::hd::*;
```

#### Step 14: Move group_id.rs to foundation/types

```bash
mv igra-core/src/group_id.rs igra-core/src/foundation/types/group_id.rs
```

**Update `foundation/types.rs`** → **rename to `foundation/types/mod.rs`**:

```bash
# First, create types directory if needed
mkdir -p igra-core/src/foundation/types

# Move types.rs to types/mod.rs
mv igra-core/src/foundation/types.rs igra-core/src/foundation/types/mod.rs

# Move group_id
mv igra-core/src/group_id.rs igra-core/src/foundation/types/group_id.rs
```

**Update `foundation/types/mod.rs`**:
```rust
pub mod group_id;

// Original type aliases
pub type SessionId = [u8; 32];
pub type RequestId = String;
pub type PeerId = String;
// ... etc

pub use group_id::*;
```

**Create shim** `igra-core/src/group_id.rs`:
```rust
pub use crate::foundation::types::group_id::*;
```

#### Step 15: Move lifecycle.rs

**Decision needed**: Is lifecycle domain or application?

**Analysis**:
- `LifecycleObserver` trait - observability hooks
- Used by Coordinator/Signer for metrics/logging
- **Answer**: Application concern (observability)

```bash
mv igra-core/src/lifecycle.rs igra-core/src/application/lifecycle.rs
```

**Update `application/mod.rs`**:
```rust
pub mod lifecycle;
pub use lifecycle::{LifecycleObserver, NoopObserver};
```

**Create shim** `igra-core/src/lifecycle.rs`:
```rust
pub use crate::application::lifecycle::*;
```

---

### Phase 5: Update lib.rs and Remove Shims (Day 3)

#### Step 16: Clean up lib.rs

**File**: `igra-core/src/lib.rs`

**Current (messy)**:
```rust
pub use domain::audit;
pub mod constants;
pub mod config;
pub use domain::coordination;
pub mod application;
pub mod error;
pub mod foundation;
pub mod event;
pub mod group_id;
pub mod hd;
pub mod domain;
pub mod infrastructure;
pub mod hyperlane;
pub mod lifecycle;
pub mod model;
pub use domain::pskt;
pub mod rpc;
pub use domain::signing;
pub mod state_machine;
pub mod storage;
pub mod transport;
pub mod types;
pub mod validation;
pub use error::{Result, ThresholdError};
```

**Target (clean)**:
```rust
//! Igra Core - Threshold signing coordination
//!
//! Architecture:
//! - foundation: Shared primitives (types, errors, utilities)
//! - domain: Pure business logic (no I/O)
//! - infrastructure: I/O operations (storage, RPC, transport)
//! - application: Orchestration layer

// Core layers
pub mod foundation;
pub mod domain;
pub mod infrastructure;
pub mod application;

// Convenience re-exports
pub use foundation::{ThresholdError, Result};
pub use application::{Coordinator, Signer};

// Legacy compatibility shims (TODO: remove in next major version)
pub mod model {
    pub use crate::domain::model::*;
}
pub mod coordination {
    pub use crate::application::{Coordinator, Signer};
}
pub mod storage {
    pub use crate::infrastructure::storage::*;
}
pub mod rpc {
    pub use crate::infrastructure::rpc::*;
}
pub mod transport {
    pub use crate::infrastructure::transport::*;
}
pub mod config {
    pub use crate::infrastructure::config::*;
}
pub mod types {
    pub use crate::foundation::types::*;
}
pub mod error {
    pub use crate::foundation::error::*;
}
pub mod pskt {
    pub use crate::domain::pskt::*;
}
pub mod signing {
    pub use crate::domain::signing::*;
}
pub mod hd {
    pub use crate::foundation::util::hd::*;
}
pub mod lifecycle {
    pub use crate::application::lifecycle::*;
}
pub mod group_id {
    pub use crate::foundation::types::group_id::*;
}
```

#### Step 17: Delete old shim files

```bash
# Delete top-level shim files (they're now in lib.rs)
rm igra-core/src/constants.rs  # 1-line shim
rm igra-core/src/error.rs      # 1-line shim
rm igra-core/src/types.rs      # 1-line shim
rm igra-core/src/state_machine.rs  # 1-line shim

# Delete empty legacy directories
rm -rf igra-core/src/coordination/  # Now empty (moved to application)
rm -rf igra-core/src/util/          # Now shim in foundation
```

#### Step 18: Verify compilation

```bash
cargo clean
cargo build --package igra-core --package igra-service
```

**Fix any import errors in**:
- igra-service code
- Test files
- Binary files (bin/)

---

### Phase 6: Update igra-service (Day 3 Afternoon)

#### Step 19: Update service imports

**Files to update**: All files in `igra-service/src/`

**Strategy**: Search and replace imports

```bash
cd igra-service

# Find all .rs files and update imports
find src -name "*.rs" -exec sed -i '' \
  -e 's|use igra_core::coordination::|use igra_core::application::|g' \
  -e 's|use igra_core::model::|use igra_core::domain::model::|g' \
  -e 's|use igra_core::storage::|use igra_core::infrastructure::storage::|g' \
  -e 's|use igra_core::transport::|use igra_core::infrastructure::transport::|g' \
  -e 's|use igra_core::rpc::|use igra_core::infrastructure::rpc::|g' \
  -e 's|use igra_core::config::|use igra_core::infrastructure::config::|g' \
  {} \;
```

#### Step 20: Update service tests

```bash
cd igra-service/tests

# Same import updates for test files
find . -name "*.rs" -exec sed -i '' \
  -e 's|use igra_core::coordination::|use igra_core::application::|g' \
  -e 's|use igra_core::model::|use igra_core::domain::model::|g' \
  -e 's|use igra_core::storage::|use igra_core::infrastructure::storage::|g' \
  {} \;
```

---

### Phase 7: Update Tests in igra-core (Day 4)

#### Step 21: Update unit tests

```bash
cd igra-core/tests/unit

find . -name "*.rs" -exec sed -i '' \
  -e 's|use igra_core::coordination::|use igra_core::application::|g' \
  -e 's|use igra_core::domain::hashes::|use igra_core::domain::hashes::|g' \
  -e 's|use igra_core::pskt::|use igra_core::domain::pskt::|g' \
  -e 's|use igra_core::signing::|use igra_core::domain::signing::|g' \
  {} \;
```

#### Step 22: Update integration tests

```bash
cd igra-core/tests/integration

find . -name "*.rs" -exec sed -i '' \
  -e 's|use igra_core::coordination::|use igra_core::application::|g' \
  -e 's|use igra_core::model::|use igra_core::domain::model::|g' \
  -e 's|use igra_core::storage::|use igra_core::infrastructure::storage::|g' \
  {} \;
```

---

### Phase 8: Final Cleanup (Day 4 Afternoon)

#### Step 23: Remove legacy shims from lib.rs

**Once all tests pass**, consider removing compatibility shims:

**Option A: Keep shims for external users** (recommended for v1.0)
```rust
// Keep the legacy compatibility section in lib.rs
// Mark as deprecated
#[deprecated(note = "Use igra_core::application::Coordinator instead")]
pub mod coordination {
    pub use crate::application::{Coordinator, Signer};
}
```

**Option B: Force migration** (breaking change for v2.0)
```rust
// Remove all legacy compatibility shims
// Users must update to new paths
```

#### Step 24: Update documentation

**Files to update**:
- `README.md` - show new import paths
- `ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md` - mark as ✅ IMPLEMENTED
- Add `MIGRATION.md` - guide for external users

**Example MIGRATION.md**:
```markdown
# Migration Guide v1.x → v2.0

## Import Path Changes

| Old Path | New Path |
|----------|----------|
| `igra_core::coordination::Coordinator` | `igra_core::application::Coordinator` |
| `igra_core::model::SigningEvent` | `igra_core::domain::model::SigningEvent` |
| `igra_core::storage::Storage` | `igra_core::infrastructure::storage::Storage` |
```

#### Step 25: Final verification

```bash
# Clean build
cargo clean

# Build everything
cargo build --workspace --all-targets

# Run all tests
cargo test --workspace

# Run clippy
cargo clippy --workspace -- -D warnings

# Check formatting
cargo fmt --check

# Build docs
cargo doc --no-deps --package igra-core
```

---

### Phase 9: Optional Enhancements (Day 5)

#### Step 26: Add architecture tests

**File**: `igra-core/tests/architecture_test.rs` (CREATE NEW)

```rust
//! Architecture boundary enforcement tests
//!
//! These tests ensure layering rules are followed:
//! - Domain NEVER imports infrastructure
//! - Infrastructure NEVER imports application
//! - Foundation NEVER imports anything internal

#[test]
fn test_domain_does_not_depend_on_infrastructure() {
    // Use cargo-modules or similar to verify no imports
    // This is a compile-time check encoded as a test
}

// TODO: Implement with https://github.com/regexident/cargo-modules
```

#### Step 27: Add feature flags for legacy paths

**File**: `igra-core/Cargo.toml`

```toml
[features]
default = ["legacy-paths"]
legacy-paths = []  # Enable compatibility shims in lib.rs
```

**Update lib.rs**:
```rust
#[cfg(feature = "legacy-paths")]
pub mod coordination {
    pub use crate::application::{Coordinator, Signer};
}
```

---

## Verification Checklist

After completing all phases, verify:

- [ ] `cargo build --workspace` succeeds
- [ ] `cargo test --workspace` passes (all tests)
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] No duplicate files (coordinator/signer in one location only)
- [ ] No empty directories
- [ ] lib.rs clean and organized
- [ ] All imports use new paths (or legacy shims)
- [ ] Documentation updated
- [ ] ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md marked ✅ IMPLEMENTED

---

## Rollback Plan

**If something breaks badly**:

```bash
# Option 1: Rollback to last DI-Step commit
git log --oneline | grep "DI-Step"
git reset --hard <commit-hash-of-step-31>

# Option 2: Rollback specific files
git checkout HEAD~1 -- igra-core/src/lib.rs
git checkout HEAD~1 -- igra-core/src/application/

# Option 3: Nuclear option
git stash
git clean -fd
```

---

## Timeline Summary

| Day | Phase | Tasks | Risk |
|-----|-------|-------|------|
| Day 1 AM | Phase 1 | Delete duplicates | Low |
| Day 1 PM | Phase 2 | Move coordinator/signer to application | Medium |
| Day 2 AM | Phase 3 | Move domain types | Low |
| Day 2 PM | Phase 4 | Move foundation utilities | Low |
| Day 3 | Phase 5 | Update lib.rs, remove shims | Medium |
| Day 3 PM | Phase 6 | Update igra-service | Low |
| Day 4 | Phase 7 | Update all tests | Medium |
| Day 4 PM | Phase 8 | Final cleanup | Low |
| Day 5 | Phase 9 | Optional enhancements | Low |

**Total**: 3-5 days

---

## Success Criteria

**Production-ready means**:
- ✅ Clean architecture (foundation → domain → infrastructure → application)
- ✅ No duplicates
- ✅ No shims (except optional legacy compatibility)
- ✅ All tests pass
- ✅ Documentation complete
- ✅ External users can migrate easily

---

## Next Immediate Actions

1. **Read this document completely**
2. **Backup your current code**:
   ```bash
   git add .
   git commit -m "Checkpoint before production refactor"
   git tag before-prod-refactor
   ```
3. **Start with Phase 1, Step 1** (delete duplicates)
4. **Test after each step**
5. **Commit after each phase**

---

**Questions? Issues? Stop and ask before proceeding.**

---

**END OF PRODUCTION REFACTOR PLAN**
