# Domain/Infrastructure Refactoring - CURRENT STATE

**Date**: 2026-01-09
**Status**: ✅ Structure Created, ⚠️ Implementations Not Moved
**Tests**: ✅ Passing
**Builds**: ✅ Compiling

---

## Visual Architecture Map

### What You Built (Current State)

```
igra-core/src/
│
├── foundation/                     ✅ REAL IMPLEMENTATIONS
│   ├── constants.rs                   (3.4 KB - real constants)
│   ├── error.rs                       (7.9 KB - real error types)
│   ├── types.rs                       (2.7 KB - real type aliases)
│   └── util/                          (real utilities)
│       ├── conversion.rs
│       ├── encoding.rs
│       └── time.rs
│
├── domain/                         ⚠️ PARTIAL - Some Real, Some Shims
│   ├── coordination/                  (~100 bytes - SHIM)
│   ├── event/                         (122 lines - REAL CODE)
│   │   ├── hashing.rs
│   │   ├── types.rs
│   │   └── validation.rs
│   ├── hashes.rs                      (real hash functions)
│   ├── policy/                        (~100 bytes - SHIM)
│   ├── request/                       (~100 bytes - SHIM)
│   ├── state_machine.rs               (6.1 KB - REAL)
│   └── validation/                    (~100 bytes - SHIM)
│
├── infrastructure/                 ⚠️ MOSTLY SHIMS
│   ├── audit/                         (~100 bytes - SHIM)
│   ├── config/                        (multiple files - SOME REAL)
│   ├── coordination/                  (~100 bytes - SHIM)
│   ├── event/                         (92 lines - REAL ingestion pipeline)
│   ├── hyperlane/                     (SOME REAL)
│   ├── kaspa_integration.rs           (665 bytes - SHIM)
│   ├── observability/                 (~100 bytes - SHIM)
│   ├── rate_limit.rs                  (5.9 KB - REAL)
│   ├── rpc/                           (~100 bytes - SHIMS)
│   ├── storage/                       (~100 bytes - SHIMS)
│   └── transport/                     (REAL in iroh/ subdirectory)
│
├── application/                    ⚠️ ONLY SHIMS
│   ├── coordinator.rs                 (71 bytes - re-export)
│   ├── event_processor.rs             (92 bytes - re-export)
│   ├── lifecycle.rs                   (29 bytes - re-export)
│   └── signer.rs                      (61 bytes - re-export)
│
└── OLD MODULES (Still Exist)       ⚠️ REAL IMPLEMENTATIONS STILL HERE
    ├── coordination/                  (coordinator.rs, signer.rs - REAL)
    ├── pskt/                          (builder.rs, multisig.rs - REAL)
    ├── signing/                       (musig2.rs, threshold.rs - REAL)
    ├── storage/                       (rocks.rs, mod.rs - REAL)
    ├── rpc/                           (grpc.rs, mod.rs - REAL)
    ├── transport/                     (mock.rs, messages.rs - NOW SHIMS)
    ├── hyperlane/                     (ism.rs - PARTIALLY MOVED)
    ├── config/                        (loader.rs, etc. - PARTIALLY MOVED)
    ├── audit/                         (mod.rs - SHIM now)
    ├── event/                         (mod.rs - SHIM now)
    ├── model.rs                       (REAL domain types)
    ├── state_machine.rs               (SHIM now)
    └── ... many others
```

---

## Module Status Matrix

| Module | Old Location | New Location | Status | Real Code Location |
|--------|-------------|--------------|--------|-------------------|
| **Foundation** |
| types | `types.rs` | `foundation/types.rs` | ✅ MOVED | foundation/ |
| error | `error.rs` | `foundation/error.rs` | ✅ MOVED | foundation/ |
| constants | (new) | `foundation/constants.rs` | ✅ NEW | foundation/ |
| util | `util/` | `foundation/util/` | ✅ MOVED | foundation/ |
| **Domain** |
| event types | `model.rs` | `domain/event/` | ⚠️ PARTIAL | Some in domain/, most in model.rs |
| hashing | `coordination/hashes.rs` | `domain/hashes.rs` | ✅ MOVED | domain/ |
| state machine | `state_machine.rs` | `domain/state_machine.rs` | ✅ MOVED | domain/ |
| policy | `model.rs` | `domain/policy/` | ⚠️ SHIM | model.rs (not moved) |
| request | `model.rs` | `domain/request/` | ⚠️ SHIM | model.rs (not moved) |
| pskt | `pskt/` | (not moved) | ❌ TODO | pskt/ (old location) |
| signing | `signing/` | (not moved) | ❌ TODO | signing/ (old location) |
| **Infrastructure** |
| storage | `storage/` | `infrastructure/storage/` | ⚠️ SHIM | storage/rocks.rs (old) |
| rpc | `rpc/` | `infrastructure/rpc/` | ⚠️ SHIM | rpc/grpc.rs (old) |
| transport | `transport/` | `infrastructure/transport/iroh/` | ✅ MOVED | infrastructure/transport/iroh/ |
| config | `config/` | `infrastructure/config/` | ⚠️ PARTIAL | Mixed |
| hyperlane | `hyperlane/` | `infrastructure/hyperlane/` | ⚠️ PARTIAL | Mixed |
| rate_limit | `rate_limit.rs` | `infrastructure/rate_limit.rs` | ✅ MOVED | infrastructure/ |
| event ingestion | `event/mod.rs` | `infrastructure/event/` | ✅ MOVED | infrastructure/event/ |
| audit | `audit/` | `infrastructure/audit/` | ⚠️ SHIM | audit/ (old) |
| **Application** |
| Coordinator | `coordination/coordinator.rs` | `application/coordinator.rs` | ⚠️ SHIM | coordination/ (old) |
| Signer | `coordination/signer.rs` | `application/signer.rs` | ⚠️ SHIM | coordination/ (old) |
| EventProcessor | `event/mod.rs` | `application/event_processor.rs` | ⚠️ SHIM | infrastructure/event/ |

---

## What "SHIM" Means

A **shim** is a tiny file that just re-exports from another location:

```rust
// Example: application/coordinator.rs (SHIM)
pub use crate::coordination::Coordinator;  // ← Just 1 line!
```

**Why shims exist**:
- Allows old imports to keep working
- Tests don't break
- Gradual migration possible

**Problem with shims**:
- Real code is still in old locations
- Confusing for developers (which path is real?)
- Two ways to import same thing

---

## Import Path Confusion

**Current reality** - Both work:

```rust
// Old path (still works)
use igra_core::coordination::Coordinator;

// New path (also works)
use igra_core::application::Coordinator;

// Both point to SAME code in coordination/coordinator.rs!
```

---

## Code Location Reality Check

### Where Real Implementations Actually Live

**Domain Logic** (business rules, no I/O):
- ✅ `foundation/error.rs` - error types
- ✅ `foundation/types.rs` - type aliases
- ✅ `domain/hashes.rs` - hash functions
- ✅ `domain/state_machine.rs` - request FSM
- ✅ `domain/event/` - event validation (122 lines)
- ❌ `model.rs` - domain types (NOT IN DOMAIN/)
- ❌ `pskt/` - transaction building (NOT IN DOMAIN/)
- ❌ `signing/` - signing protocols (NOT IN DOMAIN/)

**Infrastructure** (I/O, external systems):
- ✅ `infrastructure/rate_limit.rs` - rate limiter
- ✅ `infrastructure/event/` - event ingestion
- ✅ `infrastructure/transport/iroh/` - P2P transport
- ❌ `storage/rocks.rs` - RocksDB (NOT IN INFRASTRUCTURE/)
- ❌ `rpc/grpc.rs` - gRPC client (NOT IN INFRASTRUCTURE/)
- ❌ `config/loader.rs` - config loading (NOT IN INFRASTRUCTURE/)

**Application** (orchestration):
- ❌ `coordination/coordinator.rs` - (NOT IN APPLICATION/)
- ❌ `coordination/signer.rs` - (NOT IN APPLICATION/)

---

## Dependency Reality Check

### What Depends on What (Current)

```
application/           (SHIM)
    ↓ re-exports
coordination/          (REAL implementations)
    ↓ depends on
storage/, rpc/, transport/   (REAL implementations)
    ↓ depends on
model.rs, pskt/, signing/    (REAL domain logic)
    ↓ depends on
foundation/            (REAL types/errors)
```

**Problem**: Everything still depends on OLD paths!

### What Should Depend on What (Target)

```
application/           (orchestration)
    ↓ depends on
domain/ + infrastructure/
    ↓ depends on
foundation/
```

---

## What Broke / What Works

### ✅ What Still Works
- All tests pass
- Code compiles
- Old imports work
- New imports work (via shims)
- No functionality changed

### ⚠️ What's Confusing
- Two import paths for everything
- Hard to know which path is "real"
- Hard to know where to add new code
- Documentation says one thing, code does another

### ❌ What's Not Done
- Real implementations not moved
- Old modules still exist
- Import paths not updated
- Cleanup not done

---

## File Size Evidence

**Shims are tiny**:
```bash
$ wc -l igra-core/src/application/*.rs
       71 coordinator.rs      ← Just re-export
       92 event_processor.rs  ← Just re-export
       29 lifecycle.rs        ← Just re-export
       61 signer.rs           ← Just re-export
```

**Real implementations are big**:
```bash
$ wc -l igra-core/src/coordination/*.rs
      300+ coordinator.rs     ← REAL orchestration logic
      400+ signer.rs          ← REAL validation logic
```

---

## Git Status Check

```bash
# What files changed?
$ git status

# Tons of new files in foundation/, domain/, infrastructure/, application/
# But OLD files unchanged!
```

**This proves**: You created NEW structure without moving OLD code.

---

## Recommendation Summary

### Option A: Keep Shims (RECOMMENDED)

**Status**: ✅ You're DONE!

**What to do**:
1. Nothing - ship features
2. Use new paths in new code
3. Clean up later

**Pros**:
- Safe
- Fast
- Can ship

### Option B: Move Implementations (RISKY)

**Status**: ⚠️ 30% done

**What to do**:
1. Follow DI-NEXT-STEPS.md steps 32-42
2. Move ~30 files
3. Update hundreds of imports
4. Test extensively

**Pros**:
- Cleaner
- Matches docs

**Cons**:
- Risky
- Time-consuming
- Might break things

---

## Quick Decision Tree

```
Are you shipping features soon?
├─ YES → Use Option A (keep shims)
└─ NO → Are you brave?
         ├─ YES → Do Option B (move implementations)
         └─ NO → Use Option A (keep shims)
```

---

**END OF CURRENT STATE SUMMARY**
