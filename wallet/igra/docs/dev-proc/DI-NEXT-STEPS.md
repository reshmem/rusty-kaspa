# Domain/Infrastructure Refactoring - NEXT STEPS

**Date**: 2026-01-09
**Current Status**: Step 31 completed - Structure is in place, but most code still in old locations
**What You've Done**: Created foundation/domain/infrastructure/application directories with shims
**What's Next**: Move REAL implementations and clean up old modules

---

## CURRENT STATE SUMMARY

### ✅ What's Done (Good Job!)

You've completed the **structure creation phase**:

```
igra-core/src/
├── foundation/          ✅ HAS REAL CODE (constants, error, types, util)
├── domain/              ✅ HAS STRUCTURE (event, policy, request, validation, coordination)
├── infrastructure/      ✅ HAS STRUCTURE (audit, config, storage, rpc, transport, etc.)
├── application/         ✅ HAS SHIMS (coordinator, signer, event_processor, lifecycle)
└── [OLD MODULES]        ⚠️  STILL EXIST (audit, config, coordination, event, hyperlane, etc.)
```

**Tests pass**: ✅ `cargo test -p igra-core -p igra-service`
**Compiles**: ✅ `cargo build --package igra-core`

### ⚠️ The Problem

Most of your new directories are **thin re-exports** (shims), not real implementations:

```rust
// Example: application/coordinator.rs
pub use crate::coordination::Coordinator;  // ← Just re-exporting old location
```

**Real code is still in OLD locations**:
- `coordination/coordinator.rs` ← Real Coordinator implementation
- `coordination/signer.rs` ← Real Signer implementation
- `storage/rocks.rs` ← Real RocksDB implementation
- `rpc/grpc.rs` ← Real gRPC client
- etc.

---

## WHAT TO DO NEXT

You have **TWO OPTIONS**:

### Option A: Keep Shims, Start Using New Paths (RECOMMENDED - EASIER)

**Strategy**: Keep old code where it is, but update ONLY new code to import from new paths.

**Why this is easier**:
- Don't need to move files
- No big import refactor
- Gradual migration
- Safe (tests keep passing)

**What to do**:
1. **Leave old modules as-is** (don't touch coordination/, storage/, rpc/, etc.)
2. **Update imports in NEW code** to use new paths
3. **Add NEW features** using new paths only
4. **Over time**, move old code into new structure

**Example**:

```rust
// ❌ OLD (in new code)
use crate::coordination::Coordinator;

// ✅ NEW (in new code)
use crate::application::Coordinator;
```

**Next immediate steps**:
1. DO NOTHING - structure is good enough
2. Write new features using `domain::*`, `infrastructure::*`, `application::*` paths
3. Let old code stay in old paths
4. Clean up later when you have time

---

### Option B: Move Real Implementations (HARDER - COMPLETE REFACTOR)

**Strategy**: Actually move implementation files into new directories.

**Why this is harder**:
- Need to move ~30 files
- Update hundreds of imports
- Higher risk of breaking things
- But cleaner result

**What to do**: Follow the steps below carefully.

---

## OPTION B: COMPLETE REFACTOR STEPS

**IF YOU CHOOSE THIS**, follow these steps **EXACTLY** and **IN ORDER**.

---

### PHASE 1: Move Domain Logic (Pure Functions)

**Goal**: Move pure business logic into `domain/` modules.

#### Step 32: Move PSKT Building Logic

**Current state**:
- `pskt/builder.rs` - PSKT construction logic
- `pskt/multisig.rs` - Multisig script logic

**Action**:

1. **Create `domain/pskt/` directory**:
```bash
mkdir -p igra-core/src/domain/pskt
```

2. **Move files**:
```bash
# Move PSKT implementation
cp igra-core/src/pskt/builder.rs igra-core/src/domain/pskt/builder.rs
cp igra-core/src/pskt/multisig.rs igra-core/src/domain/pskt/multisig.rs

# Create domain/pskt/mod.rs
cat > igra-core/src/domain/pskt/mod.rs << 'EOF'
//! PSKT (Partially Signed Kaspa Transaction) domain logic.
//!
//! Pure transaction building and validation logic.

pub mod builder;
pub mod multisig;

pub use builder::*;
pub use multisig::*;
EOF
```

3. **Update `domain/mod.rs`**:
```rust
// In igra-core/src/domain/mod.rs
// REMOVE this line:
pub use crate::pskt;

// ADD this line:
pub mod pskt;
```

4. **Turn old pskt/ into shim**:
```bash
# Edit igra-core/src/pskt/mod.rs to just:
echo "pub use crate::domain::pskt::*;" > igra-core/src/pskt/mod.rs
```

5. **Verify**:
```bash
cargo build --package igra-core
cargo test --package igra-core
```

**Expected**: Should compile and pass tests.

---

#### Step 33: Move Signing Logic

**Current state**:
- `signing/musig2.rs` - MuSig2 protocol
- `signing/threshold.rs` - Threshold signing
- `signing/mpc.rs` - MPC primitives

**Action**:

1. **Create `domain/signing/` directory**:
```bash
mkdir -p igra-core/src/domain/signing
```

2. **Move files**:
```bash
cp igra-core/src/signing/*.rs igra-core/src/domain/signing/
```

3. **Update `domain/mod.rs`**:
```rust
// REMOVE:
pub use crate::signing;

// ADD:
pub mod signing;
```

4. **Turn old signing/ into shim**:
```bash
echo "pub use crate::domain::signing::*;" > igra-core/src/signing/mod.rs
```

5. **Verify**:
```bash
cargo build --package igra-core
cargo test --package igra-core
```

---

#### Step 34: Move Model Types to Domain

**Current state**:
- `model.rs` - Core domain types (SigningEvent, SigningRequest, GroupPolicy, etc.)

**Action**:

1. **Move model.rs into domain**:
```bash
cp igra-core/src/model.rs igra-core/src/domain/model.rs
```

2. **Update `domain/mod.rs`**:
```rust
// REMOVE:
pub use crate::model;

// ADD:
pub mod model;
pub use model::*;  // Re-export all types at domain level
```

3. **Turn old model.rs into shim**:
```bash
echo "pub use crate::domain::model::*;" > igra-core/src/model.rs
```

4. **Verify**:
```bash
cargo build --package igra-core
```

---

### PHASE 2: Move Infrastructure Logic (I/O Code)

**Goal**: Move infrastructure implementations into `infrastructure/` modules.

#### Step 35: Move Storage Implementation

**Current state**:
- `storage/rocks.rs` - RocksDB implementation
- `storage/mod.rs` - Storage trait

**Action**:

1. **Files already in `infrastructure/storage/`** - check what's there:
```bash
ls -la igra-core/src/infrastructure/storage/
```

2. **IF they're just shims**, move real implementations:
```bash
# Check if infrastructure/storage/rocks.rs is a shim or real impl
wc -l igra-core/src/infrastructure/storage/rocks.rs

# If < 10 lines (shim), copy real implementation:
cp igra-core/src/storage/rocks.rs igra-core/src/infrastructure/storage/rocks.rs
```

3. **Turn old storage/ into shim**:
```bash
cat > igra-core/src/storage/mod.rs << 'EOF'
//! Legacy storage path - re-exports infrastructure::storage
pub use crate::infrastructure::storage::*;
EOF
```

4. **Verify**:
```bash
cargo build --package igra-core
cargo test --package igra-core storage
```

---

#### Step 36: Move RPC Implementation

**Current state**:
- `rpc/grpc.rs` - gRPC client implementation
- `rpc/mod.rs` - RPC trait

**Action**:

1. **Check infrastructure/rpc/**:
```bash
ls -la igra-core/src/infrastructure/rpc/
```

2. **Move real implementations if needed**:
```bash
cp igra-core/src/rpc/grpc.rs igra-core/src/infrastructure/rpc/grpc.rs
cp igra-core/src/rpc/mod.rs igra-core/src/infrastructure/rpc/client.rs
```

3. **Update infrastructure/rpc/mod.rs**:
```rust
pub mod client;
pub mod grpc;
pub mod retry;  // Already created

pub use client::*;
pub use grpc::*;
```

4. **Turn old rpc/ into shim**:
```bash
echo "pub use crate::infrastructure::rpc::*;" > igra-core/src/rpc/mod.rs
```

5. **Verify**:
```bash
cargo build --package igra-core
```

---

#### Step 37: Move Transport Implementation

**Current state**:
- `transport/mock.rs` - Mock transport
- `transport/messages.rs` - Message types
- `transport/identity.rs` - Peer identity
- `transport/mod.rs` - Transport trait

**These are ALREADY in `infrastructure/transport/iroh/`** (Step 30)!

**Action**: Just verify old transport/ is a shim:
```bash
cat igra-core/src/transport/mod.rs
# Should be: pub use crate::infrastructure::transport::*;
```

If not, make it a shim:
```bash
echo "pub use crate::infrastructure::transport::*;" > igra-core/src/transport/mod.rs
```

---

### PHASE 3: Move Application Orchestration

**Goal**: Move coordinator/signer orchestration into `application/`.

#### Step 38: Move Coordinator Implementation

**Current state**:
- `coordination/coordinator.rs` - Real Coordinator implementation

**Action**:

1. **Move coordinator**:
```bash
cp igra-core/src/coordination/coordinator.rs igra-core/src/application/coordinator.rs
```

2. **Update application/coordinator.rs imports**:

Open `igra-core/src/application/coordinator.rs` and change imports:

```rust
// CHANGE OLD IMPORTS:
use crate::coordination::hashes::{event_hash, validation_hash};
use crate::storage::Storage;
use crate::transport::Transport;
use crate::rpc::NodeRpc;

// TO NEW IMPORTS:
use crate::domain::hashes::{event_hash, validation_hash};
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::Transport;
use crate::infrastructure::rpc::NodeRpc;
```

3. **Update application/mod.rs**:
```rust
// REMOVE:
pub use coordinator::Coordinator;

// Change to:
pub mod coordinator;
pub use coordinator::Coordinator;
```

4. **Turn old coordination/coordinator.rs into shim**:
```bash
echo "pub use crate::application::Coordinator;" > igra-core/src/coordination/coordinator.rs
```

5. **Verify**:
```bash
cargo build --package igra-core
```

---

#### Step 39: Move Signer Implementation

**Current state**:
- `coordination/signer.rs` - Real Signer implementation

**Action**: Same as Step 38, but for Signer.

1. **Move signer**:
```bash
cp igra-core/src/coordination/signer.rs igra-core/src/application/signer.rs
```

2. **Update imports in application/signer.rs** (same pattern as coordinator)

3. **Update application/mod.rs**:
```rust
pub mod signer;
pub use signer::Signer;
```

4. **Turn old coordination/signer.rs into shim**:
```bash
echo "pub use crate::application::Signer;" > igra-core/src/coordination/signer.rs
```

5. **Verify**:
```bash
cargo build --package igra-core
cargo test --package igra-core
```

---

### PHASE 4: Cleanup Old Modules (FINAL STEP)

**Goal**: Remove old directories that are now just shims.

**⚠️ DANGEROUS - DO THIS LAST, AFTER ALL TESTS PASS**

#### Step 40: Verify All Tests Pass

```bash
cargo test --package igra-core --package igra-service
```

**IF AND ONLY IF all tests pass**, proceed:

#### Step 41: Remove Old Module Directories

**DO NOT DO THIS YET - ONLY AFTER STEPS 32-39 ARE COMPLETE**

```bash
# Backup first!
cp -r igra-core/src igra-core/src.backup

# Remove old directories (they're now just shims)
rm -rf igra-core/src/coordination/
rm -rf igra-core/src/storage/
rm -rf igra-core/src/rpc/
rm -rf igra-core/src/transport/
# ... etc for other old modules

# Update lib.rs to remove old module declarations
# Edit igra-core/src/lib.rs and remove:
# pub mod coordination;
# pub mod storage;
# pub mod rpc;
# pub mod transport;
# (keep only foundation, domain, infrastructure, application)
```

#### Step 42: Final Verification

```bash
cargo clean
cargo build --package igra-core --package igra-service
cargo test --workspace
cargo clippy --package igra-core -- -D warnings
```

**Expected**: Everything compiles and tests pass.

---

## RECOMMENDED APPROACH FOR YOUR TEAM

Given your team is "lazy and dumb" (your words 😄), I recommend:

### DO THIS: Option A (Keep Shims)

**Why**: You've already done the hard part (creating structure). Don't undo it.

**Action**:
1. **STOP refactoring old code**
2. **Leave structure as-is** (shims are fine)
3. **Update only your ARCHITECTURE docs** to reflect current state
4. **Write NEW code using new paths**:
   ```rust
   use crate::domain::*;
   use crate::infrastructure::*;
   use crate::application::*;
   ```
5. **Move old code gradually** as you touch files

**Benefits**:
- ✅ Low risk
- ✅ Tests keep passing
- ✅ Can ship features
- ✅ Clean up later

---

### DON'T DO THIS: Option B (Complete Refactor)

**Unless**: You have:
- 2+ weeks dedicated refactoring time
- No feature deadlines
- A brave developer who won't quit halfway
- Good test coverage
- Backups

---

## STATUS TRACKING

Create a file `DI-STATUS.md` to track progress:

```markdown
# Refactoring Status

## Completed
- [x] Step 1-31: Created foundation/domain/infrastructure/application structure
- [x] All old paths work via shims
- [x] Tests pass

## Next (if doing Option B)
- [ ] Step 32: Move PSKT to domain/pskt
- [ ] Step 33: Move Signing to domain/signing
- [ ] Step 34: Move Model to domain/model
- [ ] Step 35: Move Storage to infrastructure/storage
- [ ] Step 36: Move RPC to infrastructure/rpc
- [ ] Step 37: Verify Transport shims
- [ ] Step 38: Move Coordinator to application
- [ ] Step 39: Move Signer to application
- [ ] Step 40: All tests pass
- [ ] Step 41: Remove old directories
- [ ] Step 42: Final verification

## Blockers
(None currently)

## Questions
(List any confusion here)
```

---

## QUESTIONS?

**Q: Should we do Option A or B?**
A: Option A (keep shims). Less risk, same benefit.

**Q: What if tests break?**
A: Stop immediately. Revert (`git reset --hard`). Ask for help.

**Q: Can we skip steps?**
A: NO. Follow steps IN ORDER.

**Q: What if imports break?**
A: Search and replace:
```bash
# Example: Fix storage imports
rg "use crate::storage::" --files-with-matches | xargs sed -i '' 's/use crate::storage::/use crate::infrastructure::storage::/g'
```

**Q: How long will this take?**
A:
- Option A: 0 hours (you're done!)
- Option B: 1-2 weeks (steps 32-42)

---

## FINAL RECOMMENDATION

**STOP HERE. You've done great work creating the structure. Don't risk breaking everything by moving files now.**

**Use Option A:**
1. Keep shims as-is
2. Write new code with new paths
3. Ship features
4. Clean up old code gradually over months

**When to use Option B:**
- After product launch
- During a dedicated "tech debt sprint"
- When you have time to fix breakage

---

**END OF NEXT STEPS GUIDE**
