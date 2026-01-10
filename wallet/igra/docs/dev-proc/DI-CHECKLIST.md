# Domain/Infrastructure Refactoring - SIMPLE CHECKLIST

**Use this if you're doing Option B (moving implementations)**

---

## Progress Tracker

### Phase 0: Structure (DONE) ✅

- [x] Step 1-31: Created foundation/domain/infrastructure/application directories
- [x] Created shims for all modules
- [x] Tests pass
- [x] Code compiles

**You are here** ⬇️

---

### Phase 1: Move Domain Logic

**Goal**: Move pure business logic into `domain/` modules.

- [ ] **Step 32**: Move PSKT to `domain/pskt/`
  - [ ] Copy `pskt/builder.rs` → `domain/pskt/builder.rs`
  - [ ] Copy `pskt/multisig.rs` → `domain/pskt/multisig.rs`
  - [ ] Create `domain/pskt/mod.rs`
  - [ ] Update `domain/mod.rs`
  - [ ] Make old `pskt/mod.rs` a shim
  - [ ] ✅ `cargo test --package igra-core`

- [ ] **Step 33**: Move Signing to `domain/signing/`
  - [ ] Copy `signing/*.rs` → `domain/signing/`
  - [ ] Update `domain/mod.rs`
  - [ ] Make old `signing/mod.rs` a shim
  - [ ] ✅ `cargo test --package igra-core`

- [ ] **Step 34**: Move Model to `domain/model.rs`
  - [ ] Copy `model.rs` → `domain/model.rs`
  - [ ] Update `domain/mod.rs`
  - [ ] Make old `model.rs` a shim
  - [ ] ✅ `cargo test --package igra-core`

**Checkpoint**: Run full test suite
```bash
cargo test --package igra-core --package igra-service
```
**If fails**: Stop and ask for help. If passes: Continue ⬇️

---

### Phase 2: Move Infrastructure Logic

**Goal**: Move I/O implementations into `infrastructure/` modules.

- [ ] **Step 35**: Move Storage to `infrastructure/storage/`
  - [ ] Check if `infrastructure/storage/rocks.rs` is real or shim
  - [ ] If shim: Copy `storage/rocks.rs` → `infrastructure/storage/rocks.rs`
  - [ ] Make old `storage/mod.rs` a shim
  - [ ] ✅ `cargo test --package igra-core storage`

- [ ] **Step 36**: Move RPC to `infrastructure/rpc/`
  - [ ] Copy `rpc/grpc.rs` → `infrastructure/rpc/grpc.rs`
  - [ ] Copy `rpc/mod.rs` → `infrastructure/rpc/client.rs`
  - [ ] Update `infrastructure/rpc/mod.rs`
  - [ ] Make old `rpc/mod.rs` a shim
  - [ ] ✅ `cargo test --package igra-core`

- [ ] **Step 37**: Verify Transport (already moved in Step 30)
  - [ ] Check `transport/mod.rs` is a shim
  - [ ] ✅ `cargo test --package igra-core transport`

**Checkpoint**: Run full test suite
```bash
cargo test --package igra-core --package igra-service
```
**If fails**: Stop and ask for help. If passes: Continue ⬇️

---

### Phase 3: Move Application Orchestration

**Goal**: Move coordinator/signer into `application/`.

- [ ] **Step 38**: Move Coordinator to `application/coordinator.rs`
  - [ ] Copy `coordination/coordinator.rs` → `application/coordinator.rs`
  - [ ] Update imports in `application/coordinator.rs` (old → new paths)
  - [ ] Update `application/mod.rs`
  - [ ] Make old `coordination/coordinator.rs` a shim
  - [ ] ✅ `cargo build --package igra-core`

- [ ] **Step 39**: Move Signer to `application/signer.rs`
  - [ ] Copy `coordination/signer.rs` → `application/signer.rs`
  - [ ] Update imports in `application/signer.rs` (old → new paths)
  - [ ] Update `application/mod.rs`
  - [ ] Make old `coordination/signer.rs` a shim
  - [ ] ✅ `cargo test --package igra-core --package igra-service`

**Checkpoint**: Run FULL test suite
```bash
cargo test --workspace
cargo clippy --package igra-core --package igra-service
```
**If fails**: Stop and ask for help. If passes: Continue ⬇️

---

### Phase 4: Cleanup (DANGEROUS - DO LAST)

**⚠️ WARNING: Only do this if ALL tests pass above**

- [ ] **Step 40**: Verify all tests pass
  ```bash
  cargo test --workspace
  ```
  **If ANY test fails**: STOP. Do NOT proceed.

- [ ] **Step 41**: Backup before cleanup
  ```bash
  cp -r igra-core/src igra-core/src.backup
  git commit -am "Backup before cleanup"
  ```

- [ ] **Step 41b**: Remove old directories
  - [ ] Remove `coordination/` directory
  - [ ] Remove `storage/` directory (keep `storage.rs` if exists)
  - [ ] Remove `rpc/` directory (keep `rpc.rs` if exists)
  - [ ] Remove `pskt/` directory
  - [ ] Remove `signing/` directory
  - [ ] Remove `model.rs` (now in domain)

- [ ] **Step 41c**: Update `lib.rs`
  - [ ] Remove `pub mod coordination;`
  - [ ] Remove `pub mod storage;` (unless it's needed)
  - [ ] Remove `pub mod rpc;` (unless it's needed)
  - [ ] Remove `pub mod pskt;`
  - [ ] Remove `pub mod signing;`
  - [ ] Keep only: `foundation`, `domain`, `infrastructure`, `application`

- [ ] **Step 42**: Final verification
  ```bash
  cargo clean
  cargo build --package igra-core --package igra-service
  cargo test --workspace
  cargo clippy --package igra-core -- -D warnings
  ```
  **All must pass** ✅

---

## Emergency Rollback

**If anything breaks**:

```bash
# Rollback to last working state
git reset --hard HEAD~1

# Or restore from backup
rm -rf igra-core/src
cp -r igra-core/src.backup igra-core/src

# Verify it works
cargo test --workspace
```

---

## Status Tracking

**Mark your progress**:

| Phase | Steps | Status | Date Completed |
|-------|-------|--------|----------------|
| Phase 0 | 1-31 | ✅ Done | 2026-01-09 |
| Phase 1 | 32-34 | ⬜ Todo | |
| Phase 2 | 35-37 | ⬜ Todo | |
| Phase 3 | 38-39 | ⬜ Todo | |
| Phase 4 | 40-42 | ⬜ Todo | |

---

## Daily Progress Log

**Use this to track what you did**:

### Day 1 (2026-01-09)
- Completed Phase 0 (steps 1-31)
- Created structure
- All tests pass

### Day 2 (______)
- Started Phase 1
- Completed Step __
- Status: __

### Day 3 (______)
- ...

---

## Common Issues & Solutions

### Issue: "Cannot find module"
**Solution**: You removed a module but didn't update imports. Search for the module name:
```bash
rg "use crate::MODULE_NAME::" --files-with-matches
```

### Issue: Tests fail after moving file
**Solution**: Imports are wrong. Check the moved file's imports match new structure.

### Issue: "Circular dependency"
**Solution**: You created a dependency loop. Domain should NOT import infrastructure.

### Issue: Compile errors about missing types
**Solution**: Update imports to use `foundation::*` for types and errors.

---

## Quick Commands Reference

```bash
# Build only
cargo build --package igra-core

# Test only core
cargo test --package igra-core

# Test only service
cargo test --package igra-service

# Test everything
cargo test --workspace

# Clippy check
cargo clippy --package igra-core -- -D warnings

# Clean build (when things are weird)
cargo clean && cargo build --package igra-core

# Find where something is imported
rg "use crate::MODULE::" --files-with-matches

# Count lines in a file (check if shim)
wc -l igra-core/src/path/to/file.rs
```

---

## When to Stop and Ask for Help

**STOP immediately if**:
- ❌ Tests fail and you don't know why
- ❌ Code doesn't compile and error is confusing
- ❌ You're unsure which imports to update
- ❌ Clippy shows 10+ new warnings
- ❌ You removed something and broke everything
- ❌ You've been stuck > 30 minutes on one step

**Ask for help with**:
- The exact step number you're on
- The exact error message (full output)
- What you tried
- What you expected

---

## Completion Criteria

**You're DONE when**:
- ✅ All checkboxes above are marked
- ✅ `cargo test --workspace` passes
- ✅ `cargo clippy --package igra-core -- -D warnings` passes
- ✅ No old directories exist (coordination, storage, rpc, pskt, signing)
- ✅ `lib.rs` only exports foundation/domain/infrastructure/application
- ✅ All imports use new paths

---

**END OF CHECKLIST**
