# START HERE - Production Refactor

**You asked for**: Full refactor per ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md (no shims, production-ready)

**Status**: Your team has made great progress! ~70% done. Let's finish it properly.

---

## 30-Second Summary

✅ **What's done**:
- Domain structure created (pskt, signing moved)
- Infrastructure structure created (storage, transport, RPC moved)
- Foundation complete

❌ **What's broken**:
- Coordinator/Signer exist in TWO places (duplicates!)
- Application layer is empty shims
- Some files still at top level
- lib.rs is messy

⏱️ **Time to fix**: 3-5 days following the plan

---

## Read These Documents IN ORDER

### 1. THIS FILE (you're here) ← START
Quick overview and immediate actions

### 2. PRODUCTION-REFACTOR-PLAN.md ← READ NEXT
Complete 9-phase plan with exact commands

### 3. Execute the plan
Follow steps 1-27, testing after each

---

## What You'll Do Today (Day 1)

### Morning: Fix Duplicates (2-3 hours)

**Problem**: coordinator.rs and signer.rs exist in TWO places:
- `/coordination/coordinator.rs` (OLD)
- `/infrastructure/coordination/coordinator.rs` (DUPLICATE)

**Solution**: Delete duplicates, move to correct location (application/)

**Steps**: Follow **Phase 1** and **Phase 2** in PRODUCTION-REFACTOR-PLAN.md

### Afternoon: Move to Application (2-3 hours)

**Problem**: Coordinator/Signer are orchestration (APPLICATION), not infrastructure

**Solution**: Move to `application/` and fix imports

**Steps**: Continue **Phase 2** in PRODUCTION-REFACTOR-PLAN.md

---

## Quick Pre-Flight Check

**Before starting, verify**:

```bash
# 1. You're in the right directory
pwd
# Should show: .../rusty-kaspa/wallet/igra

# 2. Code compiles
cargo build --package igra-core
# Should succeed

# 3. Tests pass
cargo test --package igra-core -- --test-threads=1 2>&1 | grep "test result"
# Should show: test result: ok

# 4. Create backup
git add .
git commit -m "Backup before production refactor"
git tag before-refactor-$(date +%Y%m%d)
git push origin --tags
```

---

## Immediate Action Plan

### Step 0: Backup (5 minutes)

```bash
# Commit current state
git add .
git commit -m "DI-Step-31 complete - before production refactor"
git tag di-step-31-complete

# Create backup branch
git checkout -b refactor-production-backup
git push origin refactor-production-backup

# Back to main branch
git checkout devel  # or whatever your main branch is
```

### Step 1: Start Phase 1 (30 minutes)

**Goal**: Delete duplicate files

```bash
# Read PRODUCTION-REFACTOR-PLAN.md Phase 1 first!

# Then execute:
rm igra-core/src/infrastructure/coordination/coordinator.rs
rm igra-core/src/infrastructure/coordination/signer.rs

# Update infrastructure/coordination/mod.rs
# (see plan for exact content)

# Verify it breaks (expected!)
cargo build --package igra-core 2>&1 | grep "cannot find"
# Should show errors about Coordinator/Signer not found
```

### Step 2: Start Phase 2 (2 hours)

**Goal**: Move coordinator/signer to application

```bash
# Read PRODUCTION-REFACTOR-PLAN.md Phase 2 first!

# Move files
mv igra-core/src/coordination/coordinator.rs igra-core/src/application/coordinator.rs
mv igra-core/src/coordination/signer.rs igra-core/src/application/signer.rs

# Fix imports (automated - see plan for commands)
cd igra-core/src/application
# Run all the sed commands from the plan

# Verify compiles
cargo build --package igra-core 2>&1 | tee build.log
```

### Step 3: Test After Phase 2

```bash
# Run tests
cargo test --package igra-core 2>&1 | tee test.log

# Check results
grep "test result" test.log
```

**If tests fail**: Read errors carefully, fix imports manually

**If tests pass**: Commit and continue!

```bash
git add .
git commit -m "refactor: move coordinator/signer to application layer (Phase 2 complete)"
```

---

## Tomorrow (Day 2)

### Morning: Phase 3-4 (Move domain types and foundation utilities)
- Move model.rs to domain
- Move hd.rs, group_id.rs to foundation
- Move lifecycle.rs to application

### Afternoon: Phase 5 (Clean lib.rs)
- Rewrite lib.rs cleanly
- Remove old shim files
- Verify compilation

---

## Common Issues & Solutions

### Issue: "Cannot find type X"
**Cause**: Import path is wrong
**Solution**: Check which layer X belongs to, update import

### Issue: "Circular dependency"
**Cause**: Domain importing infrastructure (forbidden!)
**Solution**: Move that code to application layer

### Issue: Tests fail after moving file
**Cause**: Test imports not updated
**Solution**: Update test file imports to new paths

### Issue: sed command doesn't work
**Cause**: Linux vs macOS syntax
**Solution**:
- macOS: `sed -i '' 's/old/new/g' file`
- Linux: `sed -i 's/old/new/g' file`

---

## Emergency Stop

**If anything goes really wrong**:

```bash
# Rollback to backup
git reset --hard before-refactor-$(date +%Y%m%d)

# Or rollback to specific commit
git log --oneline | head -10
git reset --hard <commit-hash>

# Nuclear option
git checkout refactor-production-backup
git branch -D devel  # or your main branch
git checkout -b devel
```

---

## Communication Template

**For your team**:

> We're doing a production refactor this week to complete the domain/infrastructure separation. The plan is in PRODUCTION-REFACTOR-PLAN.md.
>
> Day 1: Fix duplicates, move coordinator/signer to application
> Day 2: Move remaining domain types
> Day 3: Clean up lib.rs and update service imports
> Day 4: Update all tests
> Day 5: Final cleanup and documentation
>
> Please avoid making changes to igra-core this week unless coordinated.

**For your boss**:

> We're completing the architecture refactoring this week (3-5 days). This will make the codebase production-ready with clean separation of concerns. All tests will continue to pass. No external API changes unless we decide to remove legacy shim paths.

---

## Success Metrics

**You'll know you're done when**:

```bash
# All these pass
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings

# And
ls igra-core/src/coordination/  # Shows: directory not found ✅
ls igra-core/src/application/   # Shows: coordinator.rs, signer.rs ✅
wc -l igra-core/src/lib.rs      # Shows: ~80 lines (clean) ✅
```

---

## Questions?

- "Where should X go?" → Check ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md decision tree
- "This import is broken" → Check which layer the type is in now
- "Tests fail after move" → Update test imports to new paths
- "sed not working" → Check macOS vs Linux syntax
- "Everything broken" → Rollback to backup and start over

---

## Final Checklist Before Starting

- [ ] Read this file completely
- [ ] Read PRODUCTION-REFACTOR-PLAN.md completely
- [ ] Created backup (git tag + branch)
- [ ] Warned team about refactor in progress
- [ ] Have 3-5 days available
- [ ] Ready to follow steps exactly

**If all checked**: Start with Phase 1, Step 1 in PRODUCTION-REFACTOR-PLAN.md

**Good luck! 🚀**

---

**END OF START HERE**
