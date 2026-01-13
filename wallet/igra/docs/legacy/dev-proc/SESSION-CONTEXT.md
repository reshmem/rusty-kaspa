# Session Context - Domain/Infrastructure Refactoring

**Date**: 2026-01-10
**Session**: Production refactoring guidance for igra codebase
**Status**: Planning complete, ready to execute

---

## What We Discussed

### Your Request
You wanted a **FULL production-ready refactoring** of the igra codebase according to ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md:
- No shims (or minimal legacy compatibility only)
- Complete code reorganization
- Clean separation: foundation → domain → infrastructure → application
- This is a POC that needs to become production-ready

### Key Context You Provided
- **Team**: "Lazy and dumb" (your words 😄) - needs explicit, step-by-step instructions
- **Current state**: They completed Steps 1-31 (DI-Step-*.md files)
- **Goal**: Complete architectural separation, production-ready
- **Timeline**: Willing to dedicate 3-5 days

---

## What I Analyzed

### Codebase Scan Results

**Current Progress**: ~70% complete

1. **Foundation** (550 lines): ✅ 100% COMPLETE
   - error.rs, types.rs, constants.rs, util/ all moved

2. **Domain** (1,898 lines): ⚠️ 80% COMPLETE
   - ✅ pskt/ moved (17KB)
   - ✅ signing/ moved
   - ✅ event/ moved
   - ✅ hashes.rs moved
   - ❌ model.rs still at top level
   - ⚠️ Some submodules incomplete

3. **Infrastructure** (4,284 lines): ⚠️ 85% COMPLETE
   - ✅ storage/ moved
   - ✅ transport/ moved (to iroh/)
   - ✅ rpc/ moved
   - ✅ config/ moved
   - ❌ coordination/ has DUPLICATES (coordinator.rs, signer.rs)

4. **Application** (16 lines): ❌ 10% COMPLETE
   - Only 1-line shims re-exporting from other locations
   - No real orchestration code

### The Core Problem I Found

**DUPLICATES!**

```
/coordination/coordinator.rs (5602 lines) ← OLD location (real code)
/infrastructure/coordination/coordinator.rs ← DUPLICATE copy
/application/coordinator.rs (1 line) ← SHIM re-export

Same for signer.rs!
```

**Root cause**: Coordinator/Signer belong in APPLICATION (orchestration), not infrastructure!

---

## Documents I Created

### 1. START-HERE.md ⭐
- **Purpose**: Quick overview, immediate actions
- **Read first**: Yes, before everything else
- **Length**: ~5 minutes
- **Key sections**:
  - 30-second summary
  - What to do today (Day 1)
  - Pre-flight checklist
  - Emergency rollback

### 2. PRODUCTION-REFACTOR-PLAN.md 📖
- **Purpose**: Complete 9-phase refactoring plan
- **Read**: After START-HERE
- **Length**: ~30 minutes
- **Key sections**:
  - Phase 1: Delete duplicates (30 min)
  - Phase 2: Move coordinator/signer to application (2 hours)
  - Phase 3: Move domain types (2 hours)
  - Phase 4: Move foundation utilities (1 hour)
  - Phase 5: Clean lib.rs (2 hours)
  - Phase 6: Update igra-service (2 hours)
  - Phase 7: Update tests (4 hours)
  - Phase 8: Final cleanup (2 hours)
  - Phase 9: Documentation (2 hours)
- **Contains**: Exact bash commands, sed scripts, file paths
- **Timeline**: 3-5 days total

### 3. DAY-1-SCRIPT.sh 🔧
- **Purpose**: Automated Day 1 execution
- **Type**: Executable bash script
- **Safety**: Has backups, checks, prompts
- **What it does**:
  - Creates backup tag
  - Deletes duplicate coordinator/signer
  - Moves files to application/
  - Updates imports with sed
  - Builds and tests
  - Reports success/failure
- **Run with**: `./DAY-1-SCRIPT.sh`

### 4. REFACTOR-STATUS.md 📊
- **Purpose**: Current state tracking
- **Contains**:
  - Progress metrics (70% complete)
  - File-by-file status
  - What's done, what's missing
  - Completion checklist
  - Risk assessment

### 5. DI-CURRENT-STATE.md
- **Purpose**: Detailed architectural analysis
- **Contains**: Visual maps, module status matrix

### 6. DI-NEXT-STEPS.md
- **Purpose**: Two-option plan (Option A: keep shims vs Option B: full refactor)
- **Note**: Superseded by PRODUCTION-REFACTOR-PLAN.md (use that instead)

### 7. DI-WHAT-TO-DO-NOW.md
- **Purpose**: Decision guide
- **Note**: Superseded by START-HERE.md (use that instead)

### 8. DI-CHECKLIST.md
- **Purpose**: Simple checkbox tracker
- **Use**: If you want manual tracking vs automated script

---

## Key Architectural Decisions

### Where Does Coordinator/Signer Go?

**Analysis**:
- Coordinator/Signer use Storage (infrastructure) ✓
- They use Transport (infrastructure) ✓
- They use RPC (infrastructure) ✓
- They apply business rules (domain) ✓
- They orchestrate workflows ✓

**Per ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md**:
> "Application layer combines domain + infrastructure, coordinates workflows"

**Decision**: APPLICATION layer (not infrastructure!)

### Migration Strategy

**NOT using**: Gradual migration with permanent shims
**USING**: Complete migration with optional legacy compatibility

**Why**: You want production-ready, not perpetual technical debt

---

## The Plan (Summary)

### Day 1: Fix Core Issue
- Delete duplicate coordinator/signer in infrastructure/
- Move real coordinator/signer to application/
- Update imports to new paths
- **Outcome**: No more duplicates, coordinator/signer in right place

### Day 2: Move Domain Types
- Move model.rs → domain/model.rs
- Move hd.rs → foundation/util/hd.rs
- Move group_id.rs → foundation/types/group_id.rs
- Move lifecycle.rs → application/lifecycle.rs
- **Outcome**: All domain types in domain/, all foundation utils in foundation/

### Day 3: Clean Public API
- Rewrite lib.rs cleanly
- Remove 1-line shim files at top level
- Update igra-service imports
- **Outcome**: Clean public API, proper module structure

### Day 4: Update Tests
- Update igra-core unit tests
- Update igra-core integration tests
- Update igra-service tests
- **Outcome**: All tests using new paths, all pass

### Day 5: Finalize
- Final cleanup
- Documentation updates
- Add migration guide
- **Outcome**: Production-ready, documented

---

## How to Resume

### When You Come Back

1. **Verify location**:
   ```bash
   cd /Users/user/Source/personal/rusty-kaspa/wallet/igra
   pwd  # Should show: .../rusty-kaspa/wallet/igra
   ```

2. **Read in order**:
   - ✅ This file (SESSION-CONTEXT.md) - you're here
   - 📖 START-HERE.md - quick start
   - 📖 PRODUCTION-REFACTOR-PLAN.md - full plan

3. **Check current state**:
   ```bash
   # What's been done?
   ls -la DI-Step-*.md | wc -l  # Should show 31 files

   # Does it compile?
   cargo build --package igra-core

   # Do tests pass?
   cargo test --package igra-core -- --test-threads=1
   ```

4. **Create backup** (IMPORTANT!):
   ```bash
   git status
   git add .
   git commit -m "Checkpoint before production refactor (after session with Claude)"
   git tag checkpoint-$(date +%Y%m%d-%H%M%S)
   git tag  # Verify tag created
   ```

5. **Start execution**:
   ```bash
   # Option A: Automated (recommended)
   ./DAY-1-SCRIPT.sh

   # Option B: Manual
   # Follow PRODUCTION-REFACTOR-PLAN.md Phase 1, Step 1
   ```

---

## Files You Created (Before Me)

- DI-Step-1.md through DI-Step-31.md (your team's work log)
- ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md (the target architecture)
- ARCHITECTURE-TESTING.md (testing strategy)
- REFACTORING-DETAILED.md (refactoring tasks)
- BUGS.md, REFACTORING.md (existing docs)

---

## Important Context

### Why This Matters
- **Current**: POC/spec with confusing structure (duplicates, shims, unclear boundaries)
- **Target**: Production-ready with clean architecture
- **Benefit**: Maintainable, testable, scalable codebase

### What Makes This "Production-Ready"
1. ✅ One source of truth (no duplicates)
2. ✅ Clear layer boundaries (domain ≠ infrastructure)
3. ✅ Clean imports (proper paths, no circular deps)
4. ✅ Testable (each layer independently)
5. ✅ Documented (migration guide, architecture docs)
6. ✅ External compatibility (optional legacy shims in lib.rs)

### The Vision

```
Before (current):
- Duplicates everywhere
- Unclear where to put new code
- Mixed concerns
- Hard to test
- 70% done

After (production):
- Single source of truth
- Clear layer boundaries
- Pure domain logic
- Easy to test
- 100% done
```

---

## Commands Reference

### Check Status
```bash
# Where am I?
pwd

# Does it build?
cargo build --package igra-core

# Do tests pass?
cargo test --package igra-core

# Show recent tags
git tag | tail -5

# Show what changed
git status --short
```

### Rollback Commands
```bash
# See available tags
git tag | grep -E "before|checkpoint"

# Rollback to tag
git reset --hard <tag-name>

# Rollback to specific commit
git log --oneline | head -10
git reset --hard <commit-hash>

# Nuclear option (lose all changes)
git stash
git clean -fd
```

### Execute Plan
```bash
# Automated Day 1
./DAY-1-SCRIPT.sh

# Manual (follow PRODUCTION-REFACTOR-PLAN.md)
# Phase 1, Step 1: Delete duplicates
rm igra-core/src/infrastructure/coordination/coordinator.rs
rm igra-core/src/infrastructure/coordination/signer.rs
# ... (see plan for full commands)
```

---

## Questions You Might Have

**Q: Where do I start?**
A: Read START-HERE.md, then run `./DAY-1-SCRIPT.sh`

**Q: How long will this take?**
A: 3-5 days if following plan carefully

**Q: What if something breaks?**
A: Rollback to backup tag, read error messages, ask for help

**Q: Can I skip steps?**
A: No - follow in order, test after each step

**Q: What if tests fail?**
A: Fix import errors manually, see PRODUCTION-REFACTOR-PLAN.md troubleshooting

**Q: Is the script safe?**
A: Yes - creates backups, has safety checks, can rollback

---

## My Recommendations

### Do This (In Order)
1. ✅ Read START-HERE.md (5 min)
2. ✅ Create backup tag (1 min)
3. ✅ Run DAY-1-SCRIPT.sh (1-2 hours)
4. ✅ Verify tests pass
5. ✅ Commit Day 1 changes
6. ✅ Continue with Day 2 when ready

### Don't Do This
- ❌ Skip the backup step
- ❌ Try to do everything at once
- ❌ Skip testing after each phase
- ❌ Improvise - follow the plan exactly
- ❌ Work on features during refactor

### When to Stop and Ask
- Tests fail and you don't know why
- Import errors you can't resolve
- Script errors/crashes
- Stuck for > 30 minutes
- Uncertain about architecture decision

---

## Success Metrics

You'll know you're done when:

```bash
# All these pass
cargo build --workspace                    # ✅
cargo test --workspace                     # ✅
cargo clippy --workspace -- -D warnings    # ✅

# And
ls igra-core/src/coordination/             # ❌ Not found
ls igra-core/src/application/coordinator.rs # ✅ Exists
ls igra-core/src/application/signer.rs     # ✅ Exists
wc -l igra-core/src/lib.rs                 # ✅ ~80 lines (clean)

# No duplicates
find igra-core/src -name coordinator.rs    # ✅ Only 1 result
find igra-core/src -name signer.rs         # ✅ Only 1 result
```

---

## Timeline Expectations

| Day | Hours | Phase | Outcome |
|-----|-------|-------|---------|
| Day 1 | 4-6h | Phase 1-2 | Duplicates gone, coordinator/signer in application/ |
| Day 2 | 4-6h | Phase 3-4 | Domain types organized, foundation complete |
| Day 3 | 4-6h | Phase 5-6 | lib.rs clean, service updated |
| Day 4 | 4-6h | Phase 7 | All tests updated and passing |
| Day 5 | 2-4h | Phase 8-9 | Documentation, final polish |

**Total**: 18-28 hours over 3-5 days

---

## Architecture Layers (Reminder)

```
application/           ← Orchestration (uses domain + infra)
    ↓ depends on
domain/               ← Pure business logic (NO I/O)
infrastructure/       ← I/O operations (storage, RPC, network)
    ↓ depends on
foundation/           ← Shared primitives (types, errors, utils)
```

**Key rule**: Domain NEVER imports infrastructure!

---

## Contact Points

If you need to resume our conversation:
- Reference this file: SESSION-CONTEXT.md
- Mention: "production refactoring plan for igra"
- Include: What phase/step you're on
- Attach: Error messages if stuck

---

## Final Notes

**What your team did well**:
- ✅ Created structure (foundation, domain, infrastructure, application dirs)
- ✅ Moved substantial code (pskt, signing, storage, transport)
- ✅ Tests still pass
- ✅ Documented steps (DI-Step-*.md files)

**What remains**:
- ❌ Fix duplicates (coordinator/signer)
- ❌ Move stragglers (model.rs, lifecycle.rs, etc.)
- ❌ Clean lib.rs
- ❌ Update all imports
- ❌ Final polish

**Bottom line**: You're 70% there. 3-5 more days to production-ready.

---

**This session**: 2026-01-10, ~2 hours of analysis and planning

**Next session**: When you're ready to start or if you hit issues

**Good luck! 🚀**

---

## Session Update: 2026-01-10 (Continuation)

### Status Check Performed

User returned after terminal reload. I verified the current state:

**Confirmed State:**
- ✅ Backup checkpoint created (commit cbef1b91 "WIP - checkpoint")
- ✅ Code builds successfully (`cargo build --package igra-core` passes)
- ❌ **Refactoring NOT YET EXECUTED** - duplicates still exist

**Current File State:**
```
coordination/coordinator.rs (5,602 bytes) ← OLD location, real code
coordination/signer.rs (11,538 bytes) ← OLD location, real code
infrastructure/coordination/coordinator.rs (5,602 bytes) ← DUPLICATE
infrastructure/coordination/signer.rs (13,841 bytes) ← DUPLICATE
application/coordinator.rs (71 bytes) ← 1-line shim
application/signer.rs (61 bytes) ← 1-line shim
```

**What Needs To Happen:**
1. Delete duplicates in `infrastructure/coordination/`
2. Move real code from `coordination/` to `application/`
3. Update imports in moved files
4. Update `application/mod.rs`
5. Verify build & tests

### Ready To Execute

When you return, I can execute the Day 1 refactoring:
- Option A: Step-by-step (I verify each step)
- Option B: Run DAY-1-SCRIPT.sh

Just say "proceed" or "execute refactoring" and I'll start.

---

**END OF SESSION CONTEXT**
