# Refactoring Status - Domain/Infrastructure Separation

**Last Updated**: 2026-01-10
**Goal**: Full production-ready refactoring per ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md
**Current Progress**: 70% complete, ready for final push

---

## Quick Status

| Layer | Status | Completion |
|-------|--------|------------|
| **Foundation** | ✅ Complete | 100% |
| **Domain** | ⚠️ Partial | 80% |
| **Infrastructure** | ⚠️ Partial | 85% |
| **Application** | ❌ Needs Work | 10% |

**Overall**: 70% complete

---

## What Your Team Already Did (Steps 1-31)

### Foundation Layer ✅ 100%

```
foundation/
├── constants.rs      ✅ Real constants (3.4 KB)
├── error.rs          ✅ Error types (7.9 KB)
├── types.rs          ✅ Type aliases (2.7 KB)
└── util/             ✅ Utilities
    ├── conversion.rs
    ├── encoding.rs
    └── time.rs
```

**Status**: COMPLETE - no changes needed

---

### Domain Layer ⚠️ 80%

```
domain/
├── pskt/             ✅ COMPLETE (17KB)
│   ├── builder.rs
│   ├── multisig.rs
│   ├── fee.rs
│   └── validation.rs
├── signing/          ✅ COMPLETE
│   ├── musig2.rs
│   ├── threshold.rs
│   └── mpc.rs
├── event/            ✅ COMPLETE (122 lines)
│   ├── types.rs
│   ├── validation.rs
│   └── hashing.rs
├── hashes.rs         ✅ COMPLETE
├── state_machine.rs  ✅ COMPLETE
├── coordination/     ⚠️ Has structure, needs content
├── policy/           ⚠️ Has structure, needs content
├── request/          ⚠️ Has structure, needs content
└── audit/            ⚠️ Has structure, needs content
```

**What's missing**:
- `model.rs` still at top level (should be `domain/model.rs`)
- Some domain submodules incomplete

---

### Infrastructure Layer ⚠️ 85%

```
infrastructure/
├── storage/          ✅ COMPLETE (RocksDB)
│   ├── rocks.rs
│   └── mod.rs
├── transport/        ✅ COMPLETE (moved to iroh/)
│   └── iroh/
│       ├── identity.rs
│       ├── messages.rs
│       ├── mock.rs
│       └── traits.rs
├── rpc/              ✅ COMPLETE
│   ├── grpc.rs
│   ├── client.rs
│   └── retry/
├── config/           ✅ COMPLETE
├── event/            ✅ COMPLETE (ingestion pipeline)
├── hyperlane/        ✅ COMPLETE
├── rate_limit.rs     ✅ COMPLETE
├── coordination/     ❌ HAS DUPLICATES!
│   ├── coordinator.rs  ← DUPLICATE (should be in application/)
│   ├── signer.rs       ← DUPLICATE (should be in application/)
│   └── monitoring.rs   ✅ OK (infrastructure)
└── observability/    ⚠️ Placeholder
```

**What's wrong**:
- Coordinator/Signer duplicated (also in `/coordination/`)
- These belong in application layer, not infrastructure!

---

### Application Layer ❌ 10%

```
application/
├── coordinator.rs    ❌ 1-line shim (should be real orchestration)
├── signer.rs         ❌ 1-line shim (should be real orchestration)
├── event_processor.rs ❌ Shim
└── lifecycle.rs      ❌ Shim
```

**What's wrong**:
- Everything is a shim re-exporting from other places
- Real coordinator/signer still in `/coordination/` directory

---

### Legacy Files Still Exist ❌

**These should be deleted or moved**:

```
igra-core/src/
├── coordination/           ❌ DELETE (move to application)
│   ├── coordinator.rs      → application/coordinator.rs
│   ├── signer.rs           → application/signer.rs
│   ├── monitoring.rs       ✅ Keep in infrastructure
│   └── threshold.rs        → domain or delete
├── model.rs                ❌ MOVE → domain/model.rs
├── lifecycle.rs            ❌ MOVE → application/lifecycle.rs
├── hd.rs                   ❌ MOVE → foundation/util/hd.rs
├── group_id.rs             ❌ MOVE → foundation/types/group_id.rs
├── constants.rs            ❌ DELETE (1-line shim)
├── error.rs                ❌ DELETE (1-line shim)
├── types.rs                ❌ DELETE (1-line shim)
└── state_machine.rs        ❌ DELETE (1-line shim)
```

---

## The Core Problem

**Duplicate Coordinators!**

```
/coordination/coordinator.rs (5602 lines)  ← OLD LOCATION
                ↓ (copied)
/infrastructure/coordination/coordinator.rs ← DUPLICATE
                ↓ (re-exported)
/application/coordinator.rs ← 1-line shim

Same for signer.rs!
```

**This is confusing and wrong.**

---

## The Solution (3-5 Days)

### Plan Overview

Read **PRODUCTION-REFACTOR-PLAN.md** for complete details.

**Quick version**:

**Day 1**: Fix duplicates, move coordinator/signer to application
**Day 2**: Move model.rs and other domain types
**Day 3**: Clean up lib.rs, update igra-service
**Day 4**: Update all tests
**Day 5**: Final cleanup, documentation

---

## Current Directory Structure vs Target

### Current (Messy)

```
igra-core/src/
├── coordination/              ← OLD, has real code
│   ├── coordinator.rs (5602)
│   └── signer.rs (11538)
├── infrastructure/
│   └── coordination/          ← DUPLICATES
│       ├── coordinator.rs     ← DELETE THIS
│       └── signer.rs          ← DELETE THIS
├── application/               ← SHIMS
│   ├── coordinator.rs (1 line)
│   └── signer.rs (1 line)
├── model.rs                   ← TOP LEVEL (wrong!)
├── lifecycle.rs               ← TOP LEVEL (wrong!)
└── [many 1-line shims]        ← CLEANUP
```

### Target (Clean)

```
igra-core/src/
├── foundation/                ✅ DONE
│   ├── error.rs
│   ├── types/
│   │   ├── mod.rs
│   │   └── group_id.rs
│   └── util/
│       ├── time.rs
│       └── hd.rs
├── domain/                    ⚠️ MOSTLY DONE
│   ├── model.rs               ← MOVE HERE
│   ├── pskt/                  ✅ DONE
│   ├── signing/               ✅ DONE
│   ├── event/                 ✅ DONE
│   ├── policy/
│   └── request/
├── infrastructure/            ⚠️ MOSTLY DONE
│   ├── storage/               ✅ DONE
│   ├── transport/             ✅ DONE
│   ├── rpc/                   ✅ DONE
│   ├── config/                ✅ DONE
│   └── coordination/
│       └── monitoring.rs      ✅ KEEP (infra concern)
├── application/               ❌ NEEDS WORK
│   ├── coordinator.rs         ← MOVE FROM /coordination/
│   ├── signer.rs              ← MOVE FROM /coordination/
│   ├── event_processor.rs
│   └── lifecycle.rs           ← MOVE FROM TOP LEVEL
└── lib.rs                     ← CLEAN UP
```

---

## Files to Read

**In order**:

1. ✅ **This file** - Status overview
2. 📖 **START-HERE.md** - Quick start guide
3. 📖 **PRODUCTION-REFACTOR-PLAN.md** - Complete 9-phase plan
4. 🔧 **DAY-1-SCRIPT.sh** - Automated Day 1 script

**Supporting docs**:
- ARCHITECTURE-DOMAIN-INFRASTRUCTURE.md - Target architecture
- DI-CURRENT-STATE.md - Detailed analysis
- DI-NEXT-STEPS.md - Alternative approaches (skip this, use PRODUCTION-REFACTOR-PLAN.md instead)

---

## Metrics

### Code Distribution

| Layer | Files | Lines | Complete |
|-------|-------|-------|----------|
| Foundation | 8 | 550 | ✅ 100% |
| Domain | 39 | 1,898 | ⚠️ 80% |
| Infrastructure | 46 | 4,284 | ⚠️ 85% |
| Application | 5 | 16 | ❌ 10% |
| **Total** | **98** | **6,748** | **70%** |

### Legacy Code Still Exists

| Location | Lines | Status |
|----------|-------|--------|
| /coordination/ | 473 | ❌ Delete after moving |
| Top-level files | ~400 | ❌ Move or delete |
| 1-line shims | ~10 | ❌ Delete |

---

## Risk Assessment

### Low Risk
- ✅ Foundation complete (no changes needed)
- ✅ Domain PSKT/signing moved (working)
- ✅ Infrastructure storage/transport moved (working)

### Medium Risk
- ⚠️ Moving coordinator/signer (large files, many imports)
- ⚠️ Updating lib.rs (affects all imports)

### High Risk
- ❌ Updating all tests (many files to update)
- ❌ Breaking external users (if we remove shims)

**Mitigation**:
- Backup before each phase
- Test after each step
- Keep legacy shims in lib.rs (for external users)
- Can rollback anytime

---

## Next Immediate Action

**Read START-HERE.md and follow instructions.**

**Quick version**:
1. Backup your code
2. Run `./DAY-1-SCRIPT.sh`
3. Verify tests pass
4. Commit
5. Continue with Day 2

---

## Questions & Answers

**Q: Can we skip any steps?**
A: No. Follow plan exactly.

**Q: What if tests fail?**
A: Fix imports manually, or rollback and ask for help.

**Q: How long will this take?**
A: 3-5 days if following plan carefully.

**Q: Can we do this while shipping features?**
A: No. Dedicate time to refactor, or wait until you have time.

**Q: What if we break production?**
A: This is igra-core (library). No prod impact unless you deploy broken code. Test thoroughly before deploying.

---

## Completion Checklist

- [ ] Phase 1: Delete duplicates
- [ ] Phase 2: Move coordinator/signer to application
- [ ] Phase 3: Move domain types (model.rs)
- [ ] Phase 4: Move foundation utilities (hd.rs, group_id.rs)
- [ ] Phase 5: Clean lib.rs
- [ ] Phase 6: Update igra-service
- [ ] Phase 7: Update tests
- [ ] Phase 8: Final cleanup
- [ ] Phase 9: Documentation
- [ ] All tests pass
- [ ] No duplicates
- [ ] No 1-line shims (except optional legacy in lib.rs)

---

**Last updated**: 2026-01-10 after analyzing Steps 1-31

**Next update**: After completing Day 1

---

**END OF STATUS**
