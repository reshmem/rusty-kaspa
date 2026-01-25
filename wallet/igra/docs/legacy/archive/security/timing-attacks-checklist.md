# Timing Attack Fix - Implementation Checklist

**Date:** 2026-01-24
**Assignee:** ________________
**Estimated Time:** 2-3 hours
**Status:** ⬜ Not Started

---

## Pre-Implementation Checklist

- [ ] Read timing-attacks.md (understand the vulnerability)
- [ ] Create feature branch: `git checkout -b security/fix-timing-attacks`
- [ ] Backup current code: `git stash` or commit WIP
- [ ] Ensure clean working directory: `git status`
- [ ] Run baseline tests: `cargo test --workspace` (all should pass)

---

## Implementation Steps (Follow in Order)

### Phase 1: Add Constant-Time Infrastructure (30 min)

#### ☐ Step 1: Add ConstantTimeEq for Hash32
- [ ] Open `igra-core/src/foundation/types.rs`
- [ ] Find imports section (around line 5)
- [ ] Add `use subtle::ConstantTimeEq;`
- [ ] Add impl block for Hash32 (see doc for code)
- [ ] Save file
- [ ] Run: `cargo check --package igra-core`
- [ ] Verify: No compilation errors

#### ☐ Step 2: Add ct_eq() Method to Hash Macro
- [ ] Open `igra-core/src/foundation/types.rs`
- [ ] Find `(hash $name:ident)` macro (around line 53)
- [ ] Find `impl $name` block with `as_hash()` method
- [ ] Add `ct_eq()` method after `as_hash()` (see doc for code)
- [ ] Save file
- [ ] Run: `cargo clean --package igra-core && cargo check --package igra-core`
- [ ] Verify: No compilation errors

**Checkpoint 1:**
```bash
# All hash types should now have ct_eq() method
cargo doc --package igra-core --no-deps --open
# Navigate to TxTemplateHash → should see ct_eq() method
```

---

### Phase 2: Fix Coordination Layer (30 min)

#### ☐ Step 3: Fix selection.rs (2 locations)
- [ ] Open `igra-core/src/domain/coordination/selection.rs`
- [ ] **Location 1 (line 51):** Change `p.tx_template_hash == winning_hash` to `p.tx_template_hash.ct_eq(&winning_hash)`
- [ ] **Location 2 (line 125):** Change `p.tx_template_hash == h` to `p.tx_template_hash.ct_eq(&h)`
- [ ] Save file
- [ ] Run: `cargo check --package igra-core`
- [ ] Run: `cargo test --package igra-core coordination::selection`
- [ ] Verify: All tests pass

**Checkpoint 2:**
```bash
# Verify changes applied
grep "tx_template_hash\.ct_eq" igra-core/src/domain/coordination/selection.rs
# Should show 2 matches
```

---

### Phase 3: Fix CRDT Layer (30 min)

#### ☐ Step 4: Fix event_state.rs (4 locations)
- [ ] Open `igra-core/src/domain/crdt/event_state.rs`
- [ ] **Location 1 (line 102):** Change condition from `!=` to `!ct_eq()`
- [ ] **Location 2 (line 105):** Change `==` to `ct_eq()` in debug log
- [ ] **Location 3 (line 106):** Change `==` to `ct_eq()` in debug log
- [ ] **Location 4 (line 147):** Change `==` to `ct_eq()` for EventId validation
- [ ] **Location 5 (line 153):** Change `==` to `ct_eq()` for TxTemplateHash validation
- [ ] Save file
- [ ] Run: `cargo check --package igra-core`
- [ ] Run: `cargo test --package igra-core domain::crdt`
- [ ] Verify: All tests pass

**Checkpoint 3:**
```bash
# Verify changes applied
grep "\.ct_eq" igra-core/src/domain/crdt/event_state.rs
# Should show 5+ matches
```

---

### Phase 4: Fix Storage Layer (30 min)

#### ☐ Step 5: Fix storage/memory.rs (2 locations)
- [ ] Open `igra-core/src/infrastructure/storage/memory.rs`
- [ ] **Location 1 (line 314):** Change `&s.event_id == event_id` to `s.event_id.ct_eq(event_id)`
- [ ] **Location 2 (line 532):** Change `!=` to `!ct_eq()`
- [ ] Save file
- [ ] Run: `cargo check --package igra-core`
- [ ] Run: `cargo test --package igra-core storage::memory`
- [ ] Verify: All tests pass

#### ☐ Step 6: Fix storage/rocks/engine/phase.rs (1 location)
- [ ] Open `igra-core/src/infrastructure/storage/rocks/engine/phase.rs`
- [ ] **Location 1 (line 153):** Change `!=` to `!ct_eq()`
- [ ] Save file
- [ ] Run: `cargo check --package igra-core`
- [ ] Run: `cargo test --package igra-core storage::rocks`
- [ ] Verify: All tests pass

**Checkpoint 4:**
```bash
# Verify both files updated
grep "\.ct_eq" igra-core/src/infrastructure/storage/memory.rs
grep "\.ct_eq" igra-core/src/infrastructure/storage/rocks/engine/phase.rs
# Should show matches in both files
```

---

### Phase 5: Add Tests (45 min)

#### ☐ Step 7: Create Constant-Time Test File
- [ ] Create file: `igra-core/tests/unit/constant_time.rs`
- [ ] Copy full test code from timing-attacks.md Step 7
- [ ] Save file
- [ ] Open `igra-core/tests/unit/mod.rs`
- [ ] Add line: `mod constant_time;`
- [ ] Save file
- [ ] Run: `cargo test --package igra-core --test unit constant_time`
- [ ] Verify: All 5 tests pass

**Tests to verify:**
- [ ] `tx_template_hash_ct_eq_correctness` - Basic correctness
- [ ] `event_id_ct_eq_correctness` - Basic correctness
- [ ] `ct_eq_with_default_values` - Edge case (zero values)
- [ ] `ct_eq_timing_sanity_check` - Statistical timing check
- [ ] `ct_eq_works_for_all_hash_types` - All hash types tested

**Checkpoint 5:**
```bash
cargo test --package igra-core --test unit constant_time -- --nocapture
# Should see timing statistics printed:
# ✅ Constant-time check passed (match=XX, early=YY, late=ZZ)
# Max deviation should be < 25%
```

---

### Phase 6: Comprehensive Verification (30 min)

#### ☐ Step 8: Run Full Test Suite
- [ ] Run: `cargo test --package igra-core --test unit`
- [ ] Verify: All unit tests pass (no regressions)
- [ ] Run: `cargo test --package igra-core --test integration --features test-utils`
- [ ] Verify: All integration tests pass
- [ ] Run: `cargo test --workspace --all-features`
- [ ] Verify: Entire workspace tests pass

#### ☐ Step 9: Security Verification
- [ ] Run: `grep -rn "tx_template_hash\s*==" igra-core/src --include="*.rs" | grep -v test`
- [ ] Verify: Zero results (or only in comments)
- [ ] Run: `grep -rn "tx_template_hash\.ct_eq" igra-core/src --include="*.rs"`
- [ ] Verify: At least 8 results
- [ ] Run: `grep -rn "event_id\.ct_eq" igra-core/src --include="*.rs"`
- [ ] Verify: At least 5 results

#### ☐ Step 10: Code Quality Check
- [ ] Run: `cargo fmt --all`
- [ ] Run: `cargo clippy --workspace --tests --benches -- -D warnings`
- [ ] Verify: No warnings or errors
- [ ] Run: `./check` (if available)
- [ ] Verify: All checks pass

**Checkpoint 6:**
```bash
# Everything should be clean
git status
# Should show 7 modified files + new test file
```

---

### Phase 7: Documentation & Commit (15 min)

#### ☐ Step 11: Update Documentation
- [ ] Open `timing-attacks.md`
- [ ] Update vulnerability V1 status from "❌ FIX REQUIRED" to "✅ FIXED"
- [ ] Add note: "Fixed in commit [hash] on [date]"
- [ ] Save file
- [ ] Optional: Add to CHANGELOG.md if exists

#### ☐ Step 12: Commit Changes
- [ ] Review all changes one final time: `git diff`
- [ ] Stage documentation: `git add timing-attacks.md`
- [ ] Commit with message from Step 16 above
- [ ] Verify commit: `git show`

#### ☐ Step 13: Push and Create PR
- [ ] Push branch: `git push origin security/fix-timing-attacks`
- [ ] Create PR with description from Step 17 above
- [ ] Request security review from senior team member
- [ ] Link to timing-attacks.md in PR

---

## Post-Implementation Checklist

### Code Review (Team Lead)

- [ ] All ct_eq() calls reviewed and approved
- [ ] No remaining `==` or `!=` for tx_template_hash in production code
- [ ] Test coverage adequate (5 new tests)
- [ ] No performance regression
- [ ] Code follows CODE-GUIDELINE.md
- [ ] Commit message is clear and descriptive

### Deployment Preparation

- [ ] Merge PR to devel branch
- [ ] Deploy to devnet for 24 hours observation
- [ ] Monitor logs for any unexpected behavior
- [ ] Run load tests (if available)
- [ ] Deploy to testnet for 48 hours observation
- [ ] Plan mainnet deployment

### Security Sign-Off

- [ ] Vulnerability V1 confirmed mitigated
- [ ] No new vulnerabilities introduced
- [ ] Tests verify constant-time behavior
- [ ] Documentation updated
- [ ] timing-attacks.md marked as resolved

---

## Rollback Plan (If Issues Found)

**If tests fail or unexpected behavior:**

```bash
# Quick rollback
git reset --hard origin/devel

# Or revert the commit
git revert <commit-hash>

# Or abandon branch
git checkout devel
git branch -D security/fix-timing-attacks
```

**Then:**
1. Review error messages
2. Check timing-attacks.md for additional guidance
3. Ask for help in team chat
4. Re-attempt with corrections

---

## Troubleshooting

### Issue: "ct_eq method not found"

**Symptom:**
```
error[E0599]: no method named `ct_eq` found for struct `TxTemplateHash`
```

**Cause:** Step 2 not completed correctly (macro not updated)

**Fix:**
1. Verify `impl $name` block has `ct_eq()` method
2. Run `cargo clean --package igra-core` to regenerate macros
3. Run `cargo check --package igra-core` again

---

### Issue: "Tests fail after changes"

**Symptom:**
```
test domain::coordination::selection::test_select_canonical ... FAILED
```

**Cause:** Logic inversion error (forgot `!` when changing `!=` to `ct_eq()`)

**Fix:**
- Remember: `a != b` becomes `!a.ct_eq(&b)` (note the `!`)
- Review all changes for correct boolean logic

---

### Issue: "Timing test fails with high variance"

**Symptom:**
```
assertion failed: max_dev < threshold
```

**Cause:** CPU scheduling noise, not a real constant-time issue

**Fix:**
- Run test multiple times: `cargo test ct_eq_timing_sanity_check -- --test-threads=1`
- If consistently fails, increase threshold to 30% or 40%
- This is a sanity check, not proof of constant-time (acceptable to have variance)

---

### Issue: "Performance regression"

**Symptom:** Benchmarks show significant slowdown

**Cause:** Unlikely (ct_eq is highly optimized), but possible

**Fix:**
- Profile with: `cargo flamegraph --bench <benchmark>`
- If real regression found, consult with team
- subtle crate is used by Bitcoin/Ethereum, proven performant

---

## Time Tracking

**Actual Time Spent:**

| Phase | Estimated | Actual | Notes |
|-------|-----------|--------|-------|
| Phase 1 | 30 min | _____ min | Add ct_eq infrastructure |
| Phase 2 | 30 min | _____ min | Fix coordination layer |
| Phase 3 | 30 min | _____ min | Fix CRDT layer |
| Phase 4 | 30 min | _____ min | Fix storage layer |
| Phase 5 | 45 min | _____ min | Add tests |
| Phase 6 | 30 min | _____ min | Verification |
| Phase 7 | 15 min | _____ min | Commit & PR |
| **Total** | **2-3 hrs** | _____ hrs | |

---

## Sign-Off

**Developer:** ________________ (Name)
**Date Completed:** ________________
**All Tests Pass:** ☐ Yes ☐ No
**Code Review:** ________________ (Reviewer Name)
**Security Review:** ________________ (Security Lead)
**Approved for Merge:** ☐ Yes ☐ No
**Merged to devel:** ☐ Yes ☐ No (Date: ________)
**Deployed to testnet:** ☐ Yes ☐ No (Date: ________)
**Deployed to mainnet:** ☐ Yes ☐ No (Date: ________)

---

## Quick Reference: All Changes Summary

```
Files Modified: 7
Lines Added: ~140 (mostly tests)
Lines Modified: ~15
Test Coverage: 5 new tests

Changes by file:
1. types.rs: +15 lines (ct_eq implementation)
2. selection.rs: 2 lines changed
3. event_state.rs: 5 lines changed
4. memory.rs: 2 lines changed
5. phase.rs: 1 line changed
6. constant_time.rs: +120 lines (new test file)
7. unit/mod.rs: +1 line (module registration)
```

---

**Print this checklist and check off items as you complete them!**
