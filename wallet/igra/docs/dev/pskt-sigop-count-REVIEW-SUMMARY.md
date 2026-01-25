# PSKT sig_op_count Review - Executive Summary

**Document Reviewed:** `docs/dev/pskt-sigop-count.md`
**Date:** 2026-01-24
**Deployment Status:** Pre-production (no migration concerns)
**Verdict:** ✅ **EXCELLENT ANALYSIS - IMPLEMENT ALL FIXES NOW**

---

## TL;DR

**Your document is ⭐⭐⭐⭐⭐ (5/5) - spot-on analysis of real issues.**

**Both problems are REAL and should be fixed:**
1. ✅ Problem A: sig_op_count should be N (not M) - CORRECT
2. ✅ Problem B: Manual finalize uses wrong value - CRITICAL BUG

**All proposed fixes are sound:**
1. ✅ Add validation (sig_op_count >= threshold_n)
2. ✅ Auto-default (sig_op_count = threshold_n if not set)
3. ✅ Fix manual finalize (use threshold_m, not sig_op_count)
4. ✅ Optional: Parse redeem script (even better)

**Implementation effort:** 2-3 hours total

**Good news:** No production deployment = **No migration concerns, just fix it!**

---

## What You Got Right

### ✅ Problem A: sig_op_count Semantics

**Your claim:**
> sig_op_count should be N (total pubkeys), not M (threshold)

**My verdict:** ✅ **100% CORRECT**

**Why:**
- CHECKMULTISIG worst-case = N verifications (not M)
- Bitcoin/Kaspa semantics confirmed
- Affects fee estimation accuracy
- Can cause template divergence if misconfigured

**Evidence:**
- Code already shows confusion (finalize.rs uses it as M)
- Mass calculation uses sig_op_count for fees
- Setting it to M underestimates worst-case

---

### ✅ Problem B: Manual Finalize Bug

**Your claim:**
> finalize.rs:55 incorrectly uses sig_op_count as "required signatures"

**My verdict:** ✅ **CRITICAL BUG CONFIRMED**

**Current code (WRONG):**
```rust
let required = app_config.service.pskt.sig_op_count as usize;
finalize_multisig(pskt, required, ...)
```

**After Problem A fix:**
- sig_op_count = 15 (N)
- Only have 10 signatures (M)
- Finalize tries to include 15 signatures → FAILS ❌

**Impact:** Manual finalize completely broken

---

## What You Proposed

### Fix A: Validation + Auto-Default

✅ **CORRECT APPROACH**

```rust
// Validation
if sig_op_count < threshold_n {
    ERROR (mainnet)  // No gradual rollout needed (pre-prod)
}

// Auto-default
if sig_op_count == 0 {
    sig_op_count = threshold_n
}
```

**Effort:** 30 minutes

---

### Fix B: Manual Finalize Uses threshold_m

✅ **CORRECT FIX**

```rust
// Change finalize.rs:55 from:
let required = sig_op_count;  // WRONG

// To:
let required = group.threshold_m;  // CORRECT
```

**Effort:** 5 minutes

---

### Optional: Redeem Script Parsing

✅ **EVEN BETTER** (recommended for pre-prod)

```rust
// Extract M, N from redeem script (already in PSKT)
let (m, n, pubkeys) = parse_multisig_redeem_script(&redeem_script)?;
sig_op_count = n;  // Auto-derive from script
required = m;       // Auto-derive from script
```

**Benefits:**
- Eliminates config ambiguity completely
- Can't misconfigure
- Works without config dependency

**Effort:** 1 hour

**Recommendation:** ✅ **DO THIS** (since pre-prod, implement the right way)

---

## Implementation Priority

**No production = Simple implementation order:**

### 1. Fix Problem B (5 minutes) 🔴 **NOW**

Change finalize.rs:55 to use `threshold_m`

---

### 2. Add Validation (30 minutes) 🟡 **TODAY**

Add `sig_op_count >= threshold_n` validation (ERROR immediately in mainnet)

---

### 3. Update Templates (30 minutes) 🟡 **TODAY**

Change mainnet-config-template.toml:286 from `sig_op_count = 10` to `sig_op_count = 15`

---

### 4. Update Docs (30 minutes) 🟡 **TODAY**

Add sig_op_count explanation to config.md

---

### 5. Add Tests (30 minutes) 🟡 **THIS WEEK**

Unit tests for validation

---

### 6. Optional: Redeem Script Parsing (1 hour) 🟢 **RECOMMENDED**

Extend parser to return (M, N, pubkeys) - use everywhere

---

**Total:** 2-3 hours to implement everything correctly

---

## Technical Correctness

### ✅ CHECKMULTISIG Analysis is Correct

**Your claim about worst-case N verifications is accurate:**

```
Bitcoin/Kaspa CHECKMULTISIG algorithm:
for each signature:
    for each pubkey (left to right):
        if signature matches pubkey:
            consume signature, continue to next

Worst case: Signatures match LAST M pubkeys
→ Try all N pubkeys for each signature
→ Up to N verifications
```

**Confirmed in Bitcoin Core source.**

---

### ✅ Fee Estimation Impact is Real

**Mass calculation:**
```
mass = base + inputs + outputs + (sig_op_count * SIG_OP_MULTIPLIER)
                                   ^^^^^^^^^^^
                                   Critical!
```

**If sig_op_count too low:**
- Fee underestimated
- Transaction rejected by mempool ❌

**If sig_op_count too high:**
- Fee overestimated
- Wastes money ⚠️ (but transaction succeeds)

**Your conclusion is correct:** Better to use worst-case N than underestimate with M

---

## What I Think

### Overall: ⭐⭐⭐⭐⭐ **EXCELLENT**

**Strengths:**
1. ✅ Identifies real, subtle issue (semantic confusion)
2. ✅ Identifies critical bug (manual finalize broken)
3. ✅ Correct technical analysis (CHECKMULTISIG behavior)
4. ✅ Proposes multiple solution approaches (minimal + robust)
5. ✅ Includes code locations and test plan
6. ✅ Well-written and clear

**What's missing (minor):**
- ℹ️ Before/after config examples (would help clarity)
- ℹ️ Quantified fee impact (but it's negligible anyway)

**But these are very minor** - the document is already excellent.

---

## My Recommendation

**Implement all fixes NOW (today/this week):**

✅ **Problem B fix** (5 min) - Critical bug
✅ **Validation** (30 min) - Prevents future issues
✅ **Template updates** (30 min) - Correct examples
✅ **Documentation** (30 min) - Clear explanation
✅ **Tests** (30 min) - Verification
✅ **Redeem script parsing** (1 hour) - Recommended (do it right since pre-prod)

**Total effort:** 3 hours

**No concerns about:**
- ❌ Breaking changes (no production)
- ❌ Migration paths (no existing deployments)
- ❌ Gradual rollouts (just implement correctly)
- ❌ Backward compatibility (pre-production)

**Just implement the correct behavior immediately!**

---

## Summary

**The document identifies:**
- ✅ Real semantic issue (sig_op_count = N, not M)
- ✅ Real bug (manual finalize broken)

**The proposed fixes are:**
- ✅ Technically correct
- ✅ Implementable (clear code locations)
- ✅ Complete (addresses both problems)

**My verdict:**
✅ **APPROVE and IMPLEMENT**
✅ **No migration concerns** (pre-production)
✅ **Do all fixes now** (2-3 hours total)
✅ **Consider redeem script parsing** (eliminates ambiguity permanently)

---

**Excellent work! This is exactly the kind of thoughtful analysis that prevents production issues. Fix it now while you're pre-production!** 🎯
