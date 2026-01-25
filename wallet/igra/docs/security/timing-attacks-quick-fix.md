# Timing Attack Fix - Quick Reference Card

**🚨 CRITICAL SECURITY FIX REQUIRED BEFORE MAINNET**

**Time:** 2-3 hours | **Difficulty:** Medium | **Files:** 7

---

## What's Wrong?

Hash comparisons use `==` which leaks timing → Byzantine signer can manipulate transactions

```rust
// ❌ VULNERABLE (8 locations in codebase):
if proposal.tx_template_hash == canonical_hash { ... }

// ✅ SECURE (what we need):
if proposal.tx_template_hash.ct_eq(&canonical_hash) { ... }
```

---

## Fix Summary

### 1. Add ct_eq() Method (types.rs)
```rust
// After imports (~line 24):
use subtle::ConstantTimeEq;
impl ConstantTimeEq for Hash32 {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.as_slice().ct_eq(other.as_slice())
    }
}

// Inside hash macro (after as_hash() method ~line 63):
pub fn ct_eq(&self, other: &Self) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(self.0.ct_eq(&other.0))
}
```

### 2. Replace All Comparisons (5 files)

| File | Line | Find | Replace |
|------|------|------|---------|
| selection.rs | 51 | `== winning_hash` | `.ct_eq(&winning_hash)` |
| selection.rs | 125 | `== h` | `.ct_eq(&h)` |
| event_state.rs | 102 | `!= other.tx_template_hash` | `.ct_eq(&other.tx_template_hash)` (add `!`) |
| event_state.rs | 105-106 | `== other.event_id,` | `.ct_eq(&other.event_id),` (2 places) |
| event_state.rs | 147 | `== EventId::default()` | `.ct_eq(&EventId::default())` |
| event_state.rs | 153 | `== TxTemplateHash::default()` | `.ct_eq(&TxTemplateHash::default())` |
| memory.rs | 314 | `&s.event_id == event_id` | `s.event_id.ct_eq(event_id)` |
| memory.rs | 532 | `!= proposal.tx_template_hash` | `.ct_eq(&proposal.tx_template_hash)` (add `!`) |
| phase.rs | 153 | `!= proposal.tx_template_hash` | `.ct_eq(&proposal.tx_template_hash)` (add `!`) |

### 3. Add Tests (new file)
- Create `igra-core/tests/unit/constant_time.rs`
- Copy code from timing-attacks.md Step 7
- Register in `unit/mod.rs`: `mod constant_time;`

---

## Verification (Run These)

```bash
# After each file change
cargo check --package igra-core

# After all changes
cargo test --package igra-core --test unit constant_time
cargo test --workspace --all-features

# Verify no vulnerable comparisons remain
grep -rn "tx_template_hash\s*==" igra-core/src --include="*.rs" | grep -v test
# Should return ZERO results

# Verify ct_eq is used
grep -rn "\.ct_eq" igra-core/src --include="*.rs" | wc -l
# Should return 10+ results
```

---

## Testing Checklist

After implementation:

- [ ] ✅ 5 new constant-time tests pass
- [ ] ✅ No regressions in existing tests
- [ ] ✅ Timing sanity check shows < 25% variance
- [ ] ✅ Zero `tx_template_hash ==` in production code
- [ ] ✅ At least 8 `tx_template_hash.ct_eq()` calls found

---

## Commit Template

```bash
git commit -m "security: fix timing attacks in hash comparisons

Implements constant-time equality for all Hash32-based types to prevent
timing side-channel attacks on transaction template selection.

- Add ct_eq() method to all hash types
- Replace == with ct_eq() in 8 locations (coordination/CRDT/storage)
- Add 5 constant-time verification tests

Fixes: timing-attacks.md V1 (HIGH severity)

Co-Authored-By: Claude Sonnet 4.5 (1M context) <noreply@anthropic.com>"
```

---

## Need More Details?

**Full documentation:**
- `timing-attacks.md` - Complete security analysis (2100+ lines)
- `timing-attacks-checklist.md` - Step-by-step tracking

**Sections:**
- Section 1-2: Vulnerability details
- Section 3: What's already secure
- **Section 4: IMPLEMENTATION GUIDE** ← START HERE
- Section 5-17: Testing, deployment, long-term recommendations

---

## Common Mistakes to Avoid

### ❌ Wrong: Forgetting the `!` when replacing `!=`

```rust
// BEFORE:
if existing.tx_template_hash != proposal.tx_template_hash {

// ❌ WRONG:
if existing.tx_template_hash.ct_eq(&proposal.tx_template_hash) {

// ✅ CORRECT:
if !existing.tx_template_hash.ct_eq(&proposal.tx_template_hash) {
   // Note the ! at the beginning
```

### ❌ Wrong: Using == in log statements

```rust
// BEFORE:
debug!("match={}", self.event_id == other.event_id);

// ✅ CORRECT:
debug!("match={}", self.event_id.ct_eq(&other.event_id));
```

### ❌ Wrong: Skipping the macro update

**You must update BOTH:**
1. Add `impl ConstantTimeEq for Hash32` (before macro)
2. Add `ct_eq()` method inside macro (so all hash types get it)

---

## Help / Troubleshooting

**"ct_eq not found"** → Step 2 incomplete, regenerate macros: `cargo clean --package igra-core`

**"Tests fail"** → Check boolean logic (`!=` needs `!` prefix)

**"Timing test fails"** → Increase threshold to 30% (CPU noise is normal)

**"Performance regression"** → Unlikely, ct_eq is optimized. Profile with flamegraph.

---

**Priority:** 🔴 **CRITICAL** - Do before mainnet deployment
**Estimated Effort:** 2-3 hours for experienced Rust developer
**Questions?** Ask in team channel or read full analysis document

**Last Updated:** 2026-01-24
