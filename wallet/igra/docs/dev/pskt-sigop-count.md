# PSKT `sig_op_count` Semantics + Manual Finalize Fix

**Status:** DRAFT (for review)
**Last updated:** 2026-01-24

This doc captures two related issues:

1. `service.pskt.sig_op_count` is frequently interpreted as the multisig threshold `M`, but for classic `OP_CHECKMULTISIG` scripts it must be treated as a *sigops budget upper bound* (≈ `N`).
2. The manual finalize mode currently treats `sig_op_count` as “required signatures”, which is incorrect and can prevent finalization.

The intent is to remove ambiguity and make behavior consistent across:
- PSKT build/fee estimation,
- CRDT threshold checks,
- manual finalize (`kaspa-threshold-service --finalize`).

---

## 1) Problem A: `sig_op_count` Underestimates Worst-Case Sigops

### 1.1 What `sig_op_count` Means in Our Code

In our PSKT domain we pass `sig_op_count` through into each `TransactionInput.sig_op_count` and use it during fee/mass estimation:

- `igra-core/src/domain/pskt/params.rs:17` (`PsktParams.sig_op_count`)
- `igra-core/src/domain/pskt/multisig.rs:45` (PSKT input builder `.sig_op_count(...)`)
- `igra-core/src/domain/pskt/builder.rs:261-287` (`estimate_compute_mass_for_signed_tx(..., sig_op_count, ...)`)

We already document that it is **not** the multisig threshold:

- `igra-service/src/service/coordination/crdt/submission.rs:30-32`

### 1.2 Why `M-of-N` CHECKMULTISIG May Execute ~`N` Verifications

For a classic redeem script:

```
OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
```

the CHECKMULTISIG verification procedure is effectively “scan pubkeys left-to-right, trying to match the next signature”.

If the available `M` signatures correspond to pubkeys late in the list, the interpreter can perform many failed checks before finding matches. In the worst case, the number of signature verifications is bounded by approximately the **position of the last pubkey that must be matched**, which can be **`N`**.

Example:
- `N = 20`, `M = 11`
- the only signers online are “the last 11 pubkeys”
- a naive CHECKMULTISIG scan ends up doing ~`20` signature checks

This is exactly the scenario where setting `sig_op_count = M` underestimates actual executed sigops.

### 1.3 Why This Matters

- Underestimating `sig_op_count` can under-estimate transaction mass/fee and lead to mempool rejection or unreliable fee behavior.
- Inconsistent `sig_op_count` across signers can cause **template divergence** (different tx template hashes), which breaks the protocol.

### 1.4 Proposed Fix (Design + Behavior)

**Policy:** for CHECKMULTISIG-based scripts, treat `sig_op_count` as:

> `sig_op_count = N` (the number of pubkeys in the redeem script), not `M`.

**Implementation strategy (minimal change):**

1. **Add validation and guidance**:
   - If `group.threshold_n` is configured, require:
     - `sig_op_count >= group.threshold_n`
   - If only `service.hd.required_sigs` exists (legacy), at minimum require:
     - `sig_op_count >= required_sigs`
   - In production profiles, treat violations as **startup errors**; in devnet/testnet allow **warnings** (optionally).

2. **Auto-default when not configured**:
   - If `service.pskt.sig_op_count == 0` (or missing in older configs), set:
     - `sig_op_count = group.threshold_n` when group config is present
     - else fallback to a conservative safe default (legacy), but **emit a warning**

3. **Improve docs/templates**:
   - Update `docs/config/mainnet-config-template.toml` comments and example so:
     - `sig_op_count = threshold_n` (not `threshold_m`)
   - Update `docs/config/config.md` section to explicitly call it “sigops upper bound” for CHECKMULTISIG.

**Implementation locations:**
- Config validation: `igra-core/src/infrastructure/config/validation.rs` (add checks tied to network mode policy)
- Config load defaults: `igra-core/src/infrastructure/config/loader.rs` (derive default from group)
- Docs: `docs/config/*.md` + template TOMLs

**Optional (stronger, less config-dependent):**
- Parse the redeem script to recover `N` deterministically and use that as the recommended/required value.
  - We already parse redeem scripts in `igra-core/src/domain/pskt/multisig.rs:177-237` (but currently only returns pubkeys).
  - Add a helper returning `{ m, n, pubkeys }` and use `n` as the `sig_op_count` recommendation/enforcement.

---

## 2) Problem B: Manual Finalize Uses `sig_op_count` as Required Signatures

### 2.1 Current Behavior

In manual finalize mode (`kaspa-threshold-service --finalize <pskt.json>`), we currently do:

- `igra-service/src/bin/kaspa-threshold-service/modes/finalize.rs:55`
  - `let required = app_config.service.pskt.sig_op_count as usize;`
  - `finalize_multisig(pskt, required, &ordered_pubkeys)`

This treats `sig_op_count` as “how many signatures to include” (i.e. `M`), which contradicts the intended meaning in the main service path.

### 2.2 Impact

If `sig_op_count` is correctly set to `N` (Problem A fix), then manual finalize will incorrectly require `N` signatures to finalize, making it impossible to finalize in normal `M-of-N` operation.

### 2.3 Proposed Fix (Design + Behavior)

**Policy:** “required signatures” for finalization must always be derived from the multisig threshold `M`, not `sig_op_count`.

**Implementation strategy (minimal change):**

1. Replace the `required` computation in manual finalize with the same derivation used by the coordinator:
   - If `group` config present: `required = group.threshold_m`
   - Else: `required = service.hd.required_sigs`

2. Ensure the manual finalize code path logs both values distinctly:
   - `required_signatures=M`
   - `sig_op_count=N` (budget)

**Implementation locations:**
- `igra-service/src/bin/kaspa-threshold-service/modes/finalize.rs`
- (Optional) factor out a shared helper used in both:
  - `igra-service/src/service/coordination/crdt/submission.rs`
  - `igra-service/src/bin/kaspa-threshold-service/modes/finalize.rs`

**Optional (more robust / fewer config footguns):**

Derive `M` and ordered pubkeys from the PSKT’s redeem script, so the finalize tool doesn’t depend on local config matching:

- Parse redeem script from the PSKT itself (it is present on each input).
- Extract:
  - `M` (threshold)
  - ordered pubkeys
- Use those values for `finalize_multisig`.

This makes “manual finalize” work as a pure “finalize what the network already agreed on” tool, even if local config drifted.

---

## 3) Recommended End-State

After implementing both fixes:

- `sig_op_count` is consistently treated as a **sigops budget** (≈ `N` for CHECKMULTISIG).
- The **threshold** is consistently derived from:
  - `group.threshold_m` (preferred), or
  - `service.hd.required_sigs` (legacy).
- Manual finalize uses `M` for signature inclusion and is compatible with `sig_op_count = N`.

---

## 4) Test/Verification Plan (Non-Interactive)

### 4.1 Unit Tests

- Add/extend tests that:
  - reject configs where `sig_op_count < threshold_n` (production policy)
  - ensure manual finalize uses `threshold_m` (not `sig_op_count`)

### 4.2 Integration/Behavior Checks

- Run `cargo test -p igra-core -p igra-service -- --nocapture`
- (Manual) Verify that:
  - service produces identical templates across signers when `sig_op_count=N`
  - manual finalize can finalize with exactly `M` signatures present in RocksDB

