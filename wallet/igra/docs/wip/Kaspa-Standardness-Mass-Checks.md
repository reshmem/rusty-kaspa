# Kaspa Standardness Mass Checks in PSKT Builder (compute + transient + storage)

Status: **WIP design** (doc-only; do not implement yet)

This document proposes tightening `igra-core` PSKT construction so we **match kaspad standardness** when we build transaction templates:
- enforce **compute mass**, **transient mass**, and **storage/contextual mass** limits (not just storage mass), and
- compute the **minimum relay fee** using the same “effective tx mass” definition (the maximum of those mass components).

This is a small/contained change, but it has **large liveness impact** when UTXO sets are fragmented or when multisig scripts are large.

---

## 1) Why this matters

### 1.1 Today we can build PSKTs that kaspad will never accept

Currently `igra-core/src/domain/pskt/builder.rs`:
- enforces only **storage mass** (`calc_storage_mass(...)`) against `MAXIMUM_STANDARD_TRANSACTION_MASS` (100_000) in the UTXO selection loop (`build_pskt_from_utxos`, check at `builder.rs:137`).
- uses **compute mass** only to derive an “auto fee” (`apply_fee_policy_with_auto_fee`, `builder.rs:311–318`).
- does **not** enforce **compute mass** or **transient mass** limits.
- derives the “minimum relay fee” from **compute mass only** (`minimum_relay_fee_sompi_for_compute_mass`, `builder.rs:250`).

But kaspad standardness checks include:
- `compute_mass <= MAXIMUM_STANDARD_TRANSACTION_MASS`
- `transient_mass <= MAXIMUM_STANDARD_TRANSACTION_MASS`
- and a contextual mass limit (the transaction’s contextual/storage mass) ≤ `MAXIMUM_STANDARD_TRANSACTION_MASS`

See `mining/src/mempool/check_transaction_standard.rs:64–70` (compute+transient) and `mining/src/mempool/check_transaction_standard.rs:174–177` (contextual/storage).

If we build a PSKT that violates compute/transient mass, signers can:
1) converge on a proposal,
2) sign it,
3) and then hit **permanent submission failure** (“not standard”).

This wastes time, burns retries, and can stall events indefinitely.

### 1.2 Fee underestimation is possible (and looks like “random mempool rejection”)

Kaspa’s minimum relay fee is computed from the transaction’s mass.

In the wallet PSKT code, extracted transactions set `tx.mass` as:
`max(storage_mass, compute_mass, transient_mass)` (see `pskt/src/pskt.rs:458–462` in the workspace root).

However, Igra’s `apply_fee_policy_with_auto_fee` currently computes the minimum fee from **compute mass only**.
If `storage_mass` or `transient_mass` is the dominant component, the computed fee can be too low and kaspad will reject with
“not standard … under the required amount”.

We already treat “under the required amount” as non-retryable at submission time (`igra-service/src/service/flow.rs:138–139`),
but that still means we wasted the entire propose/commit/sign cycle.

### 1.3 This is a prerequisite for consolidation/sweep designs

Any consolidation (“sweep-to-self”) work must also satisfy standardness. If the builder is incomplete, consolidation can
produce self-sweeps that fail at submission for compute/transient reasons and lock up maintenance jobs.

---

## 2) Goals / Non-goals

### Goals
- Match kaspad’s standardness constraints earlier at **proposal build time** (before CRDT signing).
- Use the correct “effective tx mass” (`max(storage, compute, transient)`) for **auto-fee**.
- Keep everything deterministic (no new randomness; no network calls; same behavior across signers).
- Keep the change localized to `igra-core/src/domain/pskt/builder.rs`.

### Non-goals (for this change)
- Do not change the UTXO selection strategy (seeded ordering, largest-first fallback, consolidation planning).
- Do not introduce new storage schemas or protocol changes.
- Do not solve “1M UTXOs” RPC paging issues (separate problem; gRPC message size can fail before we even build).

---

## 3) Proposed design

### 3.1 Enforce all mass components during build

When a candidate (inputs + outputs + fee) is found, compute:
- `storage_mass` (contextual/KIP-0009) via `calc_storage_mass(...)`
- `compute_mass` + `transient_mass` via `MassCalculator::calc_non_contextual_masses(...)`

Then require:
- `storage_mass <= MAXIMUM_STANDARD_TRANSACTION_MASS` (100_000)
- `compute_mass <= MAXIMUM_STANDARD_TRANSACTION_MASS`
- `transient_mass <= MAXIMUM_STANDARD_TRANSACTION_MASS`

Rationale:
- This matches the mempool checks (`mining/src/mempool/check_transaction_standard.rs`).
- If any mass component is too large, the template is non-standard and should not be proposed.

### 3.2 Compute min relay fee from “effective mass”

In the auto-fee loop, compute:

`effective_mass = max(storage_mass, compute_mass, transient_mass)`

Then compute:

`min_fee = minimum_relay_fee_sompi_for_mass(effective_mass)`

This aligns the fee with how transaction mass is treated by wallet extraction code (`pskt/src/pskt.rs:458–462`) and avoids
“fee too low” mempool rejects caused by using only compute mass.

### 3.3 Error reporting

No new error enums are required for this change. We can continue using:
- `ThresholdError::PsktValidationFailed(String)`

But the message should clearly indicate *which* component exceeded the limit, e.g.:
- `transaction compute mass {compute_mass} exceeds standard limit {MAXIMUM_STANDARD_TRANSACTION_MASS}`
- `transaction transient mass {transient_mass} exceeds standard limit ...`
- `transaction storage mass {storage_mass} exceeds standard limit ...`

This makes operator debugging much easier.

---

## 4) Implementation plan (exact code locations)

All changes are in `igra-core/src/domain/pskt/builder.rs`.

### 4.1 Add non-contextual mass helper (compute + transient)

Current helper:
- `estimate_compute_mass_for_signed_tx(...) -> u64` (`builder.rs:261–287`)

Replace with:
- `estimate_non_contextual_masses_for_signed_tx(...) -> NonContextualMasses`

Notes:
- Import `kaspa_consensus_core::mass::NonContextualMasses`.
- Keep using the same `signature_script_template` approach so the mass estimate matches final signatures (same script length).

### 4.2 Make min-relay-fee helper accept “mass”

Current:
- `minimum_relay_fee_sompi_for_compute_mass(compute_mass: u64)` (`builder.rs:250–259`)

Replace with:
- `minimum_relay_fee_sompi_for_mass(mass: u64)`

Then update all call sites to pass `effective_mass`.

### 4.3 Update `apply_fee_policy_with_auto_fee` to use effective mass

Current signature:
- `apply_fee_policy_with_auto_fee(..., mass_calc, selected_inputs, ..., signature_script_template, outputs)` (`builder.rs:289–334`)

Change:
- Either pass `storm_param` into this function, or pass a `calc_storage_mass_for_candidate` closure, so we can compute `storage_mass`
  inside the auto-fee fixed-point loop.

Pseudo-steps inside the loop (`builder.rs:305–325`):
1) Build candidate outputs for fee `fee`.
2) Compute:
   - `storage_mass` for `(selected_inputs, outputs)` via `calc_storage_mass(...)` with the same `storm_param` we use in the main loop.
   - `NonContextualMasses { compute_mass, transient_mass }` via the new helper.
3) `effective_mass = max(storage_mass, compute_mass, transient_mass)`.
4) `min_fee = minimum_relay_fee_sompi_for_mass(effective_mass)`.
5) Iterate until fee stabilizes (keep the existing bounded 4-iteration loop).

### 4.4 Enforce compute/transient limits in the main selection loop

In `build_pskt_from_utxos`:
- After fee policy succeeds (`builder.rs:132`) and after storage mass is computed (`builder.rs:133–135`), compute non-contextual masses:
  - `let NonContextualMasses { compute_mass, transient_mass } = ...;`
- Enforce:
  - if `compute_mass > MAXIMUM_STANDARD_TRANSACTION_MASS`: return `PsktValidationFailed(...)`
  - if `transient_mass > MAXIMUM_STANDARD_TRANSACTION_MASS`: return `PsktValidationFailed(...)`
  - keep existing `storage_mass > ...` behavior (`builder.rs:137–139`)

Why “return” (not “continue”) for compute/transient?
- With the current “prefix selection” strategy, adding more inputs only increases compute/transient mass, so the rest of the loop
  cannot succeed under the same ordering. Failing fast is both correct and much cheaper.

### 4.5 Optional: submission-side error classification

If we don’t implement builder-side checks immediately, we should at least consider expanding
`is_non_retryable_submission` to include compute/transient mass reject strings (today it only matches storage-mass, fee, and sigop cases):
- `igra-service/src/service/flow.rs:134–140`

This is optional if builder-side checks are added (preferred), but it helps prevent repeated retries if a non-standard template slips through.

---

## 5) Edge cases and failure modes if we don’t do this

1) **Compute-mass overflow with “normal” input counts**
   - Multisig signature scripts are large.
   - Even under proposal caps (≤100 inputs), compute mass can be the binding constraint and kaspad will reject.
   - Without early enforcement, the system burns a full propose/commit/sign cycle on a tx that can never enter the mempool.

2) **Transient-mass overflow**
   - Serialized-size driven cases can fail transient mass even when storage mass is acceptable.
   - Today we don’t check it at all.

3) **Under-fee due to wrong mass basis**
   - Auto-fee uses compute mass only; if storage/transient dominates, we underpay.
   - This causes “not standard … under the required amount” rejections at submission time.

4) **Retry storms and “stuck events”**
   - Submission retries are bounded per attempt, but CRDT state updates can trigger repeated submission attempts across signers.
   - A permanently non-standard tx wastes time and creates noisy logs/metrics, and can block processing until humans intervene.

---

## 6) Tests (what to test)

Location: `igra-core/tests/unit/` (fast, deterministic).

1) **Builder rejects compute-mass overflow**
   - Create a large redeem script / high required signatures and enough inputs to push compute mass over 100_000.
   - Assert `build_pskt_from_utxos` returns `PsktValidationFailed` mentioning “compute mass”.

2) **Builder rejects transient-mass overflow**
   - Construct a case that pushes transient mass over 100_000 (may require many inputs/large scripts).
   - Assert the error mentions “transient mass”.

3) **Auto-fee uses effective mass**
   - Build a tx where `max(storage, transient) > compute` (or at least verify the fee equals `min_fee(max(...))` computed independently).
   - Assert builder-produced fee is ≥ independently computed minimum fee.

4) **Regression: storage mass behavior unchanged**
   - Reuse an existing storage-mass-too-large scenario and assert the same failure mode/message remains (or is improved but consistent).

Note: transient-mass-dominant cases can be tricky to craft; it’s acceptable to build a case where both compute+transient exceed
the limit, and assert we check both components (e.g. by checking which message triggers first, or by structuring error reporting).

---

## 7) Rollout / risk

This change is low risk:
- It does not alter protocol messages or storage schemas.
- It only rejects templates that kaspad would reject anyway.
- It improves determinism and liveness by preventing “doomed” proposals from being signed.

The only expected behavior change is:
- Some events that previously progressed to signing (and then failed at submission) will fail earlier at proposal build time,
  with clearer error messages.

