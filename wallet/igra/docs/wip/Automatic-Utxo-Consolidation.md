# Automatic UTXO Consolidation (Sweep-to-Self) for Large Payouts

Status: **WIP design** (intended to be implemented in `igra-core` + `igra-service`)

This document proposes an implementation for automatically handling **fragmented UTXO sets** where the wallet has enough total balance, but a **single standard Kaspa transaction cannot include enough inputs** (mass/size/standardness limits).

Concrete example:
- Multisig has **1000 UTXOs × 0.01 KAS**.
- Need to bridge/payout **9 KAS**.
- Even though total balance is enough, a single tx would need ~900 inputs, which violates our own proposal limits and Kaspa standardness.

The chosen policy decisions for this design:
- **Require the normal depth gate** (do not spend shallow/unconfirmed UTXOs).
- Add a new internal event source: `SourceType::MaintenanceConsolidation`.

---

## 1) Why this fails today (current code + constraints)

There are two separate “input limits” in the current stack:

### 1.1 Two-phase proposal hard limit (100 inputs)

Two-phase proposal validation rejects any proposal with >100 UTXOs:
- Limit constant: `MAX_UTXOS_PER_PROPOSAL = 100` in `igra-core/src/domain/coordination/config.rs` (near the top; see lines ~5–7).
- Enforced in proposal validation: `igra-core/src/domain/coordination/proposal.rs` in `Proposal::validate_structure()` (see lines ~38–56, especially the check against `MAX_UTXOS_PER_PROPOSAL`).

So even if we could build a PSKT with 900 inputs, we **cannot propose/commit** such a template in the current protocol.

### 1.2 PSKT builder limit + standardness mass

The PSKT builder currently:
- Selects a prefix of UTXOs and checks storage mass only against standard limit:
  - `igra-core/src/domain/pskt/builder.rs`:
    - selection loop + storage mass check: around lines ~102–160
    - uses `kaspa_wallet_core::tx::mass::MAXIMUM_STANDARD_TRANSACTION_MASS` (100_000)
- Allows up to `MAX_PSKT_INPUTS = 1000`:
  - `igra-core/src/foundation/constants.rs` (near line ~37)

This means the builder can attempt far more inputs than the **proposal layer** allows, and it does not explicitly enforce the **proposal layer**’s `MAX_KPSBT_SIZE` / `MAX_UTXOS_PER_PROPOSAL` constraints.

### 1.3 Depth gating exists only at commit-time

Depth gating is enforced during commit revalidation:
- `igra-service/src/service/coordination/two_phase_handler.rs` calls `revalidate_inputs(...)` (around line ~299).
- That calls `igra-core/src/application/two_phase.rs::revalidate_utxos_for_proposal(...)` (around line ~101), comparing `tip_blue_score - utxo.entry.block_daa_score` against `two_phase.min_input_score_depth`.

However, **UTXO selection** currently does not filter by depth at build-time (we fetch all UTXOs from RPC in `igra-core/src/infrastructure/rpc/kaspa_integration/mod.rs` and pass them directly into the builder).

This design keeps the “normal depth gate” but recommends moving depth filtering earlier to reduce retries and avoid accidental mempool-chaining.

---

## 2) High-level design (what we do instead)

When we cannot construct a payout tx within protocol + standardness constraints, we automatically create **one or more “sweep-to-self” consolidation transactions** that:
- Spend many small UTXOs (bounded by proposal limits),
- Produce a smaller set of larger UTXOs back to the multisig (`change_address`),
- Wait for the resulting outputs to become **deep** (normal depth gate),
- Then retry the payout using the new larger UTXOs.

Important properties:
- Consolidation transactions **do not pay third parties** (only to our own change/multisig address).
- Consolidation transactions are signed via the **same two-phase + CRDT threshold signing** flow as normal payouts.
- Consolidation outputs are not spendable until **min depth** (no mempool chains).

---

## 2.1 Implementation checklist (file-by-file)

This section is the “do this, in these exact places” version of the design.

### Domain / types
- `igra-core/src/domain/model.rs`
  - Add `GroupPolicy.amount_multiple_sompi: Option<u64>` (e.g. 100 KAS).
  - Add `SourceType::MaintenanceConsolidation { parent_event_id: EventId, job_nonce: Hash32, step_index: u16, stage_index: u16 }`.
- `igra-core/src/domain/hashes.rs`
  - Extend `encode_source_v1(...)` to include the new `SourceType::MaintenanceConsolidation` fields so `EventId` derivation stays deterministic and compile-time exhaustive.
- `igra-core/src/domain/policy/enforcement.rs`
  - Enforce `policy.amount_multiple_sompi` for non-maintenance events.
- `igra-core/src/domain/event/types.rs`
  - No changes required for wire structs, but external ingress must reject this source (Section 5.1).
- `igra-core/src/foundation/error.rs`
  - Add `ThresholdError::NeedsConsolidation { ... }` and `ThresholdError::ForbiddenSourceType { ... }` (or equivalent), and map to an API error code if needed.

### PSKT building / limits
- `igra-core/src/domain/pskt/builder.rs`
  - Add a proposal-safe payout builder that enforces:
    - `MAX_UTXOS_PER_PROPOSAL` (`igra-core/src/domain/coordination/config.rs`)
    - `MAX_KPSBT_SIZE` (`igra-core/src/domain/coordination/config.rs`)
    - `MAXIMUM_STANDARD_TRANSACTION_MASS` (`kaspa_wallet_core::tx::mass::MAXIMUM_STANDARD_TRANSACTION_MASS`)
  - Add a dedicated consolidation builder that:
    - creates exactly one output to `change_address`
    - returns deterministic template hashes
  - Add “largest-first fallback” for payout when blocked by the input cap.

### Depth gating at build-time
- `igra-core/src/application/two_phase.rs`
  - Extend `build_local_proposal_for_round(...)` signature to accept `min_input_score_depth` and pass it into RPC build.
- `igra-core/src/infrastructure/rpc/kaspa_integration/mod.rs`
  - Extend `build_pskt_with_client_seeded(...)` / `build_pskt_from_rpc_seeded(...)` to accept `min_input_score_depth`.
  - Filter UTXOs by depth before passing into builder (Section 6).

### Ingress + proposal validation
- `igra-core/src/application/event_processor.rs`
  - Reject `MaintenanceConsolidation` in external RPC path (Section 5.1).
  - On `NeedsConsolidation` from payout proposal build, call `utxo_management::ensure_consolidation_job_for_payout(...)`.
- `igra-service/src/service/coordination/two_phase_handler.rs`
  - In `validate_proposal(...)`, add a maintenance-specific validation branch:
    - bypass destination whitelist + daily volume
    - enforce destination == our change/source address

### Storage / accounting
- `igra-core/src/infrastructure/storage/traits.rs`
  - Add consolidation job state getters/setters.
- `igra-core/src/infrastructure/storage/memory.rs`
  - Skip daily volume increment for `MaintenanceConsolidation`.
  - Implement consolidation job state storage.
- `igra-core/src/infrastructure/storage/rocks/engine/storage.rs`
  - Skip `add_to_daily_volume(...)` for `MaintenanceConsolidation`.
  - Implement consolidation job state storage (new CF or key namespace).

### Retry path
- `igra-service/src/service/coordination/two_phase_timeout.rs`
  - When proposal rebuild fails with `NeedsConsolidation`, ensure consolidation job exists (coordinator restarts).

### Proactive maintenance
- `igra-service/src/service/coordination/loop.rs`
  - Spawn a `run_utxo_maintenance_loop(...)` task when `service.utxo_management.maintenance_enabled=true`.
- `igra-core/src/application/utxo_management.rs`
  - Add `maybe_run_periodic_maintenance(...)` and reuse the consolidation job planner with a synthetic `parent_event_id` (Section 5.7.3).

---

## 2.2 Policy coupling (multiples-of + parallelism)

This system can be made *much* more operationally stable by tying UTXO management to policy.

You described a deployment policy like:
- withdrawals must be **exact multiples of 100 KAS**
- `min_withdrawal = 100 KAS`
- `max_withdrawal = 1,000,000 KAS`
- many events are processed in parallel

### 2.2.1 Add “amount multiple” to group policy

Current policy fields only cover min/max/whitelist/velocity (see `GroupPolicy` in `igra-core/src/domain/model.rs` and enforcement in `igra-core/src/domain/policy/enforcement.rs`).

Add:
```rust
pub struct GroupPolicy {
    // existing…
    pub amount_multiple_sompi: Option<u64>,
}
```

Enforce for non-maintenance events in:
- `igra-core/src/domain/policy/enforcement.rs` inside `DefaultPolicyEnforcer::evaluate_policy(...)`

Rule:
- if `amount_multiple_sompi = Some(m)`, require `event.event.amount_sompi % m == 0`

### 2.2.2 “Exact multiple” requires fee mode that does not reduce recipient output

If the business rule is “the *requested amount* must be a multiple of 100 KAS”, then fee mode does not need to be constrained.

Today, `FeePaymentMode::RecipientPays` (and `Split` with `recipient_parts > 0`) can reduce the first output amount in `igra-core/src/domain/pskt/builder.rs` (see `apply_fee_policy_for_fee(...)`).

Implication:
- With `RecipientPays`, the on-chain recipient output is `requested_amount - fee`, so the *received* amount will typically **not** be an exact multiple of 100 KAS.
- This is usually acceptable if “multiple-of” applies to the requested amount (API-level), not the net received amount (on-chain).

If we ever need “the *received* amount must be a multiple of 100 KAS”, then we would switch to:
- `FeePaymentMode::SignersPay` (or `Split` with `recipient_parts = 0`), and/or
- require requests to include a fee buffer in the requested amount.

### 2.2.3 Parallel events implies “reserve count”, not just “reserve size”

When many events run concurrently, a single “big UTXO” is not sufficient; it increases collision probability (two events try to spend the same UTXO).

UTXO management should therefore target:
- a **minimum count** of deep “large-enough” UTXOs (so parallel events naturally select distinct inputs), and
- a “small UTXO cleanup” path that reduces bloat without consuming large reserve UTXOs.

The proactive maintenance feature (Section 5.7) is the mechanism to keep this reserve healthy over time.

## 3) Data model changes

### 3.1 Add new internal source type

File: `igra-core/src/domain/model.rs`

Add a new variant to `SourceType` (append-only enum):

```rust
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    // existing…
    MaintenanceConsolidation {
        /// Parent payout event that triggered consolidation.
        parent_event_id: EventId,
        /// Deterministic job nonce (ties all steps together).
        job_nonce: Hash32,
        /// 0-based step index (batch number).
        step_index: u16,
        /// Optional stage if we ever do multi-stage trees (v2).
        stage_index: u16,
    },
}
```

Notes:
- Use `EventId` / `Hash32` from `igra-core/src/foundation/types.rs` (hash types serialize as hex and remain deterministic).
- This source type must be **internal-only**: it is allowed in proposals/CRDT, but **rejected from external RPC ingestion** (see Section 5.1).

Important (determinism):
- For maintenance/consolidation events, **do not make `event_id` depend on the selected inputs**.
- `EventId` is computed from `(external_id, source, destination_script, amount_sompi)` in `igra-core/src/domain/hashes.rs`.
- If `amount_sompi` is derived from `sum(inputs) - fee`, signers can generate different `event_id`s and never reach quorum.

Therefore, for `SourceType::MaintenanceConsolidation` events:
- Treat `event.amount_sompi` as a **stable marker** (e.g. `0`), not as “the sweep output amount”.
- Build the consolidation PSKT outputs from the selected inputs (Section 4.4) and include the actual sweep amount only in the PSKT/template.

### 3.2 Exclude consolidation from daily volume accounting

Daily volume is incremented when a CRDT completion is first seen:
- Memory storage: `igra-core/src/infrastructure/storage/memory.rs` in `merge_event_crdt(...)` (around lines ~200–240) adds `event.event.amount_sompi` into `inner.volume`.
- Rocks storage: `igra-core/src/infrastructure/storage/rocks/engine/storage.rs` in `merge_event_crdt(...)` (around lines ~200–240) calls `self.add_to_daily_volume(event.event.amount_sompi, event.received_at_nanos)`.

Change required:
- If `event.event.source == SourceType::MaintenanceConsolidation { .. }` then **do not** add to volume.

Rationale:
- Consolidation is an internal reshuffle; it must not consume “max daily volume” budget.

---

## 4) PSKT construction changes (payout + consolidation builders)

### 4.1 Enforce proposal-layer limits during build

File: `igra-core/src/domain/pskt/builder.rs`

We need the builder(s) that are used by the two-phase path to enforce:
- `inputs.len() <= MAX_UTXOS_PER_PROPOSAL` (`igra-core/src/domain/coordination/config.rs`)
- `serialized_kpsbt_blob.len() <= MAX_KPSBT_SIZE` (`igra-core/src/domain/coordination/config.rs`)
- `tx_mass <= MAXIMUM_STANDARD_TRANSACTION_MASS` (Kaspa standardness)

Today we only check:
- `selected.len() <= MAX_PSKT_INPUTS` (`igra-core/src/foundation/constants.rs`)
- `storage_mass <= MAXIMUM_STANDARD_TRANSACTION_MASS` (and not explicitly the combined mass)

Design change:
- Introduce a “proposal-safe” build entrypoint (used only by the protocol path) that enforces the stricter caps.
  - Suggested new function:
    - `build_pskt_for_proposal_from_utxos(params: &PsktParams, utxos: Vec<UtxoInput>, limits: ProposalLimits) -> Result<...>`
  - Where `ProposalLimits` includes max inputs (=100), max kpsbt size (=64KiB), and max standard mass.

### 4.2 Add explicit “needs consolidation” failure

Add a new error to distinguish:
- “Balance insufficient” vs
- “Balance sufficient, but cannot fit into a single standard tx within our proposal constraints”

Suggested error:
```rust
ThresholdError::NeedsConsolidation {
    required_amount_sompi: u64,
    selected_inputs: usize,
    max_inputs: usize,
    reason: String, // e.g. "proposal input cap", "kpsbt size cap", "tx mass cap"
}
```

Where this is produced:
- In the payout builder, once we can cover amount+fees but exceed caps (or cannot cover amount without exceeding caps).

### 4.3 Payout selection: add a deterministic “largest-first fallback”

Problem:
- Current seeded ordering intentionally avoids using amount as a secondary key (`igra-core/src/domain/pskt/builder.rs` lines ~43–85).
- After consolidation, we want the payout to strongly prefer larger UTXOs to stay under 100 inputs.

Design:
- Keep the existing seed-based ordering as the **first attempt** (good for leaderless determinism).
- If payout build fails specifically due to the **input cap**, re-run selection deterministically with:
  - primary: `amount desc`
  - tie-breakers: `score(seed,outpoint)` then outpoint txid+index

This preserves determinism while enabling quick convergence on large UTXOs when fragmentation is the blocker.

### 4.4 New consolidation PSKT builder (sweep-to-self)

Add a new builder dedicated to consolidation steps:
- Inputs: a bounded list of UTXOs (≤ 100)
- Outputs: **exactly one** output paying to `change_address` (which must exist for this path)
- Amount: `sum(inputs) - fee`
- Fee: auto-fee (same fixed-point loop approach as payout)
- Must satisfy standardness + proposal limits (mass, kpsbt size, etc)

Suggested signature:
```rust
pub fn build_consolidation_pskt_from_utxos(
    params: &PsktParams,
    utxos: Vec<UtxoInput>,
    change_address: &str,
    selection_seed: Hash32,
) -> Result<(UtxoSelectionResult, PsktBuildResult), ThresholdError>
```

Implementation location:
- `igra-core/src/domain/pskt/builder.rs` (same module as payout builder, but keep functions separated and explicit).

---

## 5) Orchestration: when and how consolidation is triggered

### 5.1 Reject `MaintenanceConsolidation` from external RPC ingestion

File: `igra-core/src/application/event_processor.rs`

In `submit_signing_event(...)` (near the top where we destructure `SigningEventWire`), add:
- If `wire.source` matches `SourceType::MaintenanceConsolidation { .. }`:
  - return a specific error (new `ThresholdError::ForbiddenSourceType` or reuse `ConfigError` / `PolicyViolation` mapping).

Rationale:
- External clients must not be able to request “internal sweep” signing.

### 5.2 Proposal validation must allow consolidation even if destination whitelist is strict

File: `igra-service/src/service/coordination/two_phase_handler.rs`

In `validate_proposal(...)` (around lines ~70–120):
- Today it calls `pipeline.verify_and_enforce(&stored_event)?;` which applies:
  - destination whitelist
  - amount min/max
  - daily volume limit
  - memo requirements

For `MaintenanceConsolidation` proposals we must instead:
- Skip group “allowed destinations” checks (because destination is self, and policy may not include it).
- Skip daily volume checks (since consolidation is internal and excluded from volume indexing).
- Enforce **consolidation-specific safety checks** using service config:
  - destination must equal `service.pskt.change_address` (or derived source address if change unset)
  - destination must equal `service.pskt.source_addresses[0]` (optional stronger invariant if we want one-address-only)
  - the PSKT outputs in the proposal must contain only that destination script (this is indirectly ensured by checking the canonical `Event.destination`, but we should also validate the PSKT itself if we want extra defense-in-depth)

Where to put this logic:
- In `validate_proposal(...)`, before or instead of calling `pipeline.verify_and_enforce`.
- Add a helper:
  - `fn enforce_maintenance_consolidation_policy(service: &ServiceConfig, stored_event: &StoredEvent) -> Result<(), ThresholdError>`

### 5.3 Where to create consolidation jobs (trigger point)

We trigger consolidation only when a payout cannot be proposed within limits.

Primary trigger:
- In the initial propose step for an event:
  - `igra-core/src/application/event_processor.rs` calls `build_local_proposal_for_round(...)` (see the `entered` branch around lines ~180–220).
  - If the build returns `NeedsConsolidation`, we create a consolidation job instead of failing the payout permanently.

Retry trigger (important for robustness):
- `igra-service/src/service/coordination/two_phase_timeout.rs` retries failed events by calling `build_local_proposal_for_round(...)` again (around lines ~80–150).
  - If the retry build returns `NeedsConsolidation`, we must ensure we *still* create (or continue) the consolidation job (e.g., coordinator restarted).

### 5.4 New module: `application::utxo_management`

Add a new application module:
- File: `igra-core/src/application/utxo_management.rs` (new)
- Export from `igra-core/src/application/mod.rs`

Responsibilities:
1) Detect whether consolidation is needed (`NeedsConsolidation` error from payout builder).
2) Plan consolidation steps (partition UTXOs into batches ≤ 100).
3) Materialize those steps into internal events and start two-phase proposals for them.
4) Avoid duplication (idempotency) and rate-limit fees.

Implementation note (maintenance events):
- Do **not** route `MaintenanceConsolidation` through `resolve_pskt_config(...)` in `igra-core/src/application/event_processor.rs`, because we intentionally keep `event.amount_sompi` as a stable marker (Section 3.1).
- Instead, build the consolidation PSKT directly from a preselected input chunk via `build_consolidation_pskt_from_utxos(...)` and derive `Proposal.outputs` from the PSKT itself (not from config outputs).

Suggested API:
```rust
pub async fn ensure_consolidation_job_for_payout(
    ctx: &EventContext,
    parent_event_id: EventId,
    parent_event: &StoredEvent,
    now_ns: u64,
) -> Result<(), ThresholdError>;
```

Additional API for proactive maintenance:
```rust
pub async fn maybe_run_periodic_maintenance(
    ctx: &EventContext,
    group_id: GroupId,
    now_ns: u64,
) -> Result<(), ThresholdError>;
```

### 5.5 Consolidation planner (deterministic + bounded)

Planner inputs:
- current eligible UTXOs from RPC (`NodeRpc::get_utxos_by_addresses`)
- `MAX_UTXOS_PER_PROPOSAL` (100)
- configured fee guardrails (max total fee for job)

Algorithm (v1: single-stage):
1) Filter UTXOs by depth gate (Section 6).
2) Sort deterministically using `(job_seed, outpoint)` (same scoring approach as `pskt/builder.rs` uses today).
3) Split into disjoint chunks of size `max_inputs_per_tx` (≤ 100).
4) For each chunk, build a consolidation PSKT that sweeps to `change_address`.
5) Stop once we have produced enough “expected large outputs” such that the payout should be possible under 100 inputs.

Note:
- In the 1000×0.01KAS / 9KAS example, a first stage producing ~9–10 outputs is enough; no second stage required.
- If we later need to handle *extreme* fragmentation (e.g., >100k UTXOs), we can extend to multi-stage trees (stage index in `SourceType` already anticipates this).

### 5.6 Job idempotency and state tracking

We must prevent multiple signers from repeatedly spawning “new” consolidation jobs for the same payout.

Recommended: add a small persisted job state keyed by `parent_event_id`.

Add to `Storage` trait:
- File: `igra-core/src/infrastructure/storage/traits.rs`
- New methods:
  - `get_consolidation_job(parent_event_id) -> Option<JobState>`
  - `put_consolidation_job(parent_event_id, JobState)`

Implementations:
- Memory: `igra-core/src/infrastructure/storage/memory.rs`
- Rocks: `igra-core/src/infrastructure/storage/rocks/...` (new CF or key-space under an existing CF)

JobState fields (minimum):
- `job_nonce: Hash32`
- `created_at_ns`
- `step_event_ids: Vec<EventId>`
- `status: { planned | running | done }`

Idempotency rule:
- If job exists and not done, do not create new.
- If job done, payout can proceed normally.

## 5.7 Proactive UTXO maintenance (periodic “deep reserve”)

Reactive consolidation (triggered only on `NeedsConsolidation`) is correct, but it adds latency when fragmentation is already a problem.

For deployments with:
- strict policy bounds (min/max/multiple-of), and
- many events processed concurrently,

we should run **proactive maintenance** periodically to keep a healthy pool of deep “large-enough” UTXOs.

### 5.7.1 Goals

1) Avoid “input cap” failures for typical payouts by maintaining a reserve of deep UTXOs.
2) Reduce fragmentation over time by consolidating small UTXOs.
3) Minimize interference with live payouts (maintenance is best-effort and should not cause user-visible failures).

### 5.7.2 Run mode: depth-gated + (default) low-contention

Because we require the normal depth gate:
- Maintenance must only spend deep UTXOs (same `two_phase.min_input_score_depth`).
- Maintenance must *not* spend its own outputs until they are deep (build-time depth filtering enforces this).

To reduce contention with active payouts, v1 should be **low-contention**:
- Prefer to consolidate only “small” UTXOs (configurable threshold), leaving large reserve UTXOs untouched.
- Optionally run only when there are no events in `Proposing` or `Committed` (idle-only mode).

### 5.7.3 Scheduling + idempotency (leaderless)

We need to avoid every signer creating a different “maintenance job” at the same time.

Approach:
- Define a time bucket, e.g. `bucket_start = floor(now / maintenance_interval_seconds) * maintenance_interval_seconds`.
- Compute a deterministic `job_nonce = H("igra:utxo-maintenance:v1" || group_id || bucket_start)`.
- Define a synthetic `parent_event_id` for the job:
  - `parent_event_id = EventId::from(H("igra:utxo-maintenance-parent:v1" || group_id || bucket_start))`
- Use the same job state storage keyed by `parent_event_id` (Section 5.6) to dedup.

Each maintenance tx is represented as a `MaintenanceConsolidation` event step with:
- `parent_event_id` = synthetic parent above
- `job_nonce` = bucket nonce
- `step_index` = 0..N
- `stage_index` = 0 (v1 is single-stage)

### 5.7.4 What to consolidate (policy-aware heuristics)

Given the “multiple of 100 KAS” policy, a reasonable reserve model is:
- Keep at least `reserve_target_count` deep UTXOs each `>= reserve_min_utxo_sompi`.

How to choose defaults:
- `reserve_min_utxo_sompi` should be at least `policy.min_amount_sompi` (100 KAS in your example).
- If you also want the *max withdrawal* to fit under the 100-input proposal cap, then:
  - `reserve_min_utxo_sompi >= ceil(policy.max_amount_sompi / target_max_inputs)`
  - with `target_max_inputs <= MAX_UTXOS_PER_PROPOSAL (=100)`
  - (for 1,000,000 KAS max, that implies ~10,000 KAS average input to fit in 100 inputs).

Maintenance should prioritize consolidating UTXOs below a “small” threshold:
- `small_utxo_threshold_sompi` (suggested default: `policy.amount_multiple_sompi / 10` or a fixed KAS value)
- Select only deep UTXOs `<= small_utxo_threshold_sompi` for maintenance inputs.

This reduces collision probability with payouts, because payout selection (especially with the “largest-first fallback”) will mostly consume large UTXOs.

### 5.7.5 Where to implement the periodic loop

Service-side scheduling belongs in `igra-service`:
- Add `run_utxo_maintenance_loop(...)` spawned from `igra-service/src/service/coordination/loop.rs` (same pattern as anti-entropy/GC/two-phase tick).

The loop should:
1) Check config `service.utxo_management.maintenance_enabled`.
2) Optionally check “idle-only” gates using `phase_storage.get_events_in_phase(...)`:
   - skip if any events are in `Proposing` or `Committed`.
3) Call into `igra-core`:
   - `igra_core::application::utxo_management::maybe_run_periodic_maintenance(...)`

The `igra-core` function should:
- Fetch eligible deep UTXOs from RPC.
- Decide whether reserve is healthy (if healthy: no-op).
- If unhealthy, create (or continue) a maintenance job (synthetic parent id).
- For each step, initiate two-phase proposing (same mechanism as reactive consolidation).

### 5.7.6 Guardrails

To avoid fee burns or endless churn:
- `max_steps_per_bucket`
- `max_total_consolidation_fee_sompi` (treat as a per-job/per-bucket budget)
- `maintenance_interval_seconds` (default: minutes)
- backoff on repeated maintenance failures

---

## 6) Enforcing the “normal depth gate” (no mempool chaining)

Requirement: consolidation outputs must not be spent until they have depth ≥ `two_phase.min_input_score_depth`.

Recommended implementation: **filter UTXOs by depth at build-time**, not only at commit-time.

Where to implement:
- `igra-core/src/infrastructure/rpc/kaspa_integration/mod.rs` in `build_pskt_with_client_seeded(...)` (around lines ~25–70)

Change:
1) Add `min_input_score_depth` parameter to the PSKT build entrypoints used by two-phase:
   - `build_pskt_from_rpc_seeded(...)`
   - `build_pskt_with_client_seeded(...)`
2) After fetching UTXOs, do:
   - `tip = rpc.get_virtual_selected_parent_blue_score().await?`
   - `min_score = tip.saturating_sub(min_input_score_depth)`
   - keep only UTXOs where `utxo.entry.block_daa_score <= min_score`

Then:
- Consolidation can only use deep inputs.
- Payout can only use deep inputs, which means consolidation outputs will only become eligible after they mature.

We should keep the existing commit-time revalidation as defense-in-depth.

---

## 7) Config additions (suggested)

### 7.1 Policy config

File: `igra-core/src/domain/model.rs`

Add:
- `policy.amount_multiple_sompi: Option<u64>` (Section 2.2.1)

Then:
- Update `igra-core/src/domain/policy/enforcement.rs` to enforce it for non-maintenance events.

### 7.2 UTXO management config

File: `igra-core/src/infrastructure/config/types.rs`

Add:
```rust
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UtxoManagementConfig {
    #[serde(default)]
    pub auto_consolidate: bool,              // default: true
    #[serde(default)]
    pub consolidation_max_inputs: usize,     // default: 100 (but may reduce for big m-of-n)
    #[serde(default)]
    pub max_parallel_consolidations: usize,  // default: 4–8
    #[serde(default)]
    pub max_total_consolidation_fee_sompi: u64, // safety rail (per job/bucket), default: e.g. 0.05 KAS

    // Proactive maintenance
    #[serde(default)]
    pub maintenance_enabled: bool,           // default: false (start opt-in)
    #[serde(default)]
    pub maintenance_interval_seconds: u64,   // default: 600
    #[serde(default)]
    pub maintenance_idle_only: bool,         // default: true
    #[serde(default)]
    pub reserve_target_count: usize,         // default: e.g. 64–256 (depends on expected parallelism)
    #[serde(default)]
    pub reserve_min_utxo_sompi: u64,         // default: derived from policy.min_amount_sompi or amount_multiple_sompi
    #[serde(default)]
    pub small_utxo_threshold_sompi: Option<u64>, // if set, maintenance only consumes UTXOs <= threshold
    #[serde(default)]
    pub max_steps_per_bucket: usize,         // default: e.g. 8–32
}
```

Wire it into:
- `ServiceConfig` as `service.utxo_management: UtxoManagementConfig`
- Loader: `igra-core/src/infrastructure/config/loader.rs` (no special handling needed beyond serde defaults)

---

## 8) Tests (what to test + how)

### 8.1 Unit tests (fast, deterministic)

Location recommendation: `igra-core/tests/unit/`

Notes on wiring:
- Add new unit test files under `igra-core/tests/unit/`.
- Register them in `igra-core/tests/unit/mod.rs` (this is how unit tests are discovered in this repo).

1) **Planner determinism**
   - New tests for a pure function like `plan_consolidation_steps(...)`:
     - same `(parent_event_id, job_nonce, utxo_set)` ⇒ identical step partitions
     - each step has `<= MAX_UTXOS_PER_PROPOSAL`
     - steps are disjoint (no duplicate outpoints)
   - Implementation approach:
     - Construct `Vec<UtxoInput>` with deterministic outpoints/amounts.
     - Use a fixed seed (e.g., `[7u8; 32]`).

2) **Payout builder returns `NeedsConsolidation`**
   - Provide 1000 small UTXOs and request a payout that needs >100 inputs.
   - Assert we return `ThresholdError::NeedsConsolidation { reason: "proposal input cap", .. }`.
   - This test should run without RPC by calling the builder directly.

3) **Consolidation builder produces sweep-to-self**
   - Build consolidation PSKT from 100 fake UTXOs.
   - Assert:
     - exactly 1 output
     - output script corresponds to `change_address`
     - fee is non-zero and bounded
     - template hash deterministic across runs

4) **External ingress rejects `MaintenanceConsolidation`**
   - Add a unit test around `igra-core/src/application/event_processor.rs::submit_signing_event`:
     - create `SigningEventParams` with `source: SourceType::MaintenanceConsolidation { .. }`
     - assert error is `ForbiddenSourceType` (or whichever we add)

5) **Daily volume ignores consolidation**
   - Use `MemoryStorage` (`igra-core/src/infrastructure/storage/memory.rs`) to:
     - insert a `StoredEvent` with `SourceType::MaintenanceConsolidation`
     - mark CRDT completed (or merge a completion) so volume would normally increment
     - assert `get_volume_since(...)` unchanged

6) **Amount-multiple policy**
   - Add a unit test in `igra-core/tests/unit/domain_policy.rs` (or a new file) that:
     - sets `policy.amount_multiple_sompi = Some(100 * 100_000_000)` (100 KAS in sompi)
     - asserts amount 100 KAS passes and 150 KAS fails

7) **Maintenance event_id stability**
   - Add a unit test in `igra-core/src/domain/hashes.rs` (or `igra-core/tests/unit/domain_hashing.rs`) that:
     - builds an `Event` with `SourceType::MaintenanceConsolidation { ... }` and stable fields
     - asserts `compute_event_id(&event)` equals a fixed expected hex string
   - This guards against accidental changes in `encode_source_v1(...)`.

### 8.2 Integration tests (flow-level)

Location recommendation: `igra-core/tests/integration/` (guard with `test-utils` feature if needed)

Notes on wiring:
- Integration tests live under the explicit test target `igra-core/tests/integration/mod.rs` (see `igra-core/Cargo.toml` `[[test]] name="integration" required-features=["test-utils"]`).
- Add your new test module file and include it from `igra-core/tests/integration/mod.rs`.
- Run with: `cargo test -p igra-core --features test-utils --test integration`.

Goal: simulate the full “payout triggers consolidation then succeeds” loop.

Approach:
1) Use a test `NodeRpc` implementation:
   - Start from `igra-core/src/infrastructure/rpc/mod.rs::UnimplementedRpc`
   - For this integration test, implement a small `SimulatedRpc` that:
     - maintains an in-memory UTXO set
     - on `submit_transaction`, removes spent outpoints and adds new outputs as UTXOs
     - allows advancing `blue_score` (so we can satisfy depth gate)

   Implementation hint:
   - Use `NodeRpc` trait from `igra-core/src/infrastructure/rpc/mod.rs` (only 3 methods).
   - For output UTXOs, create `UtxoEntry::new(value, script_public_key, block_daa_score, is_coinbase)` and wrap in `UtxoWithOutpoint`.

2) Test scenario:
   - Seed RPC with 1000 × 0.01 KAS deep UTXOs.
   - Submit a payout event for 9 KAS via `submit_signing_event(...)`.
   - Assert:
     - payout proposal build returns `NeedsConsolidation`
     - consolidation job events are created (check storage for their event IDs)
     - consolidation txs are submitted (check `rpc.submitted_transactions()`)
   - Advance chain score by `min_input_score_depth` and mark consolidation outputs deep.
   - Retry payout build (invoke the retry path or call `build_local_proposal_for_round`).
   - Assert payout now produces a proposal with `<= 100` inputs and eventually submits.

3) Verify invariants:
   - No consolidation tx outputs to external destinations.
   - No payout spends consolidation outputs before they are deep (enforced by UTXO depth filter).

4) **Proactive maintenance loop (smoke)**
   - Add an integration test that:
     - configures `utxo_management.maintenance_enabled=true`
     - seeds RPC with many small deep UTXOs and an unhealthy reserve (below `reserve_target_count`)
     - runs a single “maintenance tick” function (don’t rely on real timers in tests)
     - asserts maintenance events are created and proposals/tx submissions occur
   - Add a second test for “idle-only”:
     - insert a dummy event into `PhaseStorage` in `Proposing` and ensure maintenance is skipped.

---

## 9) Rollout plan (safe incremental)

Recommended order to implement:
1) Add `SourceType::MaintenanceConsolidation` + external ingress rejection.
2) Update volume accounting to ignore maintenance consolidations.
3) Add depth filtering at build-time (still keep commit-time revalidation).
4) Add consolidation PSKT builder + `NeedsConsolidation` error.
5) Add `application::utxo_management` job planner + job state in storage.
6) Add integration test harness (`SimulatedRpc`) and end-to-end tests.
