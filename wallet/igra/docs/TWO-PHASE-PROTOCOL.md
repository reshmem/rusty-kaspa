# TWO-PHASE-PROTOCOL.md

Specification for Two-Phase UTXO Consensus Protocol.

---

## 0. Executive Summary

We need a leaderless protocol that guarantees **at most one committed transaction per event** (safety) even when signers temporarily see different UTXO sets from their Kaspa nodes, while making best-effort progress (liveness) and otherwise failing explicitly (Abandoned) instead of stalling or risking split commits.

This two-phase protocol separates:

- **Phase 1 (Propose / Vote)**: signers exchange non-committing proposals for a `tx_template_hash`. Each proposal is a **vote** and carries enough data for other signers to independently validate intent (destination/amount/change) and reproduce the exact same template.
- **Phase 2 (Commit / Sign)**: once a signer observes a commit condition that guarantees global uniqueness, it **locks** the event to that canonical template and continues with the existing CRDT signature propagation/submission path.

Under Profile A (v1), with non-equivocating signers and **M > N/2**, the critical safety rule is:

> Only commit when some `tx_template_hash` has **≥ COMMIT_QUORUM distinct votes**.

Then two different hashes cannot both be committed (split-brain commit is impossible).

**Key benefits**
- **Safety**: At most one signature per signer per event; invalid proposals are rejected pre-commit.
- **Liveness**: Best-effort progress under partial synchrony; timeouts provide bounded retries and explicit failure (Abandoned) instead of silent stalls.
- **Leaderless**: Pure gossip; no single coordinator or priority peer.
- **Bounded overhead**: One extra gossip round; end-to-end latency must be measured (it is dominated by gossip delay when convergent, and by `PROPOSAL_TIMEOUT_MS` when not).

**Assumptions**
- N ≤ 20 signers.
- **v1 fault model**: crash-fault tolerant with **non-equivocating** signers (honest-but-curious); faults handled via timeouts (no BFT view changes).
- Gossip is eventually reliable (partial synchrony); messages may be delayed or reordered.
- Kaspa node views can diverge temporarily; proposals must include data to reproduce TXs.
- **v1 ordering policy**: when the upstream source is an ordered stream (e.g., Hyperlane sender nonces), execute **strictly in-order per stream** and **stall on holes** (missing/non-actionable nonces). No skip mechanism in v1.

**High-level flow**
1. Build local TX from current UTXO view, form ProposalBroadcast, gossip it.
2. Collect proposals until some `tx_template_hash` has quorum (≥`COMMIT_QUORUM` votes).
3. Lock to that canonical hash, sign, and gossip commits (CRDT). If quorum is not reached before timeout, retry the round (no commit).

**Change footprint (expected)**
- New protocol module plus extensions in `event_processor.rs`, `crdt_handler.rs`, and storage (proposals + phase).
- Gossip envelope adds ProposalBroadcast; commit path reuses existing CRDT state.
- ~500–1000 LOC of Rust changes across protocol, storage, and coordination layers.

**Risk focus**
- Proposal validation (outputs, UTXO sufficiency, provenance).
- Handling partitions/slow gossip without permanent stalls.
- Avoid committing on timeout (retry instead) to prevent split commits under partial views.
- Establish telemetry-based SLOs for `proposal_timeouts_without_quorum` / `events_abandoned_total` (do not claim numeric targets without measured data; see Section 15.3).

---

## 1. Overview

### 1.1 Problem Statement

In a leaderless M-of-N threshold signing system, signers may independently build different transactions for the same event due to UTXO set divergence. Without coordination, signers may lock to different `tx_template_hash` values, causing:
- **Liveness failure**: Signatures split, no TX reaches threshold
- **Safety failure**: If signers can sign multiple TXs, double-payment possible

### 1.2 Solution

A two-phase commit protocol that separates **proposal** from **commitment**:

- **Phase 1 (Propose)**: Signers broadcast their proposed `tx_template_hash` without signing
- **Phase 2 (Commit)**: Once proposals are collected, signers agree on a canonical hash and sign

### 1.3 Key Properties

| Property | Guarantee |
|----------|-----------|
| **Safety** | Each signer signs at most ONE tx per event |
| **Liveness** | Events complete when ≥`COMMIT_QUORUM` signers are online/connected and views converge; otherwise bounded retries and explicit failure (Abandoned) |
| **Consistency** | If an event commits, all honest signers converge to the same tx_template_hash |
| **Determinism** | Given the same proposals, all signers select the same canonical hash |

### 1.4 Assumptions and Threat Model

- **Leaderless**: no deterministic leader.
- **N is small**: N ≤ 20.
- **Quorum**: v1 uses a strict majority quorum `M > N/2` for commit *under a non-equivocation assumption* (see below).
- **Transport**: asynchronous gossip; messages can be delayed/duplicated/out-of-order.
- **Node divergence**: Kaspa nodes may temporarily disagree on spendable UTXOs.
- **Security**: proposal content is untrusted input; we validate before persisting or signing.
- **Fault model (v1)**: tolerate crash/offline faults and partitions via timeouts and retries. Byzantine behavior (equivocation / signing conflicting values) is treated as an operational incident: detect, alert, and remove the peer out of band.
- **Malice signals**: duplicate/invalid proposals are logged for potential off-chain remediation (no in-protocol slashing).

#### 1.4.1 Fault Model Profiles (Make This Explicit)

This protocol is easiest to reason about if we separate two profiles:

1) **Profile A (v1): crash faults + non-equivocation**
- Assumption: signers do not intentionally sign conflicting proposals/commits for the same `(event_id, round)` (honest-but-curious). Crashes/offline are allowed.
- Commit quorum: `M > N/2`.
- Threshold signing: `SIGNATURE_THRESHOLD = M`.
- Safety: quorum-only commit prevents split commits **among non-equivocating signers**.
- Liveness: best-effort under partial synchrony; timeouts/backoff provide bounded retries and explicit failure.

2) **Profile B (future): Byzantine fault tolerant (BFT)**
- Assumption: up to `f` signers may be Byzantine (including equivocation), with `N >= 3f + 1`.
- Commit quorum: `Q_commit = 2f + 1`.
- Threshold signing: `SIGNATURE_THRESHOLD >= 2f + 1` (commonly `2f + 1`).
- Commit object: a **Lock Certificate** over `(event_id, round, kaspa_anchor, inputs, txDigest)` (Section 2.3, Section 5.3).
- Safety: any two quorums intersect in at least `f + 1` honest signers, so conflicting lock certificates cannot both form if honest signers refuse to sign conflicting locks for the same `(event_id, round)` and refuse to lock already-locked outpoints.
- Liveness: still requires partial synchrony unless using a fully-asynchronous common-coin style protocol.

**Why this matters**: with majority quorums alone, a Byzantine signer can equivocate and appear in multiple “quorums”, enabling a split-commit in principle. Profile A avoids this by assumption; Profile B avoids it by quorum math + honest intersection.

#### 1.4.2 Global vs Per-Stream Ordering (What We Recommend)

There are two distinct ordering requirements that often get conflated:

- **Per-stream sequentiality (semantic requirement)**: events for a given upstream stream (e.g., `(origin_domain, sender)` nonces) must execute in nonce order. This is handled by the ingestion layer (Section 1.5) and is required for correctness of many bridge semantics.
- **Global sequential consumption (allocator requirement)**: the multisig UTXO pool must not reuse outpoints across events (even across streams).

Recommendation:
- For v1, keep the simplest safe shape: **per-stream sequentiality** plus **one active event per UTXO pool** (serialization) (Section 5.0).
- For vNext / Profile B, keep **per-stream sequentiality**, and achieve **global no-reuse** via outpoint locking (Lock Certificates). A global total order across all streams is *not* required unless your application semantics demand it; it reduces throughput and adds an extra consensus layer.

### 1.5 Stream Ordering and “Holes” (v1 Policy)

Some upstream sources are inherently ordered streams (e.g., a per-sender nonce stream). In that setting, an event may be **seen** but not yet **actionable** because required verification artefacts are missing (a “hole”).

**v1 policy (simplicity-first)**:
- Execute events **strictly in-order per stream**.
- If the next nonce is not actionable, the stream **stalls** (buffers later nonces) rather than skipping ahead.
- Any “SkipCert / governance override” mechanism is explicitly **out of scope for v1** because it changes semantics (can permanently skip a valid upstream message).

This ordering policy is enforced at the event-ingestion layer (before two-phase starts): two-phase is the “UTXO/template consensus + signing” protocol for a single actionable event.

### 1.6 High-Level Flow (timing)

- **Propose window**: collect proposals for up to `PROPOSAL_TIMEOUT_MS` (e.g., 5–10s), but transition earlier on quorum.
- **Timeout behavior**: if timeout fires without a quorum for any single hash, **do not commit**. Transition to `Failed`, increment `round`, and retry (bounded by `RETRY_CONFIG`).
- **Commit window**: once quorum is observed for a single `tx_template_hash`, lock and sign immediately; liveness then follows the existing CRDT signature aggregation/submission path.
- **Late joiners**: may fast-forward on commit receipt if validation passes.

Correctness note:
- Timeouts are **not** part of the safety argument. They are used only for housekeeping (retry/backoff, anti-entropy prompting, and bounding “how long we wait before declaring non-convergence”).

Timeout tuning guidance:
- Set `PROPOSAL_TIMEOUT_MS` to exceed gossip p95 for N≈20 (often several seconds).
- Production recommendation: increase the effective timeout on each retry up to a cap (adaptive timeout) to avoid thrashing under transient network lag.

### 1.7 Integration Footprint

- **RPC entry**: `event_processor.rs` (start propose, broadcast local proposal).
- **Gossip handling**: extend transport with `ProposalBroadcast`; commit path reuses existing `EventStateBroadcast` (CRDT state).
- **Storage**: RocksDB column families for proposals and event phase; enforce one proposal per peer.
- **Kaspa integration**: reproducible TX building from supplied UTXOs/outputs; mandatory pre-sign UTXO revalidation + depth filtering (Section 8.5).
- **Module placement**: add `igra-core/src/domain/coordination/{phase,proposal,selection,state_machine}.rs` for pure types/logic; extend `igra-core/src/infrastructure/transport/iroh/messages.rs` (TransportMessage + optional PhaseContext) and `igra-core/src/infrastructure/transport/iroh/traits.rs` (publish_proposal); add `igra-core/src/infrastructure/storage/phase.rs` + RocksDB impl; add `igra-service/src/service/coordination/two_phase_handler.rs` for runtime handling and extend `igra-service/src/service/coordination/loop.rs` for timeout polling.

---

## 2. Definitions

### 2.1 Terminology

| Term | Definition |
|------|------------|
| **Event** | A signing request identified by `event_id` |
| **Proposal** | A suggested `tx_template_hash` for an event, broadcast without signatures |
| **Canonical Hash** | The agreed-upon `tx_template_hash` that all signers will sign |
| **Commit Quorum** | Votes for the same hash required to enter Committed for a round (`COMMIT_QUORUM`) |
| **Commit** | The act of locking to a canonical hash and signing |

Additional terms for ordered upstream streams:

| Term | Definition |
|------|------------|
| **Stream** | A sequence of events that must execute in order (e.g., `(origin_domain, sender)` in Hyperlane) |
| **Nonce** | The per-stream sequence number that defines in-order execution |
| **Actionable** | Event has all required verification artefacts and is eligible to execute |
| **Hole** | The next required nonce is not actionable; stream intentionally stalls in v1 |

### 2.2 Configuration Parameters

| Parameter | Description | Recommended Value |
|-----------|-------------|-------------------|
| `PROPOSAL_TIMEOUT_MS` | Max time in a propose round before either committing (if quorum reached) or retrying the round | 5000 (5 seconds) |
| `COMMIT_QUORUM` | Votes required to commit a specific `tx_template_hash` in the current round | v1: `M > N/2` (Profile A), future BFT: `2f+1` (Profile B) |
| `SIGNATURE_THRESHOLD` | Signatures required for transaction authorization | v1: `M`, future BFT: `>= 2f+1` |
| `MAX_UTXOS_PER_PROPOSAL` | DoS bound on proposal size | 100 |
| `MAX_PROPOSAL_SIZE_BYTES` | DoS bound on serialized proposal | 64 KiB |
| `RETRY_CONFIG` | `{ max_retries, base_delay_ms, max_delay_ms, backoff_multiplier, jitter_ms }` for Failed → Proposing | `{3, 5000, 30000, 2.0, 250}` |
| `MIN_INPUT_SCORE_DEPTH` | Reorg-minimization: min depth for UTXOs (blue-score or DAA-score based, see Section 8.5) | default = `max(300, group.finality_blue_score_threshold)` |
| `REVALIDATE_INPUTS_ON_COMMIT` | Mandatory pre-sign UTXO revalidation (see Section 8.4/8.5) | true |
| `MAX_SYNC_EVENTS_PER_TICK` | Anti-entropy bound: max events requested/returned per peer per tick (Section 7.4) | 64 |
| `MAX_PROPOSALS_PER_EVENT_PER_RESPONSE` | Anti-entropy bound: max proposals returned per event per response (Section 7.4) | `min(N, 20)` |
| `STATE_SYNC_COOLDOWN_MS` | DoS guard: minimum time between “future-round proposal → targeted StateSyncRequest” per `(peer,event_id)` | 2000 |

### 2.3 Message Types

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KaspaAnchorRef {
    /// Tip score observed when building the proposal (DAA score / blue score depending on what the RPC exposes).
    /// This is informational in v1; do not treat it as a finality proof.
    tip_score: u64,

    /// Optional block hash if easily available from RPC (not required).
    tip_hash: Option<Hash32>,
}

// === Profile B (vNext) concepts ===
//
// In Profile B (BFT), the “commit” object is a quorum certificate over a *lock message* that binds:
// - (event_id, round)
// - kaspa_anchor
// - exact inputs (outpoints) and tx digest
//
// This makes “no reuse” explicit (outpoints are locked), and makes chain-view divergence compositional (anchor is part of the object).

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OutpointRef {
    txid: Hash32,
    index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Proposal {
    /// Unique event identifier
    event_id: Hash32,

    /// Proposal round (monotonic). Round changes prevent mixing old proposals with new ones.
    round: u32,

    /// Hash of the proposed transaction template
    tx_template_hash: Hash32,

    /// Serialized PSKT for verification and signing
    kpsbt_blob: Vec<u8>,

    /// Deterministic inputs used to build the template.
    /// This makes a proposal reproducible even if receiver nodes have divergent UTXO views.
    utxos_used: Vec<UtxoInput>,

    /// Outputs for verification (destination + change).
    outputs: Vec<PsktOutputParams>,

    /// Event data (destination, amount, proof)
    signing_material: CrdtSigningMaterial,

    /// Peer ID of proposer (must be a known peer; see Section 9)
    proposer_peer_id: PeerId,

    /// Wall-clock timestamp (for debugging/audit only)
    timestamp_ns: u64,

    /// Optional Kaspa anchor reference (for audit/diagnostics; see Section 8.6).
    ///
    /// v1 note: proposals are not required to share the same anchor; convergence is driven by quorum on the template.
    /// vNext option: bind commit quorum to (anchor, tx_template_hash) for stricter reorg semantics.
    /// Profile B note: `kaspa_anchor` is REQUIRED and becomes part of the signed lock message (`LockMsg`).
    kaspa_anchor: Option<KaspaAnchorRef>,
}

/// Transport wrapper (naming matches the gossip intent).
///
/// In code, prefer a single `Proposal` definition shared by:
/// - storage (PhaseStorage)
/// - transport (`TransportMessage::ProposalBroadcast`)
type ProposalBroadcast = Proposal;

// Rounds: start at 0 on first propose. On timeout/Failed, increment round and ignore messages from older rounds.

/// Commit messages reuse the existing CRDT state broadcast.
/// Extend `EventStateBroadcast` to optionally carry phase/round context for two-phase gating.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PhaseContext {
    round: u32,
    phase: EventPhase,
    /// Optional anchor carried on the first committed broadcast for audit/recovery.
    kaspa_anchor: Option<KaspaAnchorRef>,
}

// === Profile B (vNext): lock certificates ===

/// Deterministic digest of a lock intent.
///
/// Conceptually:
/// lock_msg_hash = H("LOCK" || event_id || round || kaspa_anchor || outpoints || tx_template_hash)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LockMsg {
    event_id: Hash32,
    round: u32,
    kaspa_anchor: KaspaAnchorRef,
    tx_template_hash: Hash32,
    outpoints: Vec<OutpointRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LockSigBroadcast {
    lock_msg: LockMsg,
    signer_peer_id: PeerId,
    signature: Vec<u8>, // signature under the signer’s long-term identity key
}

/// A quorum certificate over `LockMsg`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct LockCert {
    lock_msg: LockMsg,
    // Minimal representation: (signer -> signature), threshold-sized.
    sigs: Vec<(PeerId, Vec<u8>)>,
}

// Existing type in codebase; add optional phase_context
struct EventStateBroadcast {
    event_id: Hash32,
    tx_template_hash: Hash32,
    state: EventCrdtState,
    sender_peer_id: PeerId,
    phase_context: Option<PhaseContext>, // NEW: conveys round/phase when used for commits
}
```

**PhaseContext usage**:
- When broadcasting a “commit” (i.e., the first CRDT state that should trigger signing), set `phase_context = Some({ round, phase: Committed })`.
- For ordinary anti-entropy CRDT broadcasts (after commit), `phase_context` may be omitted; receivers must still enforce “canonical hash only” once committed.
- **Rule**: commit signals MUST include `phase_context` (otherwise receivers must treat the broadcast as anti-entropy only).

**Authentication note**: Proposals and commits are carried in a signed transport envelope. Receivers verify:

- payload hash matches payload bytes
- envelope signature verifies for `sender_peer_id` against configured `iroh.verifier_keys`

Additionally, we should enforce `ProposalBroadcast.proposer_peer_id == envelope.sender_peer_id` and `EventStateBroadcast.sender_peer_id == envelope.sender_peer_id` for consistency.

---

## 3. State Machine

### 3.1 Event Phases

```
┌─────────────┐
│   Unknown   │  No knowledge of this event
└──────┬──────┘
       │
       │ (A) Receive RPC event
       │ (B) Receive ProposalBroadcast
       │ (C) Receive EventStateBroadcast (Committed)
       │
       ▼
┌─────────────┐
│  Proposing  │  Collecting proposals, NOT signing
└──────┬──────┘
       │
       │ (D) Quorum reached (`COMMIT_QUORUM` votes)
       │ (E) Receive EventStateBroadcast (Committed) (fast-forward)
       │ (F) Timeout expired (no quorum) → Failed
       │
       ▼
┌─────────────┐
│  Committed  │  Canonical hash locked, signing
└──────┬──────┘
       │
       │ (G) Threshold signatures reached
       │ (H) Transaction confirmed on-chain
       │
       ▼
┌─────────────┐
│  Completed  │  Event fully processed
└─────────────┘

┌─────────────┐
│   Failed    │  No quorum / invalid inputs; retryable
└──────┬──────┘
       │
       │ (I) Retry (round += 1, bounded)
       ▼
┌─────────────┐
│ Abandoned   │  Max retries exceeded; operator intervention
└─────────────┘
```

### 3.2 Transition Rules

| From | To | Trigger | Action |
|------|----|---------| -------|
| Unknown | Proposing | Receive RPC event | Build TX, broadcast proposal, start timer |
| Unknown | Proposing | Receive ProposalBroadcast | Store proposal, start timer, maybe broadcast own proposal |
| Unknown | Committed | Receive EventStateBroadcast (Committed) | Fast-forward, adopt canonical hash, sign |
| Proposing | Committed | Quorum (`COMMIT_QUORUM` votes) | Select canonical, lock, sign, broadcast commit |
| Proposing | Committed | Receive EventStateBroadcast (Committed) | Fast-forward, adopt canonical hash, sign |
| Proposing | Failed | Timeout without quorum | Increment round and retry (bounded) |
| Failed | Proposing | Retry (round += 1) | Clear stale proposals, restart collection (subject to retry policy) |
| Failed | Abandoned | Max retries exceeded | Stop processing; manual intervention |
| Committed | Completed | TX confirmed | Mark complete, stop processing |

**Retry policy**: `RETRY_CONFIG { max_retries, base_delay_ms, max_delay_ms, backoff_multiplier, jitter_ms }`.

On entering Failed, schedule a retry after:

`delay_ms = min(max_delay_ms, base_delay_ms * backoff_multiplier^retry_count) ± jitter_ms`

Then increment `retry_count`. If `retry_count >= max_retries`, transition to Abandoned and alert an operator.

### 3.3 Phase State Storage

```rust
struct EventPhaseState {
    phase: EventPhase,                // Unknown, Proposing, Committed, Completed, Failed, Abandoned
    phase_started_at: u64,            // Timestamp when current phase started
    round: u32,                       // Current proposal round
    canonical_hash: Option<Hash32>,   // Set when Committed
    own_proposal_hash: Option<Hash32>,// Hash we proposed (if any)
    retry_count: u32,                 // For backoff/abandonment
}

enum EventPhase {
    Unknown = 0,
    Proposing = 1,
    Committed = 2,
    Completed = 3, // terminal success
    Failed = 4,    // retryable failure
    Abandoned = 5, // terminal failure after retries/manual abort
}
```

---

## 4. Canonical Hash Selection

### 4.1 Algorithm

Canonical selection is used only to determine whether it is **safe to commit** (i.e., whether some hash has ≥ commit quorum votes).

**Safety rule (non-negotiable):** do not commit without quorum. There is no “min-hash commit” fallback.

```rust
use std::collections::HashMap;
use std::cmp::Reverse;

/// Vote stats per hash for canonical selection
#[derive(Debug, Clone)]
struct HashVoteStats {
    hash: Hash32,
    vote_count: usize,
    lowest_proposer: PeerId,
}

impl HashVoteStats {
    /// Deterministic ordering: higher votes wins, then lower hash, then lower proposer.
    fn canonical_key(&self) -> (Reverse<usize>, Hash32, PeerId) {
        (Reverse(self.vote_count), self.hash, self.lowest_proposer)
    }
}

fn quorum_hash(proposals: &[Proposal], commit_quorum: usize) -> Option<Hash32> {
    if proposals.is_empty() {
        return None;
    }

    // Aggregate votes per hash
    let mut stats_by_hash: HashMap<Hash32, HashVoteStats> = HashMap::new();
    for p in proposals {
        let stats = stats_by_hash
            .entry(p.tx_template_hash)
            .or_insert_with(|| HashVoteStats {
                hash: p.tx_template_hash,
                vote_count: 0,
                lowest_proposer: p.proposer_peer_id,
            });
        stats.vote_count += 1;
        stats.lowest_proposer = stats.lowest_proposer.min(p.proposer_peer_id);
    }

    // Quorum-only: return Some(hash) iff some hash has ≥ commit_quorum votes.
    stats_by_hash
        .values()
        .filter(|s| s.vote_count >= commit_quorum)
        .min_by_key(|s| s.canonical_key())
        .map(|s| s.hash)
}
```

### 4.2 Rationale

- **Quorum-first** prevents split commits when a majority already converged.
- **No-commit-without-quorum** prevents split commits even under partial views/timeouts.
- **Tie-breaks** use only deterministic data (hash, proposer) to avoid clock-skew exploitation.
- **Count tie clarity**: when vote counts are equal, the “lower hash” wins (lexicographically smaller `Hash32` byte ordering), then the “lower proposer” wins (deterministic `PeerId` ordering).

### 4.3 Divergence Risk and Mitigation

- If quorum is reached on a hash:
  - under Profile A, split commits are impossible (proof sketch in Section 4.4), and
  - under Profile B, split commits are prevented by quorum intersection plus explicit lock certificates (Section 5.3).
- If timeout fires without quorum, this protocol **does not commit**. Instead it:
  - transitions to `Failed`,
  - increments `round`,
  - retries with backoff (bounded by `RETRY_CONFIG`),
  - and emits metrics/alerts to indicate the system is not converging.

This pushes the system toward either:
- convergence after gossip catches up / UTXO views align (most expected cases), or
- explicit operator intervention if a systemic issue prevents quorum (partitions, unhealthy nodes, persistent UTXO divergence).

### 4.4 Why M > N/2 Prevents Split Commits (Proof Sketch, Profile A)

Let:
- N be the number of signers,
- M be the quorum threshold, with M > N/2,
- each honest signer emits at most one vote per round (enforced by storage: one proposal per peer per round).

Assume for contradiction that two different hashes `H1 != H2` each reach quorum in the same round.
Then at least M distinct signers voted for H1, and at least M distinct signers voted for H2.
Because votes are one-per-signer-per-round, these voter sets are disjoint, so the total distinct voters is at least 2M.
But 2M > N (since M > N/2), which is impossible with only N signers.
Therefore, at most one hash can reach quorum per round, so quorum-only commit cannot split-commit among honest signers.

**Important limitation**: this argument relies on **non-equivocation**. If Byzantine signers are allowed to sign conflicting votes, they can “reuse” their identity across multiple candidate hashes and invalidate the disjointness step. For a Byzantine model, use Profile B (`N >= 3f+1`, `Q_commit = 2f+1`) and define commits as explicit quorum certificates.

---

## 5. Protocol Logic (Condensed, Executable Pseudocode)

This section replaces role-based “initiator/follower/late-joiner” narratives with one shared handler model.

**Core rule**: a signer commits (locks + signs) only when `quorum_hash(...)` returns `Some(hash)` for the current round.

### 5.0 Cross-Event Safety: Outpoint Reservation (What This Protocol Does and Does Not Do)

This protocol coordinates **one event** to a single canonical transaction template. It does **not**, by itself, provide a replicated “global UTXO allocator” across many concurrent events unless we add an explicit outpoint reservation rule.

We therefore define two modes:

**v1 (simplest, recommended)**:
- For a given UTXO pool (one multisig script/address set), process at most **one event at a time** in `Proposing`/`Committed`.
- Additional actionable events are queued by the ingestion layer.
- Result: no two events can attempt to spend the same outpoint concurrently, so “no reuse across events” is enforced by serialization.

**vNext (multi-stream / concurrent events)**:
- Replace “best-effort reservations” with **explicit lock certificates** (Profile B):
  - Signers emit `LockSigBroadcast` for a single `LockMsg` per `(event_id, round)`.
  - A `LockCert` (quorum `Q_commit = 2f+1`) is the commit object and is the authority for reserving outpoints.
- Maintain a derived local `ReservedOutpoints` index for efficient checks:
  - `outpoint -> (event_id, round, tx_template_hash, kaspa_anchor)`
- Proposal (PLAN) validation must reject any plan whose `utxos_used` intersects reserved outpoints (except the same locked `(event_id, round)`).
- An honest signer MUST NOT sign:
  - two different lock messages for the same `(event_id, round)`, or
  - any lock message that attempts to lock an outpoint already locked by a different `LockCert` (until it is finalized/invalidated).

Note: committing to `tx_template_hash` implicitly commits to its inputs (since the PSKT encodes them). The missing pieces for multi-stream concurrency are (a) an explicit **cross-event outpoint locking invariant**, and (b) an explicit **anchor binding** for reorg compositionality (Profile B / Section 8.6).

### 5.1 Core Handlers

```rust
/// Called when an external event is received (RPC).
async fn on_event(event: StoredEvent) -> Result<()> {
    let event_id = event.id();

    // v1 ordering note:
    // If the upstream source is an ordered stream (nonces), the ingestion layer MUST call `on_event`
    // only when the event is actionable and next-in-stream; otherwise it should buffer it and wait.
    validate_signing_event(&event)?; // proof + policy

    // Ensure phase exists (round initialized if new). If we're already committed/completed, do nothing here.
    if !phase_storage.try_enter_proposing(&event_id, now())? {
        return Ok(());
    }

    // Build and publish our proposal (idempotent: one-per-peer-per-round)
    let proposal = build_local_proposal(&event).await?; // includes round, kpsbt_blob, utxos_used, outputs
    phase_storage.store_proposal(&proposal)?;
    transport.publish_proposal(proposal.clone()).await?;

    // Opportunistic commit (in case we already have quorum due to anti-entropy)
    try_commit_and_sign(&event_id, proposal.round).await?;
    Ok(())
}

/// Called when a proposal is received (gossip).
async fn on_proposal(proposal: Proposal) -> Result<()> {
    proposal.validate_structure()?;
    validate_proposal(&proposal)?; // includes validate_signing_event + output checks (+ optional local utxo checks)

    // Round rules:
    // - If Unknown: create phase state at proposal.round
    // - If proposal.round < local.round: ignore (stale)
    // - If proposal.round > local.round: do not store (future), but trigger anti-entropy so we can fast-forward
    let phase = phase_storage.get_phase(&proposal.event_id)?;
    if let Some(phase) = &phase {
        if proposal.round < phase.round {
            return Ok(());
        }
        if proposal.round > phase.round {
            // Future-round proposals are a hint we missed state. Don’t store out-of-round proposals.
            //
            // DoS guard:
            // - only trigger a sync when proposal.round == local.round + 1 (otherwise ignore as suspicious/noise),
            // - apply a per-(peer,event_id) cooldown (STATE_SYNC_COOLDOWN_MS) before re-triggering.
            if proposal.round == phase.round + 1 && should_trigger_state_sync(proposal.proposer_peer_id, proposal.event_id, now()) {
                transport.publish_state_sync_request(StateSyncRequest {
                    event_ids: vec![proposal.event_id],
                }).await?;
            }
            return Ok(());
        }
    }

    // Atomic: store_proposal is responsible for creating phase state if unknown and for enforcing round match.
    phase_storage.store_proposal(&proposal)?; // atomic (phase/round)
    try_commit_and_sign(&proposal.event_id, proposal.round).await?;
    Ok(())
}

/// Called when a committed CRDT broadcast is received (gossip).
async fn on_committed_broadcast(commit: EventStateBroadcast) -> Result<()> {
    let Some(ctx) = &commit.phase_context else { return Ok(()); };
    if ctx.phase != EventPhase::Committed { return Ok(()); }

    // Ignore stale commits if we already advanced beyond this round.
    if let Some(local) = phase_storage.get_phase(&commit.event_id)? {
        if ctx.round < local.round {
            return Ok(());
        }
    }

    // Fast-forward: set canonical hash + phase for (event_id, round)
    storage.set_event_active_template_hash(&commit.event_id, &commit.tx_template_hash)?;
    phase_storage.try_commit(&commit.event_id, ctx.round, commit.tx_template_hash, now())?;

    storage.merge_event_crdt(&commit.event_id, &commit.tx_template_hash, &commit.state)?;

    // If we haven’t signed yet, sign and re-broadcast.
    maybe_sign_and_broadcast(&commit.event_id, &commit.tx_template_hash).await?;
    Ok(())
}

/// Periodic timeout tick (integrate into existing anti-entropy loop).
async fn on_timeout_tick() -> Result<()> {
    for event_id in phase_storage.get_events_in_phase(EventPhase::Proposing)? {
        let Some(phase) = phase_storage.get_phase(&event_id)? else { continue; };
        if !timeout_expired(phase.phase_started_at, PROPOSAL_TIMEOUT_MS) { continue; }

        // Last-chance: re-check quorum at the timeout boundary.
        let proposals = phase_storage.get_proposals(&event_id, phase.round)?;
        if quorum_hash(&proposals, COMMIT_QUORUM).is_some() {
            try_commit_and_sign(&event_id, phase.round).await?;
            continue;
        }

        // No quorum: fail and retry round with backoff/jitter.
        phase_storage.fail_and_bump_round(&event_id, phase.round, now())?;
        schedule_retry(event_id, phase.retry_count)?;
    }
    Ok(())
}

async fn try_commit_and_sign(event_id: &Hash32, round: u32) -> Result<()> {
    let proposals = phase_storage.get_proposals(event_id, round)?;
    let Some(canonical_hash) = quorum_hash(&proposals, COMMIT_QUORUM) else {
        return Ok(());
    };

    // Choose a canonical proposal instance for the hash (e.g., lowest proposer id).
    let winning = select_winning_proposal(&proposals, canonical_hash)?;

    // Mandatory pre-sign checks (reorg-safe): outputs + inputs spendable + depth filter.
    validate_commit_candidate(&winning).await?;

    storage.set_event_active_template_hash(event_id, &canonical_hash)?;
    if !phase_storage.try_commit(event_id, round, canonical_hash, now())? {
        return Ok(()); // someone else committed first; idempotent
    }

    // Sign and broadcast commit signal (PhaseContext MUST be present for commit broadcasts).
    let signed_state = sign_pskt_and_build_crdt_state(&winning).await?;
    transport.publish_event_state(EventStateBroadcast {
        event_id: *event_id,
        tx_template_hash: canonical_hash,
        state: signed_state,
        sender_peer_id: local_peer_id.clone(),
        phase_context: Some(PhaseContext {
            round,
            phase: EventPhase::Committed,
            kaspa_anchor: winning.kaspa_anchor.clone(),
        }),
    }).await?;

    Ok(())
}
```

### 5.2 Atomicity and Race Notes (Minimal)

- `PhaseStorage::store_proposal(...)` must be atomic with “still accepting proposals for (event_id, round)” checks.
- `try_commit_and_sign(...)` is safe to call opportunistically from multiple places; it must be idempotent.
- Always re-check quorum at the timeout boundary to reduce “quorum just arrived” races.

### 5.3 Profile B (vNext): BFT Lock-and-Sign (Theory-Level)

This section describes the stricter, theory-level protocol for a Byzantine model (`N >= 3f+1`) that explicitly locks outpoints and binds a Kaspa anchor in the committed object.

Key differences vs v1:
- **Commit is a LockCert**, not “quorum observed” over an unsigned proposal set.
- `kaspa_anchor` is **required** and is part of what signers sign.
- Outpoints are locked explicitly, enabling safe multi-stream concurrency.
- Timeouts are **not part of correctness**; they are optional housekeeping (e.g., retransmit, garbage-collect, or trigger anti-entropy).

**Phase 1 (PLAN)**:
- A signer proposes a `Proposal` (PLAN) that includes `kaspa_anchor`, `utxos_used` (or `outpoints`), and `tx_template_hash`.
- Receivers validate that this PLAN is deterministic for the claimed anchor and event, and that its outpoints do not intersect any currently locked outpoints.

**Phase 2 (LOCK)**:
- A signer that accepts the PLAN constructs a `LockMsg` from it and emits `LockSigBroadcast { lock_msg, signature }`.
- Anyone can aggregate `Q_commit = 2f+1` distinct signer signatures into a `LockCert`.
- Upon accepting `LockCert`, every honest signer:
  - records the locked outpoints in its `ReservedOutpoints` index, and
  - refuses to sign conflicting locks.

**Phase 3 (SIGN)**:
- After a valid `LockCert`, proceed with threshold signing for `tx_template_hash` (or a dedicated digest), and broadcast the signed transaction.
- The coordinator role is replaceable: any signer can resume because the unique commitment is `LockCert`.

**Reorg handling**:
- If anchor stability assumptions are violated (anchor falls below the configured depth policy), invalidate the attempt and retry with a new anchor (Section 8.6).

This Profile B protocol is compatible with v1’s stream “holes” rule: only start PLAN/LOCK for an event when it is actionable and next-in-stream.

---

## 6. Storage Schema

### 6.1 New Column Families

```rust
/// Proposals: (event_id, round, proposer_peer_id) → Proposal
const CF_EVENT_PROPOSAL: &str = "event_proposal";

/// Event phase state: event_id → EventPhaseState
const CF_EVENT_PHASE: &str = "event_phase";

// Profile B / vNext (BFT lock certs):
// - lock sigs: (event_id, round, signer_peer_id) -> LockSigBroadcast (or signature bytes)
// - lock cert: (event_id, round) -> LockCert
// - outpoint locks: outpoint -> (event_id, round, tx_template_hash, kaspa_anchor)
// Suggested CF names (follow existing naming convention):
// const CF_EVENT_LOCK_SIG: &str = "event_lock_sig";
// const CF_EVENT_LOCK_CERT: &str = "event_lock_cert";
// const CF_OUTPOINT_LOCK: &str = "outpoint_lock";

// Background GC should periodically prune proposals/phase state for Completed/Abandoned events and anything older than a retention window.
//
// Recommended defaults:
// - Retain phase/proposals for Completed/Abandoned events for 1 hour (audit/diagnostics), then delete.
```

### 6.2 Phase Storage (Separate Trait)

Do **not** bloat the existing `Storage` trait. Keep it focused on the existing CRDT and event indexing. Two-phase introduces a dedicated storage interface for:
- event phase state (phase, round, canonical hash, retry counters), and
- proposal collection keyed by `(event_id, round, proposer_peer_id)`.

Key requirements:
- **Atomicity**: storing proposals must be atomic with “phase/round still accepting proposals” checks to avoid TOCTOU races.
- **Idempotency**: repeated gossiped proposals from the same peer/round are not errors.
- **One-per-peer-per-round**: if a peer attempts to send multiple different proposals in the same round, treat as equivocation (log + metric).
- **Garbage collection**: proposals and phase data must be pruned for completed/abandoned events.

```rust
/// Result of attempting to store a proposal (for idempotency and race clarity).
enum StoreProposalResult {
    Stored,
    DuplicateFromPeer,
    PhaseTooLate,
    RoundMismatch { expected: u32, got: u32 },
}

/// Phase/proposal storage for two-phase consensus.
///
/// In code, prefer `async` methods (RocksDB and in-memory both work), but this is kept
/// synchronous in the spec for brevity.
trait PhaseStorage {
    // === Phase state ===
    fn get_phase(&self, event_id: &Hash32) -> Result<Option<EventPhaseState>>;
    fn get_events_in_phase(&self, phase: EventPhase) -> Result<Vec<Hash32>>;

    /// Atomically enter Proposing for a new event (initialize round=0).
    /// Returns false if the event is already in a later phase.
    fn try_enter_proposing(&self, event_id: &Hash32, now_ns: u64) -> Result<bool>;

    /// Atomically set Committed only if still Proposing and round matches.
    /// Implementations should also update the stored round to `round` when committing (fast-forward support).
    fn try_commit(&self, event_id: &Hash32, round: u32, canonical_hash: Hash32, now_ns: u64) -> Result<bool>;

    /// Transition to Failed and increment round (bounded by retry policy in application layer).
    fn fail_and_bump_round(&self, event_id: &Hash32, round: u32, now_ns: u64) -> Result<()>;

    // === Proposals ===
    /// Store a proposal with phase/round enforcement.
    ///
    /// Required semantics:
    /// - If the event is Unknown, this call MUST initialize phase state to Proposing at `proposal.round`.
    /// - If local round != proposal.round, return RoundMismatch.
    /// - If phase is Committed/Completed/Abandoned, return PhaseTooLate.
    fn store_proposal(&self, proposal: &Proposal) -> Result<StoreProposalResult>;
    fn get_proposals(&self, event_id: &Hash32, round: u32) -> Result<Vec<Proposal>>;

    // === Cleanup ===
    fn clear_stale_proposals(&self, event_id: &Hash32, before_round: u32) -> Result<usize>;
    fn gc_events_older_than(&self, cutoff_timestamp_ns: u64) -> Result<usize>;
}
```

### 6.3 Data Structures

```rust
pub const MAX_UTXOS_PER_PROPOSAL: usize = 100;
pub const MAX_OUTPUTS_PER_PROPOSAL: usize = 16;
pub const MAX_KPSBT_SIZE: usize = 64 * 1024;

// Note: keep a single `Proposal` struct definition (see Section 2.3) and reuse it for:
// - transport (`TransportMessage::ProposalBroadcast`)
// - phase storage (`CF_EVENT_PROPOSAL`)

impl Proposal {
    fn validate_structure(&self) -> Result<(), ProposalValidationError> {
        if self.utxos_used.is_empty() {
            return Err(ProposalValidationError::NoUtxos);
        }
        if self.utxos_used.len() > MAX_UTXOS_PER_PROPOSAL {
            return Err(ProposalValidationError::TooManyUtxos {
                count: self.utxos_used.len(),
                max: MAX_UTXOS_PER_PROPOSAL,
            });
        }
        if self.outputs.len() > MAX_OUTPUTS_PER_PROPOSAL {
            return Err(ProposalValidationError::TooManyOutputs {
                count: self.outputs.len(),
                max: MAX_OUTPUTS_PER_PROPOSAL,
            });
        }
        if self.kpsbt_blob.len() > MAX_KPSBT_SIZE {
            return Err(ProposalValidationError::KpsbtTooLarge {
                size: self.kpsbt_blob.len(),
                max: MAX_KPSBT_SIZE,
            });
        }
        Ok(())
    }

    fn computed_hash(&self) -> Hash32 {
        Hash32::hash_of(&self.kpsbt_blob)
    }

    fn verify_hash_consistency(&self) -> bool {
        self.tx_template_hash == self.computed_hash()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum ProposalValidationError {
    #[error("too many UTXOs: {count} > {max}")]
    TooManyUtxos { count: usize, max: usize },
    #[error("too many outputs: {count} > {max}")]
    TooManyOutputs { count: usize, max: usize },
    #[error("KPSBT too large: {size} > {max} bytes")]
    KpsbtTooLarge { size: usize, max: usize },
    #[error("proposal has no UTXOs")]
    NoUtxos,
}
```

---

## 7. Transport Layer

### 7.1 New Message Types

```rust
// Extend existing transport enum (TransportMessage) rather than creating a new one
enum TransportMessage {
    EventStateBroadcast(EventStateBroadcast),
    StateSyncRequest(StateSyncRequest),
    StateSyncResponse(StateSyncResponse),
    ProposalBroadcast(ProposalBroadcast),
    // Profile B / vNext:
    // LockSigBroadcast(LockSigBroadcast),
    // LockCertBroadcast(LockCert),
}
```

**Round handling**:
- Increment `round` when re-entering Proposing after a timeout/Failed retry.
- Accept `ProposalBroadcast` only when `proposal.round == local.round` (or initialize the event at that round if phase is Unknown).
- Accept committed `EventStateBroadcast` only when `phase_context` is present and `phase_context.round >= local.round`; fast-forward to `phase_context.round` and clear stale proposals for older rounds.

### 7.2 Transport Trait Extension

```rust
trait Transport {
    // Existing
    async fn publish_event_state(&self, broadcast: EventStateBroadcast) -> Result<()>;
    async fn publish_state_sync_request(&self, request: StateSyncRequest) -> Result<()>;
    async fn publish_state_sync_response(&self, response: StateSyncResponse) -> Result<()>;

    // New
    async fn publish_proposal(&self, proposal: ProposalBroadcast) -> Result<()>;
}

// Implementation note: add `From<&StoredEventCrdt> for EventCrdtState` to avoid repeated manual conversions in handlers.
```

### 7.3 Message Handling

```rust
// Follow existing handler pattern (free functions in igra-service coordination)
pub async fn handle_proposal_broadcast(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    proposal: ProposalBroadcast,
) -> Result<(), ThresholdError> {
    // enforce round match, size limits, validation, store, then check quorum/timeout
}

// Extend existing CRDT handler with a phase gate instead of replacing it.
pub async fn handle_crdt_broadcast(...) -> Result<(), ThresholdError> {
    // In v1.1, an `EventStateBroadcast` that carries `phase_context=Committed`
    // is the commit signal and should fast-forward Unknown/Proposing peers.
    if let Some(ctx) = &broadcast.phase_context {
        if ctx.phase == EventPhase::Committed {
            return handle_committed_broadcast(...).await;
        }
    }

    // Otherwise: only merge CRDT state if we already committed to this hash.
    if let Some(phase) = phase_storage.get_phase(&broadcast.event_id)? {
        if phase.phase == EventPhase::Committed && phase.canonical_hash != Some(broadcast.tx_template_hash) {
            return Ok(()); // ignore non-canonical hash
        }
        if phase.phase == EventPhase::Proposing || phase.phase == EventPhase::Failed {
            // In v1.1, peers should not broadcast CRDT state before commit.
            // Treat as legacy/noise unless running an explicit compatibility mode.
            return Ok(());
        }
    }

    // existing merge/sign/submit flow (merge, maybe sign, maybe submit)
}
```

All handlers must enforce:
- round match with local round
- size limits (utxos_used count, payload bytes)
- rate limiting / metrics per peer/event

**DoS note (future-round proposals)**:
- Do not let “future-round proposals trigger sync” become a trivial DoS lever.
- Recommended guards:
  - Only treat `proposal.round == local.round + 1` as a “missed state” hint.
  - Ignore proposals with `proposal.round > local.round + 1` (count a metric).
  - Apply a `STATE_SYNC_COOLDOWN_MS` cooldown per `(peer,event_id)` before triggering another targeted sync.
  - Apply an overall per-peer rate limit for `StateSyncRequest` emission.

### 7.4 Anti-Entropy for Proposals and Phase State (Critical for Liveness)

The existing transport already has anti-entropy primitives:
- `StateSyncRequest { event_ids }`
- `StateSyncResponse { states: Vec<(event_id, tx_template_hash, EventCrdtState)> }`

Two-phase introduces *additional* replicated state that must be included in anti-entropy; otherwise, a lagging node can repeatedly miss proposals and time out forever.

Required properties:
- A node that missed proposal gossip can recover **current-round proposals** for an event.
- A node that missed a commit signal can recover the **committed phase state** and fast-forward.

Recommended approach (v1.1+):
- Extend `StateSyncResponse` to also carry:
  - `phase_states: Vec<(event_id, EventPhaseState)>`
  - `proposals: Vec<Proposal>` (bounded: only current round per event, and capped by `MAX_UTXOS_PER_PROPOSAL` / `MAX_PROPOSAL_SIZE_BYTES`)

Operationally:
- On each anti-entropy tick, request sync for events in `Proposing` and `Committed`.
- When receiving phase state showing `Committed`, fast-forward immediately (same as receiving a committed broadcast).
- When receiving proposals for the current round, store them and re-check `quorum_hash` to opportunistically commit.

Round correctness requirement:
- State-sync MUST be able to return proposals for the receiver’s current `(event_id, round)`; otherwise a lagging node can get stuck retrying old rounds indefinitely.
- Recommended wire shape: treat the sender’s `EventPhaseState` as the “round cursor”, and return only state for that cursor:
  - Return `EventPhaseState { round, phase, canonical_hash, retry_count }`.
  - If `phase == Proposing`, return proposals only for that `round` (never historical rounds).
  - If `phase >= Committed`, return CRDT state; proposals are optional (commit already selected).
  - Receiver rules:
    - If receiver local `round > sender.round`, ignore proposal payload.
    - If receiver local `round < sender.round`, fast-forward local phase/round first (do not store out-of-round proposals), then accept proposals for the new local round.
    - If receiver sees a future-round `ProposalBroadcast` on the gossip path, trigger a targeted `StateSyncRequest` for that event (Section 5.1).

DoS / load bounds (recommended):
- Cap sync to `MAX_SYNC_EVENTS_PER_TICK` events per peer (e.g., 64).
- Cap returned proposals to `MAX_PROPOSALS_PER_EVENT_PER_RESPONSE` per event (e.g., `min(N, 20)`).
- Prefer returning only the current round per event; never return historical rounds.
- Enforce `MAX_PROPOSAL_SIZE_BYTES` at decode time; reject oversized payloads before storing.

---

## 8. Edge Cases

### 8.1 Summary Table

| Scenario | Detection | Handling / Notes |
|---------|-----------|------------------|
| Late joiner | Committed broadcast arrives for unknown event | Fast-forward via `on_committed_broadcast`; validate and sign if needed |
| Out-of-order messages | Proposal/commit arrives before local state exists | Round rules + anti-entropy (Section 7.4); ignore stale rounds |
| Partial proposal views | Timeout boundary without quorum | Do not commit; `Failed` → `round += 1` → retry/backoff |
| Restart mid-propose | Process restarts with `Proposing` events | Resume timers; at timeout boundary do last-chance quorum check; otherwise retry |
| Network partition | Subset < M isolated | Cannot commit; retries may eventually Abandon; heals via commit fast-forward or anti-entropy |
| Duplicate proposals (retransmit) | Same peer repeats identical proposal | Idempotent store; debug log only |
| Equivocation | Same peer sends different proposals for same `(event_id, round)` | Log `warn`, metric; ignore the later one (one-per-peer-per-round) |
| Invalid proposal | Validation fails | Reject; metric; do not store |
| Conflicting commit | Received committed broadcast for different hash than our committed hash | Log `warn` + metric; never switch commitments; never sign other hash |
| Timeout with zero proposals | No proposals received (including our own) | `Failed` → retry/backoff; if repeats, Abandon and alert |
| RPC + gossip race | Event arrives concurrently via two sources | Storage-level atomic ops; handlers are idempotent |
| Clock skew | Proposal timestamps differ | Timestamps are audit-only; never used in selection |
| Proposal for Completed | Proposal arrives after completion | Ignore |
| Very late joiner | Comes online after completion | Sync completion record for audit only |
| Stream holes | Next-in-stream event not actionable | Stall stream; buffer later nonces; emit metrics/alerts; no skip in v1 |

### 8.2 Persistent Partitions / No-Quorum Conditions

If the system cannot reach quorum for an event for `max_retries + 1` rounds, the event transitions to `Abandoned` and requires operator intervention (see Section 15.1).

### 8.3 Reorg-Induced Failures

If revalidation fails repeatedly due to reorg/lag (Section 8.4/8.5), the event may thrash through retries and ultimately Abandon. This is expected behavior: the protocol prefers explicit failure over committing on unstable inputs.

### 8.4 Reorg During Commit

**Scenario**: After canonical selection, a Kaspa DAG reorg invalidates one or more inputs.

**Handling**:
- **Mandatory**: revalidate UTXO spendability and depth filter **immediately before signing**; if any input fails, refuse to sign.
- Transition to `Failed`, increment round, and restart Proposing with fresh UTXOs (bounded retries).
- Emit alert; frequent hits imply node sync lag or fee pressure.

### 8.5 UTXO Reorg Risk (Kaspa 10 BPS, probabilistic finality)

**Context**: Kaspa targets ~10 blocks/sec and provides probabilistic finality (DAG). Shallow history is more likely to change than deep history. For our system, the practical risks are:
- inputs become invalid between propose and sign (reorg / late merge / spend races),
- and different signers see slightly different “spendable” UTXO views (node lag).

**Design goal**: choose inputs that are “old enough” that the probability of them being invalidated during our operational window (seconds–minutes) is **negligible**, and that all healthy signers are likely to observe them.

#### 8.5.1 Reorg-Minimizing Input Filter (Depth Gating)

Introduce a mandatory input filter:
- Only select UTXOs whose **creation score** is at least `MIN_INPUT_SCORE_DEPTH` behind the current tip score.
- With ~10 BPS, a depth of:
  - 300 ≈ 30 seconds,
  - 600 ≈ 1 minute,
  - 1200 ≈ 2 minutes.

There is no single universally “correct” depth; treat `MIN_INPUT_SCORE_DEPTH` as an SLO knob and tune it using observed reorg/lag rates and event value tiers.

**Defaulting rule (recommended)**:
- `MIN_INPUT_SCORE_DEPTH = max(300, group.finality_blue_score_threshold)`.
- If `group.finality_blue_score_threshold` is unset/zero (dev/test), the max degenerates to 300.

**Important limitation**: depth gating is a heuristic, not a proof of finality. Kaspa’s DAG can, in rare conditions, invalidate deeper history than “typical” orphan rates would suggest. This is why:
- revalidation is mandatory immediately before signing, and
- simulation/chaos testing must be used to choose a depth that meets your operational risk tolerance.

**Non-goal**: do not automatically lower depth on later retries in production. If you add a “depth relaxation” escape hatch for liveness, it must be:
- explicitly configured (off by default),
- policy-gated (e.g., only for small-value withdrawals),
- observable (metrics/alerts), and
- tested under reorg injection.

#### 8.5.2 Liveness Failure Mode: No Eligible “Deep” UTXOs

If the depth filter yields zero eligible UTXOs:
- Do not spam proposals with shallow inputs “just to make progress”.
- Prefer transitioning to `Failed` with a specific reason (e.g., `InsufficientDeepUtxos`) and retrying with a longer delay (adaptive timeout/backoff), and/or triggering consolidation to create a deep reserve.

Optional escape hatch (explicitly configured, off by default):
- `depth_relaxation` policy:
  - `enabled: bool`
  - `after_retries: u32` (e.g., 2)
  - `min_depth_floor: u64` (e.g., 60)
  - `max_event_amount_sompi: u64` (only allow relaxing for small withdrawals)
  - `alert_on_use: bool`

If enabled, only relax depth after repeated failures and only within policy bounds; otherwise Abandon and require operator intervention.

#### 8.5.3 Quantitative Depth Selection (Calibration, Not a Proof)

Depth gating is a risk-reduction heuristic, not a finality proof. The correct question for this protocol is:

> For our expected signing window (seconds–minutes), what depth makes input invalidation during that window operationally negligible?

Useful mental model (intuition only):
- In Nakamoto-style analyses, reorg probability decays roughly exponentially with confirmation depth (often expressed in terms like `(q/p)^d` for attacker fraction `q < p`).
- GHOSTDAG has different mechanics, but the same qualitative expectation: deeper history is exponentially harder to overturn under honest majority and bounded delay.

What we do with that:
- Treat `MIN_INPUT_SCORE_DEPTH` as a tunable SLO knob rather than a magic constant.
- Use telemetry and simulation to justify defaults for your environment rather than inheriting folklore.

Telemetry signals:
- Too shallow: `utxo_revalidation_failures_total` rises, retry/abandon rate rises.
- Too deep: `utxo_depth_rejects_total` rises, “no eligible deep UTXOs” rises, retry/abandon rate rises.

#### 8.5.4 Calibrating Depth Using `simpa` (Recommended)

`rusty-kaspa` includes a DAG simulator (`simpa`) that can generate block-DAG traces under configurable block rate and network delay. Use it to calibrate depth choices against the kinds of delays you expect in production, and to provide reviewer-facing justification for `MIN_INPUT_SCORE_DEPTH`.

Workflow sketch:
1. Generate a blocks trace with representative parameters (bps, delay, miners, duration).
2. Post-process the trace to compute an empirical “order stability” curve vs depth for those parameters.
3. Pick `MIN_INPUT_SCORE_DEPTH` so that the reorg-induced invalidation probability during the signing window meets your SLO for the given event tier.

Example command (run from the `rusty-kaspa/` repo root; flags may change, always verify via `--help`):
```bash
cargo run -p simpa --release -- \
  --bps 10 \
  --delay 2 \
  --miners 64 \
  --target-blocks 20000 \
  --blocks-json-gz-output-path ./simpa-blocks.jsonl.gz
```

Notes:
- This is for calibration and confidence; production code should not depend on a simulator.
- If post-processing is not available yet, you can still use the simulator to compare relative stability across delays and select a conservative depth, then validate with live telemetry.

#### 8.5.5 Determinism: Make Convergence Likely

We already require deterministic coin selection (leaderless requirement). In this codebase, the deterministic ordering/selection lives in:
- `igra-core/src/domain/pskt/builder.rs` (deterministic UTXO ordering + “smallest prefix” selection).

The depth filter is an additional deterministic **pre-filter**. If all signers’ nodes are healthy, deep-enough UTXOs should be visible to all, making it more likely that everyone proposes the same template on the first round.

Profile B note (optional hardening):
- When `kaspa_anchor` is required, you may want deterministic ordering to be explicitly salted by `(event_id, kaspa_anchor)` to make proposal grinding harder and make “same inputs at same anchor” maximally likely:
  - example stable sort key: `H(kaspa_anchor || event_id || outpoint)` (ascending),
  - then select the smallest prefix that covers amount+fees.

#### 8.5.6 Mandatory Pre-Sign Revalidation (Avoid Wasting Rounds)

Immediately before signing (entering `Committed`), revalidate:
- every input is still unspent / present in the current UTXO set, and
- every input still satisfies the depth filter against the current tip score.

If any check fails: do not sign; transition to `Failed`, bump `round`, and re-propose with fresh inputs.

#### 8.5.7 Implementation Guidance (This Codebase)

Where to implement:
1. **Config**: extend `PsktBuildConfig` (or `GroupConfig`) with:
   - `min_input_score_depth: u64` (default `MIN_INPUT_SCORE_DEPTH`),
   - `allow_shallow_inputs: bool` (default false; devnet/testing escape hatch),
   - (optional) `min_coinbase_maturity_depth: u64` if coinbase maturity must be enforced explicitly.
2. **RPC**: the current `NodeRpc` provides `get_virtual_selected_parent_blue_score()` and `get_utxos_by_addresses(...)`. To do proper depth gating, add one of:
   - `get_virtual_selected_parent_daa_score()` (preferred if `UtxoEntry` exposes `block_daa_score`), or
   - `get_virtual_selected_parent_score()` returning both (blue + daa) in one call.
3. **Filtering**: in `igra-core/src/infrastructure/rpc/kaspa_integration/mod.rs` (right after fetching UTXOs):
   - fetch `tip_score`,
   - filter out UTXOs whose creation score is too recent,
   - pass only eligible inputs to `build_pskt_from_utxos(...)`.

Pseudo-code (score-type agnostic):
```rust
let tip_score = rpc.get_virtual_selected_parent_score().await?;
let min_score = tip_score.saturating_sub(config.min_input_score_depth);

let eligible = utxos
    .into_iter()
    .filter(|u| u.entry.creation_score() <= min_score)
    .collect::<Vec<_>>();

if eligible.is_empty() && !config.allow_shallow_inputs {
    return Err(ThresholdError::InsufficientUTXOs);
}
```

#### 8.5.8 Operational Hardening: “Deep UTXO Reserve”

To make “deep-only inputs” practical:
- periodically consolidate UTXOs (when idle) into a small set of larger outputs,
- wait until those consolidation outputs reach `MIN_INPUT_SCORE_DEPTH`,
- then use those deep outputs for events.

This reduces both:
- reorg exposure (you mostly spend deep outputs),
- and divergence (all signers see the same deep pool).

### 8.6 Kaspa Anchor Semantics (v1 Advisory, Profile B Required)

The protocol’s *effective* reorg safety comes from:
- depth gating on input selection (Section 8.5.1), and
- mandatory pre-sign revalidation (Section 8.4 / Section 8.5.6).

Some reviewers prefer (and BFT theory generally expects) an explicit “Kaspa anchor” in the *voted object* to make reorg handling compositional. We support two anchor policies:

1) **v1 (recommended): anchor is advisory**
- Proposals MAY include `kaspa_anchor: Option<KaspaAnchorRef>` for audit/diagnostics.
- Quorum is still on `tx_template_hash` alone (inputs are already bound by the PSKT template hash).
- Immediately before signing, a signer revalidates inputs against its **current** view and depth rules; if invalid, it refuses to sign and the round retries.
- This preserves liveness when signers’ Kaspa tips differ slightly.

2) **Profile B / vNext (BFT): anchor is required and signed**
- `kaspa_anchor` is REQUIRED in every PLAN/Proposal and is included in the signed `LockMsg`.
- The commit object is `LockCert` over `(event_id, round, kaspa_anchor, outpoints, tx_template_hash)` (Section 5.3).
- If the anchor later becomes unstable (falls behind the configured depth policy), invalidate the attempt and retry with a new anchor.

Tradeoff:
- Anchor binding makes the spec cleaner and reorg handling compositional, but can reduce liveness when signers’ Kaspa tips diverge.
- Advisory anchors keep the v1 implementation pragmatic: “sign only when inputs are verifiably deep/spendable now”.

---

## 9. Security Considerations

### 9.1 Proposal Validation

Every proposal must be validated before storage:

```rust
fn validate_proposal(&self, proposal: &Proposal) -> Result<()> {
    // 1. Structure (size limits, presence)
    proposal
        .validate_structure()
        .map_err(|e| ThresholdError::ProposalValidationFailed { reason: e.to_string() })?;

    // 2. Hash consistency
    if !proposal.verify_hash_consistency() {
        return Err(ThresholdError::ProposalValidationFailed { reason: "proposal hash mismatch".to_string() });
    }

    // 3. Proposer must be group member
    if !self.config.group.member_pubkeys.contains(&proposal.proposer_peer_id.to_pubkey()) {
        return Err(ThresholdError::InvalidPeerIdentity);
    }

    // 4. TX outputs must match event
    verify_tx_outputs(&proposal.kpsbt_blob, &proposal.signing_material)?;

    // 5. Source proof must be valid
    let stored_event = StoredEvent::from(&proposal.signing_material);
    let report = self.message_verifier.verify(&stored_event)?;
    if !report.valid {
        return Err(ThresholdError::EventSignatureInvalid);
    }

    // 6. Policy must pass
    self.policy_enforcer.enforce(&stored_event, &self.policy)?;

    // 7. UTXO sufficiency and depth checks already done at selection time; enforce here too
    validate_utxo_sufficiency(&proposal.utxos_used, &proposal.signing_material)?;

    Ok(())
}
```

Implementation note: extract shared event validation (source proof + policy) into a reusable helper (e.g., `validate_signing_event`) and reuse it both here and in CRDT signing paths to avoid duplication and drift.

### 9.2 Commit Validation

Same validation applies to commits (which include signing_material and kpsbt_blob).
Revalidation is mandatory: rebuild locally, ensure outputs match, and ensure UTXOs remain spendable/deep enough before signing to guard against post-proposal reorgs.

### 9.3 One Signature Per Event

The irrevocable lock remains:
- Once `set_event_active_template_hash(event_id, hash)` succeeds
- All future attempts with different hash will fail
- Signer can only sign one TX per event

### 9.4 Replay Prevention

- `event_id` is derived from event content (deterministic)
- Completed events are tracked
- Proposals/commits for completed events are rejected

### 9.5 DoS Mitigation

- Only group members can propose (validated by peer_id)
- One proposal per member per round (idempotent; equivocation tracked)
- Rate limiting on proposal processing (if needed)
- Enforce size limits (e.g., `MAX_UTXOS_PER_PROPOSAL`, `MAX_PROPOSAL_SIZE_BYTES`) and reject oversized proposals

### 9.6 Error Surface

Extend `ThresholdError` (or equivalent) with two-phase-specific variants (round mismatch, unknown proposer, proposal validation failed, invalid phase transition, conflicting commit) so errors remain typed and diagnosable.

---

## 10. Implementation Checklist

### 10.1 Storage Layer

- [ ] Add `CF_EVENT_PROPOSAL` column family
- [ ] Add `CF_EVENT_PHASE` column family
- [ ] Introduce `PhaseStorage` trait (separate from `Storage`)
- [ ] Implement `store_proposal()` (atomic with phase/round check)
- [ ] Implement `get_proposals(round)` / `has_proposal_from(round)` / `proposal_count(round)`
- [ ] Implement `get_phase()` / `try_enter_proposing()` / `try_commit()` / `fail_and_bump_round()`
- [ ] Implement `get_events_in_phase()`
- [ ] Implement proposal/phase GC (`gc_events_older_than`, `clear_stale_proposals`)
- [ ] Track round/retry_count and enforce forward-only transitions

### 10.2 Transport Layer

- [ ] Define `ProposalBroadcast` message type
- [ ] Add `publish_proposal()` to Transport trait
- [ ] Implement gossip for proposals
- [ ] Extend `TransportMessage` with `ProposalBroadcast(Proposal)`
- [ ] Extend `EventStateBroadcast` with optional `PhaseContext { round, phase }` (used to signal “Committed”)
- [ ] Add message handler routing

### 10.3 Protocol Logic

- [ ] Implement proposal reception handler (`on_proposal` / `handle_proposal_broadcast`)
- [ ] Implement commit fast-forward on committed `EventStateBroadcast`
- [ ] Implement `transition_to_committed()` guarded by `quorum_hash(...)`
- [ ] Implement `quorum_hash()` (no-fallback) helper
- [ ] Implement background timeout checker
- [ ] Implement startup recovery
- [ ] Enforce round handling rules (proposals must match round; commits may fast-forward round)

### 10.4 Event Processor Integration

- [ ] Modify `submit_signing_event()` to enter Proposing phase
- [ ] Add proposal broadcast after TX building
- [ ] Remove immediate signing (defer to Committed phase)
- [ ] Add quorum checking
- [ ] Add retry policy (max_retries/backoff) for Failed → Proposing; mark Abandoned when exhausted

### 10.5 Validation

- [ ] Implement `validate_proposal()`
- [ ] Implement `verify_tx_outputs()`
- [ ] Add proposer identity verification
- [ ] Enforce proposal size limits (`MAX_UTXOS_PER_PROPOSAL`, `MAX_PROPOSAL_SIZE_BYTES`)
- [ ] Enforce mandatory UTXO revalidation before signing
- [ ] Extract shared event validation (source proof + policy) for reuse across proposal handling and CRDT signing paths
- [ ] Add ThresholdError variants for two-phase (round mismatch, unknown proposer, validation failed, invalid phase transition, conflicting commit)

### 10.6 Testing

- [ ] Unit tests for `quorum_hash` (quorum/no-quorum, tie-break determinism)
- [ ] Unit tests for phase transitions
- [ ] Integration test: normal flow (3 signers, same proposals)
- [ ] Integration test: divergent proposals, canonical selection
- [ ] Integration test: late joiner
- [ ] Integration test: timeout with partial proposals
- [ ] Integration test: signer restart during Proposing
- [ ] Integration test: network partition and recovery
- [ ] Timeout without quorum: ensure no commit, round increments, retry/backoff
- [ ] GC behavior and Abandoned path after max retries
- [ ] Simulation: run 1000+ synthetic events with injected message delay/loss and injected “UTXO invalidation before commit”; record retry/abandon rates and tune `PROPOSAL_TIMEOUT_MS` + depth filter
- [ ] Reorg/depth calibration: use `simpa` traces to justify `MIN_INPUT_SCORE_DEPTH` defaults and validate depth vs delay assumptions (Section 8.5.4)
- [ ] Concurrency/race tests (e.g., Loom) around: timeout boundary vs. quorum arrival, commit fast-forward vs. local commit attempt

---

## 11. Migration

### 11.1 Backward Compatibility

The two-phase protocol is **not backward compatible** with the current immediate-sign protocol. All signers must be upgraded together.

### 11.2 Migration Steps

1. Coordinate upgrade window with all signers
2. Stop all signers
3. Drain or abort in-flight events (ensure no events remain in Proposing/Committed, or explicitly mark them Failed for replay after upgrade)
4. Deploy new code to all signers
5. Start all signers
6. Verify protocol version match on startup (add version handshake)

### 11.3 Version Handshake

```rust
// On peer connection
async fn handshake(&self, peer: PeerId) -> Result<()> {
    let my_version = ProtocolVersion::TwoPhase;
    let peer_version = self.exchange_version(peer, my_version).await?;

    if peer_version != my_version {
        return Err(ThresholdError::ProtocolVersionMismatch);
    }

    Ok(())
}
```

---

## 12. Metrics and Monitoring

### 12.1 Key Metrics

| Metric | Description |
|--------|-------------|
| `proposal_phase_duration_ms` | Time spent in Proposing phase |
| `proposals_received_count` | Number of proposals received per event |
| `canonical_selection_method` | How the committed hash was determined (expected: "quorum") |
| `fast_forward_count` | Times we skipped Proposing (late joiner) |
| `proposal_validation_failures` | Invalid proposals received |
| `phase_transition_errors` | Errors during phase transitions |
| `split_brain_warnings` | Times we received conflicting commits |
| `unique_hashes_per_event` | Distinct proposal hashes per event (divergence gauge) |
| `proposal_timeouts_without_quorum` | Propose rounds that timed out without quorum (triggers retry) |
| `round_retries_total` | Total number of round retries across events |
| `events_abandoned_total` | Events moved to Abandoned after max retries |
| `utxo_depth_rejects_total` | UTXOs rejected by depth filter during selection |
| `utxo_revalidation_failures_total` | Pre-sign revalidation failures (inputs missing/spent/too shallow) |
| `stream_holes_blocking_total` | Times a stream could not advance because the next nonce was not actionable |
| `stream_hole_blocked_duration_ms` | Time a stream spends blocked waiting for the next actionable nonce |
| `outpoint_lock_conflicts_total` | (vNext) Plans/locks rejected due to overlapping locked outpoints |
| `lock_sigs_received_total` | (vNext) Lock signatures received |
| `lock_certs_accepted_total` | (vNext) Lock certificates accepted |
| `state_sync_throttled_total` | Targeted sync requests suppressed by cooldown/rate limits |

### 12.2 Alerts

| Condition | Severity | Action |
|-----------|----------|--------|
| `proposal_phase_duration_ms > 10000` | Warning | Check network connectivity |
| `proposal_timeouts_without_quorum > 0` | Warning | Indicates divergence/partition or insufficient deep UTXOs |
| `split_brain_warnings > 0` | Critical | Investigate network partition |
| `proposal_validation_failures > 10/min` | Warning | Possible attack or misconfiguration |
| `events_abandoned_total > 0` | Critical | Operator intervention required |
| `proposal_timeouts_without_quorum / events_total > 0.05` (5% over 1h) | Critical | Investigate systemic divergence (node lag, depth filter too strict, transport loss) |
| `utxo_revalidation_failures_total / commits_total > 0.01` (1% over 1h) | Warning | Increase depth or fix node inconsistency |
| `stream_hole_blocked_duration_ms > 600000` (10m) | Warning | Investigate missing upstream artefacts for next-in-stream nonce |

---

## 13. Decisions (Closed)

1. **Commit threshold**: commit only when a single hash has ≥`COMMIT_QUORUM` votes in the current round. No timeout-based commit fallback.
2. **Participation requirement**: do not wait for all N; `COMMIT_QUORUM` is sufficient for safety and availability under the selected fault model (Section 1.4.1).
3. **Signing rule**: sign the winning proposal’s `kpsbt_blob` only after validating outputs and performing mandatory pre-sign UTXO revalidation (spendable + depth). If validation fails, do not sign.
4. **Revalidation failure**: if revalidation cannot confirm inputs are spendable/deep enough, transition to Failed and retry (or Abandon if exhausted). Never sign “hoping it broadcasts”.
5. **Proposal mutability**: proposals are immutable; one proposal per peer per round (duplicates idempotent; equivocation tracked).
6. **Upstream ordering (v1)**: strict in-order execution per stream; stall on holes; no SkipCert/governance skip mechanism in v1.
7. **Cross-event UTXO safety (v1)**: for a given UTXO pool (one multisig script/address set), process at most one event at a time in `Proposing`/`Committed` (Section 5.0). Multi-stream concurrency requires an explicit reserved-outpoints rule (vNext).
8. **BFT upgrade path (vNext)**: Profile B uses `LockSigBroadcast`/`LockCert` over `(event_id, round, kaspa_anchor, outpoints, tx_template_hash)` as the commit object to make outpoint locking and anchor binding explicit (Section 5.3).

---

## 14. Robustness, Performance, and Testing Focus

### 14.1 Safety and Liveness Guarantees
- One signature per signer per event (lock on commit).
- Invalid proposals rejected via deterministic validation (outputs + UTXO sufficiency).
- **Safety**: Under Profile A (non-equivocation) with `M > N/2`, or under Profile B with `N >= 3f+1` and `Q_commit = 2f+1`, conflicting commits cannot both form.
- **Liveness (best-effort)**: Under partial synchrony and healthy nodes, events should commit without exhausting retries; under partitions, node lag, or persistent UTXO divergence, rounds may time out and be retried, and may eventually be Abandoned.

### 14.2 Performance Expectations
- Latency: +1 gossip round plus proposal timeout in non-convergent cases; validate with deployment telemetry (don’t assume 1–5s without measurement).
- Bandwidth: proposals ~1 KB each (UTXO set + outputs); commits reuse existing CRDT state.
- CPU: rebuild/validate PSKTs cheap (few inputs).

### 14.3 Testing and Simulation Matrix
- **Unit**: quorum detection (`quorum_hash`), proposal validation, phase transitions.
- **Integration**: normal flow (aligned proposals), divergent proposals (no quorum → retry), late joiner fast-forward, timeout without quorum.
- **Chaos/partition**: split network (e.g., 2/5 vs 3/5), recovery after heal, high-latency gossip.
- **Restart**: crash mid-propose, resume timers/state on boot.
- **Reorg sensitivity**: invalidate UTXOs between propose and commit; ensure reset/re-propose and validate depth-gating + revalidation behavior (Section 8.4/8.5, Section 8.5.4).

### 14.4 Operational Risk Focus
- Track divergence rate (unique hashes per event) and phase durations for tuning.
- Ensure NTP-synced clocks to keep timestamps meaningful for audit/debug (timestamps are not consensus inputs).
- Observe Kaspa RPC failure rates; add retries/backoff before stalling events.

---

## 15. Liveness Analysis and Bounds

- **Partial synchrony assumption**: With `COMMIT_QUORUM` online and message delays bounded in practice, quorum is expected to be reachable; if quorum is not reached before timeout, the protocol retries a new round with backoff.
- **Partitions**: If partitions persist and quorum is never reached, retries will not make progress. Use `RETRY_CONFIG` to cap retries; after `max_retries`, transition to Abandoned and alert.
- **Circuit breaker**: Abandon events that exceed retry budget; require human/operator decision to resume/replay.
- **Divergence probability**: Quorum-only commit prevents split commits by design. Timeouts surface non-convergence explicitly (retry/abandon) instead of “guessing” a hash under partial views.
- **Reorg impact**: See Section 8.4/8.5 for the mandatory revalidation + depth gating approach and its operational tradeoffs.
- **Upstream ordering stalls (v1)**: if the next nonce in a required stream is not actionable, the system intentionally makes no progress on that stream until prerequisites appear (or an operator resolves it out of band). Track this separately via `stream_holes_*` metrics.

### 15.1 Operator Runbook (Abandoned Events)

When an event reaches `Abandoned`, the system could not reach a safe commit (no quorum) within the retry budget.
This is not a safety failure; it is an explicit liveness failure that requires action.

Recommended operator workflow:
1. **Diagnose**:
   - Check `proposal_timeouts_without_quorum`, `utxo_revalidation_failures_total`, and transport health (anti-entropy success rate).
   - Check Kaspa node health and sync lag across signers (tip score deltas).
   - If liveness is blocked but quorum/revalidation metrics are normal, check for **stream holes** (missing actionability for the next nonce).
2. **Stabilize inputs**:
   - If `utxo_depth_rejects_total` is high, provision a deep UTXO reserve (Section 8.5.8) or adjust depth policy for small-value withdrawals only (Section 8.5.2).
   - If revalidation failures are high, increase depth and/or fix node lag.
3. **Replay / Reset (must be implemented)**
   - Provide an admin API to reset an event’s two-phase state:
     - `AdminResetEvent { event_id }` → clears proposals/phase and restarts at round 0.
   - Provide an admin API to re-inject an external request:
     - `AdminReplayExternal { external_id_raw }` → re-submits the upstream event (idempotent by `event_id` derivation).
   - Define who is allowed to call these endpoints and require audit logging for every use.
4. **Resolve stream hole (if applicable)**
   - Ensure the missing nonce becomes actionable (origin RPC/indexer health, proof material availability, ISM artefacts).
   - Re-inject/rescan the missing nonce so the stream can proceed **in-order** (no skipping in v1).

Alerting integration (recommended):
- Expose metrics to Prometheus and route critical alerts (e.g., `events_abandoned_total > 0`) through Alertmanager → PagerDuty/OpsGenie.

### 15.2 Hard Bounds (What We Can Guarantee)

This protocol does not guarantee completion, but it does bound work and time spent per event:
- **Max rounds before Abandon**: `1 + RETRY_CONFIG.max_retries`
- **Max time before Abandon (upper bound)**:
  - `sum_round_timeouts + sum_retry_delays`, where
  - `sum_round_timeouts ≤ (1 + max_retries) * PROPOSAL_TIMEOUT_MS` (or larger if adaptive timeout is enabled),
  - `sum_retry_delays ≤ max_retries * RETRY_CONFIG.max_delay_ms` (by construction).

These bounds make failures predictable and operationally manageable (no infinite stalls).

### 15.3 Quantitative Expectations (Template, Not a Guarantee)

This protocol cannot provide deterministic “commit within X seconds” guarantees in an asynchronous network, but you can set measurable expectations under explicit operational assumptions:

Let:
- `D_p95` be the measured p95 end-to-end gossip delay for proposals across N≈20,
- `T` be `PROPOSAL_TIMEOUT_MS`,
- `P_deep` be the probability that all healthy signers have sufficient eligible deep UTXOs at round start.

Recommended deployment target:
- Choose `T >= 2 * D_p95` so that, when the network is healthy, a single round has a high chance of reaching quorum.

What to measure after rollout:
- `round_retries_total / events_total` (retry rate)
- `events_abandoned_total / events_total` (abandon rate)

Simple quantitative model (planning frame, not a guarantee):
- Define `p_round_success = P(quorum reached within T) * P(commit candidate passes revalidation)`.
- If rounds are independent enough for a first approximation, the expected rounds until commit is:
  - `E[rounds] ≈ 1 / p_round_success`.
- With bounded retries, the probability of abandonment is approximately:
  - `P(abandon) ≈ (1 - p_round_success)^(1 + max_retries)`.

If abandon rate is high:
- root cause is almost always one of: (a) transport loss / partitions, (b) node lag, (c) depth policy too strict / no deep reserve.
Treat this as an operational SLO breach and tune `T`, anti-entropy, and depth policy using the simulation checklist (Section 10.6).

---

## 16. References

- `UTXO_CONSENSUS_PROBLEM.md` - Problem analysis and solution comparison
- `FIXES_CRDT_GOSSIP_VALIDATION.md` - Related security fixes for gossip path
- Paxos Made Simple (Lamport) - quorum/consensus background
- THORChain/TSS design docs - quorum-based signing patterns
- Kaspa GHOSTDAG / probabilistic finality papers (reorg/finality context)

---

*Specification Version: 1.1 (draft)*
*Updated: 2026-01-15*
