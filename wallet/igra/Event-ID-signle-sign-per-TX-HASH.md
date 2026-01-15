# Event-ID-signle-sign-per-TX-HASH.md

Design note: making the “**sign only once per event**” guarantee explicit.

This doc describes the recommended change to ensure a signer **never produces signatures for two different transaction templates for the same `event_id`**, even across restarts, races, or future refactors.

---

## 1. Problem

Today, the system mostly relies on **implicit** safeguards:

- phase gating: do not sign until the event is `Committed`
- canonical gating: ignore CRDT broadcasts that do not match the local canonical hash
- per-state guard: `maybe_sign_and_broadcast` returns early if it already sees a signature from `local_peer_id` in that CRDT state

These guards are strong, but they are not an explicit, durable invariant of the form:

> “For a given `event_id`, this signer will only ever sign one `tx_template_hash`.”

If state is lost, reset, or a future code path accidentally bypasses the canonical/phase gates, a signer could end up signing the same event twice (with different templates).

---

## 2. Goal (explicit invariant)

Persist a per-event record:

> `signed_hash[event_id] = tx_template_hash`

and enforce:

> A signer must **refuse** to sign any other `tx_template_hash` for the same `event_id`.

This turns “single-sign” from an emergent property into a **hard rule**.

---

## 3. What counts as a “vote” vs a “signature”

### 3.1 Votes (Phase 1)

- A Phase 1 “vote” is a `ProposalBroadcast` (proposal) received over gossip.
- We know “who voted for what” because the gossip transport wraps every message in a signed `MessageEnvelope`, and the proposal also carries `proposer_peer_id`.

Concrete checks:
- transport-level authenticity: `MessageEnvelope.signature` is verified for `sender_peer_id`
  - code: `igra-core/src/infrastructure/transport/iroh/filtering.rs`
- proposal identity binding: `proposal.proposer_peer_id == sender_peer_id`
  - code: `igra-service/src/service/coordination/two_phase_handler.rs`

### 3.2 Signatures (Phase 2 / CRDT)

- Phase 2 signatures are partial Schnorr signatures inserted into CRDT state.
- Today we do not cryptographically verify each incoming partial signature at merge-time; we rely on correctness at signing time and eventual failure at finalize/submit if signatures are invalid.

---

## 4. Proposed change: “signed-hash record”

### 4.1 Where to store the record

Store it as a separate durable per-event record in storage (not inside `EventPhaseState`), to avoid changing the binary encoding of phase state.

- RocksDB column family: `CF_EVENT_SIGNED_HASH` (`"event_signed_hash"`)
- key: `evt_signed_hash:{event_id}`
- value: raw `Hash32` bytes (`tx_template_hash`)

This avoids forward-compatibility issues with bincode-encoded structs while keeping the rule durable across restarts.

### 4.2 Storage API: set-once operation

Extend `PhaseStorage` with a single, focused method:

```rust
pub enum RecordSignedHashResult {
    Set,
    AlreadySame,
    Conflict { existing: Hash32, attempted: Hash32 },
}

fn record_signed_hash(
    &self,
    event_id: &Hash32,
    tx_template_hash: Hash32,
    now_ns: u64,
) -> Result<RecordSignedHashResult, ThresholdError>;
```

Implement it for:
- RocksDB: `igra-core/src/infrastructure/storage/rocks/engine.rs`
- Memory: `igra-core/src/infrastructure/storage/memory.rs`

Both implementations already have a per-phase lock (`phase_lock` / `lock_inner`), so this can be done atomically.

Also add:
```rust
fn get_signed_hash(&self, event_id: &Hash32) -> Result<Option<Hash32>, ThresholdError>;
```
to pre-check conflicts without “setting” the record before we actually sign.

### 4.3 Enforcement point (hard stop)

Enforce the invariant at the only place where we actually sign:

- function: `maybe_sign_and_broadcast`
- file: `igra-service/src/service/coordination/crdt_handler.rs`

Before producing signatures:
- load phase state
- if `signed_hash == Some(existing)` and `existing != state.tx_template_hash`:
  - refuse to sign
  - log a high-severity anomaly including `event_id`, `existing`, `attempted`

After successfully adding signatures to CRDT:
- call `record_signed_hash(event_id, state.tx_template_hash, now)`
  - if result is `Conflict`, treat as a critical invariant violation and stop signing/broadcasting for that event

### 4.4 Optional: commit-time invariant check

Add a defensive check in `try_commit_and_sign`:
- if `signed_hash` exists and differs from the candidate canonical hash, refuse to commit

This should never happen in correct operation, but it makes the system fail safe.

---

## 5. What this guarantees (and what it doesn’t)

### 5.1 Guarantees

- A single signer cannot sign two different templates for the same `event_id`, even if:
  - non-canonical CRDT state arrives later
  - a bug causes `Committed` to be reached incorrectly
  - the process restarts and loses in-memory guards

### 5.2 Does not guarantee committee-level convergence

This per-signer guard does not fix “split committees” by itself.
Committee convergence still depends on:
- committing only when a single `tx_template_hash` has quorum votes (Phase 1 correctness)
- rejecting non-canonical CRDT broadcasts post-commit

If `try_commit_and_sign` commits without requiring a *single-hash* quorum, different partitions could still commit different hashes. The signed-hash record just prevents an individual signer from signing two different ones.

---

## 6. Implementation checklist

- [ ] Add `signed_hash` to `EventPhaseState` (`#[serde(default)]`)
- [ ] Add `RecordSignedHashResult` + `record_signed_hash(...)` to `PhaseStorage`
- [ ] Implement in Rocks + Memory phase storage
- [ ] Enforce in `maybe_sign_and_broadcast` (pre-check + post-record)
- [ ] Optional: add commit-time invariant check in `try_commit_and_sign`
- [ ] Add unit/integration tests:
  - [ ] record is set once
  - [ ] conflict is detected
  - [ ] signing refuses when conflict exists
