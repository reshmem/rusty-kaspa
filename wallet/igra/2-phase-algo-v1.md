# 2-phase-algo-v1.md

End-to-end description of the **two-phase UTXO-consensus signing algorithm (v1)** as it runs in Igra:

- **Phase 1 (Propose/Vote)**: build and gossip *non-committing* proposals for a concrete TX template (PSKT + inputs + outputs).
- **Phase 2 (Commit/Sign/Submit)**: once a canonical template is selected, lock the event to that template and reuse the existing CRDT path to collect signatures and submit the transaction.

This doc is intentionally “execution-level”: it describes the actual data flow between:
**event ingest → local node RPC → gossip → remote signers → signatures → submission**.

---

## 1. Actors and responsibilities

### 1.1 Local signer process

- Ingests events (e.g., from Hyperlane relayer → API/RPC handler).
- Builds local proposals by querying its **own** Kaspa node.
- Gossips proposals and CRDT state.
- Signs and submits once committed and threshold is reached.

Primary entry point: `igra-core/src/application/event_processor.rs` (`submit_signing_event`).

### 1.2 Kaspa node (per signer)

- Maintains the “truth” UTXO set (consensus + mempool view).
- Answers queries like “what UTXOs exist for these addresses” and “what is the current tip score”.

RPC calls used by v1:
- `get_utxos_by_addresses(...)`
- `get_virtual_selected_parent_blue_score()`
- `submit_transaction(...)`

### 1.3 Gossip transport

Transport messages are defined in `igra-core/src/infrastructure/transport/iroh/messages.rs`:
- `TransportMessage::ProposalBroadcast(Proposal)` (Phase 1)
- `TransportMessage::EventStateBroadcast(EventStateBroadcast)` (Phase 2 / CRDT)
- `TransportMessage::{StateSyncRequest, StateSyncResponse}` (anti-entropy for CRDT)

### 1.4 Storage

- `Storage`: persists events and CRDT state.
- `PhaseStorage`: persists phase state and proposals per `(event_id, round)`, and also persists a per-event **signed-hash** record:
  - `get_signed_hash(event_id) -> Option<Hash32>`
  - `record_signed_hash(event_id, tx_template_hash, now) -> RecordSignedHashResult`
  - Purpose: enforce “this signer signs at most one `tx_template_hash` per `event_id`” across restarts.
  - Persistence: RocksDB stores it under column family `event_signed_hash` (`CF_EVENT_SIGNED_HASH`) keyed by `evt_signed_hash:{event_id}`.

---

## 2. Key objects (what we gossip)

### 2.0 Hashes, digests, anchors, and signatures (v1)

This section defines all hashes/digests/anchors used by the algorithm, what they mean, and what is signed/verified at each layer.

#### 2.0.1 Hash and ID glossary

| Name | Type | Definition / Computation | Canonical? | Used for |
|------|------|--------------------------|------------|----------|
| `event.external_id` | `Hash32` | External event identity (e.g., Hyperlane message id, canonicalized by the source normalizer) | Upstream-defined | Part of the canonical `Event` |
| `event_id` | `Hash32` | `blake3("igra:event:v1:" || encode(Event))` | Yes (explicit byte encoding) | Per-event grouping key for proposals/CRDT |
| `payload_hash` | `Hash32` | `blake3(bincode(payload))` with fixed-int encoding | Yes | Transport signature input |
| `envelope.signature` | bytes | Ed25519 signature over `payload_hash` | N/A | Authenticates the sender peer |
| `kpsbt_blob` | `Vec<u8>` | JSON serialization of PSKT `Inner` (signer view) | No (bytes not treated as canonical) | Carries the chosen template to late joiners |
| `tx_template_hash` | `Hash32` | `blake3(borsh(unsigned tx template))` extracted from PSKT | Yes (canonical tx encoding) | Phase-1 voting key and CRDT key component |
| `tx_id` | `Hash32` | Kaspa transaction id for the finalized tx | Consensus-defined | Completion record after submission |
| `signed_hash[event_id]` | `Hash32` | Per-signer persistent record: first `tx_template_hash` we signed for `event_id` | Yes (raw bytes) | Enforced invariant: sign at most one template per event |

Where to find the code:
- `event_id`: `igra-core/src/domain/hashes.rs` (`compute_event_id`)
- `payload_hash`: `igra-core/src/infrastructure/transport/iroh/encoding.rs` (`payload_hash`)
- transport signing/verification: `igra-core/src/infrastructure/transport/iroh/identity.rs`, `igra-core/src/infrastructure/transport/iroh/filtering.rs`
- `tx_template_hash`: `igra-core/src/domain/pskt/multisig.rs` (`tx_template_hash`)

#### 2.0.2 Canonical vs non-canonical (what we rely on)

- `kpsbt_blob` bytes are not used as a consensus identifier. Two different `kpsbt_blob` encodings may still represent the same underlying unsigned tx template.
- We enforce correctness by recomputing `tx_template_hash` from `kpsbt_blob`:
  - deserialize PSKT (`deserialize_pskt_signer`)
  - extract signable tx template
  - serialize template with Borsh
  - hash with BLAKE3

Note: `tx_template_hash` is **not** the Kaspa `tx_id`.
- `tx_template_hash` is a pre-signing identifier for the unsigned template (stable across signers if they converge).
- `tx_id` only exists after finalization and submission of the fully signed transaction.

#### 2.0.3 What is signed/verified, and by which keys

**(A) Transport (gossip) authenticity**
- Signed object: `payload_hash`
- Key: per-peer Ed25519 transport key (`PeerId -> VerifyingKey`)
- Verified in: `igra-core/src/infrastructure/transport/iroh/filtering.rs`
  - Important: the signature covers the payload hash only. Envelope metadata fields (`session_id`, `seq_no`, `timestamp_nanos`) are not part of what is signed; they are used for best-effort replay suppression/rate limiting and must not be treated as consensus-critical.

**(B) Phase-1 votes**
- A “vote” is a `ProposalBroadcast` authenticated by the transport envelope.
- Binding rule: `proposal.proposer_peer_id == envelope.sender_peer_id` (prevents “I claim someone else voted”).

**(C) Origin proofs (Hyperlane / other sources)**
- Verified by `message_verifier.verify(StoredEvent)` against source-specific configured keys/thresholds.
- This is checked on ingest and again when accepting proposals / fast-forward commits.

**(D) Phase-2 transaction signatures**
- Each signer produces per-input Schnorr signatures (stored as CRDT entries).
- We do not verify every incoming partial signature at merge-time; invalid signatures typically surface during finalize/submit.

Quick reference (who signs what):

| Artifact | Produced by | Verified by | Key / trust root |
|----------|-------------|-------------|------------------|
| `MessageEnvelope.signature` | any peer | every peer on receive | Ed25519 transport keys configured per `PeerId` |
| Hyperlane (or other) origin proof inside `StoredEvent.proof` | upstream relayer/source | `message_verifier` | source-specific validator keys/thresholds from config |
| `ProposalBroadcast` vote | proposer peer | receiver peers | envelope signature + `proposer_peer_id == sender_peer_id` binding + `tx_template_hash` recomputation |
| Partial tx signatures in CRDT | each signer | Kaspa (at submit time) | Schnorr signatures over per-input sighash; validity enforced when finalizing/submitting |
| Final transaction acceptance | submitter signer | Kaspa node/consensus | consensus/mempool rules (including script verification and mass/fee policies) |

#### 2.0.4 Anchor model (v1)

v1 does not commit to a global Kaspa block-hash anchor. Instead, it uses a **local** “soft anchor” at commit time:
- `tip_blue_score` from `NodeRpc::get_virtual_selected_parent_blue_score()`
- input `block_daa_score` from each proposed UTXO (`utxos_used[*].entry.block_daa_score`)

Revalidation rule:
`depth = tip_blue_score - block_daa_score >= MIN_INPUT_SCORE_DEPTH`

Code:
- depth check: `igra-core/src/application/two_phase.rs` (`revalidate_utxos_for_proposal`)
- presence check: `igra-service/src/service/coordination/two_phase_handler.rs` (`revalidate_inputs`)

### 2.1 ProposalBroadcast (Phase 1)

Type: `igra-core/src/domain/coordination/proposal.rs` (`pub type ProposalBroadcast = Proposal`)

Fields (high level):
- `event_id`: stable identifier of the signing event
- `round`: retry round (`0..`)
- `tx_template_hash`: hash of the unsigned template (derived from PSKT)
- `kpsbt_blob`: serialized signer-view PSKT for the template
- `utxos_used`: explicit input list (outpoint + utxo entry, includes `block_daa_score`)
- `outputs`: intended outputs (recipient + amount, plus change where applicable)
- `signing_material`: proof-carrying event material used to validate intent
- `proposer_peer_id`: who proposed it

Notes:
- Proposals are not signed “inside the struct”; authenticity comes from the transport envelope signature over `payload_hash` plus the binding check `proposal.proposer_peer_id == envelope.sender_peer_id`.
- Receivers validate a proposal by recomputing `tx_template_hash` from `kpsbt_blob` (not by comparing `kpsbt_blob` bytes).

### 2.2 EventStateBroadcast (Phase 2 / CRDT)

Type: `igra-core/src/infrastructure/transport/iroh/messages.rs`

Fields:
- `event_id`
- `tx_template_hash` (the canonical committed template hash)
- `state`: CRDT payload (`EventCrdtState`) containing signatures, completion record, plus optional `signing_material` and `kpsbt_blob`
- `phase_context`: optional `{ round, phase }` used for fast-forward into committed

Notes:
- `EventStateBroadcast` is also authenticated by the transport envelope signature (same mechanism as proposals).
- There is no separate “commit certificate” message in v1; “commit” is a local state transition plus a CRDT broadcast tagged with `phase_context`.

---

## 3. UTXO subset selection (how the proposal picks inputs)

### 3.1 Data source: local node view

Inputs are selected from UTXOs returned by:
`NodeRpc::get_utxos_by_addresses(service.pskt.source_addresses)`.

Important: **Igra does not “own” the UTXO set**. Each signer observes it via its own Kaspa node, and nodes can temporarily diverge.

### 3.2 Deterministic ordering with a seed

Builder: `igra-core/src/domain/pskt/builder.rs` (`build_pskt_from_utxos`)

If `selection_seed` is present, UTXOs are sorted by:
1. `score(seed, outpoint)` ascending, where `score = blake3(seed || txid || index)`
2. txid lexicographic ascending
3. index ascending

Note: we intentionally avoid an amount-biased secondary sort. Under partial UTXO-view skew, amount bias tends to increase proposal divergence by pulling different “large” UTXOs into the selected prefix.

### 3.3 Seed derivation in two-phase

In `igra-core/src/application/two_phase.rs` (`build_local_proposal_for_round`):
- `selection_seed = blake3(event_id || round)` (32 bytes)

Intent: retries move to a new round, and the new seed changes input ordering, reducing “retry picks the same inputs forever”.

### 3.4 Output construction

Outputs are derived from the verified event data + PSKT policy config:
`igra-core/src/application/event_processor.rs` (`resolve_pskt_config`).

---

## 4. Phase 1 sequence (event → proposal → gossip → proposal storage)

### 4.1 Event ingest (local signer)

File: `igra-core/src/application/event_processor.rs`

1. Normalize input (e.g., Hyperlane) and compute `event_id`.
2. Persist the event (`storage.insert_event(event_id, stored_event)`).
3. Verify the event proof (`message_verifier.verify(&stored_event)`), enforce policy.
4. Enter proposing (idempotent): `phase_storage.try_enter_proposing(event_id, now)`.

If we successfully entered proposing for the event:
5. Build a local proposal for `round=0` (Section 5).
6. Store it in `PhaseStorage`.
7. Gossip it as `TransportMessage::ProposalBroadcast`.

If we are already in `Proposing`:
8. Ensure we have also published our own proposal for the current round (best-effort).

### 4.2 Proposal receive path (remote signer)

File: `igra-service/src/service/coordination/two_phase_handler.rs` (`handle_proposal_broadcast`)

On receiving a proposal from gossip:
1. Envelope identity check: `proposal.proposer_peer_id == sender_peer_id`.
2. Structural validation (`validate_structure`): size/DoS bounds; non-empty inputs/outputs.
3. Hash consistency check (`verify_hash_consistency`): parse PSKT → recompute `tx_template_hash`.
4. Event binding check: `compute_event_id(proposal.signing_material.event) == proposal.event_id`.
5. Proof gating: `message_verifier.verify(stored_event_from_signing_material)` must be valid.
6. Policy enforcement (same policy path as signing).
7. Persist the event (idempotent).
8. Store the proposal in `PhaseStorage`:
   - stored
   - duplicate
   - equivocation (same peer, different hash)
   - round mismatch (stale vs future)

After storing (or observing a duplicate), we attempt commit (Phase 2).

### 4.3 Round adoption (future-round proposal)

If we receive a proposal with `round > expected_round`, we may adopt the higher round:
- `phase_storage.adopt_round_if_behind(event_id, got_round, now)`
- clear stale proposals for earlier rounds
- retry storing the proposal

This is intended to help a lagging node catch up.

---

## 5. Proposal creation (local signer ↔ local node)

File: `igra-core/src/application/two_phase.rs` (`build_local_proposal_for_round`)

Steps:
1. Compute `event_id = compute_event_id(stored_event.event)`.
2. Resolve PSKT config from the event (`resolve_pskt_config`).
3. Query UTXOs from the node (`get_utxos_by_addresses`).
4. Select a UTXO subset deterministically (Section 3) to satisfy `outputs + fee`.
5. Build PSKT, compute:
   - `kpsbt_blob` (serialized signer PSKT)
   - `tx_template_hash` (hash of template)
6. Extract `utxos_used` from PSKT inputs (outpoint + utxo entry).
7. Attach `signing_material` (event + audit + proof).
8. Note on “anchor”: proposal building may query `get_virtual_selected_parent_blue_score()`, but v1 does not commit this value into the proposal; the effective “anchor” is the local node tip score at commit-time revalidation (Section 2.0.4 / 6.2).

Result: `ProposalBroadcast`.

---

## 6. Phase 2 sequence (commit → CRDT signing → submission)

### 6.1 Commit decision

File: `igra-service/src/service/coordination/two_phase_handler.rs` (`try_commit_and_sign`)

Preconditions (phase gate):
- local phase is `Proposing`
- local `phase.round == round`

Commit rule (current code):
1. Load all proposals for `(event_id, round)` from `PhaseStorage`.
2. Compute a quorum winner using `quorum_hash(proposals, COMMIT_QUORUM)`:
   - commit only if **one `tx_template_hash`** has `>= COMMIT_QUORUM` distinct proposer votes
3. Select a canonical proposal object among proposals for the winning hash using a deterministic score:
   - `canonical_proposal_score = blake3("igra:two_phase:canonical_proposal:v1:" || event_id || round || proposer_peer_id)`
   - pick the proposal with the lowest score

This avoids committing on “total proposal count” and avoids a fixed priority peer.

### 6.2 Mandatory pre-commit revalidation (UTXO depth + presence)

File: `igra-service/src/service/coordination/two_phase_handler.rs` (`revalidate_inputs`)

If `revalidate_inputs_on_commit` is enabled:
1. Fetch node tip blue score.
2. For each input outpoint, require `depth = tip - utxo.entry.block_daa_score >= MIN_INPUT_SCORE_DEPTH`.
3. Query current UTXO set and ensure every proposed outpoint still exists locally.

If revalidation fails:
- do not commit; for “UTXO missing at commit time” / “UTXO below min depth” failures, mark `Failed` and bump round (other failures simply do not commit and will be retried by the timeout/retry loop).

### 6.3 Lock canonical hash and initialize CRDT

On commit:
1. `phase_storage.mark_committed(event_id, round, canonical_hash, now)`
2. `storage.set_event_active_template_hash(event_id, canonical_hash)`
3. Initialize CRDT state by merging an empty state plus the canonical proposal’s `signing_material` + `kpsbt_blob`.
4. Broadcast `EventStateBroadcast` with:
   - `state.signing_material = Some(...)`
   - `state.kpsbt_blob = Some(...)`
   - `phase_context = Some({ round, phase: Committed })`

This makes the “chosen template” reproducible and signable for late joiners without rebuilding from local RPC state.

Notes:
- The commit transition itself is not a separately signed certificate in v1.
- The “commit signal” is the envelope-signed `EventStateBroadcast` that includes the canonical `tx_template_hash` and the canonical `kpsbt_blob`/`signing_material`.

### 6.4 CRDT signing

File: `igra-service/src/service/coordination/crdt_handler.rs` (`maybe_sign_and_broadcast`)

On `(event_id, canonical_hash)` CRDT state:
1. Verify source proof + policy.
2. Parse `kpsbt_blob`, recompute `tx_template_hash`, ensure it matches CRDT key.
3. Enforce **single-sign per event_id**:
   - if `phase_storage.get_signed_hash(event_id) == Some(other_hash)` and `other_hash != canonical_hash`, refuse to sign (`ThresholdError::SignedHashConflict`)
4. Create partial signatures for each input and add them to CRDT.
5. Record the signed hash:
   - `phase_storage.record_signed_hash(event_id, canonical_hash, now)`
   - on conflict, fail with `ThresholdError::SignedHashConflict`
6. Broadcast updated CRDT state.

### 6.5 Threshold reached → submit transaction

File: `igra-service/src/service/coordination/crdt_handler.rs` (`maybe_submit_and_broadcast`)

When CRDT has at least M partial signatures per input:
1. Apply partial signatures to PSKT.
2. Finalize and submit transaction via RPC.
3. Record completion in CRDT and broadcast completion.
4. Receivers mark phase `Completed`.

---

## 7. Timeouts, retries, and abandon (v1 liveness model)

File: `igra-service/src/service/coordination/two_phase_timeout.rs`

Tick loop (1s):
- For `Proposing` events:
  - if timeout expired: last attempt to commit
  - if still not committed: mark `Failed`, bump `round`, clear stale proposals
  - after `max_retries`: mark `Abandoned`
- For `Failed` events:
  - after backoff+jitter: rebuild proposal for current round and gossip

v1 liveness semantics:
- **No commit on timeout without quorum**: retries are explicit; failure becomes `Abandoned` instead of silent deadlock.

---

## 8. What happens to the “UTXO set cleanup” across signers?

Key point: **no signer “cleans up” the global UTXO set**. The only thing that changes the UTXO set is:
- a transaction entering a node’s mempool, and/or
- confirmation on chain.

So if signer-1 proposed inputs `{U8,U9}`:
- signer-1’s node will keep reporting `{U8,U9}` as UTXOs until it sees a spend (in mempool or confirmed).
- other signers’ nodes may see the spend earlier/later (mempool propagation differences).

Two-phase does not assume synchronized “UTXO disappearance”. It instead:
- converges on a **single canonical PSKT** (template)
- makes pre-commit checks mandatory to reduce reorg/mempool divergence impact
- relies on Kaspa consensus to ultimately mark inputs as spent.

---

## 9. Anti-entropy and state synchronization

File: `igra-service/src/service/coordination/crdt_handler.rs`

### 9.1 Anti-entropy loop

A background task runs every 5 seconds (`run_anti_entropy_loop`):

```
1. List all pending (non-completed) CRDT states
2. For each pending state:
   - Broadcast local CRDT state (signatures, completion status)
3. Collect unique event_ids from pending states
4. Publish StateSyncRequest with those event_ids
```

This ensures:
- Peers that missed broadcasts eventually receive state
- Lagging nodes can request missing data

### 9.2 State sync request/response

**StateSyncRequest:**
- Contains list of `event_ids` the requester wants state for
- Bounded to `MAX_EVENTS_PER_REQUEST = 256`

**StateSyncResponse handler** (`handle_state_sync_response`):

For each `(event_id, tx_template_hash, incoming_state)`:
1. If not yet committed and response contains valid `signing_material` + `kpsbt_blob`:
   - Validate the commit candidate (proof, policy, hash consistency)
   - Fast-forward to `Committed` phase
2. If already committed with matching canonical hash:
   - Merge incoming CRDT state
   - Sign if not already signed
   - Submit if threshold reached

### 9.3 Fast-forward to Committed via phase context

File: `igra-service/src/service/coordination/crdt_handler.rs` (`handle_crdt_broadcast`)

When receiving `EventStateBroadcast` with `phase_context.phase == Committed`:

```rust
// A node that missed Proposing can skip directly to Committed
if let Some(ctx) = broadcast.phase_context {
    match ctx.phase {
        EventPhase::Committed | EventPhase::Completed => {
            // 1. Validate signing_material + kpsbt_blob
            validate_commit_candidate(...)?;

            // 2. Set active template hash
            storage.set_event_active_template_hash(&event_id, &tx_template_hash)?;

            // 3. Mark committed directly
            phase_storage.mark_committed(&event_id, ctx.round, tx_template_hash, now)?;

            // 4. If phase is Completed, also mark completed
            if ctx.phase == EventPhase::Completed {
                phase_storage.mark_completed(&event_id, now)?;
            }
        }
    }
}
```

This allows late-joining or restarted nodes to catch up without replaying the entire Proposing phase.

Dominance rule (v1): **a valid `Committed` / `Completed` broadcast overrides local `Proposing` / `Failed` state regardless of the local round**. Once committed, pre-commit CRDT broadcasts are ignored and only the canonical `(event_id, tx_template_hash)` CRDT key is merged.

---

## 10. Storage mass validation (KIP-0009)

File: `igra-core/src/domain/pskt/builder.rs`

### 10.1 Mass calculation during UTXO selection

The UTXO selection loop validates storage mass against network limits:

```rust
for utxo in utxos {
    selected.push(utxo);

    // Try to apply fee policy
    match apply_fee_policy_with_auto_fee(...) {
        Ok(()) => {
            // Compute storage mass for this candidate
            let storage_mass = calc_storage_mass_for_candidate(&selected, &outputs)?;

            // Check against standard limit
            if storage_mass > MAXIMUM_STANDARD_TRANSACTION_MASS {
                continue; // Need more/different UTXOs
            }

            // Success - we have a valid selection
            break;
        }
        Err(InsufficientUTXOs) => continue,
        Err(err) => return Err(err),
    }
}
```

### 10.2 Why this matters

Kaspa's KIP-0009 introduces storage mass to prevent UTXO set bloat:
- Transactions that create many small outputs have high storage mass
- Transactions that consolidate UTXOs have lower (or zero) storage mass
- If `storage_mass > MAXIMUM_STANDARD_TRANSACTION_MASS`, the transaction is non-standard

The selection loop continues adding UTXOs until both:
1. Output amounts + fees are covered
2. Storage mass is within limits

If neither can be satisfied with available UTXOs, the proposal fails.

---

## 11. Fee calculation modes

File: `igra-core/src/domain/pskt/builder.rs`

### 11.1 Auto-fee calculation

If `fee_sompi` is `None` or `0`, fee is calculated automatically:

```rust
// Fixed-point iteration (up to 4 rounds)
for _ in 0..4 {
    // 1. Apply current fee estimate to outputs
    apply_fee_policy_for_fee(params, total_input, outputs, fee)?;

    // 2. Compute mass for this configuration
    let compute_mass = estimate_compute_mass_for_signed_tx(...);

    // 3. Calculate minimum relay fee from mass
    // Default: 1000 sompi per kg (matches kaspad)
    let min_fee = (compute_mass * 1000) / 1000;

    // 4. Converge when fee stabilizes
    if min_fee == fee { break; }
    fee = min_fee;
}
```

### 11.2 Fee payment modes

Type: `igra-core/src/domain/mod.rs` (`FeePaymentMode`)

| Mode | Behavior |
|------|----------|
| `RecipientPays` | Fee deducted from first output (recipient amount reduced) |
| `SignersPay` | Fee paid from change (recipient gets full amount) |
| `Split { recipient_parts, signer_parts }` | Fee split proportionally between recipient and signers |

Example with 1000 sompi fee and `Split { recipient_parts: 1, signer_parts: 1 }`:
- Recipient pays: 500 sompi
- Signers pay (via reduced change): 500 sompi

---

## 12. Deterministic jitter for retry timing

File: `igra-service/src/service/coordination/two_phase_timeout.rs`

### 12.1 Why deterministic jitter?

When multiple signers retry simultaneously, they might repeatedly collide. Jitter spreads retries over time, but must be deterministic to avoid non-determinism in testing/debugging.

### 12.2 Jitter calculation

```rust
fn jittered_delay_ms(
    two_phase: &TwoPhaseConfig,
    event_id: &Hash32,
    local_peer_id: &PeerId,
    retry_count: u32,
) -> u64 {
    // Base delay with exponential backoff
    let base = two_phase.retry.delay_for_retry(retry_count);
    // delay = base_delay_ms * backoff_multiplier^(retry-1)
    // capped at max_delay_ms

    // Deterministic jitter from hash
    let digest = blake3(event_id || peer_id || retry_count);
    let rnd = u64::from_le_bytes(digest[0..8]);

    // Jitter range: [-jitter_ms, +jitter_ms]
    let span = jitter_ms * 2 + 1;
    let offset = (rnd % span) as i64 - jitter_ms as i64;

    base + offset
}
```

### 12.3 Default configuration

```rust
RetryConfig {
    max_retries: 3,
    base_delay_ms: 5_000,      // 5 seconds
    max_delay_ms: 30_000,      // 30 seconds cap
    backoff_multiplier: 2.0,   // Exponential
    jitter_ms: 250,            // ±250ms jitter
}
```

Retry delays: ~5s, ~10s, ~20s (plus jitter), then abandon.

---

## 13. Equivocation detection and handling

File: `igra-service/src/service/coordination/two_phase_handler.rs`

### 13.1 What is equivocation?

A peer broadcasts two different `tx_template_hash` values for the same `(event_id, round)`. This could indicate:
- Bug in the peer's implementation
- Malicious behavior (trying to cause divergence)
- Network partition causing state confusion

### 13.2 Detection

```rust
// In PhaseStorage::store_proposal()
match phase_storage.store_proposal(&proposal)? {
    StoreProposalResult::Equivocation { existing_hash, new_hash } => {
        warn!(
            "equivocation detected event_id={} proposer_peer_id={} \
             existing_hash={} new_hash={}",
            hex::encode(proposal.event_id),
            proposal.proposer_peer_id,
            hex::encode(existing_hash),
            hex::encode(new_hash)
        );
        // Currently: logged but proposal is rejected
    }
}
```

### 13.3 Current handling (v1)

- **Logged** for operational visibility
- **Rejected** (second proposal not stored)
- **No penalty/slashing** in current implementation

Future versions may implement:
- Peer reputation scoring
- Temporary ban for repeated equivocation
- Evidence publication for external slashing

---

## 14. Local proposal on receive

File: `igra-service/src/service/coordination/two_phase_handler.rs`

### 14.1 Ensuring participation

After receiving and storing a remote proposal, the handler ensures the local node also participates:

```rust
// Called after storing a received proposal
publish_local_proposal_if_missing(
    app_config, flow, transport, storage, phase_storage,
    local_peer_id, event_id, round
).await?;
```

### 14.2 Logic

```rust
async fn publish_local_proposal_if_missing(...) -> Result<(), ThresholdError> {
    // Skip if terminal or already committed
    if phase.phase.is_terminal() || phase.phase == EventPhase::Committed {
        return Ok(());
    }

    // Skip if we already have a proposal for this round
    if phase_storage.has_proposal_from(&event_id, round, local_peer_id)? {
        return Ok(());
    }

    // Build and publish our own proposal
    let (proposal, _anchor) = build_local_proposal_for_round(
        rpc, service_config, &event, local_peer_id, round, now_ns
    ).await?;

    phase_storage.store_proposal(&proposal)?;
    phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
    transport.publish_proposal(proposal).await?;
}
```

### 14.3 Why this matters

A node might receive a proposal before ingesting the event itself (e.g., gossip arrives before API call). This ensures:
- The node contributes to quorum
- Commit can proceed even if the node didn't initiate

---

## 15. Phase state machine

### 15.1 States

```rust
pub enum EventPhase {
    Unknown = 0,    // Initial state
    Proposing = 1,  // Phase 1: collecting proposals
    Committed = 2,  // Phase 2: canonical hash locked, signing
    Completed = 3,  // Terminal: TX submitted successfully
    Failed = 4,     // Transient: timeout/error, will retry
    Abandoned = 5,  // Terminal: max retries exceeded
}
```

### 15.2 Valid transitions

```
Unknown ──────────────────────────────┐
    │                                 │
    ▼                                 │
Proposing ◄───────────────────────────┤ (fast-forward)
    │                                 │
    ├──────────► Committed ───────────┘
    │                │
    │                ▼
    │            Completed (terminal)
    │
    ▼
Failed ◄──────────┐
    │             │
    ├─────────────┘ (retry → Proposing)
    │
    ▼
Abandoned (terminal)
```

### 15.3 Transition rules

```rust
impl EventPhase {
    pub fn can_transition_to(self, target: EventPhase) -> bool {
        matches!(
            (self, target),
            (Unknown, Proposing)
                | (Unknown, Committed)      // Fast-forward from sync
                | (Proposing, Committed)
                | (Proposing, Failed)
                | (Committed, Completed)
                | (Failed, Committed)       // Fast-forward during retry
                | (Failed, Proposing)       // Retry
                | (Failed, Abandoned)       // Max retries
        )
    }
}
```

---

## 16. Sequence diagram (comprehensive)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         2-PHASE PROTOCOL FLOW                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐    ┌───────────────────────────────────────────────────┐ │
│  │  EVENT   │    │               PHASE 1: PROPOSING                  │ │
│  │ TRIGGER  │───▶│  1. Validate proof (Hyperlane/LZ)                 │ │
│  │ (API/HL) │    │  2. Enforce policy (volume, amount limits)        │ │
│  └──────────┘    │  3. Seed = blake3(event_id || round)              │ │
│                  │  4. Select UTXOs (seeded deterministic)            │ │
│                  │  5. Validate storage mass (KIP-0009)               │ │
│                  │  6. Build PSKT, compute tx_template_hash           │ │
│                  │  7. Broadcast proposal to group                    │ │
│                  └───────────────────────────────────────────────────┘ │
│                                      │                                  │
│                                      ▼                                  │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                    PROPOSAL COLLECTION                            │ │
│  │  • Validate: identity, structure, hash, proof, policy             │ │
│  │  • Store proposals from all peers                                 │ │
│  │  • Detect equivocation (same peer, different hash) → reject       │ │
│  │  • Handle round mismatch (adopt higher round if behind)           │ │
│  │  • Publish own proposal if missing for current round              │ │
│  │  • Wait for one tx_template_hash with ≥ commit_quorum votes       │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                      │                                  │
│           quorum reached?            │                                  │
│        ┌────────┴────────┐           │                                  │
│        │ NO              │ YES       │                                  │
│        ▼                 ▼           │                                  │
│  ┌──────────┐    ┌───────────────────────────────────────────────────┐ │
│  │ TIMEOUT  │    │               PHASE 2: COMMIT                     │ │
│  │ (5 sec)  │    │  1. Select canonical_hash via quorum_hash()       │ │
│  │          │    │     (tie-break: canonical_proposal_score)         │ │
│  └────┬─────┘    │  2. Revalidate UTXOs:                             │ │
│       │          │     - Depth >= min_input_score_depth (300)        │ │
│       │          │     - Still exists in local UTXO set              │ │
│       │          │  3. mark_committed()                              │ │
│       │          │  4. set_event_active_template_hash()              │ │
│       │          │  5. Initialize CRDT with canonical PSKT           │ │
│       │          │  6. Broadcast Committed state (with phase_context)│ │
│       ▼          └───────────────────────────────────────────────────┘ │
│  ┌──────────┐                        │                                  │
│  │  FAILED  │                        │                                  │
│  │ + retry  │                        ▼                                  │
│  │  count++ │    ┌───────────────────────────────────────────────────┐ │
│  └────┬─────┘    │                    SIGN                           │ │
│       │          │  1. Verify proof + policy (again)                 │ │
│       │          │  2. Deserialize canonical PSKT                    │ │
│  retry < max?    │  3. Verify tx_template_hash matches               │ │
│  ┌────┴────┐     │  4. Sign all inputs with local keypair            │ │
│  │YES     │NO    │  5. Enforce signed_hash(event_id) invariant       │ │
│  │        │      │  6. Store partial_sigs in CRDT                    │ │
│  │        │      │  7. Record signed_hash(event_id) = tx_template    │ │
│  │        │      │  8. Broadcast CRDT state                          │ │
│  ▼        ▼      └───────────────────────────────────────────────────┘ │
│ RETRY  ABANDON                       │                                  │
│ (new    (terminal)       threshold reached (M of N)?                    │
│ round)              ┌────────────────┴────────────────┐                │
│   │                 │ NO                              │ YES             │
│   │                 ▼                                 ▼                 │
│   │           ┌───────────┐   ┌───────────────────────────────────────┐│
│   │           │   WAIT    │   │          PHASE 3: SUBMIT              ││
│   │           │  (CRDT    │   │  1. apply_partial_sigs() to PSKT      ││
│   │           │   sync    │   │  2. finalize_multisig(M of N)         ││
│   │           │   every   │   │     - Select M sigs in pubkey order   ││
│   │           │   5 sec)  │   │  3. extract_tx()                      ││
│   │           └───────────┘   │  4. rpc.submit_transaction()          ││
│   │                           │     - Retry up to 4x with backoff     ││
│   │                           │     - Idempotent (duplicate = success)││
│   │                           │  5. mark_crdt_completed()             ││
│   │                           │  6. Broadcast completion              ││
│   │                           └───────────────────────────────────────┘│
│   │                                              │                      │
│   │                                              ▼                      │
│   │    ┌─────────────────────────────────────────────────────────────┐ │
│   │    │                    ANTI-ENTROPY                             │ │
│   │    │  • Runs every 5 seconds                                     │ │
│   │    │  • Broadcasts all pending CRDT states                       │ │
│   │    │  • Requests sync for missing events                         │ │
│   │    │  • Enables late-joiners to fast-forward to Committed        │ │
│   │    └─────────────────────────────────────────────────────────────┘ │
│   │                                              │                      │
│   │                                              ▼                      │
│   │                                       ┌───────────┐                 │
│   └──────────────────────────────────────▶│ COMPLETED │                 │
│                                           │ (terminal)│                 │
│                                           └───────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 17. Configuration reference

### 17.1 TwoPhaseConfig

File: `igra-core/src/domain/coordination/config.rs`

```rust
TwoPhaseConfig {
    proposal_timeout_ms: 5_000,        // Time to collect proposals
    commit_quorum: 0,                  // 0 = derive from group.threshold_m
    min_input_score_depth: 300,        // Min DAA score depth for UTXOs
    revalidate_inputs_on_commit: true, // Re-check UTXOs before commit
    retry: RetryConfig {
        max_retries: 3,
        base_delay_ms: 5_000,
        max_delay_ms: 30_000,
        backoff_multiplier: 2.0,
        jitter_ms: 250,
    },
}
```

### 17.2 PSKT limits

File: `igra-core/src/foundation/constants.rs` and `igra-core/src/domain/coordination/config.rs`

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_PSKT_INPUTS` | 100 | Max UTXOs per transaction |
| `MAX_UTXOS_PER_PROPOSAL` | 100 | Proposal validation limit |
| `MAX_OUTPUTS_PER_PROPOSAL` | 16 | Proposal validation limit |
| `MAX_KPSBT_SIZE` | 64 KB | Serialized PSKT size limit |
| `MAXIMUM_STANDARD_TRANSACTION_MASS` | (network) | KIP-0009 storage mass limit |

### 17.3 Timing constants

| Constant | Value | Location |
|----------|-------|----------|
| `TICK_INTERVAL` | 1 sec | `two_phase_timeout.rs` |
| `ANTI_ENTROPY_INTERVAL` | 5 sec | `crdt_handler.rs` |
| `TERMINAL_PHASE_TTL_NS` | 1 hour | `two_phase_timeout.rs` (GC) |
| `DEFAULT_MIN_INPUT_SCORE_DEPTH` | 300 | `config.rs` |

---

## 18. Known limitations and future work

### 18.1 No slashing for equivocation

Equivocation is detected and logged but has no economic penalty. For high-value deployments, consider:
- Publishing equivocation evidence
- Integration with external slashing mechanisms

### 18.2 No per-partial-signature verification on receive

We do not cryptographically verify each incoming partial signature at merge-time. Invalid signatures will typically surface during finalize/submit (RPC reject) rather than being filtered immediately.

### 18.3 Proposal anti-entropy is “rebroadcast own proposal”

Anti-entropy sync (`StateSyncRequest/Response`) is for CRDT state. For Phase 1 proposals we run a lightweight anti-entropy loop that periodically rebroadcasts **our own** `ProposalBroadcast` while an event is in `Proposing`.

This improves liveness under message loss / late joiners without requiring relays (we only rebroadcast proposals where `proposer_peer_id == local_peer_id`).

### 18.4 Submission retry is best-effort

If submission fails after threshold is reached (e.g., transient RPC/network error), the system relies on:
- retry logic in the submission path
- anti-entropy rebroadcast for CRDT state
- idempotent submission handling
