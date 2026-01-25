# Two-Phase Coordination Algorithm - Current Implementation

**Version**: 1.0
**Generated from codebase scan**: 2026-01-16
**Source**: `igra-core` and `igra-service` crates

---

## Part 1: High-Level Pseudo-Code Algorithm

### 1.1 Overview

The Two-Phase Coordination Protocol enables **leaderless consensus** among N threshold signers to construct and submit a single valid multisig transaction without a central coordinator.

### 1.2 Core Problem

Given:
- N signers (e.g., 3 signers in a 2-of-3 multisig)
- Each signer independently observes the same signing event
- UTXOs are shared and can only be spent once
- No central coordinator

Achieve:
- All signers agree on the **same UTXO selection** (deterministic)
- All signers agree on the **same transaction template** (canonical hash)
- Exactly **one valid transaction** is submitted to the network
- System tolerates network partitions and message delays

### 1.3 Why It Works: Key Invariants

1. **Deterministic UTXO Selection**: Given the same `event_id` and UTXO set, all signers compute identical UTXO selection using seeded PRNG (blake3 hash of event_id).

2. **Canonical Proposal Selection**: When multiple proposals exist, all honest signers select the same one via deterministic scoring (vote count → tx_template_hash → proposer_peer_id → blake3 hash).

3. **Signed-Hash Invariant**: Once a signer signs a `tx_template_hash`, they never sign a different hash for the same `event_id`.

4. **CRDT Convergence**: Signature sets are grow-only (GSet), ensuring all signers eventually see all signatures regardless of message ordering.

5. **Quorum Commit**: Phase transitions require explicit quorum agreement, preventing premature commitment.

### 1.4 Pseudo-Code Algorithm

```
ALGORITHM TwoPhaseCoordination(event_id, destination, amount):

    // ═══════════════════════════════════════════════════════════════
    // PHASE 1: PROPOSING
    // ═══════════════════════════════════════════════════════════════

    1. ON EVENT_TRIGGER(event_id):
        a. Verify event not already processed
        b. Store event with phase = Proposing, round = 0
        c. GOTO PROPOSE_ROUND(0)

    2. PROPOSE_ROUND(round):
        a. Fetch available UTXOs from RPC
        b. Select UTXOs deterministically:
           - Sort UTXOs by (tx_id, output_index)
           - Seed PRNG with blake3(event_id)
           - Shuffle using seeded Fisher-Yates
           - Select greedily until amount + fee covered
        c. Build PSKT transaction template
        d. Compute tx_template_hash = blake3(serialized_pskt)
        e. Create proposal = {round, tx_template_hash, input_outpoints, timestamp}
        f. Store as local_proposal
        g. Broadcast ProposalBroadcast message to peers
        h. Start commit_timeout timer

    3. ON RECEIVE ProposalBroadcast(peer_id, proposal):
        a. Validate proposal format and signatures
        b. Store in proposals_by_peer[peer_id]
        c. Check if local proposal exists for this round:
           - If NO: Build own proposal for this round, store and broadcast
        d. GOTO TRY_COMMIT()

    4. TRY_COMMIT():
        a. Get all proposals for current round
        b. Count votes per tx_template_hash
        c. If any hash has >= commit_quorum votes:
           - Select winning hash via deterministic scoring:
             1. Higher vote count wins
             2. Numerically-lower tx_template_hash breaks ties
             3. Lowest proposer_peer_id breaks further ties
           - canonical = proposal with winning hash (using blake3 score)
           - If local proposal matches canonical:
               GOTO COMMIT(canonical.tx_template_hash)
           - Else:
               Increment round, GOTO PROPOSE_ROUND(round + 1)

    5. ON TIMEOUT commit_timeout:
        a. If still in Proposing phase:
           - Increment round
           - GOTO PROPOSE_ROUND(round + 1)

    // ═══════════════════════════════════════════════════════════════
    // PHASE 2: COMMITTED (Signing)
    // ═══════════════════════════════════════════════════════════════

    6. COMMIT(tx_template_hash):
        a. Transition phase: Proposing → Committed
        b. Store committed tx_template_hash (immutable)
        c. Rebuild PSKT from stored proposal
        d. Sign all inputs with local private key
        e. Create signature_records for each input
        f. Store signatures in CRDT
        g. Broadcast CrdtSync message with signatures

    7. ON RECEIVE CrdtSync(peer_id, crdt_state):
        a. Merge remote CRDT into local CRDT
        b. Check signature threshold:
           - For each input: count unique pubkeys with valid signatures
           - If ALL inputs have >= required_sigs signatures:
               GOTO SUBMIT()

    8. SUBMIT():
        a. Finalize PSKT with collected signatures
        b. Extract raw transaction
        c. Submit to Kaspa node via RPC
        d. On success:
           - Record completion (tx_id, submitter, timestamp)
           - Transition phase: Committed → Completed
           - Broadcast completion to peers
        e. On failure:
           - If UTXO spent (double-spend): Mark as Failed
           - Else: Retry with backoff

    // ═══════════════════════════════════════════════════════════════
    // ANTI-ENTROPY (Background)
    // ═══════════════════════════════════════════════════════════════

    9. EVERY sync_interval (5 seconds):
        a. For each active event:
           - Broadcast current CRDT state
           - Broadcast current phase state
        b. Merge any received states
```

### 1.5 State Machine Diagram

```
                                    ┌─────────────────────────────────────────┐
                                    │           EVENT TRIGGER                  │
                                    │  (API request / Watcher notification)    │
                                    └─────────────────┬───────────────────────┘
                                                      │
                                                      ▼
                              ┌────────────────────────────────────────────────┐
                              │                  PROPOSING                      │
                              │  ┌─────────────────────────────────────────┐   │
                              │  │ Round 0:                                │   │
                              │  │  • Fetch UTXOs                          │   │
                              │  │  • Deterministic selection (seeded)     │   │
                              │  │  • Build PSKT template                  │   │
                              │  │  • Broadcast proposal                   │   │
                              │  └─────────────────────────────────────────┘   │
                              │                      │                          │
                              │    ┌─────────────────┼─────────────────┐       │
                              │    │                 │                 │       │
                              │    ▼                 ▼                 ▼       │
                              │  Timeout      Quorum reached     Proposal      │
                              │    │          (commit_quorum)    mismatch      │
                              │    │                 │                 │       │
                              │    │     ┌───────────┴───────────┐     │       │
                              │    │     │                       │     │       │
                              │    │     ▼                       ▼     │       │
                              │    │  Local==Canonical    Local!=Canonical     │
                              │    │     │                       │     │       │
                              │    │     │              ┌────────┘     │       │
                              │    │     │              │              │       │
                              │    └─────┼──────────────┼──────────────┘       │
                              │          │              │                       │
                              │          │              ▼                       │
                              │          │    ┌─────────────────────┐          │
                              │          │    │ Round N+1:          │◄─────────┤
                              │          │    │  • New proposal     │          │
                              │          │    │  • Broadcast        │          │
                              │          │    └─────────────────────┘          │
                              │          │                                      │
                              └──────────┼──────────────────────────────────────┘
                                         │
                                         ▼
                    ┌────────────────────────────────────────────────────┐
                    │                    COMMITTED                        │
                    │  ┌───────────────────────────────────────────────┐ │
                    │  │ Signing Phase:                                │ │
                    │  │  • tx_template_hash is IMMUTABLE              │ │
                    │  │  • Sign all inputs locally                    │ │
                    │  │  • Broadcast signatures via CRDT              │ │
                    │  │  • Merge incoming signatures                  │ │
                    │  └───────────────────────────────────────────────┘ │
                    │                        │                            │
                    │    ┌───────────────────┼───────────────────┐       │
                    │    │                   │                   │       │
                    │    ▼                   ▼                   ▼       │
                    │  Threshold         UTXO spent          Timeout    │
                    │  reached           (conflict)          (no sigs)  │
                    │    │                   │                   │       │
                    └────┼───────────────────┼───────────────────┼───────┘
                         │                   │                   │
                         ▼                   ▼                   ▼
              ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐
              │    COMPLETED     │  │     FAILED       │  │   ABANDONED  │
              │                  │  │                  │  │              │
              │ • TX submitted   │  │ • UTXO conflict  │  │ • Max rounds │
              │ • Recorded       │  │ • Unrecoverable  │  │ • No quorum  │
              └──────────────────┘  └──────────────────┘  └──────────────┘
```

### 1.6 Why Each Step Is Necessary

| Step | Purpose | What Happens Without It |
|------|---------|------------------------|
| Deterministic UTXO selection | All signers pick same UTXOs | Different transactions, signatures don't combine |
| Seeded shuffle | Fairness + determinism | Predictable selection, potential gaming |
| Commit quorum | Prevent premature signing | Signers sign different hashes, wasted work |
| Canonical proposal scoring | Single winner when proposals differ | Deadlock, no agreement |
| Signed-hash invariant | Prevent equivocation | Double-signing, potential fund loss |
| CRDT merge | Tolerate message reordering | Lost signatures, threshold never reached |
| Anti-entropy sync | Handle network partitions | Isolated nodes never complete |
| Round increment on mismatch | Progress despite UTXO churn | Infinite retry on stale UTXOs |

---

## Part 2: Detailed Implementation with Code References

> **Note**: Line numbers reference the actual source files. Function bodies shown below are
> **simplified representations** of the actual logic - consult the source files for complete
> implementations including error handling, logging, and edge cases.

### 2.1 Data Structures

#### EventPhase Enum
**File**: `igra-core/src/domain/coordination/phase.rs:6-14`
```rust
pub enum EventPhase {
    Unknown = 0,
    Proposing = 1,
    Committed = 2,
    Completed = 3,
    Failed = 4,
    Abandoned = 5,
}
```

#### EventPhaseState
**File**: `igra-core/src/domain/coordination/phase.rs:48-56`
```rust
pub struct EventPhaseState {
    pub phase: EventPhase,
    pub phase_started_at_ns: u64,
    pub round: u32,
    pub canonical_hash: Option<Hash32>,
    pub own_proposal_hash: Option<Hash32>,
    pub retry_count: u32,
}
```

#### TwoPhaseConfig
**File**: `igra-core/src/domain/coordination/config.rs:36-42`
```rust
pub struct TwoPhaseConfig {
    pub proposal_timeout_ms: u64,
    pub commit_quorum: u16,
    pub min_input_score_depth: u64,
    pub retry: RetryConfig,
    pub revalidate_inputs_on_commit: bool,
}
```

#### SignatureRecord (CRDT)
**File**: `igra-core/src/domain/crdt/types.rs:27-33`
```rust
pub struct SignatureRecord {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_peer_id: Option<PeerId>,
    pub timestamp_nanos: u64,
}
```

#### EventCrdt
**File**: `igra-core/src/domain/crdt/event_state.rs:14-30`
```rust
pub struct EventCrdt {
    pub event_id: Hash32,
    pub tx_template_hash: Hash32,
    signatures: HashMap<SignatureKey, SignatureRecord>,  // G-Set
    completion: LWWRegister<CompletionInfo>,             // LWW-Register
    version: u64,
}
```

### 2.2 Phase 1: Event Trigger and Proposal Building

#### Step 1: Event Submission
**File**: `igra-core/src/application/event_processor.rs:45-120`

```rust
// Entry point for new signing events
pub fn submit_signing_event(ctx: &EventContext, params: SigningEventParams) -> Result<...> {
    // Line 52-58: Compute event_id from external_id
    let event_id = compute_event_id(&params.event);

    // Line 65-72: Check if event already exists
    if let Some(existing) = ctx.storage.get_event(&event_id)? {
        return Ok(existing);  // Idempotent
    }

    // Line 80-95: Create and store new event
    let event = Event {
        event_id,
        phase: EventPhase::Proposing,
        round: 0,
        ...
    };
    ctx.storage.store_event(&event)?;

    // Line 100-110: Trigger proposal building
    build_and_broadcast_proposal(ctx, &event)?;
}
```

#### Step 2: Build Local Proposal
**File**: `igra-core/src/application/two_phase.rs:9-73`

```rust
pub fn build_local_proposal_for_round(
    config: &ServiceConfig,
    policy: &GroupPolicy,
    two_phase: &TwoPhaseConfig,
    event: &StoredEvent,
    rpc: &dyn RpcClient,
    round: u32,
    local_peer_id: &PeerId,
) -> Result<EventProposal, ThresholdError> {
    // Line 18-25: Fetch UTXOs from RPC
    let utxos = rpc.get_utxos_by_addresses(&config.pskt.source_addresses)?;

    // Line 28-35: Filter by minimum score depth (confirmations)
    let filtered: Vec<_> = utxos
        .into_iter()
        .filter(|u| u.entry.block_daa_score >= two_phase.min_input_score_depth)
        .collect();

    // Line 38-45: Build PSKT with deterministic selection
    let pskt = build_pskt_for_event(
        config,
        &event.event,
        &filtered,
        &event.event_id,  // Used as selection seed
    )?;

    // Line 48-55: Compute tx_template_hash
    let serialized = pskt.serialize_for_hash();
    let tx_template_hash: Hash32 = blake3::hash(&serialized).into();

    // Line 58-68: Extract input outpoints
    let input_outpoints = pskt.inputs()
        .iter()
        .map(|inp| OutpointWire::from(&inp.previous_outpoint))
        .collect();

    // Line 70-73: Return proposal
    Ok(EventProposal {
        round,
        tx_template_hash,
        input_outpoints,
        timestamp_nanos: now_nanos(),
        signer_peer_id: local_peer_id.clone(),
    })
}
```

#### Step 3: Deterministic UTXO Selection
**File**: `igra-core/src/domain/pskt/builder.rs:43-80`

```rust
fn select_utxos_deterministic(
    utxos: &[UtxoWithOutpoint],
    required_amount: u64,
    event_id: &Hash32,
) -> Result<Vec<UtxoWithOutpoint>, ThresholdError> {
    // Line 48-52: Sort UTXOs deterministically
    let mut sorted = utxos.to_vec();
    sorted.sort_by(|a, b| {
        let cmp_tx = a.outpoint.transaction_id.cmp(&b.outpoint.transaction_id);
        cmp_tx.then_with(|| a.outpoint.index.cmp(&b.outpoint.index))
    });

    // Line 55-60: Create seeded RNG from event_id
    let seed = blake3::hash(event_id).as_bytes();
    let mut rng = ChaCha8Rng::from_seed(*seed);

    // Line 63-68: Fisher-Yates shuffle with seeded RNG
    for i in (1..sorted.len()).rev() {
        let j = rng.gen_range(0..=i);
        sorted.swap(i, j);
    }

    // Line 71-80: Greedy selection
    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in sorted {
        selected.push(utxo.clone());
        total += utxo.entry.amount;
        if total >= required_amount {
            break;
        }
    }

    Ok(selected)
}
```

### 2.3 Phase 1: Proposal Reception and Commit Decision

#### Step 4: Handle Incoming Proposal
**File**: `igra-service/src/service/coordination/two_phase_handler.rs:73-325`

```rust
pub async fn handle_proposal_broadcast(
    ctx: &CoordinationContext,
    sender_peer_id: PeerId,
    msg: ProposalBroadcastMessage,
) -> Result<(), ThresholdError> {
    // Line 85-95: Validate message signature
    ctx.message_verifier.verify_proposal(&msg)?;

    // Line 100-115: Load or create phase state
    let mut phase_state = ctx.phase_storage
        .get_phase_state(&msg.event_id)?
        .unwrap_or_else(|| EventPhaseState::new(msg.event_id));

    // Line 120-135: Store peer's proposal
    let proposal = EventProposal {
        round: msg.round,
        tx_template_hash: msg.tx_template_hash,
        input_outpoints: msg.input_outpoints.clone(),
        timestamp_nanos: msg.timestamp_nanos,
        signer_peer_id: sender_peer_id.clone(),
    };
    phase_state.proposals_by_peer.insert(sender_peer_id, proposal);

    // Line 140-165: Build local proposal if we don't have one for this round
    if phase_state.local_proposal.is_none()
       || phase_state.local_proposal.as_ref().unwrap().round < msg.round
    {
        let local = build_local_proposal_for_round(
            &ctx.config,
            &ctx.policy,
            &ctx.two_phase,
            &event,
            ctx.rpc.as_ref(),
            msg.round,
            &ctx.local_peer_id,
        )?;
        phase_state.local_proposal = Some(local.clone());

        // Line 168-180: Broadcast our proposal
        let broadcast_msg = ProposalBroadcastMessage::from(&local, &msg.event_id);
        ctx.transport.broadcast(broadcast_msg).await?;
    }

    // Line 185-200: Check if we can commit
    try_commit_and_sign(ctx, &mut phase_state).await?;

    // Line 205-210: Persist updated state
    ctx.phase_storage.store_phase_state(&phase_state)?;

    Ok(())
}
```

#### Step 5: Canonical Proposal Selection
**File**: `igra-core/src/domain/coordination/selection.rs:24-66`

The selection uses **vote counting** with deterministic tie-breaks:

```rust
// lines 24-43: quorum_hash - finds hash with >= commit_quorum votes
pub fn quorum_hash(proposals: &[Proposal], commit_quorum: usize) -> Option<Hash32> {
    // Count votes per tx_template_hash
    let mut stats_by_hash: HashMap<Hash32, HashVoteStats> = HashMap::new();
    for proposal in proposals {
        let stats = stats_by_hash.entry(proposal.tx_template_hash).or_insert_with(...);
        stats.vote_count += 1;
        // Track lowest proposer_peer_id for tie-breaking
    }

    // Selection priority (line 42):
    // 1. Higher vote count wins
    // 2. Numerically-lower tx_template_hash wins
    // 3. Lowest proposer_peer_id wins
    stats_by_hash.values()
        .filter(|s| s.vote_count >= commit_quorum)
        .min_by_key(|s| s.selection_key())
        .map(|s| s.hash)
}

// lines 45-53: select_canonical_proposal_for_commit
pub fn select_canonical_proposal_for_commit<'a>(
    proposals: &'a [Proposal],
    commit_quorum: usize
) -> Option<&'a Proposal> {
    let winning_hash = quorum_hash(proposals, commit_quorum)?;
    proposals.iter()
        .filter(|p| p.tx_template_hash == winning_hash)
        .min_by_key(|p| canonical_proposal_score(&event_id, p.round, &p.proposer_peer_id))
}

// lines 55-66: canonical_proposal_score - blake3 hash for determinism
fn canonical_proposal_score(event_id: &Hash32, round: u32, proposer_peer_id: &PeerId) -> [u8; 32] {
    const DOMAIN: &[u8] = b"igra:two_phase:canonical_proposal:v1:";
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(event_id);
    hasher.update(&round.to_le_bytes());
    hasher.update(proposer_peer_id.as_str().as_bytes());
    hasher.finalize().into()
}
```

#### Step 6: Try Commit Decision
**File**: `igra-service/src/service/coordination/two_phase_handler.rs:327-421`

```rust
async fn try_commit_and_sign(
    ctx: &CoordinationContext,
    phase_state: &mut EventPhaseState,
) -> Result<(), ThresholdError> {
    // Line 335-345: Only process if in Proposing phase
    if phase_state.phase != EventPhase::Proposing {
        return Ok(());
    }

    // Line 350-365: Collect proposals for current round
    let current_round = phase_state.local_proposal
        .as_ref()
        .map(|p| p.round)
        .unwrap_or(0);

    let round_proposals: Vec<_> = phase_state.proposals_by_peer
        .values()
        .filter(|p| p.round == current_round)
        .collect();

    // Line 370-380: Check quorum
    let proposal_count = round_proposals.len() + 1; // +1 for local
    if proposal_count < ctx.two_phase.commit_quorum {
        return Ok(()); // Not enough proposals yet
    }

    // Line 385-395: Select canonical proposal
    let all_proposals: Vec<_> = round_proposals.iter()
        .chain(phase_state.local_proposal.as_ref().iter())
        .collect();
    let canonical = select_canonical_proposal(&all_proposals)
        .ok_or_else(|| ThresholdError::NoCanonicalProposal)?;

    // Line 400-415: Check if local matches canonical
    let local = phase_state.local_proposal.as_ref().unwrap();
    if local.tx_template_hash == canonical.tx_template_hash {
        // COMMIT: Transition to Committed phase
        phase_state.phase = EventPhase::Committed;
        phase_state.committed_tx_template_hash = Some(canonical.tx_template_hash);

        // Sign and broadcast
        sign_and_broadcast_crdt(ctx, phase_state).await?;
    } else {
        // MISMATCH: Increment round and re-propose
        let next_round = current_round + 1;
        if next_round > ctx.two_phase.max_rounds {
            phase_state.phase = EventPhase::Abandoned;
        } else {
            // Build new proposal for next round
            let new_proposal = build_local_proposal_for_round(
                &ctx.config, &ctx.policy, &ctx.two_phase,
                &event, ctx.rpc.as_ref(), next_round, &ctx.local_peer_id,
            )?;
            phase_state.local_proposal = Some(new_proposal);
            phase_state.round = next_round;
            // Broadcast will happen on next tick
        }
    }

    Ok(())
}
```

### 2.4 Phase 2: Signing and CRDT Aggregation

#### Step 7: Sign Inputs and Broadcast
**File**: `igra-service/src/service/coordination/crdt_handler.rs:500-600`

```rust
pub async fn maybe_sign_and_broadcast(
    ctx: &CoordinationContext,
    event_id: &Hash32,
    crdt: &mut EventCrdt,
) -> Result<(), ThresholdError> {
    // Line 510-520: Load event and phase state
    let event = ctx.storage.get_event(event_id)?
        .ok_or_else(|| ThresholdError::EventNotFound)?;
    let phase_state = ctx.phase_storage.get_phase_state(event_id)?
        .ok_or_else(|| ThresholdError::PhaseStateNotFound)?;

    // Line 525-535: Only sign if Committed
    if phase_state.phase != EventPhase::Committed {
        return Ok(());
    }

    // Line 540-555: Check if already signed
    let committed_hash = phase_state.committed_tx_template_hash
        .ok_or_else(|| ThresholdError::NoCommittedHash)?;
    if crdt.has_local_signatures(&ctx.local_peer_id) {
        return Ok(()); // Already signed
    }

    // Line 560-580: Rebuild PSKT and sign
    let pskt = rebuild_pskt_from_proposal(
        &ctx.config,
        &event,
        &phase_state.local_proposal.unwrap(),
    )?;

    let wallet_secret = load_wallet_secret()?;
    let signed_pskt = sign_pskt_inputs(
        &pskt,
        &ctx.config.service.hd,
        &wallet_secret,
    )?;

    // Line 585-595: Extract signatures and add to CRDT
    for (input_index, input) in signed_pskt.inputs().iter().enumerate() {
        for sig_data in &input.partial_sigs {
            let record = SignatureRecord {
                input_index,
                pubkey: sig_data.pubkey.clone(),
                signature: sig_data.signature.clone(),
                signer_peer_id: Some(ctx.local_peer_id.clone()),
                timestamp_nanos: now_nanos(),
            };
            crdt.add_signature(record);
        }
    }

    // Line 598-600: Broadcast CRDT state
    let sync_msg = CrdtSyncMessage::from(crdt);
    ctx.transport.broadcast(sync_msg).await?;

    Ok(())
}
```

#### Step 8: CRDT Merge on Receive
**File**: `igra-service/src/service/coordination/crdt_handler.rs:300-380`

```rust
pub async fn handle_crdt_sync(
    ctx: &CoordinationContext,
    sender_peer_id: PeerId,
    msg: CrdtSyncMessage,
) -> Result<(), ThresholdError> {
    // Line 310-320: Load local CRDT
    let mut local_crdt = ctx.storage.get_event_crdt(&msg.event_id)?
        .unwrap_or_else(|| EventCrdt::new(msg.event_id, msg.tx_template_hash));

    // Line 325-335: Verify tx_template_hash matches (signed-hash invariant)
    if local_crdt.tx_template_hash != msg.tx_template_hash {
        warn!("CRDT hash mismatch from peer {}", sender_peer_id);
        return Err(ThresholdError::HashMismatch);
    }

    // Line 340-350: Merge remote CRDT into local
    let remote_crdt = EventCrdt::from_wire(&msg)?;
    local_crdt.merge(&remote_crdt);

    // Line 355-365: Persist merged state
    ctx.storage.store_event_crdt(&local_crdt)?;

    // Line 370-380: Check if threshold reached
    maybe_submit_and_broadcast(ctx, &msg.event_id, &mut local_crdt).await?;

    Ok(())
}
```

#### Step 9: CRDT Threshold Check
**File**: `igra-core/src/domain/crdt/event_state.rs:83-96`

```rust
impl EventCrdt {
    /// Check if we have threshold signatures for all inputs.
    pub fn has_threshold(&self, input_count: usize, required: usize) -> bool {
        if input_count == 0 || required == 0 {
            return false;
        }

        let mut per_input: HashMap<u32, HashSet<&[u8]>> = HashMap::new();
        for sig in self.signatures.values() {
            if (sig.input_index as usize) < input_count {
                per_input.entry(sig.input_index).or_default().insert(sig.pubkey.as_slice());
            }
        }

        // All inputs must have >= required unique pubkeys
        (0..input_count as u32).all(|idx| per_input.get(&idx).is_some_and(|set| set.len() >= required))
    }
}
```

### 2.5 Phase 2: Transaction Submission

#### Step 10: Submit Transaction
**File**: `igra-service/src/service/coordination/crdt_handler.rs:602-672`

```rust
pub async fn maybe_submit_and_broadcast(
    ctx: &CoordinationContext,
    event_id: &Hash32,
    crdt: &mut EventCrdt,
) -> Result<(), ThresholdError> {
    // Line 610-620: Check if already completed
    if crdt.is_completed() {
        return Ok(());
    }

    // Line 625-635: Check threshold
    let input_count = /* from stored proposal */;
    let required_sigs = ctx.policy.required_signatures;
    if !crdt.has_threshold(input_count, required_sigs) {
        return Ok(()); // Not enough signatures yet
    }

    // Line 640-655: Rebuild and finalize PSKT
    let event = ctx.storage.get_event(event_id)?.unwrap();
    let phase_state = ctx.phase_storage.get_phase_state(event_id)?.unwrap();

    let pskt = rebuild_pskt_from_proposal(&ctx.config, &event, &phase_state.local_proposal.unwrap())?;
    let finalized = finalize_pskt_with_signatures(&pskt, crdt)?;
    let raw_tx = finalized.extract_transaction()?;

    // Line 658-668: Submit to Kaspa node
    match ctx.rpc.submit_transaction(&raw_tx).await {
        Ok(tx_id) => {
            // Record completion
            let completion = CompletionInfo {
                tx_id,
                submitter_peer_id: ctx.local_peer_id.clone(),
                timestamp_nanos: now_nanos(),
                blue_score: None,
            };
            crdt.set_completed(completion.clone(), now_nanos());
            ctx.storage.store_event_completion(event_id, &completion)?;

            // Broadcast completion
            let msg = CompletionBroadcastMessage::from(&completion, event_id);
            ctx.transport.broadcast(msg).await?;
        }
        Err(e) if is_utxo_spent_error(&e) => {
            // UTXO already spent - mark as failed
            phase_state.phase = EventPhase::Failed;
            ctx.phase_storage.store_phase_state(&phase_state)?;
        }
        Err(e) => {
            // Transient error - will retry on next sync
            warn!("TX submission failed: {}", e);
        }
    }

    Ok(())
}
```

### 2.6 Anti-Entropy Loop

#### Step 11: Background Sync
**File**: `igra-service/src/service/coordination/loop.rs:45-120`

```rust
pub async fn run_coordination_loop(
    config: Arc<AppConfig>,
    two_phase: TwoPhaseConfig,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    phase_storage: Arc<dyn PhaseStorage>,
    local_peer_id: PeerId,
    group_id: Hash32,
) {
    let sync_interval = Duration::from_millis(two_phase.sync_interval_ms);

    loop {
        // Line 60-75: Process incoming messages
        while let Some(msg) = transport.try_recv().await {
            match msg {
                Message::ProposalBroadcast(m) => {
                    handle_proposal_broadcast(&ctx, m.sender, m).await;
                }
                Message::CrdtSync(m) => {
                    handle_crdt_sync(&ctx, m.sender, m).await;
                }
                Message::Completion(m) => {
                    handle_completion(&ctx, m.sender, m).await;
                }
            }
        }

        // Line 80-100: Anti-entropy: broadcast current state for active events
        let active_events = storage.get_active_events()?;
        for event_id in active_events {
            if let Some(crdt) = storage.get_event_crdt(&event_id)? {
                let msg = CrdtSyncMessage::from(&crdt);
                transport.broadcast(msg).await;
            }
            if let Some(phase_state) = phase_storage.get_phase_state(&event_id)? {
                if let Some(proposal) = &phase_state.local_proposal {
                    let msg = ProposalBroadcastMessage::from(proposal, &event_id);
                    transport.broadcast(msg).await;
                }
            }
        }

        // Line 105-115: Check timeouts
        check_and_handle_timeouts(&ctx, &two_phase).await;

        tokio::time::sleep(sync_interval).await;
    }
}
```

### 2.7 Phase Transition Validation

#### Valid Transitions
**File**: `igra-core/src/domain/coordination/phase.rs:17-30`

```rust
impl EventPhase {
    pub fn can_transition_to(self, target: EventPhase) -> bool {
        use EventPhase::*;
        matches!(
            (self, target),
            (Unknown, Proposing)
                | (Unknown, Committed)      // Fast-forward via phase_context
                | (Proposing, Committed)
                | (Proposing, Failed)
                | (Committed, Completed)
                | (Failed, Committed)       // Retry after failure
                | (Failed, Proposing)       // Retry after failure
                | (Failed, Abandoned)       // Give up after max retries
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, EventPhase::Completed | EventPhase::Abandoned)
    }
}
```

### 2.8 Storage Persistence

#### Phase State Storage
**File**: `igra-core/src/infrastructure/storage/phase.rs:25-60`

```rust
pub trait PhaseStorage: Send + Sync {
    fn get_phase_state(&self, event_id: &Hash32) -> Result<Option<EventPhaseState>>;
    fn store_phase_state(&self, state: &EventPhaseState) -> Result<()>;
    fn delete_phase_state(&self, event_id: &Hash32) -> Result<()>;
    fn get_active_phase_states(&self) -> Result<Vec<EventPhaseState>>;
}
```

#### RocksDB Implementation
**File**: `igra-core/src/infrastructure/storage/rocks/engine.rs:180-220`

```rust
impl PhaseStorage for RocksEngine {
    fn store_phase_state(&self, state: &EventPhaseState) -> Result<()> {
        let key = phase_state_key(&state.event_id);
        let value = borsh::to_vec(state)?;
        self.db.put_cf(&self.cf_phase, &key, &value)?;
        Ok(())
    }

    fn get_phase_state(&self, event_id: &Hash32) -> Result<Option<EventPhaseState>> {
        let key = phase_state_key(event_id);
        match self.db.get_cf(&self.cf_phase, &key)? {
            Some(bytes) => Ok(Some(borsh::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }
}
```

---

## Appendix A: Message Types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `ProposalBroadcastMessage` | Multicast | Share local proposal for current round |
| `CrdtSyncMessage` | Multicast | Share signature CRDT state |
| `CompletionBroadcastMessage` | Multicast | Announce successful TX submission |
| `PhaseStateMessage` | Multicast | Share current phase (anti-entropy) |

## Appendix B: Error Handling

| Error Type | Recovery Action |
|------------|-----------------|
| `ThresholdError::UtxoSpent` | Mark event as Failed |
| `ThresholdError::InsufficientFunds` | Wait for more UTXOs, retry |
| `ThresholdError::NetworkTimeout` | Retry on next sync interval |
| `ThresholdError::HashMismatch` | Log and ignore (equivocation) |
| `ThresholdError::MaxRoundsExceeded` | Mark event as Abandoned |

## Appendix C: Configuration Defaults

**File**: `igra-core/src/domain/coordination/config.rs`

**Constants (lines 5-10):**
```rust
pub const MAX_UTXOS_PER_PROPOSAL: usize = 100;
pub const MAX_OUTPUTS_PER_PROPOSAL: usize = 16;
pub const MAX_KPSBT_SIZE: usize = 64 * 1024;
pub const DEFAULT_PROPOSAL_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_MIN_INPUT_SCORE_DEPTH: u64 = 300;
```

**TwoPhaseConfig struct (lines 36-42):**
```rust
pub struct TwoPhaseConfig {
    pub proposal_timeout_ms: u64,
    pub commit_quorum: u16,
    pub min_input_score_depth: u64,
    pub retry: RetryConfig,
    pub revalidate_inputs_on_commit: bool,
}
```

**Default values (lines 44-54):**
- `proposal_timeout_ms`: 5,000ms (from `DEFAULT_PROPOSAL_TIMEOUT_MS`)
- `commit_quorum`: 0 (computed dynamically via `effective()` from `GroupConfig.threshold_m`)
- `min_input_score_depth`: 0 (computed dynamically, defaults to `max(300, group.finality_blue_score_threshold)`)
- `retry`: `RetryConfig::default()` (max_retries=3, base_delay=5s, max_delay=30s, backoff=2.0x, jitter=250ms)
- `revalidate_inputs_on_commit`: true

**RetryConfig defaults (lines 21-25):**
```rust
Self { max_retries: 3, base_delay_ms: 5_000, max_delay_ms: 30_000, backoff_multiplier: 2.0, jitter_ms: 250 }
```
