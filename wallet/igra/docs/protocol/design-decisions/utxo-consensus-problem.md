# UTXO_CONSENSUS_PROBLEM.md

Deep analysis of the UTXO selection consensus problem in leaderless threshold signing.

---

## Executive Summary

The current design has a fundamental tension between **safety** (no double-payment) and **liveness** (events complete). When signers' Kaspa nodes see different UTXO sets, they may build different transactions for the same event. The current "irrevocable lock" design chooses safety over liveness, but can cause events to get stuck permanently.

---

## The Core Problem

### What We Want
- One `event_id` maps to exactly ONE transaction
- All M-of-N signers sign that same transaction
- Transaction confirms, event completes

### What Can Go Wrong
- Signers query their own Kaspa nodes for UTXOs
- Different nodes may see different UTXO sets (sync lag, recent confirmations)
- Different UTXO sets → different transactions → different `tx_template_hash`
- Signers lock to different hashes → signatures split → threshold not met OR multiple TXs confirm

---

## How Current Design Works

### The Irrevocable Lock

```rust
// storage/rocks/engine.rs:328-341
fn set_event_active_template_hash(&self, event_id: &Hash32, tx_template_hash: &Hash32) {
    if let Some(existing) = self.get(event_id) {
        if existing != tx_template_hash {
            return Err(PsktMismatch);  // CANNOT CHANGE
        }
        return Ok(());  // Same hash, idempotent
    }
    self.insert(event_id, tx_template_hash);  // First write wins, PERMANENT
}
```

Once a signer locks `event_id → H1`, they can **never** sign a different hash for that event.

### The Reuse Logic

```rust
// event_processor.rs (RPC path)
if let Some(active_hash) = storage.get_event_active_template_hash(&event_id)? {
    // Already locked - reuse existing TX
    let stored_crdt = storage.get_event_crdt(&event_id, &active_hash)?;
    sign_and_broadcast(stored_crdt.kpsbt_blob);
    return Ok(...);
}

// Not locked yet - build new TX
let tx = build_pskt_from_rpc(...);
storage.set_event_active_template_hash(&event_id, &tx.hash)?;  // LOCK
sign_and_broadcast(tx);
```

### The Gossip Handler

```rust
// crdt_handler.rs:343-364
// Rebuild TX locally and verify hash matches
let our_hash = build_pskt_from_rpc(...).hash;
if our_hash != incoming_hash {
    return Err(PsktMismatch);  // Refuse to sign
}
sign(our_tx);
```

---

## The Race Condition

### Scenario: 2-of-3 Multisig, Simultaneous RPC

```
Time T0: Event E arrives at all signers via local RPC simultaneously
         (before any gossip has propagated)

Time T1: Each signer builds TX independently (different UTXO views)

         Signer-1: UTXOs {A, B} → TX uses {A} → hash = H1
                   set_event_active_template_hash(E, H1) ← LOCKS TO H1
                   signs H1

         Signer-2: UTXOs {B, C} → TX uses {B, C} → hash = H2
                   set_event_active_template_hash(E, H2) ← LOCKS TO H2
                   signs H2

         Signer-3: UTXOs {A, B, C} → TX uses {A} → hash = H1
                   set_event_active_template_hash(E, H1) ← LOCKS TO H1
                   signs H1

Time T2: Gossip propagates (TOO LATE - everyone already locked)

         Signer-1 receives H2 from Signer-2 → REJECTED (locked to H1)
         Signer-2 receives H1 from others → REJECTED (locked to H2)

Result:
  H1: Signer-1 + Signer-3 = 2 signatures → THRESHOLD MET ✓
  H2: Signer-2 = 1 signature → orphaned

  Event completes (got lucky with the split)
```

### Worse Scenario: 2-of-2 Multisig

```
Time T1:
         Signer-1: locks to H1, signs H1
         Signer-2: locks to H2, signs H2

Result:
  H1: 1 signature (needs 2)
  H2: 1 signature (needs 2)

  NO ONE CAN CHANGE THEIR LOCK
  EVENT STUCK FOREVER ✗
```

### Worst Scenario: Different UTXOs, Both Reach Threshold

```
Setup: 2-of-3 multisig
       Wallet UTXOs: {A=500, B=300, C=200}

Time T1:
         Signer-1: builds TX1 using {A} → H1, signs H1
         Signer-2: builds TX2 using {B,C} → H2, signs H2

Time T2: Signer-3 receives both via gossip
         First to arrive wins (say H1)
         Signer-3: locks to H1, signs H1

Result:
  H1: Signer-1 + Signer-3 = 2 sigs → broadcasts → CONFIRMS
  H2: Signer-2 = 1 sig → doesn't reach threshold

  OK in this case. But what if Signer-3 had locked to H2 instead?
```

### Catastrophic Scenario: Double Payment

```
Setup: 3-of-5 multisig
       Wallet UTXOs: {A=500, B=300, C=200, D=400}

Time T1: All 5 signers receive RPC simultaneously, build different TXs

         Signers 1,2,3: build TX1 using {A} → H1
         Signers 4,5: build TX2 using {B,C} → H2

Result:
  H1: 3 signatures → THRESHOLD MET → CONFIRMS ✓
  H2: 2 signatures → not enough (needs 3)

  OK, only one TX confirms.

BUT if split was different:
         Signers 1,2,3: build TX1 using {A} → H1
         Signers 3,4,5: build TX2 using {B,C} → H2
         (Signer-3 somehow signed both - BUG)

Result:
  H1: 3 signatures → CONFIRMS
  H2: 3 signatures → CONFIRMS (different UTXOs!)

  DOUBLE PAYMENT - Event processed twice!
```

---

## Why "Sign Multiple Hashes" Doesn't Work

### Proposed Solution (BROKEN)

> "Just sign all valid tx_template_hashes for an event. Whichever reaches threshold first wins. The others become invalid when UTXOs are spent."

### Why It's Broken

If different TXs use **different UTXOs**, they don't invalidate each other:

```
TX1: inputs {A} → outputs {Alice: 100, change: 399}
TX2: inputs {B, C} → outputs {Alice: 100, change: 399}

Both are valid.
Both can reach threshold.
Both can be broadcast.
Both can CONFIRM (no shared inputs).

Alice receives 200 KAS instead of 100 KAS.
```

### The Constraint

**Each signer must sign AT MOST ONE TX per event_id.**

This is exactly what the irrevocable lock enforces. The problem isn't the lock; it's signers locking to **different** hashes before coordination.

---

## Why "Canonical Hash Selection" Doesn't Work

### Proposed Solution (BROKEN)

> "If you see a smaller hash, switch to it. All signers converge to the smallest hash."

### Why It's Broken

```
Time T1: Signer sees H1 (smallest so far) → signs H1
Time T2: Signer sees H2 < H1 → switches, signs H2
Time T3: Signer sees H3 < H2 → switches, signs H3

Result: Signer has signed H1, H2, AND H3.
        All three could potentially reach threshold.
        Double/triple payment if different UTXOs.
```

**You cannot "unsign"** - signatures are already gossiped to other signers.

---

## The Fundamental Dilemma

| Approach | Safety | Liveness |
|----------|--------|----------|
| Irrevocable lock (current) | ✓ One sig per event | ✗ Can get stuck if locked to different hashes |
| Allow switching | ✗ Multiple sigs per event → double payment | ✓ Can converge |
| Sign all valid hashes | ✗ Multiple TXs confirm | ✓ Something will complete |

**You cannot have both safety and liveness without coordination before signing.**

---

## The Root Cause

The problem is **UTXO selection divergence**:

1. Signers query their own Kaspa nodes
2. Nodes may have different views of confirmed UTXOs
3. Different UTXO sets → different TX inputs → different `tx_template_hash`
4. No pre-signing coordination → signers commit to different TXs

```
         Signer-1's Node          Signer-2's Node
              │                        │
         UTXOs: {A,B,C}           UTXOs: {B,C,D}
              │                        │
         Select: {A}              Select: {B,C}
              │                        │
         Hash: H1                 Hash: H2
              │                        │
         LOCK H1                  LOCK H2
              │                        │
              └──── DIVERGED ─────────┘
```

---

## Potential Solutions

### Solution 1: Leader-Based UTXO Selection

One signer builds the TX, others follow.

```
Leader election (deterministic):
  leader_index = hash(event_id) % N

Flow:
  1. Event arrives at all signers
  2. Non-leaders WAIT (don't build TX yet)
  3. Leader builds TX, broadcasts CRDT with kpsbt_blob
  4. Followers receive CRDT, verify outputs match event, sign leader's TX
  5. If leader timeout (30s), next signer becomes leader
```

**Pros:**
- Simple to implement
- Guaranteed convergence

**Cons:**
- Centralization (leader is single point of failure)
- Added latency for non-leaders
- Must handle leader failure/timeout

### Solution 2: Two-Phase Protocol

Separate proposal from commitment.

```
Phase 1 - Propose (NO SIGNING):
  - Each signer builds TX, computes hash
  - Broadcasts: "I propose H for event X" (but doesn't sign yet)
  - Collects proposals for T seconds

Phase 2 - Commit (SIGNING):
  - Pick canonical hash (smallest, or most votes)
  - Everyone signs THAT hash
  - Abandoned proposals were never signed (safe)
```

**Pros:**
- Decentralized
- No single point of failure
- Guaranteed convergence

**Cons:**
- Extra gossip round (latency)
- More complex protocol
- Must handle late/missing proposals

### Solution 3: UTXO Set Intersection

Agree on UTXOs before building TX.

```
Phase 1 - UTXO Discovery:
  - Each signer queries local node for UTXOs
  - Broadcasts: "I see UTXOs {A, B, C}"

Phase 2 - Intersection:
  - Compute intersection of all reported UTXO sets
  - E.g., Signer-1: {A,B,C}, Signer-2: {B,C,D} → intersection: {B,C}

Phase 3 - Deterministic Selection:
  - Select UTXOs from intersection using deterministic algorithm
  - All signers select same UTXOs → same TX → same hash
```

**Pros:**
- Decentralized
- Guaranteed same UTXO selection

**Cons:**
- Two extra gossip rounds
- Intersection might be empty (all signers see different UTXOs)
- Intersection might be too small for required amount

### Solution 4: Anchor UTXO

Ensure all TXs share at least one input.

```rust
fn anchor_utxo(event_id: Hash32, utxos: &[UTXO]) -> UTXO {
    // Deterministic selection: oldest UTXO
    utxos.iter()
        .min_by_key(|u| (u.block_daa_score, u.outpoint))
        .unwrap()
}

fn build_tx(event_id: Hash32, amount: u64) -> TX {
    let anchor = anchor_utxo(event_id, available_utxos);
    let additional = select_more_if_needed(amount - anchor.value);

    // ALL TXs include anchor, so only one can confirm
    build_with_inputs([anchor] + additional)
}
```

**Pros:**
- No extra coordination round
- Even if TXs differ in other inputs, they share anchor
- Only one TX can confirm (anchor gets spent)

**Cons:**
- Requires all signers to see the anchor UTXO
- If anchor UTXO doesn't exist in a signer's view → falls back to current problem
- Anchor might be insufficient for amount

### Solution 5: Pre-Funded Single UTXOs

Avoid UTXO selection entirely.

```
Setup:
  - Pre-fund wallet with UTXOs of known denominations
  - E.g., 100x 1000 KAS UTXOs, 50x 5000 KAS UTXOs

Per event:
  - Select exactly ONE UTXO that covers the amount
  - Deterministic selection: smallest sufficient UTXO
  - No coin selection = no divergence
```

**Pros:**
- Eliminates UTXO selection problem entirely
- Simple, deterministic

**Cons:**
- Requires careful UTXO management
- May need consolidation transactions
- Less flexible

### Solution 6: Accept Liveness Risk (Current Design)

Keep current design, accept that events may get stuck.

```
Mitigations:
  - Use nodes with good connectivity (reduces UTXO divergence)
  - Set high confirmation requirements for UTXOs
  - Manual intervention for stuck events (admin reset)
  - Alert on stuck events
```

**Pros:**
- No code changes needed
- Safety guaranteed

**Cons:**
- Events can get stuck
- Requires monitoring and manual intervention
- Not truly autonomous

---

## Comparison Matrix

| Solution | Safety | Liveness | Latency | Complexity | Decentralized |
|----------|--------|----------|---------|------------|---------------|
| Current (irrevocable lock) | ✓ | ✗ | Low | Low | ✓ |
| Leader-based | ✓ | ✓ | Medium | Medium | ✗ |
| Two-phase protocol | ✓ | ✓ | High | High | ✓ |
| UTXO intersection | ✓ | Partial | High | High | ✓ |
| Anchor UTXO | ✓ | Partial | Low | Low | ✓ |
| Pre-funded UTXOs | ✓ | ✓ | Low | Medium | ✓ |

---

## Mathematical Constraint

For safety without coordination, the multisig threshold must satisfy:

**M > N/2** (threshold must be more than half of signers)

With this constraint, even if signatures split across two TXs, only one can reach threshold:

```
N = 5 signers, M = 3 threshold
Each signer signs exactly one TX (enforced by lock)

Worst case split: TX1 gets 2 sigs, TX2 gets 3 sigs
Only TX2 reaches threshold ✓

But if M = 2:
Worst case split: TX1 gets 2 sigs, TX2 gets 2 sigs, TX3 gets 1 sig
TX1 and TX2 both reach threshold ✗ DOUBLE PAYMENT
```

**Implication**: 2-of-5, 2-of-4, etc. are unsafe without coordination.

---

## Recommendation

### Short-Term (Minimal Changes)

1. **Document the constraint**: M > N/2 required for safety
2. **Add validation**: Reject configurations where M ≤ N/2
3. **Monitoring**: Alert on stuck events (same event_id, no completion after timeout)
4. **Manual recovery**: Admin tool to reset stuck events

### Medium-Term (Anchor UTXO)

Implement deterministic anchor UTXO selection to reduce (not eliminate) divergence probability.

### Long-Term (Two-Phase Protocol or Leader-Based)

Implement proper coordination before signing to guarantee both safety and liveness.

---

## Questions to Consider

1. What is the expected multisig configuration? (M-of-N)
2. How critical is liveness vs safety?
3. Is added latency acceptable? (for two-phase or leader-based)
4. Can we control UTXO management? (for pre-funded approach)
5. Is some centralization acceptable? (for leader-based)

---

## Related Files

| File | Relevance |
|------|-----------|
| `igra-core/src/infrastructure/storage/rocks/engine.rs:328-341` | `set_event_active_template_hash` implementation |
| `igra-core/src/application/event_processor.rs` | RPC path with reuse logic |
| `igra-service/src/service/coordination/crdt_handler.rs:343-364` | Gossip handler with rebuild check |
| `igra-core/src/infrastructure/rpc/kaspa_integration.rs` | UTXO fetching and TX building |

---

## See Also

- `FIXES_CRDT_GOSSIP_VALIDATION.md` - Related security issues in gossip path
- `docs/guide/key-derivation.md` - HD key derivation issues

---

*Generated: 2025-01-14*
