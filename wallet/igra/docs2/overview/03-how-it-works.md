# How It Works (Non-Technical)

**Last Updated:** 2026-02-05
**Reading Time:** 10 minutes

---

## The Challenge

Imagine 5 people sharing a bank account. They all need to agree before making a payment. Sounds simple, right?

**Problem:** Each person checks the account balance at slightly different times and sees slightly different amounts (due to pending transactions). When they try to coordinate a payment, they each propose different transaction details. Result: No one agrees, payment fails.

**In blockchain terms:** This is called the "UTXO coordination problem." Each signer sees a different set of unspent coins and builds different transactions.

---

## The Solution: Two Steps

Igra solves this with a two-step process:

### Step 1: Vote Before Signing

Instead of everyone immediately signing their own version of the transaction:

```
Everyone proposes: "I want to use THESE specific coins"
Everyone votes on proposals
When majority agrees on ONE proposal → Lock it in
```

**Key insight:** Voting is cheap and reversible. Signatures are expensive and permanent.

### Step 2: Collect Signatures

Once everyone agrees on the exact same transaction:

```
Each person signs the agreed transaction
Signatures are collected automatically
When enough signatures → Transaction completes
```

**Key insight:** Since everyone is signing the SAME transaction, signatures can be merged without further coordination.

---

## Visual Walkthrough

### Scenario: Bridge Withdrawal

Alice wants to withdraw 100 KAS from a bridge. The bridge uses 5 signers with a 3-of-5 threshold.

```
┌─────────────────────────────────────────┐
│ Step 1: Event Arrives                   │
└─────────────────────────────────────────┘

Alice locks 100 ETH on Ethereum
    │
    ▼
Hyperlane validators attest to the lock
    │
    ▼
All 5 Igra signers receive the event:
  "Pay 100 KAS to Alice's Kaspa address"


┌─────────────────────────────────────────┐
│ Step 2: Each Signer Builds Template     │
└─────────────────────────────────────────┘

Signer 1 queries their Kaspa node:
  Available UTXOs: [A=50 KAS, B=60 KAS]
  Proposes: "Use UTXOs A+B"
  Template hash: H1

Signer 2 queries their Kaspa node:
  Available UTXOs: [A=50 KAS, B=60 KAS]
  Proposes: "Use UTXOs A+B"
  Template hash: H1  (same!)

Signer 3 queries their Kaspa node:
  Available UTXOs: [A=50 KAS, C=70 KAS]  (different!)
  Proposes: "Use UTXOs A+C"
  Template hash: H2


┌─────────────────────────────────────────┐
│ Step 3: Vote Counting                   │
└─────────────────────────────────────────┘

Votes for H1: Signer 1, Signer 2 ✓
Votes for H2: Signer 3

Signer 4 sees both proposals, votes for H1
Signer 5 sees both proposals, votes for H1

Final tally:
  H1: 4 votes ✓✓✓✓ → QUORUM (4 > 2.5)
  H2: 1 vote


┌─────────────────────────────────────────┐
│ Step 4: Commitment                      │
└─────────────────────────────────────────┘

All signers detect: H1 has quorum
All signers lock to H1
Message to each signer: "You are now signing template H1 ONLY"


┌─────────────────────────────────────────┐
│ Step 5: Signing                         │
└─────────────────────────────────────────┘

Each signer:
  1. Retrieves template H1
  2. Signs with their private key
  3. Broadcasts signature to other signers

Signer 1: Signs ✓
Signer 2: Signs ✓
Signer 3: Signs ✓ (switched to H1 after seeing quorum)
Signer 4: Signs ✓
Signer 5: Signs ✓


┌─────────────────────────────────────────┐
│ Step 6: Signature Collection            │
└─────────────────────────────────────────┘

Each signer merges received signatures:
  Local signatures: {Sig1}
  Receive from Signer 2: {Sig1, Sig2}
  Receive from Signer 3: {Sig1, Sig2, Sig3}

Threshold check: Need 3-of-5
  Have 5 signatures → THRESHOLD MET ✓


┌─────────────────────────────────────────┐
│ Step 7: Finalization                    │
└─────────────────────────────────────────┘

Any signer (e.g., Signer 1):
  1. Applies all 5 signatures to template
  2. Finalizes transaction
  3. Submits to Kaspa blockchain

Transaction confirmed!
Alice receives 100 KAS
```

---

## Key Mechanisms Explained

### 1. Quorum Voting

**What it is:** More than half of signers must agree

**Why >50%:** Prevents two different transactions from both getting approved
- With 5 signers, quorum = 3
- If H1 has 3 votes, at most 2 votes remain for any other hash
- No other hash can reach quorum

**Math:**
```
N = 5 signers
Quorum = ⌊N/2⌋ + 1 = ⌊2.5⌋ + 1 = 3
```

### 2. Template Hash

**What it is:** A fingerprint of the transaction

**How it works:**
```
Transaction details:
  - Inputs: UTXO A (50 KAS), UTXO B (60 KAS)
  - Output: 100 KAS to Alice
  - Fee: 10 KAS

Hash = BLAKE3(all the above) = "a1b2c3..."
```

**Why it's useful:**
- Small (32 bytes) vs full transaction (kilobytes)
- Two identical transactions always produce the same hash
- Different transactions always produce different hashes

### 3. CRDT (Conflict-Free Replicated Data Type)

**What it is:** A fancy way to merge data without conflicts

**Simple analogy:** Shopping list app
```
Alice's list: [milk, bread]
Bob's list: [bread, eggs]
Merged list: [milk, bread, eggs]  ← No conflicts!
```

**For signatures:**
```
Signer 1's signatures: {Sig1}
Signer 2's signatures: {Sig2}
Merged signatures: {Sig1, Sig2}
```

**Magic property:** Order doesn't matter, result is always the same
```
{Sig1} ∪ {Sig2} = {Sig2} ∪ {Sig1} = {Sig1, Sig2}
```

### 4. Deterministic Selection

**Problem:** What if signers keep proposing different templates forever?

**Solution:** Use event-specific randomness to order UTXOs
```
Round 0: seed = Hash("event123" + "0")
         Sort UTXOs by Hash(seed + utxo_id)
         Result: [A, B, C]

Round 1: seed = Hash("event123" + "1")
         Sort UTXOs by Hash(seed + utxo_id)
         Result: [B, C, A]  (different order!)
```

**Why it helps:** Different rounds try different UTXO orderings, increasing chance of convergence

---

## What Makes It Safe?

### Safety Property
**"At most one transaction per event"**

Even if:
- Signers see different blockchain states
- Network is slow or partitioned
- Some signers crash

**How it's enforced:**
1. Each signer votes once per round (enforced by storage)
2. Quorum requires >50% (only one hash can win)
3. Each signer signs once per event (enforced by protocol)

### What Happens on Failure?

**Scenario 1: Votes split 2-2-1**
```
H1: 2 votes
H2: 2 votes
H3: 1 vote

No quorum → Timeout → Retry with new round
Round 1 uses different UTXO ordering
Eventually converges or explicitly abandons
```

**Scenario 2: Only 2 signers online**
```
Need 3 for quorum
Only have 2 votes
Cannot commit → Safe! No accidental signing
```

**Scenario 3: Signer crashes after signing**
```
Signature already broadcast to others
Other signers have it in their CRDT
Crashed signer's signature still counts
Transaction can still complete
```

---

## Performance Characteristics

### Typical Transaction Timeline

```
T+0s     Event arrives
T+0.1s   Signers build templates
T+0.2s   Proposals broadcast
T+0.5s   Quorum detected
T+0.5s   Signers start signing
T+0.7s   Signatures propagate
T+0.8s   Threshold reached
T+1.0s   Transaction submitted to blockchain
T+11.0s  Transaction confirmed (Kaspa: ~10 blocks)
```

**Total latency:** 1-2 seconds (coordination) + 10 seconds (blockchain)

### Retry Timeline (on failure)

```
Round 0: 0-5s   → No quorum
Round 1: 5-10s  → No quorum
Round 2: 10-15s → Quorum! ✓

Total: 15 seconds with 2 retries
```

---

## Comparison to Alternatives

### vs Leader-Based Coordination

**Leader approach:**
```
1. Elect leader
2. Leader builds transaction
3. Everyone signs leader's transaction
```

**Problems:**
- Leader election takes time
- Leader is single point of failure
- If leader crashes, start over

**Igra approach:**
```
1. Everyone proposes simultaneously
2. Majority vote determines winner
```

**Benefits:**
- No election overhead
- No single point of failure
- Any signer can be offline

### vs Optimistic Signing

**Optimistic approach:**
```
Everyone immediately signs their own template
Hope they match
```

**Problems:**
- If templates differ → signatures useless
- No recovery mechanism
- Risk of double-signing

**Igra approach:**
```
Vote first (cheap, reversible)
Sign only after agreement (expensive, permanent)
```

---

## Real-World Analogy

Think of it like a group of friends deciding where to eat dinner:

### Without Igra (Chaos)
```
Alice: "Let's go to Restaurant A!" *calls Uber to A*
Bob: "Let's go to Restaurant B!" *calls Uber to B*
Carol: "Let's go to Restaurant A!" *calls Uber to A*

Result: Group is split, dinner plans fail
```

### With Igra (Coordination)
```
Step 1: VOTE
Alice: "I suggest Restaurant A"
Bob: "I suggest Restaurant B"
Carol: "I suggest Restaurant A"

Tally: Restaurant A has 2 votes (majority!)

Step 2: COMMIT
Everyone agrees: "We're going to Restaurant A"
Everyone calls Uber to Restaurant A
Group arrives together, dinner succeeds
```

---

## Summary

1. **Problem:** Multiple signers, different blockchain views
2. **Solution:** Two-phase voting + CRDT signature collection
3. **Safety:** Quorum ensures only one transaction per event
4. **Liveness:** Retries with different seeds until convergence
5. **Performance:** 1-2 seconds typical, 10-30 seconds with retries

---

## Next Steps

- **See it in action:** [Devnet Quickstart](../operators/deployment/01-quickstart-devnet.md)
- **Technical details:** [Architecture Overview](../developers/architecture/01-architecture-overview.md)
- **Common questions:** [FAQ](04-faq.md)

---

**Still confused?** Ask in [Kaspa Discord #igra-support](https://discord.gg/kaspa)
