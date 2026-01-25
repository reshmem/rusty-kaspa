# Distributed System Failure Analysis: IGRA Bridge

## System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              SOURCE CHAINS                                        │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐                    │
│  │ EVM Chain 1  │      │ EVM Chain 2  │      │ EVM Chain 3  │                    │
│  │   (Igra)     │      │   (Igra)     │      │   (Igra)     │                    │
│  └──────┬───────┘      └──────┬───────┘      └──────┬───────┘                    │
│         │                     │                     │                            │
│         └─────────────────────┼─────────────────────┘                            │
│                               │                                                  │
│                  ┌────────────┴────────────┐                                     │
│                  │  Hyperlane Validators   │                                     │
│                  │  (sign cross-chain msg) │                                     │
│                  └────────────┬────────────┘                                     │
└──────────────────────────────┬───────────────────────────────────────────────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Local Relayer A │  │ Local Relayer B │  │ Local Relayer C │
│ (Hyperlane)     │  │ (Hyperlane)     │  │ (Hyperlane)     │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           IGRA SIGNER CLUSTER                                     │
│                         (Leaderless Coordination)                                 │
│                                                                                   │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐       │
│  │     SIGNER A        │  │     SIGNER B        │  │     SIGNER C        │       │
│  │  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │       │
│  │  │ Coordination  │  │  │  │ Coordination  │  │  │  │ Coordination  │  │       │
│  │  │    Loop       │  │  │  │    Loop       │  │  │  │    Loop       │  │       │
│  │  │ (coordinator) │  │  │  │ (coordinator) │  │  │  │ (coordinator) │  │       │
│  │  └───────────────┘  │  │  └───────────────┘  │  │  └───────────────┘  │       │
│  │  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │       │
│  │  │    Signer     │  │  │  │    Signer     │  │  │  │    Signer     │  │       │
│  │  │   Backend     │  │  │  │   Backend     │  │  │  │   Backend     │  │       │
│  │  └───────────────┘  │  │  └───────────────┘  │  │  └───────────────┘  │       │
│  │  ┌───────────────┐  │  │  ┌───────────────┐  │  │  ┌───────────────┐  │       │
│  │  │   RocksDB     │  │  │  │   RocksDB     │  │  │  │   RocksDB     │  │       │
│  │  │   Storage     │  │  │  │   Storage     │  │  │  │   Storage     │  │       │
│  │  └───────────────┘  │  │  └───────────────┘  │  │  └───────────────┘  │       │
│  └──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘       │
│             │                        │                        │                  │
│             │         IROH GOSSIP NETWORK                     │                  │
│             │    (same session_id = same topic)               │                  │
│             └────────────────────────┼────────────────────────┘                  │
│                                      │                                           │
└──────────────────────────────────────┼───────────────────────────────────────────┘
                                       │
           ┌───────────────────────────┼───────────────────────────┐
           │                           │                           │
           ▼                           ▼                           ▼
    ┌─────────────┐            ┌─────────────┐            ┌─────────────┐
    │Local Kaspa A│            │Local Kaspa B│            │Local Kaspa C│
    └──────┬──────┘            └──────┬──────┘            └──────┬──────┘
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      │
                         ┌────────────┴────────────┐
                         │   KASPA P2P NETWORK     │
                         │                         │
                         │  First TX wins (UTXO)   │
                         │  Others rejected        │
                         └─────────────────────────┘
```

### Key Architecture Properties

| Property | Description |
|----------|-------------|
| **Leaderless** | No single coordinator - all signers can coordinate |
| **Deterministic Session ID** | Same event → same event_hash → same session_id |
| **Race to Finalize** | All signers race to collect signatures and submit |
| **UTXO Protection** | Kaspa's UTXO model prevents double-spend |
| **Local Infrastructure** | Each signer has local relayer + local Kaspa node |

### Why Leaderless Works

```
Event E emitted on EVM Chain
         │
         ▼
Hyperlane validators sign message M
         │
    ┌────┴────┬─────────┐
    │         │         │
    ▼         ▼         ▼
Relayer A  Relayer B  Relayer C    (async delivery)
    │         │         │
    ▼         ▼         ▼
Signer A   Signer B   Signer C
    │         │         │
    │         │         │
    ├─────────┴─────────┤
    │                   │
    ▼                   ▼
event_hash(E) = H    (deterministic - all compute same hash)
session_id(H) = S    (deterministic - all get same session)
    │                   │
    └─────────┬─────────┘
              │
              ▼
    All subscribe to Iroh topic S
    All see ALL messages
              │
              ▼
    Anyone with M signatures can submit
    First TX in Kaspa wins
    Others fail gracefully (UTXO spent)
```

---

## Table of Contents

1. [Leaderless Coordination Deep Dive](#1-leaderless-coordination-deep-dive)
2. [Component Failure Scenarios](#2-component-failure-scenarios)
3. [Network Failure Scenarios](#3-network-failure-scenarios)
4. [State & Consistency Scenarios](#4-state--consistency-scenarios)
5. [Timing & Ordering Scenarios](#5-timing--ordering-scenarios)
6. [Offline Node Recovery Scenarios](#6-offline-node-recovery-scenarios)
7. [Security & Attack Scenarios](#7-security--attack-scenarios)
8. [Edge Cases & Corner Cases](#8-edge-cases--corner-cases)
9. [Multi-Failure Compound Scenarios](#9-multi-failure-compound-scenarios)
10. [Current Mitigations Analysis](#10-current-mitigations-analysis)
11. [Recommended Optimizations](#11-recommended-optimizations)
12. [Recommended Solutions](#12-recommended-solutions)

---

## 1. Leaderless Coordination Deep Dive

### 1.1 Message Flow for Single Event

```
Timeline for Event E with 3 signers (M=2 threshold):

T0:   Relayer A delivers E to Signer A
T0:   A: store event_hash(E) in CF_EVENT
T0:   A: compute session_id S = derive(event_hash)
T0:   A: subscribe to Iroh topic S
T0:   A: broadcast SigningEventPropose

T2s:  Relayer B delivers E to Signer B
T2s:  B: store event_hash(E) in CF_EVENT
T2s:  B: compute session_id S (same as A!)
T2s:  B: subscribe to Iroh topic S
T2s:  B: broadcast SigningEventPropose

T3s:  A receives B's proposal (via Iroh)
T3s:  A: already has this event, could skip (optimization)

T4s:  Relayer C delivers E to Signer C
T4s:  C: store, compute S, subscribe, broadcast

T5s:  All signers see all proposals on topic S

T6s:  A: validates, signs all inputs, broadcasts PartialSigSubmit×N
T7s:  B: validates, signs all inputs, broadcasts PartialSigSubmit×N
T8s:  C: validates, signs all inputs, broadcasts PartialSigSubmit×N

T9s:  A: has A's sigs + B's sigs = threshold met!
T9s:  A: aggregate signatures, build final TX
T9s:  A: submit to Local Kaspa A

T9.1s: B: has A's sigs + B's sigs = threshold met!
T9.1s: B: aggregate, build TX, submit to Local Kaspa B

T9.2s: C: has A's sigs + B's sigs = threshold met!
T9.2s: C: aggregate, build TX, submit to Local Kaspa C

T10s: Kaspa network: First TX propagates
T10s: Other submissions: "UTXO already spent" → rejected gracefully

T11s: Winner broadcasts FinalizeNotice
T11s: All signers receive, update local state
```

### 1.2 Why Multiple Proposals Are Safe

```
Signer A proposal:
  - event_hash: H
  - session_id: S
  - request_id: R (derived from H)
  - expires_at: T0 + 60s
  - kpsbt_blob: [transaction template]

Signer B proposal:
  - event_hash: H (same!)
  - session_id: S (same!)
  - request_id: R (same!)
  - expires_at: T2 + 60s (different - B's clock)
  - kpsbt_blob: [same transaction template]

Key insight: The TRANSACTION is the same!
- Same source UTXOs
- Same destination address
- Same amount
- Same signatures required

Multiple proposals = redundancy, not conflict
```

### 1.3 Current Message Count (Unoptimized)

For 1 event with 3 signers and 5 inputs:

| Message Type | Count | Explanation |
|--------------|-------|-------------|
| SigningEventPropose | 3 | Each signer broadcasts |
| SignerAck | 9 | Each signer acks each proposal (3×3) |
| PartialSigSubmit | 15 | Each signer × each input (3×5) |
| FinalizeNotice | 1-3 | Winner(s) broadcast |
| **Total** | **28-30** | Per event |

### 1.4 Optimized Message Count

| Message Type | Count | Optimization |
|--------------|-------|--------------|
| SigningEventPropose | 3 | Unavoidable (each has local relayer) |
| SignerAck | 3 | Ack once per event_hash, not per proposal |
| PartialSigSubmit | 15 | Unavoidable (must share all sigs) |
| FinalizeNotice | 1 | Only winner broadcasts |
| **Total** | **22** | 26% reduction |

---

## 2. Component Failure Scenarios

### 2.1 Single Signer Failures

#### 2.1.1 Signer Crashes During Idle State

**Scenario**: Signer A crashes when no active sessions exist.

**Timeline**:
```
T0: Signer A is idle
T1: Signer A crashes
T2: Event E arrives at relayers B and C
T3: B and C process event, create sessions
T4: B and C sign, reach threshold (M=2)
T5: Transaction submitted successfully
```

**Impact**: **NONE** - System continues without A.

**Why It Works**: Leaderless design means any M signers can complete.

**Risk Level**: **LOW**

---

#### 2.1.2 Signer Crashes After Receiving Event, Before Signing

**Scenario**: Signer A receives event, crashes before signing.

**Timeline**:
```
T0: A receives event from relayer, stores in CF_EVENT
T1: A broadcasts proposal
T2: A crashes before signing
T3: B and C receive A's proposal
T4: B and C also receive event from their relayers
T5: B and C sign and broadcast
T6: B or C reaches threshold with B+C signatures
T7: Transaction submitted successfully
```

**Impact**: **NONE** - B and C complete the transaction.

**A's State After Recovery**:
- CF_EVENT has the event
- No signatures sent
- Will receive FinalizeNotice when back online (if still subscribed)
- Or will try to re-process (see Section 6)

**Risk Level**: **LOW**

---

#### 2.1.3 Signer Crashes Mid-Signing (Partial Signatures Sent)

**Scenario**: Signer A crashes while iterating through inputs.

**Timeline**:
```
T0: Transaction has 5 inputs
T1: A signs input 0, broadcasts
T2: A signs input 1, broadcasts
T3: A crashes (inputs 2,3,4 not signed)
T4: B signs all 5 inputs, broadcasts
T5: C signs all 5 inputs, broadcasts
```

**Signature Collection**:
```
Input 0: A's sig ✓, B's sig ✓, C's sig ✓ → 3 sigs (need 2) ✓
Input 1: A's sig ✓, B's sig ✓, C's sig ✓ → 3 sigs (need 2) ✓
Input 2: B's sig ✓, C's sig ✓ → 2 sigs (need 2) ✓
Input 3: B's sig ✓, C's sig ✓ → 2 sigs (need 2) ✓
Input 4: B's sig ✓, C's sig ✓ → 2 sigs (need 2) ✓
```

**Impact**: **NONE** - Threshold met for all inputs.

**Risk Level**: **LOW**

---

#### 2.1.4 Signer Process Hangs (Not Responding)

**Scenario**: Signer A is alive but not processing (deadlock, resource starvation).

**Impact**: Same as crash - B and C continue.

**Difference**: A won't recover automatically, may need manual restart.

**Risk Level**: **LOW** (for transaction completion), **MEDIUM** (for operations)

---

#### 2.1.5 All Signers Except One Crash

**Scenario**: Only Signer A remains, B and C crashed.

**Timeline**:
```
T0: B and C crash
T1: Event E arrives at A's relayer
T2: A processes, broadcasts proposal
T3: No responses (B and C offline)
T4: A has only A's signatures (1 of 2 needed)
T5: Session times out
```

**Impact**: **SESSION FAILS** - Cannot reach threshold.

**Recovery**: When B or C comes back online, may retry (see Section 6).

**Risk Level**: **HIGH** (but requires N-M+1 simultaneous failures)

---

### 2.2 Kaspa Node Failures

#### 2.2.1 Local Kaspa Node Unreachable

**Scenario**: Signer A's local Kaspa node is down.

**Timeline**:
```
T0: A reaches threshold
T1: A tries to submit to Kaspa-A
T2: Connection refused
T3: A retries (4 attempts with backoff)
T4: All retries fail

Meanwhile:
T2: B also reaches threshold
T3: B submits to Kaspa-B (working)
T4: Transaction accepted!
```

**Impact**: **NONE** - Another signer completes submission.

**Risk Level**: **LOW**

---

#### 2.2.2 All Local Kaspa Nodes Unreachable

**Scenario**: All signers' local Kaspa nodes are down.

**Impact**: **TRANSACTION FAILS** - No way to submit.

**Recovery**:
- Signatures are stored
- When any Kaspa node comes back, can retry submission
- Need: Persistent transaction outbox (see Section 12)

**Risk Level**: **MEDIUM**

---

#### 2.2.3 Kaspa Network Partition

**Scenario**: Kaspa-A is partitioned from network, Kaspa-B and Kaspa-C connected.

**Timeline**:
```
T0: A submits TX to Kaspa-A (partitioned)
T1: TX sits in Kaspa-A mempool, doesn't propagate
T2: B submits TX to Kaspa-B (connected)
T3: TX propagates through network
T4: TX confirmed in block
T5: Partition heals
T6: Kaspa-A sees TX already confirmed (via sync)
T7: A's local mempool TX becomes invalid (UTXO spent)
```

**Impact**: **NONE** - Transaction succeeds via B.

**Risk Level**: **LOW**

---

### 2.3 Hyperlane Relayer Failures

#### 2.3.1 Single Relayer Down

**Scenario**: Signer A's local relayer is down.

**Timeline**:
```
T0: Event E emitted on EVM chain
T1: Relayer A is down, doesn't deliver to A
T2: Relayer B delivers to B
T3: Relayer C delivers to C
T4: B and C process, sign, submit
T5: Transaction succeeds
```

**Impact**: **NONE** - Other relayers deliver, other signers process.

**Risk Level**: **LOW**

---

#### 2.3.2 All Relayers Down

**Scenario**: All Hyperlane relayers offline.

**Impact**: **EVENTS NOT DELIVERED** - System halted.

**Recovery**: When relayers come back, they deliver pending messages.

**Risk Level**: **HIGH** (infrastructure dependency)

---

#### 2.3.3 Relayer Delivers Stale Events

**Scenario**: Relayer was down, comes back, delivers old events.

**This is a critical scenario - see Section 6 for detailed analysis.**

---

### 2.4 RocksDB Failures

#### 2.4.1 Single Signer RocksDB Corruption

**Scenario**: Signer A's database corrupted.

**Impact on Current Sessions**: A cannot participate until restored.

**Impact on Completed Sessions**:
- A loses knowledge of processed events
- A's relayer may re-deliver old events
- See Section 6 for recovery scenarios

**Risk Level**: **MEDIUM**

---

#### 2.4.2 RocksDB Disk Full

**Scenario**: A's disk full, writes fail.

**Timeline**:
```
T0: A receives event
T1: insert_event() fails: "No space left"
T2: Event not stored
T3: A cannot process
T4: B and C continue normally
```

**Impact**: A degraded, but system continues.

**Risk Level**: **MEDIUM**

---

### 2.5 Iroh Transport Failures

#### 2.5.1 Single Signer Loses Iroh Connectivity

**Scenario**: A cannot connect to Iroh network.

**Timeline**:
```
T0: A's Iroh connection fails
T1: A receives event from local relayer
T2: A processes locally, broadcasts proposal
T3: Proposal doesn't reach B and C
T4: A signs, but signatures don't propagate
T5: A cannot collect others' signatures
T6: A's session times out

Meanwhile:
T3: B and C receive event from their relayers
T4: B and C communicate normally
T5: B and C reach threshold
T6: Transaction succeeds
```

**Impact**: **NONE** for transaction, A wasted work.

**Risk Level**: **LOW**

---

#### 2.5.2 Iroh Network Partition

**Scenario**: Iroh gossip splits into partitions.

**Case A: Coordinator alone in partition**
```
Partition 1: A (alone)
Partition 2: B, C (together)

A cannot reach threshold alone (M=2).
B and C can reach threshold together.
Transaction succeeds via B+C.
```

**Case B: Threshold possible in each partition (M=1, N=3)**
```
Partition 1: A
Partition 2: B, C

Both partitions could submit!
But UTXO model protects: first wins, other fails.
```

**Risk Level**: **LOW** (UTXO protection)

---

## 3. Network Failure Scenarios

### 3.1 Complete Network Outage

#### 3.1.1 All Signers Lose Internet

**Impact**: Complete system halt.

**What's Preserved**:
- All RocksDB state intact
- Can resume when connectivity restored

**Risk Level**: **HIGH** (but obvious failure, easy to detect)

---

### 3.2 Partial Network Failures

#### 3.2.1 Asymmetric Connectivity

**Scenario**: A can reach B, but B cannot reach A.

**Timeline**:
```
T0: A broadcasts proposal
T1: Message reaches B (A→B works)
T2: B broadcasts ack and signatures
T3: A doesn't receive (B→A broken)
T4: C receives both A and B's messages
T5: C signs, broadcasts
T6: A receives C's signatures (C→A works)
T7: A has A + C = threshold, submits
T8: B has B + C = threshold, submits (same TX)
```

**Impact**: **NONE** - Redundant paths succeed.

**Risk Level**: **LOW**

---

#### 3.2.2 High Latency (>30 seconds)

**Scenario**: Network works but very slow.

**Timeline**:
```
T0: A broadcasts proposal, expires_at = T0+60s
T1: B receives at T0+40s (40s latency)
T2: B validates: expires_at - now = 20s remaining
T3: B signs, broadcasts
T4: A receives at T0+80s (after expiry!)
```

**Impact**: Sessions may fail due to timing.

**Mitigation**: Increase session_timeout_seconds for high-latency deployments.

**Risk Level**: **MEDIUM** (configuration dependent)

---

### 3.3 DNS Failures

**Scenario**: DNS resolution fails for bootstrap nodes or Kaspa nodes.

**Mitigation**: Use IP addresses directly in configuration.

**Risk Level**: **LOW**

---

## 4. State & Consistency Scenarios

### 4.1 State Divergence Between Signers

#### 4.1.1 Different Events Stored

**Scenario**: Signers have different CF_EVENT contents.

**Causes**:
- Signer was offline during event delivery
- RocksDB corruption and restore from backup
- Relayer selective delivery

**Impact**:
- Signers may have different replay protection state
- Offline signer may try to re-process completed events
- See Section 6 for detailed analysis

**Risk Level**: **MEDIUM**

---

#### 4.1.2 Different Request States

**Scenario**: A shows Finalized, B shows Pending for same request.

**Causes**:
- FinalizeNotice not received by B
- B was offline during finalization

**Impact**:
- Audit trail inconsistent
- No security impact (event hash prevents re-processing)

**Risk Level**: **LOW** (cosmetic)

---

### 4.2 Clock Synchronization Issues

#### 4.2.1 Clock Skew Between Signers

**Scenario**: A's clock is 30 seconds ahead of B's clock.

**Impact on Expiry**:
```
A creates proposal: expires_at = A_clock + 60s
B receives proposal: checks B_clock vs expires_at
If A_clock = B_clock + 30s:
  A thinks it's T+30
  B thinks it's T
  Proposal expires_at = T+90 (from A's view) = T+60 (absolute)
  B sees: 60s remaining (OK)
```

**Impact on Timestamps**:
- CF_SEEN cleanup based on timestamps
- Large skew could affect deduplication

**Risk Level**: **LOW** (60s timeout provides buffer)

---

#### 4.2.2 Clock Jump (NTP Correction)

**Scenario**: Signer's clock suddenly jumps forward/backward.

**Forward Jump**:
- Proposals may appear expired
- May reject valid proposals

**Backward Jump**:
- Old seen entries may not be cleaned up
- Timestamps appear from "future"

**Risk Level**: **LOW** (rare, recoverable)

---

### 4.3 Configuration Consistency

#### 4.3.1 Different Threshold Settings

**Scenario**: A has sig_op_count=2, B has sig_op_count=3.

**Impact**:
```
With 3 signers, 2 signatures collected:
A: 2 >= 2, threshold met! Submits TX.
B: 2 < 3, threshold NOT met. Waits for more sigs.
```

**Result**: A submits, transaction succeeds. B's stricter config is irrelevant.

**Risk Level**: **LOW** (less strict config wins)

---

#### 4.3.2 Different Hyperlane Validators

**Scenario**: A has [V1,V2,V3], B has [V1,V2,V4].

**Impact**:
```
Message signed by [V1, V2, V3]:
A: validates OK (3/3 match)
B: only [V1, V2] match (2/3)
   If threshold=2: validates OK
   If threshold=3: validation FAILS
```

**Result**: B may reject valid messages if threshold too high.

**Risk Level**: **MEDIUM** (configuration must be synchronized)

---

#### 4.3.3 Different Policy Settings

**Scenario**: A allows max 1 BTC/day, B allows max 0.5 BTC/day.

**Timeline**:
```
T0: Daily volume at 0.6 BTC
T1: New event for 0.1 BTC
T2: A: 0.6 + 0.1 = 0.7 < 1.0, accepts
T3: B: 0.6 + 0.1 = 0.7 > 0.5, rejects
T4: C: accepts (assume same as A)
T5: A + C = threshold, transaction succeeds
```

**Impact**: Stricter signers may not participate, but threshold can still be met.

**Risk Level**: **LOW** (most permissive config determines success)

---

## 5. Timing & Ordering Scenarios

### 5.1 Event Arrival Order

#### 5.1.1 Events Arrive at Different Times

**Scenario**: Same event arrives at signers with significant delay.

**Timeline**:
```
T0:    A receives event E
T10s:  B receives event E
T30s:  C receives event E

T0:    A broadcasts proposal (expires T0+60)
T10s:  B broadcasts proposal (expires T10+60)
T30s:  C broadcasts proposal (expires T30+60)

All on same Iroh topic (session_id same).
All signers see all proposals.
Different expires_at values - that's OK!
```

**Impact**: **NONE** - All proposals valid, all signers sign.

**Risk Level**: **LOW**

---

#### 5.1.2 Multiple Events Arrive Simultaneously

**Scenario**: 10 events arrive at same time.

**Timeline**:
```
T0: Events E1-E10 all arrive at A
T0: A creates 10 sessions, broadcasts 10 proposals
T0: A signs for all 10, broadcasts 10×inputs signatures
```

**Impact**: Resource pressure, but functionally correct.

**Risk Level**: **LOW** (may need rate limiting)

---

### 5.2 Race Conditions

#### 5.2.1 Race to Submit Transaction

**Scenario**: All signers reach threshold simultaneously.

**Timeline**:
```
T10.000s: A has threshold, builds TX, submits to Kaspa-A
T10.001s: B has threshold, builds TX, submits to Kaspa-B
T10.002s: C has threshold, builds TX, submits to Kaspa-C

T10.100s: Kaspa-A propagates TX to network
T10.150s: Kaspa-B receives TX from network
T10.150s: Kaspa-B: "TX already in mempool", rejects B's submission
T10.200s: Kaspa-C receives TX from network
T10.200s: Kaspa-C: rejects C's submission
```

**Impact**: **NONE** - First wins, others fail gracefully.

**Risk Level**: **LOW** (by design)

---

#### 5.2.2 Race Between Signing and Timeout

**Scenario**: Threshold reached just as timeout fires.

**Timeline**:
```
T0: Session starts, timeout = 60s
T59.9s: Last signature arrives
T59.95s: has_threshold() returns true
T60.0s: Timeout fires
```

**Result**: Depends on exact timing and implementation.
- If finalization started before timeout: succeeds
- If timeout checked first: may fail despite having signatures

**Risk Level**: **LOW** (edge case)

---

### 5.3 Message Ordering

#### 5.3.1 Signatures Arrive Before Proposal

**Scenario**: Due to network routing, signatures arrive first.

**Timeline**:
```
T0: A broadcasts proposal
T1: A broadcasts signatures
T2: B receives signatures (via fast path)
T3: B receives proposal (via slow path)
```

**Impact**: B may not know what to do with signatures until proposal arrives.

**Current Behavior**: Signatures stored, matched to request when proposal arrives.

**Risk Level**: **LOW**

---

#### 5.3.2 FinalizeNotice Before All Signatures Collected

**Scenario**: Winner broadcasts finalize before others finish signing.

**Timeline**:
```
T0: A reaches threshold (A + B sigs)
T1: A submits TX, broadcasts FinalizeNotice
T2: C still signing...
T3: C's signatures arrive (but TX already submitted)
```

**Impact**: **NONE** - C's extra signatures are redundant but harmless.

**Risk Level**: **LOW**

---

## 6. Offline Node Recovery Scenarios

### 6.1 Node Comes Online After Extended Downtime

This is a **critical scenario** that needs careful analysis.

#### 6.1.1 Basic Scenario

**Setup**:
- Signer A offline for 1 hour
- During downtime: Events E1, E2, E3 processed by B and C
- Transactions T1, T2, T3 submitted to Kaspa
- UTXOs for E1, E2, E3 consumed

**Timeline When A Returns**:
```
T0:   A comes online
T1:   A's RocksDB intact but missing E1, E2, E3 in CF_EVENT
T2:   A's local Hyperlane relayer reconnects
T3:   Relayer delivers "missed" events E1, E2, E3 to A
T4:   A receives E1 - not in CF_EVENT (new to A!)
T5:   A processes E1...
```

#### 6.1.2 What Happens When A Processes Stale Event E1

```
A receives E1 from relayer:

Step 1: Validate Hyperlane signatures
        → PASS (signatures still valid)

Step 2: Check CF_EVENT for event_hash(E1)
        → NOT FOUND (A was offline)

Step 3: Store in CF_EVENT
        → SUCCESS (first time A sees it)

Step 4: Create session, compute session_id S1
        → S1 = same session_id as before (deterministic)

Step 5: Subscribe to Iroh topic S1
        → Subscribed (but session completed hours ago)

Step 6: Broadcast SigningEventPropose
        → Sent to Iroh network

Step 7: B and C receive A's proposal
        → See analysis below

Step 8: A signs inputs, broadcasts PartialSigSubmit
        → Sent to network

Step 9: A tries to collect signatures
        → May only see own signatures (old session dead)

Step 10: A reaches timeout, or reaches threshold with old sigs?
         → Depends on what B and C do
```

#### 6.1.3 What B and C Do When They Receive A's Stale Proposal

**Current Behavior** (unoptimized):
```
B receives A's proposal for E1:

Step 1: Check event_hash(E1)
        → B already has E1 in CF_EVENT (processed it while A was offline)

Step 2: Current code may still process proposal
        → Sends ack
        → Signs again
        → Broadcasts signatures

Step 3: A collects B's signatures
        → A reaches threshold!

Step 4: A builds transaction T1' (same as T1)
        → Same inputs, same outputs

Step 5: A submits T1' to Kaspa-A
        → Kaspa: "UTXO not found" (already spent by T1)
        → Submission FAILS

Step 6: A logs error, session fails
```

**Impact**:
- No double-spend (UTXO protection)
- But wasted work: signing, network traffic, CPU
- A thinks session failed (doesn't know T1 already succeeded)

#### 6.1.4 Cascading Stale Events

**Scenario**: A was offline for 1 hour, 100 events processed.

**Timeline**:
```
T0:   A comes online
T1-T100: A's relayer delivers 100 stale events
T2-T101: A tries to create 100 sessions
         A signs for 100 transactions
         A tries 100 Kaspa submissions
         ALL FAIL (UTXOs spent)

Result: Massive wasted work, error logs, confusion
```

**Risk Level**: **MEDIUM** (no security issue, but operational nightmare)

---

### 6.2 Optimizations to Handle Stale Events

#### 6.2.1 Optimization: Already-Processed Check

**When receiving proposal, check if we already processed this event:**

```rust
// In coordination loop, before processing proposal:
async fn should_process_proposal(&self, proposal: &SigningEventPropose) -> bool {
    // Check if we already have this event AND already contributed
    if let Some(request) = self.storage.get_request_by_event_hash(&proposal.event_hash)? {
        if request.decision == RequestDecision::Finalized {
            info!("Ignoring proposal for already-finalized event: {}",
                  hex::encode(proposal.event_hash));
            return false;
        }
        // Check if we already signed
        let my_sigs = self.storage.list_partial_sigs_by_signer(
            &request.request_id,
            &self.local_peer_id
        )?;
        if !my_sigs.is_empty() {
            info!("Already signed for this event, skipping");
            return false;
        }
    }
    true
}
```

**Benefit**: Signers that already processed event will skip.

**Limitation**: Doesn't help the offline signer (they don't have the event).

---

#### 6.2.2 Optimization: Event Completion Notice

**New message type for informing about completed events:**

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventCompletedNotice {
    pub event_hash: Hash32,
    pub tx_id: TransactionId,
    pub completed_at_nanos: u64,
}

// When B receives stale proposal from A:
if self.storage.get_request_by_event_hash(&proposal.event_hash)?.map(|r| r.is_finalized()) {
    // Inform A that this event is already done
    let notice = EventCompletedNotice {
        event_hash: proposal.event_hash,
        tx_id: stored_request.final_tx_id.unwrap(),
        completed_at_nanos: now_nanos(),
    };
    self.transport.publish_event_completed(session_id, notice).await?;
    return; // Don't process further
}

// A receives EventCompletedNotice:
fn handle_event_completed(&self, notice: EventCompletedNotice) {
    // Store in CF_EVENT if not present
    if self.storage.get_event(&notice.event_hash)?.is_none() {
        // Create synthetic event record
        self.storage.mark_event_completed_externally(
            &notice.event_hash,
            &notice.tx_id
        )?;
    }
    // Abort current session for this event
    self.abort_session_for_event(&notice.event_hash);
}
```

**Benefit**: Offline signer learns about completions quickly.

---

#### 6.2.3 Optimization: Pre-Submission UTXO Check

**Before submitting to Kaspa, verify UTXOs still exist:**

```rust
async fn submit_transaction(&self, tx: Transaction) -> Result<TxId, Error> {
    // Check UTXOs before submission
    for input in &tx.inputs {
        let utxo = self.kaspa_rpc.get_utxo(&input.outpoint).await?;
        if utxo.is_none() {
            warn!("UTXO already spent, aborting submission: {:?}", input.outpoint);
            return Err(Error::UtxoAlreadySpent);
        }
    }

    // UTXOs exist, proceed with submission
    self.kaspa_rpc.submit_transaction(tx).await
}
```

**Benefit**: Fail fast instead of waiting for Kaspa rejection.

**Limitation**: Race condition still possible (UTXO spent between check and submit).

---

#### 6.2.4 Optimization: Startup State Sync

**When signer comes online, sync state with peers:**

```rust
async fn startup_sync(&self) -> Result<(), Error> {
    // Request state summary from peers
    let my_state = self.compute_state_hash()?;
    let peer_states = self.request_peer_states().await?;

    for (peer_id, peer_state) in peer_states {
        if peer_state.event_count > my_state.event_count {
            // Peer has more events, request the difference
            let missing = self.request_missing_events(&peer_id, &my_state).await?;
            for event_info in missing {
                self.storage.mark_event_completed_externally(
                    &event_info.event_hash,
                    &event_info.tx_id,
                )?;
            }
        }
    }

    info!("State sync complete: imported {} events", imported_count);
    Ok(())
}
```

**Benefit**: Offline signer learns about ALL missed events before relayer floods it.

---

#### 6.2.5 Optimization: Relayer Event Acknowledgment

**Track last acknowledged event with relayer:**

```rust
// Relayer side (outside IGRA, but conceptually):
struct RelayerState {
    last_acked_event: Hash32,
    pending_events: Vec<Event>,
}

// When IGRA successfully processes event:
fn ack_event_to_relayer(&self, event_hash: &Hash32) {
    self.relayer_client.acknowledge(event_hash);
}

// Relayer only re-delivers events after last_acked
```

**Benefit**: Relayer doesn't re-deliver already-processed events.

**Limitation**: Requires relayer modification (may be outside IGRA's control).

---

### 6.3 Detailed Stale Event Scenarios

#### 6.3.1 Scenario: A Offline, DB Intact, Relayer Re-delivers

**Initial State**:
```
A: CF_EVENT = {E1, E2} (processed before offline)
B: CF_EVENT = {E1, E2, E3, E4, E5}
C: CF_EVENT = {E1, E2, E3, E4, E5}
```

**A comes online, relayer delivers E3, E4, E5**:

| Event | A's Action | B/C Response | Kaspa Result |
|-------|------------|--------------|--------------|
| E3 | Process, sign, submit | Already done, send EventCompletedNotice (opt) | "UTXO spent" |
| E4 | Process, sign, submit | Already done | "UTXO spent" |
| E5 | Process, sign, submit | Already done | "UTXO spent" |

**With Optimization**: A learns E3-E5 completed, aborts early.

---

#### 6.3.2 Scenario: A Offline, DB Corrupted, Restored from Old Backup

**Initial State**:
```
Backup (1 week old):
A: CF_EVENT = {E1, E2, E3}

Current state:
B: CF_EVENT = {E1, E2, E3, ..., E100}
C: CF_EVENT = {E1, E2, E3, ..., E100}
```

**A restored from backup, relayer delivers E4-E100**:

**Impact**: 97 stale events to process. Even worse than short downtime.

**Mitigation**: State sync on startup (6.2.4) is critical.

---

#### 6.3.3 Scenario: A Offline, New Event Arrives, A Misses It

**Timeline**:
```
T0: A goes offline
T1: New event E_new arrives at B and C
T2: B and C process, sign, submit
T3: Transaction for E_new confirmed
T4: A comes online
T5: A's relayer delivers E_new
T6: A processes E_new (stale by now)
```

**Same as 6.1.2** - A tries to process already-completed event.

---

#### 6.3.4 Scenario: A Offline During Ongoing Session

**Timeline**:
```
T0: Event E arrives at all signers
T1: All signers broadcast proposals
T2: All signers start signing
T3: A crashes mid-signing
T4: B and C complete signing
T5: B or C reaches threshold
T6: Transaction submitted, confirmed
T7: A comes online
T8: A's relayer thinks E wasn't delivered (no ack)
T9: A's relayer re-delivers E
T10: A tries to process E again
```

**Complication**: A already has partial state for E (CF_EVENT, maybe some sigs).

**Current Behavior**:
```
A checks CF_EVENT:
  - E already present → event_hash already stored
  - ThresholdError::EventReplayed?
  - Or skip to signing phase?
```

**Need**: Clear handling of "I have this event but didn't finish processing".

---

### 6.4 Recovery Decision Matrix

| Scenario | A's DB State | Relayer Behavior | Recommended Action |
|----------|--------------|------------------|-------------------|
| Short offline, DB intact | Has recent events | Re-delivers missed | Skip if already signed |
| Long offline, DB intact | Missing many events | Re-delivers all missed | State sync first |
| DB corrupted, restored | Very old state | Re-delivers many | State sync + careful replay |
| Relayer also restarted | N/A | May not re-deliver | May need manual trigger |
| Partial processing | Has event, no sigs | Re-delivers | Resume signing |

---

## 7. Security & Attack Scenarios

### 7.1 Replay Attacks

#### 7.1.1 Event Replay (Cross-Chain)

**Attack**: Replay valid Hyperlane message.

**Protection**:
- Event hash stored in CF_EVENT permanently
- Second delivery rejected as replay

**Risk Level**: **LOW** (fully mitigated)

---

#### 7.1.2 Message Replay (Transport)

**Attack**: Replay Iroh gossip message.

**Protection**:
- CF_SEEN tracks (peer_id, session_id, seq_no) for 24 hours
- Duplicate ignored

**Risk Level**: **LOW** (fully mitigated)

---

#### 7.1.3 Cross-Session Signature Replay

**Attack**: Use signature from session S1 in session S2.

**Protection**: Signature is over exact transaction hash, which includes:
- Specific UTXOs
- Specific amounts
- Specific addresses

Different event → different transaction → signature invalid.

**Risk Level**: **LOW** (cryptographically prevented)

---

### 7.2 Byzantine Signer Behavior

#### 7.2.1 Malicious Signer Sends Invalid Signature

**Attack**: Compromised signer sends garbage signature.

**Impact**:
- Other signers still provide valid signatures
- If threshold met without malicious sig: TX succeeds
- If malicious sig included: TX rejected by Kaspa

**Protection**: Kaspa validates all signatures.

**Risk Level**: **LOW**

---

#### 7.2.2 Malicious Signer Withholds Signature

**Attack**: Compromised signer never signs.

**Impact**:
- If M < N: Other signers provide threshold
- If M = N: Session fails

**Protection**: Threshold design tolerates N-M byzantine failures.

**Risk Level**: **LOW** (with proper threshold)

---

#### 7.2.3 Malicious Signer Floods Network

**Attack**: Send millions of fake proposals.

**Protection**:
- Ed25519 signature verification on all messages
- Rate limiting per peer
- Invalid event_hash rejected

**Risk Level**: **MEDIUM** (DoS possibility)

---

#### 7.2.4 All-But-One Signers Compromised

**Scenario**: M-1 signers compromised (worst case for M-of-N).

**Attack**: Cannot complete malicious transactions (need M signers).

**Impact**: Can grief legitimate transactions (never sign).

**Protection**: Requires trusting threshold number of signers.

**Risk Level**: **MEDIUM** (operational, not security)

---

### 7.3 External Attacks

#### 7.3.1 Hyperlane Message Forgery

**Attack**: Create fake cross-chain message.

**Protection**: Hyperlane validator signatures verified.

**Risk Level**: **LOW**

---

#### 7.3.2 Kaspa Double-Spend Attempt

**Attack**: Try to double-spend UTXOs.

**Protection**: Kaspa UTXO model - once spent, cannot be spent again.

**Risk Level**: **LOW** (blockchain property)

---

#### 7.3.3 Sybil Attack on Iroh

**Attack**: Create many fake Iroh peers.

**Impact**: May slow message propagation.

**Protection**:
- Messages require Ed25519 signatures
- Cannot forge valid signatures without keys

**Risk Level**: **LOW**

---

## 8. Edge Cases & Corner Cases

### 8.1 Boundary Conditions

#### 8.1.1 Exactly M Signatures

**Scenario**: Exactly threshold signatures, no more.

**Risk**: If one is invalid, finalization fails.

**Mitigation**: Signature validation before aggregation.

---

#### 8.1.2 Zero Amount Transaction

**Scenario**: Event with amount_sompi = 0.

**Behavior**: Depends on policy min_amount_sompi.

**Risk**: Low (unusual but valid).

---

#### 8.1.3 Very Large Transaction (Many Inputs)

**Scenario**: 1000 UTXOs needed.

**Impact**:
- 3 signers × 1000 inputs = 3000 signature messages
- Large PSKT blob
- May timeout

**Mitigation**: Consider input limits or transaction splitting.

---

### 8.2 Timing Edge Cases

#### 8.2.1 Event Arrives at Exact Session Timeout

**Scenario**: Proposal created, expires exactly as signature arrives.

**Impact**: Race condition between timeout and success.

**Risk**: **LOW** (rare timing)

---

#### 8.2.2 Kaspa Block at Submission Time

**Scenario**: Transaction submitted during Kaspa block production.

**Impact**: May be included in current or next block.

**Risk**: **LOW** (normal blockchain behavior)

---

### 8.3 Configuration Edge Cases

#### 8.3.1 M > N (Invalid Configuration)

**Scenario**: threshold = 5, signers = 3.

**Impact**: Sessions always fail.

**Mitigation**: Configuration validation at startup.

---

#### 8.3.2 Empty Validator List

**Scenario**: hyperlane.validators = [].

**Impact**: All events rejected (can't meet threshold).

**Mitigation**: Configuration validation.

---

## 9. Multi-Failure Compound Scenarios

### 9.1 Signer Crash + Network Partition

**Scenario**: A crashes while B-C are partitioned.

**Timeline**:
```
T0: A crashes
T1: Network partition: B cannot reach C
T2: Event arrives at B's relayer
T3: B processes alone, cannot reach threshold
T4: Session times out
T5: Partition heals
T6: Event arrives at C (delayed relayer)
T7: C processes, but B's session expired
T8: C creates new session (same session_id!)
T9: B sees C's proposal, has old sigs
```

**Impact**: Complex state, but eventually succeeds when partition heals.

---

### 9.2 Multiple Signers Restart + Stale Events

**Scenario**: All signers restart, all relayers re-deliver.

**Timeline**:
```
T0: All signers restart
T1: All relayers re-deliver E1, E2, E3 (already completed)
T2: All signers try to process
T3: All signers race to submit
T4: All submissions fail (UTXOs spent)
```

**Impact**: Massive wasted work, but no security issue.

**Mitigation**: State sync before accepting relayer events.

---

### 9.3 Kaspa Reorg + Stale Event Replay

**Scenario**: Kaspa reorgs, then signer processes stale event.

**Timeline**:
```
T0: Transaction T1 in block B1
T1: Kaspa reorgs, B1 orphaned
T2: T1 returns to mempool or lost
T3: A's relayer re-delivers E1
T4: A processes E1, creates T1' (same as T1)
T5: T1' submitted successfully (UTXOs available again!)
```

**Impact**: Transaction succeeds (this is actually good - recovery from reorg).

**Risk**: Double-spend if reorg is adversarial (very unlikely on Kaspa).

---

## 10. Current Mitigations Analysis

### 10.1 What's Working Well

| Protection | Implementation | Effectiveness |
|------------|----------------|---------------|
| Event hash deduplication | CF_EVENT permanent storage | **EXCELLENT** |
| Leaderless coordination | Any signer can coordinate | **EXCELLENT** |
| UTXO double-spend protection | Kaspa blockchain property | **EXCELLENT** |
| Message authentication | Ed25519 signatures | **EXCELLENT** |
| Hyperlane verification | Validator set + threshold | **GOOD** |
| Session timeout | Configurable deadline | **GOOD** |
| Rate limiting | Per-peer limits | **GOOD** |
| Deterministic session ID | Same event = same session | **EXCELLENT** |

### 10.2 Gaps Summary

| Gap | Severity | Impact | Section |
|-----|----------|--------|---------|
| Stale event wasteful processing | MEDIUM | Wasted work, confusion | 6.1 |
| No state sync on startup | MEDIUM | Slow recovery | 6.2.4 |
| No EventCompletedNotice | MEDIUM | Late learner problem | 6.2.2 |
| Message explosion (acks) | LOW | Inefficient | 11.1 |
| No persistent TX queue | MEDIUM | Lost transactions | 12.3 |
| No configuration consensus | MEDIUM | Split decisions | 4.3 |
| No health monitoring | MEDIUM | Silent failures | 12.4 |

---

## 11. Recommended Optimizations

### 11.1 Reduce Ack Messages

**Problem**: 3 signers × 3 proposals = 9 acks (worst case).

**Solution**: Ack once per event, not per proposal.

```rust
// Track acked events
fn should_send_ack(&self, event_hash: &Hash32) -> bool {
    let ack_key = format!("acked:{}", hex::encode(event_hash));
    if self.storage.has_flag(&ack_key)? {
        return false; // Already acked this event
    }
    self.storage.set_flag(&ack_key)?;
    true
}

// In loop, before sending ack:
if self.should_send_ack(&proposal.event_hash) {
    self.signer.submit_ack(session_id, ack, local_peer_id).await?;
}
```

**Result**: 3 acks instead of 9 (67% reduction).

---

### 11.2 Skip Already-Processed Proposals

**Problem**: Signers process proposals for events they already completed.

**Solution**: Early exit for known-finalized events.

```rust
// At start of proposal processing:
if let Some(request) = self.storage.get_request_by_event_hash(&proposal.event_hash)? {
    match request.decision {
        RequestDecision::Finalized => {
            debug!("Skipping proposal for finalized event");
            // Optionally send EventCompletedNotice
            return;
        }
        RequestDecision::Pending | RequestDecision::Approved => {
            // Check if we already signed
            if self.already_signed(&request.request_id)? {
                debug!("Already signed, skipping");
                return;
            }
            // Continue to sign (we started but didn't finish)
        }
        _ => {}
    }
}
```

---

### 11.3 EventCompletedNotice Message

**Problem**: Offline signer doesn't know events are already completed.

**Solution**: New message type to inform about completions.

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TransportMessage {
    SigningEventPropose(SigningEventPropose),
    SignerAck(SignerAck),
    PartialSigSubmit(PartialSigSubmit),
    FinalizeNotice(FinalizeNotice),
    FinalizeAck(FinalizeAck),
    EventCompletedNotice(EventCompletedNotice),  // NEW
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventCompletedNotice {
    pub event_hash: Hash32,
    pub tx_id: TransactionId,
    pub completed_by_peer: PeerId,
    pub timestamp_nanos: u64,
}
```

**Behavior**:
- When signer receives proposal for already-finalized event
- Send EventCompletedNotice instead of signing
- Proposer receives, learns event is done, aborts session

---

### 11.4 Pre-Submission UTXO Validation

**Problem**: Submitting transactions for already-spent UTXOs.

**Solution**: Check UTXOs before building final transaction.

```rust
async fn validate_utxos_available(&self, pskt: &PSKT) -> Result<bool, Error> {
    for input in &pskt.inputs {
        let outpoint = input.previous_outpoint();
        match self.kaspa_rpc.get_utxo_entry(outpoint).await? {
            Some(_) => continue,
            None => {
                warn!("UTXO not available: {:?}", outpoint);
                return Ok(false);
            }
        }
    }
    Ok(true)
}

// Before finalization:
if !self.validate_utxos_available(&pskt).await? {
    info!("UTXOs no longer available, aborting finalization");
    return Ok(()); // Graceful abort
}
```

---

## 12. Recommended Solutions

### 12.1 State Synchronization Protocol

**Problem**: Offline signer has stale state.

**Solution**: Sync protocol on startup.

```rust
// State summary for comparison
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSummary {
    pub event_count: u64,
    pub latest_event_hash: Option<Hash32>,
    pub state_hash: Hash32,  // Hash of all event_hashes
    pub timestamp_nanos: u64,
}

// Request state from peers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateRequest {
    pub requester_peer_id: PeerId,
    pub my_summary: StateSummary,
}

// Response with missing events
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateResponse {
    pub responder_peer_id: PeerId,
    pub missing_events: Vec<CompletedEventInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletedEventInfo {
    pub event_hash: Hash32,
    pub tx_id: TransactionId,
    pub completed_at_nanos: u64,
}

// On startup:
async fn sync_state_from_peers(&self) -> Result<(), Error> {
    let my_summary = self.compute_state_summary()?;

    // Broadcast state request
    let responses = self.request_peer_states(my_summary).await?;

    // Import missing events
    let mut imported = 0;
    for response in responses {
        for event_info in response.missing_events {
            if self.storage.get_event(&event_info.event_hash)?.is_none() {
                self.storage.mark_event_completed(
                    &event_info.event_hash,
                    &event_info.tx_id,
                )?;
                imported += 1;
            }
        }
    }

    info!("State sync complete: imported {} events", imported);
    Ok(())
}
```

---

### 12.2 Graceful Stale Event Handling

**Problem**: Processing stale events wastes resources.

**Solution**: Multi-layer early abort.

```rust
async fn process_event(&self, event: SigningEvent) -> Result<(), Error> {
    let event_hash = event_hash(&event)?;

    // Layer 1: Already in local DB?
    if self.storage.get_event(&event_hash)?.is_some() {
        if let Some(req) = self.storage.get_request_by_event_hash(&event_hash)? {
            if req.decision == RequestDecision::Finalized {
                debug!("Event already finalized locally, skipping");
                return Ok(());
            }
        }
    }

    // Layer 2: Ask peers if they know about this event
    if let Some(completion) = self.query_peers_for_event(&event_hash).await? {
        info!("Peers report event already completed: tx={}", completion.tx_id);
        self.storage.mark_event_completed(&event_hash, &completion.tx_id)?;
        return Ok(());
    }

    // Layer 3: Check UTXOs before full processing
    let utxos = self.select_utxos_for_event(&event).await?;
    if utxos.is_empty() {
        warn!("No UTXOs available for event, likely already spent");
        // Could query Kaspa for transaction history
        return Ok(());
    }

    // Proceed with normal processing
    self.process_event_internal(event, event_hash, utxos).await
}
```

---

### 12.3 Persistent Transaction Outbox

**Problem**: Transaction lost if all Kaspa nodes unreachable.

**Solution**: Store signed transactions for retry.

```rust
// New column family
pub const CF_TX_OUTBOX: &str = "tx_outbox";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub request_id: RequestId,
    pub event_hash: Hash32,
    pub serialized_tx: Vec<u8>,
    pub created_at_nanos: u64,
    pub last_attempt_nanos: u64,
    pub attempt_count: u32,
    pub last_error: Option<String>,
    pub status: OutboxStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OutboxStatus {
    Pending,
    Submitted { tx_id: TransactionId },
    Failed { reason: String },
}

// Background loop
async fn outbox_processor_loop(&self) {
    loop {
        let pending = self.storage.list_pending_outbox()?;

        for entry in pending {
            if entry.attempt_count > MAX_RETRIES {
                self.storage.mark_outbox_failed(&entry.request_id, "max retries")?;
                continue;
            }

            match self.submit_transaction(&entry.serialized_tx).await {
                Ok(tx_id) => {
                    self.storage.mark_outbox_submitted(&entry.request_id, tx_id)?;
                    info!("Outbox TX submitted: {}", tx_id);
                }
                Err(e) if e.is_utxo_spent() => {
                    // Someone else submitted, mark as done
                    self.storage.mark_outbox_submitted(&entry.request_id,
                        TransactionId::zero())?;  // Unknown tx_id
                }
                Err(e) => {
                    self.storage.increment_outbox_attempt(&entry.request_id, &e)?;
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
```

---

### 12.4 Health Monitoring

**Problem**: Silent failures go undetected.

**Solution**: Comprehensive health endpoints.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub node_id: PeerId,
    pub uptime_seconds: u64,

    // Component health
    pub storage_healthy: bool,
    pub transport_connected: bool,
    pub kaspa_reachable: bool,
    pub relayer_connected: bool,

    // Peer status
    pub connected_peers: Vec<PeerId>,
    pub peer_count: usize,

    // Activity metrics
    pub events_processed_today: u64,
    pub sessions_completed_today: u64,
    pub sessions_failed_today: u64,
    pub last_event_at: Option<u64>,
    pub last_submission_at: Option<u64>,

    // State summary
    pub total_events: u64,
    pub pending_sessions: u64,
    pub outbox_pending: u64,
}

// HTTP endpoint
async fn health_handler(State(app): State<AppState>) -> Json<HealthStatus> {
    let status = HealthStatus {
        node_id: app.local_peer_id.clone(),
        uptime_seconds: app.start_time.elapsed().as_secs(),
        storage_healthy: app.storage.health_check().is_ok(),
        transport_connected: app.transport.is_connected(),
        kaspa_reachable: app.rpc.ping().await.is_ok(),
        // ... etc
    };
    Json(status)
}
```

---

### 12.5 Configuration Consensus

**Problem**: Different configs cause split decisions.

**Solution**: Config hash in proposals.

```rust
// Compute deterministic config hash
fn config_hash(config: &AppConfig) -> Hash32 {
    let canonical = CanonicalConfig {
        sig_op_count: config.service.pskt.sig_op_count,
        hyperlane_validators: sorted(&config.hyperlane.validators),
        hyperlane_threshold: config.hyperlane.threshold,
        policy_hash: hash(&config.policy),
    };
    blake3::hash(&bincode::serialize(&canonical).unwrap())
}

// Include in proposal
pub struct SigningEventPropose {
    // ... existing fields
    pub coordinator_config_hash: Hash32,
}

// Signer validates
fn validate_config_match(&self, proposal: &SigningEventPropose) -> Result<(), Error> {
    let my_hash = config_hash(&self.config);
    if my_hash != proposal.coordinator_config_hash {
        warn!("Config mismatch detected!");
        // Could still proceed with warning, or reject
        // Recommend: proceed but log for operator attention
    }
    Ok(())
}
```

---

## 13. Implementation Roadmap

```
Phase 1: Critical Optimizations (Week 1-2)
├── 11.1 Reduce ack messages
├── 11.2 Skip already-processed proposals
├── 11.4 Pre-submission UTXO check
└── Basic health endpoint

Phase 2: Stale Event Handling (Week 3-4)
├── 11.3 EventCompletedNotice message
├── 12.2 Graceful stale event handling
└── Query peers for event status

Phase 3: State Synchronization (Week 5-6)
├── 12.1 State sync protocol
├── StateSummary computation
├── Peer state request/response
└── Startup sync routine

Phase 4: Reliability (Week 7-8)
├── 12.3 Persistent transaction outbox
├── Background submission retry
└── Outbox monitoring

Phase 5: Operations (Week 9-10)
├── 12.4 Full health monitoring
├── 12.5 Configuration consensus
├── Metrics and alerting
└── Runbook documentation
```

---

## Appendix A: Message Flow Diagrams

### A.1 Normal Operation (3 Signers, No Failures)

```
    A               B               C            Kaspa
    │               │               │              │
    │◄─ E from R-A  │               │              │
    │               │◄─ E from R-B  │              │
    │               │               │◄─ E from R-C │
    │               │               │              │
    ├──Propose────►├───────────────►│              │
    │◄──────────────┼──Propose──────►│              │
    │◄──────────────┼◄──Propose──────┤              │
    │               │               │              │
    ├──Ack─────────►│               │              │
    │◄──Ack─────────┤               │              │
    │◄──────────────┼◄──Ack─────────┤              │
    │               │               │              │
    ├──Sigs────────►├───────────────►│              │
    │◄──────────────┼──Sigs─────────►│              │
    │◄──────────────┼◄──Sigs────────┤              │
    │               │               │              │
    │ threshold!    │ threshold!    │ threshold!   │
    │               │               │              │
    ├───────────────┼───────────────┼──TX────────►│
    │               ├───────────────┼──TX────────►│ (rejected)
    │               │               ├──TX────────►│ (rejected)
    │               │               │              │
    ├──Finalize────►├───────────────►│              │
    │               │               │              │
```

### A.2 Signer A Crashes Mid-Session

```
    A               B               C            Kaspa
    │               │               │              │
    │◄─ E          │◄─ E          │◄─ E          │
    │               │               │              │
    ├──Propose────►│               │              │
    │   X CRASH     │               │              │
    │               │               │              │
    │               ├──Propose─────►│              │
    │               │◄─────Propose──┤              │
    │               │               │              │
    │               ├──Ack─────────►│              │
    │               │◄─────Ack──────┤              │
    │               │               │              │
    │               ├──Sigs────────►│              │
    │               │◄─────Sigs─────┤              │
    │               │               │              │
    │               │ threshold!    │ threshold!   │
    │               │               │              │
    │               ├───────────────┼──TX────────►│
    │               │               │              │
    │               ├──Finalize────►│              │
    │               │               │              │
                   SUCCESS without A!
```

### A.3 Stale Event Processing

```
    A (was offline)  B               C            Kaspa
    │                │               │              │
    │   (offline)    │◄─ E          │◄─ E          │
    │                ├──────────────►│              │
    │                │◄──────────────┤              │
    │                │     ...       │              │
    │                ├───────────────┼──TX────────►│
    │                │               │              │
    │                │ FINALIZED     │ FINALIZED    │
    │                │               │              │
    │ (comes online) │               │              │
    │◄─ E (stale!)  │               │              │
    │                │               │              │
    ├──Propose─────►│               │              │
    │                │               │              │
    │◄─EventCompleted (optimization)│              │
    │                │               │              │
    │ (aborts)      │               │              │
    │                │               │              │
```

---

## Appendix B: Testing Scenarios Checklist

### Unit Tests
- [ ] Event hash computation determinism
- [ ] Session ID derivation determinism
- [ ] Threshold calculation (exactly M, M+1, M-1)
- [ ] Config hash computation
- [ ] State summary computation

### Integration Tests
- [ ] Single signer crash during each phase
- [ ] Multiple proposals for same event
- [ ] Race to submit transaction
- [ ] Stale event rejection
- [ ] EventCompletedNotice flow
- [ ] State sync between peers
- [ ] Outbox retry logic

### Chaos Engineering
- [ ] Random signer termination
- [ ] Network partition simulation
- [ ] Kaspa node failure
- [ ] Relayer delayed delivery
- [ ] Clock skew injection
- [ ] Disk full simulation

---

## Appendix C: Monitoring Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Signer Offline | No health response for 5 min | HIGH |
| Session Failure Rate | >20% sessions timeout | MEDIUM |
| Kaspa Submission Failure | >5 consecutive failures | HIGH |
| State Divergence | Peer state hashes differ | MEDIUM |
| Stale Event Storm | >10 stale events in 1 min | MEDIUM |
| Outbox Backlog | >100 pending TXs | HIGH |
| Config Mismatch | Any signer reports mismatch | HIGH |
| Disk Usage | >80% disk used | MEDIUM |

---

## Appendix D: Operational Runbook

### D.1 Signer Won't Start

1. Check RocksDB integrity: `ls -la .igra/threshold-signing/`
2. Check disk space: `df -h`
3. Check logs for migration errors
4. If corrupted: restore from checkpoint or peer sync

### D.2 High Stale Event Rate

1. Check relayer configuration
2. Verify peer connectivity
3. Run manual state sync
4. Consider relayer event acknowledgment

### D.3 Transactions Not Confirming

1. Check Kaspa node connectivity
2. Verify UTXO availability
3. Check outbox status
4. Verify fee configuration

### D.4 State Divergence Detected

1. Identify which signer has older state
2. Trigger manual state sync
3. Investigate cause (crash, partition, etc.)
4. Monitor for recurrence
