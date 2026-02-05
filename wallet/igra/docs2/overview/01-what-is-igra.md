# What is Igra?

**Last Updated:** 2026-02-05

## Overview

Igra is a **leaderless threshold signature coordination system** designed for UTXO-based blockchains like Kaspa and Bitcoin. It solves the fundamental problem of getting multiple independent signers to agree on a single transaction when they may observe different blockchain states.

## The Problem

Imagine 5 people need to jointly sign a payment from a shared wallet:

**Challenge 1: Different Views**
- Alice's blockchain node shows UTXOs: `[A, B, C]`
- Bob's blockchain node shows UTXOs: `[A, B, D]` (different!)
- Without coordination, they build different transactions
- Result: Signatures fragment across incompatible transactions → **payment fails**

**Challenge 2: Multiple Events**
- Event 1 and Event 2 both try to spend UTXO `B`
- Signers process events in different orders
- Some spend `B` for Event 1, others for Event 2
- Result: Neither event completes

**Challenge 3: Safety vs Speed**
- Sign immediately → Risk of double-spending if views diverge
- Wait for perfect agreement → May wait forever

## The Solution

Igra uses a **two-phase voting protocol** combined with **CRDT-based signature collection**:

### Phase 1: Agree on Template (Two-Phase Coordination)
```
Round 1:
  Alice: "I propose template with hash H1" (votes, doesn't sign yet)
  Bob:   "I propose template with hash H1"
  Carol: "I propose template with hash H1"

  Result: 3/5 signers agreed on H1 → LOCK to H1

  Everyone now knows: "We're signing template H1 and ONLY H1"
```

### Phase 2: Collect Signatures (CRDT Merge)
```
  Alice: Signs template H1 → broadcasts signature
  Bob:   Signs template H1 → broadcasts signature
  Carol: Signs template H1 → broadcasts signature

  CRDT merges signatures from all signers
  When 3/5 signatures collected → Transaction complete!
```

## Key Properties

### ✅ Safety First
- **No double-signing**: Each signer signs at most ONE transaction per event
- **Quorum-based commitment**: Majority (>50%) must agree before signing
- **Explicit failures**: Better to fail explicitly than risk double-spend

### 🔄 Leaderless
- **No coordinator**: All signers participate equally
- **No single point of failure**: Any signer can be offline
- **No leader election overhead**: Start signing immediately

### 🌐 Cross-Chain Ready
- **Hyperlane**: M-of-N validator threshold signatures
- **LayerZero**: Single endpoint signature verification
- **Custom validators**: Extensible attestation framework

### 🛡️ Fault Tolerant
- **Crash failures**: Up to N-m signers can crash
- **Network partitions**: Protocol times out safely, doesn't double-spend
- **Message delays**: CRDT handles asynchronous delivery gracefully

## Real-World Analogy

Think of signing a legal document:

**Without Igra:**
- 5 people each get a different version of the contract
- Each person signs their version
- No single contract has enough signatures
- Deal falls through

**With Igra:**
- Everyone first agrees: "We're signing version #3"
- Once agreed, everyone signs version #3
- Signatures are collected until threshold reached
- Deal completes successfully

## Technical Overview (1-Minute Version)

1. **Event arrives** (e.g., "Pay 100 KAS to address X")
2. **Signers vote** on transaction template without signing
3. **Quorum reached** (>50% agree on same template hash)
4. **Signers sign** the agreed template
5. **CRDT merges** signatures from all signers
6. **Threshold reached** (m-of-n signatures collected)
7. **Transaction submitted** to blockchain

## Use Cases

### Cross-Chain Bridges
- Bridge 100 ETH from Ethereum → Kaspa
- Hyperlane validators attest to the Ethereum deposit
- Igra signers coordinate to release 100 WKAS on Kaspa

### Multi-Party Custody
- Company treasury held in 5-of-9 multisig
- 5 executives must approve large payments
- Igra ensures safe coordination even if they use different blockchain nodes

### Threshold Wallets
- Shared wallet between business partners
- Each partner runs own signer node
- Payments require m-of-n approval to execute

## What Igra Does NOT Do

❌ **Generate threshold keys** - Use external key generation ceremony
❌ **Validate event authenticity** - Relies on external validators (Hyperlane, etc.)
❌ **Run blockchain nodes** - Connects to existing Kaspa/Bitcoin nodes
❌ **Byzantine fault tolerance** - Current version assumes honest majority (BFT is future work)

## Architecture at a Glance

```
External Event → Validator Attestation → Igra Coordination → Blockchain Transaction
(Bridge msg)     (Hyperlane/LayerZero)   (2-Phase + CRDT)   (Kaspa/Bitcoin)
```

## Next Steps

- **Understand use cases**: [Use Cases](02-use-cases.md)
- **Learn how it works**: [How It Works](03-how-it-works.md)
- **Deploy quickly**: [Devnet Quickstart](../operators/deployment/01-quickstart-devnet.md)
- **Deep dive**: [Protocol Specification](../developers/architecture/02-protocol-specification.md)

## Key Terminology

| Term | Meaning |
|------|---------|
| **Signer** | A peer participating in threshold signature coordination |
| **Event** | A payment request to be executed (e.g., bridge withdrawal) |
| **Template** | An unsigned transaction specifying inputs/outputs |
| **Proposal** | A vote for a specific transaction template |
| **Quorum** | Majority threshold (>50%) required for commitment |
| **CRDT** | Conflict-free Replicated Data Type for signature merging |
| **Phase** | State of event processing (Proposing → Committed → Completed) |

---

**Ready to dive deeper?** Continue to [Use Cases](02-use-cases.md) →
