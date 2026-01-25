# Igra Protocol: Leaderless Two‑Phase Coordination with CRDT‑Based Threshold Signing

## Abstract

Igra is a leaderless protocol for coordinating threshold signature groups on UTXO-based blockchains. The protocol addresses the fundamental problem of maintaining safety when multiple independent signers must agree on a single transaction template despite observing potentially inconsistent UTXO sets from their respective blockchain nodes. We present a two-phase coordination mechanism combined with CRDT-based signature propagation that ensures at most one transaction is signed per event, even under crash faults and temporary network partitions. The protocol guarantees safety under crash-fault assumptions with non-equivocating signers, and we provide formal correctness proofs for unique commitment, deterministic agreement, and CRDT convergence. We validate the theoretical model through a reference implementation deployed on the Kaspa blockchain.

## 1. Introduction

### 1.1 The UTXO Coordination Problem

**UTXO model background.** In UTXO-based blockchains (Bitcoin, Kaspa, Litecoin, etc.), transactions consume specific unspent transaction outputs (UTXOs) as inputs and create new outputs. Unlike account-based models (Ethereum), UTXO chains lack global shared state and smart contract programmability for coordination logic. Each node independently maintains its own UTXO set view, and temporary inconsistencies arise from:
- Network propagation delays between geographically distributed nodes
- Temporary chain reorganizations (forks) before probabilistic finality
- Node synchronization lag during initial sync or after downtime
- Conflicting transactions pending in different mempools
- Variable block confirmation times (Kaspa: 1 sec, Bitcoin: 10 min)

**Lack of programmability.** UTXO chains, by design, do not support Turing-complete smart contracts at the base layer. Bitcoin Script and Kaspa TxScript are intentionally limited: they provide signature verification and time-locks but not general computation or persistent state. This means coordination logic *cannot be implemented on-chain*. Proposed solutions like covenants and extended UTXO models (Cardano) add expressiveness but do not solve the fundamental distributed coordination problem for threshold signers operating across independent nodes.

**Multi-dimensional coordination problem.** When $N$ independent signers must coordinate to produce an $m$-of-$N$ threshold signature on a payment transaction, they face *multiple sources of divergence*:

1. **UTXO set divergence**: Each signer queries their local blockchain node and may observe a *different UTXO set*. Even with eventual consistency, signers may build templates at different times and select different UTXOs as inputs.

2. **Event ordering divergence**: Payment events arrive from external sources (bridges, oracles, APIs) via asynchronous delivery. Signers may observe events in *different orders*: signer $A$ sees $(e_0, e_1, e_2)$ while signer $B$ sees $(e_1, e_0, e_2)$. If events $e_0$ and $e_1$ could both spend the same UTXO, signing them in different orders leads to different UTXO availability and thus different templates.

3. **Concurrent event contention**: Multiple simultaneous events may compete for the same UTXOs. Without coordination, signers may assign a UTXO to different events, fragmenting signatures across incompatible templates.

4. **Temporal skew**: Signers process events at different wall-clock times due to processing delays, network latency, or crash-recovery cycles. A signer joining late may see an already-spent UTXO as available, proposing an invalid template.

If signers independently build transaction templates without coordination, they will almost certainly select different UTXOs, producing incompatible templates and fragmenting the signature set.

**Safety vs. liveness trade-off.** This creates a fundamental dilemma:
- **Optimistic approach**: Sign immediately without coordination. *Risk*: Signature fragmentation (liveness failure) when templates diverge. Worse: if some signers later observe updated UTXO sets and re-sign alternate templates, the group may sign *multiple distinct transactions* spending different UTXOs (double-spend, safety violation).
- **Conservative approach**: Wait for perfect UTXO convergence and event ordering agreement. *Risk*: Under prolonged divergence, high event throughput, or network partitions, convergence may never occur (indefinite liveness failure).

**Why existing approaches are insufficient.**

*1. Leader-based coordination (Raft, Paxos, PBFT with rotating leader):*

Leader-based protocols elect a single coordinator responsible for UTXO selection and template construction. While conceptually simple, this introduces several critical problems:

- **Single point of failure**: If the leader crashes, the system halts until a new leader is elected. Leader election itself requires multiple rounds of consensus, adding latency. For high-frequency payment systems, this is unacceptable.

- **Single point of compromise**: A compromised leader can censor events, delay payments, or propose malicious templates. Even with eventual detection and leader replacement, attacks during the leader's tenure can cause service disruption.

- **Per-event election overhead**: Running leader election per event adds $O(\log N)$ message rounds and coordination delay before every transaction. This is particularly costly for systems handling thousands of events per hour.

- **Per-time-frame coordination complexity**: Batching events into epochs with one leader per epoch requires:
  - Synchronizing epoch boundaries across asynchronously-arriving events
  - Buffering events, reducing responsiveness
  - Handling epoch transitions (leader changes mid-batch)
  - Resolving conflicts when epochs overlap or UTXO availability changes between epochs

- **Degraded performance under faults**: Leader-based protocols degrade significantly when leaders are slow, malicious, or crash. Leaderless approaches avoid this performance cliff.

- **Reduced decentralization**: Concentrating coordination power in a single leader contradicts the decentralization ethos of threshold signature schemes, where security relies on distributing trust across $N$ independent parties.

*2. On-chain coordination via smart contracts:*

Using the destination UTXO chain itself for coordination (e.g., writing proposed templates to the blockchain) creates circular dependencies:
- Requires threshold signatures to write coordination state to the chain
- But coordination is needed to agree on which transaction to sign
- UTXO chains lack persistent contract state for multi-round protocols
- High on-chain costs (every proposal = on-chain transaction)

*3. Centralized coordinator service:*

Delegating coordination to a trusted centralized service:
- Reintroduces trust assumptions beyond the cryptographic threshold scheme
- Single point of failure and compromise
- Requires out-of-band mechanisms to ensure coordinator honesty
- Defeats the purpose of decentralized threshold signing

*4. Optimistic execution without coordination:*

Signing templates immediately without agreement:
- Works only if all signers observe identical UTXO sets simultaneously
- Fails under divergence: partial signatures scatter across incompatible templates
- No mechanism to recover from fragmentation
- Risk of double-spend if signers re-sign on updated views

**Robustness requirements.** A practical threshold signing system for UTXO chains must achieve:
1. **Safety**: At most one transaction is ever signed per payment request, even under UTXO divergence and event reordering.
2. **Liveness**: The system makes progress when possible (sufficient honest signers online, eventual UTXO convergence).
3. **Resilience**: Tolerate crash failures, message loss, temporary network partitions, and event ordering differences.
4. **Decentralization**: No single point of failure; all signers participate equally in coordination.
5. **Security**: Resist replay attacks, Sybil attacks, message forgery, and event injection.
6. **Auditability**: Explicit success/failure states; deterministic event-to-transaction mapping.

### 1.2 Design Principle

Igra's fundamental invariant is:

> **Single-signature per event**: Each signer signs at most one transaction template per unique event identifier.

This ensures that even if coordination fails, safety is preserved—no double-spending can occur.

### 1.3 Protocol Overview and Design Rationale

Igra combines two complementary protocols to address distinct aspects of the threshold signing coordination problem.

#### Two Sub-Problems

The coordination challenge decomposes into two independent problems:

**Problem A (Agreement).** Given $N$ signers with potentially divergent UTXO views and asynchronous event delivery, agree on exactly one transaction template to sign.

**Problem B (Collection).** After agreeing on a template, collect $m$ partial signatures from the $N$ signers and merge them into a finalized transaction.

These problems have fundamentally different requirements:
- Agreement requires **consensus** (all signers must converge to the same decision despite divergence)
- Collection requires **convergence** (signatures from different signers must be merged without additional coordination)

#### Two-Phase Protocol (Solves Problem A: Agreement)

**Design.** Igra uses a two-phase voting protocol inspired by quorum-based consensus systems (PBFT, Paxos, 2-phase commit):

1. **Phase 1 (Proposing)**: Each signer independently builds a transaction template from their local UTXO view and broadcasts a vote for the template's hash—*without signing the transaction yet*.

2. **Phase 2 (Committed)**: A signer commits to a template hash $h$ only after observing that $\ge q$ distinct signers voted for $h$, where $q > N/2$ is the commit quorum.

**Key insight: Quorum intersection.** With $q > N/2$, at most one template hash can achieve quorum in a given round (Theorem 1). This ensures that even if signers observe different proposal sets due to message delays, they cannot commit to conflicting templates.

**Why vote before signing?** The vote phase acts as a **coordination barrier**. Signers do not produce cryptographic signatures (which are irrevocable commitments) until they observe majority agreement. This prevents signature fragmentation: if signers immediately signed their locally-built templates, partial signatures would scatter across incompatible templates, and no template would reach threshold.

**Deterministic selection.** If network delays cause some signers to observe quorum for hash $h$ before others, the deterministic canonical selection function ensures all signers eventually select the same $h$ when they observe the same quorum votes (Theorem 2). This handles asynchronous message delivery gracefully.

**Retries with randomization.** If no hash reaches quorum in round $r$ (e.g., votes split 50-50), the protocol increments $r$ and retries. Different rounds use different deterministic seeds for UTXO selection:
$$
\mathit{seed}_r = \mathcal{H}(\mathit{event\_id} \,\|\, r)
$$
This changes the UTXO ordering each round, increasing the probability that signers converge on overlapping UTXO selections in subsequent rounds.

**Comparison to alternatives:**
- **Paxos/Raft**: Require leader election (single point of failure). Igra is leaderless: all signers propose simultaneously.
- **PBFT**: Requires $N \ge 3f+1$ for Byzantine tolerance. Igra achieves safety under crash faults with $N \ge 2f+1$ (majority quorum).
- **Nakamoto consensus**: Requires mining or staking infrastructure. Igra uses direct voting with authenticated peers.

**Established primitive.** Quorum systems have been extensively studied in distributed systems literature. The property that majority quorums ($q > N/2$) intersect is foundational to Paxos, viewstamped replication, and PBFT. Igra applies this principle to UTXO template selection rather than state machine replication.

#### CRDT Signature Protocol (Solves Problem B: Collection)

**Design.** After committing to template hash $h$, signers transition to signature collection using a conflict-free replicated data type (CRDT):

- **Signature set $\Sigma$**: Modeled as a Grow-only Set (G-Set). Each element is a partial signature keyed by $(\mathit{input\_idx}, \mathit{pubkey})$.
- **Merge semantics**: Set union. When a signer receives signatures from peers via gossip, it merges them via $\Sigma \leftarrow \Sigma \cup \Sigma'$.
- **Threshold detection**: Any signer can locally check if $\Sigma$ contains $\ge m$ signatures per input.
- **Finalization**: Once threshold is observed, any signer may apply signatures to the template, finalize the transaction, and submit to the blockchain.

**Key insight: Coordination-free after commitment.** Because all signers committed to the **same template hash $h$**, they are signing the **same transaction skeleton**. Signatures are deterministic (same input digest produces same signature given the same key). Therefore, signature collection is purely a **data propagation problem**, not a consensus problem. CRDTs are designed precisely for this: replicated data that converges without requiring agreement protocols.

**Why CRDT instead of consensus?** After the 2-phase commitment, running another consensus protocol (e.g., Paxos for each signature) would be wasteful. CRDTs provide:
- **Low overhead**: Merge is local computation (set union), no quorum voting needed.
- **Graceful handling of delays**: Late signatures are merged whenever they arrive; no timeouts required.
- **Crash resilience**: If a signer crashes after signing, its signature persists in other signers' CRDT states and continues to propagate.
- **Leaderless finalization**: Any signer can finalize once threshold is locally observed; no need to elect who submits.

**Concurrent finalization safety.** Multiple signers may simultaneously observe threshold and attempt finalization. This is safe because:
- Deterministic signature application produces identical transaction bytes.
- Blockchain treats duplicate submissions as idempotent (same transaction ID).
- The completion CRDT uses a last-writer-wins (LWW) register to merge competing completion records, ensuring eventual consistency.

**Comparison to alternatives:**
- **Request-reply signature collection**: Requires $O(N^2)$ messages and doesn't handle crashes. CRDT allows any subset of $m$ signers to complete.
- **Leader-based collection**: Single point of failure for finalization. CRDT allows any signer to finalize.
- **Blockchain-based collection**: Every signature as an on-chain transaction is prohibitively expensive. CRDT uses off-chain gossip.

**Established primitive.** CRDTs are well-studied in distributed systems. G-Sets (grow-only sets) and LWW-Registers are proven to converge under eventual delivery. Igra applies G-Set to partial signature replication and LWW-Register to completion status. These are standard CRDT types with known convergence properties.

#### Why Combine 2-Phase and CRDT?

**Synergy.** The combination is efficient and fault-tolerant:
1. **2-phase ensures safety** by preventing early signing on divergent templates.
2. **CRDT ensures liveness** by collecting signatures without additional coordination overhead.

**Efficiency.** Running 2-phase for both agreement and collection would require $O(m)$ consensus rounds (two phases per signature). With CRDT, we need **only 1 consensus round** (the 2-phase for template agreement), then signature collection is coordination-free.

**Fault tolerance:**
- 2-phase tolerates up to $N - q$ crash failures during voting (quorum can still be reached).
- CRDT tolerates up to $N - m$ crash failures during signing (threshold can still be reached by remaining signers).

#### Reliance on Established Theory

Igra composes well-understood primitives:

| Primitive | Source | Property | Used For |
|-----------|--------|----------|----------|
| Majority quorums | Gifford 1979 | $q > N/2$ intersect | Template agreement |
| 2-phase voting | Gray 1978 | Vote before commit | Proposal coordination |
| G-Set (CRDT) | Shapiro 2011 | Converges via union | Signature collection |
| LWW-Register | Shapiro 2011 | Converges via max | Completion status |
| Gossip | Demers 1987 | Eventual delivery | Message dissemination |

**Theoretical foundation.** All safety and convergence properties in Igra reduce to properties of these primitives. Theorem 1 (unique quorum) follows from quorum intersection. Theorem 3 (CRDT convergence) follows from G-Set properties. We do not introduce new assumptions beyond standard partial synchrony and crash-fault models.

#### Contribution

The contribution is **not** inventing new consensus mechanisms. Rather:

1. **Problem formulation**: Formally defining the UTXO threshold signing coordination problem, including UTXO divergence, event ordering divergence, and lack of on-chain programmability.

2. **Protocol composition**: Showing that 2-phase consensus + CRDT signature collection is a correct and efficient solution to this specific problem.

3. **Leaderless safety**: Proving that this combination achieves safety (no double-spend) without requiring leader election or rotating coordinators.

4. **Practical validation**: Implementing and deploying the protocol on a real UTXO chain (Kaspa), demonstrating feasibility.

Prior work on threshold signatures (MuSig2, FROST, GG20) focuses on *cryptographic protocols* (how to generate threshold signatures). Igra addresses *coordination* (when to sign, which transaction to sign) in the presence of divergent distributed state. These are orthogonal problems: Igra could use MuSig2 or FROST as the signature scheme while keeping the 2-phase + CRDT coordination layer unchanged.

### 1.4 System Architecture

```
┌──────────────────────────────────────────┐
│   EVENT SOURCE (e.g., EVM + Hyperlane)   │
│   - External payment/bridge system       │
└────────────────┬─────────────────────────┘
                 │ event
                 ▼
┌──────────────────────────────────────────┐
│         VALIDATOR SET (m-of-n)           │
│   - Attest to event authenticity         │
│   - Economic security (staking/slashing) │
└────────────────┬─────────────────────────┘
                 │ event + validator signatures
                 ▼
┌──────────────────────────────────────────┐
│      IGRA SIGNER NODES (N nodes)         │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │ 1. Event Ingestion                 │  │
│  │    - Verify validator sigs (≥T)    │  │
│  │    - Check policy constraints      │  │
│  └──────────────┬─────────────────────┘  │
│                 ▼                        │
│  ┌────────────────────────────────────┐  │
│  │ 2. Two-Phase Coordinator           │  │
│  │    - Query UTXO node               │  │
│  │    - Build template (deterministic)│  │
│  │    - Vote via gossip               │  │
│  │    - Commit on quorum              │  │
│  └──────────────┬─────────────────────┘  │
│                 ▼                        │
│  ┌────────────────────────────────────┐  │
│  │ 3. CRDT Signing                    │  │
│  │    - Sign committed template       │  │
│  │    - Merge partial signatures      │  │
│  │    - Finalize when threshold met   │  │
│  └──────────────┬─────────────────────┘  │
│                 │                        │
│  ┌──────────┐  │  ┌──────────────────┐  │
│  │ RocksDB  │◄─┼─►│ Gossip Network   │  │
│  │ Storage  │  │  │ (Ed25519 auth)   │──┼──► Other Igra Nodes
│  └──────────┘  │  └──────────────────┘  │    (P2P sync)
│                 │                        │
└─────────────────┼────────────────────────┘
                  │ submit threshold-signed transaction
                  ▼
┌──────────────────────────────────────────┐
│   UTXO DESTINATION CHAIN (e.g., Kaspa)   │
│   - Execute payment to destination       │
└──────────────────────────────────────────┘
```

**Key design elements:**
- **Validator-set abstraction**: Any external attestation system with threshold signatures (Hyperlane, LayerZero, custom oracles)
- **UTXO-agnostic coordination**: Protocol handles any UTXO chain (Kaspa, Bitcoin, etc.)
- **Authenticated gossip**: Peer-to-peer coordination without trusted third parties
- **Deterministic finalization**: Any node can submit once threshold reached

### 1.5 Contributions

- A leaderless coordination protocol for UTXO threshold signing that guarantees safety under crash faults
- Formal proofs of unique commitment and CRDT convergence
- A reference implementation on Kaspa blockchain validating the theoretical model

## 2. System Model and Trust Assumptions

### 2.1 Entities and Roles

**Signers.** A fixed group of $N$ peers. Each peer has a stable identifier $p_i \in \mathcal{P}$ and participates in a gossip network.

**Blockchain.** Each signer maintains a connection to a blockchain node providing:
- UTXO query interface
- Transaction submission interface
- Block height/finality information

**Event Sources.** External systems that produce signing requests (e.g., cross-chain bridges, payment systems).

**Validators.** External entities (e.g., Hyperlane validator set, LayerZero endpoints) that attest to the authenticity of cross-chain events.

### 2.2 Trust Assumptions

#### 2.2.1 Event Authenticity

**Core concept: Validator sets.** Igra accepts payment events from external sources (cross-chain bridges, payment systems, oracles, etc.) provided they are attested by a *trusted validator set*. The key abstraction is a set of public keys and a threshold verification rule, independent of the specific event source.

**Assumption**: Events are authenticated by cryptographic signatures from an external validator set configured at system deployment.

**Enforcement**: Each event includes cryptographic proofs (signatures) from validators. The protocol verifies these proofs before accepting an event.

**Validator models (examples)**:

*Hyperlane-style (m-of-n threshold)*:
- Configure $M$ validator public keys (secp256k1 ECDSA)
- Require $\ge T$ valid signatures where $T \le M$
- Each validator independently signs the message identifier
- Rejection: If fewer than $T$ signatures verify correctly

*LayerZero-style (single endpoint)*:
- Configure endpoint public key (secp256k1 ECDSA)
- Require exactly one valid signature from the endpoint
- Rejection: If signature verification fails

*Custom oracle or payment provider*:
- Configure provider-specific public keys and threshold rules
- Implement signature verification logic for provider's attestation format

**Trust boundary**: We trust that:
1. The configured validator set is honest (or at least $T$ of $M$ validators are honest)
2. Validators will not collude to create fraudulent events
3. Validator public keys in configuration are correct and belong to legitimate validators

This trust is *external to Igra*—it is inherited from the event source's security model (e.g., Hyperlane's economic security via staked validators and slashing).

**Why this is acceptable**: Cross-chain messaging protocols, oracles, and payment systems typically use economic security (staking), cryptoeconomic incentives (slashing), and redundancy (Byzantine quorums) to ensure honest attestation. Igra inherits and leverages these existing security mechanisms rather than reimplementing attestation infrastructure. The protocol is *validator-set agnostic*: any event source with threshold signature attestation can be integrated.

#### 2.2.2 Key Management

**Assumption**: Each signer's private key is securely generated, stored, and accessed only by authorized processes.

**Key derivation** (industry standard):
- BIP39 mnemonic phrases (12-24 words)
- BIP32 hierarchical deterministic (HD) derivation
- Optional BIP44/BIP84 derivation paths
- Schnorr-compatible key extraction (x-only public keys)

**Key storage**:
- Private keys encrypted with XChaCha20Poly1305 authenticated encryption
- Encryption key sourced from environment variable or secure file
- Keys exist in memory only during signing operations
- Memory zeroed after use (Rust `Zeroize` trait)

**Trust boundary**: We assume:
1. The encryption key (`WALLET_SECRET`) is kept secret
2. No unauthorized access to process memory during signing
3. No unauthorized access to encrypted key files
4. The operating system enforces process isolation

**Current limitation**: No hardware security module (HSM) support. Keys exist in process memory during signing, making them vulnerable if the process is compromised or memory is dumped.

**Why this is acceptable for threshold systems**: Even if one key is compromised, threshold $m$ requires compromising $m$ independent keys to forge signatures. The threshold property provides defense-in-depth.

#### 2.2.3 Peer Authentication

**Assumption**: The gossip network consists only of authorized signers.

**Enforcement**:
- Each peer has an Ed25519 keypair for message authentication
- Static whitelist of trusted peer public keys configured at startup
- All gossip messages signed; signatures verified against whitelist
- Unauthenticated messages are rejected before processing

**Trust boundary**: We trust that:
1. Configured peer public keys are correct (map peer IDs to actual signers)
2. Peer private keys are kept secret
3. No peer private key has been compromised

**Sybil resistance**: The static whitelist prevents Sybil attacks—an attacker cannot inject fake peers without compromising a legitimate peer's private key.

#### 2.2.4 Storage Integrity

**Assumption**: Persistent storage is not tampered with.

**Production storage**: RocksDB on local filesystem
- Proposals, CRDT state, phase state persisted to disk
- No encryption at rest for database files
- File system permissions expected to prevent unauthorized access

**Trust boundary**: We trust that:
1. The operating system enforces file permissions
2. No unauthorized process can read/write RocksDB files
3. Database files are not corrupted or tampered with

**Testing storage**: In-memory storage used only for automated tests; never used in production deployments.

#### 2.2.5 Blockchain Node Trust

**Assumption**: Each signer's local blockchain node provides eventually-consistent UTXO data.

**Trust model**:
- Nodes may temporarily disagree on UTXO sets (reorgs, sync lag)
- Nodes eventually converge to canonical chain state
- Nodes do not intentionally lie about UTXO availability

**Why this is acceptable**: The two-phase protocol is specifically designed to handle temporary UTXO divergence. If nodes permanently diverge, the protocol abandons the event rather than risking double-spend.

**Blockchain finality**: We trust the underlying blockchain's consensus mechanism. For Kaspa, this is GHOSTDAG with probabilistic finality based on blue score depth.

### 2.3 Threat Model (Non-Byzantine, Crash-Fault)

We assume **crash-fault tolerance**:

- **Honest majority**: At least $\lceil N/2 \rceil + 1$ signers are correct.
- **Non-equivocation**: Correct signers do not send conflicting proposals for the same $(event, round)$ pair.
- **Crash failures**: Signers may crash and be temporarily unreachable.
- **Message reordering**: Network may delay, duplicate, or reorder messages.

**Byzantine behavior** (intentional misbehavior) is considered a limitation and discussed in Section 4.4.

### 2.4 Network Model

We assume **partial synchrony**:

- There exists an unknown Global Stabilization Time (GST) and bound $\Delta$ such that messages broadcast by correct peers at time $t \ge \mathrm{GST}$ are delivered within time $\Delta$.
- Messages before GST may experience unbounded delay.
- Gossip ensures eventual delivery among connected correct peers.

### 2.5 Cryptographic Assumptions

The adversary is computationally bounded and cannot:
- Find hash collisions in BLAKE3 (128-bit security)
- Forge signatures without private keys:
  - Ed25519 for message envelopes (128-bit security)
  - secp256k1 Schnorr for blockchain transactions (128-bit security)
  - secp256k1 ECDSA for validator attestations (128-bit security)

### 2.6 Problem Statement

**Input.** A canonical event $e$ describing:
- Unique identifier
- Destination (blockchain address/script)
- Amount to transfer

**Output.** At most one valid blockchain transaction $T$ corresponding to event $e$ that is signed by threshold signers and submitted to the blockchain.

**Safety requirement.** No two distinct transactions $T_1 \ne T_2$ for the same event $e$ are both signed by threshold signers.

**Liveness requirement.** If sufficient honest signers are online and their nodes converge on a consistent UTXO view, the event eventually completes or is explicitly abandoned.

## 3. Protocol Specification

### 3.1 Core Data Structures

#### Event Identifier

An **event** is a canonical payment request. The event identifier is computed deterministically:

$$
\mathit{event\_id} := \mathcal{H}(\mathit{domain} \,\|\, \mathit{encode}(e))
$$

where $\mathcal{H}$ is a cryptographic hash function (BLAKE3), $\mathit{domain}$ is a protocol version string, and $\mathit{encode}$ serializes the event fields.

#### Transaction Template

A **transaction template** $\tau$ is an unsigned transaction specifying:
- Input set: $\{(\mathit{txid}_j, \mathit{index}_j, \mathit{amount}_j)\}$ (UTXO references)
- Output set: $\{(\mathit{destination}_k, \mathit{amount}_k)\}$
- Metadata: fees, lock times, etc.

The **template identifier** is:

$$
\mathit{template\_id} := \mathcal{H}(\mathit{canonical}(\tau))
$$

where $\mathit{canonical}$ produces a deterministic serialization of the template.

#### Proposal (Vote)

A **proposal** is a vote for a specific template in a round:

$$
\pi := (\mathit{event\_id}, r, h, \tau_{\mathit{blob}}, p, t)
$$

where:
- $r \in \mathbb{N}$: round number
- $h$: template identifier (hash)
- $\tau_{\mathit{blob}}$: serialized template
- $p \in \mathcal{P}$: proposer peer id
- $t$: timestamp

#### Phase State

Each peer maintains local phase state for each event:

$$
\phi := (\mathit{phase}, r, h_{\mathit{canon}}, h_{\mathit{own}})
$$

where:
- $\mathit{phase} \in \{\mathtt{Unknown}, \mathtt{Proposing}, \mathtt{Committed}, \mathtt{Completed}, \mathtt{Failed}, \mathtt{Abandoned}\}$
- $r$: current round
- $h_{\mathit{canon}}$: committed template hash (once locked)
- $h_{\mathit{own}}$: own proposed hash

#### CRDT State

For each $(event\_id, template\_id)$ pair, peers maintain a replicated CRDT:

$$
\mathcal{S} := (\Sigma, C, M, B)
$$

where:
- $\Sigma$: G-Set of signature records, keyed by $(\mathit{input\_idx}, \mathit{pubkey})$
- $C$: LWW-Register for completion status
- $M$: Optional event metadata
- $B$: Optional template blob

### 3.2 Protocol Invariants

**Invariant I1 (Phase Monotonicity).**
Peers never transition backward from terminal states $\mathtt{Completed}$ or $\mathtt{Abandoned}$.

**Invariant I2 (Single Vote per Round).**
For any $(event\_id, r)$, each peer $p_i$ contributes at most one proposal.

**Invariant I3 (Single Signature per Event).**
Each peer signs at most one template hash per $event\_id$.

**Invariant I4 (Commit Irreversibility).**
Once a peer records $h_{\mathit{canon}}$ for an event, it never changes to a different hash.

### 3.3 Two-Phase Coordination Protocol

#### Phase 1: Proposing

Upon receiving an event $e$:

1. **Validate external proofs**: Verify validator signatures against configured public keys. Require threshold $T$ valid signatures (Hyperlane) or single endpoint signature (LayerZero). Reject if validation fails.

2. **Check policy**: Verify amount limits, destination whitelist, velocity limits. Reject if policy violated.

3. Compute $\mathit{event\_id}$

4. Query local blockchain node for available UTXOs

5. Build transaction template $\tau$ using deterministic UTXO selection:
   $$
   \mathit{seed} := \mathcal{H}(\mathit{event\_id} \,\|\, r)
   $$

6. Compute $h := \mathit{template\_id}(\tau)$

7. Broadcast proposal $\pi := (\mathit{event\_id}, r, h, \tau_{\mathit{blob}}, p_i, t)$

#### Proposal Validation

Upon receiving proposal $\pi$ from peer $p_j$:

1. **Authenticate sender**: Verify Ed25519 signature on message envelope against $p_j$'s configured public key. Reject if invalid.

2. **Replay protection**: Check if $(p_j, session\_id, seq\_no)$ already seen. Reject duplicates.

3. **Rate limiting**: Check per-peer message rate. Reject if limit exceeded.

4. **Structural bounds**: Template size $\le$ maximum

5. **Event consistency**: Recompute $\mathit{event\_id}$ from included event data; verify match

6. **Template consistency**: $h = \mathit{template\_id}(\tau_{\mathit{blob}})$

7. **Policy constraints**: Re-verify policy on included event

8. **External proofs**: Re-verify validator signatures on included event

#### Vote Storage and Equivocation Detection

Proposals are keyed by $(event\_id, r, p)$. If peer $p$ sends two proposals with distinct hashes for the same $(event\_id, r)$, the second is rejected as equivocation.

**Enforcement.** Storage returns an $\mathtt{Equivocation}$ error; the conflicting proposal is logged but not counted in the vote set.

**Limitation under non-Byzantine model**: A Byzantine peer can send conflicting proposals to different peers before gossip converges. The protocol assumes this does not occur (non-equivocating signers assumption).

#### Phase 2: Committed

**Commit rule.** Let $V_h$ be the set of distinct proposers who voted for hash $h$ in round $r$. A peer may commit to $h$ iff:

$$
|V_h| \ge q
$$

where $q$ is the commit quorum threshold.

**Canonical selection.** If multiple hashes satisfy quorum (impossible when $q > N/2$), select deterministically:

1. Prefer hash with highest vote count
2. Tie-break by numerically smaller hash
3. Tie-break by lexicographically smaller proposer id
4. Among tied proposals, select by minimal deterministic score:
   $$
   \mathit{score} := \mathcal{H}(\mathit{domain} \,\|\, \mathit{event\_id} \,\|\, r \,\|\, p)
   $$

**Lock.** Upon commitment, set $h_{\mathit{canon}} := h$ and transition to $\mathtt{Committed}$ phase.

### 3.4 CRDT Signature Protocol

#### Signature Generation

Once committed to template hash $h$, each peer:

1. Retrieves template $\tau$ corresponding to $h$
2. **Derive signing key**: Use BIP32 HD derivation from encrypted mnemonic
3. For each input $i$ in $\tau$, computes signature $\sigma_i$ over input digest
4. Broadcasts signature records to CRDT (via authenticated gossip)

**Key management trust**: The signing key is derived from an encrypted mnemonic stored locally. We assume:
- The mnemonic was generated with sufficient entropy (industry standard: 128-256 bits)
- The encryption key is kept secret
- No unauthorized access to process memory during signing

#### CRDT Merge Semantics

**Signature Set (G-Set).** Merge is set union:
$$
\Sigma \leftarrow \Sigma \cup \Sigma'
$$

De-duplication by key $(\mathit{input\_idx}, \mathit{pubkey})$ ensures at most one signature per signer per input.

**Completion (LWW-Register).** For completion records $C = (\mathit{txid}, p, t, \ldots)$ and $C' = (\mathit{txid}', p', t', \ldots)$:

$$
\mathit{merge}(C, C') :=
\begin{cases}
C & \text{if } t \ge t', \\
C' & \text{otherwise.}
\end{cases}
$$

**Template Blob.** First valid non-empty value is kept (validated against $h$).

#### Threshold Satisfaction

**Definition (Threshold Predicate).**
Let $m$ be the signature threshold and $I$ the number of inputs. The threshold predicate holds iff:
$$
\forall i \in \{0, \ldots, I-1\}: \left|\{(\sigma, p) \mid (\sigma, p) \in \Sigma_i\}\right| \ge m
$$
where $\Sigma_i$ is the set of signatures for input $i$.

#### Finalization and Submission

When threshold is observed, any peer may:

1. Apply signatures from $\Sigma$ to template $\tau$
2. Finalize into signed transaction $T$
3. Submit $T$ to blockchain
4. Record completion: $C := (\mathit{txid}(T), p_i, t_{\mathit{now}}, \mathit{chain\_tip})$

**Concurrent finalization.** Multiple peers may finalize simultaneously. This is safe:
- Deterministic signature application produces identical $T$
- Blockchain treats duplicate submissions as idempotent (same txid)
- LWW merge on completion ensures convergence

### 3.5 Fast-Forward Mechanism

A peer receiving a committed CRDT state can bypass local proposal construction by:
1. **Re-validating external proofs** on the included event
2. **Re-verifying template hash** against included template blob
3. **Re-checking policy** constraints

If all checks pass, jump directly to $\mathtt{Committed}$ phase. This supports late-joining peers without requiring trusted setup.

### 3.6 Anti-Entropy and Retries

**Anti-entropy.** Peers periodically sync CRDT state via request/response to repair missed messages.

**Rate limiting**: Sync requests are rate-limited per peer (10 messages/second sustained, 100 message burst).

**Retries.** If quorum not reached within timeout, increment round $r := r+1$ and return to proposing phase. After bounded retries (configurable, typically 5-10 rounds), mark event as $\mathtt{Abandoned}$.

## 4. Correctness Analysis

### 4.1 Safety: Unique Commitment

**Theorem 1 (Unique Quorum Hash).**
Fix an event and round. Assume Invariant I2 (single vote per round) and $q > N/2$. Then at most one template hash $h$ satisfies $|V_h| \ge q$.

**Proof.**
Assume for contradiction that distinct hashes $h \ne h'$ both satisfy $|V_h| \ge q$ and $|V_{h'}| \ge q$.

By Invariant I2, each peer votes once per round. A vote for $h$ cannot simultaneously vote for $h' \ne h$, thus $V_h \cap V_{h'} = \emptyset$.

Total votes: $|V_h| + |V_{h'}| \ge 2q > N$, contradicting $N$ total peers. $\square$

**Theorem 2 (Agreement on Committed Hash).**
Let peer $A$ commit to hash $h$ in round $r$ based on proposal set $P_r$. Let peer $B$ later observe $P'_r \supseteq P_r$. Under Invariant I2 and $q > N/2$, peer $B$ selects the same hash $h$.

**Proof.**
Peer $A$ committed to $h$ with $|V_h| \ge q$ in $P_r$. Since $P'_r \supseteq P_r$, all votes for $h$ are present in $P'_r$, thus $V_h \subseteq V'_h$ and $|V'_h| \ge q$.

By Theorem 1 applied to $P'_r$, no distinct $h' \ne h$ satisfies quorum. The deterministic selection function filters to quorum hashes and selects among them canonically. Since only $h$ qualifies in $P'_r$, peer $B$ selects $h$. $\square$

### 4.2 CRDT Convergence

**Theorem 3 (Signature Set Convergence).**
Under eventual delivery, all correct peers converge to the same final signature set for a committed $(event\_id, template\_id)$ pair.

**Proof.**
Let $S_i(t)$ denote peer $i$'s signature set at time $t$.

Properties:
1. **Monotonicity**: G-Set never removes elements, thus $S_i(t) \subseteq S_i(t')$ for $t < t'$.
2. **Commutativity/Associativity**: Merge is set union, which is commutative and associative.
3. **Idempotence**: $S \cup S = S$.
4. **Eventual delivery**: Every signature $\sigma$ generated by a correct peer is eventually delivered to all correct peers.

By eventual delivery, every correct peer eventually includes all signatures from correct peers. Union's commutativity and associativity ensure convergence regardless of merge order:

$$
S_{\mathit{final}} = \bigcup_{p \in \mathit{correct}} \mathit{signatures}(p)
$$

Completion uses LWW-Register; under eventual delivery, all peers observe the maximal-timestamp record and converge. $\square$

### 4.3 Liveness

**Property L1 (Bounded Termination).**
Every event reaches either $\mathtt{Completed}$ or $\mathtt{Abandoned}$ within bounded time.

**Justification.** The protocol uses explicit round timeouts and bounded retry counters. Each round either reaches quorum or times out. After maximum retries, the event is marked $\mathtt{Abandoned}$.

**Non-guarantee.** Completion is not guaranteed under arbitrary UTXO divergence or prolonged network partitions. Safety is prioritized over liveness.

### 4.4 Security Analysis

#### Threats Mitigated

**T1. UTXO Divergence.**
- **Threat**: Peers observe different UTXO sets.
- **Mitigation**: Quorum voting prevents split commitment (Theorems 1, 2).

**T2. Message Replay.**
- **Threat**: Adversary replays old messages.
- **Mitigation**: Authenticated envelopes, storage deduplication (24-hour TTL), phase gating.

**T3. Network Partition.**
- **Threat**: Peers cannot reach quorum.
- **Outcome**: Protocol times out, abandons event (no unsafe signing).

**T4. Fraudulent Events.**
- **Threat**: Attacker injects fake cross-chain messages.
- **Mitigation**: Validator signature verification (m-of-n threshold for Hyperlane, single endpoint for LayerZero).

**T5. Sybil Attacks.**
- **Threat**: Attacker floods gossip with fake peers.
- **Mitigation**: Static whitelist of Ed25519 public keys; only authenticated peers participate.

#### Limitations

**A1. Byzantine Equivocation.** A Byzantine peer can send conflicting proposals to different peers before gossip converges. The protocol assumes this doesn't occur; full BFT requires explicit lock certificates.

**A2. Denial of Service.** Flooding gossip with invalid messages is mitigated by size bounds (10MB max) and rate limiting (10 msg/sec per peer), but full DoS resistance requires stake-based reputation.

**A3. Validator Compromise.** If $\ge T$ Hyperlane validators (or the LayerZero endpoint) are compromised, fraudulent events can be injected. This is a limitation inherited from the cross-chain messaging layer, not Igra itself.

**A4. Key Exposure.** Signing keys exist in process memory. Physical or remote access to the signer process during signing operations could expose keys. HSM integration would mitigate this.

**A5. Storage Tampering.** RocksDB files are not encrypted or integrity-checked. Filesystem-level access could corrupt or manipulate stored state. This is mitigated by operating system access controls.

### 4.5 Failure Scenarios and Manual Intervention

While the protocol guarantees safety (no double-spend), it does not guarantee liveness under all conditions. We identify scenarios where valid events may become stuck, requiring manual intervention.

#### Scenario F1: Quorum Failure (Vote Fragmentation)

**Description.** In round $r$, votes split such that no template hash achieves quorum $q$.

**Example (50-50 split).** With $N = 4$ signers and $q = 3$ (majority):
- Signers ${p_1, p_2}$ observe UTXO set $U_A$ and vote for hash $h_A$
- Signers ${p_3, p_4}$ observe UTXO set $U_B$ and vote for hash $h_B$
- Neither hash reaches $q = 3$: $|V_{h_A}| = 2 < 3$, $|V_{h_B}| = 2 < 3$
- Round times out, no commitment occurs

**How this happens:**
1. **Network partition during proposal phase**: Nodes ${p_1, p_2}$ are temporarily isolated from ${p_3, p_4}$. Each subgroup queries their local blockchain nodes independently.
2. **Significant UTXO divergence**: Nodes are connected to blockchain peers in different geographic regions. A recent block containing a large UTXO consumption has propagated to nodes serving ${p_1, p_2}$ but not yet to nodes serving ${p_3, p_4}$. Thus $U_A \ne U_B$.
3. **Different event orderings**: If events $e_0$ and $e_1$ both compete for the same UTXO, and half the signers process $e_0$ first (consuming the UTXO) while the other half process $e_1$ first, they will build different templates.

**Why this is unlikely:**
- **Deterministic UTXO selection seed**: $seed_r = \mathcal{H}(event\_id \,||\, r)$ ensures all signers use the same UTXO ordering logic. Even if UTXO sets differ slightly, signers prefer the same UTXOs when available.
- **Fast blockchain finality**: Kaspa (1-second blocks) and Bitcoin (10-minute blocks with batching) reduce the window of UTXO divergence.
- **Retry with new seed**: Round $r+1$ uses a different seed, producing a different UTXO ordering. If divergence was due to transient skew, retries often converge.
- **Quorum $q > N/2$**: Requires a *majority*, not unanimity. With $N=7$ and $q=4$, even 3-way fragmentation $({3, 2, 2})$ reaches quorum.

**Recovery:**
- **Automatic retries**: The protocol increments $r$ and re-proposes. Different rounds use different UTXO orderings (via seed), increasing convergence probability.
- **Timeout and abandonment**: After maximum retries (configurable, typically 5-10 rounds), the event transitions to `Abandoned`.
- **Manual intervention required**: Operators must investigate:
  - Check blockchain node synchronization across all signers
  - Verify network connectivity (partition healed?)
  - Identify UTXO divergence cause (stale node? incompatible chain fork?)
  - Manually trigger re-ingestion with fresh UTXO queries, or
  - Manually construct and sign transaction using operator tooling

**Impact.** Funds remain safe (locked in multisig, no double-spend), but the specific payment is delayed until manual intervention. For cross-chain bridges, this means the bridged funds are not released to the destination address automatically.

#### Scenario F2: Threshold Not Reached After Commit

**Description.** A template hash $h$ reaches quorum and all signers commit, but fewer than $m$ signers successfully produce signatures.

**Example.** With $N = 5$ signers, $q = 3$, $m = 3$:
- Round $r$: Signers ${p_1, p_2, p_3}$ vote for $h$, achieving quorum. All 5 signers commit.
- Signing phase: Signers ${p_1, p_2}$ sign and broadcast signatures.
- Signer $p_3$ crashes before signing.
- Signers ${p_4, p_5}$ attempt to sign but fail (e.g., key derivation error, RPC timeout).
- Only 2 signatures collected, $< m = 3$. Threshold not reached.

**How this happens:**
1. **Crash failures during signing**: Signers commit but then crash, lose network connectivity, or experience hardware failure before completing the signing operation.
2. **Key access issues**: Encrypted mnemonic decryption fails (wrong passphrase, corrupted keyfile), or key derivation produces unexpected result.
3. **Signing errors**: PSKT signing logic fails due to malformed template blob or incompatible PSKT version.

**Why this is unlikely:**
- **Commitment implies local validation**: Signers only commit after successfully validating the template blob locally. This catches most malformed templates.
- **Redundancy**: With $N > m$, up to $N - m$ signers can fail after commit without blocking threshold.
- **CRDT persistence**: Signatures are persisted and gossiped continuously. If a crashed signer recovers, it can still sign and gossip its signature.

**Recovery:**
- **Wait for crashed signers**: If signers are temporarily offline, CRDT will merge their signatures once they recover and gossip.
- **Timeout and retry**: If threshold not reached within signing timeout, the protocol may transition to `Failed` and retry the proposal phase (new round, potentially different template).
- **Manual intervention**: Operators can:
  - Investigate why signers failed to sign (check logs, key access)
  - Manually trigger signing on specific nodes
  - Import partial signatures from offline nodes and manually combine
  - Restart the event from scratch if the template is invalid

**Impact.** The event is delayed. If retries also fail, the event is abandoned and manual signing is required.

#### Scenario F3: Blockchain Rejection After Finalization

**Description.** Threshold is reached, transaction finalized, but the blockchain node rejects submission.

**Example:**
- Event $e$ commits to template $\tau$ with inputs ${utxo_1, utxo_2}$.
- All signers sign, threshold reached, transaction $T$ finalized.
- Signer $p_1$ submits $T$ to blockchain.
- Blockchain rejects: `"UTXO utxo_1 already spent"`
- Cause: Between commit time and submission time, an external transaction spent $utxo_1$.

**How this happens:**
1. **UTXO race condition**: External wallets or other processes spend UTXOs between template construction and submission.
2. **Blockchain reorg**: A chain reorganization invalidates the UTXO after commit.
3. **Mempool conflicts**: Another transaction spending the same UTXO is mined first.
4. **Invalid transaction**: Script validation fails, fee too low, or transaction violates chain rules (rare if template was validated correctly).

**Why this is unlikely:**
- **Coordinated UTXO management**: If the multisig is the only entity with access to its UTXOs (no external spenders), race conditions are impossible.
- **Input revalidation**: Before submission, the implementation can re-check that UTXOs are still unspent and have sufficient confirmations ("score depth" check).
- **Fast finality chains**: On Kaspa (1-second blocks), the window between commit and submission is small.

**Recovery:**
- **Automatic retry**: Protocol detects rejection, transitions to `Failed`, increments round, and rebuilds template with fresh UTXOs.
- **Bounded retries**: If blockchain repeatedly rejects (e.g., due to insufficient funds), event is abandoned after max retries.
- **Manual intervention**: Operators must:
  - Verify UTXO availability (query blockchain directly)
  - Check for external spending (unauthorized access to multisig?)
  - Manually construct transaction with confirmed-available UTXOs
  - Investigate if rejection indicates a deeper issue (corrupted state, chain fork)

**Impact.** The event is delayed by one or more retry rounds. If the issue is persistent (e.g., insufficient funds), the event cannot complete automatically.

#### Scenario F4: Cascading Event Failures (UTXO Contention)

**Description.** Multiple events commit to templates using overlapping UTXOs. The first succeeds; subsequent events fail on submission.

**Example.** With events $e_0$ and $e_1$ processed concurrently:
- Event $e_0$ commits to template $\tau_0$ using ${utxo_1, utxo_2}$.
- Event $e_1$ commits to template $\tau_1$ using ${utxo_2, utxo_3}$ (shares $utxo_2$).
- Both events reach threshold and finalize.
- Signer $p_1$ submits $T_0$ (event $e_0$) first. Blockchain accepts.
- Signer $p_2$ submits $T_1$ (event $e_1$). Blockchain rejects: `"UTXO utxo_2 already spent"`.
- Event $e_1$ fails despite valid commitment and threshold.

**How this happens:**
1. **Concurrent events with limited UTXO pool**: Multiple events processed simultaneously, and the multisig has few large UTXOs. Different events select overlapping UTXO subsets.
2. **No inter-event UTXO locking**: The protocol processes each event independently. UTXO allocation is not coordinated across events.
3. **Race to submission**: Whichever transaction is submitted first wins; the other is invalidated.

**Why this is unlikely:**
- **Deterministic seed per event**: Different events use different seeds ($\mathcal{H}(eventid_0 \,||\, r)$ vs $\mathcal{H}(eventid_1 \,||\, r)$), preferring different UTXO orderings. This naturally spreads UTXO selection.
- **Large UTXO pool**: If the multisig maintains many UTXOs, the probability of two events selecting the same UTXO is low.
- **Sequential event processing**: If events arrive with sufficient time gaps, the first event completes and its CRDT completion record propagates before the second event starts, informing signers that certain UTXOs are now spent.

**Recovery:**
- **Automatic retry**: Event $e_1$ detects rejection, transitions to `Failed`, increments round, and rebuilds with remaining UTXOs (excluding $utxo_2$).
- **Completion propagation**: Once $e_0$'s completion record is gossiped, other events querying UTXOs will see $utxo_2$ as spent and avoid it.
- **Retry limits**: If the multisig runs out of UTXOs, event $e_1$ is abandoned.
- **Manual intervention**: Operators can:
  - Fund the multisig with additional UTXOs
  - Manually order events (process $e_1$ after confirming $e_0$ on-chain)
  - Consolidate many small UTXOs into fewer large ones

**Impact.** The second event is delayed by retry rounds. If UTXO pool is exhausted, multiple events may be abandoned simultaneously, requiring batch manual intervention.

#### Scenario F5: Permanent Network Partition

**Description.** The gossip network partitions into two groups that cannot communicate, and the partition persists across all retry rounds.

**Example.** With $N = 6$, $q = 4$:
- Partition: ${p_1, p_2, p_3}$ vs ${p_4, p_5, p_6}$
- Each partition has 3 nodes, $< q = 4$
- Neither partition can reach quorum independently
- Retries continue indefinitely (or until timeout), but quorum never achieved

**How this happens:**
1. **Network infrastructure failure**: Firewall misconfiguration, ISP routing issue, or datacenter network split.
2. **Gossip bootstrap failure**: If bootstrap nodes are unreachable, new nodes cannot join the gossip network.
3. **Persistent Byzantine behavior**: A malicious node selectively drops messages to create artificial partition (though this violates non-equivocating assumption).

**Why this is unlikely:**
- **Redundant network paths**: Gossip protocols (Iroh) use multiple bootstrap nodes and peer discovery to heal partitions.
- **Partition detection**: Operators monitoring node logs will observe missing peer connections.
- **Partial synchrony assumption**: Partitions are assumed to eventually heal after GST.

**Recovery:**
- **Timeout and abandonment**: After maximum retries, the event is abandoned.
- **Manual intervention**: Operators must:
  - Diagnose network connectivity between nodes (ping, traceroute)
  - Reconfigure bootstrap nodes or network settings
  - Restart nodes to force gossip re-connection
  - Manually sign the transaction using a threshold of reachable nodes (if safe)

**Impact.** System liveness is completely blocked for the duration of the partition. All events during this period are abandoned.

#### Scenario F6: Irrecoverable UTXO Exhaustion

**Description.** The multisig has insufficient UTXOs to satisfy the event amount plus fees, and all retry rounds fail.

**Example:**
- Event $e$ requests withdrawal of 1000 units.
- Multisig has UTXOs: ${100, 200, 300}$ (total 600 units).
- All templates fail: insufficient funds.
- Retries continue but all fail for the same reason.
- Event is abandoned.

**How this happens:**
1. **Insufficient multisig balance**: The multisig was not funded adequately.
2. **Concurrent withdrawals**: Multiple events processed simultaneously drain the UTXO pool.
3. **Fee estimation error**: Transaction fees are higher than expected, and available UTXOs cannot cover amount + fees.

**Why this is unlikely:**
- **Balance monitoring**: Operators monitor multisig balance and fund proactively.
- **Policy enforcement**: Amount limits and velocity limits prevent draining the multisig.
- **Fee buffers**: Fee estimation includes safety margins.

**Recovery:**
- **Fund the multisig**: Deposit additional UTXOs to the multisig address.
- **Re-ingest event**: After funding, manually re-submit the event or restart the node to re-process abandoned events.
- **Manual signing**: If urgent, operators use threshold tooling to manually construct and sign a transaction from available funds.

**Impact.** The event cannot complete until the multisig is funded. Delay depends on funding transaction confirmation time.

#### Summary: When Manual Intervention Is Required

| Scenario | Root Cause | Manual Action |
|----------|------------|---------------|
| F1: Quorum failure | UTXO divergence, network partition, event ordering | Investigate node sync, heal partition, manually sign |
| F2: Threshold not reached | Signer crashes, key errors | Recover crashed nodes, fix key issues, import signatures |
| F3: Blockchain rejection | UTXO race, reorg, invalid tx | Rebuild with fresh UTXOs, investigate external spender |
| F4: Cascading failures | UTXO contention between events | Fund multisig, manually order events |
| F5: Network partition | Gossip failure, infrastructure issue | Diagnose network, reconfigure, restart |
| F6: UTXO exhaustion | Insufficient balance | Deposit funds, re-ingest event |

**Philosophical stance: Safety over liveness.** The protocol intentionally prioritizes safety. When faced with ambiguity (quorum not reached, divergent views), it *refuses to sign* rather than risking double-spend. Explicit abandonment is preferable to silent corruption. This aligns with the design philosophy of financial systems: better to delay a payment than to send it twice.

## 5. Reference Implementation

We validate the theoretical model through an implementation on Kaspa, a high-throughput UTXO blockchain.

### 5.1 Implementation Mapping

| Theoretical Concept | Implementation |
|---------------------|----------------|
| Event identifier | BLAKE3 hash with domain `"igra:event:v1:"` |
| Template format | PSKT (Kaspa's PSBT variant) serialized as JSON |
| Template identifier | BLAKE3 of Borsh-serialized transaction skeleton |
| Gossip transport | Iroh gossip protocol |
| Signature scheme | secp256k1 Schnorr (per-input) |
| Storage (production) | RocksDB persistent key-value store |
| Storage (testing) | In-memory HashMap (test-only, not for production) |
| Key management | BIP39/BIP32 HD wallets with XChaCha20Poly1305 encryption |

### 5.2 Event Structure

```rust
struct Event {
    external_id: [u8; 32],
    source: SourceType,
    destination: ScriptPubKey,
    amount: u64,
}
```

Event identifier computation:
1. Domain-separate with `"igra:event:v1:"`
2. Encode fields: `external_id`, `source`, `destination_version`, `destination_script`, `amount` (concatenated)
3. Hash with BLAKE3

### 5.3 Template Hashing

Templates use PSKT format:
1. Store/transmit as JSON-serialized PSKT
2. To hash: extract unsigned transaction skeleton → serialize with Borsh → hash with BLAKE3

This ensures deterministic hashing while allowing efficient JSON transport.

### 5.4 Proposal Structure

```rust
struct Proposal {
    event_id: [u8; 32],
    round: u32,
    tx_template_hash: [u8; 32],
    kpsbt_blob: Vec<u8>,
    utxos_used: Vec<UtxoInput>,
    outputs: Vec<Output>,
    signing_material: EventData,
    proposer_peer_id: String,
    timestamp_ns: u64,
}
```

### 5.5 Phase State Machine

Implemented with explicit transition validation:

```
Unknown → Proposing → Committed → Completed
            ↓           ↓
         Failed ↻ (retry)
            ↓
        Abandoned (terminal)
```

Storage enforces single-vote invariant by rejecting duplicate proposals with different hashes.

### 5.6 CRDT Merge Implementation

**Signature merge:**
```rust
fn merge_signatures(base: &mut Vec<Sig>, incoming: &[Sig]) {
    for sig in incoming {
        let key = (sig.input_index, sig.pubkey);
        if !base.contains_key(key) {
            base.insert(key, sig.clone());
        }
    }
}
```

**Completion merge:**
```rust
fn merge_completion(c1: Completion, c2: Completion) -> Completion {
    if c1.timestamp >= c2.timestamp { c1 } else { c2 }
}
```

Implemented in `igra-core/src/infrastructure/storage/rocks/` (production) and `storage/memory.rs` (tests only).

### 5.7 Deterministic UTXO Selection

To reduce proposal divergence across rounds:

$$
\mathit{seed}_r := \mathcal{H}(\mathit{event\_id} \,\|\, r)
$$

UTXOs are sorted by $\mathcal{H}(\mathit{seed}_r \,\|\, \mathit{outpoint})$ before selection, ensuring different rounds prefer different UTXO orderings.

### 5.8 Network Layer

**Authenticated Envelopes:**
- Compute payload hash: $h_p := \mathcal{H}(\mathit{serialize}(\mathit{payload}))$
- Sign with Ed25519: $\sigma := \mathit{Ed25519.sign}(sk_i, h_p)$
- Envelope: $(\mathit{payload}, h_p, \sigma, \mathit{metadata})$

**Message Types:**
- `ProposalBroadcast`: Two-phase proposals
- `EventStateBroadcast`: CRDT state updates
- `StateSyncRequest/Response`: Anti-entropy

**Filtering and Authentication:**
- Payload hash verified in constant-time
- Ed25519 signature verified against static whitelist
- Replay protection via seen-message tracking (24-hour TTL)
- Per-peer rate limiting (10 msg/sec sustained, 100 burst)

### 5.9 Validation Against Theoretical Model

We verify the implementation satisfies the protocol specification:

| Property | Theoretical | Implementation | Validation |
|----------|-------------|----------------|------------|
| Unique vote (I2) | Storage key $(e, r, p)$ | `(event_id, round, peer_id)` in RocksDB | Enforced |
| Deterministic selection | Algorithm 3.3 | `selection.rs::quorum_hash()` | Code audit |
| CRDT merge | Set union, LWW | `storage/rocks/event_store.rs::merge()` | Tested |
| Template hash | $\mathcal{H}(\mathit{canonical}(\tau))$ | `multisig.rs::tx_template_hash()` | Deterministic |
| Validator verification | m-of-n threshold | `validation/hyperlane.rs::verify_event()` | Tested |
| Peer authentication | Ed25519 whitelist | `transport/iroh/filtering.rs` | Enforced |

### 5.10 Performance Characteristics

**Measured on testnet (preliminary):**
- Commit latency: 200-800ms (3-node deployment)
- Retry rate: 5-15% under simulated UTXO divergence
- Gossip bandwidth: ~2KB per proposal, ~500B per signature update

**Analytic complexity:**
- Messages: $O(N^2)$ per round (all-to-all gossip)
- Storage: $O(E \cdot R \cdot N)$ proposals, $O(E \cdot I \cdot N)$ signatures

## 6. Discussion

### 6.1 Comparison to Alternatives

**Leader-based consensus (Raft, Paxos).** Requires leader election; single point of failure. Igra is leaderless.

**BFT consensus (PBFT, Tendermint).** Handles Byzantine faults but requires $N \ge 3f+1$ and $O(N^2)$ message complexity per phase. Igra achieves safety under crash faults with $N \ge 2f+1$ and simpler quorum rule.

**Optimistic concurrency.** Signing without coordination risks double-spend. Igra trades latency (two-phase delay) for safety.

### 6.2 Limitations and Extensions

**Byzantine tolerance.** Upgrading to full BFT requires:
- Lock certificates signed by $q$ peers
- Validators verify lock before accepting proposals
- Explicit slashing for equivocation

**Chain abstraction.** Current implementation embeds Kaspa-specific types. Generalizing to Bitcoin/other UTXO chains requires:
- Abstract template interface
- Chain-specific adapters for PSBT/other formats

**Interactive ceremonies.** MuSig2 and FROST require multi-round signing with nonce commitments. This needs:
- Extended CRDT to replicate interactive artifacts
- Protocol-specific validation rules

**Hardware security.** HSM integration would prevent key exposure even if the process is compromised.

## 7. Related Work

**Byzantine consensus.** PBFT and Tendermint provide BFT safety but are optimized for blockchain consensus, not threshold signing coordination.

**Conflict-free replicated data types.** CRDTs guarantee eventual consistency without coordination. Igra uses G-Set and LWW-Register for signature propagation after coordination completes.

**Threshold signatures.** MuSig2, FROST, and GG20/CMP provide cryptographic multi-party signing. Igra coordinates *when* to sign, orthogonal to *how* signatures are generated.

**Multi-party computation.** MPC protocols like CHURP and Taurus address distributed key generation and proactive secret sharing. Igra focuses on transaction coordination given existing threshold keys.

## 8. Conclusion

We presented Igra, a leaderless protocol for safe threshold signing on UTXO blockchains. The protocol combines two-phase quorum voting with CRDT-based signature propagation to guarantee that at most one transaction is signed per event, even when signers observe divergent blockchain state. Formal proofs establish unique commitment, deterministic agreement, and convergence properties under crash-fault assumptions. A reference implementation on Kaspa validates the theoretical model and demonstrates practical feasibility.

The protocol's trust model is explicit: we rely on external validator sets for event authenticity, industry-standard key derivation for signing key management, and authenticated gossip for peer communication. Physical security of signer nodes is assumed but not enforced by the protocol itself.

Future work includes Byzantine-tolerant extensions, chain abstraction for Bitcoin compatibility, hardware security module integration, and support for interactive signing ceremonies like MuSig2 and FROST.

## Acknowledgments

[To be filled for publication]

## Appendix A: Notation

| Symbol | Meaning |
|--------|---------|
| $N$ | Number of signers |
| $m$ | Signature threshold (M-of-N multisig) |
| $q$ | Commit quorum (requires $q > N/2$ for safety) |
| $T$ | Validator signature threshold (for cross-chain events) |
| $M$ | Total validators (for cross-chain events) |
| $\mathcal{P}$ | Set of peer identifiers |
| $\mathcal{H}$ | Cryptographic hash function (BLAKE3) |
| $e$ | Event (payment request) |
| $\tau$ | Transaction template |
| $r$ | Round number |
| $\Sigma$ | CRDT signature set (G-Set) |
| $C$ | CRDT completion record (LWW-Register) |

## Appendix B: Implementation Reference

The reference implementation is available in the Rusty Kaspa repository under `wallet/igra`.

**Core modules:**
- Event and template hashing: `igra-core/src/domain/hashes.rs`
- Canonical selection algorithm: `igra-core/src/domain/coordination/selection.rs`
- Phase state machine: `igra-core/src/domain/coordination/phase.rs`
- CRDT merge logic (production): `igra-core/src/infrastructure/storage/rocks/`
- CRDT merge logic (testing): `igra-core/src/infrastructure/storage/memory.rs`
- Gossip transport: `igra-core/src/infrastructure/transport/iroh/`
- Validator verification: `igra-core/src/domain/validation/`
- Key management: `igra-core/src/foundation/hd.rs`, `igra-core/src/infrastructure/config/encryption.rs`

**Verification.** All theorems and invariants are validated through:
- Unit tests for selection and merge determinism
- Integration tests simulating UTXO divergence scenarios
- Integration tests for validator verification
- Testnet deployment with monitoring
