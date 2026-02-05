# Architecture Overview

**Last Updated:** 2026-02-05
**Audience:** Software engineers, system architects, auditors

---

## System Architecture

Igra is a distributed coordination system composed of two main components:

```
┌─────────────────────────────────────────────────────────────┐
│                    Igra System Overview                      │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│  External Event  │         │  External Event  │         │  External Event  │
│     Source       │         │     Source       │         │     Source       │
│  (Hyperlane)     │         │  (LayerZero)     │         │  (Manual API)    │
└────────┬─────────┘         └────────┬─────────┘         └────────┬─────────┘
         │                            │                            │
         └──────────────────────────┬─┴────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   Validator Verification      │
                    │   (m-of-n threshold sigs)     │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           IGRA CLUSTER                                  │
│                                                                         │
│  ┌─────────────┐       ┌─────────────┐       ┌─────────────┐         │
│  │  Igra Node  │◄─────►│  Igra Node  │◄─────►│  Igra Node  │         │
│  │     #1      │       │     #2      │       │     #3      │         │
│  └──────┬──────┘       └──────┬──────┘       └──────┬──────┘         │
│         │                     │                     │                 │
│         │   Authenticated Gossip (Iroh P2P)        │                 │
│         │◄─────────────────────┼──────────────────►│                 │
│         │                     │                     │                 │
│  ┌──────▼──────────────────────▼─────────────────────▼──────┐        │
│  │              Two-Phase Coordination                       │        │
│  │  1. Vote on transaction template (no signatures yet)      │        │
│  │  2. Reach quorum (>50%)                                   │        │
│  │  3. Lock to agreed template                               │        │
│  └──────────────────────┬────────────────────────────────────┘        │
│                         │                                              │
│  ┌──────────────────────▼────────────────────────────────────┐        │
│  │              CRDT Signature Collection                    │        │
│  │  1. Each node signs agreed template                       │        │
│  │  2. Signatures propagate via gossip                       │        │
│  │  3. Merge via conflict-free set union                     │        │
│  │  4. Detect threshold (m-of-n)                             │        │
│  └──────────────────────┬────────────────────────────────────┘        │
│                         │                                              │
└─────────────────────────┼──────────────────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────────┐
              │    UTXO Blockchain        │
              │    (Kaspa/Bitcoin)        │
              │  - Finalized transaction  │
              │  - Confirmed on chain     │
              └───────────────────────────┘
```

---

## Component Breakdown

### 1. igra-core

**Purpose:** Core domain logic, protocol implementation, storage abstraction

**Directory Structure:**
```
igra-core/src/
├── application/          # Application layer (event processing, two-phase, CRDT coordination)
│   ├── event_processor.rs
│   ├── two_phase.rs
│   ├── pskt_signing.rs
│   ├── crdt_coordinator.rs
│   └── crdt_operations.rs
│
├── domain/              # Domain models and business logic
│   ├── model.rs         # Core types (Event, SourceType, GroupPolicy)
│   ├── hashes.rs        # Event ID and template hash computation
│   ├── pskt/            # Transaction template building
│   │   └── builder.rs
│   ├── coordination/    # Two-phase protocol
│   │   ├── config.rs    # Limits (MAX_UTXOS_PER_PROPOSAL, etc.)
│   │   ├── proposal.rs  # Proposal validation
│   │   ├── phase.rs     # Phase state machine
│   │   └── selection.rs # Canonical template selection
│   ├── policy/          # Policy enforcement
│   │   └── enforcement.rs
│   └── validation/      # Validator signature verification
│       ├── hyperlane.rs
│       └── layerzero.rs
│
├── foundation/          # Foundational utilities
│   ├── types.rs         # Hash32, EventId, etc.
│   ├── error.rs         # ThresholdError enum
│   ├── constants.rs     # System-wide constants
│   └── hd.rs            # BIP32/BIP39 key derivation
│
└── infrastructure/      # External system adapters
    ├── config/          # Configuration loading
    │   ├── loader.rs
    │   ├── types.rs
    │   └── encryption.rs
    ├── rpc/             # Kaspa RPC client
    │   └── kaspa_integration/
    ├── storage/         # Persistence layer
    │   ├── traits.rs    # Storage interface
    │   ├── memory.rs    # In-memory (tests only)
    │   └── rocks/       # RocksDB (production)
    └── transport/       # Network layer
        └── iroh/        # Gossip transport
```

**Key Responsibilities:**
- Event ID computation (deterministic, collision-resistant)
- Two-phase proposal voting and quorum detection
- CRDT merge operations (signature sets, completion records)
- PSKT (Kaspa PSBT) building and signing
- Policy validation (amount limits, destination whitelist)
- Validator signature verification
- Storage abstraction (RocksDB for production, in-memory for tests)

**Important Invariants:**
- **Single vote per round** (enforced by storage layer)
- **Single signature per event** (enforced by application layer)
- **Phase monotonicity** (no backward transitions from terminal states)
- **Commit irreversibility** (locked template hash never changes)

---

### 2. igra-service

**Purpose:** Service coordination, RPC API, gossip network management

**Directory Structure:**
```
igra-service/src/
├── api/                 # HTTP REST API
│   ├── routes.rs        # Endpoint definitions
│   ├── handlers.rs      # Request handlers
│   └── types.rs         # API request/response types
│
├── service/             # Service-level coordination
│   ├── coordination/    # High-level coordination logic
│   │   ├── loop.rs      # Main event loop
│   │   ├── two_phase_handler.rs  # Proposal validation + commit detection
│   │   └── two_phase_timeout.rs  # Retry logic
│   └── flow/            # Event flow management
│       └── crdt_sync.rs # Anti-entropy, state sync
│
└── transport/           # Network transport layer
    └── iroh/            # Iroh gossip integration
        ├── filtering.rs # Message authentication
        └── discovery.rs # Peer discovery
```

**Key Responsibilities:**
- HTTP API for event submission and status queries
- Coordinating two-phase protocol across gossip network
- Detecting quorum and triggering phase transitions
- Anti-entropy (periodic CRDT state sync)
- Retry logic on proposal timeouts
- Peer authentication and message filtering

---

## Data Flow

### Event Submission → Completion

```
1. EVENT INGESTION
   ┌─────────────────────┐
   │ External API Call   │
   │ POST /api/v1/events │
   └──────────┬──────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Validator Signature Check   │
   │ - Hyperlane: m-of-n         │
   │ - LayerZero: single sig     │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Policy Validation           │
   │ - Amount limits             │
   │ - Destination whitelist     │
   │ - Daily volume              │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Compute Event ID            │
   │ H(external_id, source,      │
   │   destination, amount)      │
   └──────────┬──────────────────┘
              │
              │
2. TWO-PHASE PROTOCOL
              │
              ▼
   ┌─────────────────────────────┐
   │ PHASE: Proposing            │
   │ - Query local UTXO set      │
   │ - Build transaction template│
   │ - Compute template hash     │
   │ - Broadcast proposal        │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Wait for Quorum             │
   │ - Collect proposals from    │
   │   other signers             │
   │ - Count votes per hash      │
   │ - Check if any hash has     │
   │   ≥ commit_quorum votes     │
   └──────────┬──────────────────┘
              │
              │ Quorum reached?
              ├─── No ──► Timeout ──► Retry (round++)
              │
              │ Yes
              ▼
   ┌─────────────────────────────┐
   │ PHASE: Committed            │
   │ - Lock to agreed hash       │
   │ - Retrieve template blob    │
   │ - Derive signing key        │
   │ - Sign each input           │
   │ - Broadcast signatures      │
   └──────────┬──────────────────┘
              │
              │
3. CRDT SIGNATURE COLLECTION
              │
              ▼
   ┌─────────────────────────────┐
   │ Merge Signatures (G-Set)    │
   │ - Receive sigs from peers   │
   │ - Union: Σ ← Σ ∪ Σ'        │
   │ - De-duplicate by key       │
   │   (input_idx, pubkey)       │
   └──────────┬──────────────────┘
              │
              ▼
   ┌─────────────────────────────┐
   │ Check Threshold             │
   │ ∀ input_i:                  │
   │   |signatures_i| ≥ m ?      │
   └──────────┬──────────────────┘
              │
              │ Threshold met?
              ├─── No ──► Wait for more signatures
              │
              │ Yes
              ▼
   ┌─────────────────────────────┐
   │ PHASE: Completed            │
   │ - Apply signatures to PSKT  │
   │ - Finalize transaction      │
   │ - Submit to blockchain      │
   │ - Record completion (LWW)   │
   └─────────────────────────────┘
```

---

## Key Design Patterns

### 1. Leaderless Coordination

**Problem:** Leader-based systems have single points of failure
**Solution:** All nodes propose simultaneously; quorum determines agreement

**Benefits:**
- No leader election overhead
- Any node can be offline (up to N - quorum)
- No coordinator bottleneck

### 2. Vote Before Sign

**Problem:** Signing divergent templates fragments signatures
**Solution:** Vote on template hash first; sign only after quorum

**Benefits:**
- Prevents signature fragmentation
- Ensures at most one template per event
- Safe under UTXO divergence

### 3. CRDT for Signature Collection

**Problem:** Coordinating signature collection requires additional consensus rounds
**Solution:** Use conflict-free replicated data type (G-Set)

**Benefits:**
- Coordination-free after commitment
- Handles message reordering gracefully
- Automatic convergence

### 4. Deterministic UTXO Selection

**Problem:** Different nodes may select different UTXOs
**Solution:** Seed-based deterministic ordering

```rust
seed_r = H(event_id || round)
utxos.sort_by_key(|u| H(seed_r || u.outpoint))
```

**Benefits:**
- Increases convergence probability
- Different rounds try different orderings
- Reproducible across all nodes

### 5. Storage Abstraction

**Problem:** Tests should be fast; production needs persistence
**Solution:** Trait-based storage interface

```rust
trait Storage {
    fn store_proposal(...);
    fn get_proposals(...);
    fn merge_event_crdt(...);
}

// Production: RocksDB
// Tests: HashMap
```

---

## Concurrency Model

### Thread Safety

Igra uses Tokio async runtime with:
- **Message passing** (channels) for inter-task communication
- **Arc + RwLock** for shared state (storage, configuration)
- **No global mutable state**

### Task Structure

```
Main Service Task
│
├─► Gossip Listener Task (receives proposals, signatures)
│   └─► Spawns: Proposal Handler Task (per message)
│
├─► API Server Task (handles HTTP requests)
│   └─► Spawns: Event Submission Task (per request)
│
├─► Two-Phase Timeout Task (periodic, checks for stuck events)
│
├─► Anti-Entropy Task (periodic CRDT sync)
│
└─► Monitoring Task (metrics export, health checks)
```

---

## Security Architecture

### Threat Boundaries

```
┌───────────────────────────────────────────────────┐
│          EXTERNAL UNTRUSTED BOUNDARY              │
│                                                   │
│  Cross-Chain Events (Ethereum, BSC, etc.)        │
│  ─────────────────────────────────────────────   │
│  Validator Signatures Required ✓                 │
│  m-of-n threshold (Hyperlane)                    │
│  Single endpoint sig (LayerZero)                 │
└────────────────┬──────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────┐
│       VALIDATOR VERIFICATION (Trust Boundary)      │
│  - Cryptographic signature verification            │
│  - Configured public keys (static whitelist)      │
└────────────────┬───────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────┐
│            IGRA INTERNAL TRUSTED ZONE              │
│                                                    │
│  Gossip Network                                   │
│  ──────────────────────────────────────────────   │
│  Ed25519 authenticated messages ✓                 │
│  Static peer whitelist ✓                          │
│  Replay protection (24h TTL) ✓                    │
│  Rate limiting (10 msg/sec per peer) ✓            │
│                                                    │
│  Key Management                                   │
│  ──────────────────────────────────────────────   │
│  BIP39 mnemonics (12-24 words)                    │
│  XChaCha20Poly1305 encrypted storage              │
│  Environment variable encryption key              │
│  Memory zeroing after use (Zeroize trait)         │
│                                                    │
│  Limitations:                                      │
│  ❌ No HSM support (keys in process memory)       │
│  ❌ No Byzantine fault tolerance                   │
└────────────────┬───────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────┐
│              BLOCKCHAIN (Trust Boundary)           │
│  - Each signer queries own Kaspa node             │
│  - Eventual consistency assumed                    │
│  - Probabilistic finality (GHOSTDAG)              │
└────────────────────────────────────────────────────┘
```

---

## Failure Modes

See [Troubleshooting Guide](../../operators/troubleshooting/03-failure-scenarios.md) for detailed analysis.

**Summary:**
1. **Quorum failure** → Event abandoned after retries
2. **Threshold not reached** → Wait for more signers or abandon
3. **Blockchain rejection** → Retry with fresh UTXOs
4. **UTXO contention** → Deterministic selection reduces collisions
5. **Network partition** → Timeout and explicit abandonment

**Safety Guarantee:** Even under failures, at most one transaction is signed per event.

---

## Performance Characteristics

### Latency
- **Best case:** 200-500ms (single round, immediate quorum)
- **Typical:** 500ms-2s (1-2 retries)
- **Worst case:** 30-60s (multiple retries + timeout)

### Throughput
- **Sequential events:** 2-5 events/sec (limited by blockchain confirmation)
- **Concurrent events:** 10-50 events/sec (depends on UTXO pool size)

### Scalability
- **Message complexity:** O(N²) per round (all-to-all gossip)
- **Storage growth:** O(E · R · N) proposals + O(E · I · N) signatures
  - E = events, R = rounds, N = nodes, I = inputs per tx

### Resource Usage (per node)
- **RAM:** 100-500 MB (depends on event volume and retention)
- **Disk:** 1-10 GB/year (RocksDB storage)
- **Network:** 1-10 KB/sec sustained, 100 KB/sec burst

---

## Next Steps

- **Deep dive into protocol**: [Protocol Specification](02-protocol-specification.md)
- **Understand two-phase**: [Two-Phase Coordination](03-two-phase-coordination.md)
- **Understand CRDT**: [CRDT Signing](04-crdt-signing.md)
- **Explore codebase**: [Codebase Structure](06-codebase-structure.md)

---

**Questions?** File an issue or ask in [Kaspa Discord #igra-dev](https://discord.gg/kaspa)
