# Design-2: Reimagined Igra Architecture (Providers × Chains × Ceremonies)

## Summary

We want a clean, extensible architecture that supports:

- Multiple **event providers**: Hyperlane, LayerZero, API/manual, future providers.
- Multiple **chains**: Kaspa, Bitcoin, future chains.
- Multiple **ceremonies**: classic multisig, MuSig2, MPC/FROST (threshold), future ceremonies.

The central goal is to keep the **coordination/CRDT logic chain-agnostic and provider-agnostic**, while allowing plug-in implementations for provider I/O, chain I/O, and signing/ceremony mechanics.

This document describes a single-repo layout with `igra/src/{domain,app,infra}` and a runtime entrypoint under `src/bin/*` (equivalent to today’s `igra-service` crate).

## Terminology

- **CRDT**: replicated state + merge rules (convergence).
- **Coordination**: protocol/state machine using CRDT (rounds, proposals, quorum, phases).
- **Ceremony**: the signing workflow (multisig/musig2/frost) executed via coordination/CRDT.
- **Ports**: traits defined by domain that represent external capabilities.
- **Adapters**: infrastructure implementations of ports.

## Architectural Principles

1. **Domain defines the protocol and the ports** (traits) that it requires.
2. **App orchestrates use-cases** and selects concrete implementations at wiring time.
3. **Infra implements ports** for event providers, chain clients, signers, transports, and storage.
4. Ceremony state machines should be **swappable** without rewriting coordination or storage.
5. The CRDT schema must be able to replicate:
   - one-shot signature records (multisig),
   - and interactive artifacts (MuSig2/FROST) even if those ceremonies are stubbed initially.

## High-Level Flow (Conceptual)

```
 EventProvider (infra) -> canonical Event + proof
             |
             v
     app/usecases (orchestration)
             |
             v
 domain/coordination + domain/crdt
             |
             +--> domain/ceremony driver (multisig / musig2 / frost)
             |
             +--> Storage (infra)       Transport (infra)
             |
             +--> ChainClient (infra)   TxTemplateEngine (infra or domain impl)
             |
             +--> SignatureProvider (infra) + SigningProtocol (infra for interactive)
```

## Proposed Repository Layout (single top-level crate)

```
igra/
  src/
    domain/
      model/
      protocol/
      crdt/
      coordination/
      ceremony/
      ports/
    app/
      usecases/
      wiring/
    infra/
      event_providers/
      chains/
      ceremonies/
      signers/
      transport/
      storage/
    bin/
      kaspa-threshold-service.rs
```

### `igra/src/domain/`

#### `igra/src/domain/model/`
Canonical, stable data types:
- `Event` (provider-agnostic canonical payload)
- identifiers: `EventId`, `SessionId`, `PeerId`, `Hash32`, etc.
- policy models (group policy, limits, etc.)

##### Note: `Event.destination` transition plan

Today `Event.destination` is Kaspa-typed (e.g. `kaspa_consensus_core::tx::ScriptPublicKey`), which is not chain-agnostic.

Migration guidance:
- **Phase A (fast migration):** keep the existing field/type temporarily, but ensure coordination/CRDT/app does not interpret it directly; only chain-specific adapters/ports touch it.
- **Phase B (target):** move to a chain-neutral representation (e.g. `ScriptBytes(Vec<u8>)` or `Destination { chain: ChainId, script: Vec<u8> }`) once ports are in place, so the domain becomes chain-agnostic by construction.

#### `igra/src/domain/protocol/`
Wire/state models replicated across peers:
- `Proposal` / `PhaseContext` / `EventPhase` / `EventPhaseState`
- `EventCrdtState` and related message payloads
- `PartialSigRecord` (one-shot signature record; current concept)
- `SigningArtifact` (generic artifact record for interactive ceremonies)
- `CompletionRecord` (final tx id + metadata; keep chain-neutral)

##### Chain-neutral `CompletionRecord`

Avoid chain-specific field names like `blue_score`. Prefer a generic finality anchor that can represent Kaspa and Bitcoin:

```rust
pub struct CompletionRecord {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub chain: ChainId,
    pub finality: Option<FinalityAnchor>,
}

pub enum FinalityAnchor {
    Score(u64),           // e.g. Kaspa blue score / DAA score (as chosen)
    Height(u64),          // e.g. Bitcoin block height
    Confirmations(u32),   // if that is what the backend provides at record time
    Other(String, u64),   // escape hatch
}
```

#### `igra/src/domain/crdt/`
Merge rules + replicated data structures:
- G-Set / OR-Set semantics for signature records
- LWW registers for completion status
- Merge rules for `SigningArtifact` (de-dup by `(kind, sign_target, participant, digest)` etc.)

#### `igra/src/domain/coordination/`
Chain/provider-agnostic coordination algorithms:
- two-phase proposal rounds
- quorum selection + deterministic tie-break
- phase transitions and timeouts
- gating rules: “must have a validated template”, “must have threshold”, etc.

#### `igra/src/domain/ceremony/`
Ceremony state machines that operate over the protocol/CRDT state.

We define all ceremonies at the API level, but only fully implement **classic multisig** for now.
MuSig2 and MPC/FROST are present as ceremony *kinds* with stub implementations that return `Unsupported` errors if invoked.

#### `igra/src/domain/ports/`
Traits (ports) used by domain/app:
- `EventProviderPort`
- `TransportPort`
- `StoragePort`
- `ClockPort`
- `TxTemplateEnginePort`
- `ChainClientPort`
- `SignatureProviderPort`
- `SigningProtocolPort` (interactive signing)

### `igra/src/app/`

Use-cases and orchestration logic. App code wires domain state machines + ports.

#### `igra/src/app/usecases/` (examples)
- `ingest_event` (receive/verify provider event; persist; start coordination)
- `handle_inbound_message` (merge CRDT/proposal updates; advance phases)
- `tick_timeouts` (retry rounds; abandon sessions)
- `try_commit` / `try_sign` / `try_submit` (drive ceremony forward)

#### `igra/src/app/wiring/`
Construct concrete instances based on configuration:
- choose event provider (hyperlane/layerzero/api)
- choose chain backend (kaspa/bitcoin)
- choose ceremony kind (multisig/musig2/frost)

### `igra/src/infra/`

Adapters implementing domain ports.

#### `igra/src/infra/event_providers/`
- `hyperlane/`
- `layerzero/`
- `api/` (manual submission)

#### `igra/src/infra/chains/`
- `kaspa/` (RPC client, tx template tooling, fee model)
- `bitcoin/` (backend client: bitcoind/electrum/esplora; tx tooling/fee model)

#### `igra/src/infra/ceremonies/`
Interactive ceremony protocol engines (optional at first):
- `musig2/` (later)
- `frost/` (later)

#### `igra/src/infra/signers/`
- `hd/` (mnemonic/derivation)
- `remote/` (remote signing service)
- `hsm/` (if needed)

#### `igra/src/infra/transport/`
- `iroh/` or other gossip channels

#### `igra/src/infra/storage/`
- `rocks/` etc.

## Domain APIs (Ports)

Below are the conceptual ports. Exact signatures can be adjusted, but the separation of concerns is the important part.

### `EventProviderPort` (provider I/O)

Responsibilities:
- parse/verify provider-specific payloads
- map into canonical `domain::model::Event` + proof/audit context

### `TransportPort` (p2p messaging)

Responsibilities:
- publish protocol messages (proposal broadcast, CRDT state broadcast, sync request/response)
- subscribe to inbound messages

### `StoragePort` (persistence)

Responsibilities:
- store and merge CRDT state
- store phase state and proposals
- idempotent event persistence

### `TxTemplateEnginePort` (pure template semantics; chain-specific implementation)

Responsibilities (no I/O, no secrets):
- validate a template blob and compute a deterministic `TemplateId`
- produce a signing plan (`SigningJob`s) from a template
- apply signatures/artifacts into the template deterministically
- finalize to `FinalTx` bytes and compute txid

This is the “format semantics” boundary: PSKT, PSBT, Taproot, etc.

### Fee estimation ownership (clarification)

To avoid mixing responsibilities:
- `ChainClientPort` owns fee-rate discovery and chain-tip context (I/O).
- `TxTemplateEnginePort` owns size/mass/weight accounting and fee computation for a given template semantics (pure).

### `ChainClientPort` (chain I/O)

Responsibilities:
- query tip/finality (blue score, confirmations, etc.)
- fetch spendable inputs / UTXOs
- estimate fees (mass vs vbytes/weight)
- broadcast `FinalTx` bytes
- optionally check tx acceptance/status

### `SignatureProviderPort` (key custody + cryptographic primitives)

This is *not* “one-shot only” in the final architecture.

It is the “local cryptographic capability” port. It can provide:
- identity/public keys
- signing primitives used by either:
  - direct one-shot schemes (ECDSA multisig),
  - or interactive signing protocols (MuSig2/FROST) that still require local signing steps.

Why keep it separate from `SigningProtocolPort`:
- key custody is an environmental concern (mnemonic/HSM/remote).
- signing protocols are coordination/validation concerns (message formats, transcript rules).

### `SigningProtocolPort` (interactive signing protocol engine)

This is required only for interactive ceremonies (MuSig2, FROST).

Responsibilities:
- create sessions bound to a `SigningJob` (domain-separated context)
- accept inbound artifacts and emit outbound artifacts
- determine when a partial signature or final signature is ready

## Ceremony APIs

### Common Ceremony Driver (domain)

Define a domain-level ceremony interface that the coordination layer can call.

Conceptual responsibilities:
- given current CRDT state, decide “what to do next” (emit messages, request signing, attempt finalization, attempt submission)
- produce CRDT updates (signatures/artifacts/completion)

### Ceremony Kinds

#### 1) Classic Multisig (`m-of-n`, non-interactive)

Characteristics:
- one-shot per-input signatures (ECDSA for Bitcoin P2WSH; Schnorr for Kaspa depending on chain rules)
- CRDT replicates `PartialSigRecord` (G-Set)
- finalization occurs when threshold reached

Ports used:
- `TxTemplateEnginePort`
- `SignatureProviderPort` (one-shot signing path)
- `ChainClientPort` (broadcast)
- `StoragePort`, `TransportPort`

#### 2) MuSig2 (interactive; stub for now)

Characteristics:
- interactive protocol exchanging artifacts (nonce commitments, nonces, partial sigs)
- CRDT replicates `SigningArtifact` (and optionally final signature record)

For now: define the API surface, but return `Unsupported` if invoked.

Ports required (eventually):
- `TxTemplateEnginePort` (must support Taproot/Schnorr template semantics if on Bitcoin)
- `SigningProtocolPort` (MuSig2 engine)
- `SignatureProviderPort` (local signing primitives / nonce generation)
- `ChainClientPort`, `StoragePort`, `TransportPort`

#### 3) MPC/FROST (interactive threshold; stub for now)

Characteristics:
- interactive threshold signing with rounds and shares
- CRDT replicates `SigningArtifact` (protocol messages)

For now: define the API surface, but return `Unsupported` if invoked.

Ports required (eventually):
- `TxTemplateEnginePort` (scheme-specific signature embedding)
- `SigningProtocolPort` (FROST engine)
- `SignatureProviderPort` (share custody / local computations)
- `ChainClientPort`, `StoragePort`, `TransportPort`

## “Unsupported” Strategy for Future Ceremonies

To keep the codebase compile-ready while postponing implementation:

- The `domain::ceremony` module exposes:
  - `MultisigCeremony` (implemented)
  - `MuSig2Ceremony` (stub)
  - `FrostCeremony` (stub)

- Stubs should fail fast with a structured error, e.g.:
  - `ThresholdError::UnsupportedCeremony { ceremony: "musig2", operation: "start_session" }`

This keeps the architecture stable while allowing incremental delivery.

## Answer: Why “SignatureProvider is one-shot only” was misleading

In Design-1, `SignatureProvider` was described as one-shot for simplicity (digest → signature).

In the refined architecture, `SignatureProviderPort` is better understood as a **key custody + cryptographic primitives** port:
- It can support one-shot signing APIs for simple ceremonies.
- It can also support the local cryptographic steps needed by interactive protocols.

Interactive protocols still need a separate `SigningProtocolPort` because:
- they define session transcripts, message validation rules, and multi-round state transitions,
- which is distinct from “where the key lives” and “how to invoke a signer”.

## Migration Path (from current code)

1. Introduce `domain::ports` traits without changing behavior.
2. Move the current “PSKT ceremony plumbing” behind `TxTemplateEnginePort` + `ChainClientPort`.
3. Update coordination handlers to depend only on ports, not direct chain/provider crates.
4. Introduce ceremony module boundaries:
   - multisig uses `PartialSigRecord` only,
   - musig2/frost exist but return `Unsupported`.
