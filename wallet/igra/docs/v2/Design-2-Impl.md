# Design-2 Implementation Plan (Migration from Current Codebase)

This document describes a concrete, reviewable sequence to migrate the current `wallet/igra` codebase into the architecture described in `Desing-2.md` (with `src/{domain,app,infra}` and a runtime entrypoint under `src/bin/*`).

We are *not* optimizing for “production safety” yet; the goal is to reach the new shape quickly, keep the system compiling, and preserve behavior for the Kaspa + classic multisig path.

## Runtime placement: `src/bin/*` (service is a bin)

`src/{domain,app,infra}` is a *library architecture*. `igra-service` is a *runtime binary crate* (HTTP/CLI, task loops, process lifecycle, config loading, tracing/logging bootstrap).

We will converge on a **single crate** layout where:
- `src/{domain,app,infra}` contains library code
- `src/bin/*` contains runtime entrypoints (the “service”)

## Milestones and Acceptance Criteria

We gate the migration by compilation checkpoints:

1) **M1: Module skeleton exists**: `igra-core/src/{domain,app,infra}` builds; old paths still work via re-exports.
2) **M2: Domain types relocated**: coordination/CRDT code imports from `domain::{model,protocol,...}`.
3) **M3: Ports introduced**: `domain/ports/*` traits exist; app code depends on traits, not concrete infra types.
4) **M4: Use-cases extracted**: most logic from `igra-service/src/service/coordination/*` moved into `igra-core/src/app/usecases/*`.
5) **M5: Infra adapters**: storage/transport/rpc/signing implement domain ports in `igra-core/src/infra/*`.
6) **M6: Ceremony structure**: classic multisig implemented; MuSig2/FROST stubs return `Unsupported` errors.
7) **M7: Multi-provider/multi-chain wiring**: provider/chain/ceremony chosen in one place; Bitcoin/provider stubs compile.
8) **M8: Cleanup**: remove legacy module entrypoints, minimize re-export shims.

## Concrete Type Skeletons (for review)

These are the minimal “shape” definitions that make the plan reviewable. They are not final; they define the intent and expected responsibilities.

```rust
pub enum ChainId {
    Kaspa,
    Bitcoin,
}

pub enum TemplateFormat {
    Pskt,
    Psbt,
    Raw,
    Other(String),
}

pub struct TxTemplateBlob {
    pub chain: ChainId,
    pub format: TemplateFormat,
    pub bytes: Vec<u8>,
}

/// Deterministic identifier for a tx template (what we currently call `tx_template_hash`).
pub type TemplateId = [u8; 32];

pub struct FinalTx {
    pub chain: ChainId,
    pub bytes: Vec<u8>,
}

pub enum SigScheme {
    Secp256k1Ecdsa,
    Secp256k1Schnorr,
    Other(String),
}

pub struct SigningJob {
    pub input_index: u32,
    pub digest32: [u8; 32],
    pub scheme: SigScheme,
}

/// Existing concept today: replicated, one-shot partial signature for a specific input.
pub struct PartialSigRecord {
    pub signer_peer_id: PeerId,
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp_nanos: u64,
}

/// New (even if unused initially): replicated artifact for interactive schemes (MuSig2/FROST).
pub struct SigningArtifact {
    pub scheme: SigScheme,
    pub kind: ArtifactKind,
    pub sign_target: SignTarget,
    pub participant: ParticipantId,
    pub bytes: Vec<u8>,
    pub timestamp_nanos: u64,
}

pub enum ArtifactKind {
    NonceCommitment,
    PublicNonce,
    PartialSignature,
    TranscriptContext,
    Other(String),
}

pub enum SignTarget {
    Input { index: u32 },
    Tx,
    Other(String),
}

pub enum ParticipantId {
    Peer(PeerId),
    Pubkey(Vec<u8>),
    Other(String),
}
```

## Step-by-Step Plan

### Step 1 — Create the new module skeleton (no behavior changes)

Add directories and `mod.rs` files:
- `igra-core/src/domain/mod.rs`
- `igra-core/src/domain/{model,protocol,crdt,coordination,ceremony,ports}/mod.rs`
- `igra-core/src/app/mod.rs`
- `igra-core/src/app/{usecases,wiring}/mod.rs`
- `igra-core/src/infra/mod.rs`
- `igra-core/src/infra/{event_providers,chains,ceremonies,signers,transport,storage}/mod.rs`

Initial behavior: each new module just `pub use` re-exports existing items from old locations.

Acceptance:
- `cargo check -p igra-core` passes.
- No file moves yet.

### Step 2 — Relocate canonical domain types

Move (or copy-then-switch) these types:

**To `domain/model/`:**
- `Event`, `StoredEvent`, `CrdtSigningMaterial`, `GroupConfig`, policy types.

**To `domain/protocol/`:**
- `Proposal`, `ProposalBroadcast`
- `EventPhase`, `PhaseContext`, `EventPhaseState`
- CRDT payload structures that are transmitted/replicated (currently in transport messages).
- `PartialSigRecord` (existing).
- Add new `SigningArtifact` type (even if unused initially). See “Concrete Type Skeletons” above.
- `CompletionRecord` should be chain-neutral.

During this step:
- Update imports across `igra-core` and `igra-service` to point to the new module paths.
- Keep temporary `pub use` re-exports from old modules so callers don’t break all at once.

Acceptance:
- `cargo check -p igra-core` and `cargo check -p igra-service` pass.

### Step 3 — Make CRDT merge semantics explicit

Create `domain/crdt/` helpers:
- merge signatures (`PartialSigRecord`) with deterministic de-dup keys.
- merge artifacts (`SigningArtifact`) with deterministic de-dup keys (even if unused).
- merge completion record as LWW.

Then:
- Ensure storage merge calls a domain merge function (so rules aren’t “accidentally” split across layers).

Acceptance:
- existing behavior still works for current multisig flow.
- compilation passes.

### Step 4 — Define domain ports (traits)

Add traits in `domain/ports/` (names are flexible; keep them small and focused):

- `EventProviderPort` (verify/normalize provider payload → canonical `Event` + proof/audit)
- `TransportPort` (publish + subscribe protocol messages)
- `StoragePort` (persist and merge CRDT; proposals; phases)
- `ClockPort` (time)
- `TxTemplateEnginePort` (pure template semantics: validate/hash/signing plan/apply/finalize/txid)
- `ChainClientPort` (tip, utxos, fees, broadcast, status)
- `SignatureProviderPort` (key custody + local primitives; supports one-shot signing APIs)
- `SigningProtocolPort` (interactive sessions for MuSig2/FROST)

Guidelines:
- `TxTemplateEnginePort` MUST NOT do network I/O.
- `ChainClientPort` MUST be the only way to talk to a node/backend.
- `SigningProtocolPort` can exist even if not implemented; return `Unsupported` if invoked.

#### Draft port method signatures (for review)

The exact signatures can change, but having a draft clarifies intent and ownership.

```rust
pub trait TxTemplateEnginePort: Send + Sync {
    /// Validate the template blob and return derived facts needed by coordination.
    fn validate(&self, template: &TxTemplateBlob) -> Result<TemplateInfo, ThresholdError>;

    /// Compute the deterministic TemplateId (may be part of validate; kept separate for flexibility).
    fn template_id(&self, template: &TxTemplateBlob) -> Result<TemplateId, ThresholdError>;

    /// Derive the signing plan (what digests must be signed).
    fn signing_jobs(&self, template: &TxTemplateBlob) -> Result<Vec<SigningJob>, ThresholdError>;

    /// Apply one-shot partial signatures into the template (classic multisig path).
    fn apply_partial_sigs(&self, template: &TxTemplateBlob, sigs: &[PartialSigRecord]) -> Result<TxTemplateBlob, ThresholdError>;

    /// Apply interactive artifacts into the template/protocol state (MuSig2/FROST path).
    fn apply_artifacts(&self, template: &TxTemplateBlob, artifacts: &[SigningArtifact]) -> Result<TxTemplateBlob, ThresholdError>;

    /// Finalize into raw tx bytes ready for broadcast.
    fn finalize(&self, template: &TxTemplateBlob) -> Result<FinalTx, ThresholdError>;

    /// Compute tx id from raw bytes (or return a domain `TransactionId` type).
    fn txid(&self, final_tx: &FinalTx) -> Result<TransactionId, ThresholdError>;
}

pub struct TemplateInfo {
    pub template_id: TemplateId,
    pub input_count: usize,
}

pub trait SignatureProviderPort: Send + Sync {
    /// One-shot signing used by classic multisig flows (ECDSA P2WSH, Kaspa Schnorr, etc.).
    fn sign(&self, job: &SigningJob) -> Result<Vec<u8>, ThresholdError>;
    fn public_key_bytes(&self, scheme: SigScheme) -> Result<Vec<u8>, ThresholdError>;
}

pub trait SigningProtocolPort: Send + Sync {
    /// Interactive signing session engine (MuSig2/FROST). Stubs may return Unsupported.
    fn start(&self, job: &SigningJob, participants: &[ParticipantId]) -> Result<(SessionId, Vec<SigningArtifact>), ThresholdError>;
    fn handle(&self, session: &SessionId, inbound: &SigningArtifact) -> Result<Vec<SigningArtifact>, ThresholdError>;
    fn try_finish(&self, session: &SessionId) -> Result<Option<SigningArtifact>, ThresholdError>;
}

pub trait ChainClientPort: Send + Sync {
    fn tip(&self) -> Result<ChainTip, ThresholdError>;
    fn get_utxos(&self, addresses: &[String]) -> Result<Vec<Utxo>, ThresholdError>;
    fn estimate_fee(&self, request: &FeeEstimateRequest) -> Result<FeeEstimate, ThresholdError>;
    fn broadcast(&self, tx: &FinalTx) -> Result<TransactionId, ThresholdError>;
}
```

Note on `TxTemplateEnginePort::validate`:
- Today we “validate” by parsing PSKT and comparing against the claimed template hash; the port should return at least `TemplateInfo { template_id, input_count }`.

Acceptance:
- traits compile and are imported by app code (next step).

### Step 5 — Extract coordination handlers into app use-cases

Move logic out of:
- `igra-service/src/service/coordination/*`

Into:
- `igra-core/src/app/usecases/*`

The use-cases should:
- accept trait objects (`&dyn StoragePort`, `&dyn TransportPort`, `&dyn TxTemplateEnginePort`, etc.)
- return domain errors (`ThresholdError`) and domain outputs (protocol messages, state transitions)

Then reduce `igra-service` to:
- load config
- construct concrete infra implementations
- feed inbound messages into `app/usecases::handle_inbound_message`
- drive periodic ticks/timeouts

Acceptance:
- service still performs propose → commit → sign → submit for Kaspa path.
- compilation passes.

### Step 6 — Move concrete implementations into `infra/*` and implement ports

Create infra adapters that implement the domain ports by delegating to existing code.

Examples:
- `infra/transport/iroh/*` implements `TransportPort`
- `infra/storage/rocks/*` implements `StoragePort`
- `infra/chains/kaspa/*` implements:
  - `ChainClientPort` (RPC)
  - `TxTemplateEnginePort` (PSKT)
- `infra/signers/hd/*` implements `SignatureProviderPort`

At this stage you can keep existing internal module layout and just add thin wrappers.

#### Clarification: PSKT location (domain vs infra)

Step 6 does **not** require moving `domain/pskt/*` immediately (that would be a larger change).

Recommended incremental approach:

1) **Wrapper-first (no big move):**
   - Keep PSKT code where it is today.
   - Add `infra/chains/kaspa/*` adapters that implement ports and delegate into existing PSKT helpers.
   - Update app/usecases to depend on the ports only.

2) **Relocation later (optional cleanup):**
   - Once ports are stable, move PSKT implementation details under `infra/chains/kaspa/tx_template/*`.
   - This becomes a mechanical move because callers already go through `TxTemplateEnginePort`.

Acceptance:
- app use-cases depend only on ports; concrete types live in infra.

### Step 7 — Introduce ceremony drivers (multisig implemented; others stubbed)

In `domain/ceremony/`:
- `multisig.rs`: uses `TxTemplateEnginePort` + `SignatureProviderPort` + `ChainClientPort`
- `musig2.rs`: stub that returns `UnsupportedCeremony` on every call
- `frost.rs`: stub that returns `UnsupportedCeremony` on every call

Update coordination/app flow to call ceremony via an enum or trait object:
- `CeremonyKind::{Multisig, Musig2, Frost}`

Acceptance:
- multisig path still works.
- musig2/frost compile but fail fast if configured.

### Step 8 — Provider and chain matrix wiring (real Kaspa + stubs elsewhere)

Add provider selection in `app/wiring/`:
- Hyperlane provider (real or existing code moved)
- LayerZero provider (real or stub)
- Manual/API provider (real or stub)

Add chain selection in `app/wiring/`:
- Kaspa: real implementations
- Bitcoin: compile-time stubs returning `Unsupported` for now

Acceptance:
- config selects `{provider, chain, ceremony}` in one place.
- system compiles with all variants present.

### Step 9 — Clean up legacy module entrypoints

Once callers use the new module paths:
- remove old `application/` and `infrastructure/` module roots or turn them into `pub use crate::app` / `pub use crate::infra`.
- delete redundant re-export shims.

Acceptance:
- `igra-core` has clear separation: `domain`, `app`, `infra`.

## Specific “Known Tight Couplings” to Fix Early

These currently force Kaspa specifics into ceremony/coordination:

- `Event.destination` uses `kaspa_consensus_core::tx::ScriptPublicKey`.
- Proposal and CRDT state refer to `kpsbt_blob` and validate via PSKT decode.
- UTXO inputs use `kaspa_consensus_core` types.
- Kaspa blue score is used in completion/anchors.

For the migration, the fastest workable approach is:
- keep fields as-is initially but route accesses through ports (`TxTemplateEnginePort`, `ChainClientPort`)
- then replace types with chain-neutral equivalents once ports are in place.

### Clarification: `Event.destination` (“keep as-is” vs wrapper)

There are two viable phases:

- **Phase A (fastest):** keep `Event.destination` as the current Kaspa type during the migration, but ensure only chain-specific adapters touch it. Coordination/CRDT/app should treat it as opaque.
- **Phase B (target):** replace it with a chain-neutral wrapper (e.g. `ScriptBytes(Vec<u8>)` or `Destination { chain: ChainId, script: Vec<u8> }`) once ports are wired, so the domain becomes chain-agnostic by construction.

### Clarification: chain-neutral completion record

To avoid embedding Kaspa-specific names in the protocol, model completion finality as a generic anchor:

```rust
pub struct CompletionRecord {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,
    pub timestamp_nanos: u64,
    pub chain: ChainId,
    pub finality: Option<FinalityAnchor>,
}

pub enum FinalityAnchor {
    Score(u64),           // e.g. Kaspa blue score / DAA score
    Height(u64),          // e.g. Bitcoin block height
    Confirmations(u32),   // if that is what the backend provides
    Other(String, u64),   // escape hatch
}
```

## Test Strategy (migration verification)

This migration is primarily structural, but we still want behavioral confidence.

### What to preserve (baseline)

Before large moves, identify and lock in the “critical path”:
- proposal acceptance + deterministic quorum selection
- CRDT merge of signatures leading to “threshold reached”
- finalize + submit invoked (for Kaspa path)

### Milestone checks

- **M1/M2 (type moves):**
  - Run `cargo test -p igra-core` and `cargo test -p igra-service` (even if the suite is small).
  - Add/keep unit tests for pure selection logic and other deterministic helpers.

- **M3 (CRDT merge extraction):**
  - Add unit tests for merge rules:
    - de-dup for `PartialSigRecord` (e.g., same `(input_index, pubkey)` should not duplicate)
    - LWW semantics for completion records
    - artifact merge rules for `SigningArtifact` (even if unused initially)

- **M4/M5 (ports + usecases):**
  - Add tests at the usecase level with in-memory mocks:
    - mock storage + mock transport + mock chain client + mock template engine
  - Assert “given state X and message Y, next transition/outbound messages Z”.

- **M6 (ceremony drivers):**
  - Multisig: add a small end-to-end-in-process test that simulates signatures reaching threshold and finalization being attempted (with mocked broadcast).
  - MuSig2/FROST: tests only assert they return `Unsupported` for now.

If there are no existing integration tests today, the minimum valuable tests to add are:
1) selection/quorum unit tests (fast),
2) CRDT merge unit tests (fast),
3) one “flow test” using mocks (medium).

## Fee Estimation Ownership (port responsibility split)

This is intentionally spelled out to avoid confusion:

- `ChainClientPort` owns **data acquisition**:
  - fee rate source (Kaspa fee per gram / Bitcoin sat/vB),
  - chain tip/finality,
  - UTXO discovery.

- `TxTemplateEnginePort` owns **template semantics**:
  - size/mass/weight accounting and how fee rate translates to absolute fee,
  - chain-specific script/witness overhead.

Pragmatic migration rule:
- Keep fee behavior as-is initially, but ensure app/usecases do not compute mass/vbytes directly; route through one port boundary.

## Effort Notes (non-binding)

No strict timeline is committed in this plan, but for rough expectations:
- **M1–M2**: mostly mechanical refactor (low/medium).
- **M3–M5**: real design work (medium); most churn happens here.
- **M6–M7**: multisig stability + wiring (medium); MuSig2/FROST stubs are low.
- **M8**: cleanup cost depends on how many shims remain (medium).
