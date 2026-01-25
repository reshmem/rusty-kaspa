# Design-2 Execution Plan (Detailed)

This plan executes the architecture described in `Desing-2.md` and `Design-2-Impl.md`, while following the non-architecture standards in `CODE-GUIDELINE.md` (structured errors, no `unwrap()` in prod, logging context, naming, etc.).

## Ground Rules (from `CODE-GUIDELINE.md`)

- No `.unwrap()` / `.expect()` outside tests.
- Avoid `ThresholdError::Message` except the outermost edge (CLI/HTTP response formatting). Prefer structured variants and add new ones to `igra-core/src/foundation/error.rs`.
- Logs must include identifiers (`event_id`, `round`, `peer_id`, `tx_template_hash`) and use `hex::encode()` for `Hash32`.
- No magic numbers; use named constants with units (prefer `igra-core/src/foundation/constants.rs` for domain policy constants).
- Keep handlers as free functions (no OO handler structs).

## Execution Model

- We do this in small, compiling checkpoints aligned to M1–M8 in `Design-2-Impl.md`.
- Each step below states:
  - **Goal**
  - **Edits**
  - **Verification** (commands/tests)
  - **Notes** (common pitfalls)

## Phase 0 — Baseline and Safety Net

### 0.1 Capture “known-good” baseline behavior

**Goal**
- Establish a reference so refactors don’t silently change behavior.

**Edits**
- None.

**Verification**
- Run:
  - `cargo check -p igra-core`
  - `cargo check -p igra-service`
  - `cargo test -p igra-core`
  - `cargo test -p igra-service`

**Notes**
- If test coverage is thin, add a minimal “flow test” with mocks later (Phase 3/4) to cover propose→commit→sign→finalize invocation.

### 0.2 Inventory of current “hard couplings” (for tracking)

**Goal**
- Maintain a checklist of Kaspa-specific fields and where they are used.

**Edits**
- Add/update a short tracking section in `Design-2-Impl.md` if needed (no code changes).

**Verification**
- Use grep:
  - `rg "kaspa_" igra-core/src/domain igra-service/src`
  - `rg "kpsbt_blob|PSKT|pskt" igra-core/src igra-service/src`

## Phase 1 — M1: Create `domain/`, `app/`, `infra/` Skeleton in `igra-core`

### 1.1 Add module tree and re-export shims

**Goal**
- Create `igra-core/src/{domain,app,infra}` with `mod.rs` files, while keeping the old module paths working.

**Edits**
- Add:
  - `igra-core/src/domain/mod.rs`
  - `igra-core/src/domain/{model,protocol,crdt,coordination,ceremony,ports}/mod.rs`
  - `igra-core/src/app/mod.rs`
  - `igra-core/src/app/{usecases,wiring}/mod.rs`
  - `igra-core/src/infra/mod.rs`
  - `igra-core/src/infra/{event_providers,chains,ceremonies,signers,transport,storage}/mod.rs`
- Each new module initially `pub use`-reexports existing items from their current locations.

**Verification**
- `cargo check -p igra-core`

**Notes**
- Keep naming `snake_case`.
- Prefer minimal changes; do not change behavior yet.

## Phase 2 — M2: Move Canonical Types into `domain/{model,protocol}`

This phase is mostly mechanical but high-impact: it reduces churn later by stabilizing import paths.

### 2.1 Move `Event` and related canonical models to `domain/model`

**Goal**
- Make domain model types live under `igra-core/src/domain/model/*`.

**Edits**
- Move types from current locations into:
  - `igra-core/src/domain/model/event.rs` (or similar)
  - `igra-core/src/domain/model/group.rs`
  - `igra-core/src/domain/model/policy.rs`
- Re-export from `igra-core/src/domain/model/mod.rs`.
- Keep compatibility re-exports temporarily (old modules `pub use` from new path).

**Verification**
- `cargo check -p igra-core`
- `cargo check -p igra-service`

**Notes**
- **Event.destination**:
  - Follow Phase A in `Design-2-Impl.md`: keep the current Kaspa type temporarily.
  - Ensure coordination/app layers treat it as opaque; only chain adapters interpret it.

### 2.2 Move “wire/state” structs to `domain/protocol`

**Goal**
- Consolidate protocol/CRDT-visible structs under `igra-core/src/domain/protocol/*`.

**Edits**
- Move or define:
  - `Proposal`, `ProposalBroadcast`
  - `EventPhase`, `PhaseContext`, `EventPhaseState`
  - `EventCrdtState` payload types (currently tied to transport)
  - `PartialSigRecord` (existing)
  - `SigningArtifact` (skeleton; even if unused)
  - `CompletionRecord` with chain-neutral `FinalityAnchor` (per docs)

**Verification**
- `cargo check -p igra-core`
- `cargo check -p igra-service`

**Notes**
- Do not change serialization formats lightly; if you do, version the schema.
- Ensure `SigningArtifact` is treated as opaque bytes in all non-ceremony code.

## Phase 3 — M3: Make CRDT Merge Rules Explicit + Add Tests

### 3.1 Extract merge rules into `domain/crdt`

**Goal**
- Make CRDT behavior deterministic and testable, independent of storage/transport.

**Edits**
- Add functions like:
  - `merge_signatures(existing: &mut Vec<...>, incoming: &[...])`
  - `merge_artifacts(...)`
  - `merge_completion(...)`
- Define de-dup keys:
  - signatures: `(input_index, pubkey)` (existing behavior should be preserved)
  - artifacts: `(scheme, kind, sign_target, participant, bytes_hash)` or similar stable key
  - completion: LWW by `timestamp_nanos`

**Verification**
- Add unit tests under `igra-core/src/domain/crdt/*`:
  - no duplicate signature insertion
  - completion LWW behavior
  - artifact de-dup (even if unused by runtime)
- Run `cargo test -p igra-core`

**Notes**
- Avoid `unwrap()` in tests only where safe; otherwise use `expect("test setup: ...")`.
- If you need new errors, add structured variants (don’t use `ThresholdError::Message`).

## Phase 4 — M4: Introduce Ports (Traits) with Draft Signatures

### 4.1 Define ports in `domain/ports`

**Goal**
- Domain/app code depends on traits, not concrete implementations.

**Edits**
- Add port traits (draft signatures from `Design-2-Impl.md`):
  - `TxTemplateEnginePort`
  - `ChainClientPort`
  - `TransportPort`
  - `StoragePort`
  - `EventProviderPort`
  - `SignatureProviderPort`
  - `SigningProtocolPort`
  - `ClockPort`
- Add structured errors for unsupported features:
  - e.g. `ThresholdError::UnsupportedPortOperation { port, operation }`
  - e.g. `ThresholdError::UnsupportedCeremony { ceremony, operation }`

**Verification**
- `cargo check -p igra-core`
- `cargo test -p igra-core`

**Notes**
- Keep ports small; prefer multiple narrow traits over a mega-trait.
- `TxTemplateEnginePort` must remain pure (no RPC).

## Phase 5 — M5: Move Service Logic into `app/usecases` (Free Functions)

### 5.1 Extract use-cases from `igra-service/src/service/coordination/*`

**Goal**
- Make `igra-service` “thin runtime”, and move orchestration into `igra-core/src/app/usecases/*`.

**Edits**
- For each handler, create a corresponding usecase module, e.g.:
  - `app/usecases/handle_proposal_broadcast.rs`
  - `app/usecases/handle_crdt_broadcast.rs`
  - `app/usecases/try_commit.rs`
  - `app/usecases/try_sign.rs`
  - `app/usecases/try_submit.rs`
  - `app/usecases/tick_timeouts.rs`
- Use free-function style (per guideline).
- Replace direct concrete deps with ports:
  - `&dyn StoragePort`, `&dyn TransportPort`, `&dyn TxTemplateEnginePort`, `&dyn ChainClientPort`, etc.

**Verification**
- `cargo check -p igra-core`
- `cargo check -p igra-service`

**Notes**
- Keep logs and errors structured and contextual.
- Avoid leaking Kaspa types into app/usecases APIs.

## Phase 6 — M6: Implement Infra Adapters (Kaspa Real, Others Stubbed)

### 6.1 Add infra adapters under `igra-core/src/infra/*`

**Goal**
- Concrete implementations live in infra and satisfy domain ports.

**Edits**
- Implement ports by thin wrappers:
  - `infra/chains/kaspa/`:
    - `KaspaChainClient: ChainClientPort` (delegate to existing RPC client)
    - `KaspaTxTemplateEngine: TxTemplateEnginePort` (delegate to existing PSKT code)
  - `infra/storage/rocks/`: `RocksStorage: StoragePort`
  - `infra/transport/iroh/`: `IrohTransport: TransportPort`
  - `infra/signers/hd/`: `HdSignatureProvider: SignatureProviderPort`
- Add stubs:
  - `infra/chains/bitcoin/`: all methods return structured `Unsupported*` errors.

**Verification**
- `cargo check -p igra-core`
- `cargo check -p igra-service`

**Notes**
- PSKT relocation is optional at this stage:
  - Keep `domain/pskt/*` initially and delegate to it.
  - Relocate later once ports are stable.

## Phase 7 — M7: Ceremony Module + Stubs for MuSig2/FROST

### 7.1 Create `domain/ceremony` drivers

**Goal**
- Explicit ceremony boundary: multisig works; musig2/frost exist but fail fast.

**Edits**
- `domain/ceremony/multisig.rs`: implemented using ports.
- `domain/ceremony/musig2.rs`: stub returning `ThresholdError::UnsupportedCeremony`.
- `domain/ceremony/frost.rs`: stub returning `ThresholdError::UnsupportedCeremony`.
- Introduce `CeremonyKind` selection in `app/wiring`.

**Verification**
- Add tests:
  - multisig driver: mocked ports reach “threshold reached → finalize attempted”
  - musig2/frost: calling any entrypoint returns `UnsupportedCeremony`
- `cargo test -p igra-core`

**Notes**
- Keep ceremony logic free of RPC; it should request actions via ports.

## Phase 8 — Convert Runtime to `src/bin/*` (Replace `igra-service` crate)

User requirement: “service is like bin folder”. This phase folds runtime entrypoints into the library crate as bin(s).

### 8.1 Move binary entrypoints

**Goal**
- Replace `wallet/igra/igra-service` with `igra-core/src/bin/*` binaries.

**Edits**
- Add:
  - `igra-core/src/bin/kaspa-threshold-service.rs` (main entrypoint)
- Move CLI/HTTP wiring code from `igra-service/src/bin/*` and `igra-service/src/service/*` into:
  - `igra-core/src/bin/*` (runtime main)
  - `igra-core/src/app/wiring/*` (construction of ports and config parsing helpers)
- Update workspace `Cargo.toml` as needed:
  - remove/stop building the `igra-service` crate once parity is achieved

**Verification**
- `cargo check -p igra-core --bins`
- `cargo run -p igra-core --bin kaspa-threshold-service -- --help` (or equivalent)

**Notes**
- Keep “edge formatting” (CLI/HTTP) as the only place `ThresholdError::Message` is allowed.

## Phase 9 — Cleanup and De-Kaspa-ize Domain Types (Phase B)

### 9.1 Make domain truly chain-agnostic by construction

**Goal**
- Remove Kaspa-only types from domain model/protocol.

**Edits**
- Replace `Event.destination` with a chain-neutral wrapper:
  - `ScriptBytes(Vec<u8>)` or `Destination { chain: ChainId, script: Vec<u8> }`
- Replace Kaspa-only fields/terms:
  - `blue_score` → `FinalityAnchor` in `CompletionRecord` (already planned)
  - `kpsbt_blob` → `TxTemplateBlob`
- Push parsing/encoding into chain adapters (`TxTemplateEnginePort` / `ChainClientPort`).

**Verification**
- `cargo test -p igra-core`
- Re-run the “flow test” with mocks

**Notes**
- This is easiest once ports are already the only way coordination touches chain semantics.

## Deliverables Checklist

- `igra-core/src/domain/*` contains models, protocol schema, CRDT merge rules, coordination, ceremonies, and ports.
- `igra-core/src/app/*` contains use-cases + wiring only.
- `igra-core/src/infra/*` contains all concrete implementations.
- `igra-core/src/bin/*` contains runtime entrypoints (service).
- Kaspa + classic multisig path still works.
- Bitcoin/MuSig2/FROST compile as stubs and fail with structured `Unsupported*` errors if invoked.

