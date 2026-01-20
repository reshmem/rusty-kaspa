# Hyperlane Devnet (Anvil + Hyperlane Agents + Igra)

This document specifies how we will run a **fully local** Hyperlane devnet that delivers real Hyperlane messages from an **EVM Anvil chain** into the existing **Igra Kaspa devnet**, using the **real Hyperlane validator + relayer agents** (Rust) and the `hyperlane-kaspa` chain client (HTTP → `igra-service`).

It is written as an implementation guide for a new orchestration script:

- `orchestration/devnet/scripts/run_local_devnet_with_avail_and_hyperlane.sh` (name kept for compatibility; the EVM devnet is **Anvil**, not Avail).

This devnet is intended for debugging and iteration (no Docker, no cloud infra).

---

## Goals

- Bring up a local Kaspa devnet + 3x `igra-service` signers (existing behavior).
- Bring up a local EVM devnet (Anvil).
- Deploy Hyperlane **core contracts** onto Anvil (Mailbox, MerkleTreeHook, ValidatorAnnounce, IGP, etc.).
- Run **2 Hyperlane validators** (threshold **2**) signing origin checkpoints and **announcing** their checkpoint storage locations on-chain.
- Run **3 Hyperlane relayers**, each configured to deliver to Igra (Kaspa) via the `hyperlane-kaspa` HTTP client (one relayer per `igra-service` instance).
- Provide a helper script to send **real EVM `Mailbox.dispatch()` transactions** whose bodies encode `(kaspa_address, amount)` in the format Igra expects.
- Keep all state under a single `--root` directory and manage PIDs the same way as existing devnet scripts.

---

## Non-Goals (for this phase)

- No Docker / no containers.
- No multi-origin / multi-destination topologies (only Anvil → Kaspa).
- No additional ISM modes beyond `message_id_multisig`.
- No production hardening (rate limits, monitoring, key custody, etc.).

---

## Key Constraints / Decisions

### D1. No fake Hyperlane in the “real agents” devnet

- `run_local_devnet.sh` must gain a `--no-fake-hyperlane` flag that **prevents starting any fake hyperlane process** during `start`.
- The new “Anvil + Hyperlane” script will start Igra devnet via `run_local_devnet.sh --no-fake-hyperlane ...`.

### D2. Hyperlane fork + branch

- Repo: `https://github.com/reshmem/hyperlane-monorepo.git`
- Branch: `devel`
- All Hyperlane processes will be run from a checkout under the same `--root` tree.

### D3. Validator keys must be aligned with Igra acceptance

- Igra verifies Hyperlane metadata signatures against the configured validator pubkeys.
- Devnet source of truth remains `orchestration/devnet/hyperlane-keys.json` (and the `hyperlane_keys` section embedded into `devnet-keys.json` by our keygen flow).
- The Hyperlane validator agents must use the same validator private keys.
- **Interop detail:** Igra stores validators as secp256k1 pubkeys, but the `validators_and_threshold` RPC returns **EVM addresses** (padded to 32 bytes) derived from those pubkeys so real Hyperlane relayers can query `ValidatorAnnounce`.

### D4. Local filesystem checkpoint syncers (no S3/GCS)

- Each validator writes checkpoints to a local directory and announces the location as a `file://...` URL.
- Relayers must run with `allowLocalCheckpointSyncers=true`.

### D5. 2 validators, threshold = 2

- Hyperlane validator set size: 2
- Threshold: 2
- This threshold is enforced at destination verification time (Igra) via `validators_and_threshold` and `dry_run_verify`.

### D6. EVM prefunded deployer account must be recorded in devnet keys

- We will extend `orchestration/devnet/devnet-keys.json` generation to include an `evm` section with:
  - mnemonic/seed (or explicit private key),
  - address,
  - public key (optional, derivable),
  - private key hex (required for automation).
- For the first iteration we will use Anvil’s default prefunded account:
  - private key: `0xac0974be...f2ff80`
  - address: `0xf39Fd6e5...2266`

### D7. Message format into Igra (body encoding)

The EVM message body that Igra expects is:

```
body := amount_sompi_u64_le || kaspa_address_utf8_bytes
```

- `amount_sompi_u64_le` is 8 bytes little-endian.
- The remaining bytes are a UTF-8 Kaspa address string (e.g. `kaspadev:qq...`).

This matches the current Hyperlane processing handler in Igra.

### D8. Devnet constants (locked in)

- Kaspa Hyperlane domain id: `7` (legacy devnet value)
- Anvil origin domain id: `31337` (from `anvil1` metadata)
- Destination address for transfers: the **Kaspa mining address** from `devnet-keys.json` (`wallet.mining_address`)

### D9. EVM `recipientAddress` mapping (bytes32)

Hyperlane `Mailbox.dispatch` requires a `bytes32 recipientAddress`, but our actual transfer destination is a **Kaspa address string** carried in the message body (D7/D8).

For devnet we will set:

```
recipientAddress := keccak256("igra:kaspa-miner-recipient:v1:" || kaspa_mining_address_utf8)
```

Rationale:
- deterministic and stable across runs (given the same mining address),
- does not require any on-chain destination contract semantics,
- avoids pretending a Kaspa address can be represented as an EVM `bytes32` “address”.

---

## High-Level Architecture / Process Topology

```
          (origin chain)                                        (destination “chain”)
 ┌─────────────────────────┐                         ┌─────────────────────────────────────┐
 │        Anvil EVM        │                         │     3x igra-service signers         │
 │  Mailbox + Hook + ...   │                         │  (Kaspa PSKT + CRDT threshold)      │
 └───────────┬─────────────┘                         └───────────────┬─────────────────────┘
             │ dispatch()                                             │ HTTP/JSON-RPC
             ▼                                                        │ (hyperlane-kaspa)
      ┌───────────────┐                                              ▼
      │ Validators (2) │  announce(file://...)                ┌───────────────────────────────┐
      │ sign checkpoints│────────────────────────────────────► │ Hyperlane Relayers (3)        │
      └───────┬────────┘                                       │ each targets a signer RPC URL │
              │ writes local checkpoints                        └───────────────┬──────────────┘
              ▼                                                               process()
        file:// checkpoint dirs                                                  │
                                                                                ▼
                                                                         Kaspa transaction
                                                                         (2-of-3 signer CRDT)
```

Notes:
- Multiple relayers may attempt to deliver the same message concurrently. This is safe but may cause redundant calls.
- Delivery idempotence comes from the Hyperlane message ID and Igra’s `delivered(message_id)` behavior converging via CRDT completion indexing.

---

## Directory Layout under `--root`

We will keep the same root semantics as `run_local_devnet.sh`, and add a `hyperlane/` subtree:

```
<ROOT>/
  bin/                         # staged binaries (existing)
  config/                      # igra configs (existing)
  logs/                        # logs (existing)
  pids/                        # pidfiles (existing)
  sources/
    rusty-kaspa/               # existing clone mode layout
    kaspa-miner/
    hyperlane-monorepo/        # new: cloned from reshmem/hyperlane-monorepo@devel
  hyperlane/
    anvil/
      state/                   # anvil state dir
      logs/
      pids/
    registry/                  # Hyperlane CLI registry dir (local)
      chains/anvil1/metadata.yaml
      deployments/...
    core/
      core-config.yaml         # input to `hyperlane core deploy`
      addresses.yaml|json      # outputs (if we choose to materialize)
    validator-1/
      config/agent.json
      db/
      checkpoints/             # local storage (announced via file://)
      logs/
      pids/
    validator-2/...
    relayer-1/
      config/agent.json
      db/
      logs/
      pids/
    relayer-2/...
    relayer-3/...
```

We will keep per-process config directories so `./config/*.json` merging cannot accidentally combine multiple agents’ settings.

---

## Required Local Prerequisites

The orchestration script will `require_cmd` these (and fail with install hints):

- Foundry: `anvil`, `cast`
- Node tooling: `node`, `pnpm`
- Rust: `cargo`, `rustc`
- Common: `git`, `jq` (optional but strongly recommended for extracting JSON/YAML outputs)

---

## Configuration Overview (Hyperlane Agents)

Hyperlane agents load settings from:

1) `./config/*.json` (relative to their current working directory)
2) extra files in `CONFIG_FILES` (comma-separated JSON files)
3) environment variables prefixed by `HYP_...`

We will run each agent in its own working dir that contains a `config/agent.json`.

### Core pieces we must provide to agents

#### Origin chain (Anvil / Ethereum protocol)

- `chains.anvil1.domainId = 31337`
- `chains.anvil1.rpcUrls = ["http://127.0.0.1:<anvil_port>"]`
- `chains.anvil1.addresses` populated from `hyperlane core deploy` output:
  - mailbox, validatorAnnounce, merkleTreeHook, interchainGasPaymaster
- origin chain signer must be funded (for deploy + validator announce)

#### Destination chain (“kaspa” protocol via `igra-service`)

For the relayer only:

- `chains.kaspa.domainId = <KASPA_DOMAIN_ID>`
- `chains.kaspa.protocol = "kaspa"`
- `chains.kaspa.rpcUrls = ["http://127.0.0.1:8088"]` (and similarly 8089/8090 per relayer)
- `chains.kaspa.addresses.mailbox` = `0x<group_id_as_h256>`
- `chains.kaspa.addresses.interchainSecurityModule` = `0x<group_id_as_h256>`

This matches the expectations of the `hyperlane-kaspa` client and the Hyperlane base types.

---

## Step-by-Step Orchestration Plan

This is the intended workflow inside `run_local_devnet_with_avail_and_hyperlane.sh`.

### Phase 0 — Start Igra devnet (Kaspa + signers)

1) Call:
   - `HYPERLANE_DOMAIN=31337 orchestration/devnet/scripts/run_local_devnet.sh --root <ROOT> --no-fake-hyperlane default`
   - or, if keys/config already exist:
     `... start all`
2) Wait for all three `igra-service` HTTP servers to return `GET /health`.

### Phase 1 — Start Anvil

1) Start Anvil with stable ports and state dir:
   - `anvil -p 8545 --chain-id 31337 --state <ROOT>/hyperlane/anvil/state ...`
2) Record PID and logs under `<ROOT>/hyperlane/anvil/*`.

### Phase 2 — Fetch + build Hyperlane monorepo (local)

1) Clone or update:
   - `<ROOT>/sources/hyperlane-monorepo` from `reshmem/hyperlane-monorepo@devel`
2) Build JS CLI prerequisites:
   - `pnpm -C <repo> install`
3) Build Rust agents (release recommended for stability):
   - `cargo build -p validator --release`
   - `cargo build -p relayer --release`

Important: the relayer must be built with Kaspa support enabled (see “Open Risks”).

### Phase 3 — Deploy Hyperlane core contracts onto Anvil

1) Prepare registry dir:
   - Copy `typescript/cli/test-configs/anvil/chains/anvil1/metadata.yaml` into `<ROOT>/hyperlane/registry/chains/anvil1/metadata.yaml`
2) Prepare `core-config.yaml` in `<ROOT>/hyperlane/core/core-config.yaml`:
   - `owner` = EVM deployer address (prefunded)
   - default hook/ism can remain the CLI example defaults for local testing
3) Run:
   - `pnpm --filter @hyperlane-xyz/cli -C <repo> run hyperlane core deploy --registry <ROOT>/hyperlane/registry --config <ROOT>/hyperlane/core/core-config.yaml --chain anvil1 --key <EVM_DEPLOYER_PRIVKEY> --yes`
4) Extract deployed addresses from registry outputs and materialize them into files the validator/relayer configs can consume (JSON is easiest).

### Phase 4 — Fund validator accounts (if needed)

If validator private keys are not one of Anvil’s pre-funded accounts:

1) Derive each validator EVM address from its private key (via `cast wallet address --private-key ...`).
2) Send ETH from the deployer:
   - `cast send --private-key <deployer> <validator_addr> --value 10ether --rpc-url http://127.0.0.1:8545`

### Phase 5 — Start Hyperlane validators (2)

For each validator `v1`, `v2`:

1) Create working dir: `<ROOT>/hyperlane/validator-i/`
2) Write `config/agent.json` with:
   - `originChainName = "anvil1"`
   - `validator` signer conf using the validator private key
   - `checkpointSyncer = { type: "localStorage", path: "<ROOT>/hyperlane/validator-i/checkpoints" }`
   - `chains.anvil1` (rpcUrls + deployed core addresses)
3) Run validator binary from within that working dir.
4) Verify it successfully self-announces:
   - either via logs (“Validator has announced signature storage location”)
   - or by querying `ValidatorAnnounce` contract via `cast call`.

### Phase 6 — Start Hyperlane relayers (3)

For each relayer `r1..r3`:

1) Create working dir: `<ROOT>/hyperlane/relayer-i/`
2) Write `config/agent.json` with:
   - `relayChains = "anvil1,kaspa"`
   - `allowLocalCheckpointSyncers = true`
   - `chains.anvil1` (rpcUrls + deployed addresses)
   - `chains.kaspa`:
     - `rpcUrls = ["http://127.0.0.1:8088"]` (then 8089/8090 for other relayers)
     - `domainId = <KASPA_DOMAIN_ID>`
     - `protocol = "kaspa"`
     - `addresses.mailbox = 0x<group_id>`
     - `addresses.interchainSecurityModule = 0x<group_id>`
3) Run relayer binary from within that working dir.
4) Verify relayers can:
   - index origin chain messages (logs)
   - call destination endpoints:
     - `/rpc/mailbox/delivered/{id}`
     - JSON-RPC `hyperlane.mailbox_process`

### Phase 7 — Message sender helper

Add a small Rust helper binary (separate from orchestration) to dispatch messages:

- Proposed location: `igra-service/src/bin/hyperlane_anvil_sender.rs`

It should:

1) Read Anvil mailbox contract address from `<ROOT>/hyperlane/registry/...` outputs.
2) Read destination domain id and recipient bytes32:
   - destination domain id = `7`
   - recipient bytes32 computed from the Kaspa mining address (D9)
3) Encode message body as described in D7.
4) Call the Mailbox contract directly via `alloy` (no shelling out to `cast`).

Optional: accept flags for number of messages, random amounts, and random recipient selection among the devnet signer addresses.

---

## Verification / Smoke Checks

### Hyperlane layer

- Validators:
  - announce successfully (validator logs + on-chain state)
  - write checkpoints locally (files under `validator-i/checkpoints/`)
- Relayers:
  - observe `dispatch` events on Anvil
  - fetch validator storage locations from `ValidatorAnnounce`
  - build metadata for `message_id_multisig` using 2-of-2 signatures
  - call Igra destination `mailbox_process`

### Igra layer

- `GET http://127.0.0.1:8088/rpc/mailbox/delivered/<messageId>` transitions from false → true after processing.
- A Kaspa transaction is created and broadcast, and CRDT completion is indexed in storage.

---

## Open Risks / Known Unknowns

1) **Relayer build feature wiring for Kaspa**
   - The relayer must be compiled with `hyperlane-base`’s `kaspa` feature enabled.
   - If the current `devel` branch does not forward this feature into the relayer binary, we will patch the Hyperlane fork (minimal change: add a relayer crate feature that enables `hyperlane-base/kaspa`, and build with it).

2) **Kaspa destination domain id**
   - Locked to `7` for devnet; keep consistent across:
     - the EVM `dispatch(destinationDomain=7, ...)`,
     - relayer destination chain config (`chains.kaspa.domainId = 7`),
     - Igra config and indexing.

3) **Recipient semantics**
   - Today Igra extracts destination address from the **message body**, not `message.recipient`.
   - Devnet will set `message.recipient` deterministically from the Kaspa mining address (D9).

4) **Duplicate deliveries across multiple relayers**
   - With three relayers, we may see redundant `process()` calls if `delivered(message_id)` hasn’t converged across signers yet.
   - This is acceptable for devnet; if it causes noise we can later add a single-relayer option or a lightweight “shared delivered cache”.

---

## Questions (remaining)

1) None for now; sender helper will be implemented as a Rust binary that calls Anvil directly using an embedded ABI via `alloy`.
