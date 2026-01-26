# Local EVM + Hyperlane + Igra (E2E Devnet)

This document explains the exact mechanics of `orchestration/devnet/scripts/run_local_devnet_with_avail_and_hyperlane.sh`: what it runs, how components connect, and how `hyperlane_anvil_sender` dispatches messages into Anvil.

## Big Picture

This runner composes three layers:

1. **Kaspa + Igra devnet** (3 signer instances) started by `run_local_devnet.sh` with `--no-fake-hyperlane`.
2. **Anvil** (local EVM) providing the **origin chain** where Hyperlane core contracts live.
3. **Hyperlane agents** (2 validators + 3 relayers) delivering messages from Anvil to Igra via Igra’s Hyperlane JSON-RPC adapter.

## Ports and Processes

**Kaspa + Igra (from `run_local_devnet.sh`)**

- `kaspad`: `grpc://127.0.0.1:16110`
- Igra signers (`kaspa-threshold-service`):
  - `signer-01`: `http://127.0.0.1:8088`
  - `signer-02`: `http://127.0.0.1:8089`
  - `signer-03`: `http://127.0.0.1:8090`

**Anvil (EVM)**

- Anvil JSON-RPC: `http://127.0.0.1:8545` (chain id `31337`)

**Hyperlane agents**

- Validators (watch Anvil, produce checkpoints):
  - `validator-1` metrics: `9910`
  - `validator-2` metrics: `9911`
- Relayers (deliver to Igra):
  - `relayer-1` metrics: `9920`, targets Igra `:8088`
  - `relayer-2` metrics: `9921`, targets Igra `:8089`
  - `relayer-3` metrics: `9922`, targets Igra `:8090`

## Directory Layout Under `--root`

The script uses a single root directory (default `$(pwd)/igra_devnet`):

- `config/`
  - `igra-config.toml` (generated; includes Hyperlane validator pubkeys)
  - `hyperlane-keys.json` (generated; validator private keys for Hyperlane agents)
  - `devnet-keys.json` (generated; includes Anvil prefunded deployer key)
- `bin/` (staged binaries, including `hyperlane_anvil_sender`)
- `logs/` and `pids/` (Kaspa + Igra processes)
- `hyperlane/`
  - `registry/` (Hyperlane “registry” used by the CLI and sender to find deployed addresses)
  - `core/` (temporary core deploy config)
  - `validator-*/` (config/db/checkpoints)
  - `relayer-*/` (config/db)
  - `logs/` and `pids/` (Hyperlane processes)

## What the Script Actually Does

### `default`

`default` brings up everything from scratch:

1. Calls `run_local_devnet.sh default` (with `--no-fake-hyperlane`) to build/stage binaries, generate keys/configs, and prepare the devnet root.
2. Starts Anvil on `:8545`.
3. Clones/builds the Hyperlane fork and builds the `validator` and `relayer` agents.
4. Deploys Hyperlane core contracts to Anvil.
5. Funds the 2 validator EVM accounts (so they can sign/announce).
6. Starts 2 validators + 3 relayers.

### `start`

`start` assumes the root already exists:

1. Calls `run_local_devnet.sh start all` (with `--no-fake-hyperlane`) to start Kaspa + Igra signers.
2. Starts Anvil.
3. (Re)builds Hyperlane agents if needed, ensures core is deployed, funds validators, then starts validators/relayers.

### `send`

`send` dispatches EVM messages into the Anvil Mailbox using `bin/hyperlane_anvil_sender` (details below).

## How Messages Flow End-to-End

### Domain ids

- **Anvil** domain id: `31337` (origin)
- **Kaspa devnet** domain id: `7` (destination)

### Flow

1. **Dispatch on Anvil**: `Mailbox.dispatch(destinationDomain=7, recipientAddress=bytes32, messageBody=bytes)`.
2. **Validators observe** the origin chain (Anvil Mailbox events), sign checkpoints, and write signed checkpoints to local disk.
3. **Relayer picks up** message + validator signatures and submits the delivery to Igra via Igra’s Hyperlane JSON-RPC adapter (`/rpc`).
4. **Igra verifies** the proof (signatures/metadata) against its configured Hyperlane validator set and then enqueues a signing flow based on the message body.
5. **Threshold signing** runs across the Igra signer set (iroh gossip), producing/approving the Kaspa transaction.

## Igra’s “Hyperlane Destination Adapter”

Hyperlane relayers expect a “destination chain adapter”. For Kaspa devnet, the relayer is configured to talk HTTP to Igra, not an EVM.

The Igra service exposes:

- JSON-RPC endpoint: `POST http://127.0.0.1:8088/rpc` (and similarly for 8089/8090)
  - Implements `hyperlane.validators_and_threshold` and `hyperlane.mailbox_process`.
- Convenience endpoints (HTTP):
  - `GET /rpc/mailbox/default_ism`
  - `GET /rpc/mailbox/count`
  - `GET /rpc/mailbox/delivered/<message_id>`
  - `POST /rpc/mailbox/estimate_costs`
  - `GET /rpc/ism/module_type`
  - `POST /rpc/ism/dry_run_verify`

## How `hyperlane_anvil_sender` Dispatches

Source: `igra-service/src/bin/hyperlane_anvil_sender.rs`.

For the rationale and exact schema of `recipientAddress` vs the Kaspa address payload, see:

- `orchestration/devnet/Hyperlane-EVM-recipientAddress.md`

### Inputs it uses

- **Anvil RPC URL**: default `http://127.0.0.1:8545`
- **Mailbox contract**:
  - Either `--mailbox 0x...`, or
  - Loaded from the registry: `--registry <ROOT>/hyperlane/registry --chain anvil1` (reads `chains/anvil1/addresses.yaml`)
- **EOA private key** (`--private-key 0x...`):
  - For devnet orchestration, this is read from `<ROOT>/config/devnet-keys.json` as `evm.private_key_hex`.
  - `devnet-keygen` intentionally emits an **Anvil prefunded deployer private key**, so the account has ETH to pay gas.
- **Kaspa destination address**:
  - Either `--kaspa-address kaspadev:...`, or
  - Loaded from `<ROOT>/config/devnet-keys.json` as `wallet.mining_address`.
- **Destination domain**:
  - default `7` (Kaspa devnet)

### Recipient bytes32 (Hyperlane’s `recipientAddress`)

Hyperlane’s `Mailbox.dispatch` uses a `bytes32 recipientAddress`. In our devnet, the “real” recipient (Kaspa address string) lives in the message body; the `recipientAddress` is a stable tag-hash:

- `recipient_bytes32 = keccak256("igra:v1:" + <kaspa_address>)`

### Message body format (what Igra parses)

The body bytes are:

- `amount_sompi` as **little-endian u64** (8 bytes)
- followed by the **UTF-8 bytes** of the Kaspa address string

### The actual EVM call

The binary ABI-encodes and sends:

- `dispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes messageBody)`

It constructs an EVM transaction:

- `to = mailbox_address`
- `data = abi_encode(dispatch(...))`
- `value = 0` (no ETH attached; this is important if you later configure a hook that requires `msg.value`)

### How gas is paid

- The transaction is signed by the EOA derived from `--private-key`.
- **Gas is paid in ETH by that EOA**, like any normal Anvil/Ethereum transaction.
- The binary uses Alloy’s `ProviderBuilder::with_recommended_fillers()` to automatically fill things like nonce, gas estimates, and fees.

### What it does *not* do

- It does **not** call `InterchainGasPaymaster.payForGas(...)`.
- It does **not** explicitly attach ETH to `dispatch` as `msg.value`.

That’s fine for local dev because you run the relayer yourself; there is no economic requirement. If you later configure Mailbox hooks that require a protocol fee (`msg.value`) or want to simulate production gas-payment semantics, you’ll need to extend the sender to:

- set a non-zero transaction value (for protocol-fee hooks), and/or
- call the IGP contract to pay interchain gas.

## Port Conflicts / Orphans (Why This Matters)

If an old Anvil/validator/relayer or an old Igra instance is still listening on the expected port, a new process can fail to bind while your health checks and relayers accidentally talk to the old instance.

Both:

- `orchestration/devnet/scripts/run_local_devnet.sh`, and
- `orchestration/devnet/scripts/run_local_devnet_with_avail_and_hyperlane.sh`

now detect port ownership and will:

- kill **known** leftover devnet processes on the expected ports, and
- refuse to kill unknown processes (to avoid destroying unrelated work).
