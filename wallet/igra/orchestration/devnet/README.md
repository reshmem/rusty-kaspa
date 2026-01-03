# Igra Devnet Orchestration

This folder provides a devnet environment with a Kaspa node, a miner, and a Rothschild wallet container to fund multisig addresses for integration testing.

## What It Runs

- **kaspad**: devnet node with UTXO index enabled.
- **kaspaminer**: connects to the node and produces blocks. Built from `tmrlvi/kaspa-miner` (CPU miner); override with `KASPA_MINER_REPO`/`KASPA_MINER_REF` if you need a different fork/tag.
- **rothschild**: wallet CLI used to initialize a devnet wallet and send funds to multisig addresses.
- **igra-service**: containerized kaspa-threshold-service built from the forked repo.

## How Components Connect

- `kaspad` exposes `grpc://localhost:16110` which is used by Igra services for UTXO reads and PSKT construction.
- `kaspaminer` mines blocks and pays rewards to `KASPA_MINING_ADDRESS` (owned by the Rothschild wallet). The default command uses `--kaspad-address=kaspad --port=16110 --mine-when-not-synced`.
- `rothschild` holds the devnet wallet keys and funds multisig addresses; it only needs access to the wallet volume.
- Hyperlane is **not** part of devnet; we mock events via JSON-RPC with a local fake Hyperlane loop inside `igra-service`.

## Build From Source

The images are built from the local `rusty-kaspa` checkout using the Dockerfiles copied from the root `docker/` directory. This keeps the devnet setup self-contained while reusing upstream build logic.

## Setup

1) Copy the environment file and update the wallet mnemonic/addresses if needed:
```bash
cp .env.example .env
```

2) Build images:
```bash
make build
```

3) Initialize the devnet wallet and obtain a mining address:
```bash
make bootstrap
```

4) Start devnet node, miner, and igra-service:
```bash
make up
```

5) Tail logs until you see blocks being mined:
```bash
make logs
```

## Wallet Bootstrap (Rothschild)

Use the wallet container to initialize and manage a devnet wallet. Commands are run via `docker compose run` so the wallet data persists in the `wallet-data` volume.

### Create or Restore Wallet

The `./scripts/bootstrap_wallet.sh` script creates the wallet (if needed) and updates `KASPA_MINING_ADDRESS` in `.env`.

## Funding Multisig Addresses

Once blocks are mined and the wallet has balance, send funds to the multisig addresses used by Igra. The sample `multisig-addresses.txt` file is a template; replace the placeholders with real addresses.

```bash
make fund
```

Repeat for additional multisig addresses. Adjust amounts to match your test scenarios.

## Notes on Miner Keying

Mining rewards are paid to `KASPA_MINING_ADDRESS`, which is derived from the Rothschild wallet. Wallet keys live in the `wallet-data` volume and are used only by the `wallet` container. The miner does not require access to private keys; it only needs the payout address.

## Makefile Shortcuts

- `make build` - build all images
- `make bootstrap` - create wallet + set mining address
- `make up` - start kaspad + miner
- `make up-miner` - restart only the miner (after changing `KASPA_MINING_ADDRESS`)
- `make logs` - follow kaspad logs
- `make fund` - fund multisig addresses
- `make down` - stop and remove containers
- `make devnet-all` - build + bootstrap + start kaspad/miner

## Hyperlane Local Bundle

Hyperlane’s local E2E harness is available under `orchestration/testnet/hyperlane/` and is not part of devnet.

## Fake Hyperlane (Devnet)

The devnet compose config runs a companion binary (`fake-hyperlane`) alongside `kaspa-threshold-service`. It submits a signed Hyperlane event to the local JSON-RPC every 10 seconds by default. Configure via environment variables in `orchestration/devnet/docker-compose.yml`:

- `HYPERLANE_INTERVAL_SECS`
- `HYPERLANE_START_EPOCH_SECS`
- `HYPERLANE_AMOUNT_SOMPI`
- `HYPERLANE_DESTINATION`
- `HYPERLANE_DOMAIN`
- `HYPERLANE_SENDER`
- `HYPERLANE_COORDINATOR_PEER_ID`
- `HYPERLANE_KEYS_PATH`

## Igra Docker

Igra’s container build lives under `orchestration/devnet/igra/`. It builds from the forked repo via SSH and runs `kaspa-threshold-service`.

## Notes

- Devnet blocks are mined locally and do not require external peers.
- `kaspad` RPC is exposed at `grpc://localhost:16110` for use by Igra.
- If Rothschild CLI flags differ in your version, run `rothschild --help` inside the container and adjust accordingly.
