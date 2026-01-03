# Hyperlane Local Bundle (Testnet)

This container runs Hyperlane's `run-locally` E2E harness, which uses **Anvil** (Foundry) for a local EVM chain and does not require a real external RPC.

## What Hyperlane Provides

From the Hyperlane v3 monorepo:
- `rust/main/utils/run-locally` is an automated local E2E harness.
- It spins up **Anvil** for a local EVM and runs validator/relayer/scraper agents.
- It also starts a Postgres container via `docker` for the scraper.

There is no official docker-compose for this workflow in the repo; the primary entrypoint is the `run-locally` binary.

## Build + Run

1) Copy env:
```bash
cp .env.example .env
```

2) Build the image:
```bash
docker compose build
```

3) Run:
```bash
docker compose up
```

## Notes

- The container mounts `/var/run/docker.sock` so `run-locally` can start a Postgres container. This is required because `run-locally` shells out to `docker run`.
- Logs are written under `/tmp/test_logs` and persisted in the `hyperlane-logs` volume.
- `run-locally` uses `pnpm` scripts from `typescript/infra`, so the build installs JS dependencies.

## Repo Source

By default the container clones:
- `https://github.com/hyperlane-xyz/hyperlane-monorepo.git` (branch `main`)

You can override by editing `.env`.
