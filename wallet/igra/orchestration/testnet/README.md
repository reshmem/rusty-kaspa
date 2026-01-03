# Igra Testnet Orchestration

This folder hosts testnet-oriented orchestration assets. The Hyperlane local bundle lives under `orchestration/testnet/hyperlane/`.

## Hyperlane Local Bundle

The bundle uses Hyperlane’s `run-locally` harness to spin up Anvil + validator/relayer/scraper without a real EVM RPC. See:

- `orchestration/testnet/hyperlane/README.md`

## Makefile Shortcuts

- `make hyperlane-build`
- `make hyperlane-up`
- `make hyperlane-logs`
- `make hyperlane-down`
