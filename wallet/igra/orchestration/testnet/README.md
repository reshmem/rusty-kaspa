# Testnet Orchestration (v1)

This directory contains **testnet-v1** orchestration assets:
- templates and scripts to generate **per-signer config bundles**
- bootstrap scripts for operators to run their local stack

Source-of-truth design notes live in:
- `docs/wip/testnet-v1.md`
- `docs/wip/Domain-and-Network-IDs-Hyperlane.md`
Admin runbook:
- `orchestration/testnet/admin/Igra-Admin-Guide.md`
Prereqs:
- `orchestration/testnet/PREREQS.md`

## Directory layout

- `orchestration/testnet/scripts/` — bundle generator + operator bootstrap scripts
- `orchestration/testnet/templates/` — config templates (no secrets)
- `orchestration/testnet/aws/` — AWS policy templates (examples)
- `orchestration/testnet/bundles/` — generated per-signer bundles (gitignored)

## Quick start (bundle generation)

From the repo root:

1) Build binaries you will distribute/run:
   - `cargo build -p igra-service --bin kaspa-threshold-service --release`
   - `cargo build -p igra-core --bin devnet-keygen --release`

2) Generate bundles (writes into `orchestration/testnet/bundles/`):
   - `python3 orchestration/testnet/scripts/generate_testnet_v1_bundles.py`

3) Distribute one bundle per signer:
   - `orchestration/testnet/bundles/signer-01/`
   - …
   - `orchestration/testnet/bundles/signer-05/`

## Operator runbook (per signer)

See:
- `orchestration/testnet/scripts/run_testnet_v1_signer.sh --help`
- `orchestration/testnet/scripts/sync_hyperlane_registry.sh --help`

## Build helpers

- Build kaspa node (`kaspad`): `orchestration/testnet/scripts/build_kaspa_node.sh --help`
- Build Hyperlane agents (reshmem fork): `orchestration/testnet/scripts/build_hyperlane_agents.sh --help`
- Update generated bundle `.env` with detected binaries: `orchestration/testnet/scripts/update_bundle_env_example.py --help`

## Option A (single machine, no S3)

For local-only testing (everything on one machine), explicitly set:
- `HYP_CHECKPOINT_SYNCER=local` (bundles default to `s3`)
- `HYP_REGISTRY_DIR` pointing to a local registry directory (admin can use the output of `deploy_hyperlane_core.sh`)
