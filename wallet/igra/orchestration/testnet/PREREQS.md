# Testnet-v1 Prerequisites (Admin + Signers)

This document lists the recommended tooling to install before running testnet-v1.

Targets:
- macOS (Homebrew)
- Ubuntu (apt)

Notes:
- `cast` is part of **Foundry** (toolkit includes `forge`, `cast`, `anvil`).
- Operators do **not** need Node.js unless they intend to use Hyperlane CLI locally.
- Operators running Hyperlane validators that write checkpoints to S3 must have AWS credentials available
  (IAM user creds or instance role on AWS).

---

## 1) Admin machine

Admin responsibilities:
- Deploy Hyperlane core contracts to the origin EVM chain
- Publish Hyperlane registry to S3
- Fund operator EVM accounts (validators + relayers)

Required tools:
- `git`
- `node` + `npm` (used by `orchestration/testnet/admin/scripts/install_hyperlane_cli.sh`)
- `aws` CLI
- `python3` (for some local scripts)

Strongly recommended:
- Foundry (`cast`) — easiest way to compute EVM address from private key and to send ETH on testnets.
- `jq` — convenient JSON parsing during debugging.

### macOS (Homebrew)

Install:
- `brew install git node awscli python@3 jq`

Foundry (recommended):
- `brew install foundry`

### Ubuntu (apt)

Install:
- `sudo apt-get update && sudo apt-get install -y git nodejs npm awscli python3 jq`

Foundry (recommended):
- Install using Foundry’s official installer (curl-based).

Important:
- Many Ubuntu repos ship an older Node.js. If Hyperlane CLI install fails due to Node version,
  use `nvm` (recommended) or a NodeSource package to install a modern Node LTS.

---

## 2) Signer operator machine

Each signer operator runs:
- `kaspad` (Kaspa node)
- Hyperlane `validator` + `relayer` (Rust agents from `reshmem/hyperlane-monorepo`)
- `kaspa-threshold-service` (Igra signer)

Required tools:
- `bash`
- `aws` CLI (only if validator uses IAM user credentials locally; instance roles on AWS do not require awscli)

Recommended:
- `jq` (debugging/log analysis)
- Foundry `cast` (to compute EVM addresses and check balances easily)

### macOS (Homebrew)

Install:
- `brew install awscli jq`

Foundry (optional but recommended):
- `brew install foundry`

### Ubuntu (apt)

Install:
- `sudo apt-get update && sudo apt-get install -y awscli jq`

Foundry (optional but recommended):
- Install using Foundry’s official installer (curl-based).

---

## 3) Building binaries (if not provided by admin)

If operators build locally, they also need:
- Rust toolchain (`rustup`, stable)
- A working C toolchain (for some deps)

macOS:
- Install Rust via `rustup` (recommended)

Ubuntu:
- Install build essentials: `sudo apt-get install -y build-essential pkg-config`
- Install Rust via `rustup` (recommended)

Build helpers (from this repo):
- `orchestration/testnet/scripts/build_kaspa_node.sh`
- `orchestration/testnet/scripts/build_hyperlane_agents.sh`

