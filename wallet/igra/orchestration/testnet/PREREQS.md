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
- `sudo apt-get update && sudo apt-get install -y git nodejs npm python3 jq`

Foundry (recommended):
- Install using Foundry’s official installer (curl-based).

Important:
- Many Ubuntu repos ship an older Node.js. If Hyperlane CLI install fails due to Node version,
  use `nvm` (recommended) or a NodeSource package to install a modern Node LTS.
- Some Ubuntu images don’t have `awscli` in apt repos; use AWS CLI v2 installer instead:
  - `curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip && unzip -q /tmp/awscliv2.zip -d /tmp && sudo /tmp/aws/install`

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
- `sudo apt-get update && sudo apt-get install -y jq`

Foundry (optional but recommended):
- Install using Foundry’s official installer (curl-based).

---

## 3) Building binaries (if not provided by admin)

If operators build locally, they also need:
- Rust toolchain (`rustup`, stable)
- A working C toolchain (for some deps)
- Rusty-Kaspa native build prerequisites (Protobuf + LLVM/Clang), if building Kaspa binaries from source

macOS:
- Install Rust via `rustup` (recommended)

Ubuntu:
- Install build essentials: `sudo apt-get install -y build-essential pkg-config`
- Install Rust via `rustup` (recommended)

### 3.1) Rusty-Kaspa prerequisites (from repo README)

If you plan to build Kaspa components from source (e.g. `kaspad`, gRPC, RocksDB, WASM targets), you also need:

Linux (Ubuntu/Debian):
- General prerequisites:
  - `sudo apt install curl git build-essential libssl-dev pkg-config`
- Protobuf (for gRPC):
  - `sudo apt install protobuf-compiler libprotobuf-dev`
- Clang/LLVM toolchain (RocksDB + WASM secp256k1 builds):
  - `sudo apt-get install clang-format clang-tidy clang-tools clang clangd libc++-dev libc++1 libc++abi-dev libc++abi1 libclang-dev libclang1 liblldb-dev libllvm-ocaml-dev libomp-dev libomp5 lld lldb llvm-dev llvm-runtime llvm python3-clang`

macOS:
- Protobuf (for gRPC): `brew install protobuf`
- LLVM (Homebrew; Xcode LLVM doesn’t support WASM targets): `brew install llvm`
  - If building WASM, you may need to add Homebrew LLVM to your env (example for Apple Silicon):
    - `export PATH="/opt/homebrew/opt/llvm/bin:$PATH"`
    - `export LDFLAGS="-L/opt/homebrew/opt/llvm/lib"`
    - `export CPPFLAGS="-I/opt/homebrew/opt/llvm/include"`
    - `export AR=/opt/homebrew/opt/llvm/bin/llvm-ar`

Build helpers (from this repo):
- `orchestration/testnet/scripts/build_igra_binaries.sh`
- `orchestration/testnet/scripts/build_kaspa_node.sh`
- `orchestration/testnet/scripts/build_hyperlane_agents.sh`

---

## 4) Copy-paste install (recommended “full” setup)

These one-liners install a **superset** of tools (covers admin + signer + local builds).

### macOS (Homebrew)

```bash
/bin/bash -lc 'command -v brew >/dev/null || { echo "Homebrew is required. Install it from https://brew.sh and re-run." >&2; exit 1; }; brew update && brew install git node awscli python@3 jq foundry pkg-config protobuf llvm && (xcode-select -p >/dev/null 2>&1 || xcode-select --install || true) && (command -v rustup >/dev/null 2>&1 || curl https://sh.rustup.rs -sSf | sh -s -- -y) && source "$HOME/.cargo/env" && rustup toolchain install stable && rustup default stable'
```

### Ubuntu (apt)

```bash
bash -lc 'set -euo pipefail; sudo apt-get update && sudo apt-get install -y git curl ca-certificates jq python3 python3-venv build-essential pkg-config libssl-dev protobuf-compiler libprotobuf-dev clang lld llvm libclang-dev unzip && (command -v aws >/dev/null 2>&1 || { tmp="$(mktemp -d)"; curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "${tmp}/awscliv2.zip"; (cd "${tmp}" && unzip -q awscliv2.zip && sudo ./aws/install); rm -rf "${tmp}"; }) && curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash - && sudo apt-get install -y nodejs && curl -L https://foundry.paradigm.xyz | bash && "$HOME/.foundry/bin/foundryup" && curl https://sh.rustup.rs -sSf | sh -s -- -y && source "$HOME/.cargo/env" && rustup toolchain install stable && rustup default stable'
```
