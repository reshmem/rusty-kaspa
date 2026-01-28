#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  evm_address_from_privkey.sh 0x<hex-private-key>

Prints the EVM address for a given secp256k1 private key.

Preferred dependency:
  - Foundry `cast` (if available)

Fallback:
  - Node.js + local `ethers` installed under `orchestration/testnet/admin/.tools/hyperlane-cli`
    (run `install_hyperlane_cli.sh` first)
EOF
}

key="${1:-}"
if [[ -z "${key}" || "${key}" == "--help" || "${key}" == "-h" ]]; then
  usage
  exit 1
fi

if [[ "${key}" != 0x* ]]; then
  echo "expected key to start with 0x" >&2
  exit 1
fi

if command -v cast >/dev/null 2>&1; then
  cast wallet address --private-key "${key}"
  exit 0
fi

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
node_modules="${igra_root}/orchestration/testnet/admin/.tools/hyperlane-cli/node_modules"
if [[ ! -d "${node_modules}" ]]; then
  echo "missing node_modules at: ${node_modules}" >&2
  echo "run: orchestration/testnet/admin/scripts/install_hyperlane_cli.sh" >&2
  exit 1
fi

NODE_PATH="${node_modules}" node - <<'NODE'
const { Wallet } = require("ethers");

const key = process.argv[1];
if (!key || !key.startsWith("0x")) {
  console.error("expected 0x<hex-private-key>");
  process.exit(1);
}
const w = new Wallet(key);
process.stdout.write(w.address + "\n");
NODE "${key}"

