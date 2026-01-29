#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build_igra_binaries.sh

Builds the Igra binaries needed for testnet-v1 orchestration:
  - kaspa-threshold-service (igra-service)
  - devnet-keygen (igra-core)  # used by generate_testnet_v1_bundles.py

Outputs (default Cargo locations):
  - target/release/kaspa-threshold-service
  - target/release/devnet-keygen
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
workspace_root="$(cd "${igra_root}/../.." && pwd)"
cd "${workspace_root}"

echo "Building Igra binaries (release, locked)..."
RUSTC_WRAPPER= SCCACHE_DISABLE=1 cargo build --release --locked -p igra-service --bin kaspa-threshold-service
RUSTC_WRAPPER= SCCACHE_DISABLE=1 cargo build --release --locked -p igra-core --bin devnet-keygen

echo "Built:"
echo "  ${workspace_root}/target/release/kaspa-threshold-service"
echo "  ${workspace_root}/target/release/devnet-keygen"
