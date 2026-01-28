#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  deploy_hyperlane_core.sh [--registry-dir <dir>] [--chain-name <name>] [--chain-id <id>] [--domain-id <id>]

Deploys Hyperlane core contracts to the origin EVM chain and writes a local registry directory.

Required env:
  IGRA_EVM_RPC_URL            Origin EVM JSON-RPC (igra-testnet-4)
  HYP_EVM_DEPLOYER_KEY_HEX    Deployer private key (hex, no 0x)

Optional env:
  HYPERLANE_CLI_BIN           Path to `hyperlane` binary (otherwise uses local install under admin/.tools)

Defaults:
  chain-name = igra-testnet-4
  chain-id   = 38836
  domain-id  = 38836
  registry-dir = orchestration/testnet/admin/.tmp/registry
EOF
}

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
registry_dir="${igra_root}/orchestration/testnet/admin/.tmp/registry"
chain_name="igra-testnet-4"
chain_id="38836"
domain_id="38836"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --registry-dir) registry_dir="$2"; shift 2;;
    --chain-name) chain_name="$2"; shift 2;;
    --chain-id) chain_id="$2"; shift 2;;
    --domain-id) domain_id="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

if [[ -z "${IGRA_EVM_RPC_URL:-}" ]]; then
  echo "missing env: IGRA_EVM_RPC_URL" >&2
  exit 1
fi
if [[ -z "${HYP_EVM_DEPLOYER_KEY_HEX:-}" ]]; then
  echo "missing env: HYP_EVM_DEPLOYER_KEY_HEX" >&2
  exit 1
fi

hyperlane_bin="${HYPERLANE_CLI_BIN:-${igra_root}/orchestration/testnet/admin/.tools/hyperlane-cli/node_modules/.bin/hyperlane}"
if [[ ! -x "${hyperlane_bin}" ]]; then
  echo "missing hyperlane CLI binary at: ${hyperlane_bin}" >&2
  echo "run: orchestration/testnet/admin/scripts/install_hyperlane_cli.sh" >&2
  exit 1
fi

tmp_dir="${igra_root}/orchestration/testnet/admin/.tmp"
mkdir -p "${tmp_dir}"
mkdir -p "${registry_dir}"

cfg="${tmp_dir}/core-config.yaml"
cat > "${cfg}" <<YAML
chains:
  ${chain_name}:
    name: ${chain_name}
    protocol: ethereum
    chainId: ${chain_id}
    domainId: ${domain_id}
    rpcUrls:
      - http: "${IGRA_EVM_RPC_URL}"
YAML

echo "Deploying Hyperlane core contracts..."
echo "  chain=${chain_name} chainId=${chain_id} domainId=${domain_id}"
echo "  registry_dir=${registry_dir}"

"${hyperlane_bin}" core deploy \
  --registry "${registry_dir}" \
  --config "${cfg}" \
  --chain "${chain_name}" \
  --key "0x${HYP_EVM_DEPLOYER_KEY_HEX}" \
  --yes

echo "Registry updated:"
echo "  ${registry_dir}/chains/${chain_name}/metadata.yaml"
echo "  ${registry_dir}/chains/${chain_name}/addresses.yaml"

