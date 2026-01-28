#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  deploy_hyperlane_core.sh [--registry-dir <dir>] [--chain-name <name>] [--chain-id <id>] [--domain-id <id>]

Deploys Hyperlane core contracts to the origin EVM chain and writes a local registry directory.

Required env:
  IGRA_EVM_RPC_URL            Origin EVM JSON-RPC (igra-testnet-4)
  HYP_EVM_DEPLOYER_KEY_HEX    Deployer private key (hex; with or without 0x)

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

deployer_key="$(printf "%s" "${HYP_EVM_DEPLOYER_KEY_HEX}" | tr -d ' \t\r\n')"
deployer_key="${deployer_key#0x}"
if [[ ! "${deployer_key}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "invalid HYP_EVM_DEPLOYER_KEY_HEX: expected 32-byte hex (64 chars), got: $(printf '%q' "${HYP_EVM_DEPLOYER_KEY_HEX}")" >&2
  echo "hint: export HYP_EVM_DEPLOYER_KEY_HEX=<64-hex-no-0x> (or with 0x prefix)" >&2
  exit 1
fi
if [[ "${deployer_key}" =~ ^0+$ ]]; then
  echo "invalid HYP_EVM_DEPLOYER_KEY_HEX: private key cannot be all zeros" >&2
  echo "hint: use a real funded EVM private key (Anvil prints prefunded keys at startup)" >&2
  exit 1
fi

# Extra validation: reject out-of-range keys early with a clearer error message.
if command -v cast >/dev/null 2>&1; then
  if ! cast wallet address --private-key "0x${deployer_key}" >/dev/null 2>&1; then
    echo "invalid HYP_EVM_DEPLOYER_KEY_HEX: cast failed to derive an address (key out of range?)" >&2
    echo "hint: export HYP_EVM_DEPLOYER_KEY_HEX=<valid funded key> (64 hex chars; with or without 0x)" >&2
    exit 1
  fi
fi

hyperlane_bin="${HYPERLANE_CLI_BIN:-${igra_root}/orchestration/testnet/admin/.tools/hyperlane-cli/node_modules/.bin/hyperlane}"
if [[ ! -x "${hyperlane_bin}" ]]; then
  echo "missing hyperlane CLI binary at: ${hyperlane_bin}" >&2
  echo "run: orchestration/testnet/admin/scripts/install_hyperlane_cli.sh" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "missing required command: curl" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "missing required command: python3" >&2
  exit 1
fi

# Preflight RPC connectivity + chain id match (helps catch pointing at the wrong node).
chain_id_rpc="$(curl -sS --max-time 5 -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
  "${IGRA_EVM_RPC_URL}" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(int(j["result"],16))' 2>/dev/null || true)"
if [[ -z "${chain_id_rpc}" ]]; then
  echo "failed to query eth_chainId from IGRA_EVM_RPC_URL=$(printf '%q' "${IGRA_EVM_RPC_URL}")" >&2
  echo "hint: ensure the EVM node is running and reachable" >&2
  exit 1
fi
if [[ "${chain_id_rpc}" != "${chain_id}" ]]; then
  echo "IGRA_EVM_RPC_URL chainId mismatch: rpc=${chain_id_rpc} expected=${chain_id}" >&2
  echo "hint: point IGRA_EVM_RPC_URL to the correct chain, or pass --chain-id to match the node" >&2
  exit 1
fi

tmp_dir="${igra_root}/orchestration/testnet/admin/.tmp"
mkdir -p "${tmp_dir}"
mkdir -p "${registry_dir}"

chain_dir="${registry_dir}/chains/${chain_name}"
mkdir -p "${chain_dir}"

# Hyperlane CLI requires chain metadata to exist in the registry before it can deploy core contracts.
# This is the same pattern used in our devnet scripts (they copy anvil1 metadata.yaml into the registry).
meta="${chain_dir}/metadata.yaml"
cat > "${meta}" <<YAML
# Minimal chain metadata for Hyperlane CLI
name: ${chain_name}
displayName: ${chain_name}
protocol: ethereum
chainId: ${chain_id}
domainId: ${domain_id}
rpcUrls:
  - http: "${IGRA_EVM_RPC_URL}"
nativeToken:
  name: Ether
  symbol: ETH
  decimals: 18
YAML

owner_addr=""
if command -v cast >/dev/null 2>&1; then
  owner_addr="$(cast wallet address --private-key "0x${deployer_key}" 2>/dev/null | tr -d '\r')"
fi
if [[ -z "${owner_addr}" ]]; then
  # Fallback: derive owner address via node+ethers (installed by install_hyperlane_cli.sh).
  node_modules="${igra_root}/orchestration/testnet/admin/.tools/hyperlane-cli/node_modules"
  if [[ ! -d "${node_modules}" ]]; then
    echo "missing node_modules for ethers fallback at: ${node_modules}" >&2
    echo "run: orchestration/testnet/admin/scripts/install_hyperlane_cli.sh" >&2
    exit 1
  fi
  if ! command -v node >/dev/null 2>&1; then
    echo "missing required command: node (needed to derive owner address)" >&2
    exit 1
  fi
  owner_addr="$(NODE_PATH="${node_modules}" node -e 'const { Wallet } = require("ethers"); console.log(new Wallet(process.env.K).address);' \
    K="0x${deployer_key}" 2>/dev/null | tr -d '\r')"
fi
if [[ -z "${owner_addr}" ]]; then
  echo "failed to derive deployer EVM address from HYP_EVM_DEPLOYER_KEY_HEX" >&2
  exit 1
fi

# Core deployment config (contracts + hooks). Chain metadata comes from the registry metadata.yaml above.
cfg="${tmp_dir}/core-config.yaml"
cat > "${cfg}" <<YAML
owner: "${owner_addr}"
defaultIsm:
  type: "testIsm"
  threshold: 1
  validators:
    - "${owner_addr}"
defaultHook:
  # MerkleTreeHook is required to produce checkpoints for validators/relayers.
  type: "merkleTreeHook"
requiredHook:
  type: protocolFee
  maxProtocolFee: "1000000000000000000"
  # Keep protocol fee at 0 for testnet-v1 local testing.
  # If you change this to >0, dispatchers must attach ETH or use an IGP flow.
  protocolFee: "0"
  beneficiary: "${owner_addr}"
  owner: "${owner_addr}"
proxyAdmin:
  owner: "${owner_addr}"
YAML

echo "Deploying Hyperlane core contracts..."
echo "  chain=${chain_name} chainId=${chain_id} domainId=${domain_id}"
echo "  registry_dir=${registry_dir}"
echo "  owner=${owner_addr}"

"${hyperlane_bin}" core deploy \
  --registry "${registry_dir}" \
  --config "${cfg}" \
  --chain "${chain_name}" \
  --key "0x${deployer_key}" \
  --yes

echo "Registry updated:"
echo "  ${registry_dir}/chains/${chain_name}/metadata.yaml"
echo "  ${registry_dir}/chains/${chain_name}/addresses.yaml"
