#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  boostrap.sh [--anvil] [--out <bundles-dir>]

End-to-end local bootstrap for testnet-v1:
  - (optional) start Anvil locally (chainId=38836 / 0x97b4)
  - install Hyperlane CLI (local under orchestration/testnet/admin/.tools)
  - deploy Hyperlane core contracts to the origin EVM
  - build required binaries (Igra, kaspad, Hyperlane agents)
  - start kaspad (testnet) locally on grpc://127.0.0.1:16110
  - generate 3-of-5 signer bundles
  - (anvil only) fund deployer + validator + relayer EVM accounts
  - start all 5 signers (igra-signer + hyperlane validator + hyperlane relayer)

Environment (defaults for local bootstrap/testing):
  IGRA_SECRETS_PASSPHRASE   (default: "passphrase")
  HYP_EVM_DEPLOYER_KEY_HEX  (default: 0x3121152508ebc49a28759172e856f108879990533dd74f233636c7bfb2c363e3)
  IGRA_EVM_RPC_URL          (default: http://127.0.0.1:8545)

Notes:
  - This script is intended for local testing and determinism.
  - It writes state under orchestration/testnet/admin/.tmp so reruns can stop the previous stack cleanly.
EOF
}

ANVIL="false"
OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --anvil) ANVIL="true"; shift;;
    --out) OUT_DIR="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; usage; exit 1;;
  esac
done

igra_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
workspace_root="$(cd "${igra_root}/../.." && pwd)"
tmp_dir="${igra_root}/orchestration/testnet/admin/.tmp"
state_file="${tmp_dir}/boostrap_state.json"
registry_dir="${tmp_dir}/registry"

mkdir -p "${tmp_dir}"

IGRA_SECRETS_PASSPHRASE="${IGRA_SECRETS_PASSPHRASE:-passphrase}"
HYP_EVM_DEPLOYER_KEY_HEX="${HYP_EVM_DEPLOYER_KEY_HEX:-0x3121152508ebc49a28759172e856f108879990533dd74f233636c7bfb2c363e3}"
IGRA_EVM_RPC_URL="${IGRA_EVM_RPC_URL:-http://127.0.0.1:8545}"

export IGRA_SECRETS_PASSPHRASE
export HYP_EVM_DEPLOYER_KEY_HEX
export IGRA_EVM_RPC_URL

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
}

port_listener_pid() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN -t 2>/dev/null | head -n 1 || true
    return 0
  fi
  echo ""
}

kill_pidfile() {
  local name="$1"
  local pid_file="$2"
  if [[ ! -f "${pid_file}" ]]; then
    return 0
  fi
  local pid=""
  pid="$(cat "${pid_file}" 2>/dev/null || true)"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    echo "stopping ${name} pid=${pid}..."
    kill "${pid}" >/dev/null 2>&1 || true
    sleep 1
    if kill -0 "${pid}" >/dev/null 2>&1; then
      echo "force killing ${name} pid=${pid}..."
      kill -9 "${pid}" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "${pid_file}"
}

stop_previous_stack() {
  if [[ -f "${state_file}" ]]; then
    prev_run_dir="$(
      python3 - <<'PY' "${state_file}"
import json,sys
path = sys.argv[1]
try:
  with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
  print(data.get("bundles_dir", ""))
except Exception:
  print("")
PY
    )"
    if [[ -n "${prev_run_dir}" && -d "${prev_run_dir}" ]]; then
      echo "Stopping previous signer stack from: ${prev_run_dir}"
      for b in "${prev_run_dir}"/signer-*/; do
        if [[ -d "${b}" ]]; then
          bash "${igra_root}/orchestration/testnet/scripts/run_testnet_v1_signer.sh" --bundle "${b%/}" stop || true
        fi
      done
    fi
  fi

  kill_pidfile "kaspad" "${tmp_dir}/kaspad.pid"
  kill_pidfile "anvil" "${tmp_dir}/anvil.pid"
}

wait_for_eth_chainid() {
  local expected_chain_id="$1"
  local max_wait="${2:-30}"
  for _ in $(seq 1 "${max_wait}"); do
    local chain_id=""
    chain_id="$(curl -s --max-time 2 -H 'Content-Type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
      "${IGRA_EVM_RPC_URL}" 2>/dev/null | python3 -c 'import json,sys; j=json.load(sys.stdin); print(int(j["result"],16))' 2>/dev/null || true)"
    if [[ -n "${chain_id}" && "${chain_id}" == "${expected_chain_id}" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "EVM JSON-RPC not ready at ${IGRA_EVM_RPC_URL} (expected chainId=${expected_chain_id})" >&2
  return 1
}

anvil_set_balance() {
  local addr="$1"
  local balance_hex="$2"
  local resp=""
  resp="$(curl -sS --max-time 5 -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"anvil_setBalance\",\"params\":[\"${addr}\",\"${balance_hex}\"]}" \
    "${IGRA_EVM_RPC_URL}" || true)"
  if [[ -z "${resp}" ]]; then
    echo "anvil_setBalance failed (empty response) addr=${addr}" >&2
    return 1
  fi
  if echo "${resp}" | python3 -c 'import json,sys; j=json.load(sys.stdin); sys.exit(0 if "error" not in j else 1)' >/dev/null 2>&1; then
    return 0
  fi
  echo "anvil_setBalance failed addr=${addr} resp=${resp}" >&2
  return 1
}

start_anvil() {
  require_cmd anvil
  require_cmd curl
  require_cmd python3

  local port_pid=""
  port_pid="$(port_listener_pid 8545)"
  if [[ -n "${port_pid}" ]]; then
    echo "port 8545 already in use (pid ${port_pid}); refusing to start anvil" >&2
    exit 1
  fi

  echo "Starting Anvil (chainId=38836) ..."
  rm -f "${tmp_dir}/anvil.log"
  anvil --host 127.0.0.1 --port 8545 --chain-id 38836 >"${tmp_dir}/anvil.log" 2>&1 &
  echo $! >"${tmp_dir}/anvil.pid"

  wait_for_eth_chainid 38836 30

  # Fund deployer key so deploy_hyperlane_core.sh can transact.
  local deployer_addr=""
  deployer_addr="$("${igra_root}/orchestration/testnet/admin/scripts/evm_address_from_privkey.sh" "${HYP_EVM_DEPLOYER_KEY_HEX}")"
  if [[ -z "${deployer_addr}" ]]; then
    echo "failed to derive deployer address from HYP_EVM_DEPLOYER_KEY_HEX" >&2
    exit 1
  fi
  echo "Funding deployer on Anvil: ${deployer_addr}"
  anvil_set_balance "${deployer_addr}" "0x56BC75E2D63100000" # 100 ETH
}

ensure_hyperlane_cli() {
  local bin="${igra_root}/orchestration/testnet/admin/.tools/hyperlane-cli/node_modules/.bin/hyperlane"
  if [[ -x "${bin}" ]]; then
    return 0
  fi
  bash "${igra_root}/orchestration/testnet/admin/scripts/install_hyperlane_cli.sh"
}

deploy_hyperlane_core() {
  # If we're using a fresh local Anvil chain, remove any existing registry to avoid stale addresses.yaml.
  if [[ "${ANVIL}" == "true" ]]; then
    rm -rf "${registry_dir}"
  fi
  bash "${igra_root}/orchestration/testnet/admin/scripts/deploy_hyperlane_core.sh" --registry-dir "${registry_dir}"
}

ensure_igra_binaries() {
  local svc="${workspace_root}/target/release/kaspa-threshold-service"
  local keygen="${workspace_root}/target/release/devnet-keygen"
  if [[ -x "${svc}" && -x "${keygen}" ]]; then
    # Smoke test: ensure `devnet-keygen` supports `--format file-per-signer` (required by testnet-v1).
    local smoke_dir="${tmp_dir}/keygen-smoke"
    rm -rf "${smoke_dir}"
    mkdir -p "${smoke_dir}"
    if "${keygen}" \
      --format file-per-signer \
      --output-dir "${smoke_dir}" \
      --passphrase "${IGRA_SECRETS_PASSPHRASE}" \
      --num-signers 1 \
      --threshold-m 1 \
      --kaspa-network testnet \
      --network-id 4 \
      --hyperlane-validator-count 1 \
      --hyperlane-validator-name-format two-digit \
      --signer-profile signer-01 \
      --overwrite >/dev/null 2>&1; then
      if [[ -f "${smoke_dir}/signer-01/secrets.bin" ]]; then
        rm -rf "${smoke_dir}"
        return 0
      fi
    fi
    rm -rf "${smoke_dir}"
  fi
  bash "${igra_root}/orchestration/testnet/scripts/build_igra_binaries.sh"
}

ensure_kaspad_binary() {
  local bin="${workspace_root}/target-igra-testnet/release/kaspad"
  if [[ -x "${bin}" ]]; then
    return 0
  fi
  bash "${igra_root}/orchestration/testnet/scripts/build_kaspa_node.sh"
}

ensure_hyperlane_agents() {
  local repo_dir="${HOME}/Source/personal/hyperlane-monorepo"
  local validator="${repo_dir}/target-igra-testnet/release/validator"
  local relayer="${repo_dir}/target-igra-testnet/release/relayer"
  local build_info="${repo_dir}/target-igra-testnet/igra-build-info.json"
  if [[ -x "${validator}" && -x "${relayer}" && -f "${build_info}" ]]; then
    if python3 - <<'PY' "${build_info}" >/dev/null 2>&1; then
import json,sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
  data = json.load(fh)
features = data.get("relayer_features", [])
sys.exit(0 if "kaspa" in features else 1)
PY
      return 0
    fi
  fi
  bash "${igra_root}/orchestration/testnet/scripts/build_hyperlane_agents.sh" --clone --update
}

start_kaspad() {
  require_cmd curl
  require_cmd python3

  local port_pid=""
  port_pid="$(port_listener_pid 16110)"
  if [[ -n "${port_pid}" ]]; then
    echo "port 16110 already in use (pid ${port_pid}); refusing to start kaspad" >&2
    exit 1
  fi

  local kaspad_bin="${workspace_root}/target-igra-testnet/release/kaspad"
  if [[ ! -x "${kaspad_bin}" ]]; then
    echo "missing kaspad binary at: ${kaspad_bin}" >&2
    exit 1
  fi

  local appdir="${tmp_dir}/kaspad-appdir"
  mkdir -p "${appdir}"
  if find "${appdir}/kaspa-testnet" -name LOCK -type f -print -quit >/dev/null 2>&1; then
    echo "Removing stale kaspad lock files under ${appdir}/kaspa-testnet"
    find "${appdir}/kaspa-testnet" -name LOCK -type f -print -delete || true
  fi

  echo "Starting kaspad (testnet)..."
  rm -f "${tmp_dir}/kaspad.log"
  "${kaspad_bin}" \
    --testnet \
    --utxoindex \
    --appdir="${appdir}" \
    --rpclisten=127.0.0.1:16110 >"${tmp_dir}/kaspad.log" 2>&1 &
  echo $! >"${tmp_dir}/kaspad.pid"

  # Best-effort readiness: ensure the port is listening.
  for _ in $(seq 1 30); do
    if [[ -n "$(port_listener_pid 16110)" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "kaspad did not start listening on 127.0.0.1:16110 (see ${tmp_dir}/kaspad.log)" >&2
  return 1
}

generate_bundles() {
  local out="${OUT_DIR}"
  if [[ -z "${out}" ]]; then
    out="${igra_root}/orchestration/testnet/bundles/testnet-v1-$(date +%s)"
  fi
  local log_file="${tmp_dir}/bundle-gen.log"
  rm -f "${log_file}"
  if ! python3 "${igra_root}/orchestration/testnet/scripts/generate_testnet_v1_bundles.py" \
    --out "${out}" \
    --num-signers 5 \
    --threshold-m 3 \
    --iroh-network-id 4 \
    --hyperlane-origin-domain-id 0x97B4 \
    --passphrase "${IGRA_SECRETS_PASSPHRASE}" >"${log_file}" 2>&1; then
    echo "bundle generation failed; see ${log_file}" >&2
    tail -n 80 "${log_file}" >&2 || true
    return 1
  fi
  echo "Wrote bundles to: ${out}" >&2
  echo "${out}"
}

fund_bundle_accounts_anvil() {
  local bundles_dir="$1"
  require_cmd python3
  for b in "${bundles_dir}"/signer-*/; do
    if [[ ! -d "${b}" ]]; then
      continue
    fi
    local to_admin="${b%/}/to-admin.json"
    if [[ ! -f "${to_admin}" ]]; then
      echo "missing to-admin.json: ${to_admin}" >&2
      exit 1
    fi
    python3 - <<'PY' "${to_admin}"
import json,sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
  data = json.load(fh)
print(data["hyperlane"]["validator"]["evm_address"])
print(data["hyperlane"]["relayer"]["evm_address"])
PY
  done | while read -r addr; do
    if [[ -n "${addr}" ]]; then
      echo "Funding on Anvil: ${addr}"
      anvil_set_balance "${addr}" "0x8AC7230489E80000" # 10 ETH
    fi
  done
}

start_signers() {
  local bundles_dir="$1"
  for b in "${bundles_dir}"/signer-*/; do
    if [[ ! -d "${b}" ]]; then
      continue
    fi
    (
      set -a
      # shellcheck disable=SC1090
      source "${b%/}/.env"
      set +a
      export IGRA_EVM_RPC_URL="${IGRA_EVM_RPC_URL}"
      export HYP_REGISTRY_DIR="${registry_dir}"
      bash "${igra_root}/orchestration/testnet/scripts/run_testnet_v1_signer.sh" --bundle "${b%/}" --checkpoint-syncer local start
    )
  done
}

verify_signers() {
  local bundles_dir="$1"
  local failed="false"
  for b in "${bundles_dir}"/signer-*/; do
    if [[ ! -d "${b}" ]]; then
      continue
    fi
    echo "Status: ${b%/}"
    status_out="$(bash "${igra_root}/orchestration/testnet/scripts/run_testnet_v1_signer.sh" --bundle "${b%/}" status)"
    echo "${status_out}"
    if echo "${status_out}" | grep -q "^stopped:"; then
      failed="true"
    fi
  done
  if [[ "${failed}" == "true" ]]; then
    echo "one or more signers failed to start; inspect logs under <bundle>/logs and ${tmp_dir}/*.log" >&2
    return 1
  fi
  return 0
}

write_state() {
  local bundles_dir="$1"
  python3 - <<PY "${state_file}" "${bundles_dir}"
import json,sys,time
state_path = sys.argv[1]
bundles_dir = sys.argv[2]
data = {
  "timestamp": int(time.time()),
  "bundles_dir": bundles_dir,
}
with open(state_path, "w", encoding="utf-8") as fh:
  json.dump(data, fh, indent=2)
  fh.write("\\n")
print(f"Wrote state: {state_path}")
PY
}

main() {
  require_cmd python3
  require_cmd curl
  require_cmd cargo
  require_cmd git

  stop_previous_stack

  if [[ "${ANVIL}" == "true" ]]; then
    start_anvil
  fi

  ensure_hyperlane_cli
  deploy_hyperlane_core

  ensure_igra_binaries
  ensure_kaspad_binary
  ensure_hyperlane_agents

  start_kaspad

  bundles_dir="$(generate_bundles)"
  # Write state early so a failed run can be cleaned up via a subsequent rerun.
  write_state "${bundles_dir}"
  if [[ "${ANVIL}" == "true" ]]; then
    fund_bundle_accounts_anvil "${bundles_dir}"
  fi

  start_signers "${bundles_dir}"
  sleep 2
  verify_signers "${bundles_dir}"

  echo ""
  echo "Bootstrap complete."
  echo "Bundles: ${bundles_dir}"
  echo "Registry: ${registry_dir}"
  echo "Logs:"
  echo "  - kaspad: ${tmp_dir}/kaspad.log"
  if [[ "${ANVIL}" == "true" ]]; then
    echo "  - anvil: ${tmp_dir}/anvil.log"
  fi
}

main
