#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: check_balance.sh [--root PATH] [--rpc HOST:PORT] [--addresses addr1,addr2,...]

Queries balances via devnet-balance (gRPC). By default it uses the miner and multisig addresses from:
  <root>/config/devnet-keys.json (wallet.mining_address + multisig_address)

Options:
  --root PATH        Devnet root (default: $(pwd)/igra_devnet)
  --rpc HOST:PORT    gRPC server (default: 127.0.0.1:16110)
  --addresses LIST   Comma-separated addresses to query (overrides defaults)
  -h, --help         Show this help
EOF
}

ROOT="${ROOT:-}"
RPC="127.0.0.1:16110"
ADDRS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --rpc) RPC="$2"; shift 2 ;;
    --addresses) ADDRS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${ROOT}" ]]; then
  ROOT="$(pwd)/igra_devnet"
fi

BIN_DIR="${ROOT}/bin"
CONFIG_DIR="${ROOT}/config"
BAL_BIN="${BIN_DIR}/devnet-balance"
ENV_FILE="${CONFIG_DIR}/.env"
KEYS_JSON="${CONFIG_DIR}/devnet-keys.json"

if [[ ! -x "${BAL_BIN}" ]]; then
  echo "devnet-balance not found at ${BAL_BIN}; run the build/stage flow first." >&2
  exit 1
fi

collect_addresses() {
  local list=()
  if [[ -f "${KEYS_JSON}" ]]; then
    local parsed
    parsed=$(KEYS_JSON="${KEYS_JSON}" python3 <<'PY'
import json, os
path = os.environ.get("KEYS_JSON")
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
miner = data.get("wallet", {}).get("mining_address", "") or ""
msig = data.get("multisig_address") or (data.get("source_addresses") or [None])[0] or ""
print(miner)
print(msig)
PY
    )
    while IFS= read -r line; do
      [[ -z "${line}" ]] && continue
      list+=("${line}")
    done <<< "${parsed}"
  fi
  # Deduplicate while preserving order.
  local dedup=()
  local seen=""
  for addr in "${list[@]}"; do
    [[ -z "${addr}" ]] && continue
    if ! [[ " ${seen} " == *" ${addr} "* ]]; then
      dedup+=("${addr}")
      seen+=" ${addr}"
    fi
  done
  printf "%s\n" "${dedup[@]}"
}

if [[ -z "${ADDRS}" ]]; then
  ADDR_ARRAY=()
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    ADDR_ARRAY+=("${line}")
  done < <(collect_addresses)
else
  IFS=',' read -r -a ADDR_ARRAY <<< "${ADDRS}"
fi

if [[ "${#ADDR_ARRAY[@]}" -eq 0 ]]; then
  echo "No addresses found. Provide --addresses or ensure devnet-keys.json/.env exist." >&2
  exit 1
fi

echo "Checking balances via ${BAL_BIN} (rpc ${RPC})"
echo "Addresses: ${ADDR_ARRAY[*]}"
"${BAL_BIN}" --rpc "${RPC}" --addresses "$(IFS=','; echo "${ADDR_ARRAY[*]}")"
