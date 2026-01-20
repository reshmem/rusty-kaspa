#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: send_anvil_mailbox_messages.sh --root PATH [--count N] [--amount-sompi N]

Sends Hyperlane Mailbox.dispatch() transactions on Anvil using the staged
`hyperlane_anvil_sender` binary.

Requirements:
  - The devnet root was created by `run_local_devnet_with_avail_and_hyperlane.sh`.
  - Hyperlane core is deployed and registry contains `chains/anvil1/addresses.yaml`.
EOF
}

ROOT=""
COUNT=1
AMOUNT_SOMPI=20000000

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="${2:-}"; shift 2 ;;
    --count) COUNT="${2:-}"; shift 2 ;;
    --amount-sompi) AMOUNT_SOMPI="${2:-}"; shift 2 ;;
    -h|--help|help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${ROOT}" ]]; then
  echo "Missing --root" >&2
  usage
  exit 1
fi

SENDER_BIN="${ROOT}/bin/hyperlane_anvil_sender"
KEYSET_JSON="${ROOT}/config/devnet-keys.json"
REGISTRY="${ROOT}/hyperlane/registry"

if [[ ! -x "${SENDER_BIN}" ]]; then
  echo "Missing sender binary at ${SENDER_BIN}" >&2
  exit 1
fi
if [[ ! -f "${KEYSET_JSON}" ]]; then
  echo "Missing devnet keys at ${KEYSET_JSON}" >&2
  exit 1
fi
if [[ ! -f "${REGISTRY}/chains/anvil1/addresses.yaml" ]]; then
  echo "Missing core deployment addresses at ${REGISTRY}/chains/anvil1/addresses.yaml" >&2
  exit 1
fi

EVM_PRIV_HEX="$(python3 - <<PY
import json
with open(r"""${KEYSET_JSON}""", "r", encoding="utf-8") as fh:
    data = json.load(fh)
print(data["evm"]["private_key_hex"])
PY
)"

exec "${SENDER_BIN}" \
  --rpc-url "http://127.0.0.1:8545" \
  --registry "${REGISTRY}" \
  --chain anvil1 \
  --private-key "0x${EVM_PRIV_HEX}" \
  --destination-domain 7 \
  --igra-root "${ROOT}" \
  --count "${COUNT}" \
  --amount-sompi "${AMOUNT_SOMPI}"

