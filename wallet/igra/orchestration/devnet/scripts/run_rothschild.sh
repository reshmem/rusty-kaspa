#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run_rothschild.sh [--root PATH] --to ADDRESS [--amount SOMPI] [--tps N] [--rpc HOST:PORT] [--threads N] [--private-key HEX]

Send devnet funds with the rothschild CLI.

Options:
  --root PATH         Devnet root (default: $(pwd)/igra_devnet)
  --to ADDRESS        Destination address (required)
  --amount SOMPI      Amount per transaction output in sompi (defaults to rothschild built-in 10 KAS)
  --tps N             Transactions per second (default: 1)
  --rpc HOST:PORT     Kaspad RPC server (default: 127.0.0.1:16110)
  --threads N         Worker threads for tx generation (default: 2)
  --private-key HEX   Private key hex; if omitted, read wallet.private_key_hex from <root>/config/devnet-keys.json
  -h, --help          Show this help

Notes:
  - Requires <root>/bin/rothschild to be present (built by run_local_devnet.sh build).
  - Reads keys from <root>/config/devnet-keys.json when --private-key is not provided.
EOF
}

ROOT="${ROOT:-}"
TO_ADDR=""
AMOUNT=""
TPS=1
RPCSERVER="127.0.0.1:16110"
THREADS=2
PRIVATE_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --to) TO_ADDR="$2"; shift 2 ;;
    --amount) AMOUNT="$2"; shift 2 ;;
    --tps) TPS="$2"; shift 2 ;;
    --rpc|--rpcserver) RPCSERVER="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --private-key) PRIVATE_KEY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${ROOT}" ]]; then
  ROOT="$(pwd)/igra_devnet"
fi

if [[ -z "${TO_ADDR}" ]]; then
  usage
  exit 1
fi

BIN_DIR="${ROOT}/bin"
KEYS_JSON="${ROOT}/config/devnet-keys.json"
ROTHSCHILD_BIN="${BIN_DIR}/rothschild"

if [[ ! -x "${ROTHSCHILD_BIN}" ]]; then
  echo "rothschild binary not found at ${ROTHSCHILD_BIN}; build/stage binaries first." >&2
  exit 1
fi

if [[ -z "${PRIVATE_KEY}" ]]; then
  if [[ ! -f "${KEYS_JSON}" ]]; then
    echo "Key file not found at ${KEYS_JSON}; run the build/setup flow to generate keys." >&2
    exit 1
  fi
  PRIVATE_KEY=$(python3 - "${KEYS_JSON}" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
pk = data.get("wallet", {}).get("private_key_hex")
if not pk:
    sys.stderr.write("wallet.private_key_hex missing in devnet-keys.json\n")
    sys.exit(1)
print(pk)
PY
  ) || exit 1
fi

CMD=("${ROTHSCHILD_BIN}" --rpcserver "${RPCSERVER}" --tps "${TPS}" --threads "${THREADS}" --private-key "${PRIVATE_KEY}" --to-addr "${TO_ADDR}")
if [[ -n "${AMOUNT}" ]]; then
  CMD+=(--amount "${AMOUNT}")
fi

echo "[run_rothschild] ${CMD[*]}"
exec "${CMD[@]}"
