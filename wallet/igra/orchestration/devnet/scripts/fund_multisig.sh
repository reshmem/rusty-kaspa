#!/bin/sh
set -e

COMPOSE="docker compose"
WALLET_NAME=${KASPA_DEVNET_WALLET_NAME:-devnet}
WALLET_DIR=/wallet
AMOUNT=${KASPA_FUND_AMOUNT_KAS:-50}
ADDR_FILE=${1:-multisig-addresses.txt}

if [ ! -f .env ]; then
  echo "Missing .env; copy .env.example first." >&2
  exit 1
fi

# Load environment variables for wallet settings.
set -a
. ./.env
set +a

if [ ! -f "${ADDR_FILE}" ]; then
  echo "Missing address file: ${ADDR_FILE}" >&2
  exit 1
fi

while IFS= read -r addr; do
  case "${addr}" in
    ""|"#"*) continue ;;
  esac
  echo "Sending ${AMOUNT} KAS to ${addr}"
  ${COMPOSE} run --rm wallet rothschild send \
    --network devnet \
    --wallet-dir ${WALLET_DIR} \
    --wallet "${WALLET_NAME}" \
    --to "${addr}" \
    --amount "${AMOUNT}" \
    --password "${KASPA_DEVNET_WALLET_PASSWORD}"
  sleep 1
done < "${ADDR_FILE}"
