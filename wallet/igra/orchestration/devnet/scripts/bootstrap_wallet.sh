#!/bin/sh
set -e

COMPOSE="docker compose"
WALLET_NAME=${KASPA_DEVNET_WALLET_NAME:-devnet}
WALLET_DIR=/wallet

if [ ! -f .env ]; then
  echo "Missing .env; copy .env.example first." >&2
  exit 1
fi

# Load environment variables for wallet settings.
set -a
. ./.env
set +a

# Create wallet (idempotent: ignore error if it already exists).
${COMPOSE} run --rm wallet rothschild wallet create \
  --network devnet \
  --wallet-dir ${WALLET_DIR} \
  --name "${WALLET_NAME}" \
  --mnemonic "${KASPA_DEVNET_WALLET_MNEMONIC}" \
  --password "${KASPA_DEVNET_WALLET_PASSWORD}" || true

ADDRESS=$(${COMPOSE} run --rm wallet rothschild address new \
  --network devnet \
  --wallet-dir ${WALLET_DIR} \
  --wallet "${WALLET_NAME}" | tail -n 1)

if [ -z "${ADDRESS}" ]; then
  echo "Failed to obtain mining address." >&2
  exit 1
fi

echo "Mining address: ${ADDRESS}"

# Update .env in place if KASPA_MINING_ADDRESS is present.
if grep -q "^KASPA_MINING_ADDRESS=" .env; then
  TMP_FILE=$(mktemp)
  sed "s|^KASPA_MINING_ADDRESS=.*|KASPA_MINING_ADDRESS=\"${ADDRESS}\"|" .env > "${TMP_FILE}"
  mv "${TMP_FILE}" .env
  echo "Updated .env with KASPA_MINING_ADDRESS. Restart kaspaminer after this." >&2
else
  echo "KASPA_MINING_ADDRESS not found in .env; please set it manually." >&2
fi
