#!/bin/sh
set -e

if [ -z "${IGRA_PROFILE:-}" ]; then
  echo "ERROR: IGRA_PROFILE is required (e.g. signer-01)" >&2
  exit 1
fi

/app/kaspa-threshold-service --network devnet --profile "${IGRA_PROFILE}" &
SERVICE_PID=$!

# Give the RPC server a moment to start
sleep 2

/app/fake-hyperlane-ism &
FAKE_PID=$!

trap 'kill ${FAKE_PID} ${SERVICE_PID} 2>/dev/null || true' INT TERM

wait ${SERVICE_PID}
