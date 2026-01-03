#!/bin/sh
set -e

/app/kaspa-threshold-service &
SERVICE_PID=$!

# Give the RPC server a moment to start
sleep 2

/app/fake-hyperlane-ism &
FAKE_PID=$!

trap 'kill ${FAKE_PID} ${SERVICE_PID} 2>/dev/null || true' INT TERM

wait ${SERVICE_PID}
