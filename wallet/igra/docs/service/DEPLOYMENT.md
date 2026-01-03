# Deployment Guide (V1)

This guide describes how to deploy Igra service nodes in a production signing group.

## Prerequisites

- Kaspa node with `--utxoindex` enabled.
- Rust toolchain (for building from source).
- Stable networking between signers (Iroh gossip).
- Group agreement on threshold, pubkeys, and policies.

## Key Material

- Kaspa signing keys: secp256k1 Schnorr (per signer).
- Iroh transport keys: Ed25519 (peer identity).
- Hyperlane validator keys: secp256k1 ECDSA (event verification).

Keep these keys separate and never reuse across roles.

## Group Setup

1) Agree on `threshold_m` / `threshold_n` and the exact pubkey ordering.
2) Agree on policy constraints (allowlist, amount limits, velocity).
3) Compute and share the `group_id` from `[group]` parameters.
4) Exchange Iroh peer ids + Ed25519 verification keys (`peer_id:hex_pubkey`).

## Configuration

Each signer runs the same binary but may disable RPC ingestion:

```ini
[rpc]
enabled = true           # set false for pure signers
addr = 127.0.0.1:8088
token = <optional>

[runtime]
session_timeout_seconds = 60

[pskt]
source_addresses = kaspatest:...
redeem_script_hex = <hex>
sig_op_count = 2
fee_payment_mode = recipient_pays
fee_sompi = 0
change_address = kaspatest:...

[policy]
allowed_destinations = kaspatest:...
min_amount_sompi = 1000000
max_amount_sompi = 100000000000
max_daily_volume_sompi = 500000000000
require_reason = false

[group]
threshold_m = 2
threshold_n = 3
member_pubkeys = <hex_pubkey1>,<hex_pubkey2>,<hex_pubkey3>
session_timeout_seconds = 60
finality_blue_score_threshold = 0

[iroh]
group_id = <32-byte-hex>
verifier_keys = peer-1:<hex_pubkey>,peer-2:<hex_pubkey>
bootstrap = <endpoint-id>
```

## Running the Service

```bash
cargo run -p igra-service --bin kaspa-threshold-service
```

## Operational Notes

- Ensure `group_id` matches the computed value from `[group]`. The service fails fast on mismatch.
- If `rpc.enabled = false`, the node will not accept external events and will only sign proposals from peers.
- Configure `hyperlane.validators` for Hyperlane-sourced events.

## Troubleshooting

- If no proposals finalize, check Iroh connectivity and `verifier_keys` allowlist.
- If PSKT build fails, confirm `source_addresses` and `redeem_script_hex`.
- If policy rejects proposals, verify `[policy]` allowlist and limits.

