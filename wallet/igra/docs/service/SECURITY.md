# Security Notes (V1)

This document summarizes security boundaries, key separation, and replay protection.

## Key Separation

- **Kaspa signing keys:** secp256k1 Schnorr (transaction signatures).
- **Iroh identity keys:** Ed25519 (transport envelopes).
- **Hyperlane validator keys:** secp256k1 ECDSA (event authenticity).

Never reuse keys across these roles.

## Replay Protection

Replay protection is enforced at multiple layers:

- **Event replay:** `event_hash` is stored in RocksDB and duplicates are rejected.
- **Transport replay:** per-message dedup via `seen:` keys on `(sender_peer_id, session_id, seq_no)`.
- **Request audit trail:** `proposal`, `req_ack`, `req_sig`, and `req` entries allow independent verification.

## Policy Enforcement

The signer enforces:

- Destination allowlist.
- Min/max amount.
- Daily volume limit.
- Optional reason metadata requirement.

Policy violations return a signed rejection (`SignerAck { accept: false }`).

## Threat Model (Summary)

- **Compromised coordinator:** signers independently validate all proposals.
- **Malicious event source:** Hyperlane signatures are verified; policy blocks unsafe events.
- **Replay attacks:** rejected via `event_hash` and `seen:` markers.
- **Key compromise:** rotate keys and update `verifier_keys` + group agreement.

## Operational Best Practices

- Run with `rpc.enabled = true` only on designated proposers.
- Keep Iroh `verifier_keys` list minimal and agreed across peers.
- Monitor storage growth and keep backups for audit recovery.

