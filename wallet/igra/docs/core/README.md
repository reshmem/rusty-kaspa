# igra-core

Shared primitives for Igra:

- Event ingestion pipeline (`event/`) used by JSON-RPC and file-based providers.
- Signing backends (`signing/`) with explicit Threshold, MuSig2, and MPC interfaces.
- Coordination state machines (`coordination/`) and models (`model/`).
- RocksDB storage, validation helpers, and PSKT builder utilities.

Key material inventory

| Component | Key type | Curve | Purpose |
| --- | --- | --- | --- |
| Kaspa transaction signing | Keypair | secp256k1 (Schnorr) | Signing and verification of Kaspa transactions |
| Hyperlane validator signatures | Public key | secp256k1 (ECDSA) | Event authenticity verification |
| Iroh transport identity | Keypair | Ed25519 | Peer identity and envelope signing |

Storage schema (audit portability)

RocksDB keys are namespaced so a lost signer can import another peer's DB and
re-verify each request end-to-end:

- `evt:` SigningEvent indexed by `event_hash`
- `req:` SigningRequest indexed by `request_id`
- `proposal:` StoredProposal (includes PSKT blob) indexed by `request_id`
- `req_input:` RequestInput indexed by `request_id + input_index`
- `req_ack:` SignerAckRecord indexed by `request_id + signer_peer_id`
- `req_sig:` PartialSigRecord indexed by `request_id + signer_peer_id + input_index`

When `proposal`, `req_ack`, `req_sig`, and `final_tx_id` are present, the full
session can be replayed and verified independently.

Configuration notes

- INI section `signing.backend` selects the backend kind (`threshold`, `musig2`, `mpc`).
- `signing::backend_kind_from_config` validates the selection.
