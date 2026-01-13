# Protocol Specification (V1)

## Roles

- Coordinator: proposes a signing session and aggregates signatures
- Signers: validate proposals, sign inputs, and return partial signatures
- Request source: submits signing events via RPC or file watcher

## Flow Overview

1) Receive signing event (RPC or file watcher)
2) Validate event signature (Hyperlane/LayerZero) and policy
3) Build PSKT from UTXOs via Kaspa RPC
4) Propose signing session over Iroh gossip
5) Collect signer acknowledgements
6) Collect partial signatures per input
7) Finalize and submit transaction when threshold reached

## Message Types

- SigningEventPropose: includes event, hashes, PSKT blob, and coordinator id
- SignerAck: accept/reject proposal with validation hash
- PartialSigSubmit: per-input signature fragments
- FinalizeNotice: finalized transaction id

## Invariants

- Each request has a unique request_id and session_id
- All signers validate event_hash, tx_template_hash, and validation_hash
- A request is finalized only after reaching threshold signatures
- Finalized requests are terminal and must not be re-signed
