# Igra Hyperlane Relayer API

This document defines the JSON-RPC surface for integrating Hyperlane v3 attestation and delivery semantics into the Igra threshold-signing service. It mirrors the roles of `Mailbox.process` and `validators_and_threshold` while reusing Igra’s existing `/rpc` endpoint, authentication, rate limiting, and message size limits.

## Transport and Auth

- **Endpoint:** `POST /rpc`
- **Protocol:** JSON-RPC 2.0
- **Auth:** Same as the service (`Authorization: Bearer <token>` or `x-api-key: <token>` when configured).
- **Limits:** The service’s global rate limits and per-request size limits apply; callers must respect the max proposal/metadata size (recommended ≤ 1 MB).

## Methods

### `hyperlane.validators_and_threshold`

Returns the validator set and threshold expected for a given message context (destination ISM/domain).

**Request**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "hyperlane.validators_and_threshold",
  "params": {
    "message_id": "<32-byte-hex>",
    "destination_domain": "<u32>",
    "origin_domain": "<u32>"
  }
}
```

**Fields**

- `message_id` — The Hyperlane message leaf (H256). Used for auditing and to anchor which message the returned set is intended to verify. Comes from the origin Mailbox Merkle tree.
- `destination_domain` — Hyperlane destination domain (u32). Selects the ISM view for that destination; server rejects unknown domains.
- `origin_domain` — Hyperlane origin domain (u32). Informational context; can be logged and validated against policy.

**Response**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "validators": ["0x<secp256k1-pubkey-hex>", "..."],
    "threshold": 2,
    "config_hash": "0x<blake3-of-validator-set>"
  }
}
```

- `validators` — ECDSA secp256k1 public keys (uncompressed or compressed hex) configured for the destination ISM. Source: local configuration; should match on-chain ISM validator set.
- `threshold` — Required number of validator signatures. Source: local configuration matching destination ISM.
- `config_hash` — Blake3 hash of the returned set/threshold for client pinning and replay protection.

### `hyperlane.mailbox_process`

API analogue of `Mailbox.process`. Verifies a message against a provided checkpoint + signatures (and Merkle proof when required). On success it attests that the message is proven and the server immediately triggers the downstream signing flow using the message body.

**Request**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "hyperlane.mailbox_process",
    "params": {
      "message": {
        "version": 0,
        "nonce": "<u32>",
        "origin": "<u32>",
        "sender": "<0xH256>",
        "destination": "<u32>",
        "recipient": "<0xH256>",
        "body": "<0x...>" // hex-encoded bytes or a raw byte array
      },
      "metadata": {
        "checkpoint": {
          "merkle_tree_hook_address": "<0x...>",
          "mailbox_domain": "<u32>",
          "root": "<0x...>",
          "index": "<u32>",
          "message_id": "<0xH256>"
        },
        "merkle_proof": ["<0x...>", "..."],
        "signatures": ["<0x65-byte>", "..."]
      },
      "mode": "message_id_multisig" // or "merkle_root_multisig"
    }
  }
  ```

**Field details and security anchoring**

- `message` — The Hyperlane message leaf fields (see Hyperlane spec). The `message_id` is `keccak256(serialized_message)`. Originated on the origin chain Mailbox; security depends on correct serialization and immutability of fields.
  - `version`/`nonce`/`origin`/`destination` — Define the routing and replay domain; validated as per Hyperlane spec.
  - `sender`/`recipient` — 32-byte addresses (H256) on origin/destination chains. Integrity is bound via `message_id`.
  - `body` — Opaque payload; size-limited by the service; contributes to `message_id`.
  - Uniqueness note: `message_id` embeds `origin` and `nonce`, so messages from different chains remain unique as long as each chain uses a distinct origin domain. Only a misconfigured setup with identical `origin` IDs and identical payloads/nonce could collide.
- `metadata.checkpoint` — The attested Merkle root context produced by validators on origin.
  - `merkle_tree_hook_address` — Origin contract address; anchors the tree.
  - `mailbox_domain` — Origin domain id; must match `origin`.
  - `root` — Merkle root being attested.
  - `index` — Leaf index in the origin Merkle tree.
  - `message_id` — The leaf hash for this checkpoint index; must match the serialized `message`. Security: Validators sign over this structure.
- `metadata.merkle_proof` — Required for `merkle_root_multisig` mode. Array of sibling hashes (depth 32 typical). Used to prove `message_id` ∈ `root` at `index`. Security depends on correct ordering and depth.
- `metadata.signatures` — ECDSA secp256k1 65-byte recoverable signatures (`r || s || v`, `v` may be 0/1 or 27/28) over the checkpoint binding:
  - Signing hash: `keccak256(domain_hash(merkle_tree_hook_address, mailbox_domain) || root || index_be || message_id)`.
  - Validators and threshold are resolved via `hyperlane.validators_and_threshold`. The service requires `threshold` distinct validators to recover.
- `mode` — `message_id_multisig` or `merkle_root_multisig`; determines whether `merkle_proof` is required and which signing hash is verified.

**Response (success)**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "status": "proven",
    "message_id": "<0xH256>",
    "event_id": "<0xH256>",
    "root": "<0x...>",
    "quorum": <n>,
    "validators_used": ["0x<pubkey>", "..."],
    "config_hash": "0x<blake3-of-validator-set>",
    "mode": "message_id_multisig",
    "session_id": "0x<blake3(group_id||message_id)>",
    "signing_submitted": true
  }
}
```

**Errors**

- `invalid_params` — Malformed fields, bad hex, oversized payloads.
- `unknown_domain` — Destination domain not configured.
- `insufficient_quorum` — Signatures fewer than threshold or duplicate validator keys.
- `invalid_signature` — Signature recovery fails or not in validator set.
- `invalid_proof` — Merkle proof does not bind `message_id` to `root/index`.
- `mismatch_origin` — `metadata.checkpoint.mailbox_domain` != `message.origin`.

## Validation Flow (Server Side)

1. **Auth and limits** — Enforce auth token, rate limits, and size limits before decoding.
2. **Decode and sanity check** — Strict hex-length checks; reject non-canonical encodings.
3. **Resolve validator set** — From configured destination domain; hash and expose `config_hash`.
4. **Recompute `message_id`** — From `message` fields; must match provided `metadata.message_id`.
5. **Signature verification** — Recover validator addresses from signatures over the mode-specific signing hash; require `threshold` distinct validators from the configured set.
6. **Merkle proof (if needed)** — For `merkle_root_multisig`, verify inclusion of `message_id` at `index` in `root`.
7. **Origin/destination checks** — Ensure `mailbox_domain` == `message.origin` and `message.destination` matches caller intent/policy.
8. **Audit trail** — Record `message_id`, domains, quorum, validators used, and result.

## Mapping a Proven Hyperlane Message to `signing_event.submit`

When `hyperlane.mailbox_process` succeeds, the server immediately constructs and submits an internal `signing_event.submit`, with all fields derived from the proven Hyperlane message (no client-supplied submit payload is accepted):

- `event_id` = `message_id` (0x-hex); `request_id` = `event_id`.
- `event_source` = Hyperlane variant:
  - `domain` = `message.destination` (as string).
  - `sender` = `message.sender` (0x-hex).
- `derivation_path` / `derivation_index` = derived defaults (path empty, index 0).
- `destination_address` = derived from `message.recipient` (32-byte Kaspa payload) plus local network prefix (kaspa/kaspatest/kaspadev); version assumed `PubKey`.
- `amount_sompi` = parsed from `message.body` (must be exactly 8-byte big-endian u64).
- `metadata` includes:
  - `hyperlane.mode` (`message_id_multisig` or `merkle_root_multisig`).
  - `hyperlane.merkle_root` (`checkpoint.root`).
  - `hyperlane.mailbox_domain` (`checkpoint.mailbox_domain`).
  - `hyperlane.index` (`checkpoint.index`).
  - `hyperlane.message_id` (0x-hex).
  - `hyperlane.proof.index` when a Merkle proof is present.
  - `hyperlane.quorum` (threshold from validator set).
- `timestamp_nanos` = server clock at submission time.
- `signature`/`signature_hex` = empty (Hyperlane proof already verified).
- `session_id_hex` = `blake3(group_id || message_id)`; server rejects submission if `group_id` is missing/invalid. `group_id` comes from the local Iroh config and is the same value used for the signer mesh.  
- `coordinator_peer_id` = the local peer ID of this Igra node (not client-provided).  
- `expires_at_nanos` = server default (10 minutes from submission).

This preserves deterministic identities (event_id == message_id, session_id bound to group_id) and carries Hyperlane context for audit and policy.

### Default extraction from message fields

- `recipient` must be the 32-byte Kaspa destination payload (no prefix). The server adds the local network prefix (kaspa/kaspatest/kaspadev) and assumes version `PubKey` to build the full Kaspa address.
- `body` must be exactly 8 bytes = `u64::to_be_bytes(amount_sompi)`. No JSON; raw bytes only.
- Network prefix is inferred from the node’s PSKT source/change addresses; mismatches are rejected. Any other body length/encoding is rejected.

**Important:** `message.body` is part of `message_id`. You must not mutate or re-encode the body when forwarding to `mailbox_process`; the bytes used to compute `message_id` must be preserved verbatim. Only parse the body for extracting signing parameters—do not rewrite it. The server recomputes `message_id` from the exact bytes you submit.

## Security Dependencies

- Validator set correctness: Must match the on-chain ISM for the destination; stale or misconfigured sets weaken security. Exposed via `config_hash` for pinning.
- Signature verification: Uses ECDSA secp256k1 recoverable signatures; relies on canonical signing hash defined above.
- Merkle proof correctness: In `merkle_root_multisig` mode, proof binds `message_id` to the attested `root` and `index`.
- Rate limiting and size limits: Protect against DoS (oversized metadata/proof/signature arrays).
- Auth tokens: Prevent unauthorized use of the proving API; rotate if compromised.

## Operational Notes

- Keep validator sets and thresholds aligned with destination ISM governance; update config and restart nodes when ISM changes.
- Monitor audit logs for `insufficient_quorum` or `invalid_signature` spikes (could indicate config drift or malicious payloads).
- Consider exposing a metrics counter for successful `mailbox_process` proofs and failure reasons for observability.

## Mode Selection (`message_id_multisig` vs `merkle_root_multisig`)

- **`message_id_multisig` (preferred, Hyperlane default today):**
  - Validators sign a checkpoint that binds `{merkle_tree_hook_address, mailbox_domain, root, index, message_id}`.
  - No Merkle proof required; calldata is smaller and verification is simpler. This is the default ISM mode used in most Hyperlane production deployments.
- **`merkle_root_multisig`:**
  - Validators sign the same checkpoint hash but callers must also supply a Merkle proof showing that `message_id` is included in `root` at `index`.
  - Calldata is larger and verification includes inclusion proof checks. Use when the ISM configuration requires Merkle proofs alongside checkpoint signatures.

**Implementation order in Igra:** We will first ship support for `message_id_multisig` (matches current Hyperlane default and keeps integration minimal). Support for `merkle_root_multisig` will be added afterward for compatibility with root-only ISM configurations.

### Message ID uniqueness note

`message_id = keccak256(serialized_message)` includes `origin` and `nonce`. Even if two mailboxes on different chains start from nonce 0, their `origin` domains differ, keeping `message_id` unique. Collisions would require a misconfigured setup where distinct chains share the same `origin` id and emit identical messages.
