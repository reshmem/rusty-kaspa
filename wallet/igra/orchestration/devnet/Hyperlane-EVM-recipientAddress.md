# Hyperlane EVM `recipientAddress` vs Kaspa Addresses (Design Note)

This document explains why we do **not** place the Kaspa recipient address directly into Hyperlane EVM `Mailbox.dispatch(..., bytes32 recipientAddress, bytes messageBody)`, and what we do instead.

It is intended to be unambiguous for auditors, readers, and implementers.

## Problem

Hyperlane’s EVM `Mailbox.dispatch` requires:

- `recipientAddress`: **exactly 32 bytes** (`bytes32`)
- `messageBody`: arbitrary bytes

For Igra, the “real” recipient is a **Kaspa address**, which is normally represented and transported as a **bech32 address string** (e.g. `kaspadev:...`).

### Why a Kaspa address is not “just 32 bytes”

Kaspa addresses have multiple *variants* and encode more than a single 32-byte payload:

- **Network / prefix** (e.g. `kaspa`, `kaspatest`, `kaspadev`)
- **Version** (at least `PubKey`, `ScriptHash`, and `PubKeyECDSA`)
- **Payload bytes**
  - `PubKey` payload length: 32 bytes
  - `ScriptHash` payload length: 32 bytes
  - `PubKeyECDSA` payload length: 33 bytes
- **Checksum**

So even when the payload is 32 bytes, the address is not uniquely determined without the **version** and **prefix**. And for `PubKeyECDSA`, the payload is **33 bytes**, which cannot fit into `bytes32` at all.

### Constraints we must satisfy

1. Igra must be able to reconstruct and validate the **exact** Kaspa destination address for signing.
2. The destination address must be **bound to the signed Hyperlane proof** (cannot be swapped without breaking verification).
3. The schema should be easy to reproduce across languages (Rust/TS/solidity tooling).

## Decision (Solution Overview)

We split “routing” and “payload”:

1. `recipientAddress` is a **deterministic tag-hash** (32 bytes) derived from the Kaspa address string.
2. `messageBody` carries the **full** signing payload (amount + the full Kaspa address string).

This keeps the Kaspa address in a form that is:

- human-auditable (`kaspadev:...`)
- unambiguous (includes prefix and implies network)
- parseable/validatable by Igra using the canonical Kaspa address parser

## Exact Schema

### `recipientAddress` (bytes32)

We compute:

```
recipient_bytes32 = keccak256("igra:v1:" || kaspa_address_utf8)
```

Where:

- The tag `"igra:v1:"` is **domain separation** (prevents accidental reuse of hashes across other schemes).
- `kaspa_address_utf8` is the UTF-8 bytes of the full bech32 address string.
- `keccak256` is the EVM-standard hash used widely for `bytes32` identifiers.

Implementation: `igra-service/src/bin/hyperlane_anvil_sender.rs` (`DEFAULT_RECIPIENT_TAG`, `compute_recipient_bytes32()`).

### `messageBody` (bytes)

We encode the signing payload as:

```
message_body = amount_sompi_le_u64 || kaspa_address_utf8
```

- `amount_sompi_le_u64`: 8 bytes, little-endian `u64`
- followed by the UTF-8 bytes of the full Kaspa address string

Implementation: `igra-service/src/bin/hyperlane_anvil_sender.rs` (`build_message_body()`).

Igra parses it as:

- `amount_sompi = u64::from_le_bytes(body[0..8])`
- `destination_address = utf8(body[8..])`
- validates it using the Kaspa address parser

Implementation: `igra-service/src/api/handlers/hyperlane.rs` (`extract_signing_payload()`).

## Why This Is Sound

### 1) The Kaspa recipient is cryptographically bound to the proof

Hyperlane `message_id` is computed from the full message fields (including **recipient** and **body**). Our proof verification in Igra verifies signatures over a checkpoint that is tied to `message_id`.

Therefore, if an attacker changes either:

- `recipientAddress` **or**
- `messageBody` (amount / Kaspa address)

the `message_id` changes, and the previously-valid validator signatures no longer verify. That makes the recipient and amount tamper-evident.

### 1.1) The destination enforces the `recipientAddress` ↔ body mapping

Igra additionally enforces that the EVM `recipientAddress` equals our canonical tag-hash of the Kaspa address string carried in the body:

```
recipient_bytes32 == keccak256("igra:v1:" || kaspa_address_utf8)
```

This prevents messages whose `recipientAddress` and body disagree from entering the signing pipeline.

### 2) Full recipient validation happens at the destination

Igra validates the bech32 Kaspa address string using the canonical Kaspa address parser (not a “best effort” decode). This prevents malformed addresses from entering the signing pipeline.

### 3) Tag-hash avoids ambiguity and keeps EVM semantics

We still supply a stable `bytes32 recipientAddress` to satisfy the EVM Mailbox ABI and avoid using a constant value. The tag-hash:

- is deterministic (same Kaspa recipient → same recipient bytes32),
- is collision-resistant (keccak256),
- includes domain separation via the tag prefix.

### 4) Works across address versions

Because the actual address is carried as a full string in the body, we do not need to assume:

- which Kaspa address version is used (PubKey vs ScriptHash vs PubKeyECDSA),
- which payload length is present,
- or how to reconstruct the string from only 32 bytes.

## Alternatives Considered (and Rejected)

### A) Put a 32-byte payload directly into `recipientAddress`

This fails because:

- Kaspa has address versions with different payload lengths (`PubKeyECDSA` = 33 bytes).
- Even for 32-byte payloads, you still need at least a version byte (and network prefix) to reconstruct/validate the address unambiguously.
- Igra would need extra policy (“always ScriptHash”, “prefix from domain”, etc.) that is not currently part of the protocol.

### B) Put `hash(kaspa_address)` in `recipientAddress` and omit it from the body

This fails because:

- a hash is one-way; the destination cannot recover the full Kaspa address from `bytes32`.
- you’d need an external mapping service or pre-shared lookup table (complex, brittle, and harder to audit).

## Summary

- We cannot use `recipientAddress` alone to carry Kaspa recipient information because Kaspa addresses are not a single fixed 32-byte value in a way that preserves prefix/version semantics (and some variants exceed 32 bytes).
- We use `recipientAddress` as a deterministic tag-hash identifier.
- We carry the full recipient address string (plus amount) in `messageBody`, which Igra parses and validates.
- The proof ties `recipientAddress` and `messageBody` to the signed `message_id`, so recipient+amount are tamper-evident.
