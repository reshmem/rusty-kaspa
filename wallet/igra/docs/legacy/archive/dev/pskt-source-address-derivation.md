# PSKT Source Address Derivation (Make `service.pskt.source_addresses` Optional)

**Status:** Design proposal  
**Last Updated:** 2026-01-25  
**Owner:** (TBD)

---

## Problem

Today we require `service.pskt.source_addresses` in config. This is redundant and error-prone:

- For a fixed multisig `redeem_script_hex`, the P2SH script-hash (and thus the funding address) is deterministic.
- Operators can paste the wrong address/prefix (mainnet vs testnet vs devnet), causing UTXO discovery and network validation failures.
- Templates force users to maintain two coupled values: `redeem_script_hex` and its derived funding address.

In practice, signers should scan only the funding address that corresponds to the configured redeem script.

---

## Current Behavior (Why It Exists)

`service.pskt.source_addresses` is used for:

1. **UTXO discovery**: query node RPC for all UTXOs at those addresses.
2. **Network validation**: ensure destination/change/source addresses match the expected network prefix.

The bug is that we ask users to provide the address that we could derive from the redeem script, and then we sometimes use that address to infer/validate the network.

---

## Goals

- Make `service.pskt.source_addresses` optional.
- Derive the canonical P2SH funding address from:
  - `service.pskt.redeem_script_hex`
  - `service.network` (or CLI `--network`, which should populate `service.network` at runtime)
- Fail closed:
  - If `source_addresses` is provided and non-empty, it must match the derived address.
- Keep changes minimal:
  - Preserve `Vec<String>` for now (the rest of the code expects a list for RPC calls), but make the effective list a single derived address.

---

## Non-Goals

- No “v1 → v2” migration work. This is a pre-production refactor and should be implemented directly, with the simplest compatibility behavior.

---

## Proposed Configuration Semantics

### Required inputs for derivation

- `service.pskt.redeem_script_hex` must be set and valid hex.
- `service.network` must be set (explicit confirmation of the intended network).

### Effective source addresses

Compute:

1. `redeem_script = hex::decode(redeem_script_hex)`
2. `p2sh_script_pub_key = pay_to_script_hash_script(redeem_script)`
3. `derived_address = extract_script_pub_key_address(p2sh_script_pub_key, prefix_for(service.network))`

Then:

- If `service.pskt.source_addresses` is **missing/empty/blank-only**:
  - `effective_source_addresses = [derived_address]`
- If `service.pskt.source_addresses` is **provided**:
  - Trim/ignore blank entries.
  - Every provided address must equal `derived_address` (string compare after trim).
  - `effective_source_addresses = [derived_address]` (normalize to canonical single value)

### Change address defaulting

If `service.pskt.change_address` is missing/blank, default it to `derived_address`.

Rationale:
- In our flow, change is frequently enabled, and missing `change_address` becomes a runtime PSKT builder error.
- For multisig funding, returning change to the same multisig address is the safe default.

---

## Validation Rules

When `service.network` is set:

- Enforce that destination addresses, `change_address`, and `effective_source_addresses[0]` match the expected network prefix.
- If `source_addresses` is provided, enforce that it matches the derived address (this catches copy/paste mistakes early).

When `service.network` is not set:

- Do not attempt derivation.
- Keep the existing behavior (users must provide `source_addresses`) until we can require `service.network` everywhere.

---

## Implementation Notes (Where to Apply)

To avoid ordering problems, derivation needs to happen before any logic that:

- Validates network prefix
- Normalizes `change_address`
- Fetches UTXOs via RPC

Preferred approach:

- After config load (and after `service.network` is resolved), compute and apply:
  - `effective_source_addresses`
  - `change_address` default
- Then pass the effective config to all PSKT building / event processing / RPC code.

---

## Examples

### Minimal PSKT config (preferred)

```toml
[service]
network = "mainnet"

[service.pskt]
redeem_script_hex = "<REPLACE_WITH_YOUR_10_OF_15_REDEEM_SCRIPT_HEX>"
# source_addresses omitted (derived)
# change_address omitted (defaults to derived)
```

### With explicit override (must match derived)

```toml
[service]
network = "testnet"

[service.pskt]
redeem_script_hex = "<...>"
source_addresses = ["kaspatest:..."] # must equal derived address
```

