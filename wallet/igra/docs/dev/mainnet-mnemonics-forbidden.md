# Mainnet: Forbid `hd_mnemonic` Signing Keys

**Status:** ✅ CURRENT
**Last updated:** 2026-01-24

## Problem

Historically, Igra supported `service.hd.key_type = "hd_mnemonic"` where the signer derives its secp256k1 signing key from a BIP39 mnemonic (and optional `payment_secret`).

For mainnet deployments this is a footgun:

- Even “encrypted mnemonics in config” still increases operator error risk (copy/paste, backups, config distribution).
- Mnemonic handling expands the attack surface and complicates ops procedures.
- Our production key story is now centered around `secrets.bin` + `KeyManager` and future KMS/HSM backends (key-oriented, not mnemonic-oriented).

## Decision

**Mainnet forbids mnemonic-based signing.**

In `NetworkMode::Mainnet` the only supported signer key type is:

- `service.hd.key_type = "raw_private_key"`

Mnemonic-based signing (`"hd_mnemonic"`) remains allowed for devnet/testnet (as a development convenience).

## Implementation

We enforce the rule in two places:

1. **Static validation** (so `--validate-only` fails):
   - `igra-core/src/infrastructure/network_mode/rules/config.rs`
   - Rule: if `mode == Mainnet` and `service.hd.key_type == HdMnemonic` → `ErrorCategory::Configuration` error.

2. **Startup validation** (defense-in-depth):
   - `igra-core/src/infrastructure/network_mode/rules/startup.rs`
   - Rule: if `mode == Mainnet` and `service.hd.key_type == HdMnemonic` → `ErrorCategory::Secrets` error, skip further secret checks.

## Operator Impact (Mainnet)

- Each signer stores its private key in `secrets.bin` under:
  - `igra.signer.private_key_<profile_suffix>`
  - Example: profile `signer-01` → `igra.signer.private_key_signer_01`
- `docs/config/mainnet-config-template.toml` is updated to mark `hd_mnemonic` as **FORBIDDEN IN MAINNET** and to document the `secrets.bin` key names.

## Tests

- `igra-core/tests/unit/network_mode_security.rs` includes a unit test ensuring mainnet rejects `service.hd.key_type=hd_mnemonic`.

