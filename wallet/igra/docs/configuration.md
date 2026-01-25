# Configuration

The service loads a **base config** plus optional **profile overrides** from `[profiles.<name>]`.

For a full key-by-key reference (defaults, requiredness, cross-checks), see:
- `docs/configuration-reference.md`

## Active Profile (Required)

The active signer profile must be explicit:
- CLI: `--profile signer-XX` (recommended)
- Or config: `service.active_profile = "signer-XX"`

Canonical format is `signer-XX` (01-99). Startup fails if missing or invalid.

## Secrets Backend

- File secrets (recommended): set `service.use_encrypted_secrets = true` and provide `IGRA_SECRETS_PASSPHRASE`.
- Env secrets (devnet/CI only): `IGRA_SECRET__*` variables.

## PSKT Inputs

`service.pskt.redeem_script_hex` is the source of truth for multisig behavior.

`service.pskt.source_addresses` is optional and derived from the redeem script + network. Prefer omitting it unless you have a specific reason.
