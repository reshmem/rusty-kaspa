# Mnemonics Refactor: Profile-Based Secret Storage

**Status:** Implemented  
**Created:** 2026-01-25  
**Last Updated:** 2026-01-25

## Goals

- Mnemonics never appear in TOML config files.
- One `secrets.bin` per signer (no shared secrets file).
- Active profile is explicit (CLI `--profile` or `service.active_profile`), no profile inference from environment variables.
- Signer profiles are canonical: `signer-XX` (01-99) and must align with pubkey index order in the redeem script.
- Mainnet forbids mnemonic-based signing (`service.hd.key_type="hd_mnemonic"`).

## Non-Goals

- No “v1 → v2 migration” flow (we are not in production yet).
- No support for arbitrary profile names (e.g. `alice`, `seed`).

## Summary of the New Model

### Configuration (`igra-config.toml`)

Config contains only public / operational data. In particular:
- `service.hd` config contains **how** to derive the signing key (mode + derivation path + xpubs), but **no mnemonics**.
- `profiles.signer-XX.*` contains per-signer operational overrides (e.g. per-signer `data_dir`, per-signer RPC port).

Active profile selection is explicit:
- Prefer: `kaspa-threshold-service --profile signer-01 ...`
- Alternative: `service.active_profile = "signer-01"` (or env override `IGRA_SERVICE__ACTIVE_PROFILE=signer-01`)

### Secrets (per signer)

Each signer machine has its own `secrets.bin` (encrypted at rest, Argon2id + XChaCha20-Poly1305). Example layout:

- `/var/lib/igra/signer-01/secrets.bin`
- `/var/lib/igra/signer-02/secrets.bin`
- ...

### Secret Names

Canonical secret names are profile-based:

- `igra.signer.mnemonic_{profile}` (dev/test only)
- `igra.signer.payment_secret_{profile}` (optional BIP39 passphrase / “25th word”, per signer)
- `igra.signer.private_key_{profile}` (raw key mode, mainnet supported)
- `igra.iroh.signer_seed_{profile}` (transport identity)

Examples (FileSecretStore, profile contains `-`):
- `igra.signer.mnemonic_signer-01`
- `igra.signer.payment_secret_signer-01`
- `igra.signer.private_key_signer-01`
- `igra.iroh.signer_seed_signer-01`

EnvSecretStore note: environment variables cannot contain `-`, so the env backend uses an underscore suffix:
- Profile `signer-01` → env suffix `signer_01`
- Example env var: `IGRA_SECRET__igra_signer__mnemonic_signer_01="..."` (used only for devnet/CI)

## Mainnet Policy

Mainnet forbids mnemonic signing. Enforced by startup validation:
- Allowed: `service.hd.key_type="raw_private_key"` + `igra.signer.private_key_signer-XX`
- Forbidden: `service.hd.key_type="hd_mnemonic"` and/or `igra.signer.mnemonic_*`

## Signer Index Alignment (Critical Safety Rule)

Profile numbering must match the pubkey order in the redeem script:

- Profile format: `signer-XX` (1-based index, zero padded)
- Startup validation derives this signer’s pubkey from its secret material and ensures it matches the redeem-script pubkey at index `XX`.

This prevents running `signer-07` with `signer-03`’s key material.

**Operator workflow**
1. Compute your signer pubkey from your secret material (mnemonic/payment_secret or raw private key).
2. Find it in the redeem script pubkey list (order matters).
3. Use the 1-based position as your profile number (position 7 → `signer-07`).

## Tooling

### `secrets-admin`

Import and verify a mnemonic inside a signer’s `secrets.bin`:

```bash
# Import mnemonic (writes igra.signer.mnemonic_signer-01)
secrets-admin --path /var/lib/igra/signer-01/secrets.bin import-mnemonic --profile signer-01 --stdin

# Verify mnemonic (checks BIP39 validity and that the secret exists)
secrets-admin --path /var/lib/igra/signer-01/secrets.bin verify-mnemonic --profile signer-01
```

### `devnet-keygen`

Preferred devnet mode writes one `secrets.bin` per signer:

```bash
devnet-keygen --format file-per-signer --output-dir ./devnet-out --passphrase "devnet-secret" --overwrite
```

Single-signer generation (useful for per-signer provisioning flows):

```bash
devnet-keygen --num-signers 1 --signer-profile signer-01 --format file-per-signer --output-dir ./devnet-out --passphrase "devnet-secret" --overwrite
```

EnvSecretStore output (devnet only):

```bash
eval "$(devnet-keygen --format env)"
```

## Running the Service

```bash
export IGRA_SECRETS_PASSPHRASE="<from password manager>"
kaspa-threshold-service --network devnet --config ./igra-config.toml --profile signer-01
```

## Implementation References

- Profile + config loading: `igra-service/src/bin/kaspa-threshold-service.rs`
- Signing secret loading: `igra-core/src/application/pskt_signing.rs`
- Startup validation (mainnet policy + alignment): `igra-core/src/infrastructure/network_mode/rules/startup.rs`
- Secrets validation: `igra-core/src/infrastructure/network_mode/rules/secrets.rs`
- CLI tools: `igra-core/src/bin/secrets-admin.rs`, `igra-core/src/bin/devnet-keygen.rs`

