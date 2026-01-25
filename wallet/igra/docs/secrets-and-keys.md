# Secrets and Keys

## One `secrets.bin` Per Signer

Each signer must have its own encrypted secrets file at:
- `${data_dir}/secrets.bin` (or `service.secrets_file`)

No shared secrets file.

## Secret Names (Profile-Based)

Profile format: `signer-XX` (01-99).

FileSecretStore uses the profile string as-is:
- `igra.signer.mnemonic_signer-01` (dev/test only)
- `igra.signer.payment_secret_signer-01` (optional BIP39 passphrase)
- `igra.signer.private_key_signer-01` (mainnet supported)
- `igra.iroh.signer_seed_signer-01`

EnvSecretStore uses an underscore suffix because env vars cannot contain `-`:
- `signer-01` → `signer_01`

## Mainnet Policy

Mainnet forbids mnemonic-based signing (`service.hd.key_type="hd_mnemonic"`). Use raw private keys on mainnet.

## Signer Index Alignment (Safety Rule)

Startup validation enforces: profile index `XX` must match the pubkey position inside `service.pskt.redeem_script_hex`.

## Tooling

```bash
# Import + verify mnemonic in a signer secrets file
export IGRA_SECRETS_PASSPHRASE="devnet-secret"
./target/debug/secrets-admin --path ./.igra/signer-01/secrets.bin import-mnemonic --profile signer-01 --stdin
./target/debug/secrets-admin --path ./.igra/signer-01/secrets.bin verify-mnemonic --profile signer-01
```

```bash
# Generate one secrets.bin per signer directory
./target/debug/devnet-keygen --format file-per-signer --output-dir ./.igra --passphrase "devnet-secret" --overwrite
```
