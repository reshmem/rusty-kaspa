# Secrets and Keys

## One `secrets.bin` Per Signer

Each signer must have its own encrypted secrets file at:
- `${data_dir}/secrets.bin` (or `service.secrets_file`)

No shared secrets file.

For `kaspa-threshold-service`, the passphrase is provided via:
- `IGRA_SECRETS_PASSPHRASE` (non-interactive; recommended), or
- `secrets-admin --passphrase ...` (for admin operations).

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

### Build

```bash
# Build the core operator tools
cargo build -p igra-core --bin secrets-admin --release --locked
cargo build -p igra-core --bin devnet-keygen --release --locked
```

Or (testnet orchestration helper):

```bash
orchestration/testnet/scripts/build_igra_binaries.sh
```

### `devnet-keygen` (generate per-signer `secrets.bin`)

```bash
# Generate one secrets.bin per signer directory (production-aligned layout)
./target/release/devnet-keygen \
  --format file-per-signer \
  --output-dir ./.igra \
  --passphrase "devnet-secret" \
  --overwrite
```

This writes:
- `./.igra/signer-01/secrets.bin`
- `./.igra/signer-02/secrets.bin`
- …

### `secrets-admin` (inspect/verify/rotate)

Use `secrets-admin` when you need to:
- verify that a secrets file contains a valid mnemonic (dev/test only),
- rotate the *file passphrase* without changing key material,
- inspect the secret keys stored in a file (careful with `--unsafe-print`).

For testnet-v1 bundles, operators typically only need `secrets-admin` for passphrase rotation
(the admin pre-generates `secrets.bin` for v1).

Mnemonic import is dev/test-only. On mainnet, mnemonics are forbidden by config policy.

```bash
export IGRA_SECRETS_PASSPHRASE="devnet-secret"

# List secret names (does not print values)
./target/release/secrets-admin --path ./.igra/signer-01/secrets.bin list

# Verify mnemonic (dev/test only)
./target/release/secrets-admin --path ./.igra/signer-01/secrets.bin verify-mnemonic --profile signer-01
```

Passphrase rotation is documented in `docs/passphrase-rotation.md`.
