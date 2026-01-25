# Quickstart (Devnet)

This quickstart runs multiple signers locally using **one `secrets.bin` per signer** and explicit `--profile signer-XX`.

## Build

```bash
cargo build -p igra-core --bin devnet-keygen
cargo build -p igra-core --bin secrets-admin
cargo build -p igra-service --bin kaspa-threshold-service
```

## Generate Per-Signer Secrets Files

```bash
./target/debug/devnet-keygen \
  --format file-per-signer \
  --output-dir ./.igra \
  --passphrase "devnet-secret" \
  --overwrite
```

This writes:
- `./.igra/signer-01/secrets.bin`
- `./.igra/signer-02/secrets.bin`
- `./.igra/signer-03/secrets.bin`

## Config

Use `artifacts/igra-config.toml` as a starting point and set:
- `service.network = "devnet"`
- `service.use_encrypted_secrets = true`
- `service.pskt.redeem_script_hex = "<your redeem script>"`

## Run (3 signers)

```bash
export IGRA_SECRETS_PASSPHRASE="devnet-secret"

./target/debug/kaspa-threshold-service --network devnet --config ./igra-config.toml --profile signer-01 --data-dir ./.igra/signer-01
./target/debug/kaspa-threshold-service --network devnet --config ./igra-config.toml --profile signer-02 --data-dir ./.igra/signer-02
./target/debug/kaspa-threshold-service --network devnet --config ./igra-config.toml --profile signer-03 --data-dir ./.igra/signer-03
```

