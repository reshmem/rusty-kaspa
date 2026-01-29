# Passphrase Rotation (`secrets.bin`)

Igra’s encrypted secrets file (`secrets.bin`) tracks passphrase age and supports manual rotation via `secrets-admin rotate-passphrase`.

## Config

```toml
[service]
passphrase_rotation_enabled = true
passphrase_rotation_warn_days = 60
passphrase_rotation_error_days = 90
```

## Rotate Passphrase

```bash
./target/release/secrets-admin rotate-passphrase \
  --secrets-file ./.igra/signer-01/secrets.bin \
  --old-passphrase-file /secure/old-pass.txt \
  --new-passphrase-file /secure/new-pass.txt
```

Notes:
- For non-interactive runs, set `IGRA_SECRETS_PASSPHRASE` or use `--old-passphrase-file`.
- Rotation is per-signer because there is one `secrets.bin` per signer.
