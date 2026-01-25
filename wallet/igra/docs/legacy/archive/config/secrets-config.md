# Secret Management Guide (`secrets.bin`)

**Last Updated:** 2026-01-25  
**Status:** ✅ CURRENT

---

## Overview

Igra supports two secret sources:

- **FileSecretStore** (recommended; required in mainnet): encrypted `secrets.bin`
- **EnvSecretStore** (devnet/CI only): `IGRA_SECRET__*` environment variables

Mainnet security validation requires `service.use_encrypted_secrets=true`.

---

## Creating `secrets.bin`

Create an encrypted secrets file (prompts for a passphrase if `IGRA_SECRETS_PASSPHRASE` is not set):

```bash
cargo run --bin secrets-admin -- --path /var/lib/igra/secrets.bin init
```

Recommended permissions:
- File: `0600`
- Parent directory: owned by the service user, not world-accessible

---

## Service Configuration

```toml
[service]
use_encrypted_secrets = true
secrets_file = "/var/lib/igra/secrets.bin" # optional; defaults to ${data_dir}/secrets.bin
```

For non-interactive startup (required in mainnet), set:

```bash
export IGRA_SECRETS_PASSPHRASE="..."
```

---

## Passphrase Rotation

Passphrase rotation is enforced via:

- `service.passphrase_rotation_enabled`
- `service.passphrase_rotation_warn_days`
- `service.passphrase_rotation_error_days`

See `docs/dev/passphrase-rotation.md` for procedures and the on-disk format.

Rotate passphrase (re-encrypts `secrets.bin` in place):

```bash
cargo run --bin secrets-admin -- rotate-passphrase \
  --secrets-file /var/lib/igra/secrets.bin \
  --old-passphrase-file /secure/old-pass.txt \
  --new-passphrase-file /secure/new-pass.txt
```

After rotation, update `IGRA_SECRETS_PASSPHRASE` for the service and restart.

---

## Troubleshooting

### “unsupported secret file format”

`secrets.bin` files created before 2026-01-25 do not include the `RTM1` rotation metadata tag and are incompatible. Recreate the file with:

```bash
cargo run --bin secrets-admin -- --path /var/lib/igra/secrets.bin init
```

### “secret decryption failed”

Common causes:
- Wrong `IGRA_SECRETS_PASSPHRASE`
- File was modified/corrupted (header is authenticated)
- Mismatched `secrets_file` path in config vs the rotated file

