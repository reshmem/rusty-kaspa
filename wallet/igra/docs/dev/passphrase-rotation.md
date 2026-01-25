# Passphrase Rotation for Encrypted Secrets (`secrets.bin`)

**Status:** Implemented  
**Last Updated:** 2026-01-25  
**Priority:** High (security hygiene)

---

## Summary

Igra’s encrypted secrets file (`secrets.bin`) now tracks passphrase age and supports manual passphrase rotation:

- `secrets.bin` stores `created_at_nanos` and `last_rotated_at_nanos`.
- Network-mode validation warns/errors when the passphrase is too old.
- `secrets-admin rotate-passphrase` re-encrypts the file with a new passphrase and updates `last_rotated_at_nanos`.

This is an incompatible on-disk format change while keeping `Version: 1`. Any `secrets.bin` created before this change must be recreated.

---

## File Format (Version 1, with `RTM1` rotation tag)

```
[0-3]   Magic: "ISEC" (0x49534543)
[4]     Version: 1
[5-8]   Argon2 m_cost (u32 LE)
[9-12]  Argon2 t_cost (u32 LE)
[13-16] Argon2 p_cost (u32 LE)
[17-48] Salt (32 bytes)
[49-72] Nonce (24 bytes)
[73-76] Rotation tag: "RTM1" (4 bytes)
[77-84] created_at_nanos (u64 LE, unix nanos)
[85-92] last_rotated_at_nanos (u64 LE, unix nanos)
[93-..] Ciphertext + Tag (XChaCha20-Poly1305)
```

**Integrity note:** the header fields (including timestamps) are authenticated as AEAD associated data (AAD). Editing them will cause decryption to fail.

---

## Configuration

Add to the `[service]` section:

```toml
[service]
passphrase_rotation_enabled = true
passphrase_rotation_warn_days = 60
passphrase_rotation_error_days = 90
```

Environment overrides:

```bash
export IGRA_SERVICE__PASSPHRASE_ROTATION_ENABLED=false
export IGRA_SERVICE__PASSPHRASE_ROTATION_WARN_DAYS=30
export IGRA_SERVICE__PASSPHRASE_ROTATION_ERROR_DAYS=60
```

Defaults by network mode:

- **Mainnet:** enabled, warn=60, error=90
- **Testnet:** enabled, warn=90, error=0 (warn-only)
- **Devnet:** disabled (no checks)

---

## Validation Behavior

Validation runs during startup security checks:

- If `service.use_encrypted_secrets=false`: no passphrase rotation checks.
- If `passphrase_rotation_enabled=false`: checks are skipped (mainnet emits a warning).
- If `age_days >= warn_days`: validation adds a warning.
- If `error_days > 0` and `age_days >= error_days`:
  - **Mainnet:** validation adds an error (startup blocked).
  - **Testnet:** validation adds a warning (startup continues).

---

## Tooling

### Create a New `secrets.bin`

```bash
secrets-admin --path /var/lib/igra/secrets.bin init
```

Passphrase resolution:
- Uses `--passphrase` if provided
- Else uses `IGRA_SECRETS_PASSPHRASE` if set
- Else prompts (hidden input)

### Rotate Passphrase (Re-encrypt In Place)

```bash
secrets-admin rotate-passphrase \
  --secrets-file /var/lib/igra/secrets.bin \
  --old-passphrase-file /secure/old-pass.txt \
  --new-passphrase-file /secure/new-pass.txt
```

If `--old-passphrase*` flags are omitted, the tool falls back to `IGRA_SECRETS_PASSPHRASE` or prompts.  
If `--new-passphrase*` flags are omitted, the tool prompts twice (hidden input + confirmation).

---

## Operational Procedures

### Single-Signer Rotation (Planned)

1. Generate a new passphrase (password manager preferred).
2. Backup `secrets.bin` (encrypted backups still require access control).
3. Stop the signer/service.
4. Rotate passphrase with `secrets-admin rotate-passphrase`.
5. Update `IGRA_SECRETS_PASSPHRASE` for the service (e.g. systemd environment file).
6. Start the signer/service and verify readiness.

Readiness and metrics endpoints require RPC auth if configured (token can be sent via `x-api-key` or `Authorization: Bearer ...`):

```bash
curl -H "x-api-key: $TOKEN" http://127.0.0.1:8088/ready
curl -H "x-api-key: $TOKEN" http://127.0.0.1:8088/metrics | rg passphrase_
```

### Multi-Signer Rolling Rotation (Zero-Downtime)

For an M-of-N threshold, keep at least M signers online at all times.

- Rotate one signer at a time: stop signer → rotate → update env → start signer → verify readiness → proceed.
- Never take more than `(N - M)` signers offline simultaneously.

---

## Monitoring (Prometheus)

Exposed metrics (via `/metrics`):

- `passphrase_rotation_enabled` (0/1)
- `passphrase_age_days`
- `passphrase_rotation_warn_threshold_days`
- `passphrase_rotation_error_threshold_days`
- `passphrase_created_at_unix_seconds`
- `passphrase_last_rotated_at_unix_seconds`

Example alerts:

```yaml
- alert: PassphraseRotationDueSoon
  expr: passphrase_age_days >= passphrase_rotation_warn_threshold_days
  for: 24h
  labels:
    severity: warning

- alert: PassphraseRotationBlockingSoon
  expr: passphrase_rotation_error_threshold_days > 0 and passphrase_age_days >= (passphrase_rotation_error_threshold_days - 5)
  for: 1h
  labels:
    severity: critical
```

---

## Notes / Gotchas

- This is an incompatible `secrets.bin` format change while keeping `Version: 1`. Old files (without the `RTM1` tag) must be recreated.
- Passphrase prompts use hidden input (no terminal echo).
