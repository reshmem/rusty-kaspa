# Igra Security Quick Check

**Print this page and check off items before each deployment**

---

## Pre-Deployment Security Checklist ✓

### Configuration File (`config.toml`)

```bash
# Verify configuration
cat /var/lib/igra/config.toml
```

- [ ] `network = "mainnet"` explicitly set (for production)
- [ ] `use_encrypted_secrets = true`
- [ ] `node_url = "grpc://127.0.0.1:16110"` (local RPC)
- [ ] `threshold_m >= 2` (multi-signature required)
- [ ] `key_audit.enabled = true`
- [ ] `key_audit.log_path` configured
- [ ] `logging.level = "info"` (not debug/trace)

---

### File Permissions (Unix/Linux)

```bash
# Check permissions
ls -la /var/lib/igra/
ls -la /var/lib/igra/secrets.bin
ls -la /var/lib/igra/config.toml
```

- [ ] Data directory: `drwx------` (0700)
- [ ] Config file: `-rw-------` (0600)
- [ ] Secrets file: `-rw-------` (0600)
- [ ] Audit log: `-rw-------` (0600)

**Fix permissions if needed:**
```bash
chmod 700 /var/lib/igra/
chmod 600 /var/lib/igra/config.toml
chmod 600 /var/lib/igra/secrets.bin
chmod 600 /var/log/igra/key-audit.log
```

---

### Environment Variables

```bash
# Check environment
env | grep -i igra
env | grep -i kaspa
```

- [ ] `IGRA_SECRETS_PASSPHRASE` set (for production startup)
- [ ] `KASPA_IGRA_LOG_DIR` set (for mainnet)
- [ ] `RUST_LOG="info"` or similar (not debug/trace)
- [ ] **NOT SET**: `KASPA_IGRA_WALLET_SECRET` (forbidden in mainnet)
- [ ] **NOT SET**: `IGRA_SECRET__*` env vars (use encrypted file instead)

---

### System Resources

```bash
# Check system resources
df -h /var/lib/igra          # Disk space
free -h                       # Memory
ulimit -n                     # File descriptors
ulimit -c                     # Core dumps
whoami                        # User
```

- [ ] Disk space: ≥ 10 GB available
- [ ] Memory: ≥ 1 GB available
- [ ] File descriptors: ≥ 4096 (`ulimit -n`)
- [ ] Core dumps: Disabled (`ulimit -c` = 0)
- [ ] Service user: **NOT** root

---

### Kaspa Node

```bash
# Check Kaspa node
ps aux | grep kaspad
netstat -tlnp | grep 16110
```

- [ ] Local `kaspad` process running
- [ ] Listening on `127.0.0.1:16110`
- [ ] Node is synced (verify with `kaspad --help` or RPC call)
- [ ] Network matches Igra config (mainnet/testnet/devnet)

---

### Secrets Management

```bash
# Verify secrets file
ls -la /var/lib/igra/secrets.bin
file /var/lib/igra/secrets.bin
```

- [ ] Secrets file exists
- [ ] File is encrypted (not plain JSON)
- [ ] Passphrase is strong (≥16 chars, mixed case, numbers, symbols)
- [ ] Passphrase stored securely (password manager, KMS, HSM)
- [ ] Test mnemonic NOT used ("abandon abandon abandon...")
- [ ] Backup of secrets taken and stored securely

---

### Validation Test

```bash
# Run validation
kaspa-threshold-service --config /var/lib/igra/config.toml --validate-only
```

- [ ] Validation passes with no errors
- [ ] Output shows: `✓ Using local Kaspa RPC endpoint`
- [ ] Output shows: `✅ NO ERRORS - Configuration is valid`

**If validation fails:**
1. Read error messages carefully
2. Fix issues in config file
3. Check file permissions
4. Verify Kaspa node connectivity
5. Re-run `--validate-only`

---

### Code Audit (Developer Checklist)

```bash
# Run automated security audit
./security-audit.sh
```

- [ ] No secrets in log statements
- [ ] No hardcoded keys or mnemonics
- [ ] No `unwrap()`/`expect()` in key management code
- [ ] NetworkMode enforcement present
- [ ] File permission validation implemented
- [ ] Audit logging implemented
- [ ] Security tests pass: `cargo test -p igra-core network_mode_security`

---

### Logging

```bash
# Check log configuration
echo $KASPA_IGRA_LOG_DIR
ls -la $KASPA_IGRA_LOG_DIR
```

- [ ] Log directory exists and is writable
- [ ] Log rotation configured (size or time-based)
- [ ] Audit log file is `0600` permissions
- [ ] No secrets visible in recent logs: `tail -100 $KASPA_IGRA_LOG_DIR/igra.log`

---

### Monitoring Setup

- [ ] Audit log monitoring configured (alerts on `sign_failure`)
- [ ] Disk space monitoring
- [ ] Memory monitoring
- [ ] Kaspa node health monitoring
- [ ] Service uptime monitoring (systemd, Docker health checks, etc.)

---

## Quick Commands Reference

### Validate Configuration
```bash
kaspa-threshold-service --config /var/lib/igra/config.toml --validate-only
```

### Start Service
```bash
# With systemd
systemctl start igra-threshold-service
systemctl status igra-threshold-service

# Or directly
kaspa-threshold-service --config /var/lib/igra/config.toml
```

### Monitor Logs
```bash
# Service logs
journalctl -u igra-threshold-service -f

# Audit logs
tail -f /var/log/igra/key-audit.log

# Filter for errors
journalctl -u igra-threshold-service -p err
```

### Check Recent Signing Operations
```bash
# Last 10 sign requests
grep "sign_request" /var/log/igra/key-audit.log | tail -10

# Count today's operations
grep "$(date +%Y-%m-%d)" /var/log/igra/key-audit.log | wc -l

# Find failures
grep "sign_failure" /var/log/igra/key-audit.log
```

### Emergency Stop
```bash
# Stop service immediately
systemctl stop igra-threshold-service

# Or kill process
pkill -9 kaspa-threshold-service
```

---

## Network Mode Quick Reference

| Mode | Config | Use Case | Validation |
|------|--------|----------|------------|
| **mainnet** | `network = "mainnet"` | Production with real funds | ❌ Errors block startup |
| **testnet** | `network = "testnet"` | Pre-production testing | ⚠️ Warnings only |
| **devnet** | `network = "devnet"` | Local development | ℹ️ Minimal checks |

**Default:** `mainnet` (safe by default)

---

## Red Flags - Stop Immediately If:

- ⛔ `secrets.bin` has permissions `0644` or higher (world/group readable)
- ⛔ `KASPA_IGRA_WALLET_SECRET` env var is set (legacy, insecure)
- ⛔ Config has `use_encrypted_secrets = false` in mainnet
- ⛔ RPC endpoint is remote without `--allow-remote-rpc` flag
- ⛔ Service running as root
- ⛔ Core dumps enabled (`ulimit -c` != 0)
- ⛔ Log level is `debug` or `trace` in mainnet
- ⛔ Test mnemonic in use ("abandon abandon abandon...")

---

## Incident Response - If Compromised

1. **IMMEDIATELY STOP SERVICE**
   ```bash
   systemctl stop igra-threshold-service
   ```

2. **Review audit logs**
   ```bash
   grep "sign_request" /var/log/igra/key-audit.log | tail -100
   grep "sign_failure" /var/log/igra/key-audit.log
   ```

3. **Check file access**
   ```bash
   # Check who accessed secrets file
   ls -la /var/lib/igra/secrets.bin
   stat /var/lib/igra/secrets.bin
   ```

4. **Review system logs**
   ```bash
   journalctl -u igra-threshold-service --since "1 hour ago"
   ```

5. **If secrets compromised:**
   - Generate new keys immediately
   - Update multisig group configuration
   - Rotate all validator keys
   - Notify other multisig participants

6. **Document incident**
   - What happened
   - When detected
   - What data exposed
   - Actions taken

---

## Support & References

- **Full Guidelines**: See `CODE-GUIDELINE.md` Section 8 (Security Guidelines)
- **Key Management Audit**: See `docs/security/key-management-extended-audit.md`
- **Network Mode Security**: See `docs/config/network-modes.md`
- **Automated Audit Script**: Run `./security-audit.sh`

---

**Last Updated**: 2026-01-24
**Version**: 1.0
