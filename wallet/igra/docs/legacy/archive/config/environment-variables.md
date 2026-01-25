# Environment Variables Reference

**Version:** 0.5.0
**Last Updated:** 2026-01-24

---

## Overview

Igra supports environment variable overrides for all TOML configuration parameters, plus special variables for runtime control and secret management.

**Benefits:**
- Override config without editing files
- Per-environment deployment (dev/staging/prod)
- Docker/Kubernetes friendly
- CI/CD integration

---

## Configuration Override Pattern

### Format

```
IGRA_<SECTION>__<SUBSECTION>__<PARAMETER>=<value>
```

**Rules:**
- Prefix: `IGRA_`
- Separator: `__` (double underscore)
- Casing: UPPERCASE with underscores
- Nested: Each level separated by `__`

---

### Examples

```bash
# service.node_rpc_url
export IGRA_SERVICE__NODE_RPC_URL="grpc://10.0.0.1:16110"

# service.pskt.sig_op_count
export IGRA_SERVICE__PSKT__SIG_OP_COUNT=3

# service.hd.required_sigs
export IGRA_SERVICE__HD__REQUIRED_SIGS=2

# runtime.session_timeout_seconds
export IGRA_RUNTIME__SESSION_TIMEOUT_SECONDS=120

# rpc.enabled
export IGRA_RPC__ENABLED=true

# rpc.addr
export IGRA_RPC__ADDR="0.0.0.0:8088"

# iroh.network_id
export IGRA_IROH__NETWORK_ID=1

# iroh.discovery.enable_pkarr
export IGRA_IROH__DISCOVERY__ENABLE_PKARR=true

# iroh.relay.enable
export IGRA_IROH__RELAY__ENABLE=true

# hyperlane.poll_secs
export IGRA_HYPERLANE__POLL_SECS=10

# group.threshold_m
export IGRA_GROUP__THRESHOLD_M=2

# group.threshold_n
export IGRA_GROUP__THRESHOLD_N=3
```

---

## Secret Management Variables

### IGRA_SECRETS_PASSPHRASE

**Purpose:** Decrypt `secrets.bin` file (FileSecretStore)

**Required:**
- **Mainnet:** YES (error if missing when `use_encrypted_secrets=true`)
- **Testnet:** Recommended (warns if missing)
- **Devnet:** Optional (can prompt interactively)

**Security:**
- ⚠️ Passphrase is sensitive (protects all signing keys)
- ✅ Better than storing keys directly in env
- ✅ Mainnet forbids interactive prompts (must be env var)

**Example:**
```bash
export IGRA_SECRETS_PASSPHRASE="my-secure-passphrase-min-20-chars"
```

**Best practice:**
- Use password manager or secrets management system
- Minimum 20 characters
- Never commit to git
- Rotate periodically

---

### IGRA_SECRET__* (EnvSecretStore)

**Purpose:** Provide secrets via environment variables (devnet/test only)

**Format:**
```bash
IGRA_SECRET__<namespace>__<name>=<encoding>:<value>
```

**Encoding:**
- `hex:` - Hex-encoded bytes
- `b64:` or `base64:` - Base64-encoded bytes
- No prefix - Plain UTF-8 string

**Examples:**
```bash
# NOTE: EnvSecretStore is intended for devnet/CI only.
# Profile suffix uses `_` because shell env vars cannot contain `-`.
# Example: profile `signer-01` → suffix `signer_01`.

# Signer mnemonic (dev/test only; mainnet forbids mnemonic-based signing)
export IGRA_SECRET__igra_signer__mnemonic_signer_01="abandon abandon abandon ... (24 words)"

# Signer payment secret (optional BIP39 passphrase / "25th word")
export IGRA_SECRET__igra_signer__payment_secret_signer_01="my-25th-word"

# Iroh signer seed (profile-specific, 32 bytes)
export IGRA_SECRET__igra_iroh__signer_seed_signer_01="hex:abcdef..."

# Raw private key (profile-specific, when service.hd.key_type=raw_private_key)
export IGRA_SECRET__igra_signer__private_key_signer_01="hex:deadbeef..."
```

**Validation:**
- **Mainnet:** EnvSecretStore is not supported (mainnet requires `service.use_encrypted_secrets=true`)
- **Testnet:** Discouraged (warning)
- **Devnet:** Allowed

**Security:** ⭐⭐ (visible in process list, devnet only)

**Where used:**
- `igra-core/src/infrastructure/keys/backends/env_secret_store.rs` - Environment-based secret loading

---

### KASPA_IGRA_WALLET_SECRET (Legacy - Removed)

**Purpose:** Legacy HD wallet secret (no longer used)

**Status:** Setting this variable has no effect on key loading. It is kept only for configuration validation warnings/errors.

**Validation:**
- **Mainnet:** FORBIDDEN (error if set)
- **Testnet:** Discouraged (warning)
- **Devnet:** Allowed (for backward compatibility)

**Migration:**
- Remove the environment variable.
- Use FileSecretStore (`secrets.bin`) + `IGRA_SECRETS_PASSPHRASE`.

**Status:** ⚠️ **DEPRECATED** - Will be removed in future version

---

## Special Variables

### KASPA_CONFIG_PATH

**Purpose:** Override config file path

**Default:** `${KASPA_DATA_DIR}/igra-config.toml` or `./igra-config.toml`

**Example:**
```bash
export KASPA_CONFIG_PATH="/etc/igra/config.toml"
kaspa-threshold-service  # Uses /etc/igra/config.toml
```

---

### KASPA_DATA_DIR

**Purpose:** Override data directory

**Default:** `./.igra` in current working directory

**Example:**
```bash
export KASPA_DATA_DIR="/var/lib/igra"
kaspa-threshold-service  # Uses /var/lib/igra
```

**Note:** Also accessible via `IGRA_SERVICE__DATA_DIR` (new style)

---

### KASPA_IGRA_PROFILE (Removed)

This environment variable is no longer supported.

**Replacement (explicit):**
- CLI: `kaspa-threshold-service --profile signer-01 ...`
- Config: `service.active_profile = "signer-01"` (or env override `IGRA_SERVICE__ACTIVE_PROFILE=signer-01`)

---

### KASPA_IGRA_LOG_DIR

**Purpose:** Log directory (required for mainnet)

**Validation:**
- **Mainnet:** MUST be set (error if missing)
- **Testnet:** Recommended
- **Devnet:** Optional

**Example:**
```bash
export KASPA_IGRA_LOG_DIR="/var/log/igra"
```

**Directory must exist and be writable:**
```bash
sudo mkdir -p /var/log/igra
sudo chown igra-service:igra-service /var/log/igra
sudo chmod 750 /var/log/igra
```

---

### KASPA_IGRA_NETWORK

**Purpose:** Network mode detection (legacy compatibility)

**Values:** `mainnet`, `testnet`, `devnet`

**Note:** Prefer `--network` CLI flag over env var

**Example:**
```bash
export KASPA_IGRA_NETWORK="mainnet"
kaspa-threshold-service  # Detects mainnet mode
```

---

## Testing Variables

**These variables should NEVER be set in production:**

### KASPA_IGRA_TEST_NOW_NANOS

**Purpose:** Override wall clock for testing (deterministic timestamps)

**Example:**
```bash
export KASPA_IGRA_TEST_NOW_NANOS="1706112345000000000"
```

**Where used:**
- `igra-core/src/foundation/time.rs:15` - Clock override

**Validation:** Only works in test builds or devnet

---

### KASPA_FINALIZE_PSKT_JSON

**Purpose:** Path to PSKT JSON file for finalize mode

**Usage:**
```bash
export KASPA_FINALIZE_PSKT_JSON="/tmp/pskt.json"
kaspa-threshold-service --finalize /tmp/pskt.json
```

**See:** Finalize mode documentation (advanced operations)

---

### KASPA_AUDIT_REQUEST_ID

**Purpose:** Request ID for audit trail dump

**Usage:**
```bash
export KASPA_AUDIT_REQUEST_ID="req_abc123"
kaspa-threshold-service --audit req_abc123
```

---

## Complete Variable List

### Service Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_SERVICE__NETWORK` | `service.network` | `mainnet` |
| `IGRA_SERVICE__ALLOW_REMOTE_RPC` | `service.allow_remote_rpc` | `true` |
| `IGRA_SERVICE__NODE_RPC_URL` | `service.node_rpc_url` | `grpc://127.0.0.1:16110` |
| `IGRA_SERVICE__DATA_DIR` | `service.data_dir` | `/var/lib/igra` |
| `IGRA_SERVICE__ALLOW_SCHEMA_WIPE` | `service.allow_schema_wipe` | `false` |
| `IGRA_SERVICE__USE_ENCRYPTED_SECRETS` | `service.use_encrypted_secrets` | `true` |
| `IGRA_SERVICE__SECRETS_FILE` | `service.secrets_file` | `/etc/igra/secrets.bin` |
| `IGRA_SERVICE__KEY_AUDIT_LOG_PATH` | `service.key_audit_log_path` | `/var/log/igra/audit.log` |
| `IGRA_SERVICE__PASSPHRASE_ROTATION_ENABLED` | `service.passphrase_rotation_enabled` | `true` |
| `IGRA_SERVICE__PASSPHRASE_ROTATION_WARN_DAYS` | `service.passphrase_rotation_warn_days` | `60` |
| `IGRA_SERVICE__PASSPHRASE_ROTATION_ERROR_DAYS` | `service.passphrase_rotation_error_days` | `90` |

### PSKT Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_SERVICE__PSKT__NODE_RPC_URL` | `service.pskt.node_rpc_url` | `grpc://10.0.0.1:16110` |
| `IGRA_SERVICE__PSKT__SIG_OP_COUNT` | `service.pskt.sig_op_count` | `3` |
| `IGRA_SERVICE__PSKT__FEE_SOMPI` | `service.pskt.fee_sompi` | `1000` |

**Note:** Arrays (e.g., `source_addresses`) cannot be set via env vars - use TOML

### HD Wallet Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_SERVICE__HD__REQUIRED_SIGS` | `service.hd.required_sigs` | `2` |
| `IGRA_SERVICE__HD__DERIVATION_PATH` | `service.hd.derivation_path` | `m/44'/111111'/0'/0/0` |

### Runtime Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_RUNTIME__SESSION_TIMEOUT_SECONDS` | `runtime.session_timeout_seconds` | `120` |
| `IGRA_RUNTIME__SESSION_EXPIRY_SECONDS` | `runtime.session_expiry_seconds` | `600` |
| `IGRA_RUNTIME__TEST_MODE` | `runtime.test_mode` | `true` |

### RPC Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_RPC__ADDR` | `rpc.addr` | `0.0.0.0:8088` |
| `IGRA_RPC__ENABLED` | `rpc.enabled` | `true` |
| `IGRA_RPC__TOKEN` | `rpc.token` | `bearer-token-here` |
| `IGRA_RPC__RATE_LIMIT_RPS` | `rpc.rate_limit_rps` | `100` |
| `IGRA_RPC__RATE_LIMIT_BURST` | `rpc.rate_limit_burst` | `200` |

### Iroh Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_IROH__PEER_ID` | `iroh.peer_id` | `peer-abc123` |
| `IGRA_IROH__GROUP_ID` | `iroh.group_id` | `0x1234...` |
| `IGRA_IROH__NETWORK_ID` | `iroh.network_id` | `1` |
| `IGRA_IROH__BIND_PORT` | `iroh.bind_port` | `11205` |
| `IGRA_IROH__DISCOVERY__ENABLE_PKARR` | `iroh.discovery.enable_pkarr` | `true` |
| `IGRA_IROH__DISCOVERY__ENABLE_DNS` | `iroh.discovery.enable_dns` | `true` |
| `IGRA_IROH__DISCOVERY__DNS_DOMAIN` | `iroh.discovery.dns_domain` | `discovery.example.com` |
| `IGRA_IROH__RELAY__ENABLE` | `iroh.relay.enable` | `true` |
| `IGRA_IROH__RELAY__CUSTOM_URL` | `iroh.relay.custom_url` | `https://relay.example.com` |

### Hyperlane Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_HYPERLANE__POLL_SECS` | `hyperlane.poll_secs` | `5` |
| `IGRA_HYPERLANE__THRESHOLD` | `hyperlane.threshold` | `2` |

### Group Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_GROUP__THRESHOLD_M` | `group.threshold_m` | `2` |
| `IGRA_GROUP__THRESHOLD_N` | `group.threshold_n` | `3` |
| `IGRA_GROUP__SESSION_TIMEOUT_SECONDS` | `group.session_timeout_seconds` | `300` |

### Two-Phase Configuration

| Variable | Maps to TOML | Example |
|----------|-------------|---------|
| `IGRA_TWO_PHASE__PROPOSAL_TIMEOUT_MS` | `two_phase.proposal_timeout_ms` | `10000` |
| `IGRA_TWO_PHASE__COMMIT_QUORUM` | `two_phase.commit_quorum` | `2` |

---

## Secret Storage Variables

### IGRA_SECRETS_PASSPHRASE

**Purpose:** Passphrase for decrypting `secrets.bin`

**Required:** Yes (when `use_encrypted_secrets=true` in mainnet)

**Security:** ⭐⭐⭐⭐ High-sensitivity (protects all secrets)

**Example:**
```bash
export IGRA_SECRETS_PASSPHRASE="my-very-secure-passphrase-min-20-chars"
```

**Best practices:**
- Minimum 20 characters
- Use password manager or secrets vault
- Never log or commit to git
- Rotate periodically
- Different per environment (dev/staging/prod)

---

### IGRA_SECRET__* (EnvSecretStore)

**Purpose:** Provide secrets directly via environment (devnet/test only)

**Format:**
```
IGRA_SECRET__<namespace>__<name>=<encoding>:<value>
```

**Encodings:**
- `hex:...` - Hex-decoded to bytes
- `b64:...` or `base64:...` - Base64-decoded to bytes
- No prefix - UTF-8 string bytes

**Common secrets:**

```bash
# Signer mnemonic (dev/test only; mainnet forbids mnemonic-based signing)
export IGRA_SECRET__igra_signer__mnemonic_signer_01="abandon abandon abandon ... (24 words)"

# Signer payment secret (optional BIP39 passphrase / "25th word", per signer)
export IGRA_SECRET__igra_signer__payment_secret_signer_01="my-passphrase"

# Iroh signer seed (per-profile, 32 bytes)
export IGRA_SECRET__igra_iroh__signer_seed_signer_01="hex:abcdef..."
export IGRA_SECRET__igra_iroh__signer_seed_signer_02="hex:123456..."

# Raw private key (per-profile, when hd.key_type=raw_private_key)
export IGRA_SECRET__igra_signer__private_key_signer_01="hex:deadbeef..."
export IGRA_SECRET__igra_signer__private_key_signer_02="hex:cafebabe..."

# Hyperlane validator keys (EVM-compatible secp256k1)
export IGRA_SECRET__igra_hyperlane__validator_1_key="hex:..."
export IGRA_SECRET__igra_hyperlane__validator_2_key="hex:..."

# Hyperlane EVM key (devnet only)
export IGRA_SECRET__igra_hyperlane__evm_key="hex:ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Devnet wallet key (devnet only; funds used for mining / test payments)
export IGRA_SECRET__igra_devnet__wallet_private_key="hex:..."
```

**Validation:**
- **Mainnet:** EnvSecretStore is not supported (mainnet requires `service.use_encrypted_secrets=true`)
- **Testnet:** Discouraged with warning
- **Devnet:** Allowed

**Security:** ⭐⭐ Low (visible via `ps auxe`, acceptable for devnet only)

---

## System Variables

### KASPA_CONFIG_PATH

**Purpose:** Config file path override

**Default:** `${KASPA_DATA_DIR}/igra-config.toml` or `./igra-config.toml`

**Example:**
```bash
export KASPA_CONFIG_PATH="/etc/igra/config.toml"
```

---

### KASPA_DATA_DIR

**Purpose:** Data directory override

**Default:** `./.igra`

**Example:**
```bash
export KASPA_DATA_DIR="/var/lib/igra"
```

**Note:** Can also use `IGRA_SERVICE__DATA_DIR` (new style)

---

### KASPA_IGRA_LOG_DIR

**Purpose:** Log directory (mainnet required)

**Validation:**
- **Mainnet:** Required (error if missing)
- **Testnet:** Recommended
- **Devnet:** Optional

**Example:**
```bash
export KASPA_IGRA_LOG_DIR="/var/log/igra"
```

**Log files created:**
- Service logs (if log4rs configured)
- Not the same as `key_audit_log_path` (key operations)

---

## Testing & Debug Variables

**⚠️ NEVER SET IN PRODUCTION**

### KASPA_IGRA_TEST_NOW_NANOS

**Purpose:** Override system clock for deterministic testing

**Example:**
```bash
export KASPA_IGRA_TEST_NOW_NANOS="1706112345000000000"
```

**Where used:**
- `igra-core/src/foundation/time.rs:15` - Clock override for tests

---

### KASPA_FINALIZE_PSKT_JSON

**Purpose:** Path to PSKT JSON for finalize mode

**Example:**
```bash
export KASPA_FINALIZE_PSKT_JSON="/tmp/pskt.json"
kaspa-threshold-service --finalize /tmp/pskt.json
```

---

### KASPA_AUDIT_REQUEST_ID

**Purpose:** Request ID for audit trail dump

**Example:**
```bash
export KASPA_AUDIT_REQUEST_ID="req_abc123"
kaspa-threshold-service --audit req_abc123
```

---

## Docker/Kubernetes Examples

### Docker Compose

```yaml
version: '3.8'

services:
  igra-signer-1:
    image: igra:latest
    environment:
      # Service config
      - IGRA_SERVICE__NODE_RPC_URL=grpc://kaspad:16110
      - IGRA_SERVICE__DATA_DIR=/data
      - IGRA_SERVICE__USE_ENCRYPTED_SECRETS=true

      # Secrets (use Docker secrets in production)
      - IGRA_SECRETS_PASSPHRASE_FILE=/run/secrets/igra_passphrase

      # Iroh
      - IGRA_IROH__BIND_PORT=11205
      - IGRA_IROH__DISCOVERY__ENABLE_PKARR=true
      - IGRA_IROH__RELAY__ENABLE=true

      # RPC
      - IGRA_RPC__ENABLED=true
      - IGRA_RPC__ADDR=0.0.0.0:8088

      # Profile
      - IGRA_SERVICE__ACTIVE_PROFILE=signer-01

    volumes:
      - igra-data-1:/data
      - ./secrets.bin:/data/secrets.bin:ro

    secrets:
      - igra_passphrase

secrets:
  igra_passphrase:
    file: ./secrets/passphrase.txt
```

---

### Kubernetes ConfigMap + Secret

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: igra-config
data:
  IGRA_SERVICE__NODE_RPC_URL: "grpc://kaspad.default.svc.cluster.local:16110"
  IGRA_SERVICE__DATA_DIR: "/data"
  IGRA_RPC__ENABLED: "true"
  IGRA_RPC__ADDR: "0.0.0.0:8088"
  IGRA_IROH__DISCOVERY__ENABLE_PKARR: "true"
  IGRA_SERVICE__ACTIVE_PROFILE: "signer-01"

---

apiVersion: v1
kind: Secret
metadata:
  name: igra-secrets
type: Opaque
stringData:
  IGRA_SECRETS_PASSPHRASE: "my-secure-passphrase"

---

apiVersion: apps/v1
kind: Deployment
metadata:
  name: igra-signer-1
spec:
  template:
    spec:
      containers:
      - name: igra
        image: igra:latest
        envFrom:
        - configMapRef:
            name: igra-config
        - secretRef:
            name: igra-secrets
```

---

## Systemd Unit File Example

```ini
[Unit]
Description=Igra Threshold Signing Service
After=network.target kaspad.service

[Service]
Type=simple
User=igra-service
Group=igra-service
WorkingDirectory=/var/lib/igra

# Environment variables
Environment="IGRA_SERVICE__DATA_DIR=/var/lib/igra"
Environment="IGRA_SERVICE__USE_ENCRYPTED_SECRETS=true"
Environment="KASPA_IGRA_LOG_DIR=/var/log/igra"
Environment="IGRA_SERVICE__ACTIVE_PROFILE=signer-01"
EnvironmentFile=/etc/igra/environment

# Load secrets passphrase from file
EnvironmentFile=/etc/igra/secrets.env

ExecStart=/usr/local/bin/kaspa-threshold-service \
    --network mainnet \
    --config /etc/igra/config.toml

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**File:** `/etc/igra/secrets.env`
```bash
IGRA_SECRETS_PASSPHRASE=my-secure-passphrase
```

**Permissions:**
```bash
sudo chmod 600 /etc/igra/secrets.env
sudo chown igra-service:igra-service /etc/igra/secrets.env
```

---

## Best Practices

### 1. Never Hardcode Secrets in Config Files

**❌ BAD:**
```toml
[service]
api_token = "hardcoded-token-in-git"  # Will be committed!
```

**✅ GOOD:**
```bash
export IGRA_RPC__TOKEN="secret-token-from-vault"
```

Or use FileSecretStore for all secrets.

---

### 2. Use Encrypted Secrets for Production

**❌ BAD (devnet only):**
```bash
export IGRA_SECRET__igra_signer__mnemonic_signer_01="abandon abandon abandon ... (24 words)"
```

**✅ GOOD (mainnet):**
```bash
# Secrets in encrypted file
export IGRA_SECRETS_PASSPHRASE="from-password-manager"
# secrets.bin contains actual keys
```

---

### 3. Different Passphrases Per Environment

```bash
# Development
export IGRA_SECRETS_PASSPHRASE="dev-passphrase"

# Staging
export IGRA_SECRETS_PASSPHRASE="staging-passphrase"

# Production
export IGRA_SECRETS_PASSPHRASE="prod-passphrase-from-vault"
```

---

### 4. Use Secrets Management Systems

**AWS Secrets Manager:**
```bash
export IGRA_SECRETS_PASSPHRASE=$(aws secretsmanager get-secret-value \
  --secret-id igra/mainnet/passphrase \
  --query SecretString \
  --output text)
```

**HashiCorp Vault:**
```bash
export IGRA_SECRETS_PASSPHRASE=$(vault kv get -field=passphrase secret/igra/mainnet)
```

**Kubernetes Secrets:**
```yaml
envFrom:
- secretRef:
    name: igra-secrets  # Contains IGRA_SECRETS_PASSPHRASE
```

---

## Environment Variable Precedence

**Highest precedence wins:**

```
1. Command-line flags (e.g., --network mainnet)
   ↓
2. Environment variables (IGRA_*)
   ↓
3. Profile overrides ([profiles.<name>])
   ↓
4. TOML config file
   ↓
5. Compiled defaults (lowest)
```

**Example:**
```bash
# Config file has:
[service]
node_rpc_url = "grpc://127.0.0.1:16110"

# Environment override:
export IGRA_SERVICE__NODE_RPC_URL="grpc://10.0.0.1:16110"

# Result: Uses 10.0.0.1:16110 (env var wins)
```

---

## Debugging Configuration

### Print Effective Configuration

```bash
# Validate and show parsed config
kaspa-threshold-service --network devnet --config config.toml --validate-only

# Logs will show:
# [INFO] config loaded rpc_enabled=true network_id=10 ...
```

---

### Check Environment Variables

```bash
# List all IGRA_* variables
env | grep IGRA_

# Check specific variable
echo $IGRA_SERVICE__NODE_RPC_URL
```

---

### Verify Secrets

```bash
# Check secrets file exists and is readable
ls -la /var/lib/igra/secrets.bin

# Check passphrase is set
echo ${IGRA_SECRETS_PASSPHRASE:+SET} ${IGRA_SECRETS_PASSPHRASE:-NOT_SET}
# Outputs: SET (doesn't print actual value)
```

---

## Related Documentation

- [service-config.md](service-config.md) - Service parameter details
- [secrets-config.md](secrets-config.md) - Secret management guide
- [network-modes.md](network-modes.md) - Security validation
- [examples.md](examples.md) - Complete configuration examples

---

**Quick Reference:** See [config.md](config.md) for all parameters
