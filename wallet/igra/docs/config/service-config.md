# Service Configuration Reference (`[service]`)

**Version:** 0.5.0
**Last Updated:** 2026-01-24

---

## Overview

The `[service]` section contains core service settings including Kaspa RPC connectivity, data storage, and secret management.

**Location in config:** Top-level `[service]` section

**Related sections:**
- `[service.pskt]` - See [pskt-config.md](pskt-config.md)
- `[service.hd]` - See [hd-wallet-config.md](hd-wallet-config.md)

---

## Complete Parameter Reference

### service.network

**Type:** `String` (optional)
**Default:** `None`
**Environment:** `IGRA_SERVICE__NETWORK`
**Required:** No (but recommended for mainnet/testnet)

**Description:**
Network mode declaration for security validation. Must match `--network` CLI flag.

**Valid values:**
```toml
network = "mainnet"  # Production network
network = "testnet"  # Test network
network = "devnet"   # Development network
```

**Validation:**
- **Mainnet:** MUST be explicitly set to `"mainnet"` (error if missing or mismatch)
- **Testnet:** Recommended (warning if missing)
- **Devnet:** Optional

**Why this exists:**
Prevents accidental use of test configuration in production. Forces explicit network confirmation.

**Where used:**
- `igra-core/src/infrastructure/network_mode/rules/config.rs:5` - Network confirmation validation
- `igra-service/src/bin/kaspa-threshold-service.rs:33` - CLI mode matching

**Security:** ⭐⭐⭐⭐⭐ Critical for mainnet (prevents config drift)

**Example:**
```toml
[service]
network = "mainnet"  # Required for --network mainnet
```

---

### service.allow_remote_rpc

**Type:** `Boolean`
**Default:** `false`
**Environment:** `IGRA_SERVICE__ALLOW_REMOTE_RPC`
**CLI Flag:** `--allow-remote-rpc`

**Description:**
Explicitly allow remote Kaspa RPC endpoints in mainnet. This is a security validation flag only - it doesn't change RPC behavior, just allows validation to pass.

**Why this exists:**
Mainnet defaults to local-only RPC for security. Remote RPC endpoints can lie about UTXO state or track transactions. This flag forces explicit acknowledgment of risk.

**Validation:**
- **Mainnet:** If `node_rpc_url` is remote (not 127.0.0.1/localhost), this MUST be `true`
- **Testnet/Devnet:** Not enforced

**Where used:**
- `igra-core/src/infrastructure/network_mode/rules/rpc.rs:47` - RPC security validation

**Security:** ⭐⭐⭐⭐⭐ Prevents accidental remote RPC in production

**Example:**
```toml
[service]
node_rpc_url = "grpcs://token@remote-kaspad.example.com:16110"
allow_remote_rpc = true  # Explicit opt-in to risk
```

**Alternative (CLI flag):**
```bash
kaspa-threshold-service --network mainnet --allow-remote-rpc
```

---

### service.node_rpc_url

**Type:** `String`
**Default:** `"grpc://127.0.0.1:16110"`
**Environment:** `IGRA_SERVICE__NODE_RPC_URL`
**Required:** Yes

**Description:**
Kaspa node gRPC endpoint for UTXO queries and transaction submission.

**Format:**
```
<scheme>://[<user>:<pass>@]<host>:<port>
```

**Schemes:**
- `grpc://` - Unencrypted gRPC (local only in mainnet)
- `grpcs://` - TLS-encrypted gRPC (required for remote in mainnet)

**Validation:**
- **Mainnet:** Must be localhost (`127.0.0.1`, `localhost`, `::1`, `127.*`) unless `allow_remote_rpc=true`
- **Mainnet + Remote:** Must use `grpcs://` and include auth (`user:pass@`)
- **Testnet:** Warns if remote and unencrypted
- **Devnet:** No restrictions

**Why this exists:**
UTXO state comes from Kaspa node. Malicious/compromised node can lie about balances.

**Where used:**
- `igra-core/src/infrastructure/rpc/kaspa_grpc_client.rs:28` - gRPC client construction
- `igra-core/src/application/pskt_operations.rs:45` - UTXO queries
- `igra-service/src/service/flow.rs:89` - Transaction submission

**Performance:**
- Local: ~1-5ms latency
- Remote: ~50-200ms latency (network dependent)

**Security:** ⭐⭐⭐⭐⭐ Critical (trusted data source)

**Examples:**
```toml
[service]
# Local (recommended)
node_rpc_url = "grpc://127.0.0.1:16110"

# Local with TLS
node_rpc_url = "grpcs://localhost:16110"

# Remote with auth (requires allow_remote_rpc=true in mainnet)
node_rpc_url = "grpcs://mytoken@kaspad.example.com:16110"
```

---

### service.data_dir

**Type:** `String`
**Default:** From `KASPA_DATA_DIR` env var, or `"./.igra"` in current directory
**Environment:** `KASPA_DATA_DIR` or `IGRA_SERVICE__DATA_DIR`
**Required:** Yes

**Description:**
Data directory for all persistent storage (RocksDB, secrets, audit logs, Iroh identity).

**Directory contents:**
```
${data_dir}/
├── rocksdb/              # CRDT state, proposals, signatures
├── secrets.bin           # Encrypted secrets (if use_encrypted_secrets=true)
├── key-audit.log         # Key operation audit trail
└── iroh/
    └── identity.json     # Iroh peer identity and seed
```

**Validation:**
- **Mainnet:** Directory must exist before startup
- **Mainnet:** Must have 0700 permissions (owner-only, group/world no access)
- **Mainnet:** Must have ≥10 GB available disk space
- **Mainnet:** Path must not contain "devnet" or "test" (prevents config drift)
- **Testnet:** Warns on permission issues or low disk space
- **Devnet:** No restrictions

**Why this exists:**
Stores all state required for Byzantine-tolerant coordination (CRDT, proposals, signatures).

**Where used:**
- `igra-core/src/infrastructure/storage/rocks/engine.rs:45` - RocksDB path
- `igra-core/src/infrastructure/keys/backends/file_secret_store.rs:67` - Secrets file path
- `igra-service/src/bin/kaspa-threshold-service/setup.rs:310` - Identity path

**Disk usage:**
- Minimal: ~100 MB (RocksDB metadata + Iroh identity)
- Typical: 500 MB - 2 GB (depends on event volume and retention)
- With GC: Old CRDT states removed after 24 hours (configurable via `runtime.crdt_gc_ttl_seconds`)

**Backup:** Important - contains signing history and peer identity

**Example:**
```toml
[service]
# Development
data_dir = "./.igra-devnet"

# Production
data_dir = "/var/lib/igra"
```

**Permissions:**
```bash
# Mainnet requirement
sudo mkdir -p /var/lib/igra
sudo chown igra-service:igra-service /var/lib/igra
sudo chmod 700 /var/lib/igra
```

---

### service.allow_schema_wipe

**Type:** `Boolean`
**Default:** `false`
**Environment:** `IGRA_SERVICE__ALLOW_SCHEMA_WIPE`

**Description:**
**DEVNET-ONLY** escape hatch to automatically wipe RocksDB if schema version mismatches.

**Why this exists:**
During development, schema changes frequently. Manual database cleanup is tedious.

**Behavior:**
- If `true` and schema mismatch detected → Wipe RocksDB and start fresh
- If `false` and schema mismatch detected → Error and exit

**Validation:**
- **Mainnet:** Always `false` (cannot override, hardcoded check)
- **Testnet:** Always `false`
- **Devnet:** Can be `true`

**DANGER:**
- ❌ Destroys all event history
- ❌ Destroys all signature collection progress
- ❌ Destroys all proposal state
- ❌ Cannot recover data after wipe

**Where used:**
- `igra-core/src/infrastructure/storage/rocks/engine.rs:112` - Schema migration check

**Example (devnet only):**
```toml
[service]
allow_schema_wipe = true  # Convenient for rapid development
```

---

### service.use_encrypted_secrets

**Type:** `Boolean`
**Default:** `false`
**Environment:** `IGRA_SERVICE__USE_ENCRYPTED_SECRETS`

**Description:**
Use encrypted `secrets.bin` file (FileSecretStore) instead of environment variables (EnvSecretStore).

**Why this exists:**
Production systems should not store secrets in environment variables (visible via `ps auxe`, process dumps).

**Validation:**
- **Mainnet:** MUST be `true` (error if false)
- **Testnet:** Recommended (warns if false)
- **Devnet:** Optional

**When true:**
- Secrets stored in `${data_dir}/secrets.bin`
- Encrypted with XChaCha20-Poly1305 AEAD
- Key derived from `IGRA_SECRETS_PASSPHRASE` via Argon2id (64 MB, 3 iterations)
- File must have 0600 permissions (mainnet)

**When false:**
- Secrets loaded from environment variables
- Format: `IGRA_SECRET__<namespace>__<name>=<encoding>:<value>`
- Acceptable for devnet/CI only

**Where used:**
- `igra-service/src/bin/kaspa-threshold-service/setup.rs:75` - SecretStore selection

**Security:**
- FileSecretStore: ⭐⭐⭐⭐⭐ (encrypted at rest, access control)
- EnvSecretStore: ⭐⭐ (plaintext in process environment, devnet only)

**Example:**
```toml
[service]
use_encrypted_secrets = true  # Required for mainnet
```

**Setup:**
```bash
# Create encrypted secrets file
cargo run --bin secrets-admin -- --path secrets.bin init

# Set passphrase
export IGRA_SECRETS_PASSPHRASE="my-secure-passphrase"
```

**See:** [Secret Management Guide](secrets-config.md) for complete setup instructions.

---

### service.secrets_file

**Type:** `String` (optional)
**Default:** `"${data_dir}/secrets.bin"`
**Environment:** `IGRA_SERVICE__SECRETS_FILE`

**Description:**
Custom path to encrypted secrets file (overrides default location).

**Validation:**
- Must exist if `use_encrypted_secrets=true`
- **Mainnet:** Must have 0600 permissions
- **Testnet:** Warns on loose permissions

**Why this exists:**
Allows secrets file to be in different location from data directory (e.g., encrypted volume, HSM-backed storage).

**Where used:**
- `igra-core/src/infrastructure/network_mode/rules/secrets.rs:111` - Path resolution

**Example:**
```toml
[service]
use_encrypted_secrets = true
secrets_file = "/mnt/encrypted/igra-secrets.bin"
```

---

### service.passphrase_rotation_enabled

**Type:** `Boolean` (optional)  
**Default:** `true` (mainnet/testnet), `false` (devnet)  
**Environment:** `IGRA_SERVICE__PASSPHRASE_ROTATION_ENABLED`

Enable/disable passphrase rotation enforcement for encrypted secrets.

---

### service.passphrase_rotation_warn_days

**Type:** `u64` (optional)  
**Default:** `60` (mainnet), `90` (testnet), `0` (devnet)  
**Environment:** `IGRA_SERVICE__PASSPHRASE_ROTATION_WARN_DAYS`

Warn threshold for passphrase age.

---

### service.passphrase_rotation_error_days

**Type:** `u64` (optional)  
**Default:** `90` (mainnet), `0` (testnet/devnet)  
**Environment:** `IGRA_SERVICE__PASSPHRASE_ROTATION_ERROR_DAYS`

Error threshold for passphrase age. `0` disables “error” enforcement (warn-only).

---

### service.key_audit_log_path

**Type:** `String` (optional)
**Default:** `"${data_dir}/key-audit.log"`
**Environment:** `IGRA_SERVICE__KEY_AUDIT_LOG_PATH`

**Description:**
Path for key operation audit log (JSON lines format).

**Log format:**
```json
{"timestamp_nanos":1706112345678901234,"request_id":"req_a1b2c3","event":"SecretAccess","secret_name":"igra.signer.private_key_signer-01","operation":"Get","result":"Success"}
{"timestamp_nanos":1706112345678912345,"request_id":"req_a1b2c3","event":"Signing","key_ref":"igra.signer.private_key_signer-01","scheme":"schnorr","payload_size":32,"signature_size":64,"duration_ms":2}
```

**Events logged:**
- `SecretAccess` - Secret retrieved from store
- `SecretList` - Secrets enumerated
- `Signing` - Signature created (no secret value, just metadata)

**Validation:**
- **Mainnet:** Parent directory must exist
- **Mainnet:** File must have 0600 permissions (if exists)

**Why this exists:**
Forensic trail for all cryptographic operations. Required for compliance, incident response, and security audits.

**Where used:**
- `igra-core/src/infrastructure/keys/audit.rs:28` - Audit event writing
- `igra-service/src/bin/kaspa-threshold-service/modes/audit.rs:10` - Audit trail queries

**Retention:** Recommended minimum 90 days (compliance), configurable via log rotation

**Query audit trail:**
```bash
# Dump all events for specific request
kaspa-threshold-service --audit req_a1b2c3

# Filter by event type
grep '"event":"Signing"' /var/log/igra/key-audit.log | jq .

# Count secret accesses today
grep "$(date +%Y-%m-%d)" key-audit.log | grep SecretAccess | wc -l
```

**Example:**
```toml
[service]
key_audit_log_path = "/var/log/igra/key-audit.log"
```

---

### service.node_rpc_circuit_breaker

**Type:** `Object`
**Default:** See sub-parameters below

**Description:**
Circuit breaker configuration for Kaspa node RPC calls (prevents cascading failures).

**Sub-parameters:**

#### service.node_rpc_circuit_breaker.failure_threshold

**Type:** `u32`
**Default:** `5`
**Environment:** `IGRA_SERVICE__NODE_RPC_CIRCUIT_BREAKER__FAILURE_THRESHOLD`

**Description:** Consecutive failures before opening circuit

---

#### service.node_rpc_circuit_breaker.open_duration_secs

**Type:** `u64`
**Default:** `30`
**Environment:** `IGRA_SERVICE__NODE_RPC_CIRCUIT_BREAKER__OPEN_DURATION_SECS`

**Description:** Maximum time circuit stays open before attempting recovery

---

#### service.node_rpc_circuit_breaker.success_threshold

**Type:** `u32`
**Default:** `2`
**Environment:** `IGRA_SERVICE__NODE_RPC_CIRCUIT_BREAKER__SUCCESS_THRESHOLD`

**Description:** Required successes in half-open state before closing circuit

---

**Circuit breaker states:**

```
CLOSED (Normal)
  ↓ (failure_threshold failures)
OPEN (Rejecting requests)
  ↓ (after open_duration_secs)
HALF-OPEN (Probing)
  ↓ (success_threshold successes)
CLOSED (Recovered)
```

**Backoff strategy:**
- Base: 1 second
- Multiplier: 2x per failure
- Max: `open_duration_secs`

**Why this exists:**
Prevents overwhelming a struggling Kaspa node. Gives node time to recover.

**Where used:**
- `igra-core/src/infrastructure/rpc/kaspa_grpc_client.rs:78` - Circuit breaker wrapper

**Example:**
```toml
[service.node_rpc_circuit_breaker]
failure_threshold = 10     # Tolerate more failures
open_duration_secs = 60    # Longer recovery window
success_threshold = 3      # Require more successes
```

---

## Example Configurations

### Minimal (Devnet)

```toml
[service]
node_rpc_url = "grpc://127.0.0.1:16210"
data_dir = "./.igra-devnet"
```

---

### Production (Mainnet)

```toml
[service]
network = "mainnet"                     # Explicit confirmation
node_rpc_url = "grpc://127.0.0.1:16110" # Local RPC only
data_dir = "/var/lib/igra"              # Dedicated directory
use_encrypted_secrets = true            # Encrypted secrets required
secrets_file = "/var/lib/igra/secrets.bin"
key_audit_log_path = "/var/log/igra/key-audit.log"

[service.node_rpc_circuit_breaker]
failure_threshold = 10
open_duration_secs = 120
success_threshold = 3
```

**Permissions:**
```bash
sudo chmod 700 /var/lib/igra
sudo chmod 600 /var/lib/igra/secrets.bin
sudo chmod 600 /var/log/igra/key-audit.log
```

---

### With Remote RPC (Not Recommended)

```toml
[service]
network = "mainnet"
node_rpc_url = "grpcs://apitoken@kaspad.example.com:16110"  # TLS + auth
allow_remote_rpc = true                 # Explicit risk acknowledgment
use_encrypted_secrets = true
```

**⚠️ SECURITY WARNING:**
This configuration trusts a remote RPC endpoint. Use only if:
- You control the remote node
- Connection is over private network
- You understand the risks (UTXO manipulation, transaction tracking)

---

## Validation Rules

### Network Mode Impact

| Parameter | Mainnet | Testnet | Devnet |
|-----------|---------|---------|--------|
| `network` | ERROR if missing/mismatch | WARNING if missing | Optional |
| `allow_remote_rpc` | Required for remote RPC | Not enforced | Not enforced |
| `node_rpc_url` | Local only (or explicit opt-in) | Warning if remote+insecure | Any |
| `data_dir` | Must exist, 0700 perms, ≥10GB | Warns on issues | Any |
| `use_encrypted_secrets` | MUST be true | Recommended | Optional |
| `secrets_file` | Must exist, 0600 perms | Warns on perms | Any |
| `key_audit_log_path` | Parent must exist, 0600 perms | Warns on perms | Any |

**See:** [validation.md](validation.md) for complete validation rules.

---

## Troubleshooting

### "Mainnet requires explicit 'network = \"mainnet\"' in config"

**Cause:** Missing or mismatched network confirmation

**Fix:**
```toml
[service]
network = "mainnet"  # Add this
```

---

### "Mainnet requires local RPC endpoint"

**Cause:** `node_rpc_url` points to remote host without explicit opt-in

**Fix Option 1 (Recommended):**
```toml
[service]
node_rpc_url = "grpc://127.0.0.1:16110"
```

**Fix Option 2 (Acknowledge Risk):**
```toml
[service]
node_rpc_url = "grpcs://token@remote:16110"
allow_remote_rpc = true
```

---

### "Data directory must be 0700, got 0755"

**Cause:** Insecure directory permissions

**Fix:**
```bash
chmod 700 /var/lib/igra
```

---

### "Failed to connect to Kaspa node"

**Cause:** kaspad not running or wrong URL

**Fix:**
```bash
# Check kaspad is running
kaspad --version
netstat -an | grep 16110

# Verify RPC endpoint
grpcurl -plaintext 127.0.0.1:16110 list

# Fix config
[service]
node_rpc_url = "grpc://127.0.0.1:16110"  # Correct port
```

---

## Related Configuration

**Nested sections:**
- `[service.pskt]` - [pskt-config.md](pskt-config.md)
- `[service.hd]` - [hd-wallet-config.md](hd-wallet-config.md)

**Related:**
- [network-modes.md](network-modes.md) - Security validation details
- [secrets-config.md](secrets-config.md) - Secret management
- [environment-variables.md](environment-variables.md) - Env var overrides

---

**Next:** [pskt-config.md](pskt-config.md) - Transaction builder configuration
