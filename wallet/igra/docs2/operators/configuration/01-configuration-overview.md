# Configuration Overview

**Last Updated:** 2026-02-05
**Audience:** Operators, system administrators

---

## Configuration File Structure

Igra uses TOML configuration files with the following sections:

```toml
[network]           # Network mode (devnet/testnet/mainnet)
[pskt]              # Transaction building and signing
[kaspa_rpc]         # Kaspa node connection
[two_phase]         # Coordination protocol settings
[service]           # Service bind address and API
[gossip]            # P2P network configuration
[storage]           # Database backend
[policy]            # Optional: policy enforcement
[monitoring]        # Optional: metrics and logging
```

---

## Minimal Configuration

**File:** `config/minimal.toml`

```toml
[network]
mode = "testnet"

[pskt]
source_addresses = ["kaspa:qzabcdef1234..."]
change_address = "kaspa:qzabcdef1234..."
threshold = 2
network = "kaspa-testnet"

[pskt.wallet]
encrypted_mnemonic_path = "/etc/igra/secrets/mnemonic.json"

[kaspa_rpc]
endpoint = "http://127.0.0.1:16110"

[two_phase]
commit_quorum = 2
min_input_score_depth = 10

[service]
bind_address = "0.0.0.0:8001"
peer_id_keypair_path = "/etc/igra/secrets/peer-id.key"

[gossip]
bootstrap_nodes = [
    "12D3KooWABC...@node1.example.com:8001",
    "12D3KooWDEF...@node2.example.com:8001"
]

[storage]
backend = "rocksdb"
path = "/var/lib/igra/db"
```

---

## Section-by-Section Reference

### `[network]`

Controls network mode and validation rules.

```toml
[network]
mode = "devnet"  # Options: "devnet" | "testnet" | "mainnet"
```

**Options:**
- `devnet` - Local development, relaxed validation
- `testnet` - Public testnet, full validation
- `mainnet` - Production, strict validation + additional safety checks

**Impact:**
- Changes default ports
- Enables/disables certain features
- Affects validator signature requirements

---

### `[pskt]` - Transaction Building

Core transaction building configuration.

```toml
[pskt]
source_addresses = [
    "kaspa:qz1234...",  # Multisig address (required)
]
change_address = "kaspa:qz1234..."  # Where change goes (required)
threshold = 2                        # M in M-of-N (required)
network = "kaspa-testnet"            # Network identifier (required)

[pskt.wallet]
encrypted_mnemonic_path = "/etc/igra/secrets/mnemonic.json"

[pskt.fee]
priority_fee_sompi = 1000      # Optional: Fixed fee addition
```

**Field Details:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_addresses` | Array[String] | Yes | Multisig address(es) to spend from |
| `change_address` | String | Yes | Where to send change outputs |
| `threshold` | Integer | Yes | Signature threshold (m in m-of-n) |
| `network` | String | Yes | Kaspa network identifier |
| `encrypted_mnemonic_path` | String | Yes | Path to encrypted key file |
| `priority_fee_sompi` | Integer | No | Additional fee in sompi |

**Security:**
- Never commit `encrypted_mnemonic_path` file to version control
- Set file permissions: `chmod 600 /etc/igra/secrets/mnemonic.json`
- Encryption key via environment variable: `WALLET_SECRET`

---

### `[kaspa_rpc]` - Blockchain Connection

Configure connection to Kaspa node.

```toml
[kaspa_rpc]
endpoint = "http://127.0.0.1:16110"   # HTTP RPC endpoint
timeout_ms = 30000                     # Request timeout (optional)
```

**Requirements:**
- Kaspa node must have `--utxoindex` enabled
- Kaspa node must be fully synced
- Use local node for best performance and reliability

**Ports by Network:**
- Devnet: `16110` (HTTP), `17110` (Borsh)
- Testnet: `16210` (HTTP), `17210` (Borsh)
- Mainnet: `16110` (HTTP), `17110` (Borsh)

---

### `[two_phase]` - Coordination Protocol

Two-phase protocol parameters.

```toml
[two_phase]
commit_quorum = 3                  # Votes needed for commitment
min_input_score_depth = 10         # UTXO confirmation requirement
proposal_timeout_ms = 5000         # Timeout per round
max_retries = 10                   # Max rounds before abandoning
```

**Field Details:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `commit_quorum` | Integer | N/2+1 | Minimum votes to commit to template |
| `min_input_score_depth` | Integer | 10 | Min block confirmations for input UTXOs |
| `proposal_timeout_ms` | Integer | 5000 | Milliseconds to wait for quorum |
| `max_retries` | Integer | 10 | Max proposal rounds before abandoning |

**Tuning Guidelines:**

**commit_quorum:**
- Must be > N/2 (majority)
- Typical: 2 for N=3, 3 for N=5, 4 for N=7
- Higher quorum = stronger agreement, harder to reach

**min_input_score_depth:**
- Kaspa: 10 blocks ≈ 10 seconds finality
- Bitcoin: 6 blocks ≈ 60 minutes finality
- Increase for high-value transactions
- Decrease for faster confirmations (less safe)

**proposal_timeout_ms:**
- Fast network: 3000-5000ms
- Slow network: 10000-15000ms
- High latency (intercontinental): 20000ms+

---

### `[service]` - API Service

HTTP API and service configuration.

```toml
[service]
bind_address = "0.0.0.0:8001"
peer_id_keypair_path = "/etc/igra/secrets/peer-id.key"
max_request_size_bytes = 10485760   # 10 MB
```

**Security:**
- `0.0.0.0` exposes API to all interfaces (use firewall!)
- `127.0.0.1` restricts to localhost only (recommended for testing)
- Production: Use reverse proxy (nginx/caddy) with TLS

**API Endpoints:**
- `POST /api/v1/events` - Submit new event
- `GET /api/v1/events/{id}` - Query event status
- `GET /api/v1/health` - Health check
- `GET /metrics` - Prometheus metrics

---

### `[gossip]` - P2P Network

Iroh gossip network configuration.

```toml
[gossip]
bootstrap_nodes = [
    "12D3KooWABC123...@10.0.1.10:8001",
    "12D3KooWDEF456...@10.0.1.11:8001",
]
bind_port = 8001
topic = "igra-coordination-v1"
```

**Bootstrap Nodes:**
- Format: `<peer_id>@<host>:<port>`
- Peer ID: Ed25519 public key fingerprint
- First node: Empty array `[]`
- Subsequent nodes: Include all previous nodes

**Discovery:**
- Nodes automatically discover peers via bootstrap
- Fully connected mesh topology (all-to-all)
- Authenticated via Ed25519 message signatures

**Firewall Requirements:**
- Allow inbound TCP on `bind_port` from all signer IPs
- Allow outbound TCP to all signer IPs

---

### `[storage]` - Database Backend

Persistence layer configuration.

```toml
[storage]
backend = "rocksdb"              # Options: "memory" | "rocksdb"
path = "/var/lib/igra/db"        # RocksDB directory
max_open_files = 1000            # RocksDB tuning
write_buffer_size_mb = 64        # RocksDB tuning
```

**Backend Options:**

**`memory`** (in-memory)
- ✅ Fast (no disk I/O)
- ✅ Simple (no configuration)
- ❌ Data lost on restart
- ❌ Limited by RAM
- **Use for:** Testing only

**`rocksdb`** (persistent)
- ✅ Persistent across restarts
- ✅ Handles large datasets
- ✅ Production-ready
- ❌ Slower than memory
- **Use for:** Production

**Disk Requirements:**
- Initial: ~100 MB
- Growth: ~1 GB/year (typical load)
- SSD recommended for performance

---

### `[policy]` - Optional Policy Enforcement

Enforce business rules on events.

```toml
[policy]
min_amount_sompi = 100_000_000_000            # 1000 KAS minimum
max_amount_sompi = 10_000_000_000_000         # 100,000 KAS maximum
max_daily_volume_sompi = 50_000_000_000_000   # 500,000 KAS per day
amount_multiple_sompi = 10_000_000_000        # Amounts must be multiples of 100 KAS

allowed_destinations = [
    "kaspa:qr0vendor1...",
    "kaspa:qr0vendor2...",
]

require_reason = true   # Require "reason" field in events
```

**Use Cases:**
- Corporate treasury (amount limits)
- Compliance (destination whitelist)
- Bridge operations (velocity limits)
- Automated systems (exact multiples)

**Enforcement:**
- Events violating policy are rejected immediately
- No coordination attempted
- Error returned to API caller

---

### `[monitoring]` - Metrics and Logging

Observability configuration.

```toml
[monitoring]
log_level = "info"            # trace | debug | info | warn | error
log_format = "json"           # json | text
metrics_enabled = true
metrics_bind_address = "0.0.0.0:9090"
```

**Log Levels:**
- `error` - Errors only (production default)
- `warn` - Warnings + errors
- `info` - Info + warn + errors (recommended)
- `debug` - Verbose debugging
- `trace` - Very verbose (development only)

**Metrics:**
- Prometheus format on `/metrics` endpoint
- Scrape interval: 15-60 seconds
- Retention: Configure in Prometheus

See [Monitoring Guide](../monitoring/01-monitoring-overview.md)

---

## Environment Variables

Igra uses environment variables for sensitive data:

```bash
# Required
export WALLET_SECRET="your-encryption-key-here"

# Optional
export RUST_LOG="info,igra_core=debug"
export RUST_BACKTRACE="1"
```

**Security:**
- Never log `WALLET_SECRET`
- Use secret management (Vault, AWS Secrets Manager)
- Set via systemd service file (not shell profile)

---

## Configuration Validation

### Validate Before Starting

```bash
# Dry-run validation
igra-service --config /etc/igra/config.toml --validate

# Expected output: "Configuration valid ✓"
```

### Common Validation Errors

**"Invalid multisig address"**
- Ensure address matches `network` mode
- Devnet: Starts with `kaspa:qz...` (testnet encoding)
- Testnet: Starts with `kaspa:qz...` (testnet encoding)
- Mainnet: Starts with `kaspa:qr...` (mainnet encoding)

**"Quorum must be > N/2"**
- Example: N=5 → quorum must be ≥3
- Fix: Increase `commit_quorum` value

**"Bootstrap nodes required"**
- First node can have empty array `[]`
- All other nodes must specify bootstrap peers

---

## Configuration Examples

### 3-Node Devnet (Local)

**Node 1:**
```toml
[network]
mode = "devnet"

[two_phase]
commit_quorum = 2

[service]
bind_address = "127.0.0.1:8001"

[gossip]
bootstrap_nodes = []
bind_port = 8001
```

**Node 2:**
```toml
[network]
mode = "devnet"

[two_phase]
commit_quorum = 2

[service]
bind_address = "127.0.0.1:8002"

[gossip]
bootstrap_nodes = ["<node1_peer_id>@127.0.0.1:8001"]
bind_port = 8002
```

**Node 3:**
```toml
[network]
mode = "devnet"

[two_phase]
commit_quorum = 2

[service]
bind_address = "127.0.0.1:8003"

[gossip]
bootstrap_nodes = [
    "<node1_peer_id>@127.0.0.1:8001",
    "<node2_peer_id>@127.0.0.1:8002",
]
bind_port = 8003
```

---

### 5-Node Production (Distributed)

See [Mainnet Deployment](../deployment/03-deployment-mainnet.md)

---

## Next Steps

- **Deploy devnet:** [Quickstart Guide](../deployment/01-quickstart-devnet.md)
- **Network setup:** [Network Modes](02-network-modes.md)
- **Key management:** [Secrets and Keys](03-secrets-and-keys.md)
- **Hyperlane config:** [Hyperlane Integration](04-hyperlane-config.md)

---

**Questions?** See [Troubleshooting](../troubleshooting/01-common-issues.md) or ask in [Discord](https://discord.gg/kaspa)
