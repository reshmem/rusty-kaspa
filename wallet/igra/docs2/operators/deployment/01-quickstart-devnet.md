# Quickstart - Devnet Deployment

**Last Updated:** 2026-02-05
**Estimated Time:** 15-30 minutes
**Audience:** Developers, operators testing Igra locally

---

## Overview

This guide gets you running a **3-node Igra devnet** on your local machine in under 30 minutes. Perfect for:
- Testing Igra functionality
- Developing integrations
- Learning the protocol
- Reproducing issues

**Not covered here:**
- Production deployment (see [Mainnet Deployment](03-deployment-mainnet.md))
- Multi-machine setup (see [Testnet Deployment](02-deployment-testnet.md))
- Security hardening (see [Security Guide](../../devops/security/01-security-overview.md))

---

## Prerequisites

### System Requirements
- **OS:** Linux, macOS, or WSL2 on Windows
- **RAM:** 4 GB minimum, 8 GB recommended
- **Disk:** 10 GB free space
- **CPU:** 2 cores minimum, 4 cores recommended

### Software Dependencies
```bash
# Rust toolchain (1.70+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Kaspa node (devnet)
# Download from: https://github.com/kaspanet/rusty-kaspa/releases

# Git
sudo apt-get install git  # Ubuntu/Debian
brew install git          # macOS
```

### Knowledge Prerequisites
- Basic command line usage
- Understanding of JSON configuration files
- (Optional) Familiarity with UTXO blockchains

---

## Step 1: Clone Repository

```bash
cd ~/
git clone https://github.com/kaspanet/rusty-kaspa.git
cd rusty-kaspa/wallet/igra
```

---

## Step 2: Start Local Kaspa Devnet

Igra requires a Kaspa node to query UTXOs and submit transactions.

### Option A: Use Pre-Built Binary
```bash
# Download kaspad binary for your platform
wget https://github.com/kaspanet/rusty-kaspa/releases/download/v0.14.0/kaspad-v0.14.0-linux-amd64.tar.gz
tar -xzf kaspad-v0.14.0-linux-amd64.tar.gz
cd kaspad-v0.14.0

# Start devnet with mining enabled
./kaspad --devnet --enable-unsynced-mining --rpclisten=127.0.0.1:16110 --rpclisten-borsh=127.0.0.1:17110 --utxoindex &

# Note the PID for later shutdown
KASPAD_PID=$!
echo $KASPAD_PID > /tmp/kaspad.pid
```

### Option B: Build from Source
```bash
cd ~/rusty-kaspa
cargo build --release --bin kaspad

# Start devnet
./target/release/kaspad --devnet --enable-unsynced-mining --rpclisten=127.0.0.1:16110 --rpclisten-borsh=127.0.0.1:17110 --utxoindex &

KASPAD_PID=$!
echo $KASPAD_PID > /tmp/kaspad.pid
```

### Verify Kaspa is Running
```bash
# Check RPC is responding (wait 10 seconds for node to start)
sleep 10
curl -X POST http://127.0.0.1:16110 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"getBlockCount","params":[],"id":1}'

# Expected response: {"jsonrpc":"2.0","result":...,"id":1}
```

---

## Step 3: Build Igra

```bash
cd ~/rusty-kaspa/wallet/igra

# Build igra-core and igra-service
cargo build --release

# Binaries will be in:
# - target/release/igra-service (main service)
# - target/release/igra-keygen (key generation utility)
```

---

## Step 4: Generate Signing Keys

Each of the 3 nodes needs a BIP39 mnemonic and encryption key.

```bash
cd ~/rusty-kaspa/wallet/igra

# Generate keys for node 1
./target/release/igra-keygen generate --output secrets/node1.json

# Generate keys for node 2
./target/release/igra-keygen generate --output secrets/node2.json

# Generate keys for node 3
./target/release/igra-keygen generate --output secrets/node3.json
```

Each file contains:
```json
{
  "mnemonic_encrypted": "...",
  "encryption_key": "...",
  "address": "kaspa:qz..."
}
```

**⚠️ Security Note:** In production, store encryption keys in a secrets manager, not in JSON files.

---

## Step 5: Fund the Multisig Address

The 3 nodes form a 2-of-3 multisig. We need to fund it with devnet KAS.

### Extract Multisig Address
```bash
# Combine public keys from all 3 nodes
./target/release/igra-keygen multisig \
  --pubkey secrets/node1.json \
  --pubkey secrets/node2.json \
  --pubkey secrets/node3.json \
  --threshold 2 \
  --network devnet

# Output:
# Multisig address (2-of-3): kaspa:qz8h3j...
```

### Mine Coins to Multisig
```bash
# Use kaspa-cli to mine blocks
cd ~/rusty-kaspa
./target/release/kaspa-cli --devnet \
  mineblocks kaspa:qz8h3j... 100

# This mines 100 blocks, sending rewards to the multisig address
```

### Verify Balance
```bash
./target/release/kaspa-cli --devnet \
  getbalance kaspa:qz8h3j...

# Expected output: Balance: 50000.00000000 KAS (or similar)
```

---

## Step 6: Configure Igra Nodes

Create configuration files for each node.

### Node 1 Configuration (`config/devnet/node1.toml`)

```toml
[network]
mode = "devnet"

[pskt]
source_addresses = ["kaspa:qz8h3j..."]  # Multisig address
change_address = "kaspa:qz8h3j..."      # Same as source
threshold = 2
network = "kaspa-devnet"

[pskt.wallet]
encrypted_mnemonic_path = "secrets/node1.json"

[kaspa_rpc]
endpoint = "http://127.0.0.1:16110"

[two_phase]
commit_quorum = 2          # 2 out of 3
min_input_score_depth = 10 # Confirmations required

[service]
bind_address = "127.0.0.1:8001"
peer_id_keypair_path = "secrets/node1-peer.key"

[gossip]
bootstrap_nodes = []  # Will be populated after first node starts

[storage]
backend = "memory"  # Use in-memory storage for devnet
```

### Generate Peer Identity Keys
```bash
# Generate Ed25519 keypair for gossip authentication
./target/release/igra-service keygen-peer --output secrets/node1-peer.key
./target/release/igra-service keygen-peer --output secrets/node2-peer.key
./target/release/igra-service keygen-peer --output secrets/node3-peer.key
```

### Node 2 Configuration (`config/devnet/node2.toml`)
```toml
[network]
mode = "devnet"

[pskt]
source_addresses = ["kaspa:qz8h3j..."]
change_address = "kaspa:qz8h3j..."
threshold = 2
network = "kaspa-devnet"

[pskt.wallet]
encrypted_mnemonic_path = "secrets/node2.json"

[kaspa_rpc]
endpoint = "http://127.0.0.1:16110"

[two_phase]
commit_quorum = 2
min_input_score_depth = 10

[service]
bind_address = "127.0.0.1:8002"
peer_id_keypair_path = "secrets/node2-peer.key"

[gossip]
bootstrap_nodes = ["<node1_peer_id>@127.0.0.1:8001"]  # Fill after node1 starts

[storage]
backend = "memory"
```

### Node 3 Configuration (`config/devnet/node3.toml`)
```toml
[network]
mode = "devnet"

[pskt]
source_addresses = ["kaspa:qz8h3j..."]
change_address = "kaspa:qz8h3j..."
threshold = 2
network = "kaspa-devnet"

[pskt.wallet]
encrypted_mnemonic_path = "secrets/node3.json"

[kaspa_rpc]
endpoint = "http://127.0.0.1:16110"

[two_phase]
commit_quorum = 2
min_input_score_depth = 10

[service]
bind_address = "127.0.0.1:8003"
peer_id_keypair_path = "secrets/node3-peer.key"

[gossip]
bootstrap_nodes = [
  "<node1_peer_id>@127.0.0.1:8001",
  "<node2_peer_id>@127.0.0.1:8002"
]

[storage]
backend = "memory"
```

---

## Step 7: Start Igra Nodes

### Terminal 1: Node 1
```bash
cd ~/rusty-kaspa/wallet/igra
WALLET_SECRET=$(cat secrets/node1.json | jq -r .encryption_key) \
  ./target/release/igra-service \
  --config config/devnet/node1.toml \
  --log-level info
```

**Copy the peer ID from the startup logs:**
```
INFO igra_service: Peer ID: 12D3KooWABC123...
```

### Terminal 2: Node 2
Update `config/devnet/node2.toml` with node1's peer ID, then:
```bash
cd ~/rusty-kaspa/wallet/igra
WALLET_SECRET=$(cat secrets/node2.json | jq -r .encryption_key) \
  ./target/release/igra-service \
  --config config/devnet/node2.toml \
  --log-level info
```

### Terminal 3: Node 3
Update `config/devnet/node3.toml` with node1 and node2 peer IDs, then:
```bash
cd ~/rusty-kaspa/wallet/igra
WALLET_SECRET=$(cat secrets/node3.json | jq -r .encryption_key) \
  ./target/release/igra-service \
  --config config/devnet/node3.toml \
  --log-level info
```

---

## Step 8: Submit Test Event

Create a test withdrawal event:

```bash
curl -X POST http://127.0.0.1:8001/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "external_id": "0000000000000000000000000000000000000000000000000000000000000001",
    "source": {
      "type": "manual"
    },
    "destination": "kaspa:qr0test1234567890abcdefghijklmnopqrstuvwxyz",
    "amount_sompi": 100000000000,
    "reason": "Test withdrawal"
  }'
```

### Expected Response
```json
{
  "event_id": "a1b2c3d4...",
  "status": "proposing"
}
```

---

## Step 9: Monitor Progress

### Check Event Status
```bash
curl http://127.0.0.1:8001/api/v1/events/a1b2c3d4...
```

### Watch Logs
You should see in the terminal logs:
```
INFO Phase transition: Unknown -> Proposing
INFO Proposal broadcast: round=0 hash=abc123...
INFO Quorum reached: round=0 hash=abc123... votes=2
INFO Phase transition: Proposing -> Committed
INFO Signature threshold reached: 2/2
INFO Transaction submitted: txid=def456...
INFO Phase transition: Committed -> Completed
```

### Verify on Blockchain
```bash
./target/release/kaspa-cli --devnet \
  gettransaction def456...
```

---

## Troubleshooting

### Issue: "Insufficient UTXOs"
**Solution:** Mine more blocks to the multisig address (Step 5)

### Issue: "Peer connection failed"
**Solution:**
1. Check bootstrap node peer IDs are correct
2. Verify firewall allows local connections
3. Ensure nodes started in order (node1 → node2 → node3)

### Issue: "Quorum not reached"
**Solution:**
1. Check all 3 nodes are running
2. Verify gossip connections established (check logs)
3. Ensure nodes see same Kaspa blockchain state

### Issue: "Template validation failed"
**Solution:**
1. Check UTXOs have sufficient confirmations (min_input_score_depth)
2. Verify multisig address has enough balance
3. Check transaction fee settings in config

---

## Clean Up

```bash
# Stop all Igra nodes (Ctrl+C in each terminal)

# Stop Kaspa node
kill $(cat /tmp/kaspad.pid)

# Clean up data
rm -rf ~/.kaspa-devnet
rm -rf secrets/
```

---

## Next Steps

- **Deploy to testnet**: [Testnet Deployment](02-deployment-testnet.md)
- **Configure policies**: [Configuration Guide](../configuration/01-configuration-overview.md)
- **Monitor production**: [Monitoring Guide](../monitoring/01-monitoring-overview.md)
- **Understand internals**: [Architecture Overview](../../developers/architecture/01-architecture-overview.md)

---

**Questions?** Ask in [Kaspa Discord #igra-support](https://discord.gg/kaspa)
