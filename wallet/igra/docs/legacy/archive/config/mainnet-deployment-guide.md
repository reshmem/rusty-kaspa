# Mainnet Deployment Guide - 10-of-15 Configuration

**Version:** 0.5.0
**Last Updated:** 2026-01-24
**Configuration:** 10-of-15 Kaspa signers, 12-of-15 Hyperlane validators

---

## Overview

This guide walks through deploying Igra to Kaspa mainnet with a **10-of-15 threshold configuration**.

**Security level:** Maximum (production-ready)
**Complexity:** High (15 distributed signers)
**Estimated setup time:** 4-6 hours (first deployment)

---

## Prerequisites

### Infrastructure

- **15 servers** (one per signer)
  - CPU: 2+ cores
  - RAM: 4 GB minimum
  - Disk: 50 GB minimum
  - OS: Linux (Ubuntu 22.04 LTS recommended)
  - Network: Low-latency connectivity between signers

- **1-2 seed servers** (bootstrap nodes)
  - Public IPs with DNS names
  - Higher availability requirements (99.9%+ uptime)

- **Optional: 1 relay server** (if signers behind NAT)
  - Public IP
  - Handles NAT traversal for firewall-protected nodes

### Software

- **Kaspa node (kaspad)** - One per signer or shared
- **Rust 1.75+** - For building Igra
- **PostgreSQL** (optional) - For monitoring/analytics

### Credentials

- **15 BIP39 mnemonics** (24 words each) - One per signer
- **15 Iroh seeds** (32 bytes each) - For P2P identity
- **Secrets passphrase** (20+ characters) - For FileSecretStore encryption
- **15 Hyperlane validator keys** (secp256k1) - For cross-chain verification

---

## Deployment Phases

### Phase 1: Planning & Key Generation (2-3 hours)

#### Step 1.1: Generate Signing Keys

**Use devnet-keygen or manual BIP39 generation:**

```bash
# Generate 15 mnemonics (secure, offline machine recommended)
for i in {1..15}; do
    cargo run --bin devnet-keygen -- --num-signers 1 | jq -r '.signers[0].mnemonic'
done > mnemonics.txt

# SECURITY: Keep mnemonics.txt in secure location (encrypted volume)
# Each line is one signer's mnemonic
```

**Alternative: Use hardware wallet or HSM for key generation**

---

#### Step 1.2: Derive Public Keys

```bash
# From mnemonics, derive Schnorr x-only pubkeys
cargo run --bin devnet-keygen -- \
    --num-signers 15 \
    --wallet-secret mainnet-wallet-secret \
    > keyset.json

# Extract member_pubkeys (x-only, 32 bytes each)
jq -r '.member_pubkeys[]' keyset.json

# Extract redeem_script_hex (10-of-15)
jq -r '.redeem_script_hex' keyset.json

# Extract multisig address
jq -r '.multisig_address' keyset.json
```

---

#### Step 1.3: Generate Iroh P2P Seeds

```bash
# Generate 15 Iroh seeds (32 bytes hex each)
for i in {1..15}; do
    openssl rand -hex 32
done > iroh-seeds.txt

# Derive peer IDs from seeds (for verifier_keys)
for seed in $(cat iroh-seeds.txt); do
    echo -n "signer-$(printf "%02d" $i):"
    echo -n "$seed" | xxd -r -p | blake3sum | cut -c1-16
    i=$((i+1))
done > verifier-keys.txt
```

---

#### Step 1.4: Collect Hyperlane Validator Keys

**If you're running Hyperlane validators:**
```bash
# Export public keys from each validator
hyperlane validator export-pubkey > validator-01-pubkey.txt
# Repeat for all 15 validators
```

**If using external validators:**
- Coordinate with validator operators to get their secp256k1 public keys

---

#### Step 1.5: Compute Group ID

```bash
# Group ID is derived from group configuration
# Will be computed automatically on first start
# Or pre-compute with:
cargo run --bin compute-group-id -- \
    --threshold-m 10 \
    --threshold-n 15 \
    --network-id 1 \
    --member-pubkeys "$(jq -r '.member_pubkeys | join(",")' keyset.json)"
```

---

### Phase 2: Configuration Setup (1-2 hours)

#### Step 2.1: Create Base Configuration

```bash
# Copy template
cp docs/config/mainnet-config-template.toml /etc/igra/config.toml

# Secure permissions
chmod 600 /etc/igra/config.toml
```

---

#### Step 2.2: Fill in Placeholders

**Edit `/etc/igra/config.toml` and replace ALL `<REPLACE...>` placeholders:**

1. **redeem_script_hex** - 10-of-15 redeem script (from keyset.json; source address is derived)
2. **member_pubkeys** - 15 x-only pubkeys (from keyset.json)
3. **group_id** - Group identifier (from compute-group-id)
4. **verifier_keys** - 15 peer_id:pubkey pairs (from verifier-keys.txt)
5. **bootstrap** - Seed node EndpointIDs
6. **bootstrap_addrs** - Seed node addresses (EndpointID@host:port)
7. **hyperlane validators** - 15 validator pubkeys
8. **Per-profile sections** - One per signer (data_dir, peer_id, etc.)

**Verification:**
```bash
# Check no placeholders remain
grep "<REPLACE" /etc/igra/config.toml
# Should return empty (all replaced)
```

---

#### Step 2.3: Create Encrypted Secrets File

```bash
# Create secrets.bin (requires IGRA_SECRETS_PASSPHRASE or interactive prompt)
export IGRA_SECRETS_PASSPHRASE="$(cat /secure/passphrase.txt)"
cargo run --bin secrets-admin -- --path /var/lib/igra/secrets.bin init

# Add secrets (one per signer)
for i in {1..15}; do
    mnemonic=$(sed -n "${i}p" mnemonics.txt)
    seed=$(sed -n "${i}p" iroh-seeds.txt)

    signer=$(printf "signer_%02d" $i)
    cargo run --bin secrets-admin -- --path /var/lib/igra/secrets.bin \
        set "igra.hd.mnemonic_${signer}" "$mnemonic"

    cargo run --bin secrets-admin -- --path /var/lib/igra/secrets.bin \
        set "igra.iroh.signer_seed_${signer}" "0x${seed}" --hex
done

# Secure permissions
chmod 600 /var/lib/igra/secrets.bin

# SECURITY: Remove plaintext files after loading them (secure deletion is OS/filesystem dependent)
rm -f mnemonics.txt iroh-seeds.txt /secure/passphrase.txt
unset IGRA_SECRETS_PASSPHRASE
```

---

#### Step 2.4: Set Up Directories and Permissions

```bash
# Create data directories (one per signer)
for i in {1..15}; do
    sudo mkdir -p /var/lib/igra/signer-$(printf "%02d" $i)
done

# Create log directory
sudo mkdir -p /var/log/igra

# Create service user (not root!)
sudo useradd -r -s /bin/false igra-service

# Set ownership
sudo chown -R igra-service:igra-service /var/lib/igra /var/log/igra /etc/igra

# Set permissions (mainnet requirements)
sudo chmod 700 /var/lib/igra
sudo chmod 700 /var/lib/igra/signer-*
sudo chmod 600 /var/lib/igra/secrets.bin
sudo chmod 600 /etc/igra/config.toml
sudo chmod 750 /var/log/igra

# Verify permissions
ls -la /var/lib/igra
ls -la /etc/igra
```

---

### Phase 3: Validation (30 minutes)

#### Step 3.1: Validate Configuration

```bash
# Set passphrase (from secrets management system)
export IGRA_SECRETS_PASSPHRASE="<from-password-manager>"
export KASPA_IGRA_LOG_DIR="/var/log/igra"

# Validate config (don't start service yet)
kaspa-threshold-service \
    --network mainnet \
    --config /etc/igra/config.toml \
    --validate-only

# Expected output:
# [INFO] config validation passed
# [INFO] static validation passed (0 errors, 0 warnings)
# [INFO] startup validation passed (0 errors, 0 warnings)
# [INFO] validate-only complete
```

**If validation fails:**
- Check error messages (actionable fixes provided)
- Verify all placeholders replaced
- Check file permissions
- Check kaspad is running and accessible

---

#### Step 3.2: Validate Per Profile

```bash
# Validate each signer profile (1-15)
for i in {1..15}; do
    echo "Validating signer-$(printf "%02d" $i)..."
    kaspa-threshold-service \
        --network mainnet \
        --profile signer-$(printf "%02d" $i) \
        --validate-only
done

# All 15 validations must pass
```

---

### Phase 4: Deployment (1-2 hours)

#### Step 4.1: Deploy Seed Nodes (2-3 nodes)

**Seed nodes provide bootstrap for peer discovery**

**On seed1.mainnet.your-domain.io:**
```bash
# Start signer-01 (designated seed node)
systemctl enable igra-signer-01
systemctl start igra-signer-01

# Verify started
journalctl -u igra-signer-01 -f
# Look for: "iroh endpoint bound endpoint_id=..."
```

**On seed2.mainnet.your-domain.io:**
```bash
# Start signer-02 (second seed node)
systemctl enable igra-signer-02
systemctl start igra-signer-02
```

**Wait 60 seconds for bootstrap**

---

#### Step 4.2: Deploy Remaining Signers (13 nodes)

**On each signer node (03-15):**
```bash
# Start service
sudo -u igra-service kaspa-threshold-service \
    --network mainnet \
    --profile signer-XX \
    --config /etc/igra/config.toml

# Or use systemd:
systemctl enable igra-signer-XX
systemctl start igra-signer-XX
```

**Deployment order (recommended):**
1. Start seed nodes (01-02) first
2. Wait 60s for bootstrap
3. Start 3-5 nodes simultaneously
4. Wait 60s
5. Start remaining nodes (batches of 3-5)

**Why gradual:** Allows network to stabilize, easier to debug issues

---

#### Step 4.3: Verify Network Formation

```bash
# Check peer connections (on any signer)
curl http://127.0.0.1:8088/api/v1/status

# Expected:
# {
#   "connected_peers": 14,  # Should see 14 other signers
#   "gossip_topics": 1,
#   "signing_backend": "threshold"
# }

# Check logs for peer discovery
journalctl -u igra-signer-01 | grep "peer discovered"
# Should see 14 peer discovery messages
```

---

### Phase 5: Testing (1 hour)

#### Step 5.1: Test Signing (Testnet First!)

**IMPORTANT: Test on testnet before mainnet**

1. Deploy same configuration to testnet (change network_id, addresses)
2. Send test transaction
3. Verify 10-of-15 signatures collected
4. Verify transaction submitted
5. Monitor for 24 hours
6. If stable, proceed to mainnet

---

#### Step 5.2: Mainnet Dry-Run

**After testnet verification:**

```bash
# Send test transaction (small amount)
curl -X POST http://127.0.0.1:8088/api/v1/sign \
  -H "Content-Type: application/json" \
  -d '{
    "recipient": "kaspa:qr<TEST_ADDRESS>",
    "amount_sompi": 100000000,
    "reason": "Mainnet deployment test"
  }'

# Monitor signing progress
tail -f /var/log/igra/key-audit.log | grep Signing

# Expected: 10 signatures collected within session_timeout
```

---

### Phase 6: Monitoring (Ongoing)

#### Step 6.1: Log Monitoring

```bash
# Service logs
tail -f /var/log/igra/igra-service.log

# Key audit logs
tail -f /var/log/igra/key-audit.log

# Look for:
# - [INFO] gossip: joined peers=14 (all peers connected)
# - [INFO] crdt: signature added (signature collection)
# - [INFO] transaction submitted tx_id=... (successful signing)
```

---

#### Step 6.2: Health Checks

```bash
# Check each signer
for i in {1..15}; do
    echo "Signer $(printf "%02d" $i):"
    curl -s http://127.0.0.1:$((8087+i))/api/v1/health | jq '.status'
done

# All should return: "healthy"
```

---

#### Step 6.3: Metrics (if Prometheus configured)

```bash
# Scrape metrics
curl http://127.0.0.1:9090/metrics

# Key metrics:
# - igra_connected_peers (should be 14)
# - igra_signatures_collected (increment on signing)
# - igra_transactions_submitted (increment on submit)
# - igra_crdt_state_size (monitor growth)
```

---

## Security Checklist

### Pre-Deployment

- [ ] All placeholders in config replaced (<REPLACE...>)
- [ ] Secrets.bin created with encrypted mnemonics
- [ ] IGRA_SECRETS_PASSPHRASE set (from password manager)
- [ ] File permissions correct (0600 config/secrets, 0700 data_dir)
- [ ] Directories created (/var/lib/igra, /var/log/igra)
- [ ] Service user created (igra-service, not root)
- [ ] Kaspad running and accessible (local RPC)
- [ ] Validation passed (--validate-only)
- [ ] Timing attack fix applied (ct_eq for hash comparisons)
- [ ] NetworkMode-Security.md reviewed
- [ ] Tested on testnet first (24+ hours stable)

---

### Post-Deployment

- [ ] All 15 signers running (systemctl status)
- [ ] All peers connected (14 peers per node)
- [ ] First test transaction successful
- [ ] Logs monitored (no errors)
- [ ] Key audit trail verified (all 10 signers logged)
- [ ] Alerting configured (Prometheus/Grafana)
- [ ] Backup procedure tested (secrets.bin, config)
- [ ] Incident response plan documented
- [ ] Runbook created (restart procedures, troubleshooting)

---

## Configuration Highlights

### Threshold: 10-of-15

**Security analysis:**
- **Byzantine tolerance:** Up to 5 signers can fail/be malicious
- **Availability:** Need 10 out of 15 online (66% uptime per signer)
- **Compromise resistance:** Attacker needs 10+ keys (difficult)

**Trade-offs:**
- Higher security (5 Byzantine tolerance)
- Lower availability (need 10 online simultaneously)
- Slower signing (collect 10 signatures)

**Alternative:** 7-of-15 (higher availability, lower security)

---

### Hyperlane: 12-of-15

**Security analysis:**
- **Byzantine tolerance:** Up to 3 validators can fail/be malicious
- **Message verification:** Requires 12 signatures for cross-chain messages
- **Compromise resistance:** Attacker needs 12+ validator keys

**Why 12-of-15:**
- Kaspa threshold: 10-of-15 (66%)
- Hyperlane threshold: 12-of-15 (80%)
- **Higher** Hyperlane threshold = more security for cross-chain (recommended)

**Rationale:**
Cross-chain attacks are more complex (two chains involved). Higher threshold provides defense-in-depth.

---

### Session Timeout: 600 seconds (10 minutes)

**For 10-of-15 threshold:**
- Need 10 signers to respond
- Geographically distributed (network latency)
- Allows time for signature collection

**Recommended range:**
- Minimum: 300s (5 min) - Co-located signers (low latency)
- Maximum: 600s (10 min) - Global distribution (high latency)

**Trade-off:** Longer timeout = more availability, slower transaction finality

---

### Fee Payment: "signers_pay"

**Why:**
- Signers control multisig (have funds)
- Cleaner accounting (recipient gets exact amount)
- Prevents fee sniping (fees paid from change)

**Alternative:**
```toml
fee_payment_mode = "recipient_pays"  # Deduct fees from recipient amount
```

**Or split:**
```toml
fee_payment_mode = { split = { recipient_parts = 1, signer_parts = 1 } }  # 50/50
```

---

### Policy: Conservative Limits

**Default config has:**
- Min amount: 0.1 KAS (prevents dust)
- Max amount: 1000 KAS (risk management)
- Daily volume: 5000 KAS (aggregate limit)
- Require reason: true (audit trail)

**Customize per your risk tolerance:**
- Higher limits for treasury operations
- Lower limits for hot wallet
- Whitelist for known recipients only

---

## Systemd Unit Files

### Template: igra-signer-XX.service

**File:** `/etc/systemd/system/igra-signer-01.service`

```ini
[Unit]
Description=Igra Threshold Signing Service (Signer 01)
After=network.target kaspad.service
Requires=kaspad.service

[Service]
Type=simple
User=igra-service
Group=igra-service
WorkingDirectory=/var/lib/igra/signer-01

# Environment
Environment="KASPA_IGRA_LOG_DIR=/var/log/igra"
EnvironmentFile=/etc/igra/environment
EnvironmentFile=/etc/igra/secrets.env

# Main process
ExecStart=/usr/local/bin/kaspa-threshold-service \
    --network mainnet \
    --profile signer-01 \
    --config /etc/igra/config.toml

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/igra/signer-01 /var/log/igra

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=igra-signer-01

[Install]
WantedBy=multi-user.target
```

**File:** `/etc/igra/secrets.env`
```bash
IGRA_SECRETS_PASSPHRASE=<from-secrets-manager>
```

**Permissions:**
```bash
sudo chmod 600 /etc/igra/secrets.env
sudo chmod 644 /etc/systemd/system/igra-signer-*.service
```

**Create for all 15 signers:**
```bash
# Generate 15 unit files (signer-01 through signer-15)
for i in {1..15}; do
    signer=$(printf "signer-%02d" $i)
    port=$((8087+i))

    sed "s/signer-01/$signer/g; s/8088/$port/g" \
        /etc/systemd/system/igra-signer-01.service \
        > /etc/systemd/system/igra-$signer.service
done

# Reload systemd
sudo systemctl daemon-reload
```

---

## Network Topology

### Recommended Setup

```
                    ┌─────────────────────────────────┐
                    │     Kaspa Mainnet               │
                    │     (kaspad nodes)              │
                    └─────────────────────────────────┘
                                 ↑
                                 │ gRPC (local)
                                 │
┌────────────────────────────────┼────────────────────────────────┐
│                   Igra Signer Network                            │
│                                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐        ┌──────────┐  │
│  │ Signer 1 │──│ Signer 2 │──│ Signer 3 │── ... ─│ Signer15 │  │
│  │ (seed)   │  │ (seed)   │  │          │        │          │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘        └────┬─────┘  │
│       │             │             │                     │        │
│       └─────────────┴─────────────┴─────────────────────┘        │
│                    Iroh Gossip (QUIC/Ed25519)                    │
│       Threshold: 10-of-15 signers required for transaction       │
└───────────────────────────────────────────────────────────────────┘
                                 ↓
                    ┌─────────────────────────────────┐
                    │  Hyperlane Validators (12-of-15)│
                    │  (Cross-chain message verify)   │
                    └─────────────────────────────────┘
```

---

### Infrastructure Options

**Option A: Co-Located (All on Same Network)**
- Low latency (<10ms between signers)
- Shorter session_timeout possible (300s)
- Simpler deployment (private IPs)
- Single point of failure (network/datacenter)

**Option B: Geographically Distributed (Recommended)**
- High availability (multi-region)
- Network latency (50-200ms)
- Longer session_timeout needed (600s)
- Requires pkarr discovery + relay (NAT traversal)

**Option C: Hybrid (2-3 Regions)**
- Balance availability and latency
- 5 signers per region (US, EU, Asia)
- Regional co-location + global distribution
- session_timeout: 450-600s

---

## Operational Procedures

### Starting the Network

**Cold start (all nodes offline):**
1. Start seed nodes (signer-01, signer-02)
2. Wait 60-120s for Iroh endpoint binding
3. Start remaining signers in batches (5 at a time)
4. Verify peer connections reach 14 per node
5. Monitor logs for 10 minutes

---

### Adding a Signer (Hot Add)

**To add 16th signer to 10-of-15:**
1. Update config (threshold_n=16, add 16th pubkey)
2. Generate new redeem script (10-of-16)
3. Migrate funds to new multisig address
4. Update all signers' configs
5. Rolling restart (one signer at a time)
6. Old address funds moved to new address

**Downtime:** Minimal (10 signers can continue signing during restart)

---

### Removing a Signer (Hot Remove)

**To remove signer from 10-of-15:**
1. Update config (threshold_n=14, remove pubkey)
2. Generate new redeem script (10-of-14)
3. Migrate funds to new multisig
4. Update configs, rolling restart

**Security:** Threshold still requires 10, so removing one doesn't weaken security

---

### Key Rotation

**Full key rotation (all signers):**
1. Generate 15 new mnemonics
2. Derive new pubkeys and redeem script
3. Create new multisig address
4. Update configs (new pubkeys, new address)
5. Rolling restart (one at a time)
6. Migrate funds: old multisig → new multisig
7. Monitor old address (ensure all funds moved)

**Partial key rotation (single signer compromised):**
1. Generate new mnemonic for compromised signer
2. Update multisig (same threshold, replace one pubkey)
3. Migrate funds
4. Update configs, restart

**Frequency:** Annually or on compromise

---

## Troubleshooting

### "Only 9 peers connected, expected 14"

**Possible causes:**
1. Signer(s) not started (check systemctl status)
2. Network connectivity (firewall blocking port 11205)
3. Bootstrap nodes not reachable (check seed1/seed2 DNS)
4. Pkarr DHT not propagated (wait 5-10 minutes)

**Debug:**
```bash
# Check which peers are connected
curl http://127.0.0.1:8088/api/v1/debug/peers | jq .

# Check Iroh endpoint
journalctl -u igra-signer-01 | grep "endpoint bound"

# Test UDP connectivity (Iroh uses UDP)
nc -u -v seed1.mainnet.your-domain.io 11205
```

---

### "Signature collection timeout"

**Possible causes:**
1. < 10 signers online (need threshold to sign)
2. Network latency (geographically distributed)
3. Kaspad slow (UTXO query timeout)
4. session_timeout too short

**Debug:**
```bash
# Check how many signatures collected
curl http://127.0.0.1:8088/api/v1/events/<event_id> | jq '.signatures | length'

# Check which signers haven't signed
curl http://127.0.0.1:8088/api/v1/events/<event_id> | jq '.missing_signers'

# Increase timeout (if needed)
[runtime]
session_timeout_seconds = 900  # 15 minutes
```

---

### "Hyperlane message verification failed"

**Possible causes:**
1. < 12 validators signed message
2. Validator keys mismatch (config vs actual)
3. Message replay (old message)
4. ISM mode mismatch

**Debug:**
```bash
# Check Hyperlane event
curl http://127.0.0.1:8088/api/v1/hyperlane/events/<message_id>

# Verify validator signatures
# Should have ≥12 valid signatures

# Check validator keys in config vs Hyperlane contract
```

---

## Maintenance

### Daily

- [ ] Check all 15 signers running (systemctl status)
- [ ] Review logs for errors
- [ ] Verify peer connections (14 per node)
- [ ] Check disk space (≥10 GB free)

### Weekly

- [ ] Review key-audit.log (unauthorized access?)
- [ ] Check transaction volume (within policy limits?)
- [ ] Verify backups (secrets.bin, config)
- [ ] Update OS security patches

### Monthly

- [ ] Review configuration (any changes needed?)
- [ ] Check Kaspad version (update if needed)
- [ ] Review firewall rules
- [ ] Test disaster recovery (restore from backup)

### Quarterly

- [ ] Rotate IGRA_SECRETS_PASSPHRASE
- [ ] Review and update documentation
- [ ] Security audit (if budget allows)
- [ ] Disaster recovery drill (full failover test)

---

## Disaster Recovery

### Backup

**Critical files to backup:**
```bash
# Configuration
/etc/igra/config.toml

# Secrets (encrypted)
/var/lib/igra/secrets.bin

# Iroh identity
/var/lib/igra/signer-*/iroh/identity.json

# Key audit log (compliance)
/var/log/igra/key-audit.log

# RocksDB (optional - can resync from peers)
/var/lib/igra/signer-*/rocksdb/
```

**Backup script:**
```bash
#!/bin/bash
tar -czf igra-backup-$(date +%Y%m%d).tar.gz \
    /etc/igra/ \
    /var/lib/igra/secrets.bin \
    /var/lib/igra/signer-*/iroh/identity.json \
    /var/log/igra/key-audit.log

# Encrypt backup
gpg --encrypt --recipient backup@your-domain.io igra-backup-*.tar.gz

# Store offsite
aws s3 cp igra-backup-*.tar.gz.gpg s3://igra-backups/
```

---

### Recovery

**Scenario: Single signer failure**

1. Restore from backup (config, secrets, identity)
2. Verify 9+ other signers still online (threshold still met)
3. Restart failed signer
4. Verify rejoins network (14 peers)
5. Monitor for 1 hour

**No downtime** - 10-of-15 threshold still satisfied with 14 online

---

**Scenario: 6+ signers failure (below threshold)**

1. Service degraded (cannot sign new transactions)
2. Restore failed signers from backups
3. Or: Emergency key rotation (if keys compromised)
4. Once 10+ online, service resumes

**Downtime:** Until 10 signers back online

---

## Cost Estimates

### Infrastructure (Monthly)

**Cloud deployment (AWS/GCP/Azure):**
- 15 signers (t3.medium): $45/month × 15 = $675/month
- 2 seed nodes (t3.small): $30/month × 2 = $60/month
- 1 relay server (t3.medium): $45/month
- Storage (100 GB EBS): $10/month × 15 = $150/month
- Data transfer: $100/month (estimate)
- **Total:** ~$1,030/month

**Dedicated servers (self-hosted):**
- 15 servers (4 GB RAM, 50 GB disk): ~$50-100/month each
- Bandwidth: Included or $50/month
- **Total:** $750-1,500/month

---

### Personnel (One-Time + Ongoing)

**Setup (one-time):**
- Configuration: 8-16 hours @ $100/hr = $800-1,600
- Testing: 8 hours @ $100/hr = $800
- **Total:** $1,600-2,400

**Operations (monthly):**
- Monitoring: 10 hours/month @ $100/hr = $1,000
- Incident response: Variable
- **Total:** $1,000-2,000/month

---

### Total Cost of Ownership

**First year:**
- Setup: $1,600-2,400 (one-time)
- Infrastructure: $12,000-18,000 (annual)
- Operations: $12,000-24,000 (annual)
- **Total:** $25,600-44,400

**Ongoing (per year):**
- Infrastructure: $12,000-18,000
- Operations: $12,000-24,000
- **Total:** $24,000-42,000/year

---

## Scaling Considerations

### 10-of-15 is Appropriate For:

✅ **High-value treasury** ($1M+ equivalent)
✅ **Enterprise deployments** (regulated entities)
✅ **Cross-chain bridge** (high security requirement)
✅ **Decentralized governance** (no single point of control)

---

### Consider Smaller Threshold If:

⚠️ **Lower value** (<$100k)
⚠️ **Higher availability requirements** (need faster signing)
⚠️ **Cost-sensitive** (fewer servers)
⚠️ **Simpler operations** (fewer moving parts)

**Alternative: 3-of-5 or 5-of-9** (easier to operate, sufficient for most use cases)

---

## Compliance & Auditing

### SOC 2 Compliance

**If you need SOC 2:**
- Enable comprehensive logging (key-audit.log, service logs)
- Retain logs for 90+ days
- Implement access controls (who can restart signers?)
- Document incident response procedures
- Regular security reviews

**See:** [docs/security/soc2-compliance.md](../security/soc2-compliance.md)

---

### Security Audit Preparation

**For external audit:**
1. Provide configuration (redacted secrets)
2. Provide architecture documentation
3. Demonstrate security validation (--validate-only output)
4. Show key audit log (sample, no secrets)
5. Explain Byzantine tolerance (10-of-15)

**See:** [docs/security/timing-attacks.md](../security/timing-attacks.md)

---

## Related Documentation

- **Configuration Reference:** [config.md](config.md)
- **Network Security:** [network-modes.md](network-modes.md)
- **Iroh Discovery:** [iroh-discovery.md](iroh-discovery.md)
- **Hyperlane Bridge:** [hyperlane.md](hyperlane.md)
- **Security Analysis:** [../security/timing-attacks.md](../security/timing-attacks.md)
- **Key Management:** [../security/key-management-audit.md](../security/key-management-audit.md)
- **Protocol Design:** [../protocol/architecture.md](../protocol/architecture.md)

---

## Support

**For deployment assistance:**
- Review logs first (most issues are in logs)
- Check troubleshooting section above
- Consult configuration reference docs
- File GitHub issue with logs (redact secrets!)

**For security questions:**
- Review security documentation
- Consult with security team
- External audit (if high-value deployment)

---

**Status:** Production-ready template for 10-of-15 mainnet deployment

**Last Updated:** 2026-01-24
