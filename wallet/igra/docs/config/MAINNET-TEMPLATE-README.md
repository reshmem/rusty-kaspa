# Mainnet Configuration Template - Quick Start

**Template:** [mainnet-config-template.toml](mainnet-config-template.toml)
**Guide:** [mainnet-deployment-guide.md](mainnet-deployment-guide.md)

---

## What You're Getting

**A production-ready mainnet configuration template for:**
- ✅ **10-of-15 Kaspa threshold** (66% Byzantine tolerance)
- ✅ **12-of-15 Hyperlane validators** (80% Byzantine tolerance)
- ✅ **Maximum security** (mainnet-grade validation)
- ✅ **Fully commented** (800+ lines, every parameter explained)
- ✅ **Complete deployment guide** (6 phases, step-by-step)

---

## Quick Start

### 1. Copy Template (2 minutes)

```bash
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra

# Copy to your config directory
cp docs/config/mainnet-config-template.toml /etc/igra/config.toml

# Secure permissions
chmod 600 /etc/igra/config.toml
```

---

### 2. Customize Template (1-2 hours)

**Replace ALL placeholders marked with `<REPLACE>`:**

```bash
# Search for placeholders
grep "<REPLACE" /etc/igra/config.toml

# You must replace (14 sections):
# 1. redeem_script_hex (10-of-15 redeem script)
# 2. member_pubkeys (15 signer pubkeys)
# 3. group_id (your unique group ID)
# 4. iroh.verifier_keys (15 peer verification keys)
# 5. iroh.bootstrap (seed node EndpointIDs)
# 6. iroh.bootstrap_addrs (seed node multiaddrs)
# 7. hyperlane.validators (15 validator pubkeys)
# 8-14. Per-profile mnemonics (one per signer)
```

**See:** [mainnet-deployment-guide.md](mainnet-deployment-guide.md) Phase 2 for detailed instructions

---

### 3. Generate Secrets (1 hour)

**Create encrypted secrets.bin:**

```bash
# Generate 15 mnemonics (one per signer)
# Generate 15 Iroh seeds (one per signer)
# Encrypt into secrets.bin
# Set IGRA_SECRETS_PASSPHRASE

# See deployment guide Phase 1 for complete instructions
```

---

### 4. Validate Configuration (15 minutes)

```bash
# Set passphrase
export IGRA_SECRETS_PASSPHRASE="<from-password-manager>"
export KASPA_IGRA_LOG_DIR="/var/log/igra"

# Validate without starting
kaspa-threshold-service \
    --network mainnet \
    --config /etc/igra/config.toml \
    --validate-only

# Must pass with 0 errors before proceeding
```

---

### 5. Deploy (2-4 hours)

**Start each signer:**

```bash
# Signer 1
kaspa-threshold-service --network mainnet --profile signer-01

# Signer 2 (different terminal/server)
kaspa-threshold-service --network mainnet --profile signer-02

# ... (up to signer-15)
```

**See:** [mainnet-deployment-guide.md](mainnet-deployment-guide.md) Phase 4 for deployment procedures

---

## Template Highlights

### Security Features

**✅ Maximum Security Configuration:**
- Encrypted secrets required (`use_encrypted_secrets = true`)
- Local RPC only (`node_rpc_url = "grpc://127.0.0.1:16110"`)
- Key audit logging enabled (`key_audit_log_path`)
- Transaction policy limits (`min/max amounts, daily volume`)
- Network mode validation (`network = "mainnet"`)
- File permission enforcement (0600/0700)

**✅ Byzantine Tolerance:**
- 10-of-15 Kaspa threshold (5 signers can fail/be malicious)
- 12-of-15 Hyperlane threshold (3 validators can fail)
- Geographically distributed (recommended)
- Pkarr discovery (automatic peer recovery)

**✅ Defense in Depth:**
- Circuit breaker (node RPC failures)
- Two-phase consensus (UTXO divergence prevention)
- CRDT garbage collection (storage management)
- Rate limiting (API abuse prevention)
- Session timeouts (prevent stale sessions)

---

### Operational Features

**✅ Multi-Signer Deployment:**
- 15 profiles defined (`[profiles.signer-01]` through `[profiles.signer-15]`)
- Per-signer data directories (`/var/lib/igra/signer-XX`)
- Per-signer RPC ports (8088-8102)
- Per-signer secrets (isolated keys)

**✅ Production-Ready:**
- Systemd unit file templates (included in guide)
- Log rotation support
- Monitoring endpoints
- Backup procedures
- Disaster recovery

**✅ Compliance-Ready:**
- Audit logging (forensic trail)
- Policy enforcement (transaction limits)
- Reason required (every transaction justified)
- Retention policies (CRDT GC)

---

## Configuration Size

**Template statistics:**
- **Lines:** 793 (comprehensive)
- **Comments:** ~300 lines (38% commented)
- **Sections:** 12 major sections
- **Parameters:** 50+ configured
- **Profiles:** 15 (one per signer)

**Why so large:**
- Complete configuration (nothing missing)
- Extensive comments (educational)
- All security settings (defense-in-depth)
- Production-ready (not minimal demo)

---

## What Makes This Template Special

### 1. Every Parameter Explained

**Not just values, but WHY:**
```toml
# REQUIRED: Minimum recipient amount (prevents tiny/spam transactions)
# Mainnet recommendation: 1000000 sompi (0.01 KAS)
min_recipient_amount_sompi = 1000000
```

**Benefit:** Operators understand what they're configuring

---

### 2. Security Warnings Throughout

```toml
# SECURITY: MUST be local (127.0.0.1/localhost) for mainnet
# Remote RPC nodes can lie about UTXO state → loss of funds
node_rpc_url = "grpc://127.0.0.1:16110"
```

**Benefit:** Security implications are clear

---

### 3. Complete Placeholders

```toml
# REPLACE with your actual 15 signer pubkeys
member_pubkeys = [
    "<REPLACE_PUBKEY_01>",  # Signer 1
    "<REPLACE_PUBKEY_02>",  # Signer 2
    ...
]
```

**Benefit:** Easy to find and replace (search for `<REPLACE`)

---

### 4. Production Best Practices

```toml
# RECOMMENDED: Daily volume limit (aggregate across all transactions)
# 5000 KAS per day = 5,000,000,000,000 sompi
# Resets at midnight UTC
max_daily_volume_sompi = 5000000000000
```

**Benefit:** Incorporates operational experience

---

### 5. Deployment Instructions Inline

```toml
# BEFORE FIRST START:
#
# 1. REPLACE ALL PLACEHOLDERS
# 2. GENERATE SECRETS
# 3. SET FILE PERMISSIONS
# ...
```

**Benefit:** Can't miss critical steps

---

## Comparison to Other Templates

| Template | Threshold | Comments | Security | Complexity | Audience |
|----------|-----------|----------|----------|------------|----------|
| **Devnet (existing)** | 2-of-3 | Minimal | Low | Low | Developers |
| **This template** | 10-of-15 | Extensive | Maximum | High | Production |
| **Examples (planned)** | Various | Moderate | Medium | Medium | Everyone |

**This template is for serious production deployments** (treasury, bridge, enterprise)

---

## Who Should Use This Template

### ✅ Use This Template If:

- Managing high-value funds ($1M+ equivalent)
- Enterprise deployment (regulated entity)
- Cross-chain bridge operation (Hyperlane)
- Need high Byzantine tolerance (5+ attacker resistance)
- Have 15+ participants willing to run signers
- Can afford operational complexity (15 servers, monitoring)

---

### ⚠️ Consider Simpler Config If:

- Lower value ($100k or less)
- Smaller team (3-5 participants)
- Simpler operations (fewer moving parts)
- Cost-sensitive (15 servers is expensive)
- Higher availability needs (10-of-15 requires many online)

**For smaller deployments:** See examples.md for 3-of-5 or 5-of-9 templates (when created)

---

## How to Use This Template

### For Operators

1. **Read:** [mainnet-deployment-guide.md](mainnet-deployment-guide.md) (1 hour)
2. **Plan:** Infrastructure (15 servers, networking)
3. **Execute:** Phase 1-6 in deployment guide (4-6 hours)
4. **Monitor:** Ongoing operations

**Total time:** 1-2 days for initial deployment

---

### For Auditors

1. **Read:** Template file (understand configuration)
2. **Review:** Security settings (all marked with SECURITY:)
3. **Verify:** Validation rules (mainnet requirements enforced)
4. **Check:** Network mode security (network-modes.md)
5. **Assess:** Byzantine tolerance (10-of-15 analysis)

**Audit areas:**
- Secret management (FileSecretStore, encrypted, file permissions)
- RPC security (local-only enforcement)
- Policy controls (amount limits, whitelists)
- Threshold validation (M ≤ N, M ≥ 2)
- Hyperlane security (12-of-15 validator threshold)

---

### For Architects

**Use this template to:**
- Understand production deployment model
- Design multi-signer infrastructure
- Plan network topology (co-located vs distributed)
- Estimate costs (infrastructure, operations)
- Assess operational complexity

**Extract patterns:**
- Profile system (per-signer overrides)
- Secret isolation (one mnemonic per signer)
- Network topology (seed nodes, pkarr discovery, relay)

---

## Files in This Directory

| File | Size | Purpose |
|------|------|---------|
| **mainnet-config-template.toml** | 793 lines | Production config (10-of-15) |
| **mainnet-deployment-guide.md** | 600+ lines | Step-by-step deployment |
| **README.md** | Updated | Navigation (includes template) |

---

## Next Steps

1. **Review template:** [mainnet-config-template.toml](mainnet-config-template.toml) (30 min)
2. **Read deployment guide:** [mainnet-deployment-guide.md](mainnet-deployment-guide.md) (1 hour)
3. **Plan infrastructure:** 15 servers, networking, monitoring (2-4 hours)
4. **Execute deployment:** Follow guide Phase 1-6 (6-10 hours)

---

## Related Documentation

**Configuration:**
- [Complete Configuration Reference](config.md) - All parameters
- [Service Configuration](service-config.md) - service.* details
- [Environment Variables](environment-variables.md) - Env var reference

**Security:**
- [Network Mode Security](network-modes.md) - Validation rules
- [Timing Attacks](../security/timing-attacks.md) - Cryptographic security
- [Key Management](../security/key-management-audit.md) - Key management audit

**Protocol:**
- [Two-Phase Consensus](../protocol/two-phase-consensus.md) - Consensus algorithm
- [Architecture](../protocol/architecture.md) - System design

---

**Status:** ✅ Production-ready template and deployment guide

**Ready to deploy?** Start with the [deployment guide](mainnet-deployment-guide.md)!
