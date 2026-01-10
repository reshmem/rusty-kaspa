# Key Management Security Analysis

**Document ID**: KEY-MGMT-001
**Classification**: Internal Security Review
**Status**: TODO - Critical Priority
**Created**: 2026-01-10
**Related**: IGRA-SERVICE-DEEP-DIVE.md, IDENTITY-SECURITY-TODO.md

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current Key Material Inventory](#current-key-material-inventory)
3. [Identity Initialization Flow](#identity-initialization-flow)
4. [Critical Security Issues](#critical-security-issues)
5. [Current identity.json Structure (INSECURE)](#current-identityjson-structure-insecure)
6. [Threat Analysis](#threat-analysis)
7. [Recommendations](#recommendations)
8. [Target Architecture](#target-architecture)

---

## Executive Summary

**Rating**: **CRITICAL - NEEDS IMMEDIATE ATTENTION**

Ed25519 signing seeds and other key material are stored in plaintext in configuration files and auto-generated `identity.json`. Any filesystem access compromises signer identity completely.

### Key Issues

| Issue | Severity | Location |
|-------|----------|----------|
| Plaintext seed in config | **CRITICAL** | `IrohRuntimeConfig.signer_seed_hex` |
| Plaintext seed in file | **CRITICAL** | `identity.json` |
| No seed rotation mechanism | HIGH | N/A |
| Weak peer ID generation | MEDIUM | `setup.rs:217-218` |
| No HSM/enclave integration | HIGH | N/A |

---

## Current Key Material Inventory

| Asset | Type | Storage | Protection | Risk |
|-------|------|---------|------------|------|
| **Ed25519 signing seed** | 32-byte secret | `identity.json` or config | **NONE** | CRITICAL |
| **HD wallet mnemonics** | BIP39 words | `encrypted_mnemonics` in config | Encrypted (kaspa-wallet) | MEDIUM |
| **Iroh transport seed** | 32-byte secret | Derived from signer seed | **NONE** | HIGH |
| **Peer verifier keys** | Ed25519 pubkeys | Config `verifier_keys` | N/A (public) | LOW |

---

## Identity Initialization Flow

**Location**: `igra-service/src/bin/kaspa-threshold-service/setup.rs:190-224`

```
┌─────────────────────────────────────────────────────────────────────┐
│                    IDENTITY INITIALIZATION                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Check config for peer_id + signer_seed_hex                      │
│      │                                                              │
│      ├─ Present → Use configured values                             │
│      │                                                              │
│      └─ Missing → load_or_create_iroh_identity()                    │
│                      │                                              │
│                      ├─ Check {data_dir}/iroh/identity.json         │
│                      │                                              │
│                      ├─ Exists → Load peer_id + seed_hex            │
│                      │                                              │
│                      └─ Missing → Generate random seed (OsRng)      │
│                                   Write to identity.json ❌ PLAINTEXT│
│                                                                     │
│  2. Derive Ed25519 signer from seed                                 │
│                                                                     │
│  3. Build verifier with known peer pubkeys                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Code Reference

```rust
// setup.rs:190-224
fn load_or_create_iroh_identity(data_dir: &str) -> Result<(PeerId, String), ThresholdError> {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct IdentityRecord {
        peer_id: String,
        seed_hex: String,  // ❌ PLAINTEXT 32-byte secret
    }
    // ...
    // Writes plaintext seed to disk
    std::fs::write(&identity_path, json)?;
}
```

---

## Critical Security Issues

### 1. Plaintext Seed in Config File

**Location**: `IrohRuntimeConfig.signer_seed_hex`

```rust
// infrastructure/config/types.rs
pub struct IrohRuntimeConfig {
    pub signer_seed_hex: Option<String>,  // ❌ 32-byte hex, plaintext
    // ...
}
```

**Impact**: Config file exposure compromises all signers using that config.

### 2. Plaintext Seed in identity.json

**Location**: `{data_dir}/iroh/identity.json`

**Impact**: Any filesystem read access (backup, log shipping, container escape) exposes signing key.

### 3. No Key Rotation Mechanism

**Current State**: No way to rotate keys without manual reconfiguration of all peers.

**Impact**: Compromised key remains valid indefinitely. No forward secrecy.

### 4. Weak Peer ID Generation

**Location**: `setup.rs:217-218`

```rust
let mut peer_id_bytes = [0u8; 16];
rand::rngs::OsRng.fill_bytes(&mut peer_id_bytes);
let record = IdentityRecord {
    peer_id: format!("peer-{}", hex::encode(peer_id_bytes)),  // Random, not derived
    // ...
};
```

**Issue**: Peer ID is random, not cryptographically bound to the public key. Should derive peer_id from Ed25519 public key for binding.

### 5. No HSM/Enclave Integration

**Current State**: All signing operations use in-memory keys loaded from plaintext.

**Impact**: No hardware protection. Memory dumps expose keys.

---

## Current identity.json Structure (INSECURE)

```json
{
  "peer_id": "peer-a1b2c3d4e5f6...",
  "seed_hex": "deadbeef...32 bytes...cafebabe"
}
```

**Problems**:
- `seed_hex` is the raw 32-byte Ed25519 seed in hex
- No encryption
- No integrity protection
- No version field for migration

---

## Threat Analysis

### Threat: Filesystem Access

| Vector | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Container escape | MEDIUM | CRITICAL | Encrypt at rest |
| Backup exposure | HIGH | CRITICAL | Encrypt at rest |
| Log aggregation | MEDIUM | CRITICAL | Never log seeds |
| Insider access | MEDIUM | CRITICAL | HSM integration |

### Threat: Memory Extraction

| Vector | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Core dump | LOW | CRITICAL | Disable core dumps |
| Memory forensics | LOW | CRITICAL | HSM/enclave |
| Side-channel | LOW | HIGH | Constant-time ops |

### Threat: Key Compromise Response

| Scenario | Current Response | Target Response |
|----------|------------------|-----------------|
| Single key compromised | Manual reconfig | Automated rotation |
| Threshold breach | Total loss | Key refresh protocol |
| Insider threat | Undetectable | Audit + HSM logging |

---

## Recommendations

### Immediate (P0)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 1 | Encrypt `identity.json` with passphrase | 2-4 hours | Prevents plaintext exposure |
| 2 | Remove `signer_seed_hex` from config, require identity.json | 1-2 hours | Single source of truth |
| 3 | Derive peer_id from Ed25519 pubkey | 1-2 hours | Cryptographic binding |
| 4 | Add version field to identity.json | 30 min | Migration support |

### Short-Term (P1)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 5 | Implement key rotation protocol | 1 week | Limits compromise window |
| 6 | Add key access audit logging | 4-8 hours | Forensics capability |
| 7 | Add `--passphrase` CLI with env var fallback | 2-4 hours | Operational flexibility |

### Medium-Term (P2)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 8 | HSM integration (PKCS#11) | 1-2 weeks | Hardware key protection |
| 9 | YubiKey/Ledger support | 1 week | Operator-held keys |
| 10 | SGX/SEV enclave integration | 2-4 weeks | Memory protection |
| 11 | Proactive secret sharing refresh | 2-3 weeks | Forward secrecy |

---

## Target Architecture

### Encrypted identity.json (Phase 1)

```json
{
  "version": 2,
  "peer_id": "peer-<base58-of-pubkey>",
  "encrypted_seed": {
    "ciphertext": "base64...",
    "nonce": "base64...",
    "kdf": {
      "algorithm": "argon2id",
      "salt": "base64...",
      "memory_kib": 65536,
      "iterations": 3,
      "parallelism": 4
    }
  },
  "created_at": "2026-01-10T00:00:00Z",
  "rotated_from": null
}
```

### Key Derivation (Phase 1)

```
passphrase
    │
    ▼
┌─────────────────┐
│   Argon2id      │
│  (salt, params) │
└────────┬────────┘
         │
         ▼
    32-byte key
         │
         ▼
┌─────────────────┐
│ ChaCha20-Poly1305│
│    decrypt      │
└────────┬────────┘
         │
         ▼
   Ed25519 seed
         │
         ▼
┌─────────────────┐
│ Ed25519 keygen  │
└────────┬────────┘
         │
         ├──► signing_key (secret)
         └──► verifying_key (public) ──► peer_id
```

### HSM Architecture (Phase 2)

```
┌─────────────────────────────────────────────────────────────────┐
│                        Igra Service                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────┐     ┌─────────────────────────────────┐  │
│   │   KeyStore      │     │        SignerBackend            │  │
│   │   (trait)       │     │        (trait)                  │  │
│   └────────┬────────┘     └────────────────┬────────────────┘  │
│            │                               │                    │
│   ┌────────┴────────────────┬──────────────┴─────────┐         │
│   │                         │                        │         │
│   ▼                         ▼                        ▼         │
│ ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│ │ FileKeyStore │  │  Pkcs11KeyStore  │  │  EnclaveKeyStore │  │
│ │ (encrypted)  │  │  (HSM)           │  │  (SGX/SEV)       │  │
│ └──────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Rotation Protocol (Phase 2)

```
┌─────────────────────────────────────────────────────────────────┐
│                    KEY ROTATION PROTOCOL                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Operator initiates rotation (CLI command)                   │
│                          │                                      │
│                          ▼                                      │
│  2. Generate new Ed25519 keypair                                │
│                          │                                      │
│                          ▼                                      │
│  3. Announce new pubkey to peers (signed by old key)            │
│                          │                                      │
│                          ▼                                      │
│  4. Wait for threshold acknowledgments                          │
│                          │                                      │
│                          ▼                                      │
│  5. Atomic switch to new key                                    │
│                          │                                      │
│                          ▼                                      │
│  6. Archive old key (retain for verification of old sigs)       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Migration Path

### v1 → v2 (Plaintext → Encrypted)

```bash
# Detect v1 identity
$ kaspa-threshold-service --migrate-identity

# Prompts for passphrase
Enter passphrase for identity encryption: ********
Confirm passphrase: ********

# Backs up old file
Backed up identity.json to identity.json.v1.bak

# Writes encrypted v2
Migrated identity to encrypted format (v2)
```

### Startup with v2

```bash
# Via CLI flag
$ kaspa-threshold-service --passphrase-file /run/secrets/passphrase

# Via environment variable
$ KASPA_IGRA_PASSPHRASE=... kaspa-threshold-service

# Interactive prompt (if TTY)
$ kaspa-threshold-service
Enter identity passphrase: ********
```

---

## Security Checklist

### Before Production

- [ ] identity.json encrypted with passphrase
- [ ] signer_seed_hex removed from config schema
- [ ] peer_id derived from pubkey
- [ ] Key access events audited
- [ ] Core dumps disabled in container
- [ ] Filesystem permissions restricted (0600)

### For High-Value Deployments

- [ ] HSM integration enabled
- [ ] Key rotation tested
- [ ] Backup/recovery procedure documented
- [ ] Incident response playbook for key compromise

---

**End of Document**
