# Igra Configuration Guide

**Version:** 0.5.0
**Last Updated:** 2026-01-24
**Status:** ✅ CURRENT

---

## Overview

Igra uses a layered TOML-based configuration system with environment variable overrides and profile support for multi-signer deployments.

**Configuration precedence (lowest to highest):**
```
1. Compiled defaults
2. TOML config file (igra-config.toml)
3. Profile overrides ([profiles.<name>])
4. Environment variables (IGRA_*)
```

---

## Quick Start

### Minimal Configuration

```toml
[service]
node_rpc_url = "grpc://127.0.0.1:16110"
network = "devnet"

[service.pskt]
redeem_script_hex = "52209601..."
sig_op_count = 2
#
# source_addresses is optional and derived from redeem_script_hex + service.network.
# source_addresses = ["kaspadev:qz..."]

[service.hd]
key_type = "hd_mnemonic" # devnet/testnet only
required_sigs = 2
```

**Run:**
```bash
kaspa-threshold-service --network devnet --config igra-config.toml --profile signer-01
```

---

## Configuration Sections

### Core Configuration

- **[service.*](service-config.md)** - Main service settings (RPC, data directory, secrets)
- **[service.pskt.*](pskt-config.md)** - Transaction builder (UTXOs, fees, outputs)
- **[service.hd.*](hd-wallet-config.md)** - HD wallet (mnemonics, derivation paths)
- **[group.*](group-config.md)** - Threshold group (M-of-N, member pubkeys)
- **[policy.*](policy-config.md)** - Transaction policy (amount limits, whitelists)

### Network & Transport

- **[iroh.*](iroh-config.md)** - P2P gossip (discovery, relay, bootstrap nodes)
- **[hyperlane.*](hyperlane-config.md)** - Cross-chain bridge (validators, ISM)
- **[layerzero.*](layerzero-config.md)** - LayerZero integration

### Protocol & Runtime

- **[two_phase.*](two-phase-config.md)** - Two-phase consensus (timeouts, quorum)
- **[runtime.*](runtime-config.md)** - Runtime behavior (timeouts, GC, testing)
- **[signing.*](signing-config.md)** - Signing backend selection

### API & Operations

- **[rpc.*](rpc-config.md)** - JSON-RPC API (listen address, auth, rate limiting)

---

## Environment Variables

See [environment-variables.md](environment-variables.md) for complete reference.

**Quick examples:**
```bash
# Override RPC URL
export IGRA_SERVICE__NODE_RPC_URL="grpc://10.0.0.1:16110"

# Set secrets passphrase (mainnet required)
export IGRA_SECRETS_PASSPHRASE="my-secure-passphrase"

# Enable pkarr discovery
export IGRA_IROH__DISCOVERY__ENABLE_PKARR=true
```

---

## Network Modes

Igra supports three network modes with different security validation levels:

| Mode | Security | Use Case |
|------|----------|----------|
| **mainnet** | Maximum (strict) | Production with real funds |
| **testnet** | Moderate (warnings) | Pre-production testing |
| **devnet** | Minimal (permissive) | Local development |

**See:** [network-modes.md](network-modes.md) for detailed security validation rules.

---

## Profile System

Profiles enable multi-signer deployments with per-signer overrides.

**Example:**
```toml
# Base configuration (shared)
[service]
data_dir = "/base"

[iroh]
group_id = "abc123"

# Profile: signer-1
[profiles.signer-1.service]
data_dir = "/base/signer-1"

[profiles.signer-1.iroh]
peer_id = "signer-1"
```

**Load specific profile:**
```bash
kaspa-threshold-service --profile signer-1
```

**See:** [profiles.md](profiles.md) for complete profile system documentation.

---

## Configuration Files

| File | Purpose | Audience |
|------|---------|----------|
| [config.md](config.md) | **Master reference** (all parameters) | Everyone |
| [service-config.md](service-config.md) | Service settings | Operators |
| [pskt-config.md](pskt-config.md) | Transaction builder | Operators |
| [hd-wallet-config.md](hd-wallet-config.md) | HD wallet setup | Operators |
| [group-config.md](group-config.md) | Threshold group | Operators |
| [policy-config.md](policy-config.md) | Transaction policy | Operators |
| [iroh-config.md](iroh-config.md) | P2P networking | Operators |
| [hyperlane-config.md](hyperlane-config.md) | Cross-chain bridge | Operators |
| [two-phase-config.md](two-phase-config.md) | Consensus protocol | Advanced |
| [runtime-config.md](runtime-config.md) | Runtime behavior | Advanced |
| [rpc-config.md](rpc-config.md) | API server | Operators |
| [environment-variables.md](environment-variables.md) | Env var reference | Everyone |
| [profiles.md](profiles.md) | Profile system | Operators |
| [examples.md](examples.md) | Complete examples | Everyone |
| [validation.md](validation.md) | Validation rules | Advanced |
| [network-modes.md](network-modes.md) | Security validation | Operators |
| [iroh-discovery.md](iroh-discovery.md) | P2P discovery (pkarr, relay) | Operators |

---

## Example Configurations

### Production Template

**⭐ [mainnet-config-template.toml](mainnet-config-template.toml)** - Complete 10-of-15 mainnet template
- 15 Kaspa signers (10-of-15 threshold)
- 15 Hyperlane validators (12-of-15 threshold)
- Comprehensive security settings
- Fully commented (every parameter explained)
- Production-ready (800+ lines)

**📖 [mainnet-deployment-guide.md](mainnet-deployment-guide.md)** - Step-by-step deployment
- Key generation procedures
- Configuration setup (6 phases)
- Systemd unit files
- Monitoring and operations
- Troubleshooting
- Cost estimates

### By Environment

- **[Devnet](examples.md#devnet-configuration)** - Local development
- **[Testnet](examples.md#testnet-configuration)** - Pre-production testing
- **⭐ [Mainnet](mainnet-config-template.toml)** - **Production (10-of-15 template)**

### By Setup Type

- **[Single Node](examples.md#single-node-setup)** - Standalone signing
- **[Multi-Signer](examples.md#multi-signer-setup)** - Distributed threshold (2-of-3, 3-of-5)
- **⭐ [10-of-15 Multi-Signer](mainnet-config-template.toml)** - **Enterprise production**
- **[With Hyperlane](examples.md#hyperlane-bridge-setup)** - Cross-chain signing

---

## Configuration Validation

**Validate config without starting service:**
```bash
kaspa-threshold-service --network mainnet --config config.toml --validate-only
```

**See:** [validation.md](validation.md) for complete validation rules and network mode impact.

---

## Troubleshooting

**Common configuration errors:**

| Error | Cause | Fix |
|-------|-------|-----|
| "Missing service.pskt.source_addresses" | Could not derive source address | Set `service.network` + `service.pskt.redeem_script_hex` (or provide a matching `source_addresses`) |
| "Threshold m > n" | Invalid threshold | Ensure m ≤ n |
| "Remote RPC not allowed in mainnet" | Security violation | Use local RPC or add --allow-remote-rpc |
| "Missing IGRA_SECRETS_PASSPHRASE" | Mainnet secret requirement | Set env var |

**See:** [validation.md](validation.md) for complete error reference.

---

## Migration from Legacy Config

If you're migrating from old configuration format:

**Legacy (pre-v0.4):**
```toml
[multisig]
required_signatures = 2
```

**Current (v0.5+):**
```toml
[group]
threshold_m = 2
threshold_n = 3
```

**See:** [migration.md](migration.md) for complete migration guide (if needed).

---

## Related Documentation

- **Security:** [NetworkMode Security](network-modes.md) - Security validation rules
- **Discovery:** [Iroh Discovery](iroh-discovery.md) - P2P discovery (pkarr, DHT, relay)
- **Secrets:** [hd-wallet-config.md](hd-wallet-config.md) - Secret management
- **API:** [rpc-config.md](rpc-config.md) - JSON-RPC server

---

**Next:** Read [config.md](config.md) for complete parameter reference, or jump to specific section documentation.
