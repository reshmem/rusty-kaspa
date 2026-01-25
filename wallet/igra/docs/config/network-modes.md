# Network Mode Security - Implementation Guide

**Feature**: Network-aware security validation (Mainnet/Testnet/Devnet)

**Security Principle**: Defense in depth with strictness proportional to value at risk

**Timeline**: ~1 week implementation + testing

---

## Table of Contents

1. [Overview](#overview)
2. [Security Philosophy](#security-philosophy)
3. [Network Mode Definitions](#network-mode-definitions)
4. [Security Validation Rules](#security-validation-rules)
5. [RPC Security Model](#rpc-security-model)
6. [Implementation](#implementation)
7. [CLI Integration](#cli-integration)
8. [Configuration Schema](#configuration-schema)
9. [Validation Flow](#validation-flow)
10. [Testing Strategy](#testing-strategy)
11. [Deployment Guide](#deployment-guide)

---

## Overview

### What This Adds

Network mode determines the **security posture** of the Igra service:

```
--mainnet  → MAXIMUM SECURITY (zero tolerance for misconfigurations)
--testnet  → MODERATE SECURITY (warnings, reasonable defaults)
--devnet   → FLEXIBLE SECURITY (development-friendly, minimal checks)
```

**Default**: `--mainnet` (safe by default)

### Goals

1. **Prevent production misconfigurations** - Catch security issues at startup
2. **Clear security contracts** - Each mode has explicit guarantees
3. **Defense in depth** - Multiple layers of validation
4. **Fail-safe defaults** - Mainnet by default, explicit opt-in to relaxed modes

---

## Security Philosophy

### Core Principles

1. **Mainnet = Real Money** → Zero tolerance for security weaknesses
2. **Local-First RPC** → Trust local nodes, distrust remote endpoints
3. **Explicit is Better** → No "magic" remote connections without user consent
4. **Fail Fast** → Invalid configurations rejected at startup (not runtime)
5. **Audit Everything** → All security-relevant operations logged

### Threat Model (Mainnet)

**Threats we protect against:**
- ❌ Accidental secret exposure (env vars, logs, world-readable files)
- ❌ Untrusted RPC endpoints (MITM, malicious nodes)
- ❌ Configuration drift (test config accidentally used in production)
- ❌ Weak authentication (default passwords, missing tokens)
- ❌ Logging secrets (debug logs leaking sensitive data)
- ❌ Privilege escalation (running as root)

**Out of scope:**
- Physical security of host machine
- Network-level attacks (DDoS, etc.)
- Cryptographic attacks on algorithms themselves

---

## Network Mode Definitions

### Mainnet Mode

**Purpose**: Production deployment with real funds

**Security Level**: MAXIMUM (strict enforcement)

**Characteristics**:
- Real Kaspa mainnet addresses (`kaspa:` prefix)
- BIP44 coin type `111110` (Kaspa mainnet)
- Encrypted secrets required
- Audit logging mandatory
- Local RPC required (unless explicitly allowed)
- No debug/trace logging
- Strict file permissions (0600/0700)
- Comprehensive validation at startup

**When to use**: Production deployments handling real KAS

---

### Testnet Mode

**Purpose**: Pre-production testing, staging environments

**Security Level**: MODERATE (warnings, not failures)

**Characteristics**:
- Testnet addresses (`kaspatest:` prefix)
- BIP44 coin type `111111` (Kaspa testnet)
- Encrypted secrets recommended (warnings if not)
- Audit logging recommended
- Remote RPC allowed with warnings
- Debug logging allowed
- File permissions validated (warnings)
- Most validations warn instead of fail

**When to use**: Integration testing, staging, testnet multisig

---

### Devnet Mode

**Purpose**: Local development, testing, CI/CD

**Security Level**: FLEXIBLE (minimal restrictions)

**Characteristics**:
- Devnet addresses (`kaspadev:` prefix)
- BIP44 coin type `111111` (testnet/devnet shared)
- Environment variable secrets allowed
- Audit logging optional
- Any RPC configuration allowed
- Trace logging allowed
- File permissions not enforced
- Minimal validation (just syntax)

**When to use**: Local development, CI, automated testing

---

## Security Validation Rules

### 1. Secret Management

| Validation | Mainnet | Testnet | Devnet |
|-----------|---------|---------|--------|
| **Encrypted secrets required** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Reject KASPA_IGRA_WALLET_SECRET env var** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Reject default/test secrets** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Audit logging required** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Passphrase from stdin** | ✅ ERROR | ℹ️ ALLOWED | ℹ️ ALLOWED |
| **Secrets file permissions 0600** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |

**Mainnet Rules**:
```rust
// MUST use FileSecretStore
if !config.use_encrypted_secrets {
    return Err("Mainnet requires encrypted secrets file (set use_encrypted_secrets=true)");
}

// MUST NOT use legacy env var
if env::var("KASPA_IGRA_WALLET_SECRET").is_ok() {
    return Err("Mainnet forbids KASPA_IGRA_WALLET_SECRET - use secrets.bin");
}

// MUST have audit logging
if config.key_audit_log_path.is_none() {
    return Err("Mainnet requires audit logging (set key_audit_log_path)");
}

// MUST NOT prompt for passphrase interactively
if config.secrets_passphrase_source == PassphraseSource::Stdin {
    return Err("Mainnet forbids interactive passphrase - set IGRA_SECRETS_PASSPHRASE env var or use keyring");
}

// Validate secrets file permissions (Unix only)
#[cfg(unix)]
{
    let mode = fs::metadata(&secrets_path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!("Mainnet secrets file must be 0600, got {:o}", mode));
    }
}
```

---

### 2. RPC Security Model

**CRITICAL SECURITY PRINCIPLE**: In mainnet, trust **only local nodes** by default.

| Validation | Mainnet | Testnet | Devnet |
|-----------|---------|---------|--------|
| **Require localhost RPC** | ✅ ERROR if remote | ⚠️ WARNING | ℹ️ ALLOWED |
| **Allow remote with flag** | `--allow-remote-rpc` | Not needed | Not needed |
| **Require TLS for remote** | ✅ ERROR if no TLS | ⚠️ WARNING | ℹ️ ALLOWED |
| **Validate RPC auth token** | ✅ ERROR if missing | ⚠️ WARNING | ℹ️ ALLOWED |

#### Why Local-Only RPC in Mainnet?

**Security Rationale**:
1. **Trust Boundary**: Your local Kaspa node is under your control
2. **No MITM**: Localhost traffic cannot be intercepted on network
3. **Performance**: Lower latency, no network issues
4. **Reliability**: No external dependencies for RPC
5. **Auditability**: Your node, your validation rules

**Remote RPC Risks**:
- ❌ Malicious node can lie about UTXO state
- ❌ MITM attack can modify transactions
- ❌ Network failures can cause loss of funds
- ❌ Third-party can track your transactions
- ❌ Rate limiting / censorship possible

#### Mainnet RPC Validation

```rust
fn validate_kaspa_rpc_endpoint(config: &ServiceConfig, network_mode: NetworkMode) -> Result<(), ThresholdError> {
    let node_url = &config.node_url;

    match network_mode {
        NetworkMode::Mainnet => {
            // Parse URL
            let url = Url::parse(node_url)
                .map_err(|e| format!("Invalid node_url: {}", e))?;

            let host = url.host_str()
                .ok_or("Missing host in node_url")?;

            // Check if localhost
            let is_local = host == "localhost"
                || host == "127.0.0.1"
                || host == "::1"
                || host.starts_with("127.")
                || host == "[::1]";

            if !is_local {
                // Remote RPC endpoint detected
                if !config.allow_remote_rpc {
                    return Err(format!(
                        "Mainnet requires local Kaspa RPC endpoint. \
                        Got: {}\n\
                        \n\
                        To use remote RPC (NOT RECOMMENDED), add --allow-remote-rpc flag.\n\
                        \n\
                        Security warning: Remote RPC endpoints can:\n\
                        - Lie about UTXO state\n\
                        - Track your transactions\n\
                        - Censor your operations\n\
                        \n\
                        Recommended: Run local kaspad node on same machine.",
                        node_url
                    ));
                }

                // If remote allowed, enforce TLS
                let scheme = url.scheme();
                if scheme != "grpcs" && scheme != "https" {
                    return Err(format!(
                        "Mainnet remote RPC must use secure protocol (grpcs:// or https://). \
                        Got: {}",
                        node_url
                    ));
                }

                // Require authentication for remote
                if !node_url.contains("@") && config.node_rpc_auth_token.is_none() {
                    return Err(
                        "Mainnet remote RPC requires authentication token"
                    );
                }

                // Log security warning
                log::warn!(
                    "⚠️  SECURITY WARNING: Using remote RPC endpoint in mainnet: {}",
                    node_url
                );
                log::warn!(
                    "⚠️  You are trusting {} to provide accurate blockchain data",
                    host
                );
            } else {
                // Local RPC - all good!
                log::info!("✓ Using local Kaspa RPC endpoint: {}", node_url);
            }
        }

        NetworkMode::Testnet => {
            // Warn if remote and insecure
            if node_url.starts_with("http://") && !node_url.contains("127.0.0.1") {
                log::warn!(
                    "Testnet using insecure remote RPC: {} (consider grpcs:// or local node)",
                    node_url
                );
            }
        }

        NetworkMode::Devnet => {
            // Allow anything
        }
    }

    Ok(())
}
```

**Example Mainnet Configurations**:

✅ **GOOD** (Local RPC):
```toml
# igra-config.toml
network = "mainnet"
node_url = "grpc://127.0.0.1:16110"
```

✅ **GOOD** (Local RPC with TLS):
```toml
network = "mainnet"
node_url = "grpcs://localhost:16110"
```

❌ **BAD** (Remote RPC without flag):
```toml
network = "mainnet"
node_url = "grpc://kaspa-node.example.com:16110"  # ERROR: remote not allowed
```

✅ **ACCEPTABLE** (Remote RPC with explicit flag):
```toml
network = "mainnet"
node_url = "grpcs://kaspa-node.example.com:16110"
allow_remote_rpc = true  # Or --allow-remote-rpc CLI flag
```

---

### 3. Iroh P2P Configuration

**INTENTIONALLY FLEXIBLE** - All configurations allowed in all modes.

| Configuration | Mainnet | Testnet | Devnet |
|--------------|---------|---------|--------|
| **Bootstrap nodes** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED |
| **DNS discovery** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED |
| **PKARR public services** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED |
| **Custom bootstrap** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED |
| **No bootstrap (pure DHT)** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED |

**Rationale**: Different deployment models require different P2P strategies:

1. **Preconfigured Bootstrap Nodes** - Some groups use known signers as bootstrap
2. **Public Discovery** - Some rely on DNS/PKARR for dynamic discovery
3. **Private Networks** - Some use custom bootstrap for isolated signing groups
4. **Hybrid** - Some combine multiple discovery methods

**No validation needed** - Iroh handles peer discovery security internally via:
- Ed25519 peer authentication
- Encrypted transport (QUIC + TLS 1.3)
- Peer ID verification

```rust
fn validate_iroh_config(config: &ServiceConfig, network_mode: NetworkMode) -> Result<(), ThresholdError> {
    // No restrictions on Iroh configuration in any network mode
    // All P2P configurations are intentionally allowed

    match &config.iroh_bootstrap_nodes {
        Some(nodes) if !nodes.is_empty() => {
            log::info!("Using {} preconfigured bootstrap nodes", nodes.len());
        }
        Some(_) | None => {
            log::info!("Using DNS/PKARR discovery for Iroh peer discovery");
        }
    }

    Ok(())
}
```

---

### 4. Configuration Validation

| Validation | Mainnet | Testnet | Devnet |
|-----------|---------|---------|--------|
| **Explicit network confirmation** | ✅ ERROR | ⚠️ WARNING | ℹ️ OPTIONAL |
| **Address prefix matches mode** | ✅ ERROR | ✅ ERROR | ℹ️ ALLOWED |
| **Derivation path coin type** | ✅ ERROR | ✅ ERROR | ℹ️ ALLOWED |
| **No test/default values** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Threshold m <= n** | ✅ ERROR | ✅ ERROR | ✅ ERROR |
| **Threshold m >= 2** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |

**Mainnet Rules**:
```rust
// MUST explicitly confirm network
if config.network != Some("mainnet") {
    return Err(
        "Mainnet mode requires explicit 'network = \"mainnet\"' in config \
        (prevents accidental use of test config)"
    );
}

// MUST use mainnet addresses
for addr in &config.source_addresses {
    if !addr.starts_with("kaspa:") {
        return Err(format!(
            "Mainnet address {} invalid (must start with 'kaspa:')",
            addr
        ));
    }
}

// MUST use mainnet coin type in derivation paths
let mainnet_coin_type = "111110";
for (profile_name, profile) in &config.profiles {
    if profile.key_type == KeyType::HdMnemonic {
        if !profile.derivation_path.contains(mainnet_coin_type) {
            return Err(format!(
                "Profile {} uses non-mainnet coin type in derivation path. \
                Expected m/45'/{}'/ for mainnet",
                profile_name, mainnet_coin_type
            ));
        }
    }
}

// MUST NOT use test/placeholder values
if config.data_dir.to_str().unwrap_or("").contains("devnet")
    || config.data_dir.to_str().unwrap_or("").contains("test") {
    return Err(
        "Mainnet data directory path contains 'devnet' or 'test' \
        (suggests test configuration being used)"
    );
}

// MUST have reasonable threshold
if config.group.threshold_m > config.group.threshold_n {
    return Err(format!(
        "Invalid threshold: m={} > n={}",
        config.group.threshold_m, config.group.threshold_n
    ));
}

if config.group.threshold_m < 2 {
    return Err(
        "Mainnet requires threshold m >= 2 (single signer is insecure)"
    );
}

// MUST have sufficient signers
if config.profiles.len() < config.group.threshold_m {
    return Err(format!(
        "Insufficient profiles: {} configured, need at least {}",
        config.profiles.len(),
        config.group.threshold_m
    ));
}
```

---

### 5. Logging Security

| Validation | Mainnet | Testnet | Devnet |
|-----------|---------|---------|--------|
| **Forbid DEBUG/TRACE levels** | ✅ ERROR | ℹ️ ALLOWED | ℹ️ ALLOWED |
| **Require INFO or higher** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Require log rotation** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Validate log file permissions** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |

**Mainnet Rules**:
```rust
// Check RUST_LOG environment variable
let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

if rust_log.to_lowercase().contains("debug")
    || rust_log.to_lowercase().contains("trace") {
    return Err(
        "Mainnet forbids DEBUG/TRACE logging (risk of secret exposure). \
        Set RUST_LOG=info or RUST_LOG=warn"
    );
}

// MUST have log rotation configured
if config.log_max_size.is_none() || config.log_max_files.is_none() {
    return Err(
        "Mainnet requires log rotation (set log_max_size and log_max_files)"
    );
}

// Validate log directory permissions
#[cfg(unix)]
{
    let log_dir = config.log_dir.as_ref()
        .unwrap_or(&config.data_dir.join("logs"));

    if log_dir.exists() {
        let mode = fs::metadata(log_dir)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "Mainnet log directory {:?} has insecure permissions {:o} \
                (expected 0700 - owner only)",
                log_dir, mode
            ));
        }
    }
}
```

---

### 6. File System Security

| Validation | Mainnet | Testnet | Devnet |
|-----------|---------|---------|--------|
| **Data directory 0700** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Config file 0600** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Secrets file 0600** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Audit log 0600** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Reject running as root** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |

**Mainnet Rules (Unix only)**:
```rust
#[cfg(target_family = "unix")]
fn validate_file_permissions(config: &ServiceConfig) -> Result<(), ThresholdError> {
    use std::os::unix::fs::PermissionsExt;

    // Check data directory
    let data_mode = fs::metadata(&config.data_dir)?.permissions().mode() & 0o777;
    if data_mode != 0o700 {
        return Err(format!(
            "Mainnet data directory must be 0700 (owner only), got {:o}. \
            Fix with: chmod 700 {:?}",
            data_mode, config.data_dir
        ));
    }

    // Check config file (if path known)
    if let Some(config_path) = &config.config_file_path {
        let config_mode = fs::metadata(config_path)?.permissions().mode() & 0o777;
        if config_mode != 0o600 {
            return Err(format!(
                "Mainnet config file must be 0600, got {:o}. \
                Fix with: chmod 600 {:?}",
                config_mode, config_path
            ));
        }
    }

    // Check secrets file
    if let Some(secrets_path) = &config.secrets_file {
        let secrets_mode = fs::metadata(secrets_path)?.permissions().mode() & 0o777;
        if secrets_mode != 0o600 {
            return Err(format!(
                "Mainnet secrets file must be 0600, got {:o}. \
                Fix with: chmod 600 {:?}",
                secrets_mode, secrets_path
            ));
        }
    }

    // Check not running as root
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        return Err(
            "Mainnet service must not run as root. \
            Create dedicated user: sudo useradd -r -s /bin/false igra-service"
        );
    }

    Ok(())
}
```

---

### 7. Startup Validation

| Check | Mainnet | Testnet | Devnet |
|-------|---------|---------|--------|
| **Kaspa node connectivity** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **All secrets accessible** | ✅ ERROR | ✅ ERROR | ✅ ERROR |
| **Disk space available** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Memory available** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Open file limits** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |
| **Core dumps disabled** | ✅ ERROR | ⚠️ WARNING | ℹ️ ALLOWED |

**Mainnet Rules**:
```rust
async fn validate_startup_readiness(
    config: &ServiceConfig,
    key_manager: &Arc<dyn KeyManager>,
) -> Result<(), ThresholdError> {
    // MUST connect to Kaspa node
    let node_info = kaspa_client::get_info(&config.node_url)
        .await
        .map_err(|e| format!(
            "Failed to connect to Kaspa node at {}: {}. \
            Ensure kaspad is running and accessible.",
            config.node_url, e
        ))?;

    // MUST be on correct network
    if !node_info.network_id.contains("mainnet") {
        return Err(format!(
            "Kaspa node is on network '{}', expected mainnet",
            node_info.network_id
        ));
    }

    // MUST have all required secrets
    let required_secrets = vec![
        KeyRef::new("igra.hd", "wallet_secret"),
        // Add all profile mnemonics/keys
    ];

    for key_ref in &required_secrets {
        key_manager.secret_store()
            .ok_or("No SecretStore")?
            .get(&key_ref.qualified_name().into())
            .await
            .map_err(|e| format!(
                "Missing required secret: {} ({})",
                key_ref.qualified_name(), e
            ))?;
    }

    // MUST have sufficient disk space (at least 10GB)
    let available_space = fs_available_space(&config.data_dir)?;
    if available_space < 10 * 1024 * 1024 * 1024 {
        return Err(format!(
            "Insufficient disk space: {} GB available, need at least 10 GB",
            available_space / (1024 * 1024 * 1024)
        ));
    }

    // MUST have sufficient memory (at least 1GB)
    let available_memory = system_available_memory()?;
    if available_memory < 1024 * 1024 * 1024 {
        return Err(format!(
            "Insufficient memory: {} MB available, need at least 1 GB",
            available_memory / (1024 * 1024)
        ));
    }

    // MUST have reasonable open file limits
    #[cfg(unix)]
    {
        let (soft_limit, hard_limit) = get_file_limits()?;
        if soft_limit < 4096 {
            return Err(format!(
                "Open file limit too low: {} (need at least 4096). \
                Set with: ulimit -n 4096",
                soft_limit
            ));
        }
    }

    // MUST disable core dumps in mainnet
    #[cfg(unix)]
    {
        let core_limit = get_core_dump_limit()?;
        if core_limit != 0 {
            return Err(
                "Core dumps must be disabled in mainnet (may contain secrets). \
                Set with: ulimit -c 0"
            );
        }
    }

    Ok(())
}
```

---

## Implementation

### File Structure

```
igra-core/src/infrastructure/
├── network_mode/
│   ├── mod.rs                    # NetworkMode enum, exports
│   ├── validator.rs              # SecurityValidator
│   ├── rules/
│   │   ├── mod.rs
│   │   ├── secrets.rs           # Secret management rules
│   │   ├── rpc.rs               # RPC endpoint validation
│   │   ├── config.rs            # Configuration validation
│   │   ├── logging.rs           # Logging security
│   │   ├── filesystem.rs        # File permissions
│   │   └── startup.rs           # Startup checks
│   └── report.rs                # ValidationReport
```

### Core Types

**File**: `igra-core/src/infrastructure/network_mode/mod.rs`

```rust
//! Network mode security validation

use serde::{Deserialize, Serialize};
use std::fmt;

/// Network mode determines security posture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Production network with real funds
    ///
    /// Enforces maximum security:
    /// - Encrypted secrets required
    /// - Local RPC required (unless explicitly allowed)
    /// - Audit logging mandatory
    /// - Strict file permissions
    /// - No debug logging
    /// - Comprehensive validation
    Mainnet,

    /// Test network for pre-production validation
    ///
    /// Moderate security with warnings:
    /// - Encrypted secrets recommended
    /// - Remote RPC allowed with warnings
    /// - Audit logging recommended
    /// - File permissions validated
    /// - Debug logging allowed
    Testnet,

    /// Development network for local testing
    ///
    /// Minimal restrictions:
    /// - Environment secrets allowed
    /// - Any RPC configuration allowed
    /// - Audit logging optional
    /// - File permissions not enforced
    /// - Trace logging allowed
    Devnet,
}

impl NetworkMode {
    /// Parse from CLI flag or config string
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "devnet" => Ok(Self::Devnet),
            _ => Err(format!(
                "Invalid network mode: '{}'. Must be: mainnet, testnet, or devnet",
                s
            )),
        }
    }

    /// Check if this is a production network
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Mainnet)
    }

    /// Get expected Kaspa address prefix
    pub fn address_prefix(&self) -> &'static str {
        match self {
            Self::Mainnet => "kaspa:",
            Self::Testnet => "kaspatest:",
            Self::Devnet => "kaspadev:",
        }
    }

    /// Get BIP44 coin type
    pub fn coin_type(&self) -> &'static str {
        match self {
            Self::Mainnet => "111110",  // Kaspa mainnet
            Self::Testnet => "111111",  // Kaspa testnet
            Self::Devnet => "111111",   // Devnet uses testnet coin type
        }
    }

    /// Get expected Kaspa network ID
    pub fn kaspa_network_id(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet-10",  // or testnet-11, etc.
            Self::Devnet => "devnet",
        }
    }
}

impl Default for NetworkMode {
    fn default() -> Self {
        // Safe default: strictest mode
        Self::Mainnet
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Devnet => write!(f, "devnet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_mode_from_str() {
        assert_eq!(NetworkMode::from_str("mainnet").unwrap(), NetworkMode::Mainnet);
        assert_eq!(NetworkMode::from_str("MAINNET").unwrap(), NetworkMode::Mainnet);
        assert_eq!(NetworkMode::from_str("testnet").unwrap(), NetworkMode::Testnet);
        assert_eq!(NetworkMode::from_str("devnet").unwrap(), NetworkMode::Devnet);
        assert!(NetworkMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_default_is_mainnet() {
        assert_eq!(NetworkMode::default(), NetworkMode::Mainnet);
    }

    #[test]
    fn test_address_prefix() {
        assert_eq!(NetworkMode::Mainnet.address_prefix(), "kaspa:");
        assert_eq!(NetworkMode::Testnet.address_prefix(), "kaspatest:");
        assert_eq!(NetworkMode::Devnet.address_prefix(), "kaspadev:");
    }
}
```

---

### Validation Report

**File**: `igra-core/src/infrastructure/network_mode/report.rs`

```rust
//! Validation report and error accumulation

use std::fmt;

/// Validation report with errors and warnings
#[derive(Debug, Clone)]
pub struct ValidationReport {
    network_mode: crate::infrastructure::network_mode::NetworkMode,
    errors: Vec<ValidationError>,
    warnings: Vec<ValidationWarning>,
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub category: ErrorCategory,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub category: ErrorCategory,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Secrets,
    RpcEndpoint,
    Configuration,
    Logging,
    FilePermissions,
    Startup,
    Network,
}

impl ValidationReport {
    pub fn new(network_mode: crate::infrastructure::network_mode::NetworkMode) -> Self {
        Self {
            network_mode,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, category: ErrorCategory, message: impl Into<String>) {
        self.errors.push(ValidationError {
            category,
            message: message.into(),
        });
    }

    pub fn add_warning(&mut self, category: ErrorCategory, message: impl Into<String>) {
        self.warnings.push(ValidationWarning {
            category,
            message: message.into(),
        });
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// Format as human-readable report
    pub fn format_report(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n🔍 Security Validation Report ({})\n",
            self.network_mode
        ));
        output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        if self.errors.is_empty() && self.warnings.is_empty() {
            output.push_str("✅ All validation checks passed\n");
            return output;
        }

        if !self.errors.is_empty() {
            output.push_str(&format!("❌ {} ERROR(S) FOUND:\n\n", self.errors.len()));
            for (i, error) in self.errors.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. [{:?}] {}\n",
                    i + 1,
                    error.category,
                    error.message
                ));
            }
            output.push('\n');
        }

        if !self.warnings.is_empty() {
            output.push_str(&format!("⚠️  {} WARNING(S):\n\n", self.warnings.len()));
            for (i, warning) in self.warnings.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. [{:?}] {}\n",
                    i + 1,
                    warning.category,
                    warning.message
                ));
            }
            output.push('\n');
        }

        if self.network_mode.is_production() && self.has_errors() {
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            output.push_str("❌ Mainnet validation FAILED - fix errors above before starting\n");
        }

        output
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_report())
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secrets => write!(f, "SECRETS"),
            Self::RpcEndpoint => write!(f, "RPC"),
            Self::Configuration => write!(f, "CONFIG"),
            Self::Logging => write!(f, "LOGGING"),
            Self::FilePermissions => write!(f, "PERMISSIONS"),
            Self::Startup => write!(f, "STARTUP"),
            Self::Network => write!(f, "NETWORK"),
        }
    }
}
```

---

## CLI Integration

### Command-Line Flags

**File**: `igra-service/src/bin/kaspa-threshold-service.rs`

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "kaspa-threshold-service")]
#[command(about = "Igra threshold signature service")]
struct Args {
    /// Network mode (mainnet, testnet, devnet)
    ///
    /// Determines security validation level:
    /// - mainnet: Maximum security, strict validation
    /// - testnet: Moderate security, warnings
    /// - devnet: Minimal security, flexible
    ///
    /// Default: mainnet
    #[arg(long, default_value = "mainnet", value_name = "MODE")]
    #[arg(value_parser = ["mainnet", "testnet", "devnet"])]
    network: String,

    /// Allow remote RPC endpoint in mainnet (NOT RECOMMENDED)
    ///
    /// By default, mainnet requires local Kaspa RPC for security.
    /// Use this flag to explicitly allow remote RPC endpoints.
    ///
    /// Security warning: Remote RPC can lie about blockchain state.
    #[arg(long)]
    allow_remote_rpc: bool,

    /// Path to configuration file
    #[arg(long, short = 'c', value_name = "PATH")]
    config: Option<PathBuf>,

    /// Data directory
    #[arg(long, short = 'd', value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Parse network mode
    let network_mode = NetworkMode::from_str(&args.network)?;

    // Load configuration
    let mut config = load_config(args.config.as_deref())?;

    // Apply CLI overrides
    if let Some(data_dir) = args.data_dir {
        config.data_dir = data_dir;
    }
    config.allow_remote_rpc = args.allow_remote_rpc;

    // Validate configuration for network mode
    let validator = SecurityValidator::new(network_mode);
    let report = validator.validate(&config).await?;

    // Print report
    if report.has_warnings() || report.has_errors() {
        println!("{}", report);
    }

    // In mainnet, fail on errors
    if network_mode.is_production() && report.has_errors() {
        std::process::exit(1);
    }

    // Continue with service startup...
    setup_and_run(config, network_mode).await?;

    Ok(())
}
```

**Example Usage**:

```bash
# Mainnet (strict validation)
cargo run --bin kaspa-threshold-service -- --network mainnet --config ./mainnet-config.toml

# Mainnet with remote RPC (not recommended)
cargo run --bin kaspa-threshold-service -- --network mainnet --allow-remote-rpc

# Testnet (moderate validation)
cargo run --bin kaspa-threshold-service -- --network testnet

# Devnet (minimal validation)
cargo run --bin kaspa-threshold-service -- --network devnet
```

---

## Configuration Schema

### Updates to ServiceConfig

**File**: `igra-core/src/infrastructure/config/types.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    // === Network Mode ===

    /// Network mode: mainnet, testnet, devnet
    ///
    /// Determines security validation level.
    /// Must match CLI --network flag.
    #[serde(default)]
    pub network: Option<String>,

    /// Allow remote RPC endpoint (mainnet only)
    ///
    /// By default, mainnet requires local RPC.
    /// Set to true to allow remote endpoints (NOT RECOMMENDED).
    #[serde(default)]
    pub allow_remote_rpc: bool,

    // === Existing fields ===

    pub node_url: String,
    pub data_dir: PathBuf,
    pub use_encrypted_secrets: bool,
    pub secrets_file: Option<String>,
    pub key_audit_log_path: Option<String>,

    // ... rest of config
}
```

### Example Mainnet Configuration

```toml
# mainnet-config.toml

# Explicit network confirmation (required for mainnet)
network = "mainnet"

# Kaspa RPC endpoint (MUST be local in mainnet)
node_url = "grpc://127.0.0.1:16110"

# Security: Encrypted secrets required in mainnet
use_encrypted_secrets = true
secrets_file = "/var/lib/igra/secrets.bin"

# Security: Audit logging required in mainnet
key_audit_log_path = "/var/lib/igra/audit/key-audit.log"

# Data directory (will be validated for 0700 permissions)
data_dir = "/var/lib/igra/data"

# Logging configuration (INFO or higher in mainnet)
log_level = "info"
log_max_size = "100MB"
log_max_files = 10

# Group configuration (threshold >= 2 required in mainnet)
[group]
threshold_m = 2
threshold_n = 3
member_pubkeys = [
    "02b0272b5886403c0e13c83f7fa59567ba50b07cb31dd7294982fd8160f94d54e2",
    "03c87e7e5e2f1f16178a4e1306a9dd843c98813ee01ae7b15a81e347de6f1bc500",
    "03ccb183a76023af7c955a3855268ea4646d5213aec1cf01a65c9040a598701e54"
]

# Profile configuration (mainnet addresses and derivation paths)
[profiles.signer-1]
name = "signer-1"
key_type = "hd_mnemonic"
derivation_path = "m/45'/111110'/0'/0/0"  # Mainnet coin type 111110
rpc_address = "127.0.0.1:8088"

[profiles.signer-2]
name = "signer-2"
key_type = "hd_mnemonic"
derivation_path = "m/45'/111110'/0'/0/0"
rpc_address = "127.0.0.1:8089"

[profiles.signer-3]
name = "signer-3"
key_type = "hd_mnemonic"
derivation_path = "m/45'/111110'/0'/0/0"
rpc_address = "127.0.0.1:8090"

# Iroh P2P configuration (flexible - all options allowed)
[iroh]
# Option 1: Use preconfigured bootstrap nodes
bootstrap_nodes = [
    "/ip4/10.0.1.10/udp/4433/quic-v1/p2p/12D3KooW...",
    "/ip4/10.0.1.11/udp/4433/quic-v1/p2p/12D3KooW..."
]

# Option 2: Use DNS/PKARR discovery (omit bootstrap_nodes)
# dns_resolvers = ["1.1.1.1", "8.8.8.8"]

# Option 3: Custom PKARR relay
# pkarr_relay = "https://pkarr.example.com"
```

---

## Validation Flow

### Startup Sequence

```
1. Parse CLI arguments
   ├─> Extract --network flag (default: mainnet)
   ├─> Extract --allow-remote-rpc flag
   └─> Extract config path

2. Load configuration file
   ├─> Parse TOML
   ├─> Apply CLI overrides
   └─> Merge with defaults

3. Create SecurityValidator
   └─> Initialize with NetworkMode

4. Run validation
   ├─> Validate secrets configuration
   ├─> Validate RPC endpoints
   ├─> Validate config values
   ├─> Validate logging setup
   ├─> Validate file permissions (Unix)
   └─> Generate ValidationReport

5. Handle validation results
   ├─> Print report (errors + warnings)
   ├─> If mainnet + errors → EXIT
   ├─> If testnet + errors → WARN + CONTINUE
   └─> If devnet → CONTINUE

6. Run startup checks (mainnet only)
   ├─> Connect to Kaspa node
   ├─> Verify network ID matches
   ├─> Check all secrets accessible
   ├─> Validate disk space
   ├─> Validate memory
   ├─> Check file limits
   └─> Verify core dumps disabled

7. Initialize services
   ├─> Setup KeyManager
   ├─> Initialize Iroh P2P
   ├─> Start RPC server
   └─> Begin coordination

8. Log startup complete
   └─> Ready to sign transactions
```

---

## Testing Strategy

### Unit Tests

**File**: `igra-core/tests/unit/network_mode_tests.rs`

```rust
use igra_core::infrastructure::network_mode::*;

#[test]
fn test_mainnet_rejects_env_secrets() {
    let mut config = ServiceConfig::default();
    config.use_encrypted_secrets = false;

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_secrets(&config);

    assert!(report.has_errors());
    assert!(report.errors[0].message.contains("encrypted secrets"));
}

#[test]
fn test_mainnet_rejects_remote_rpc() {
    let mut config = ServiceConfig::default();
    config.node_url = "grpc://remote-node.example.com:16110".to_string();
    config.allow_remote_rpc = false;

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_rpc_endpoints(&config);

    assert!(report.has_errors());
    assert!(report.errors[0].message.contains("local"));
}

#[test]
fn test_mainnet_allows_remote_rpc_with_flag() {
    let mut config = ServiceConfig::default();
    config.node_url = "grpcs://remote-node.example.com:16110".to_string();
    config.allow_remote_rpc = true;  // Explicit opt-in

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_rpc_endpoints(&config);

    // Should have warnings but not errors
    assert!(!report.has_errors());
    assert!(report.has_warnings());
}

#[test]
fn test_devnet_allows_env_secrets() {
    let mut config = ServiceConfig::default();
    config.use_encrypted_secrets = false;

    let validator = SecurityValidator::new(NetworkMode::Devnet);
    let report = validator.validate_secrets(&config);

    assert!(!report.has_errors());
}
```

### Integration Tests

**File**: `igra-service/tests/integration/network_mode_integration.rs`

```rust
#[tokio::test]
async fn test_mainnet_startup_with_valid_config() {
    let config = create_valid_mainnet_config();
    let validator = SecurityValidator::new(NetworkMode::Mainnet);

    let report = validator.validate(&config).await.unwrap();

    assert!(!report.has_errors());
}

#[tokio::test]
async fn test_mainnet_startup_rejects_invalid_config() {
    let config = create_invalid_mainnet_config();
    let validator = SecurityValidator::new(NetworkMode::Mainnet);

    let report = validator.validate(&config).await.unwrap();

    assert!(report.has_errors());
}
```

---

## Deployment Guide

### Mainnet Deployment Checklist

**Pre-Deployment**:

- [ ] Generate mainnet secrets with `devnet-keygen --format file --network mainnet`
- [ ] Set secrets file permissions: `chmod 600 /var/lib/igra/secrets.bin`
- [ ] Set data directory permissions: `chmod 700 /var/lib/igra/data`
- [ ] Set config file permissions: `chmod 600 /etc/igra/config.toml`
- [ ] Create dedicated user: `sudo useradd -r -s /bin/false igra-service`
- [ ] Set file ownership: `chown -R igra-service:igra-service /var/lib/igra`
- [ ] Disable core dumps: `ulimit -c 0`
- [ ] Set file limits: `ulimit -n 4096`
- [ ] Verify kaspad running locally: `kaspad --version`
- [ ] Configure log rotation

**Configuration**:

- [ ] Set `network = "mainnet"` in config
- [ ] Use mainnet addresses (kaspa: prefix)
- [ ] Use mainnet coin type (111110) in derivation paths
- [ ] Configure local RPC: `node_url = "grpc://127.0.0.1:16110"`
- [ ] Enable encrypted secrets: `use_encrypted_secrets = true`
- [ ] Enable audit logging: `key_audit_log_path = "/var/lib/igra/audit.log"`
- [ ] Set log level: `log_level = "info"`
- [ ] Configure log rotation: `log_max_size`, `log_max_files`
- [ ] Set threshold m >= 2

**Environment**:

- [ ] Set passphrase: `export IGRA_SECRETS_PASSPHRASE="..."`
- [ ] Set log level: `export RUST_LOG=info`
- [ ] Unset debug env vars: `unset KASPA_IGRA_WALLET_SECRET`

**Start Service**:

```bash
# Run validation
sudo -u igra-service kaspa-threshold-service \
    --network mainnet \
    --config /etc/igra/config.toml \
    --validate-only

# Start service
sudo -u igra-service kaspa-threshold-service \
    --network mainnet \
    --config /etc/igra/config.toml
```

**Post-Deployment**:

- [ ] Verify startup logs show "Mainnet mode"
- [ ] Check no validation errors in logs
- [ ] Verify Kaspa node connectivity
- [ ] Check audit log is being written
- [ ] Monitor resource usage
- [ ] Test signing operation
- [ ] Verify multisig address matches expected

---

## Migration from Existing Deployment

### If Currently Running Without Network Mode

**Step 1**: Identify current network

```bash
# Check your addresses
grep "source_addresses" /etc/igra/config.toml

# kaspa: → mainnet
# kaspatest: → testnet
# kaspadev: → devnet
```

**Step 2**: Add network field to config

```toml
# Add to top of config.toml
network = "mainnet"  # or testnet/devnet
```

**Step 3**: Run validation

```bash
kaspa-threshold-service --network mainnet --config /etc/igra/config.toml --validate-only
```

**Step 4**: Fix any reported errors

Common issues:
- Environment variable secrets → Migrate to secrets.bin
- Missing audit logging → Add `key_audit_log_path`
- Insecure file permissions → `chmod 600`/`chmod 700`
- Debug logging → Change to `RUST_LOG=info`

**Step 5**: Restart with network mode

```bash
kaspa-threshold-service --network mainnet --config /etc/igra/config.toml
```

---

## Summary

### What This Provides

1. **Defense in Depth** - Multiple layers of security validation
2. **Fail-Safe Defaults** - Mainnet by default, explicit opt-in to relaxed modes
3. **Clear Contracts** - Each mode has well-defined security guarantees
4. **Audit Trail** - All validation decisions logged
5. **Operational Clarity** - Clear error messages with remediation steps

### Security Impact

**Before**:
- ❌ No validation of secret storage
- ❌ No validation of RPC endpoints
- ❌ No validation of file permissions
- ❌ Same security for all networks
- ❌ Debug logging in production

**After**:
- ✅ Encrypted secrets enforced in mainnet
- ✅ Local RPC enforced in mainnet (unless explicitly allowed)
- ✅ Strict file permissions validated
- ✅ Security proportional to risk
- ✅ Debug logging forbidden in mainnet

### Next Steps

1. Implement NetworkMode enum and validation infrastructure
2. Add CLI flags to kaspa-threshold-service
3. Integrate validation into startup sequence
4. Add comprehensive tests
5. Update deployment documentation
6. Train team on network mode usage

---

END OF GUIDE

---

## Complete Implementation

### File 1: Security Validator Core

**File**: `igra-core/src/infrastructure/network_mode/validator.rs`

```rust
//! Security validator for network mode enforcement

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::ServiceConfig;
use crate::infrastructure::network_mode::{NetworkMode, report::*};
use std::path::Path;

/// Security validator enforces network-specific rules
pub struct SecurityValidator {
    network_mode: NetworkMode,
}

impl SecurityValidator {
    pub fn new(network_mode: NetworkMode) -> Self {
        Self { network_mode }
    }

    /// Run comprehensive validation
    pub async fn validate(&self, config: &ServiceConfig) -> Result<ValidationReport, ThresholdError> {
        let mut report = ValidationReport::new(self.network_mode);

        log::info!("🔍 Running security validation for {} mode", self.network_mode);

        // Run all validation modules
        self.validate_secrets(config, &mut report)?;
        self.validate_rpc_endpoints(config, &mut report)?;
        self.validate_configuration(config, &mut report)?;
        self.validate_logging(config, &mut report)?;

        #[cfg(target_family = "unix")]
        self.validate_file_permissions(config, &mut report)?;

        self.validate_addresses(config, &mut report)?;

        // Startup checks (mainnet only)
        if self.network_mode == NetworkMode::Mainnet {
            self.validate_startup_readiness(config, &mut report).await?;
        }

        // Log summary
        if report.has_errors() {
            log::error!("❌ Validation found {} error(s)", report.error_count());
        } else if report.has_warnings() {
            log::warn!("⚠️  Validation found {} warning(s)", report.warning_count());
        } else {
            log::info!("✅ All security validations passed");
        }

        Ok(report)
    }

    fn validate_secrets(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                // STRICT: Must use encrypted secrets
                if !config.use_encrypted_secrets {
                    report.add_error(
                        ErrorCategory::Secrets,
                        "Mainnet requires encrypted secrets file (set use_encrypted_secrets=true in config)"
                    );
                }

                // STRICT: No environment variable secrets
                if std::env::var("KASPA_IGRA_WALLET_SECRET").is_ok() {
                    report.add_error(
                        ErrorCategory::Secrets,
                        "Mainnet forbids KASPA_IGRA_WALLET_SECRET environment variable (use secrets.bin instead)"
                    );
                }

                // STRICT: Must have secrets file configured
                if config.secrets_file.is_none() {
                    report.add_error(
                        ErrorCategory::Secrets,
                        "Mainnet requires secrets_file path in configuration"
                    );
                }

                // STRICT: Must have audit logging
                if config.key_audit_log_path.is_none() {
                    report.add_error(
                        ErrorCategory::Secrets,
                        "Mainnet requires audit logging (set key_audit_log_path in config)"
                    );
                }

                // STRICT: Secrets file must exist
                if let Some(secrets_path) = &config.secrets_file {
                    if !Path::new(secrets_path).exists() {
                        report.add_error(
                            ErrorCategory::Secrets,
                            format!("Secrets file does not exist: {}", secrets_path)
                        );
                    }
                }

                // STRICT: No passphrase from stdin in production
                // (This assumes you add PassphraseSource to config)
                if std::env::var("IGRA_SECRETS_PASSPHRASE").is_err() {
                    report.add_error(
                        ErrorCategory::Secrets,
                        "Mainnet requires IGRA_SECRETS_PASSPHRASE environment variable \
                        (interactive passphrase prompts are insecure in production)"
                    );
                }
            }

            NetworkMode::Testnet => {
                // MODERATE: Warn if not using encrypted secrets
                if !config.use_encrypted_secrets {
                    report.add_warning(
                        ErrorCategory::Secrets,
                        "Testnet should use encrypted secrets file (set use_encrypted_secrets=true)"
                    );
                }

                // MODERATE: Warn if no audit logging
                if config.key_audit_log_path.is_none() {
                    report.add_warning(
                        ErrorCategory::Secrets,
                        "Testnet should enable audit logging (set key_audit_log_path)"
                    );
                }
            }

            NetworkMode::Devnet => {
                // RELAXED: No requirements
                log::debug!("Devnet mode: allowing flexible secret configuration");
            }
        }

        Ok(())
    }

    fn validate_rpc_endpoints(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                // Parse Kaspa node URL
                let node_url = &config.node_url;

                // Extract host from URL
                let host = Self::extract_host_from_url(node_url)
                    .map_err(|e| {
                        report.add_error(
                            ErrorCategory::RpcEndpoint,
                            format!("Invalid node_url: {}", e)
                        );
                        e
                    })
                    .ok();

                if let Some(host) = host {
                    let is_local = Self::is_localhost(&host);

                    if !is_local {
                        // Remote RPC detected
                        if !config.allow_remote_rpc {
                            report.add_error(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Mainnet requires local Kaspa RPC endpoint (got: {}).\n\
                                    \n\
                                    Current URL: {}\n\
                                    \n\
                                    SECURITY: Igra requires a local kaspad node for maximum security.\n\
                                    Remote RPC endpoints can:\n\
                                    - Provide incorrect UTXO data\n\
                                    - Track your transactions\n\
                                    - Censor your operations\n\
                                    \n\
                                    RECOMMENDED: Run kaspad locally on 127.0.0.1:16110\n\
                                    \n\
                                    To explicitly allow remote RPC (NOT RECOMMENDED):\n\
                                    - Add 'allow_remote_rpc = true' to config, OR\n\
                                    - Use --allow-remote-rpc CLI flag",
                                    host,
                                    node_url
                                )
                            );
                        } else {
                            // Remote allowed via flag, but enforce TLS
                            if node_url.starts_with("grpc://") {
                                report.add_error(
                                    ErrorCategory::RpcEndpoint,
                                    format!(
                                        "Mainnet remote RPC must use TLS (grpcs://). \
                                        Got insecure: {}",
                                        node_url
                                    )
                                );
                            }

                            // Warn about security implications
                            report.add_warning(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Using remote RPC endpoint: {}. \
                                    You are trusting {} for blockchain data.",
                                    node_url, host
                                )
                            );

                            log::warn!("⚠️  SECURITY RISK: Remote RPC enabled in mainnet");
                        }
                    } else {
                        // Local RPC - excellent!
                        log::info!("✓ Using local Kaspa RPC: {}", node_url);
                    }
                }
            }

            NetworkMode::Testnet => {
                // MODERATE: Warn if insecure remote
                if config.node_url.starts_with("grpc://")
                    && !Self::is_localhost(&Self::extract_host_from_url(&config.node_url).unwrap_or_default()) {
                    report.add_warning(
                        ErrorCategory::RpcEndpoint,
                        format!(
                            "Testnet using insecure remote RPC: {}. \
                            Consider using grpcs:// or local node.",
                            config.node_url
                        )
                    );
                }
            }

            NetworkMode::Devnet => {
                // RELAXED: Allow any RPC configuration
                log::debug!("Devnet mode: allowing any RPC configuration");
            }
        }

        Ok(())
    }

    fn validate_configuration(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
        match self.network_mode {
            NetworkMode::Mainnet => {
                // STRICT: Must explicitly confirm network
                if config.network.as_deref() != Some("mainnet") {
                    report.add_error(
                        ErrorCategory::Configuration,
                        "Mainnet mode requires explicit 'network = \"mainnet\"' in config \
                        (prevents accidental use of test configuration)"
                    );
                }

                // STRICT: Validate threshold values
                if config.group.threshold_m > config.group.threshold_n {
                    report.add_error(
                        ErrorCategory::Configuration,
                        format!(
                            "Invalid threshold: m={} > n={}",
                            config.group.threshold_m,
                            config.group.threshold_n
                        )
                    );
                }

                if config.group.threshold_m < 2 {
                    report.add_error(
                        ErrorCategory::Configuration,
                        format!(
                            "Mainnet requires threshold m >= 2 (got m={}). \
                            Single signer is insecure for production.",
                            config.group.threshold_m
                        )
                    );
                }

                // STRICT: Must have sufficient profiles
                if config.profiles.len() < config.group.threshold_m {
                    report.add_error(
                        ErrorCategory::Configuration,
                        format!(
                            "Insufficient profiles: {} configured, need at least m={}",
                            config.profiles.len(),
                            config.group.threshold_m
                        )
                    );
                }

                // STRICT: Validate data directory path
                if let Some(data_dir_str) = config.data_dir.to_str() {
                    if data_dir_str.contains("devnet") || data_dir_str.contains("test") {
                        report.add_error(
                            ErrorCategory::Configuration,
                            format!(
                                "Mainnet data directory path contains 'devnet' or 'test': {}. \
                                This suggests test configuration being used.",
                                data_dir_str
                            )
                        );
                    }
                }
            }

            NetworkMode::Testnet => {
                // MODERATE: Warn if network not confirmed
                if config.network.as_deref() != Some("testnet") {
                    report.add_warning(
                        ErrorCategory::Configuration,
                        "Testnet should have 'network = \"testnet\"' in config"
                    );
                }

                // MODERATE: Validate thresholds
                if config.group.threshold_m < 2 {
                    report.add_warning(
                        ErrorCategory::Configuration,
                        format!(
                            "Testnet threshold m={} is low (consider m >= 2)",
                            config.group.threshold_m
                        )
                    );
                }
            }

            NetworkMode::Devnet => {
                // RELAXED: Only validate basic sanity
                if config.group.threshold_m > config.group.threshold_n {
                    report.add_error(
                        ErrorCategory::Configuration,
                        format!(
                            "Invalid threshold even for devnet: m={} > n={}",
                            config.group.threshold_m,
                            config.group.threshold_n
                        )
                    );
                }
            }
        }

        Ok(())
    }

    fn validate_logging(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
        let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        match self.network_mode {
            NetworkMode::Mainnet => {
                // STRICT: No debug/trace logging (risk of secret exposure)
                if rust_log.to_lowercase().contains("debug")
                    || rust_log.to_lowercase().contains("trace") {
                    report.add_error(
                        ErrorCategory::Logging,
                        format!(
                            "Mainnet forbids DEBUG/TRACE logging (RUST_LOG={}). \
                            These log levels may expose secrets. \
                            Set RUST_LOG=info or RUST_LOG=warn",
                            rust_log
                        )
                    );
                }

                // STRICT: Must have log rotation
                if config.log_max_size.is_none() || config.log_max_files.is_none() {
                    report.add_error(
                        ErrorCategory::Logging,
                        "Mainnet requires log rotation (set log_max_size and log_max_files in config)"
                    );
                }
            }

            NetworkMode::Testnet => {
                // MODERATE: Warn if using trace
                if rust_log.to_lowercase().contains("trace") {
                    report.add_warning(
                        ErrorCategory::Logging,
                        "Testnet using TRACE logging (may expose sensitive data)"
                    );
                }
            }

            NetworkMode::Devnet => {
                // RELAXED: Allow any log level
            }
        }

        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn validate_file_permissions(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
        use std::os::unix::fs::PermissionsExt;

        match self.network_mode {
            NetworkMode::Mainnet => {
                // Check data directory exists and has correct permissions
                if config.data_dir.exists() {
                    let data_meta = std::fs::metadata(&config.data_dir)
                        .map_err(|e| ThresholdError::secret_store_unavailable(
                            "file",
                            format!("Cannot read data directory metadata: {}", e)
                        ))?;

                    let data_mode = data_meta.permissions().mode() & 0o777;
                    if data_mode != 0o700 {
                        report.add_error(
                            ErrorCategory::FilePermissions,
                            format!(
                                "Data directory {:?} has insecure permissions: {:o} (expected 0700).\n\
                                Fix with: chmod 700 {:?}",
                                config.data_dir, data_mode, config.data_dir
                            )
                        );
                    }
                } else {
                    report.add_warning(
                        ErrorCategory::FilePermissions,
                        format!("Data directory {:?} does not exist (will be created)", config.data_dir)
                    );
                }

                // Check secrets file permissions
                if let Some(secrets_path) = &config.secrets_file {
                    let path = Path::new(secrets_path);
                    if path.exists() {
                        let secrets_meta = std::fs::metadata(path)
                            .map_err(|e| ThresholdError::secret_store_unavailable(
                                "file",
                                format!("Cannot read secrets file metadata: {}", e)
                            ))?;

                        let secrets_mode = secrets_meta.permissions().mode() & 0o777;
                        if secrets_mode != 0o600 {
                            report.add_error(
                                ErrorCategory::FilePermissions,
                                format!(
                                    "Secrets file {:?} has insecure permissions: {:o} (expected 0600).\n\
                                    Fix with: chmod 600 {:?}",
                                    path, secrets_mode, path
                                )
                            );
                        }
                    }
                }

                // Check not running as root
                let uid = unsafe { libc::getuid() };
                if uid == 0 {
                    report.add_error(
                        ErrorCategory::FilePermissions,
                        "Mainnet service must not run as root user.\n\
                        Create dedicated user:\n\
                        sudo useradd -r -s /bin/false igra-service\n\
                        sudo chown -R igra-service:igra-service /var/lib/igra"
                    );
                }
            }

            NetworkMode::Testnet => {
                // MODERATE: Warn about permissions
                if config.data_dir.exists() {
                    let data_meta = std::fs::metadata(&config.data_dir).ok();
                    if let Some(meta) = data_meta {
                        let mode = meta.permissions().mode() & 0o777;
                        if mode & 0o077 != 0 {
                            report.add_warning(
                                ErrorCategory::FilePermissions,
                                format!(
                                    "Data directory {:?} has permissive permissions: {:o} (recommend 0700)",
                                    config.data_dir, mode
                                )
                            );
                        }
                    }
                }
            }

            NetworkMode::Devnet => {
                // RELAXED: No permission checks
            }
        }

        Ok(())
    }

    #[cfg(not(target_family = "unix"))]
    fn validate_file_permissions(&self, _config: &ServiceConfig, _report: &mut ValidationReport) -> Result<(), ThresholdError> {
        // No file permission validation on non-Unix systems
        Ok(())
    }

    fn validate_addresses(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
        let expected_prefix = self.network_mode.address_prefix();

        match self.network_mode {
            NetworkMode::Mainnet | NetworkMode::Testnet => {
                // STRICT: Addresses must match network mode
                for addr in &config.source_addresses {
                    if !addr.starts_with(expected_prefix) {
                        report.add_error(
                            ErrorCategory::Network,
                            format!(
                                "Address '{}' does not match {} network (expected prefix: {})",
                                addr,
                                self.network_mode,
                                expected_prefix
                            )
                        );
                    }
                }

                // STRICT: Multisig address must match
                if !config.multisig_address.starts_with(expected_prefix) {
                    report.add_error(
                        ErrorCategory::Network,
                        format!(
                            "Multisig address '{}' does not match {} network",
                            config.multisig_address,
                            self.network_mode
                        )
                    );
                }

                // STRICT: Derivation paths must use correct coin type
                let expected_coin_type = self.network_mode.coin_type();
                for (profile_name, profile) in &config.profiles {
                    if profile.key_type == crate::infrastructure::config::types::KeyType::HdMnemonic {
                        if !profile.derivation_path.contains(expected_coin_type) {
                            report.add_error(
                                ErrorCategory::Configuration,
                                format!(
                                    "Profile '{}' uses incorrect coin type in derivation path.\n\
                                    Path: {}\n\
                                    Expected coin type: {} (for {})\n\
                                    Example: m/45'/{}'/{}'/{}/{}",
                                    profile_name,
                                    profile.derivation_path,
                                    expected_coin_type,
                                    self.network_mode,
                                    expected_coin_type, 0, 0, 0
                                )
                            );
                        }
                    }
                }
            }

            NetworkMode::Devnet => {
                // RELAXED: Allow cross-network addresses (for testing)
                log::debug!("Devnet mode: allowing any address format");
            }
        }

        Ok(())
    }

    async fn validate_startup_readiness(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
        // Only run in mainnet
        if self.network_mode != NetworkMode::Mainnet {
            return Ok(());
        }

        log::info!("Running mainnet startup readiness checks...");

        // Check disk space
        if let Ok(available) = Self::get_available_disk_space(&config.data_dir) {
            let min_space = 10 * 1024 * 1024 * 1024; // 10 GB
            if available < min_space {
                report.add_error(
                    ErrorCategory::Startup,
                    format!(
                        "Insufficient disk space: {} GB available, need at least 10 GB",
                        available / (1024 * 1024 * 1024)
                    )
                );
            }
        }

        // Check file limits (Unix only)
        #[cfg(target_family = "unix")]
        {
            let (soft, _hard) = Self::get_file_limits()?;
            if soft < 4096 {
                report.add_error(
                    ErrorCategory::Startup,
                    format!(
                        "Open file limit too low: {} (need at least 4096).\n\
                        Fix with: ulimit -n 4096\n\
                        Or add to /etc/security/limits.conf",
                        soft
                    )
                );
            }

            // Check core dumps disabled
            let core_limit = Self::get_core_dump_limit()?;
            if core_limit != 0 {
                report.add_error(
                    ErrorCategory::Startup,
                    "Core dumps are enabled (may contain secrets).\n\
                    Disable with: ulimit -c 0"
                );
            }
        }

        Ok(())
    }

    // Helper methods

    fn extract_host_from_url(url: &str) -> Result<String, String> {
        // Simple parsing for grpc://host:port or http://host:port
        let without_scheme = url
            .strip_prefix("grpc://")
            .or_else(|| url.strip_prefix("grpcs://"))
            .or_else(|| url.strip_prefix("http://"))
            .or_else(|| url.strip_prefix("https://"))
            .ok_or_else(|| format!("Invalid URL scheme: {}", url))?;

        // Extract host (before port)
        let host = without_scheme
            .split(':')
            .next()
            .ok_or_else(|| "Missing host".to_string())?;

        Ok(host.to_string())
    }

    fn is_localhost(host: &str) -> bool {
        host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host == "[::1]"
            || host.starts_with("127.")
    }

    fn get_available_disk_space(path: &Path) -> Result<u64, std::io::Error> {
        // Platform-specific implementation
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(path)?;
            // This is a simplified version - proper implementation needs statvfs
            Ok(metadata.size())
        }

        #[cfg(not(target_family = "unix"))]
        {
            // Windows or other platforms
            Ok(u64::MAX) // Skip check on non-Unix
        }
    }

    #[cfg(target_family = "unix")]
    fn get_file_limits() -> Result<(u64, u64), ThresholdError> {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };

        if result != 0 {
            return Err(ThresholdError::secret_store_unavailable(
                "system",
                "Failed to get file limits"
            ));
        }

        Ok((rlim.rlim_cur, rlim.rlim_max))
    }

    #[cfg(target_family = "unix")]
    fn get_core_dump_limit() -> Result<u64, ThresholdError> {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        let result = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };

        if result != 0 {
            return Err(ThresholdError::secret_store_unavailable(
                "system",
                "Failed to get core dump limit"
            ));
        }

        Ok(rlim.rlim_cur)
    }
}
```

---

## Validation Examples

### Example 1: Valid Mainnet Config

```toml
# Production mainnet configuration
network = "mainnet"

# Local RPC (required in mainnet)
node_url = "grpc://127.0.0.1:16110"

# Encrypted secrets (required in mainnet)
use_encrypted_secrets = true
secrets_file = "/var/lib/igra/secrets.bin"

# Audit logging (required in mainnet)
key_audit_log_path = "/var/lib/igra/audit/key-audit.log"

# Data directory
data_dir = "/var/lib/igra/data"

# Log rotation (required in mainnet)
log_level = "info"
log_max_size = "100MB"
log_max_files = 10

# Threshold (m >= 2 required in mainnet)
[group]
threshold_m = 2
threshold_n = 3

# PSKT config (source address derived from redeem_script_hex + service.network)
[service.pskt]
redeem_script_hex = "<REPLACE_WITH_REDEEM_SCRIPT_HEX>"
sig_op_count = 3
# source_addresses is optional; if set, it must match the derived address:
# source_addresses = ["kaspa:..."]

# Profiles with mainnet coin type
[profiles.signer-1]
name = "signer-1"
key_type = "hd_mnemonic"
derivation_path = "m/45'/111110'/0'/0/0"  # Mainnet coin type
rpc_address = "127.0.0.1:8088"
```

**Validation Result**: ✅ ALL CHECKS PASS

---

### Example 2: Invalid Mainnet Config (Multiple Issues)

```toml
# Missing explicit network confirmation
# network = "mainnet"  <-- MISSING

# Remote RPC without flag
node_url = "grpc://remote.example.com:16110"  # ERROR: not localhost

# Environment secrets (insecure)
use_encrypted_secrets = false  # ERROR: mainnet requires encrypted

# No audit logging
# key_audit_log_path = "..."  <-- MISSING

# Test directory path
data_dir = "./devnet-data"  # ERROR: contains "devnet"

[group]
threshold_m = 1  # ERROR: must be >= 2
threshold_n = 3

[profiles.signer-1]
derivation_path = "m/45'/111111'/0'/0/0"  # ERROR: testnet coin type
```

**Validation Result**:
```
❌ 6 ERROR(S) FOUND:

  1. [CONFIG] Mainnet mode requires explicit 'network = "mainnet"' in config
  2. [RPC] Mainnet requires local Kaspa RPC endpoint (got: remote.example.com)
  3. [SECRETS] Mainnet requires encrypted secrets file
  4. [SECRETS] Mainnet requires audit logging
  5. [CONFIG] Mainnet data directory path contains 'devnet'
  6. [CONFIG] Mainnet requires threshold m >= 2 (got m=1)
  7. [CONFIG] Profile 'signer-1' uses incorrect coin type (111111 instead of 111110)

❌ Mainnet validation FAILED - fix errors above before starting
```

---

### Example 3: Mainnet with Remote RPC (Explicitly Allowed)

```toml
network = "mainnet"

# Remote RPC with explicit flag
node_url = "grpcs://trusted-node.example.com:16110"  # TLS required
allow_remote_rpc = true  # Explicit opt-in

use_encrypted_secrets = true
secrets_file = "/var/lib/igra/secrets.bin"
key_audit_log_path = "/var/lib/igra/audit.log"

# ... rest of config
```

**Validation Result**:
```
⚠️  1 WARNING:

  1. [RPC] Using remote RPC endpoint: grpcs://trusted-node.example.com:16110. 
     You are trusting trusted-node.example.com for blockchain data.

✅ All validation checks passed (with warnings)
```

---

## Environment Detection

### Auto-Detect Network Mode (Optional)

If no CLI flag provided, auto-detect from config or addresses:

```rust
pub fn auto_detect_network_mode(config: &ServiceConfig) -> NetworkMode {
    // Check explicit network field
    if let Some(network) = &config.network {
        if let Ok(mode) = NetworkMode::from_str(network) {
            return mode;
        }
    }

    // Detect from addresses
    if let Some(addr) = config.source_addresses.first() {
        if addr.starts_with("kaspa:") {
            return NetworkMode::Mainnet;
        }
        if addr.starts_with("kaspatest:") {
            return NetworkMode::Testnet;
        }
        if addr.starts_with("kaspadev:") {
            return NetworkMode::Devnet;
        }
    }

    // Safe default
    log::warn!("Could not detect network mode from config, defaulting to mainnet");
    NetworkMode::Mainnet
}
```

---

## Production Deployment Checklist

### Pre-Deployment Security Audit

**System Setup**:
- [ ] Create dedicated user: `igra-service`
- [ ] Configure file limits: `ulimit -n 4096`
- [ ] Disable core dumps: `ulimit -c 0`
- [ ] Run as non-root user
- [ ] Set up log rotation (logrotate)

**Secrets**:
- [ ] Generate production secrets: `devnet-keygen --format file --network mainnet`
- [ ] Store passphrase securely (NOT in shell history)
- [ ] Set secrets file permissions: `chmod 600 /var/lib/igra/secrets.bin`
- [ ] Set IGRA_SECRETS_PASSPHRASE env var (use systemd EnvironmentFile)
- [ ] Remove any KASPA_IGRA_WALLET_SECRET env vars
- [ ] Test secret loading: `secrets-admin list`

**Configuration**:
- [ ] Set `network = "mainnet"` in config
- [ ] Configure local RPC: `node_url = "grpc://127.0.0.1:16110"`
- [ ] Use mainnet addresses (kaspa: prefix)
- [ ] Use mainnet coin type (111110) in derivation paths
- [ ] Set `use_encrypted_secrets = true`
- [ ] Set `key_audit_log_path = "..."`
- [ ] Configure threshold m >= 2
- [ ] Configure log rotation
- [ ] Set config permissions: `chmod 600 /etc/igra/config.toml`

**Kaspa Node**:
- [ ] Run kaspad locally on same machine
- [ ] Configure kaspad for mainnet: `kaspad --mainnet`
- [ ] Verify kaspad listening: `127.0.0.1:16110`
- [ ] Test connectivity: `grpcurl -plaintext 127.0.0.1:16110 list`

**File Permissions**:
- [ ] Data directory: `chmod 700 /var/lib/igra/data`
- [ ] Config file: `chmod 600 /etc/igra/config.toml`
- [ ] Secrets file: `chmod 600 /var/lib/igra/secrets.bin`
- [ ] Audit log: `chmod 600 /var/lib/igra/audit.log`
- [ ] Set ownership: `chown -R igra-service:igra-service /var/lib/igra`

**Validation**:
- [ ] Run validation: `kaspa-threshold-service --network mainnet --validate-only`
- [ ] Fix all errors (zero tolerance)
- [ ] Review warnings
- [ ] Check logs for security warnings
- [ ] Verify no secrets in logs

**Startup**:
- [ ] Set environment: `export RUST_LOG=info`
- [ ] Set passphrase: `export IGRA_SECRETS_PASSPHRASE="..."`
- [ ] Start service: `kaspa-threshold-service --network mainnet`
- [ ] Monitor startup logs
- [ ] Verify "Mainnet mode" logged
- [ ] Check Kaspa node connection
- [ ] Verify all secrets loaded
- [ ] Test signing operation

**Post-Deployment**:
- [ ] Monitor audit logs: `tail -f /var/lib/igra/audit.log`
- [ ] Set up log monitoring/alerts
- [ ] Configure backup for secrets.bin
- [ ] Document recovery procedures
- [ ] Test incident response

---

## FAQ

### Q: What if I need to run mainnet with remote RPC temporarily?

**A**: Use the `--allow-remote-rpc` flag explicitly:

```bash
kaspa-threshold-service --network mainnet --allow-remote-rpc
```

You'll get warnings but service will start. Ensure the remote endpoint uses TLS (grpcs://).

### Q: Can I use testnet coin type in mainnet for testing?

**A**: NO. Mainnet validation will reject this. Use a testnet deployment for testing with testnet coin types.

### Q: What if I'm running in a secure environment (VM, container) - can I relax permissions?

**A**: Use `--network testnet` for moderate security if your environment provides isolation. Mainnet mode assumes zero trust.

### Q: What about Iroh bootstrap nodes - do they need to be localhost?

**A**: NO. Iroh configuration is intentionally flexible in all network modes. You can:
- Use preconfigured bootstrap nodes (any location)
- Use DNS/PKARR public services
- Use custom discovery
- Omit bootstrap entirely (pure DHT)

Iroh handles P2P security internally with Ed25519 authentication and encrypted transport.

### Q: Why is mainnet the default?

**A**: Fail-safe design. If someone forgets to specify `--network devnet`, they get strict validation instead of accidentally exposing secrets.

### Q: Can validation be skipped?

**A**: NO. Validation always runs. In mainnet, errors are fatal. In testnet/devnet, warnings are logged but service continues.

---

## Implementation Timeline

### Week 1: Core Implementation

**Day 1-2**: Foundation
- [ ] Create `network_mode/` directory structure
- [ ] Implement `NetworkMode` enum
- [ ] Implement `ValidationReport`
- [ ] Implement `SecurityValidator` skeleton

**Day 3-4**: Validation Rules
- [ ] Implement secrets validation
- [ ] Implement RPC endpoint validation
- [ ] Implement configuration validation
- [ ] Implement logging validation
- [ ] Implement file permissions validation
- [ ] Implement startup checks

**Day 5**: CLI Integration
- [ ] Add CLI flags to kaspa-threshold-service
- [ ] Wire validation into startup flow
- [ ] Add --validate-only flag

### Week 2: Testing & Documentation

**Day 1-2**: Testing
- [ ] Write unit tests for all validation rules
- [ ] Write integration tests for each network mode
- [ ] Test devnet scripts still work
- [ ] Test mainnet validation catches issues

**Day 3-4**: Documentation
- [ ] Update deployment guide
- [ ] Create mainnet checklist
- [ ] Document error messages
- [ ] Create runbook for common issues

**Day 5**: Team Validation
- [ ] Team testing in devnet
- [ ] Team testing in testnet
- [ ] Review security model
- [ ] Sign-off for production use

---

## Success Criteria

Implementation is complete when:

1. ✅ All three network modes implemented
2. ✅ Mainnet rejects insecure configurations
3. ✅ Testnet warns but continues
4. ✅ Devnet has minimal restrictions
5. ✅ RPC local-only enforced in mainnet
6. ✅ Remote RPC requires explicit flag
7. ✅ All tests pass
8. ✅ Devnet scripts work unchanged
9. ✅ Validation report is clear and actionable
10. ✅ Team can deploy to mainnet confidently

---

END OF GUIDE


---

## Inbound RPC Security (Server Side)

### Trust Model Overview

**Production Deployment** (per signer machine):

```
┌─────────────────────────────────────────┐
│  Signer Machine (Trusted Boundary)     │
│                                         │
│  ┌──────────┐    localhost              │
│  │ kaspad   │◄──────────────┐          │
│  │ :16110   │                │          │
│  └──────────┘                │          │
│                               │          │
│  ┌──────────────┐   ┌────────┴──────┐  │
│  │ hyperlane-   │──►│ igra-service  │  │
│  │ relayer      │   │ :8088 (HTTP)  │  │
│  └──────────────┘   └───────────────┘  │
│                               │          │
│                               │ Iroh P2P │
└───────────────────────────────┼──────────┘
                                │
                        (encrypted, authenticated)
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Signer 2   │         │  Signer 3   │         │  External   │
│  (remote)   │         │  (remote)   │         │  Client     │
│  TLS + Auth │         │  TLS + Auth │         │  TLS + Auth │
└─────────────┘         └─────────────┘         └─────────────┘
```

**Key insight**: 
- **On same machine**: Localhost communication (kaspad ↔ igra ↔ hyperlane-relayer)
- **Between machines**: Network communication (signer ↔ signer, client ↔ signer)

---

### Inbound RPC Security Rules

Igra **exposes** RPC endpoints on `rpc_address` for:
- Hyperlane relayers (submit cross-chain messages)
- Other signers (CRDT coordination, if using HTTP)
- Admin tools (management operations)
- Monitoring systems (health checks, metrics)

#### Mainnet Rules (Strict)

| Listen Address | TLS | Auth | Flag Required | Status |
|---------------|-----|------|---------------|--------|
| `127.0.0.1:*` | Optional | Optional | No | ✅ ALLOWED (local trust) |
| `0.0.0.0:*` | **MANDATORY** | **MANDATORY** | `--allow-remote-rpc-server` | ⚠️ ALLOWED with warning |
| `<specific-ip>:*` | **MANDATORY** | **MANDATORY** | `--allow-remote-rpc-server` | ⚠️ ALLOWED with warning |

**Validation Logic**:

```rust
fn validate_inbound_rpc(&self, config: &ServiceConfig, report: &mut ValidationReport) -> Result<(), ThresholdError> {
    match self.network_mode {
        NetworkMode::Mainnet => {
            for (profile_name, profile) in &config.profiles {
                let rpc_addr = &profile.rpc_address;
                
                // Parse listen address
                let is_localhost = rpc_addr.starts_with("127.")
                    || rpc_addr.starts_with("localhost:")
                    || rpc_addr.starts_with("::1");
                
                let is_network_exposed = rpc_addr.starts_with("0.0.0.0:")
                    || (!is_localhost && rpc_addr.contains(':'));

                if is_localhost {
                    // Local RPC server - acceptable
                    log::info!(
                        "✓ Profile '{}' RPC listening on localhost: {}",
                        profile_name,
                        rpc_addr
                    );
                    
                    // TLS and auth optional for localhost (same-machine trust)
                    if profile.rpc_tls_enabled.unwrap_or(false) {
                        log::info!(
                            "  TLS enabled for localhost (unnecessary but harmless)"
                        );
                    }
                } else if is_network_exposed {
                    // Network-exposed RPC server
                    
                    // STRICT: Require explicit flag
                    if !config.allow_remote_rpc_server {
                        report.add_error(
                            ErrorCategory::RpcEndpoint,
                            format!(
                                "Profile '{}' RPC server listens on network address: {}\n\
                                \n\
                                SECURITY: Mainnet RPC servers should listen on localhost (127.0.0.1) only.\n\
                                \n\
                                Your deployment model:\n\
                                - kaspad (local)\n\
                                - igra-service (local)\n\
                                - hyperlane-relayer (local)\n\
                                \n\
                                All services run on same machine = use localhost.\n\
                                \n\
                                If you have distributed signers or remote clients:\n\
                                - Add 'allow_remote_rpc_server = true' to config, OR\n\
                                - Use --allow-remote-rpc-server CLI flag\n\
                                \n\
                                This will require TLS + authentication.",
                                profile_name,
                                rpc_addr
                            )
                        );
                    } else {
                        // Remote RPC server allowed via flag
                        
                        // STRICT: TLS is MANDATORY (cannot be disabled)
                        if !profile.rpc_tls_enabled.unwrap_or(false) {
                            report.add_error(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Profile '{}' exposes RPC on network ({}) without TLS.\n\
                                    \n\
                                    Mainnet REQUIRES TLS for network-exposed RPC servers.\n\
                                    \n\
                                    Set in config:\n\
                                    [profiles.{}]\n\
                                    rpc_tls_enabled = true\n\
                                    rpc_tls_cert = \"/path/to/cert.pem\"\n\
                                    rpc_tls_key = \"/path/to/key.pem\"",
                                    profile_name,
                                    rpc_addr,
                                    profile_name
                                )
                            );
                        } else {
                            // Validate TLS certificate exists
                            if let Some(cert_path) = &profile.rpc_tls_cert {
                                if !Path::new(cert_path).exists() {
                                    report.add_error(
                                        ErrorCategory::RpcEndpoint,
                                        format!(
                                            "TLS certificate not found: {}",
                                            cert_path
                                        )
                                    );
                                }
                            } else {
                                report.add_error(
                                    ErrorCategory::RpcEndpoint,
                                    format!(
                                        "Profile '{}' has rpc_tls_enabled but no rpc_tls_cert configured",
                                        profile_name
                                    )
                                );
                            }
                            
                            if let Some(key_path) = &profile.rpc_tls_key {
                                if !Path::new(key_path).exists() {
                                    report.add_error(
                                        ErrorCategory::RpcEndpoint,
                                        format!(
                                            "TLS private key not found: {}",
                                            key_path
                                        )
                                    );
                                }
                            } else {
                                report.add_error(
                                    ErrorCategory::RpcEndpoint,
                                    format!(
                                        "Profile '{}' has rpc_tls_enabled but no rpc_tls_key configured",
                                        profile_name
                                    )
                                );
                            }
                        }
                        
                        // STRICT: Authentication is MANDATORY (cannot be disabled)
                        if !profile.rpc_require_auth.unwrap_or(false) {
                            report.add_error(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Profile '{}' exposes RPC on network without authentication.\n\
                                    \n\
                                    Mainnet REQUIRES authentication for network-exposed RPC.\n\
                                    \n\
                                    Set in config:\n\
                                    [profiles.{}]\n\
                                    rpc_require_auth = true\n\
                                    rpc_auth_tokens = [\"token1\", \"token2\"]  # API tokens\n\
                                    # OR\n\
                                    rpc_mtls_enabled = true  # Mutual TLS",
                                    profile_name,
                                    profile_name
                                )
                            );
                        } else {
                            // Validate auth configuration
                            let has_tokens = profile.rpc_auth_tokens
                                .as_ref()
                                .map(|t| !t.is_empty())
                                .unwrap_or(false);
                            
                            let has_mtls = profile.rpc_mtls_enabled.unwrap_or(false);
                            
                            if !has_tokens && !has_mtls {
                                report.add_error(
                                    ErrorCategory::RpcEndpoint,
                                    format!(
                                        "Profile '{}' has rpc_require_auth=true but no auth method configured.\n\
                                        Set either:\n\
                                        - rpc_auth_tokens = [\"...\"]  (API tokens), OR\n\
                                        - rpc_mtls_enabled = true (mutual TLS)",
                                        profile_name
                                    )
                                );
                            }
                        }
                        
                        // Log security warning
                        log::warn!(
                            "⚠️  SECURITY NOTICE: Profile '{}' RPC server exposed on network: {}",
                            profile_name,
                            rpc_addr
                        );
                        log::warn!(
                            "⚠️  NOT RECOMMENDED: Prefer localhost RPC with reverse proxy for external access"
                        );
                        log::warn!(
                            "⚠️  Recommended deployment: kaspad + igra-service + hyperlane-relayer on same machine"
                        );
                        
                        report.add_warning(
                            ErrorCategory::RpcEndpoint,
                            format!(
                                "Profile '{}' RPC server listening on network address: {}. \
                                Recommended: Use localhost (127.0.0.1) with reverse proxy.",
                                profile_name,
                                rpc_addr
                            )
                        );
                    }
                }
            }
        }
        
        NetworkMode::Testnet => {
            // MODERATE: Warn if network-exposed without TLS
            for (profile_name, profile) in &config.profiles {
                let rpc_addr = &profile.rpc_address;
                
                if rpc_addr.starts_with("0.0.0.0:") {
                    if !profile.rpc_tls_enabled.unwrap_or(false) {
                        report.add_warning(
                            ErrorCategory::RpcEndpoint,
                            format!(
                                "Profile '{}' RPC server exposed without TLS: {}",
                                profile_name,
                                rpc_addr
                            )
                        );
                    }
                    
                    if !profile.rpc_require_auth.unwrap_or(false) {
                        report.add_warning(
                            ErrorCategory::RpcEndpoint,
                            format!(
                                "Profile '{}' RPC server exposed without authentication: {}",
                                profile_name,
                                rpc_addr
                            )
                        );
                    }
                }
            }
        }
        
        NetworkMode::Devnet => {
            // RELAXED: Allow any RPC server configuration
            log::debug!("Devnet mode: allowing flexible RPC server configuration");
        }
    }
    
    Ok(())
}
```

---

### Configuration Schema Updates

**File**: `igra-core/src/infrastructure/config/types.rs`

Add to `ServiceConfig`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    // === Existing fields ===
    pub network: Option<String>,
    pub allow_remote_rpc: bool,  // For outbound (client) - connecting to kaspad
    
    // === NEW: Inbound RPC server security ===
    
    /// Allow RPC server to listen on network addresses (0.0.0.0 or specific IPs)
    ///
    /// Default: false (localhost only in mainnet)
    #[serde(default)]
    pub allow_remote_rpc_server: bool,
    
    // ... rest of config
}
```

Add to `ProfileConfig`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub name: String,
    pub key_type: KeyType,
    pub derivation_path: String,
    
    /// RPC server listen address
    ///
    /// Mainnet:
    /// - Use "127.0.0.1:<port>" for localhost-only (recommended)
    /// - Use "0.0.0.0:<port>" for network exposure (requires --allow-remote-rpc-server + TLS + auth)
    pub rpc_address: String,
    
    // === NEW: RPC Server Security ===
    
    /// Enable TLS for RPC server
    ///
    /// Mainnet: MANDATORY if rpc_address is not localhost
    /// Testnet/Devnet: Optional
    #[serde(default)]
    pub rpc_tls_enabled: Option<bool>,
    
    /// Path to TLS certificate (PEM format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_tls_cert: Option<String>,
    
    /// Path to TLS private key (PEM format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_tls_key: Option<String>,
    
    /// Require authentication for RPC requests
    ///
    /// Mainnet: MANDATORY if rpc_address is not localhost
    /// Testnet/Devnet: Recommended
    #[serde(default)]
    pub rpc_require_auth: Option<bool>,
    
    /// API tokens for Bearer authentication
    ///
    /// Clients must include: Authorization: Bearer <token>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_auth_tokens: Option<Vec<String>>,
    
    /// Enable mutual TLS (client certificates required)
    #[serde(default)]
    pub rpc_mtls_enabled: Option<bool>,
    
    /// Path to CA certificate for mTLS client verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_mtls_ca_cert: Option<String>,
    
    /// IP allowlist for RPC server (CIDR notation)
    ///
    /// Example: ["10.0.1.0/24", "192.168.1.100/32"]
    /// If set, only these IPs can connect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_allowed_ips: Option<Vec<String>>,
}
```

---

### Example Configurations

#### Configuration 1: Localhost-Only (Recommended for Mainnet)

**Use Case**: All services co-located on same machine

```toml
network = "mainnet"

# Outbound: Connect to local kaspad
node_url = "grpc://127.0.0.1:16110"

# Inbound: RPC server listens on localhost only
[profiles.signer-1]
name = "signer-1"
rpc_address = "127.0.0.1:8088"  # Localhost only - no network exposure
# TLS and auth optional for localhost (same-machine trust)

# Hyperlane relayer runs on same machine, connects via localhost
# Admin tools use localhost
# Monitoring uses localhost
```

**Validation**: ✅ PASS (no warnings)

**Security**:
- ✅ No network exposure
- ✅ Cannot be accessed from internet
- ✅ Hyperlane relayer connects locally
- ✅ All traffic on localhost (secure by OS design)

---

#### Configuration 2: Network-Exposed with TLS + Auth (Distributed Signers)

**Use Case**: Signers on different machines, or external clients

```toml
network = "mainnet"

# Outbound: Connect to local kaspad (still required)
node_url = "grpc://127.0.0.1:16110"

# Inbound: RPC server exposed on network (requires flag)
allow_remote_rpc_server = true  # Explicit opt-in

[profiles.signer-1]
name = "signer-1"
rpc_address = "0.0.0.0:8088"  # Listen on all interfaces

# TLS MANDATORY for network exposure
rpc_tls_enabled = true
rpc_tls_cert = "/etc/igra/certs/signer-1.crt"
rpc_tls_key = "/etc/igra/certs/signer-1.key"

# Authentication MANDATORY for network exposure
rpc_require_auth = true
rpc_auth_tokens = [
    "secret-token-for-hyperlane-relayer",
    "secret-token-for-signer-2",
    "secret-token-for-monitoring"
]

# Optional: IP allowlist for defense in depth
rpc_allowed_ips = [
    "10.0.1.0/24",      # Signer subnet
    "192.168.1.50/32"   # Monitoring server
]

[profiles.signer-2]
name = "signer-2"
rpc_address = "0.0.0.0:8089"
rpc_tls_enabled = true
rpc_tls_cert = "/etc/igra/certs/signer-2.crt"
rpc_tls_key = "/etc/igra/certs/signer-2.key"
rpc_require_auth = true
rpc_auth_tokens = ["..."]
```

**Validation**: ⚠️ PASS with warnings

**Logs**:
```
⚠️  SECURITY NOTICE: Profile 'signer-1' RPC server exposed on network: 0.0.0.0:8088
⚠️  NOT RECOMMENDED: Prefer localhost RPC with reverse proxy for external access
⚠️  Recommended deployment: kaspad + igra-service + hyperlane-relayer on same machine
✓ TLS enabled for profile 'signer-1'
✓ Authentication enabled for profile 'signer-1'
```

**Security**:
- ✅ TLS protects transport
- ✅ Auth prevents unauthorized access
- ✅ IP allowlist provides additional filtering
- ⚠️ Network exposure increases attack surface

---

#### Configuration 3: Mutual TLS (Highest Security for Network)

**Use Case**: Distributed signers with certificate-based authentication

```toml
network = "mainnet"
allow_remote_rpc_server = true

[profiles.signer-1]
name = "signer-1"
rpc_address = "0.0.0.0:8088"

# TLS with client certificate verification
rpc_tls_enabled = true
rpc_tls_cert = "/etc/igra/certs/signer-1-server.crt"
rpc_tls_key = "/etc/igra/certs/signer-1-server.key"

# Mutual TLS (client must present valid certificate)
rpc_mtls_enabled = true
rpc_mtls_ca_cert = "/etc/igra/certs/ca.crt"  # CA that signed client certs

# Optional: Additional token auth (defense in depth)
rpc_require_auth = true
rpc_auth_tokens = ["additional-token"]

# IP allowlist (defense in depth)
rpc_allowed_ips = ["10.0.1.0/24"]
```

**Validation**: ✅ PASS (warnings about network exposure)

**Security**:
- ✅ TLS encryption
- ✅ Client certificate verification (mTLS)
- ✅ API token validation
- ✅ IP allowlist
- 🔒 **Multi-layer security** (defense in depth)

---

### Validation Error Examples

#### Error 1: Network Exposure Without Flag

```toml
[profiles.signer-1]
rpc_address = "0.0.0.0:8088"
# allow_remote_rpc_server not set (missing flag)
```

**Error**:
```
❌ [RPC] Profile 'signer-1' RPC server listens on network address: 0.0.0.0:8088

SECURITY: Mainnet RPC servers should listen on localhost (127.0.0.1) only.

Your deployment model:
- kaspad (local)
- igra-service (local)
- hyperlane-relayer (local)

All services run on same machine = use localhost.

If you have distributed signers or remote clients:
- Add 'allow_remote_rpc_server = true' to config, OR
- Use --allow-remote-rpc-server CLI flag

This will require TLS + authentication.
```

**Fix**: Either use `127.0.0.1:8088` OR add `allow_remote_rpc_server = true` + TLS + auth

---

#### Error 2: Network Exposure Without TLS

```toml
allow_remote_rpc_server = true

[profiles.signer-1]
rpc_address = "0.0.0.0:8088"
# rpc_tls_enabled missing (TLS MANDATORY)
```

**Error**:
```
❌ [RPC] Profile 'signer-1' exposes RPC on network (0.0.0.0:8088) without TLS.

Mainnet REQUIRES TLS for network-exposed RPC servers.

Set in config:
[profiles.signer-1]
rpc_tls_enabled = true
rpc_tls_cert = "/path/to/cert.pem"
rpc_tls_key = "/path/to/key.pem"
```

**Fix**: Add TLS configuration (cannot be disabled in mainnet)

---

#### Error 3: Network Exposure Without Authentication

```toml
allow_remote_rpc_server = true

[profiles.signer-1]
rpc_address = "0.0.0.0:8088"
rpc_tls_enabled = true
rpc_tls_cert = "/etc/igra/certs/server.crt"
rpc_tls_key = "/etc/igra/certs/server.key"
# rpc_require_auth missing (AUTH MANDATORY)
```

**Error**:
```
❌ [RPC] Profile 'signer-1' exposes RPC on network without authentication.

Mainnet REQUIRES authentication for network-exposed RPC.

Set in config:
[profiles.signer-1]
rpc_require_auth = true
rpc_auth_tokens = ["token1", "token2"]  # API tokens
# OR
rpc_mtls_enabled = true  # Mutual TLS
```

**Fix**: Add authentication (cannot be disabled in mainnet)

---

### Complete RPC Security Summary

#### Outbound RPC (Igra → Kaspad)

| Mainnet Rule | Rationale |
|-------------|-----------|
| **Localhost required** | Trust your own kaspad node |
| **Remote needs flag** | Explicit opt-in for remote kaspad |
| **Remote needs TLS** | Protect connection to remote node |

#### Inbound RPC (External → Igra)

| Mainnet Rule | Rationale |
|-------------|-----------|
| **Localhost recommended** | Co-located deployment (kaspad + igra + hyperlane) |
| **Network needs flag** | Explicit opt-in for network exposure |
| **Network needs TLS** | MANDATORY - cannot be disabled |
| **Network needs auth** | MANDATORY - cannot be disabled |

#### Iroh P2P (Signer ↔ Signer)

| Mainnet Rule | Rationale |
|-------------|-----------|
| **Completely flexible** | Iroh provides transport security (Ed25519 + encryption) |
| **No restrictions** | Different groups use different discovery strategies |

---

### Recommended Production Architecture

**Standard Deployment** (per signer):

```
┌────────────────────────────────────────────────┐
│  Signer Machine (10.0.1.10)                   │
│                                                │
│  ┌──────────────────┐                         │
│  │  kaspad          │                         │
│  │  127.0.0.1:16110 │◄──┐                    │
│  └──────────────────┘   │                    │
│                          │                    │
│  ┌──────────────────┐   │  localhost         │
│  │  igra-service    │───┤  (trusted)         │
│  │  127.0.0.1:8088  │   │                    │
│  └──────────────────┘   │                    │
│         ▲                │                    │
│         │ localhost      │                    │
│         │                │                    │
│  ┌──────────────────┐   │                    │
│  │ hyperlane-       │───┘                    │
│  │ relayer          │                         │
│  └──────────────────┘                         │
│         │                                      │
│         │ Iroh P2P (encrypted)                │
└─────────┼──────────────────────────────────────┘
          │
          │ (network - TLS + auth + encryption)
          │
    ┌─────┴──────┬─────────────┐
    ▼            ▼             ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ Signer 2 │ │ Signer 3 │ │ External │
│ (remote) │ │ (remote) │ │ Client   │
└──────────┘ └──────────┘ └──────────┘
```

**Communication**:
1. **Localhost** (same machine): Unencrypted OK (OS-level security)
2. **Network** (between machines): TLS + Auth + Iroh encryption (multi-layer)

---

### Advanced: Reverse Proxy Pattern (Enterprise)

For **maximum security**, use reverse proxy on each machine:

```
External Request (HTTPS)
    ↓
┌────────────────────────────────┐
│  nginx (reverse proxy)         │
│  - TLS termination             │
│  - Authentication              │
│  - Rate limiting               │
│  - IP filtering                │
│  0.0.0.0:443 → 127.0.0.1:8088 │
└────────────────────────────────┘
    ↓ localhost
┌────────────────────────────────┐
│  igra-service                  │
│  127.0.0.1:8088 (no TLS)      │
└────────────────────────────────┘
```

**Configuration**:
```toml
[profiles.signer-1]
# Igra listens on localhost only
rpc_address = "127.0.0.1:8088"

# nginx handles TLS + auth + filtering
# (configured separately in /etc/nginx/sites-enabled/igra)
```

**Benefits**:
- ✅ Igra doesn't need TLS implementation
- ✅ nginx handles connection security
- ✅ Centralized auth/rate limiting
- ✅ Easier certificate management
- ✅ Can add WAF (Web Application Firewall)

**Validation**: ✅ PASS (localhost = no requirements)

---

### CLI Flags Summary

```bash
# Mainnet with localhost RPC server (recommended)
kaspa-threshold-service --network mainnet

# Mainnet with network-exposed RPC server (requires TLS + auth)
kaspa-threshold-service --network mainnet --allow-remote-rpc-server

# Mainnet with remote kaspad + network-exposed RPC server
kaspa-threshold-service --network mainnet --allow-remote-rpc --allow-remote-rpc-server

# Testnet (moderate security)
kaspa-threshold-service --network testnet

# Devnet (minimal security)
kaspa-threshold-service --network devnet
```

---

### Validation Logic: Complete Bidirectional RPC

**File**: `igra-core/src/infrastructure/network_mode/rules/rpc.rs`

```rust
//! RPC endpoint security validation (both inbound and outbound)

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::ServiceConfig;
use crate::infrastructure::network_mode::{NetworkMode, report::*};
use std::path::Path;

pub struct RpcValidator;

impl RpcValidator {
    /// Validate outbound RPC (Igra → Kaspad)
    pub fn validate_outbound_rpc(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet => {
                let node_url = &config.node_url;
                let host = Self::extract_host(node_url)?;
                let is_local = Self::is_localhost(&host);

                if !is_local {
                    // Remote kaspad detected
                    if !config.allow_remote_rpc {
                        report.add_error(
                            ErrorCategory::RpcEndpoint,
                            format!(
                                "Mainnet requires local Kaspa RPC endpoint (got: {}).\n\
                                \n\
                                SECURITY: Run kaspad locally for maximum security.\n\
                                Remote RPC can provide false blockchain data.\n\
                                \n\
                                To use remote kaspad (NOT RECOMMENDED):\n\
                                - Add 'allow_remote_rpc = true' to config, OR\n\
                                - Use --allow-remote-rpc CLI flag",
                                node_url
                            )
                        );
                    } else {
                        // Remote allowed, enforce TLS
                        if !node_url.starts_with("grpcs://") {
                            report.add_error(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Mainnet remote RPC must use TLS (grpcs://). Got: {}",
                                    node_url
                                )
                            );
                        }

                        report.add_warning(
                            ErrorCategory::RpcEndpoint,
                            format!(
                                "Using remote kaspad: {}. You trust {} for blockchain data.",
                                node_url, host
                            )
                        );
                    }
                } else {
                    log::info!("✓ Outbound RPC: Using local kaspad at {}", node_url);
                }
            }

            NetworkMode::Testnet => {
                // Warn about insecure remote
                if config.node_url.starts_with("grpc://")
                    && !Self::is_localhost(&Self::extract_host(&config.node_url).unwrap_or_default()) {
                    report.add_warning(
                        ErrorCategory::RpcEndpoint,
                        format!("Testnet using insecure remote RPC: {}", config.node_url)
                    );
                }
            }

            NetworkMode::Devnet => {
                // Allow anything
            }
        }

        Ok(())
    }

    /// Validate inbound RPC (External → Igra)
    pub fn validate_inbound_rpc(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet => {
                for (profile_name, profile) in &config.profiles {
                    let rpc_addr = &profile.rpc_address;
                    
                    // Determine if network-exposed
                    let is_localhost = rpc_addr.starts_with("127.")
                        || rpc_addr.starts_with("localhost:")
                        || rpc_addr.starts_with("::1")
                        || rpc_addr.starts_with("[::1]");
                    
                    let is_network = rpc_addr.starts_with("0.0.0.0:")
                        || (!is_localhost && rpc_addr.contains(':'));

                    if is_localhost {
                        // Localhost-only RPC server (RECOMMENDED)
                        log::info!(
                            "✓ Inbound RPC: Profile '{}' listening on localhost: {} (secure)",
                            profile_name,
                            rpc_addr
                        );
                    } else if is_network {
                        // Network-exposed RPC server
                        
                        // STRICT: Require explicit flag
                        if !config.allow_remote_rpc_server {
                            report.add_error(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Profile '{}' RPC server listens on network: {}\n\
                                    \n\
                                    MAINNET RECOMMENDED DEPLOYMENT:\n\
                                    - kaspad (localhost)\n\
                                    - igra-service (localhost)\n\
                                    - hyperlane-relayer (localhost)\n\
                                    → All on same machine, use rpc_address = \"127.0.0.1:8088\"\n\
                                    \n\
                                    For distributed signers or remote clients:\n\
                                    - Add 'allow_remote_rpc_server = true' to config, OR\n\
                                    - Use --allow-remote-rpc-server CLI flag\n\
                                    - This will require TLS + authentication (cannot be disabled)",
                                    profile_name,
                                    rpc_addr
                                )
                            );
                        } else {
                            // Network exposure allowed via flag
                            
                            // TLS is MANDATORY (cannot be disabled)
                            if !profile.rpc_tls_enabled.unwrap_or(false) {
                                report.add_error(
                                    ErrorCategory::RpcEndpoint,
                                    format!(
                                        "Profile '{}' network-exposed RPC REQUIRES TLS (cannot be disabled).\n\
                                        \n\
                                        Set in config:\n\
                                        [profiles.{}]\n\
                                        rpc_tls_enabled = true\n\
                                        rpc_tls_cert = \"/etc/igra/certs/server.crt\"\n\
                                        rpc_tls_key = \"/etc/igra/certs/server.key\"",
                                        profile_name,
                                        profile_name
                                    )
                                );
                            } else {
                                Self::validate_tls_files(profile_name, profile, report)?;
                            }
                            
                            // Authentication is MANDATORY (cannot be disabled)
                            if !profile.rpc_require_auth.unwrap_or(false) {
                                report.add_error(
                                    ErrorCategory::RpcEndpoint,
                                    format!(
                                        "Profile '{}' network-exposed RPC REQUIRES authentication (cannot be disabled).\n\
                                        \n\
                                        Set in config:\n\
                                        [profiles.{}]\n\
                                        rpc_require_auth = true\n\
                                        rpc_auth_tokens = [\"token1\", \"token2\"]  # API tokens\n\
                                        # OR\n\
                                        rpc_mtls_enabled = true  # Client certificates",
                                        profile_name,
                                        profile_name
                                    )
                                );
                            } else {
                                Self::validate_auth_config(profile_name, profile, report)?;
                            }
                            
                            // Log security warnings
                            log::warn!(
                                "⚠️  SECURITY NOTICE: Profile '{}' RPC server exposed on network: {}",
                                profile_name,
                                rpc_addr
                            );
                            log::warn!(
                                "⚠️  NOT RECOMMENDED: Prefer localhost (127.0.0.1) with reverse proxy"
                            );
                            log::warn!(
                                "⚠️  Recommended: kaspad + igra-service + hyperlane-relayer on same machine"
                            );
                            
                            report.add_warning(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Profile '{}' RPC exposed on network: {}. \
                                    Recommended: Use 127.0.0.1 with reverse proxy for external access.",
                                    profile_name,
                                    rpc_addr
                                )
                            );
                        }
                    }
                }
            }

            NetworkMode::Testnet => {
                // MODERATE: Warn about network exposure without security
                for (profile_name, profile) in &config.profiles {
                    let rpc_addr = &profile.rpc_address;
                    
                    if rpc_addr.starts_with("0.0.0.0:") {
                        if !profile.rpc_tls_enabled.unwrap_or(false) {
                            report.add_warning(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Profile '{}' RPC server exposed without TLS: {}",
                                    profile_name, rpc_addr
                                )
                            );
                        }
                        
                        if !profile.rpc_require_auth.unwrap_or(false) {
                            report.add_warning(
                                ErrorCategory::RpcEndpoint,
                                format!(
                                    "Profile '{}' RPC server exposed without auth: {}",
                                    profile_name, rpc_addr
                                )
                            );
                        }
                    }
                }
            }

            NetworkMode::Devnet => {
                // RELAXED: Allow any configuration
            }
        }

        Ok(())
    }

    fn validate_tls_files(
        profile_name: &str,
        profile: &ProfileConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // Check certificate file exists
        if let Some(cert_path) = &profile.rpc_tls_cert {
            if !Path::new(cert_path).exists() {
                report.add_error(
                    ErrorCategory::RpcEndpoint,
                    format!(
                        "Profile '{}': TLS certificate not found: {}",
                        profile_name, cert_path
                    )
                );
            }
        } else {
            report.add_error(
                ErrorCategory::RpcEndpoint,
                format!(
                    "Profile '{}' has rpc_tls_enabled but no rpc_tls_cert path",
                    profile_name
                )
            );
        }
        
        // Check private key file exists
        if let Some(key_path) = &profile.rpc_tls_key {
            if !Path::new(key_path).exists() {
                report.add_error(
                    ErrorCategory::RpcEndpoint,
                    format!(
                        "Profile '{}': TLS private key not found: {}",
                        profile_name, key_path
                    )
                );
            } else {
                // Validate key file permissions (Unix)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::fs::metadata(key_path)?.permissions().mode() & 0o777;
                    if mode != 0o600 {
                        report.add_error(
                            ErrorCategory::FilePermissions,
                            format!(
                                "Profile '{}': TLS key has insecure permissions: {:o} (expected 0600)\n\
                                Fix with: chmod 600 {}",
                                profile_name, mode, key_path
                            )
                        );
                    }
                }
            }
        } else {
            report.add_error(
                ErrorCategory::RpcEndpoint,
                format!(
                    "Profile '{}' has rpc_tls_enabled but no rpc_tls_key path",
                    profile_name
                )
            );
        }

        Ok(())
    }

    fn validate_auth_config(
        profile_name: &str,
        profile: &ProfileConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        let has_tokens = profile.rpc_auth_tokens
            .as_ref()
            .map(|tokens| !tokens.is_empty())
            .unwrap_or(false);
        
        let has_mtls = profile.rpc_mtls_enabled.unwrap_or(false);
        
        if !has_tokens && !has_mtls {
            report.add_error(
                ErrorCategory::RpcEndpoint,
                format!(
                    "Profile '{}' has rpc_require_auth=true but no auth method configured.\n\
                    \n\
                    Choose one or both:\n\
                    - rpc_auth_tokens = [\"token1\", \"token2\"]  (API tokens)\n\
                    - rpc_mtls_enabled = true (client certificates)",
                    profile_name
                )
            );
        }
        
        // Validate mTLS configuration
        if has_mtls {
            if profile.rpc_mtls_ca_cert.is_none() {
                report.add_error(
                    ErrorCategory::RpcEndpoint,
                    format!(
                        "Profile '{}' has rpc_mtls_enabled but no rpc_mtls_ca_cert configured",
                        profile_name
                    )
                );
            } else if let Some(ca_path) = &profile.rpc_mtls_ca_cert {
                if !Path::new(ca_path).exists() {
                    report.add_error(
                        ErrorCategory::RpcEndpoint,
                        format!(
                            "Profile '{}': mTLS CA certificate not found: {}",
                            profile_name, ca_path
                        )
                    );
                }
            }
        }

        Ok(())
    }

    // Helper methods
    
    fn extract_host(url: &str) -> Result<String, String> {
        let without_scheme = url
            .strip_prefix("grpc://")
            .or_else(|| url.strip_prefix("grpcs://"))
            .or_else(|| url.strip_prefix("http://"))
            .or_else(|| url.strip_prefix("https://"))
            .ok_or_else(|| format!("Invalid URL scheme: {}", url))?;

        let host = without_scheme
            .split('@').last()  // Handle user:pass@host
            .unwrap_or(without_scheme)
            .split(':').next()
            .ok_or_else(|| "Missing host".to_string())?;

        Ok(host.to_string())
    }

    fn is_localhost(host: &str) -> bool {
        host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host == "[::1]"
            || host.starts_with("127.")
    }
}
```

---

## Complete Security Matrix

### Mainnet RPC Security (Both Directions)

| Direction | Endpoint Type | Default | TLS | Auth | Flag Required |
|-----------|--------------|---------|-----|------|---------------|
| **Outbound** (→ kaspad) | Localhost | ✅ REQUIRED | Optional | Optional | No |
| **Outbound** (→ kaspad) | Remote | ❌ FORBIDDEN | MANDATORY | Recommended | `--allow-remote-rpc` |
| **Inbound** (← clients) | Localhost | ✅ RECOMMENDED | Optional | Optional | No |
| **Inbound** (← clients) | Network | ⚠️ NOT RECOMMENDED | **MANDATORY** | **MANDATORY** | `--allow-remote-rpc-server` |

### Summary Table

| Service | Listen Address | Mainnet Default | Notes |
|---------|---------------|-----------------|-------|
| **kaspad** | 127.0.0.1:16110 | ✅ Local | Your trusted blockchain node |
| **igra-service** | 127.0.0.1:8088 | ✅ Local | Recommended (co-located with hyperlane) |
| **hyperlane-relayer** | (client only) | N/A | Calls igra on localhost |
| **Iroh P2P** | 0.0.0.0:4433 | ✅ Flexible | Encrypted transport, any config allowed |

---

## Production Deployment Patterns

### Pattern 1: Single Machine (Recommended)

**Architecture**: All services co-located

```
Signer Machine 1:          Signer Machine 2:          Signer Machine 3:
┌────────────────┐        ┌────────────────┐        ┌────────────────┐
│ kaspad         │        │ kaspad         │        │ kaspad         │
│ igra-service   │◄──────►│ igra-service   │◄──────►│ igra-service   │
│ hyperlane      │  Iroh  │ hyperlane      │  Iroh  │ hyperlane      │
└────────────────┘        └────────────────┘        └────────────────┘
   All localhost            All localhost            All localhost
```

**Configuration**:
```toml
node_url = "grpc://127.0.0.1:16110"  # Local kaspad
rpc_address = "127.0.0.1:8088"        # Local RPC server

# Iroh handles signer-to-signer communication (encrypted)
[iroh]
listen_addr = "0.0.0.0:4433"  # Iroh QUIC (secure)
```

**Security**: ✅ Maximum (no network-exposed HTTP)

---

### Pattern 2: Reverse Proxy (Enterprise)

**Architecture**: nginx provides TLS/auth termination

```
External → nginx (TLS + auth) → igra-service (localhost)
            0.0.0.0:443           127.0.0.1:8088
```

**Configuration**:
```toml
# Igra listens on localhost only
rpc_address = "127.0.0.1:8088"

# nginx.conf handles TLS + authentication
# (see deployment guide for nginx example)
```

**Security**: ✅ Maximum (TLS + auth via nginx, igra unexposed)

---

### Pattern 3: Direct Network Exposure (Not Recommended)

**Architecture**: Igra directly exposed to network

```toml
rpc_address = "0.0.0.0:8088"
allow_remote_rpc_server = true

# TLS MANDATORY (cannot be disabled)
rpc_tls_enabled = true
rpc_tls_cert = "/etc/igra/certs/server.crt"
rpc_tls_key = "/etc/igra/certs/server.key"

# Auth MANDATORY (cannot be disabled)
rpc_require_auth = true
rpc_auth_tokens = ["secure-random-token-1", "secure-random-token-2"]
```

**Security**: ⚠️ Acceptable with warnings (prefer reverse proxy)

---

## Testing Checklist

### Inbound RPC Tests

**Test 1: Localhost-only passes**
```rust
#[test]
fn test_mainnet_allows_localhost_rpc_server() {
    let mut config = ServiceConfig::default();
    config.network = Some("mainnet".to_string());
    
    let mut profile = ProfileConfig::default();
    profile.rpc_address = "127.0.0.1:8088".to_string();
    config.profiles.insert("signer-1".to_string(), profile);
    
    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate(&config).await.unwrap();
    
    assert!(!report.has_errors());
}
```

**Test 2: Network exposure without flag fails**
```rust
#[test]
fn test_mainnet_rejects_network_rpc_without_flag() {
    let mut config = ServiceConfig::default();
    config.network = Some("mainnet".to_string());
    config.allow_remote_rpc_server = false;
    
    let mut profile = ProfileConfig::default();
    profile.rpc_address = "0.0.0.0:8088".to_string();
    config.profiles.insert("signer-1".to_string(), profile);
    
    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate(&config).await.unwrap();
    
    assert!(report.has_errors());
    assert!(report.errors[0].message.contains("network"));
}
```

**Test 3: Network exposure without TLS fails**
```rust
#[test]
fn test_mainnet_rejects_network_rpc_without_tls() {
    let mut config = ServiceConfig::default();
    config.network = Some("mainnet".to_string());
    config.allow_remote_rpc_server = true;
    
    let mut profile = ProfileConfig::default();
    profile.rpc_address = "0.0.0.0:8088".to_string();
    profile.rpc_tls_enabled = Some(false);  // TLS disabled
    config.profiles.insert("signer-1".to_string(), profile);
    
    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate(&config).await.unwrap();
    
    assert!(report.has_errors());
    assert!(report.errors[0].message.contains("TLS"));
    assert!(report.errors[0].message.contains("MANDATORY"));
}
```

**Test 4: Network exposure with TLS but no auth fails**
```rust
#[test]
fn test_mainnet_rejects_network_rpc_without_auth() {
    let mut config = ServiceConfig::default();
    config.network = Some("mainnet".to_string());
    config.allow_remote_rpc_server = true;
    
    let mut profile = ProfileConfig::default();
    profile.rpc_address = "0.0.0.0:8088".to_string();
    profile.rpc_tls_enabled = Some(true);
    profile.rpc_tls_cert = Some("/etc/igra/cert.pem".to_string());
    profile.rpc_tls_key = Some("/etc/igra/key.pem".to_string());
    profile.rpc_require_auth = Some(false);  // Auth disabled
    config.profiles.insert("signer-1".to_string(), profile);
    
    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate(&config).await.unwrap();
    
    assert!(report.has_errors());
    assert!(report.errors[0].message.contains("authentication"));
    assert!(report.errors[0].message.contains("MANDATORY"));
}
```

**Test 5: Complete network exposure with TLS + auth passes**
```rust
#[test]
fn test_mainnet_allows_network_rpc_with_security() {
    let mut config = ServiceConfig::default();
    config.network = Some("mainnet".to_string());
    config.allow_remote_rpc_server = true;
    
    let mut profile = ProfileConfig::default();
    profile.rpc_address = "0.0.0.0:8088".to_string();
    profile.rpc_tls_enabled = Some(true);
    profile.rpc_tls_cert = Some("/tmp/test-cert.pem".to_string());
    profile.rpc_tls_key = Some("/tmp/test-key.pem".to_string());
    profile.rpc_require_auth = Some(true);
    profile.rpc_auth_tokens = Some(vec!["token1".to_string()]);
    
    // Create test cert files
    std::fs::write("/tmp/test-cert.pem", "fake-cert").unwrap();
    std::fs::write("/tmp/test-key.pem", "fake-key").unwrap();
    
    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate(&config).await.unwrap();
    
    assert!(!report.has_errors());
    assert!(report.has_warnings());  // Warning about network exposure
}
```

---

## Quick Reference: RPC Security

### ✅ Recommended: Localhost-Only (Mainnet Default)

```toml
# OUTBOUND: Connect to local kaspad
node_url = "grpc://127.0.0.1:16110"

# INBOUND: Listen on localhost only
[profiles.signer-1]
rpc_address = "127.0.0.1:8088"

# No TLS/auth required (localhost trust)
# hyperlane-relayer runs locally, connects via 127.0.0.1:8088
```

**Deploy**: kaspad + igra-service + hyperlane-relayer on **same machine**

---

### ⚠️ Acceptable: Network-Exposed with Security

```toml
# OUTBOUND: Still use local kaspad
node_url = "grpc://127.0.0.1:16110"

# INBOUND: Exposed to network (explicit flag required)
allow_remote_rpc_server = true

[profiles.signer-1]
rpc_address = "0.0.0.0:8088"

# TLS MANDATORY (cannot be disabled in mainnet)
rpc_tls_enabled = true
rpc_tls_cert = "/etc/igra/certs/server.crt"
rpc_tls_key = "/etc/igra/certs/server.key"

# Auth MANDATORY (cannot be disabled in mainnet)
rpc_require_auth = true
rpc_auth_tokens = ["token-for-hyperlane", "token-for-monitoring"]

# Optional: IP allowlist
rpc_allowed_ips = ["10.0.1.0/24"]
```

**Deploy**: Distributed signers OR external clients need network access

---

### 🔒 Iroh P2P (Always Flexible)

```toml
# Iroh configuration is intentionally unrestricted in all modes

[iroh]
# Option 1: Preconfigured bootstrap (any network mode)
bootstrap_nodes = [
    "/ip4/10.0.1.10/udp/4433/quic-v1/p2p/12D3KooW..."
]

# Option 2: DNS/PKARR discovery (any network mode)
# (omit bootstrap_nodes, use public discovery)

# Option 3: Custom PKARR relay (any network mode)
pkarr_relay = "https://pkarr.example.com"

# Listen address (always allowed on network)
listen_addr = "0.0.0.0:4433"  # QUIC transport (encrypted by Iroh)
```

**Rationale**: Iroh provides its own security layer (Ed25519 + encryption)

---

## Error Message Examples

### Error: Network RPC Without Flag

```
❌ [RPC] Profile 'signer-1' RPC server listens on network: 0.0.0.0:8088

MAINNET RECOMMENDED DEPLOYMENT:
- kaspad (localhost)
- igra-service (localhost)
- hyperlane-relayer (localhost)
→ All on same machine, use rpc_address = "127.0.0.1:8088"

For distributed signers or remote clients:
- Add 'allow_remote_rpc_server = true' to config, OR
- Use --allow-remote-rpc-server CLI flag
- This will require TLS + authentication (cannot be disabled)
```

---

### Error: Network RPC Without TLS

```
❌ [RPC] Profile 'signer-1' network-exposed RPC REQUIRES TLS (cannot be disabled).

Set in config:
[profiles.signer-1]
rpc_tls_enabled = true
rpc_tls_cert = "/etc/igra/certs/server.crt"
rpc_tls_key = "/etc/igra/certs/server.key"
```

---

### Error: Network RPC Without Auth

```
❌ [RPC] Profile 'signer-1' network-exposed RPC REQUIRES authentication (cannot be disabled).

Set in config:
[profiles.signer-1]
rpc_require_auth = true
rpc_auth_tokens = ["token1", "token2"]  # API tokens
# OR
rpc_mtls_enabled = true  # Client certificates
```

---

### Warning: Network RPC Allowed

```
⚠️  SECURITY NOTICE: Profile 'signer-1' RPC server exposed on network: 0.0.0.0:8088
⚠️  NOT RECOMMENDED: Prefer localhost (127.0.0.1) with reverse proxy
⚠️  Recommended: kaspad + igra-service + hyperlane-relayer on same machine

[RPC] Profile 'signer-1' RPC exposed on network: 0.0.0.0:8088. 
Recommended: Use 127.0.0.1 with reverse proxy for external access.
```

---

## Updated Validation Checklist

### Mainnet Pre-Deployment (Inbound RPC)

**For Localhost RPC (Recommended)**:
- [ ] Set `rpc_address = "127.0.0.1:<port>"`
- [ ] Deploy kaspad locally
- [ ] Deploy hyperlane-relayer locally
- [ ] All services on same machine
- [ ] No TLS/auth required (localhost trust)

**For Network-Exposed RPC (Not Recommended)**:
- [ ] Set `allow_remote_rpc_server = true`
- [ ] Set `rpc_address = "0.0.0.0:<port>"`
- [ ] Generate TLS certificates (server cert + key)
- [ ] Set `rpc_tls_enabled = true`
- [ ] Set `rpc_tls_cert` and `rpc_tls_key` paths
- [ ] Generate API tokens (strong random strings)
- [ ] Set `rpc_require_auth = true`
- [ ] Set `rpc_auth_tokens = ["..."]`
- [ ] Optional: Configure IP allowlist
- [ ] Optional: Enable mTLS for client certificates
- [ ] Set TLS key permissions: `chmod 600 /etc/igra/certs/server.key`
- [ ] Test TLS handshake: `openssl s_client -connect <host>:<port>`
- [ ] Test authentication: `curl -H "Authorization: Bearer <token>" https://<host>:<port>/health`

---


---

## Step-by-Step Implementation Guide

### Overview of Modular Architecture

We implement network mode security validation using **modular design**:

```
network_mode/
├── mod.rs              - NetworkMode enum, public API
├── report.rs           - ValidationReport and error types
├── validator.rs        - SecurityValidator (orchestrator)
└── rules/              - Individual validation modules
    ├── mod.rs          - Exports all rules
    ├── secrets.rs      - Secret management validation
    ├── rpc.rs          - RPC endpoint validation (inbound + outbound)
    ├── config.rs       - Configuration validation
    ├── logging.rs      - Logging security validation
    ├── filesystem.rs   - File permissions validation (Unix)
    └── startup.rs      - Startup readiness checks (mainnet)
```

**Benefits**:
- Clean separation of concerns
- Each validator testable independently
- Easy to add new validation rules
- Matches KeyManager architecture

---

### Implementation Steps

#### Phase 1: Foundation (Day 1)

1. Create directory structure
2. Implement NetworkMode enum (mod.rs)
3. Implement ValidationReport (report.rs)
4. Write tests for NetworkMode

**Deliverable**: Core types compile and test

#### Phase 2: Validation Rules (Day 2-3)

5. Implement secrets validation (rules/secrets.rs)
6. Implement RPC validation (rules/rpc.rs)
7. Implement config validation (rules/config.rs)
8. Implement logging validation (rules/logging.rs)
9. Implement filesystem validation (rules/filesystem.rs)
10. Implement startup validation (rules/startup.rs)
11. Write tests for each rule module

**Deliverable**: All validation rules working independently

#### Phase 3: Integration (Day 4)

12. Implement SecurityValidator orchestrator (validator.rs)
13. Update CLI to accept network mode flags
14. Wire validation into service startup
15. Add --validate-only flag

**Deliverable**: Validation runs at startup

#### Phase 4: Testing & Documentation (Day 5)

16. Integration tests for each network mode
17. End-to-end tests
18. Update deployment documentation
19. Team training

**Deliverable**: Production-ready feature

---

## Complete File Implementations

### File 2: Validation Report (Complete)

**File**: `igra-core/src/infrastructure/network_mode/report.rs`

```rust
//! Validation report and error accumulation

use crate::infrastructure::network_mode::NetworkMode;
use std::fmt;

/// Category of validation error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Secret management (encryption, storage, access)
    Secrets,
    
    /// RPC endpoint configuration (inbound and outbound)
    RpcEndpoint,
    
    /// General configuration validation
    Configuration,
    
    /// Logging security (levels, rotation)
    Logging,
    
    /// File system permissions
    FilePermissions,
    
    /// Startup readiness checks
    Startup,
    
    /// Network and address validation
    Network,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secrets => write!(f, "SECRETS"),
            Self::RpcEndpoint => write!(f, "RPC"),
            Self::Configuration => write!(f, "CONFIG"),
            Self::Logging => write!(f, "LOGGING"),
            Self::FilePermissions => write!(f, "PERMISSIONS"),
            Self::Startup => write!(f, "STARTUP"),
            Self::Network => write!(f, "NETWORK"),
        }
    }
}

/// Validation error with category and message
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub category: ErrorCategory,
    pub message: String,
}

/// Validation warning with category and message
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub category: ErrorCategory,
    pub message: String,
}

/// Validation report accumulates errors and warnings
#[derive(Debug, Clone)]
pub struct ValidationReport {
    network_mode: NetworkMode,
    errors: Vec<ValidationError>,
    warnings: Vec<ValidationWarning>,
}

impl ValidationReport {
    /// Create new validation report for a network mode
    pub fn new(network_mode: NetworkMode) -> Self {
        Self {
            network_mode,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Add validation error
    pub fn add_error(&mut self, category: ErrorCategory, message: impl Into<String>) {
        self.errors.push(ValidationError {
            category,
            message: message.into(),
        });
    }

    /// Add validation warning
    pub fn add_warning(&mut self, category: ErrorCategory, message: impl Into<String>) {
        self.warnings.push(ValidationWarning {
            category,
            message: message.into(),
        });
    }

    /// Check if any errors present
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Check if any warnings present
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Get error count
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Get warning count
    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// Get network mode
    pub fn network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    /// Get errors slice
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    /// Get warnings slice
    pub fn warnings(&self) -> &[ValidationWarning] {
        &self.warnings
    }

    /// Format as human-readable report
    pub fn format_report(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n🔍 Security Validation Report ({})\n",
            self.network_mode
        ));
        output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        if self.errors.is_empty() && self.warnings.is_empty() {
            output.push_str("✅ All validation checks passed\n");
            return output;
        }

        if !self.errors.is_empty() {
            output.push_str(&format!("❌ {} ERROR(S) FOUND:\n\n", self.errors.len()));
            for (i, error) in self.errors.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. [{:?}] {}\n",
                    i + 1,
                    error.category,
                    error.message
                ));
            }
            output.push('\n');
        }

        if !self.warnings.is_empty() {
            output.push_str(&format!("⚠️  {} WARNING(S):\n\n", self.warnings.len()));
            for (i, warning) in self.warnings.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. [{:?}] {}\n",
                    i + 1,
                    warning.category,
                    warning.message
                ));
            }
            output.push('\n');
        }

        if self.network_mode.is_production() && self.has_errors() {
            output.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            output.push_str("❌ Mainnet validation FAILED - fix errors above before starting\n");
        }

        output
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_report())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_report_empty() {
        let report = ValidationReport::new(NetworkMode::Mainnet);
        assert!(!report.has_errors());
        assert!(!report.has_warnings());
        
        let formatted = report.format_report();
        assert!(formatted.contains("All validation checks passed"));
    }

    #[test]
    fn test_validation_report_with_errors() {
        let mut report = ValidationReport::new(NetworkMode::Mainnet);
        report.add_error(ErrorCategory::Secrets, "Test error 1");
        report.add_error(ErrorCategory::RpcEndpoint, "Test error 2");
        
        assert!(report.has_errors());
        assert_eq!(report.error_count(), 2);
        
        let formatted = report.format_report();
        assert!(formatted.contains("2 ERROR(S) FOUND"));
        assert!(formatted.contains("Test error 1"));
        assert!(formatted.contains("FAILED"));
    }

    #[test]
    fn test_validation_report_with_warnings() {
        let mut report = ValidationReport::new(NetworkMode::Testnet);
        report.add_warning(ErrorCategory::Logging, "Test warning");
        
        assert!(report.has_warnings());
        assert!(!report.has_errors());
        
        let formatted = report.format_report();
        assert!(formatted.contains("WARNING"));
    }
}
```

---

### File 3: Secrets Validation Rules

**File**: `igra-core/src/infrastructure/network_mode/rules/secrets.rs`

```rust
//! Secret management security validation

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::ServiceConfig;
use crate::infrastructure::network_mode::{NetworkMode, report::*};
use std::path::Path;

pub struct SecretsValidator;

impl SecretsValidator {
    pub fn validate(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet => Self::validate_mainnet(config, report),
            NetworkMode::Testnet => Self::validate_testnet(config, report),
            NetworkMode::Devnet => Self::validate_devnet(config, report),
        }
    }

    fn validate_mainnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // STRICT: Must use encrypted secrets
        if !config.use_encrypted_secrets {
            report.add_error(
                ErrorCategory::Secrets,
                "Mainnet requires encrypted secrets file (set use_encrypted_secrets=true in config)"
            );
        }

        // STRICT: No environment variable secrets
        if std::env::var("KASPA_IGRA_WALLET_SECRET").is_ok() {
            report.add_error(
                ErrorCategory::Secrets,
                "Mainnet forbids KASPA_IGRA_WALLET_SECRET environment variable (use secrets.bin instead)"
            );
        }

        // STRICT: Must have secrets file configured
        if config.secrets_file.is_none() {
            report.add_error(
                ErrorCategory::Secrets,
                "Mainnet requires secrets_file path in configuration"
            );
        }

        // STRICT: Must have audit logging
        if config.key_audit_log_path.is_none() {
            report.add_error(
                ErrorCategory::Secrets,
                "Mainnet requires audit logging (set key_audit_log_path in config)"
            );
        }

        // STRICT: Secrets file must exist
        if let Some(secrets_path) = &config.secrets_file {
            if !Path::new(secrets_path).exists() {
                report.add_error(
                    ErrorCategory::Secrets,
                    format!("Secrets file does not exist: {}", secrets_path)
                );
            }
        }

        // STRICT: No passphrase from stdin in production
        if std::env::var("IGRA_SECRETS_PASSPHRASE").is_err() {
            report.add_error(
                ErrorCategory::Secrets,
                "Mainnet requires IGRA_SECRETS_PASSPHRASE environment variable \
                (interactive passphrase prompts are insecure in production)"
            );
        }

        Ok(())
    }

    fn validate_testnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // MODERATE: Warn if not using encrypted secrets
        if !config.use_encrypted_secrets {
            report.add_warning(
                ErrorCategory::Secrets,
                "Testnet should use encrypted secrets file (set use_encrypted_secrets=true)"
            );
        }

        // MODERATE: Warn if no audit logging
        if config.key_audit_log_path.is_none() {
            report.add_warning(
                ErrorCategory::Secrets,
                "Testnet should enable audit logging (set key_audit_log_path)"
            );
        }

        Ok(())
    }

    fn validate_devnet(
        _config: &ServiceConfig,
        _report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // RELAXED: No requirements
        log::debug!("Devnet mode: allowing flexible secret configuration");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_rejects_env_secrets() {
        std::env::set_var("KASPA_IGRA_WALLET_SECRET", "test");
        
        let mut config = ServiceConfig::default();
        config.use_encrypted_secrets = false;
        
        let mut report = ValidationReport::new(NetworkMode::Mainnet);
        SecretsValidator::validate(&config, NetworkMode::Mainnet, &mut report).unwrap();
        
        assert!(report.has_errors());
        assert!(report.error_count() >= 2); // Both env var and encrypted_secrets
    }

    #[test]
    fn test_testnet_warns_env_secrets() {
        let mut config = ServiceConfig::default();
        config.use_encrypted_secrets = false;
        
        let mut report = ValidationReport::new(NetworkMode::Testnet);
        SecretsValidator::validate(&config, NetworkMode::Testnet, &mut report).unwrap();
        
        assert!(report.has_warnings());
        assert!(!report.has_errors());
    }

    #[test]
    fn test_devnet_allows_env_secrets() {
        let mut config = ServiceConfig::default();
        config.use_encrypted_secrets = false;
        
        let mut report = ValidationReport::new(NetworkMode::Devnet);
        SecretsValidator::validate(&config, NetworkMode::Devnet, &mut report).unwrap();
        
        assert!(!report.has_errors());
        assert!(!report.has_warnings());
    }
}
```

---

### File 4: Configuration Validation Rules

**File**: `igra-core/src/infrastructure/network_mode/rules/config.rs`

```rust
//! Configuration validation rules

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::{KeyType, ServiceConfig};
use crate::infrastructure::network_mode::{NetworkMode, report::*};

pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet => Self::validate_mainnet(config, report),
            NetworkMode::Testnet => Self::validate_testnet(config, report),
            NetworkMode::Devnet => Self::validate_devnet(config, report),
        }
    }

    fn validate_mainnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // STRICT: Must explicitly confirm network
        if config.network.as_deref() != Some("mainnet") {
            report.add_error(
                ErrorCategory::Configuration,
                "Mainnet mode requires explicit 'network = \"mainnet\"' in config \
                (prevents accidental use of test configuration)"
            );
        }

        // STRICT: Validate threshold values
        if config.group.threshold_m > config.group.threshold_n {
            report.add_error(
                ErrorCategory::Configuration,
                format!(
                    "Invalid threshold: m={} > n={}",
                    config.group.threshold_m,
                    config.group.threshold_n
                )
            );
        }

        if config.group.threshold_m < 2 {
            report.add_error(
                ErrorCategory::Configuration,
                format!(
                    "Mainnet requires threshold m >= 2 (got m={}). \
                    Single signer is insecure for production.",
                    config.group.threshold_m
                )
            );
        }

        // STRICT: Must have sufficient profiles
        if config.profiles.len() < config.group.threshold_m {
            report.add_error(
                ErrorCategory::Configuration,
                format!(
                    "Insufficient profiles: {} configured, need at least m={}",
                    config.profiles.len(),
                    config.group.threshold_m
                )
            );
        }

        // STRICT: Validate data directory path
        if let Some(data_dir_str) = config.data_dir.to_str() {
            if data_dir_str.contains("devnet") || data_dir_str.contains("test") {
                report.add_error(
                    ErrorCategory::Configuration,
                    format!(
                        "Mainnet data directory path contains 'devnet' or 'test': {}. \
                        This suggests test configuration being used.",
                        data_dir_str
                    )
                );
            }
        }

        Ok(())
    }

    fn validate_testnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // MODERATE: Warn if network not confirmed
        if config.network.as_deref() != Some("testnet") {
            report.add_warning(
                ErrorCategory::Configuration,
                "Testnet should have 'network = \"testnet\"' in config"
            );
        }

        // MODERATE: Validate thresholds
        if config.group.threshold_m < 2 {
            report.add_warning(
                ErrorCategory::Configuration,
                format!(
                    "Testnet threshold m={} is low (consider m >= 2)",
                    config.group.threshold_m
                )
            );
        }

        Ok(())
    }

    fn validate_devnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // RELAXED: Only validate basic sanity
        if config.group.threshold_m > config.group.threshold_n {
            report.add_error(
                ErrorCategory::Configuration,
                format!(
                    "Invalid threshold even for devnet: m={} > n={}",
                    config.group.threshold_m,
                    config.group.threshold_n
                )
            );
        }

        Ok(())
    }
}
```

---

### File 5: Logging Validation Rules

**File**: `igra-core/src/infrastructure/network_mode/rules/logging.rs`

```rust
//! Logging security validation

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::ServiceConfig;
use crate::infrastructure::network_mode::{NetworkMode, report::*};

pub struct LoggingValidator;

impl LoggingValidator {
    pub fn validate(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet => Self::validate_mainnet(config, report),
            NetworkMode::Testnet => Self::validate_testnet(config, report),
            NetworkMode::Devnet => Ok(()),
        }
    }

    fn validate_mainnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        // STRICT: No debug/trace logging (risk of secret exposure)
        if rust_log.to_lowercase().contains("debug")
            || rust_log.to_lowercase().contains("trace") {
            report.add_error(
                ErrorCategory::Logging,
                format!(
                    "Mainnet forbids DEBUG/TRACE logging (RUST_LOG={}). \
                    These log levels may expose secrets. \
                    Set RUST_LOG=info or RUST_LOG=warn",
                    rust_log
                )
            );
        }

        // STRICT: Must have log rotation
        if config.log_max_size.is_none() || config.log_max_files.is_none() {
            report.add_error(
                ErrorCategory::Logging,
                "Mainnet requires log rotation (set log_max_size and log_max_files in config)"
            );
        }

        Ok(())
    }

    fn validate_testnet(
        _config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        // MODERATE: Warn if using trace
        if rust_log.to_lowercase().contains("trace") {
            report.add_warning(
                ErrorCategory::Logging,
                "Testnet using TRACE logging (may expose sensitive data)"
            );
        }

        Ok(())
    }
}
```

---

### File 6: Filesystem Validation Rules

**File**: `igra-core/src/infrastructure/network_mode/rules/filesystem.rs`

```rust
//! File system permissions validation (Unix only)

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::ServiceConfig;
use crate::infrastructure::network_mode::{NetworkMode, report::*};
use std::path::Path;

pub struct FilesystemValidator;

impl FilesystemValidator {
    #[cfg(target_family = "unix")]
    pub fn validate(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet => Self::validate_mainnet(config, report),
            NetworkMode::Testnet => Self::validate_testnet(config, report),
            NetworkMode::Devnet => Ok(()),
        }
    }

    #[cfg(not(target_family = "unix"))]
    pub fn validate(
        _config: &ServiceConfig,
        _network_mode: NetworkMode,
        _report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        // No file permission validation on non-Unix systems
        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn validate_mainnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        use std::os::unix::fs::PermissionsExt;

        // Check data directory
        if config.data_dir.exists() {
            let data_meta = std::fs::metadata(&config.data_dir)
                .map_err(|e| ThresholdError::secret_store_unavailable(
                    "file",
                    format!("Cannot read data directory metadata: {}", e)
                ))?;

            let data_mode = data_meta.permissions().mode() & 0o777;
            if data_mode != 0o700 {
                report.add_error(
                    ErrorCategory::FilePermissions,
                    format!(
                        "Data directory {:?} has insecure permissions: {:o} (expected 0700).\n\
                        Fix with: chmod 700 {:?}",
                        config.data_dir, data_mode, config.data_dir
                    )
                );
            }
        } else {
            report.add_warning(
                ErrorCategory::FilePermissions,
                format!("Data directory {:?} does not exist (will be created)", config.data_dir)
            );
        }

        // Check secrets file permissions
        if let Some(secrets_path) = &config.secrets_file {
            let path = Path::new(secrets_path);
            if path.exists() {
                let secrets_meta = std::fs::metadata(path)
                    .map_err(|e| ThresholdError::secret_store_unavailable(
                        "file",
                        format!("Cannot read secrets file metadata: {}", e)
                    ))?;

                let secrets_mode = secrets_meta.permissions().mode() & 0o777;
                if secrets_mode != 0o600 {
                    report.add_error(
                        ErrorCategory::FilePermissions,
                        format!(
                            "Secrets file {:?} has insecure permissions: {:o} (expected 0600).\n\
                            Fix with: chmod 600 {:?}",
                            path, secrets_mode, path
                        )
                    );
                }
            }
        }

        // Check config file permissions (if path known)
        if let Some(config_path) = &config.config_file_path {
            let config_meta = std::fs::metadata(config_path)
                .map_err(|e| ThresholdError::secret_store_unavailable(
                    "file",
                    format!("Cannot read config file metadata: {}", e)
                ))?;

            let config_mode = config_meta.permissions().mode() & 0o777;
            if config_mode != 0o600 {
                report.add_error(
                    ErrorCategory::FilePermissions,
                    format!(
                        "Config file {:?} has insecure permissions: {:o} (expected 0600).\n\
                        Fix with: chmod 600 {:?}",
                        config_path, config_mode, config_path
                    )
                );
            }
        }

        // Check not running as root
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            report.add_error(
                ErrorCategory::FilePermissions,
                "Mainnet service must not run as root user.\n\
                Create dedicated user:\n\
                sudo useradd -r -s /bin/false igra-service\n\
                sudo chown -R igra-service:igra-service /var/lib/igra"
            );
        }

        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn validate_testnet(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        use std::os::unix::fs::PermissionsExt;

        // MODERATE: Warn about permissions
        if config.data_dir.exists() {
            if let Ok(meta) = std::fs::metadata(&config.data_dir) {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    report.add_warning(
                        ErrorCategory::FilePermissions,
                        format!(
                            "Data directory {:?} has permissive permissions: {:o} (recommend 0700)",
                            config.data_dir, mode
                        )
                    );
                }
            }
        }

        Ok(())
    }
}
```

---

### File 7: Network Address Validation Rules

**File**: `igra-core/src/infrastructure/network_mode/rules/network.rs`

```rust
//! Network address validation (Kaspa addresses, derivation paths)

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::{KeyType, ServiceConfig};
use crate::infrastructure::network_mode::{NetworkMode, report::*};

pub struct NetworkValidator;

impl NetworkValidator {
    pub fn validate(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        match network_mode {
            NetworkMode::Mainnet | NetworkMode::Testnet => {
                Self::validate_addresses(config, network_mode, report)?;
                Self::validate_derivation_paths(config, network_mode, report)?;
            }
            NetworkMode::Devnet => {
                // RELAXED: Allow cross-network addresses
                log::debug!("Devnet mode: allowing any address format");
            }
        }

        Ok(())
    }

    fn validate_addresses(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        let expected_prefix = network_mode.address_prefix();

        // Validate source addresses
        for addr in &config.source_addresses {
            if !addr.starts_with(expected_prefix) {
                report.add_error(
                    ErrorCategory::Network,
                    format!(
                        "Address '{}' does not match {} network (expected prefix: {})",
                        addr,
                        network_mode,
                        expected_prefix
                    )
                );
            }
        }

        // Validate multisig address
        if !config.multisig_address.starts_with(expected_prefix) {
            report.add_error(
                ErrorCategory::Network,
                format!(
                    "Multisig address '{}' does not match {} network",
                    config.multisig_address,
                    network_mode
                )
            );
        }

        Ok(())
    }

    fn validate_derivation_paths(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        let expected_coin_type = network_mode.coin_type();

        for (profile_name, profile) in &config.profiles {
            if profile.key_type == KeyType::HdMnemonic {
                if !profile.derivation_path.contains(expected_coin_type) {
                    report.add_error(
                        ErrorCategory::Configuration,
                        format!(
                            "Profile '{}' uses incorrect coin type in derivation path.\n\
                            Path: {}\n\
                            Expected coin type: {} (for {})\n\
                            Example: m/45'/{}'/{}'/{}/{}",
                            profile_name,
                            profile.derivation_path,
                            expected_coin_type,
                            network_mode,
                            expected_coin_type, 0, 0, 0
                        )
                    );
                }
            }
        }

        Ok(())
    }
}
```

---

### File 8: Startup Readiness Validation

**File**: `igra-core/src/infrastructure/network_mode/rules/startup.rs`

```rust
//! Startup readiness checks (mainnet only)

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::ServiceConfig;
use crate::infrastructure::network_mode::{NetworkMode, report::*};

pub struct StartupValidator;

impl StartupValidator {
    pub async fn validate(
        config: &ServiceConfig,
        network_mode: NetworkMode,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        if network_mode != NetworkMode::Mainnet {
            return Ok(());
        }

        log::info!("Running mainnet startup readiness checks...");

        Self::check_disk_space(config, report)?;
        
        #[cfg(target_family = "unix")]
        {
            Self::check_file_limits(report)?;
            Self::check_core_dumps(report)?;
        }

        Ok(())
    }

    fn check_disk_space(
        config: &ServiceConfig,
        report: &mut ValidationReport,
    ) -> Result<(), ThresholdError> {
        if let Ok(available) = Self::get_available_disk_space(&config.data_dir) {
            let min_space = 10 * 1024 * 1024 * 1024; // 10 GB
            if available < min_space {
                report.add_error(
                    ErrorCategory::Startup,
                    format!(
                        "Insufficient disk space: {} GB available, need at least 10 GB",
                        available / (1024 * 1024 * 1024)
                    )
                );
            }
        }

        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn check_file_limits(report: &mut ValidationReport) -> Result<(), ThresholdError> {
        let (soft, _hard) = Self::get_file_limits()?;
        if soft < 4096 {
            report.add_error(
                ErrorCategory::Startup,
                format!(
                    "Open file limit too low: {} (need at least 4096).\n\
                    Fix with: ulimit -n 4096\n\
                    Or add to /etc/security/limits.conf",
                    soft
                )
            );
        }

        Ok(())
    }

    #[cfg(target_family = "unix")]
    fn check_core_dumps(report: &mut ValidationReport) -> Result<(), ThresholdError> {
        let core_limit = Self::get_core_dump_limit()?;
        if core_limit != 0 {
            report.add_error(
                ErrorCategory::Startup,
                "Core dumps are enabled (may contain secrets).\n\
                Disable with: ulimit -c 0"
            );
        }

        Ok(())
    }

    // Helper functions

    fn get_available_disk_space(path: &std::path::Path) -> Result<u64, std::io::Error> {
        #[cfg(target_family = "unix")]
        {
            // Simplified - proper implementation needs statvfs
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(path)?;
            Ok(metadata.size())
        }

        #[cfg(not(target_family = "unix"))]
        {
            Ok(u64::MAX) // Skip check
        }
    }

    #[cfg(target_family = "unix")]
    fn get_file_limits() -> Result<(u64, u64), ThresholdError> {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };

        if result != 0 {
            return Err(ThresholdError::secret_store_unavailable(
                "system",
                "Failed to get file limits"
            ));
        }

        Ok((rlim.rlim_cur, rlim.rlim_max))
    }

    #[cfg(target_family = "unix")]
    fn get_core_dump_limit() -> Result<u64, ThresholdError> {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        let result = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };

        if result != 0 {
            return Err(ThresholdError::secret_store_unavailable(
                "system",
                "Failed to get core dump limit"
            ));
        }

        Ok(rlim.rlim_cur)
    }
}
```

---

### File 9: Rules Module Exports

**File**: `igra-core/src/infrastructure/network_mode/rules/mod.rs`

```rust
//! Validation rule modules

pub mod config;
pub mod filesystem;
pub mod logging;
pub mod network;
pub mod rpc;
pub mod secrets;
pub mod startup;

// Re-export validators
pub use config::ConfigValidator;
pub use filesystem::FilesystemValidator;
pub use logging::LoggingValidator;
pub use network::NetworkValidator;
pub use rpc::RpcValidator;
pub use secrets::SecretsValidator;
pub use startup::StartupValidator;
```

---

### File 10: Security Validator Orchestrator (Updated)

**File**: `igra-core/src/infrastructure/network_mode/validator.rs`

```rust
//! Security validator orchestrator

use crate::foundation::error::ThresholdError;
use crate::infrastructure::config::types::ServiceConfig;
use crate::infrastructure::network_mode::{
    NetworkMode,
    report::ValidationReport,
    rules::*,
};

/// Security validator orchestrates all validation rules
pub struct SecurityValidator {
    network_mode: NetworkMode,
}

impl SecurityValidator {
    pub fn new(network_mode: NetworkMode) -> Self {
        Self { network_mode }
    }

    /// Run comprehensive validation
    pub async fn validate(&self, config: &ServiceConfig) -> Result<ValidationReport, ThresholdError> {
        let mut report = ValidationReport::new(self.network_mode);

        log::info!("🔍 Running security validation for {} mode", self.network_mode);

        // Delegate to individual validators
        SecretsValidator::validate(config, self.network_mode, &mut report)?;
        RpcValidator::validate_outbound(config, self.network_mode, &mut report)?;
        RpcValidator::validate_inbound(config, self.network_mode, &mut report)?;
        ConfigValidator::validate(config, self.network_mode, &mut report)?;
        LoggingValidator::validate(config, self.network_mode, &mut report)?;
        FilesystemValidator::validate(config, self.network_mode, &mut report)?;
        NetworkValidator::validate(config, self.network_mode, &mut report)?;
        StartupValidator::validate(config, self.network_mode, &mut report).await?;

        // Log summary
        if report.has_errors() {
            log::error!("❌ Validation found {} error(s)", report.error_count());
        } else if report.has_warnings() {
            log::warn!("⚠️  Validation found {} warning(s)", report.warning_count());
        } else {
            log::info!("✅ All security validations passed");
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mainnet_validation_with_valid_config() {
        let config = create_valid_mainnet_config();
        let validator = SecurityValidator::new(NetworkMode::Mainnet);
        
        let report = validator.validate(&config).await.unwrap();
        
        assert!(!report.has_errors());
    }

    #[tokio::test]
    async fn test_devnet_validation_permissive() {
        let mut config = ServiceConfig::default();
        config.use_encrypted_secrets = false;  // Would fail in mainnet
        
        let validator = SecurityValidator::new(NetworkMode::Devnet);
        
        let report = validator.validate(&config).await.unwrap();
        
        assert!(!report.has_errors());
    }

    fn create_valid_mainnet_config() -> ServiceConfig {
        let mut config = ServiceConfig::default();
        config.network = Some("mainnet".to_string());
        config.use_encrypted_secrets = true;
        config.secrets_file = Some("/tmp/test-secrets.bin".to_string());
        config.key_audit_log_path = Some("/tmp/test-audit.log".to_string());
        config.node_url = "grpc://127.0.0.1:16110".to_string();
        config
    }
}
```

---

### File 11: Network Mode Module Root

**File**: `igra-core/src/infrastructure/network_mode/mod.rs` (UPDATED)

```rust
//! Network mode security validation

pub mod report;
pub mod rules;
pub mod validator;

use serde::{Deserialize, Serialize};
use std::fmt;

// Re-export main types
pub use report::{ErrorCategory, ValidationError, ValidationReport, ValidationWarning};
pub use validator::SecurityValidator;

/// Network mode determines security posture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Production network with real funds
    Mainnet,

    /// Test network for pre-production validation
    Testnet,

    /// Development network for local testing
    Devnet,
}

impl NetworkMode {
    /// Parse from CLI flag or config string
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "devnet" => Ok(Self::Devnet),
            _ => Err(format!(
                "Invalid network mode: '{}'. Must be: mainnet, testnet, or devnet",
                s
            )),
        }
    }

    /// Check if this is a production network
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Mainnet)
    }

    /// Get expected Kaspa address prefix
    pub fn address_prefix(&self) -> &'static str {
        match self {
            Self::Mainnet => "kaspa:",
            Self::Testnet => "kaspatest:",
            Self::Devnet => "kaspadev:",
        }
    }

    /// Get BIP44 coin type
    pub fn coin_type(&self) -> &'static str {
        match self {
            Self::Mainnet => "111110",
            Self::Testnet => "111111",
            Self::Devnet => "111111",
        }
    }

    /// Get expected Kaspa network ID
    pub fn kaspa_network_id(&self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Devnet => "devnet",
        }
    }
}

impl Default for NetworkMode {
    fn default() -> Self {
        Self::Mainnet
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Devnet => write!(f, "devnet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_mode_from_str() {
        assert_eq!(NetworkMode::from_str("mainnet").unwrap(), NetworkMode::Mainnet);
        assert_eq!(NetworkMode::from_str("MAINNET").unwrap(), NetworkMode::Mainnet);
        assert_eq!(NetworkMode::from_str("testnet").unwrap(), NetworkMode::Testnet);
        assert_eq!(NetworkMode::from_str("devnet").unwrap(), NetworkMode::Devnet);
        assert!(NetworkMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_default_is_mainnet() {
        assert_eq!(NetworkMode::default(), NetworkMode::Mainnet);
    }

    #[test]
    fn test_address_prefix() {
        assert_eq!(NetworkMode::Mainnet.address_prefix(), "kaspa:");
        assert_eq!(NetworkMode::Testnet.address_prefix(), "kaspatest:");
        assert_eq!(NetworkMode::Devnet.address_prefix(), "kaspadev:");
    }

    #[test]
    fn test_coin_type() {
        assert_eq!(NetworkMode::Mainnet.coin_type(), "111110");
        assert_eq!(NetworkMode::Testnet.coin_type(), "111111");
        assert_eq!(NetworkMode::Devnet.coin_type(), "111111");
    }
}
```

---


---

## Detailed Implementation Steps

### Step 1: Create Directory Structure

```bash
cd igra-core/src/infrastructure
mkdir -p network_mode/rules
touch network_mode/mod.rs
touch network_mode/report.rs
touch network_mode/validator.rs
touch network_mode/rules/mod.rs
touch network_mode/rules/secrets.rs
touch network_mode/rules/rpc.rs
touch network_mode/rules/config.rs
touch network_mode/rules/logging.rs
touch network_mode/rules/filesystem.rs
touch network_mode/rules/network.rs
touch network_mode/rules/startup.rs
```

---

### Step 2: Update Infrastructure Module

**File**: `igra-core/src/infrastructure/mod.rs`

Add to existing modules:

```rust
pub mod network_mode;
```

---

### Step 3: Implement Core Types (Day 1)

Implement in this order:

1. ✅ **mod.rs** - NetworkMode enum (from File 11 above)
2. ✅ **report.rs** - ValidationReport (from File 2 above)
3. ✅ Test that it compiles: `cargo build --package igra-core`

---

### Step 4: Implement Validation Rules (Day 2-3)

Implement each rule module:

4. ✅ **rules/secrets.rs** - Secret management validation (from File 3 above)
5. ✅ **rules/config.rs** - Configuration validation (from File 4 above)
6. ✅ **rules/logging.rs** - Logging validation (from File 5 above)
7. ✅ **rules/filesystem.rs** - File permissions validation (from File 6 above)
8. ✅ **rules/network.rs** - Address/path validation (from File 7 above)
9. ✅ **rules/startup.rs** - Startup checks (from File 8 above)
10. ✅ **rules/rpc.rs** - RPC validation (from earlier "Complete Implementation" section)
11. ✅ **rules/mod.rs** - Module exports (from File 9 above)

Test each module independently:
```bash
cargo test --package igra-core --lib infrastructure::network_mode::rules::secrets
cargo test --package igra-core --lib infrastructure::network_mode::rules::config
# ... etc
```

---

### Step 5: Implement Orchestrator (Day 4)

12. ✅ **validator.rs** - SecurityValidator orchestrator (from File 10 above)
13. ✅ Test full validation: `cargo test --package igra-core --lib infrastructure::network_mode`

---

### Step 6: Update Configuration Schema (Day 4)

**File**: `igra-core/src/infrastructure/config/types.rs`

Add to `ServiceConfig`:

```rust
// After existing fields, add:

// === Network Mode Security ===

/// Network mode: mainnet, testnet, devnet
#[serde(default)]
pub network: Option<String>,

/// Allow remote RPC client (connecting to kaspad)
#[serde(default)]
pub allow_remote_rpc: bool,

/// Allow remote RPC server (listening on network)
#[serde(default)]
pub allow_remote_rpc_server: bool,

/// Log rotation max file size
#[serde(skip_serializing_if = "Option::is_none")]
pub log_max_size: Option<String>,

/// Log rotation max file count
#[serde(skip_serializing_if = "Option::is_none")]
pub log_max_files: Option<usize>,

/// Path to config file (for permission validation)
#[serde(skip)]
pub config_file_path: Option<std::path::PathBuf>,
```

Add to `ProfileConfig`:

```rust
// After existing fields, add:

// === RPC Server Security ===

/// Enable TLS for RPC server
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_tls_enabled: Option<bool>,

/// TLS certificate path
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_tls_cert: Option<String>,

/// TLS private key path
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_tls_key: Option<String>,

/// Require authentication
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_require_auth: Option<bool>,

/// API tokens for Bearer auth
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_auth_tokens: Option<Vec<String>>,

/// Enable mutual TLS
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_mtls_enabled: Option<bool>,

/// CA certificate for mTLS
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_mtls_ca_cert: Option<String>,

/// IP allowlist (CIDR)
#[serde(skip_serializing_if = "Option::is_none")]
pub rpc_allowed_ips: Option<Vec<String>>,
```

---

### Step 7: Update CLI (Day 4-5)

**File**: `igra-service/src/bin/kaspa-threshold-service.rs`

Update Args struct:

```rust
use clap::Parser;
use igra_core::infrastructure::network_mode::{NetworkMode, SecurityValidator};

#[derive(Parser)]
#[command(name = "kaspa-threshold-service")]
struct Args {
    /// Network mode: mainnet, testnet, devnet
    #[arg(long, default_value = "mainnet")]
    #[arg(value_parser = ["mainnet", "testnet", "devnet"])]
    network: String,

    /// Allow remote RPC client (connect to remote kaspad)
    #[arg(long)]
    allow_remote_rpc: bool,

    /// Allow remote RPC server (listen on network)
    #[arg(long)]
    allow_remote_rpc_server: bool,

    /// Validate configuration and exit (no service start)
    #[arg(long)]
    validate_only: bool,

    /// Config file path
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,

    /// Data directory
    #[arg(long, short = 'd')]
    data_dir: Option<PathBuf>,

    /// Log level
    #[arg(long)]
    log_level: Option<String>,
}
```

Update main() function:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Parse network mode
    let network_mode = NetworkMode::from_str(&args.network)
        .map_err(|e| format!("Invalid network mode: {}", e))?;

    log::info!("🚀 Starting Igra Threshold Service ({})", network_mode);

    // Load configuration
    let config_path = args.config
        .or_else(|| std::env::var("KASPA_CONFIG_PATH").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("igra-config.toml"));

    let mut config = load_config(&config_path)?;

    // Store config path for validation
    config.config_file_path = Some(config_path.clone());

    // Apply CLI overrides
    if let Some(data_dir) = args.data_dir {
        config.data_dir = data_dir;
    }
    config.allow_remote_rpc = args.allow_remote_rpc;
    config.allow_remote_rpc_server = args.allow_remote_rpc_server;

    // Run security validation
    let validator = SecurityValidator::new(network_mode);
    let report = validator.validate(&config).await?;

    // Print validation report
    if report.has_warnings() || report.has_errors() {
        println!("{}", report);
    }

    // In mainnet, fail on errors
    if network_mode.is_production() && report.has_errors() {
        log::error!("❌ Mainnet validation failed - exiting");
        std::process::exit(1);
    }

    // If validate-only mode, exit here
    if args.validate_only {
        if report.has_errors() {
            std::process::exit(1);
        } else {
            println!("✅ Validation passed");
            std::process::exit(0);
        }
    }

    // Continue with service startup
    setup_and_run(config, network_mode).await?;

    Ok(())
}
```

---

### Step 8: Add Foundation Error Variants (Day 5)

**File**: `igra-core/src/foundation/error.rs`

Add to `ThresholdError` enum:

```rust
#[error("Configuration validation failed: {errors:?}")]
ConfigValidationFailed {
    errors: Vec<String>,
},

#[error("Network mode error: {details}")]
NetworkModeError {
    details: String,
},
```

---

## Implementation Checklist

### Files to Create (11 files)

- [ ] `network_mode/mod.rs` (NetworkMode enum + re-exports)
- [ ] `network_mode/report.rs` (ValidationReport, ErrorCategory)
- [ ] `network_mode/validator.rs` (SecurityValidator orchestrator)
- [ ] `network_mode/rules/mod.rs` (Module exports)
- [ ] `network_mode/rules/secrets.rs` (SecretsValidator)
- [ ] `network_mode/rules/rpc.rs` (RpcValidator - inbound + outbound)
- [ ] `network_mode/rules/config.rs` (ConfigValidator)
- [ ] `network_mode/rules/logging.rs` (LoggingValidator)
- [ ] `network_mode/rules/filesystem.rs` (FilesystemValidator)
- [ ] `network_mode/rules/network.rs` (NetworkValidator - addresses/paths)
- [ ] `network_mode/rules/startup.rs` (StartupValidator - readiness)

### Files to Update (4 files)

- [ ] `infrastructure/mod.rs` - Add `pub mod network_mode;`
- [ ] `foundation/error.rs` - Add ConfigValidationFailed variant
- [ ] `config/types.rs` - Add network mode fields to ServiceConfig and ProfileConfig
- [ ] `bin/kaspa-threshold-service.rs` - Add CLI flags and validation call

### Tests to Write (8 test files)

- [ ] `network_mode/mod.rs` - NetworkMode tests (in same file)
- [ ] `network_mode/report.rs` - ValidationReport tests (in same file)
- [ ] `tests/unit/network_mode_secrets.rs` - SecretsValidator tests
- [ ] `tests/unit/network_mode_rpc.rs` - RpcValidator tests
- [ ] `tests/unit/network_mode_config.rs` - ConfigValidator tests
- [ ] `tests/unit/network_mode_logging.rs` - LoggingValidator tests
- [ ] `tests/unit/network_mode_filesystem.rs` - FilesystemValidator tests (Unix only)
- [ ] `tests/integration/network_mode_e2e.rs` - End-to-end validation tests

---

## Testing Each Module

### Test Module Independently

```bash
# Test NetworkMode enum
cargo test --package igra-core --lib infrastructure::network_mode -- test_network_mode

# Test ValidationReport
cargo test --package igra-core --lib infrastructure::network_mode::report

# Test individual validators
cargo test --package igra-core --lib infrastructure::network_mode::rules::secrets
cargo test --package igra-core --lib infrastructure::network_mode::rules::rpc
cargo test --package igra-core --lib infrastructure::network_mode::rules::config

# Test orchestrator
cargo test --package igra-core --lib infrastructure::network_mode::validator

# Test all network_mode
cargo test --package igra-core --lib infrastructure::network_mode
```

### Integration Test

```bash
# Test service startup with different modes
cargo run --bin kaspa-threshold-service -- --network mainnet --validate-only
cargo run --bin kaspa-threshold-service -- --network testnet --validate-only
cargo run --bin kaspa-threshold-service -- --network devnet --validate-only
```

---

## Module Dependencies

Each rule module is **independent** and can be implemented in parallel:

```
mod.rs (NetworkMode)
    ↓
report.rs (ValidationReport)
    ↓
rules/ ← All can be done in parallel:
  ├─ secrets.rs     (no dependencies)
  ├─ config.rs      (no dependencies)
  ├─ logging.rs     (no dependencies)
  ├─ filesystem.rs  (no dependencies)
  ├─ network.rs     (no dependencies)
  ├─ startup.rs     (no dependencies)
  └─ rpc.rs         (uses helper functions)
    ↓
validator.rs (orchestrates all rules)
```

**Parallel implementation possible**: Assign different rule modules to different team members!

---

## Validation Workflow

```rust
// When service starts:

1. Parse CLI args
   ├─> Extract --network flag (default: mainnet)
   ├─> Extract --allow-remote-rpc
   └─> Extract --allow-remote-rpc-server

2. Load config from file
   └─> Apply CLI overrides

3. Create SecurityValidator
   └─> new(network_mode)

4. Run validator.validate(config)
   ├─> SecretsValidator::validate()
   ├─> RpcValidator::validate_outbound()
   ├─> RpcValidator::validate_inbound()
   ├─> ConfigValidator::validate()
   ├─> LoggingValidator::validate()
   ├─> FilesystemValidator::validate()
   ├─> NetworkValidator::validate()
   └─> StartupValidator::validate()
        └─> Returns ValidationReport

5. Check report
   ├─> If errors + mainnet → EXIT(1)
   ├─> If errors + testnet → WARN + CONTINUE
   └─> If errors + devnet → CONTINUE

6. If --validate-only → EXIT(0)

7. Continue service startup
```

---

## Complete Implementation Timeline

### Day 1: Foundation
- **Morning**: Create directory structure
- **Afternoon**: Implement NetworkMode enum (mod.rs)
- **Evening**: Implement ValidationReport (report.rs)
- **Tests**: Write and run NetworkMode tests

### Day 2: Validation Rules (Part 1)
- **Morning**: Implement SecretsValidator (rules/secrets.rs)
- **Afternoon**: Implement ConfigValidator (rules/config.rs)
- **Evening**: Implement LoggingValidator (rules/logging.rs)
- **Tests**: Write tests for each module

### Day 3: Validation Rules (Part 2)
- **Morning**: Implement FilesystemValidator (rules/filesystem.rs)
- **Afternoon**: Implement NetworkValidator (rules/network.rs)
- **Evening**: Implement StartupValidator (rules/startup.rs)
- **Tests**: Write tests for each module

### Day 4: RPC and Orchestration
- **Morning**: Implement RpcValidator (rules/rpc.rs) - most complex
- **Afternoon**: Implement rules/mod.rs exports
- **Evening**: Implement SecurityValidator orchestrator (validator.rs)
- **Tests**: Integration tests

### Day 5: CLI and Integration
- **Morning**: Update kaspa-threshold-service CLI
- **Afternoon**: Wire validation into startup
- **Evening**: End-to-end testing
- **Documentation**: Update deployment guides

---

## Verification Checklist

After implementation, verify:

### Compilation
- [ ] `cargo build --package igra-core` compiles
- [ ] `cargo build --package igra-service` compiles
- [ ] No warnings in network_mode module

### Unit Tests
- [ ] NetworkMode enum tests pass
- [ ] ValidationReport tests pass
- [ ] SecretsValidator tests pass
- [ ] ConfigValidator tests pass
- [ ] LoggingValidator tests pass
- [ ] FilesystemValidator tests pass (Unix)
- [ ] NetworkValidator tests pass
- [ ] StartupValidator tests pass
- [ ] RpcValidator tests pass

### Integration Tests
- [ ] Mainnet validation rejects invalid configs
- [ ] Testnet validation warns on issues
- [ ] Devnet validation is permissive
- [ ] --validate-only flag works
- [ ] CLI flags override config correctly

### Functional Tests
- [ ] Mainnet with valid config starts
- [ ] Mainnet with invalid config exits with error
- [ ] Testnet with warnings continues
- [ ] Devnet scripts work unchanged
- [ ] Remote RPC requires explicit flags

### Documentation
- [ ] Code comments in all files
- [ ] Error messages are clear
- [ ] Examples in docs/
- [ ] Team training complete

---

## Quick Start for Your Team

```bash
# 1. Create structure
cd igra-core/src/infrastructure
mkdir -p network_mode/rules

# 2. Implement in order (copy from this doc):
# - File 11: mod.rs (NetworkMode)
# - File 2: report.rs (ValidationReport)
# - File 3: rules/secrets.rs
# - File 4: rules/config.rs
# - File 5: rules/logging.rs
# - File 6: rules/filesystem.rs
# - File 7: rules/network.rs
# - File 8: rules/startup.rs
# - File 9: rules/mod.rs
# - (RPC validator from section 3261)
# - File 10: validator.rs

# 3. Test as you go
cargo test --package igra-core --lib infrastructure::network_mode

# 4. Update CLI (kaspa-threshold-service.rs)

# 5. Test full flow
cargo run --bin kaspa-threshold-service -- --network mainnet --validate-only
```

---

## File Count Summary

**Total new files**: 11 Rust files

**Code volume**:
- mod.rs: ~100 lines
- report.rs: ~200 lines
- validator.rs: ~80 lines
- rules/secrets.rs: ~120 lines
- rules/config.rs: ~100 lines
- rules/logging.rs: ~80 lines
- rules/filesystem.rs: ~150 lines
- rules/network.rs: ~100 lines
- rules/startup.rs: ~130 lines
- rules/rpc.rs: ~400 lines
- rules/mod.rs: ~10 lines

**Total**: ~1,470 lines of production code + tests

---

END OF COMPLETE GUIDE
