# Iroh Discovery Integration Guide

**Version:** 1.0
**Date:** 2026-01-24
**Status:** Implementation Ready

---

## Executive Summary

This document provides a step-by-step implementation guide for adding **pkarr DHT discovery** and **relay support** to the Igra threshold signing system. The implementation enables:

1. **Automatic peer discovery** via Mainline DHT (no manual IP configuration)
2. **NAT traversal** via DERP relay servers
3. **Production-ready failover** with multiple discovery mechanisms

**Complexity:** Medium
**Estimated Effort:** 2-3 days
**Risk:** Low (additive changes, no breaking changes)

---

## Table of Contents

1. [Background & Concepts](#1-background--concepts)
2. [Architecture Changes](#2-architecture-changes)
3. [Implementation Steps](#3-implementation-steps)
4. [Configuration](#4-configuration)
5. [Testing](#5-testing)
6. [Production Deployment](#6-production-deployment)
7. [Monitoring & Operations](#7-monitoring--operations)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Background & Concepts

### 1.1 The Problem

**Current State (Static Discovery):**
```toml
# Manual configuration required
bootstrap_addrs = [
    "peer1@203.0.113.50:11205",
    "peer2@198.51.100.20:11205"
]
```

**Problems:**
- IP changes break connectivity (cloud restarts, DHCP changes)
- Manual config for 10+ nodes is error-prone
- No automatic peer discovery
- Nodes behind NAT cannot connect

### 1.2 The Solution: Three-Component System

```
┌─────────────────────────────────────────────────────────┐
│                  Discovery Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │   Static     │  │    Pkarr     │  │   Relay     │  │
│  │  Bootstrap   │  │  (DHT-based) │  │ (Fallback)  │  │
│  └──────────────┘  └──────────────┘  └─────────────┘  │
└─────────────────────────────────────────────────────────┘
          │                  │                  │
          └──────────────────┴──────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Iroh Endpoint  │
                    └─────────────────┘
```

**Component Roles:**

| Component | Purpose | When Used |
|-----------|---------|-----------|
| **Static Bootstrap** | Cold start, seed nodes | Node startup (first 60s) |
| **Pkarr DHT** | Dynamic peer discovery | After DHT bootstrap (ongoing) |
| **Relay** | NAT traversal | Direct connection fails |

### 1.3 How Pkarr Works

**Pkarr = Public Key Addressable Resource Records**

```
1. Node publishes to DHT:
   Key:   blake3(EndpointId)
   Value: SignedRecord {
       addresses: ["203.0.113.50:11205"],
       timestamp: 1234567890,
       signature: <Ed25519 signature>
   }

2. Other nodes query DHT:
   Input:  EndpointId
   Output: ["203.0.113.50:11205"]

3. Connect using discovered address
```

**DHT Properties:**
- **Decentralized:** 20M+ BitTorrent DHT nodes
- **Self-healing:** Survives node failures
- **TTL:** Records expire after ~1 hour (auto-republish)
- **Latency:** 2-10 seconds for first query, cached thereafter

### 1.4 Relay (DERP) Mechanism

**Problem:** Nodes behind NAT have private IPs

```
Node A (NAT)               Relay Server              Node B (NAT)
192.168.1.10               relay.example.com          10.0.0.5
     │                            │                        │
     ├─ Outbound to relay ───────►│                        │
     │                            ├─ Forward to Node B ───►│
     │                            │                        │
     │◄── Relay response ─────────┤◄── Outbound to relay ─┤
```

**Key Points:**
- Relay has public IP, always reachable
- Both nodes connect **outbound** (NAT allows this)
- End-to-end encrypted (relay cannot decrypt)
- Automatic fallback (tries direct first)

---

## 2. Architecture Changes

### 2.1 Module Structure

```
igra-core/src/infrastructure/transport/iroh/
├── mod.rs                      # Re-exports (no changes)
├── config.rs                   # Add discovery config types [MODIFY]
├── client.rs                   # IrohTransport implementation [MODIFY]
├── discovery.rs                # Discovery provider logic [NEW]
└── identity.rs                 # Identity helpers (no changes)

igra-core/src/foundation/
├── constants.rs                # Add discovery constants [MODIFY]
└── error.rs                    # Add discovery error variants [MODIFY]

igra-core/src/infrastructure/config/
├── types.rs                    # Add IrohDiscoveryConfig, IrohRelayConfig [MODIFY]
└── validation.rs               # Add config validation [MODIFY]

igra-service/src/bin/kaspa-threshold-service/
└── setup.rs                    # Modify init_iroh_gossip [MODIFY]
```

### 2.2 Configuration Schema

**New config types:**

```rust
// igra-core/src/infrastructure/config/types.rs

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrohDiscoveryConfig {
    /// Enable pkarr DHT discovery
    #[serde(default)]
    pub enable_pkarr: bool,

    /// Enable DNS discovery (optional)
    #[serde(default)]
    pub enable_dns: bool,

    /// DNS discovery domain (e.g., "discovery.igra.kaspa.org")
    #[serde(default)]
    pub dns_domain: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrohRelayConfig {
    /// Enable relay for NAT traversal
    #[serde(default)]
    pub enable: bool,

    /// Custom relay URL (if None, uses Iroh's default relay)
    #[serde(default)]
    pub custom_url: Option<String>,
}

// Add to existing IrohRuntimeConfig
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrohRuntimeConfig {
    // ... existing fields ...

    #[serde(default)]
    pub discovery: IrohDiscoveryConfig,

    #[serde(default)]
    pub relay: IrohRelayConfig,
}
```

### 2.3 Error Handling

**Add new error variants (following Mistake #1 guideline):**

```rust
// igra-core/src/foundation/error.rs

#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    // ... existing variants ...

    /// Pkarr DHT discovery initialization failed
    #[error("pkarr discovery init failed: {details}")]
    PkarrInitFailed { details: String },

    /// Relay configuration is invalid
    #[error("invalid relay config: {reason}")]
    InvalidRelayConfig { reason: String },

    /// Custom relay URL is malformed
    #[error("malformed relay url: {url}")]
    MalformedRelayUrl { url: String },

    /// DNS discovery domain is invalid
    #[error("invalid DNS domain: {domain}")]
    InvalidDnsDomain { domain: String },
}
```

### 2.4 Constants

**Add to foundation/constants.rs:**

```rust
// igra-core/src/foundation/constants.rs

// ===== Iroh Discovery Constants =====

/// Maximum time to wait for DHT bootstrap (milliseconds)
pub const DHT_BOOTSTRAP_TIMEOUT_MS: u64 = 10_000;

/// Pkarr record republish interval (seconds)
/// Records expire after ~3600s, republish at 50 minutes
pub const PKARR_REPUBLISH_INTERVAL_SECS: u64 = 3_000;

/// Maximum custom relay URL length
pub const MAX_RELAY_URL_LENGTH: usize = 256;

/// Default relay URL (Iroh's public relay)
pub const DEFAULT_RELAY_URL: &str = "https://relay.iroh.computer";

/// DNS discovery query timeout (milliseconds)
pub const DNS_DISCOVERY_TIMEOUT_MS: u64 = 5_000;
```

---

## 3. Implementation Steps

### Step 1: Add Discovery Configuration Types

**File:** `igra-core/src/infrastructure/config/types.rs`

**Action:** Add new config structs after `IrohRuntimeConfig`

```rust
impl Default for IrohDiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_pkarr: false,
            enable_dns: false,
            dns_domain: None,
        }
    }
}

impl Default for IrohRelayConfig {
    fn default() -> Self {
        Self {
            enable: false,
            custom_url: None,
        }
    }
}
```

**Validation (add to `igra-core/src/infrastructure/config/validation.rs`):**

```rust
/// Validate IrohDiscoveryConfig
pub fn validate_iroh_discovery(config: &IrohDiscoveryConfig) -> Result<(), String> {
    // DNS domain required if DNS discovery enabled
    if config.enable_dns && config.dns_domain.as_ref().map_or(true, |d| d.trim().is_empty()) {
        return Err("iroh.discovery.dns_domain required when enable_dns=true".to_string());
    }

    // Validate DNS domain format (basic check)
    if let Some(domain) = &config.dns_domain {
        if domain.contains(' ') || !domain.contains('.') {
            return Err(format!("invalid DNS domain format: {}", domain));
        }
    }

    Ok(())
}

/// Validate IrohRelayConfig
pub fn validate_iroh_relay(config: &IrohRelayConfig) -> Result<(), String> {
    if let Some(url) = &config.custom_url {
        if url.trim().is_empty() {
            return Err("iroh.relay.custom_url cannot be empty".to_string());
        }

        if url.len() > MAX_RELAY_URL_LENGTH {
            return Err(format!(
                "iroh.relay.custom_url too long: {} > {}",
                url.len(),
                MAX_RELAY_URL_LENGTH
            ));
        }

        // Basic URL validation
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!("iroh.relay.custom_url must start with http:// or https://: {}", url));
        }
    }

    Ok(())
}
```

**Add to existing `validate_app_config` function:**

```rust
// In validate_app_config function
validate_iroh_discovery(&config.iroh.discovery)
    .map_err(|e| format!("iroh.discovery validation: {}", e))?;

validate_iroh_relay(&config.iroh.relay)
    .map_err(|e| format!("iroh.relay validation: {}", e))?;
```

---

### Step 2: Create Discovery Module

**File:** `igra-core/src/infrastructure/transport/iroh/discovery.rs` (NEW)

```rust
//! Discovery provider construction for Iroh transport.
//!
//! Combines multiple discovery mechanisms (static, pkarr, DNS) into a single
//! unified discovery provider for the Iroh endpoint.

use crate::foundation::{ThresholdError, DNS_DISCOVERY_TIMEOUT_MS, PKARR_REPUBLISH_INTERVAL_SECS};
use crate::infrastructure::config::types::{IrohDiscoveryConfig, IrohRelayConfig};
use iroh::discovery::Discovery;
use iroh::discovery::static_provider::StaticProvider;
use iroh::endpoint::{EndpointAddr, RelayMode};
use log::{info, warn};
use std::sync::Arc;
use std::time::Duration;

/// Build combined discovery provider from static addresses and config.
///
/// Returns a boxed Discovery trait object that combines all enabled discovery
/// mechanisms. Discovery attempts run concurrently via ConcurrentDiscovery.
pub fn build_discovery_provider(
    static_addrs: Vec<EndpointAddr>,
    discovery_config: &IrohDiscoveryConfig,
) -> Result<Option<Box<dyn Discovery>>, ThresholdError> {
    let mut providers: Vec<Box<dyn Discovery>> = Vec::new();

    // 1. Static provider (always first if available)
    if !static_addrs.is_empty() {
        info!(
            "discovery: adding static provider with {} bootstrap addresses",
            static_addrs.len()
        );
        let static_provider = StaticProvider::new();
        for addr in &static_addrs {
            static_provider.add_endpoint_info(addr.clone());
        }
        providers.push(Box::new(static_provider));
    } else {
        warn!("discovery: no static bootstrap addresses configured");
    }

    // 2. Pkarr DHT provider
    if discovery_config.enable_pkarr {
        info!("discovery: enabling pkarr DHT provider");
        match build_pkarr_provider() {
            Ok(pkarr) => providers.push(Box::new(pkarr)),
            Err(e) => {
                warn!("discovery: pkarr init failed, skipping: {}", e);
            }
        }
    }

    // 3. DNS provider (if configured)
    if discovery_config.enable_dns {
        if let Some(ref domain) = discovery_config.dns_domain {
            info!("discovery: enabling DNS provider domain={}", domain);
            match build_dns_provider(domain) {
                Ok(dns) => providers.push(Box::new(dns)),
                Err(e) => {
                    warn!("discovery: DNS init failed, skipping: {}", e);
                }
            }
        }
    }

    if providers.is_empty() {
        warn!("discovery: no discovery providers configured");
        return Ok(None);
    }

    // Combine all providers
    let combined = iroh::discovery::ConcurrentDiscovery::from_services(providers);
    info!("discovery: initialized with {} provider(s)", combined.len());
    Ok(Some(Box::new(combined)))
}

/// Build pkarr DHT discovery provider.
fn build_pkarr_provider() -> Result<iroh::discovery::pkarr::PkarrPublisher, ThresholdError> {
    // Use default pkarr settings:
    // - Republish interval: ~50 minutes (records expire at 60 minutes)
    // - DHT bootstrap: Mainline DHT bootstrap nodes
    let pkarr = iroh::discovery::pkarr::PkarrPublisher::default();
    Ok(pkarr)
}

/// Build DNS discovery provider.
fn build_dns_provider(domain: &str) -> Result<iroh::discovery::dns::DnsDiscovery, ThresholdError> {
    let dns = iroh::discovery::dns::DnsDiscovery::new(domain.to_string());
    Ok(dns)
}

/// Parse relay mode from config.
pub fn parse_relay_mode(relay_config: &IrohRelayConfig) -> Result<RelayMode, ThresholdError> {
    if !relay_config.enable {
        return Ok(RelayMode::Disabled);
    }

    match &relay_config.custom_url {
        Some(url) if !url.trim().is_empty() => {
            info!("relay: using custom relay url={}", url);
            let parsed_url = url
                .parse()
                .map_err(|_e| ThresholdError::MalformedRelayUrl { url: url.clone() })?;
            Ok(RelayMode::Custom(parsed_url))
        }
        _ => {
            info!("relay: using default Iroh relay");
            Ok(RelayMode::Default)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::config::types::{IrohDiscoveryConfig, IrohRelayConfig};

    #[test]
    fn test_relay_mode_disabled() {
        let config = IrohRelayConfig {
            enable: false,
            custom_url: None,
        };
        let mode = parse_relay_mode(&config).expect("should parse");
        assert!(matches!(mode, RelayMode::Disabled));
    }

    #[test]
    fn test_relay_mode_default() {
        let config = IrohRelayConfig {
            enable: true,
            custom_url: None,
        };
        let mode = parse_relay_mode(&config).expect("should parse");
        assert!(matches!(mode, RelayMode::Default));
    }

    #[test]
    fn test_relay_mode_custom() {
        let config = IrohRelayConfig {
            enable: true,
            custom_url: Some("https://relay.example.com".to_string()),
        };
        let mode = parse_relay_mode(&config).expect("should parse");
        assert!(matches!(mode, RelayMode::Custom(_)));
    }

    #[test]
    fn test_relay_mode_invalid_url() {
        let config = IrohRelayConfig {
            enable: true,
            custom_url: Some("not a url".to_string()),
        };
        let result = parse_relay_mode(&config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ThresholdError::MalformedRelayUrl { .. }));
    }

    #[test]
    fn test_build_discovery_empty() {
        let config = IrohDiscoveryConfig::default();
        let result = build_discovery_provider(vec![], &config).expect("should succeed");
        // No providers configured
        assert!(result.is_none());
    }

    #[test]
    fn test_build_discovery_pkarr_only() {
        let config = IrohDiscoveryConfig {
            enable_pkarr: true,
            enable_dns: false,
            dns_domain: None,
        };
        let result = build_discovery_provider(vec![], &config).expect("should succeed");
        assert!(result.is_some());
    }
}
```

**Add to `igra-core/src/infrastructure/transport/iroh/mod.rs`:**

```rust
pub mod discovery;
```

---

### Step 3: Modify Endpoint Initialization

**File:** `igra-service/src/bin/kaspa-threshold-service/setup.rs`

**Modify `init_iroh_gossip` function signature:**

```rust
pub async fn init_iroh_gossip(
    bind_port: Option<u16>,
    static_addrs: Vec<EndpointAddr>,
    secret_key: IrohSecretKey,
    discovery_config: &IrohDiscoveryConfig,  // NEW
    relay_config: &IrohRelayConfig,          // NEW
) -> Result<(iroh_gossip::net::Gossip, iroh::protocol::Router), ThresholdError> {
    info!(
        "initializing iroh gossip bind_port={:?} static_addrs={} pkarr={} relay={}",
        bind_port,
        static_addrs.len(),
        discovery_config.enable_pkarr,
        relay_config.enable
    );

    // Parse relay mode
    let relay_mode = discovery::parse_relay_mode(relay_config)?;

    // Create endpoint builder
    let mut builder = iroh::Endpoint::empty_builder(relay_mode).secret_key(secret_key);

    // Build discovery provider
    if let Some(discovery) = discovery::build_discovery_provider(static_addrs, discovery_config)? {
        builder = builder.discovery(discovery);
    } else {
        warn!("no discovery providers configured - nodes will not auto-discover peers");
    }

    // Set bind port
    if let Some(port) = bind_port {
        builder = builder.bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    }

    // Bind endpoint
    let endpoint = builder
        .bind()
        .await
        .map_err(|err| ThresholdError::Message(format!("iroh endpoint bind failed: {}", err)))?;

    info!("iroh endpoint bound endpoint_id={}", endpoint.endpoint_id());

    // Create gossip protocol
    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());

    // Create protocol router
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(iroh_gossip::net::GOSSIP_ALPN, gossip.clone())
        .spawn();

    info!("iroh gossip initialized");
    Ok((gossip, router))
}
```

---

### Step 4: Update Service Initialization

**File:** `igra-service/src/bin/kaspa-threshold-service.rs`

**Modify the main initialization around line 140:**

```rust
// Parse static bootstrap addresses
let static_addrs = setup::parse_bootstrap_addrs(&app_config.iroh.bootstrap_addrs)?;
let iroh_secret = setup::derive_iroh_secret(identity.seed);

info!(
    "iroh identity ready peer_id={} group_id={:#x} bootstrap_addrs={} pkarr={} relay={}",
    identity.peer_id,
    group_id,
    static_addrs.len(),
    app_config.iroh.discovery.enable_pkarr,
    app_config.iroh.relay.enable
);

// Initialize Iroh gossip with discovery and relay config
let (gossip, _iroh_router) = setup::init_iroh_gossip(
    app_config.iroh.bind_port,
    static_addrs,
    iroh_secret,
    &app_config.iroh.discovery,  // NEW
    &app_config.iroh.relay,       // NEW
)
.await?;
```

---

### Step 5: Add Cargo Dependencies

**File:** `igra-core/Cargo.toml` and `igra-service/Cargo.toml`

**Verify dependencies (already present in iroh 0.95.x):**

```toml
[dependencies]
iroh = "0.95.1"
iroh-gossip = "0.95.0"

# Note: Pkarr and relay are included in iroh 0.95.x
# No additional dependencies needed
```

---

## 4. Configuration

### 4.1 Configuration File Examples

#### Devnet (Local, No Discovery)

```toml
[iroh]
network_id = 10
bind_port = 11205

# Static bootstrap only (manual IPs)
bootstrap_addrs = [
    "peer1@127.0.0.1:11205",
    "peer2@127.0.0.1:11206",
    "peer3@127.0.0.1:11207"
]

# No pkarr or relay needed for localhost
[iroh.discovery]
enable_pkarr = false
enable_dns = false

[iroh.relay]
enable = false
```

#### Testnet (Cloud, Pkarr + Relay)

```toml
[iroh]
network_id = 1
bind_port = 11205

# Minimal static bootstrap (1-2 seed nodes)
bootstrap_addrs = [
    "seed1@seed1.testnet.kaspa-igra.io:11205"
]

# Enable pkarr for automatic discovery
[iroh.discovery]
enable_pkarr = true
enable_dns = false

# Enable relay for NAT traversal
[iroh.relay]
enable = true
# custom_url = "https://relay.testnet.kaspa-igra.io"  # Optional
```

#### Mainnet (Production, All Features)

```toml
[iroh]
network_id = 1
bind_port = 11205

# Multiple seed nodes for redundancy
bootstrap_addrs = [
    "seed1@seed1.mainnet.kaspa-igra.io:11205",
    "seed2@seed2.mainnet.kaspa-igra.io:11205"
]

# Enable all discovery mechanisms
[iroh.discovery]
enable_pkarr = true
enable_dns = true
dns_domain = "discovery.mainnet.kaspa-igra.io"

# Enable relay with custom server
[iroh.relay]
enable = true
custom_url = "https://relay.mainnet.kaspa-igra.io"
```

### 4.2 Environment Variable Overrides

**Supported env vars:**

```bash
# Discovery
export KASPA_IGRA_IROH_DISCOVERY_ENABLE_PKARR=true
export KASPA_IGRA_IROH_DISCOVERY_ENABLE_DNS=true
export KASPA_IGRA_IROH_DISCOVERY_DNS_DOMAIN=discovery.example.com

# Relay
export KASPA_IGRA_IROH_RELAY_ENABLE=true
export KASPA_IGRA_IROH_RELAY_CUSTOM_URL=https://relay.example.com
```

### 4.3 Configuration Validation

**Run validation:**

```bash
# Dry-run config validation
cargo run --bin kaspa-threshold-service -- --config config.toml --validate-only

# Expected output:
# [INFO] config validation passed
# [INFO] iroh.discovery: pkarr=true dns=false
# [INFO] iroh.relay: enabled=true custom_url=<URL>
```

---

## 5. Testing

### 5.1 Unit Tests

**File:** `igra-core/src/infrastructure/transport/iroh/discovery.rs` (already included above)

**Run unit tests:**

```bash
cargo test --package igra-core discovery::tests
```

### 5.2 Integration Test

**File:** `igra-core/tests/integration/iroh_discovery_test.rs` (NEW)

```rust
//! Integration test for Iroh discovery mechanisms.

use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::config::types::{IrohDiscoveryConfig, IrohRelayConfig};
use igra_core::infrastructure::transport::iroh::discovery;
use iroh::endpoint::{EndpointAddr, RelayMode};

#[test]
fn test_discovery_config_validation() {
    // DNS enabled but no domain
    let config = IrohDiscoveryConfig {
        enable_pkarr: false,
        enable_dns: true,
        dns_domain: None,
    };
    let result = igra_core::infrastructure::config::validation::validate_iroh_discovery(&config);
    assert!(result.is_err());

    // Valid config
    let config = IrohDiscoveryConfig {
        enable_pkarr: true,
        enable_dns: true,
        dns_domain: Some("discovery.example.com".to_string()),
    };
    let result = igra_core::infrastructure::config::validation::validate_iroh_discovery(&config);
    assert!(result.is_ok());
}

#[test]
fn test_relay_config_validation() {
    // Invalid URL
    let config = IrohRelayConfig {
        enable: true,
        custom_url: Some("not a url".to_string()),
    };
    let result = igra_core::infrastructure::config::validation::validate_iroh_relay(&config);
    assert!(result.is_err());

    // Valid config
    let config = IrohRelayConfig {
        enable: true,
        custom_url: Some("https://relay.example.com".to_string()),
    };
    let result = igra_core::infrastructure::config::validation::validate_iroh_relay(&config);
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_endpoint_with_pkarr() {
    // This test requires network access (skipped in CI)
    if std::env::var("CI").is_ok() {
        return;
    }

    let discovery_config = IrohDiscoveryConfig {
        enable_pkarr: true,
        enable_dns: false,
        dns_domain: None,
    };

    let relay_config = IrohRelayConfig {
        enable: false,
        custom_url: None,
    };

    // Build discovery provider
    let discovery = discovery::build_discovery_provider(vec![], &discovery_config)
        .expect("should build discovery");
    assert!(discovery.is_some());

    // Build relay mode
    let relay_mode = discovery::parse_relay_mode(&relay_config).expect("should parse relay");
    assert!(matches!(relay_mode, RelayMode::Disabled));
}
```

**Run integration tests:**

```bash
cargo test --test iroh_discovery_test
```

### 5.3 Manual Testing

**Test 1: Pkarr Publishing**

```bash
# Terminal 1: Start node with pkarr enabled
cargo run --bin kaspa-threshold-service -- --config config-pkarr.toml

# Check logs for:
# [INFO] discovery: enabling pkarr DHT provider
# [INFO] iroh endpoint bound endpoint_id=kmwm7ox...
```

**Test 2: Multi-Node Discovery**

```bash
# Terminal 1: Start seed node
cargo run --bin kaspa-threshold-service -- \
    --config config-seed.toml \
    --profile signer-01

# Terminal 2: Start signer 1 (with pkarr, bootstrap to seed)
cargo run --bin kaspa-threshold-service -- \
    --config config-signer1.toml \
    --profile signer-02

# Terminal 3: Start signer 2 (with pkarr, bootstrap to seed)
cargo run --bin kaspa-threshold-service -- \
    --config config-signer2.toml \
    --profile signer-03

# Check logs for peer connections:
# [INFO] gossip: joined peers=3
```

**Test 3: Relay Fallback**

```bash
# Simulate NAT by binding to localhost only
cargo run --bin kaspa-threshold-service -- \
    --config config-with-relay.toml

# Check logs for:
# [INFO] relay: using default Iroh relay
# [INFO] connection established via relay peer=...
```

---

## 6. Production Deployment

### 6.1 Deployment Architecture

**3-Node Example:**

```
┌──────────────────────────────────────────────────────────┐
│                     Internet/Cloud                        │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Seed 1     │  │   Seed 2     │  │  Relay Server│   │
│  │  Public IP   │  │  Public IP   │  │  Public IP   │   │
│  │  DNS: seed1  │  │  DNS: seed2  │  │  DNS: relay  │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│         │                 │                  │            │
└─────────┼─────────────────┼──────────────────┼────────────┘
          │                 │                  │
    ┌─────┴─────────────────┴──────────────────┴────────┐
    │              Signer Mesh (N nodes)                 │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
    │  │ Signer 1 │  │ Signer 2 │  │ Signer 3 │  ...   │
    │  │(any NAT) │  │(any NAT) │  │(any NAT) │        │
    │  └──────────┘  └──────────┘  └──────────┘        │
    └────────────────────────────────────────────────────┘
```

**Infrastructure Requirements:**

| Component | Count | Specs | Purpose |
|-----------|-------|-------|---------|
| Seed Nodes | 2-3 | t3.small, Public IP, DNS | Bootstrap, DHT entry |
| Relay Server | 1 | t3.medium, Public IP, DNS | NAT traversal |
| Signer Nodes | N | t3.medium, Any network | Threshold signing |

### 6.2 Deployment Checklist

- [ ] **Seed nodes deployed** with public IPs and DNS records
- [ ] **Relay server deployed** (or using Iroh's default relay)
- [ ] **Config files generated** with correct bootstrap_addrs
- [ ] **Firewall rules configured** (UDP/TCP on bind_port)
- [ ] **Monitoring enabled** (see section 7)
- [ ] **Test connectivity** between all nodes
- [ ] **Backup configs** and identity files

### 6.3 Rollout Strategy

**Phase 1: Enable Pkarr Only**
```toml
[iroh.discovery]
enable_pkarr = true
enable_dns = false

[iroh.relay]
enable = false  # Test without relay first
```

**Deploy:** Seed nodes → Signers (one by one)
**Verify:** Peers discover each other via DHT
**Duration:** 1-2 days observation

**Phase 2: Enable Relay**
```toml
[iroh.relay]
enable = true
custom_url = "https://relay.example.com"  # Or use default
```

**Deploy:** All nodes simultaneously
**Verify:** NATed nodes connect via relay
**Duration:** 1-2 days observation

**Phase 3: Optional DNS Discovery**
```toml
[iroh.discovery]
enable_pkarr = true
enable_dns = true
dns_domain = "discovery.example.com"
```

**Deploy:** After DNS infrastructure setup
**Verify:** DNS queries working as fallback

---

## 7. Monitoring & Operations

### 7.1 Key Metrics

**Add to existing metrics:**

```rust
// Example metrics (if using Prometheus)
gauge!("iroh_discovery_providers", providers.len() as f64);
counter!("iroh_pkarr_publish_success").increment(1);
counter!("iroh_pkarr_publish_failed").increment(1);
counter!("iroh_relay_connections").increment(1);
histogram!("iroh_peer_discovery_latency_ms", latency_ms);
```

### 7.2 Log Patterns to Monitor

**Success Indicators:**

```
[INFO] discovery: enabling pkarr DHT provider
[INFO] iroh endpoint bound endpoint_id=kmwm7ox...
[INFO] gossip: joined peers=3
[INFO] peer discovered via DHT peer_id=... latency_ms=2345
```

**Warning Indicators:**

```
[WARN] discovery: no static bootstrap addresses configured
[WARN] discovery: pkarr init failed, skipping: <reason>
[WARN] relay: custom relay unreachable, falling back to direct
```

**Error Indicators:**

```
[ERROR] iroh endpoint bind failed: <reason>
[ERROR] pkarr publish failed after retries: <reason>
[ERROR] all discovery providers failed
```

### 7.3 Health Checks

**Endpoint health check:**

```bash
# Query local endpoint status
curl http://localhost:8080/api/v1/health

# Expected response:
{
  "status": "healthy",
  "iroh": {
    "endpoint_id": "kmwm7ox...",
    "connected_peers": 3,
    "discovery_providers": ["static", "pkarr"],
    "relay_enabled": true
  }
}
```

---

## 8. Troubleshooting

### 8.1 Common Issues

#### Issue 1: "No discovery providers configured"

**Symptoms:**
```
[WARN] discovery: no discovery providers configured
[WARN] nodes will not auto-discover peers
```

**Causes:**
- No static bootstrap_addrs AND pkarr disabled
- All discovery providers failed to initialize

**Solution:**
```bash
# Check config
grep -A5 "\[iroh.discovery\]" config.toml

# Enable pkarr or add bootstrap_addrs
```

#### Issue 2: "Pkarr init failed"

**Symptoms:**
```
[WARN] discovery: pkarr init failed, skipping: <error>
```

**Causes:**
- Firewall blocking UDP (DHT uses UDP)
- No internet access
- DHT bootstrap nodes unreachable

**Solution:**
```bash
# Test UDP connectivity
nc -vuz bootstrap.dht.example.com 6881

# Check firewall rules
sudo iptables -L | grep DROP
```

#### Issue 3: "Relay connection failed"

**Symptoms:**
```
[ERROR] relay connection failed: <error>
[INFO] falling back to direct connection
```

**Causes:**
- Custom relay URL unreachable
- Relay server down
- Firewall blocking HTTPS

**Solution:**
```bash
# Test relay connectivity
curl -v https://relay.example.com

# Fallback to Iroh's default relay
# Remove custom_url from config
```

#### Issue 4: "Peers not discovering each other"

**Symptoms:**
- Nodes start successfully
- No peer connections established
- DHT queries timeout

**Diagnosis:**
```bash
# Check endpoint_id matches in logs
grep "endpoint_id=" logs/*.log

# Verify group_id matches
grep "group_id=" logs/*.log

# Check network_id matches
grep "network_id=" logs/*.log
```

**Solution:**
- Ensure all nodes use same group_id
- Ensure all nodes use same network_id
- Verify bootstrap_addrs are reachable
- Wait 2-5 minutes for DHT propagation

### 8.2 Debug Commands

**Enable debug logging:**

```bash
export RUST_LOG=igra_core::infrastructure::transport::iroh=debug,iroh::discovery=debug

cargo run --bin kaspa-threshold-service -- --config config.toml
```

**Check DHT status:**

```bash
# Query DHT for specific peer
# (requires custom debug endpoint, not implemented yet)
curl http://localhost:8080/api/v1/debug/dht/query?endpoint_id=kmwm7ox...
```

**Check relay status:**

```bash
# Query relay connections
curl http://localhost:8080/api/v1/debug/relay/status
```

### 8.3 Rollback Plan

**If discovery causes issues:**

1. **Disable pkarr immediately:**
   ```toml
   [iroh.discovery]
   enable_pkarr = false
   ```

2. **Restart all nodes** (rolling restart)

3. **Verify connectivity** via static bootstrap only

4. **Investigate logs** for root cause

5. **Re-enable pkarr** after fix

---

## 9. Security Considerations

### 9.1 DHT Attacks

**Risk:** Malicious DHT nodes could return incorrect peer addresses

**Mitigation:**
- Pkarr records are signed with Ed25519
- Iroh verifies signatures before accepting
- Invalid records are rejected

### 9.2 Relay Privacy

**Risk:** Relay server sees metadata (not content)

**Mitigation:**
- End-to-end encryption (relay cannot decrypt)
- Self-host relay for full control
- Relay only used as fallback (direct preferred)

### 9.3 Config Validation

**Risk:** Invalid config breaks connectivity

**Mitigation:**
- Strict config validation (implemented in Step 1)
- Dry-run validation mode
- Fallback to static bootstrap if discovery fails

---

## 10. Future Enhancements

### 10.1 Planned Features

1. **DNS Discovery Implementation**
   - Status: Config added, implementation deferred
   - Use case: Centralized discovery for enterprise

2. **Custom DHT Bootstrap Nodes**
   - Status: Not implemented
   - Use case: Private DHT for air-gapped networks

3. **Relay Server Clustering**
   - Status: Not implemented
   - Use case: High-availability relay

### 10.2 Monitoring Improvements

1. **DHT Query Metrics**
   - Track query latency
   - Track success/failure rates

2. **Relay Usage Metrics**
   - Track % of connections via relay
   - Track relay bandwidth

---

## Appendix A: Quick Reference

### A.1 Config Template

```toml
[iroh]
network_id = 1
bind_port = 11205
bootstrap_addrs = ["seed@seed.example.com:11205"]

[iroh.discovery]
enable_pkarr = true
enable_dns = false
dns_domain = ""

[iroh.relay]
enable = true
custom_url = ""
```

### A.2 Command Cheat Sheet

```bash
# Validate config
cargo run --bin kaspa-threshold-service -- --config config.toml --validate-only

# Run with debug logs
RUST_LOG=debug cargo run --bin kaspa-threshold-service -- --config config.toml

# Run integration tests
cargo test --package igra-core discovery::tests
cargo test --test iroh_discovery_test

# Format code
cargo fmt --all

# Run lints
cargo clippy --workspace --tests --benches
```

### A.3 Error Codes

| Error | Code | Action |
|-------|------|--------|
| PkarrInitFailed | DISC001 | Check UDP/firewall |
| InvalidRelayConfig | DISC002 | Fix config.toml |
| MalformedRelayUrl | DISC003 | Fix relay URL |
| InvalidDnsDomain | DISC004 | Fix DNS domain |

---

## Document Review Checklist

Before implementation:

- [ ] All error handling uses structured ThresholdError variants (no Message)
- [ ] All constants defined in foundation/constants.rs with proper naming
- [ ] All config validated in config/validation.rs
- [ ] Logging includes context (peer_id, endpoint_id, etc.)
- [ ] No .unwrap() or .expect() in production code
- [ ] Tests follow naming conventions (test_*, tests:: module)
- [ ] Documentation includes examples and error cases
- [ ] Follows module structure guidelines (domain/application/infrastructure)
- [ ] No magic numbers (all timeouts/limits are constants)
- [ ] No duplicate code (DRY principle)

---

**End of Implementation Guide**

**Version:** 1.0
**Last Updated:** 2026-01-24
**Maintainer:** Igra Core Team
