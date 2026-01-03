# Code Reorganization and Refactoring Plan

## Executive Summary

The igra codebase is **well-architected** with clear separation of concerns and comprehensive test coverage (1.67:1 test-to-production ratio). However, there are opportunities to improve **maintainability**, **auditability**, and **robustness** through strategic refactoring.

**Current Status**: 8/10 - Production-ready with clear improvement path

**Key Findings**:
- ✅ No circular dependencies, no unsafe blocks
- ✅ Excellent test infrastructure and coverage
- ✅ Clear module boundaries and separation of concerns
- ⚠️ Large configuration file (784 lines) mixing multiple concerns
- ⚠️ Error handling inconsistencies
- ⚠️ Limited audit logging for security events
- ⚠️ Some performance bottlenecks (volume tracking)

---

## Part 1: Code Reorganization

### 1.1 Split Large Configuration Module

**Current State**: `igra-core/src/config.rs` (784 lines)
- Mixes INI parsing, DB persistence, validation, encryption, HD derivation
- 13+ configuration structs
- Hard to navigate and maintain

**Proposed Structure**:

```
igra-core/src/config/
├── mod.rs                    # Public API (re-exports)
├── types.rs                  # Configuration structs
├── loader.rs                 # INI parsing and loading
├── persistence.rs            # RocksDB storage integration
├── validation.rs             # Validation logic
├── encryption.rs             # Mnemonic encryption/decryption
└── env.rs                    # Environment variable handling
```

#### Implementation Plan

**Step 1: Create `config/types.rs`** (Priority: CRITICAL)

Move all configuration structs:
```rust
// igra-core/src/config/types.rs

use serde::{Deserialize, Serialize};

/// Service-level configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub node_rpc_url: String,
    pub data_dir: PathBuf,
}

/// PSKT building configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PsktConfig {
    pub source_addresses: Vec<Address>,
    pub redeem_script_hex: String,
    pub sig_op_count: u8,
    pub fee_payment_mode: FeePaymentMode,
    pub fee_sompi: u64,
    pub change_address: Option<Address>,
}

/// Runtime behavior configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub test_mode: bool,
    pub test_recipient: Option<Address>,
    pub test_amount_sompi: Option<u64>,
    pub session_timeout_seconds: u64,
}

/// Signing backend configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningConfig {
    pub backend: SigningBackend,
}

/// RPC server configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub addr: SocketAddr,
    pub token: Option<String>,
    pub enabled: bool,
}

/// Iroh transport configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrohConfig {
    pub group_id: String,
    pub peer_id: String,
    pub signer_seed_hex: Option<String>,
    pub verifier_keys: HashMap<String, String>,
    pub network_id: u32,
    pub bootstrap: Option<String>,
    pub bind_port: Option<u16>,
}

/// Hyperlane validator configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HyperlaneConfig {
    pub validators: Vec<String>,
    pub events_dir: Option<PathBuf>,
    pub poll_secs: u64,
}

/// LayerZero endpoint configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerZeroConfig {
    pub endpoint_pubkeys: Vec<String>,
}

/// HD wallet configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HdConfig {
    pub mnemonics: Option<Vec<String>>,  // Encrypted
    pub xpubs: Vec<String>,
    pub required_sigs: u8,
    pub passphrase: Option<String>,
}

/// Main application configuration (aggregates all sub-configs)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub service: ServiceConfig,
    pub pskt: PsktConfig,
    pub runtime: RuntimeConfig,
    pub signing: SigningConfig,
    pub rpc: RpcConfig,
    pub policy: GroupPolicy,
    pub group: GroupConfig,
    pub iroh: IrohConfig,
    pub hyperlane: HyperlaneConfig,
    pub layerzero: LayerZeroConfig,
    pub hd: Option<HdConfig>,
}

impl AppConfig {
    /// Validate entire configuration tree
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.service.validate()?;
        self.pskt.validate()?;
        self.runtime.validate()?;
        self.signing.validate()?;
        self.rpc.validate()?;
        self.policy.validate()?;
        self.group.validate()?;
        self.iroh.validate()?;
        self.hyperlane.validate()?;
        self.layerzero.validate()?;
        if let Some(hd) = &self.hd {
            hd.validate()?;
        }
        Ok(())
    }
}
```

**Step 2: Create `config/loader.rs`** (Priority: CRITICAL)

Extract INI parsing logic:
```rust
// igra-core/src/config/loader.rs

use ini::Ini;
use std::path::Path;
use super::types::*;
use super::env;

/// Load configuration from INI file
pub fn load_from_ini(path: &Path) -> Result<AppConfig, ConfigError> {
    let ini = Ini::load_from_file(path)
        .map_err(|e| ConfigError::IniParse(path.display().to_string(), e))?;

    let mut config = AppConfig::default();

    if let Some(section) = ini.section(Some("service")) {
        apply_service_config(&mut config.service, section)?;
    }

    if let Some(section) = ini.section(Some("pskt")) {
        apply_pskt_config(&mut config.pskt, section)?;
    }

    if let Some(section) = ini.section(Some("runtime")) {
        apply_runtime_config(&mut config.runtime, section)?;
    }

    // ... apply other sections

    // Resolve environment variables
    env::apply_env_overrides(&mut config)?;

    // Validate after loading
    config.validate()?;

    Ok(config)
}

fn apply_service_config(
    config: &mut ServiceConfig,
    section: &ini::Properties,
) -> Result<(), ConfigError> {
    if let Some(url) = section.get("node_rpc_url") {
        config.node_rpc_url = url.to_string();
    }
    if let Some(dir) = section.get("data_dir") {
        config.data_dir = PathBuf::from(dir);
    }
    Ok(())
}

// ... other apply_* functions
```

**Step 3: Create `config/persistence.rs`** (Priority: CRITICAL)

Extract database persistence:
```rust
// igra-core/src/config/persistence.rs

use crate::storage::Storage;
use super::types::AppConfig;

const CONFIG_KEY: &[u8] = b"cfg:app";

/// Load configuration from storage, fallback to INI if not found
pub fn load_or_initialize(
    storage: &dyn Storage,
    ini_path: Option<&Path>,
) -> Result<AppConfig, ConfigError> {
    // Try loading from storage first
    if let Some(stored_config) = load_from_storage(storage)? {
        return Ok(stored_config);
    }

    // Load from INI
    let ini_path = ini_path.or_else(|| env::get_config_path())
        .ok_or(ConfigError::NoConfigPath)?;

    let config = super::loader::load_from_ini(ini_path)?;

    // Persist to storage
    save_to_storage(storage, &config)?;

    Ok(config)
}

/// Load configuration from storage
pub fn load_from_storage(storage: &dyn Storage) -> Result<Option<AppConfig>, ConfigError> {
    match storage.get(CONFIG_KEY)? {
        Some(bytes) => {
            let config = bincode::deserialize(&bytes)
                .map_err(|e| ConfigError::Deserialization(e))?;
            Ok(Some(config))
        }
        None => Ok(None),
    }
}

/// Save configuration to storage
pub fn save_to_storage(storage: &dyn Storage, config: &AppConfig) -> Result<(), ConfigError> {
    let bytes = bincode::serialize(config)
        .map_err(|e| ConfigError::Serialization(e))?;
    storage.insert(CONFIG_KEY, &bytes)?;
    Ok(())
}
```

**Step 4: Create `config/validation.rs`** (Priority: CRITICAL)

Centralize validation logic:
```rust
// igra-core/src/config/validation.rs

use super::types::*;

/// Validation trait for all config types
pub trait Validate {
    fn validate(&self) -> Result<(), ConfigError>;
}

impl Validate for ServiceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate node_rpc_url is valid URL
        if self.node_rpc_url.is_empty() {
            return Err(ConfigError::InvalidField("service.node_rpc_url", "cannot be empty"));
        }

        // Validate data_dir exists or can be created
        if !self.data_dir.exists() {
            std::fs::create_dir_all(&self.data_dir)
                .map_err(|e| ConfigError::InvalidDataDir(self.data_dir.clone(), e))?;
        }

        Ok(())
    }
}

impl Validate for PsktConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate source addresses
        if self.source_addresses.is_empty() {
            return Err(ConfigError::InvalidField(
                "pskt.source_addresses",
                "at least one address required",
            ));
        }

        for addr in &self.source_addresses {
            if addr.network() != self.source_addresses[0].network() {
                return Err(ConfigError::InvalidField(
                    "pskt.source_addresses",
                    "all addresses must be on same network",
                ));
            }
        }

        // Validate redeem script
        if self.redeem_script_hex.is_empty() {
            return Err(ConfigError::InvalidField(
                "pskt.redeem_script_hex",
                "cannot be empty",
            ));
        }

        let script_bytes = hex::decode(&self.redeem_script_hex)
            .map_err(|_| ConfigError::InvalidField(
                "pskt.redeem_script_hex",
                "invalid hex encoding",
            ))?;

        if script_bytes.is_empty() {
            return Err(ConfigError::InvalidField(
                "pskt.redeem_script_hex",
                "decoded script is empty",
            ));
        }

        // Validate sig_op_count
        if self.sig_op_count == 0 {
            return Err(ConfigError::InvalidField(
                "pskt.sig_op_count",
                "must be > 0",
            ));
        }

        // Validate fee_payment_mode
        self.fee_payment_mode.validate()?;

        // Validate change_address if present
        if let Some(change_addr) = &self.change_address {
            if change_addr.network() != self.source_addresses[0].network() {
                return Err(ConfigError::InvalidField(
                    "pskt.change_address",
                    "must be on same network as source addresses",
                ));
            }
        }

        Ok(())
    }
}

impl Validate for RuntimeConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate session timeout
        if self.session_timeout_seconds < 10 {
            return Err(ConfigError::InvalidField(
                "runtime.session_timeout_seconds",
                "must be >= 10 seconds",
            ));
        }

        if self.session_timeout_seconds > 600 {
            return Err(ConfigError::InvalidField(
                "runtime.session_timeout_seconds",
                "must be <= 600 seconds",
            ));
        }

        // Validate test mode consistency
        if self.test_mode {
            if self.test_recipient.is_none() {
                return Err(ConfigError::InvalidField(
                    "runtime.test_recipient",
                    "required when test_mode is true",
                ));
            }
            if self.test_amount_sompi.is_none() {
                return Err(ConfigError::InvalidField(
                    "runtime.test_amount_sompi",
                    "required when test_mode is true",
                ));
            }
        }

        Ok(())
    }
}

impl Validate for GroupConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate threshold
        if self.threshold_m == 0 {
            return Err(ConfigError::InvalidField(
                "group.threshold_m",
                "must be > 0",
            ));
        }

        if self.threshold_m > self.threshold_n {
            return Err(ConfigError::InvalidField(
                "group.threshold_m",
                "must be <= threshold_n",
            ));
        }

        // Validate member count matches threshold_n
        if self.member_pubkeys.len() != self.threshold_n as usize {
            return Err(ConfigError::InvalidField(
                "group.member_pubkeys",
                &format!("expected {} pubkeys, got {}", self.threshold_n, self.member_pubkeys.len()),
            ));
        }

        // Validate pubkeys are valid hex
        for pubkey in &self.member_pubkeys {
            hex::decode(pubkey).map_err(|_| ConfigError::InvalidField(
                "group.member_pubkeys",
                "invalid hex encoding",
            ))?;
        }

        Ok(())
    }
}

impl Validate for GroupPolicy {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate allowed destinations
        for addr_str in &self.allowed_destinations {
            Address::try_from(addr_str.as_str())
                .map_err(|_| ConfigError::InvalidField(
                    "policy.allowed_destinations",
                    &format!("invalid address: {}", addr_str),
                ))?;
        }

        // Validate amount limits
        if let (Some(min), Some(max)) = (self.min_amount_sompi, self.max_amount_sompi) {
            if min > max {
                return Err(ConfigError::InvalidField(
                    "policy.min_amount_sompi",
                    "must be <= max_amount_sompi",
                ));
            }
        }

        // Validate daily volume limit
        if let Some(limit) = self.max_daily_volume_sompi {
            if limit == 0 {
                return Err(ConfigError::InvalidField(
                    "policy.max_daily_volume_sompi",
                    "must be > 0 if set",
                ));
            }
        }

        Ok(())
    }
}

impl Validate for FeePaymentMode {
    fn validate(&self) -> Result<(), ConfigError> {
        if let FeePaymentMode::Split { recipient_portion } = self {
            if *recipient_portion < 0.0 || *recipient_portion > 1.0 {
                return Err(ConfigError::InvalidField(
                    "fee_payment_mode.recipient_portion",
                    "must be between 0.0 and 1.0",
                ));
            }
        }
        Ok(())
    }
}

// Implement Validate for other config types...
```

**Step 5: Create `config/encryption.rs`** (Priority: CRITICAL)

Extract mnemonic encryption:
```rust
// igra-core/src/config/encryption.rs

use kaspa_wallet_core::encryption::{decrypt_mnemonic, encrypt_mnemonic};
use zeroize::Zeroizing;

/// Encrypt mnemonics using wallet secret
pub fn encrypt_mnemonics(
    mnemonics: &[String],
    secret: &str,
) -> Result<Vec<String>, ConfigError> {
    mnemonics
        .iter()
        .map(|mnemonic| {
            encrypt_mnemonic(mnemonic, secret)
                .map_err(|e| ConfigError::EncryptionFailed(e.to_string()))
        })
        .collect()
}

/// Decrypt mnemonics using wallet secret
pub fn decrypt_mnemonics(
    encrypted: &[String],
    secret: &str,
) -> Result<Vec<Zeroizing<String>>, ConfigError> {
    encrypted
        .iter()
        .map(|enc| {
            decrypt_mnemonic(enc, secret)
                .map_err(|e| ConfigError::DecryptionFailed(e.to_string()))
        })
        .collect()
}

/// Get wallet secret from environment
pub fn get_wallet_secret() -> Result<String, ConfigError> {
    std::env::var("KASPA_IGRA_WALLET_SECRET")
        .map_err(|_| ConfigError::MissingWalletSecret)
}

/// Encrypt HD config mnemonics in place
pub fn encrypt_hd_config(
    hd_config: &mut HdConfig,
    secret: &str,
) -> Result<(), ConfigError> {
    if let Some(mnemonics) = &hd_config.mnemonics {
        let encrypted = encrypt_mnemonics(mnemonics, secret)?;
        hd_config.mnemonics = Some(encrypted);
    }
    Ok(())
}

/// Decrypt HD config mnemonics
pub fn decrypt_hd_config(
    hd_config: &HdConfig,
    secret: &str,
) -> Result<Vec<Zeroizing<String>>, ConfigError> {
    match &hd_config.mnemonics {
        Some(encrypted) => decrypt_mnemonics(encrypted, secret),
        None => Ok(vec![]),
    }
}
```

**Step 6: Create `config/env.rs`** (Priority: HIGH)

Centralize environment variable handling:
```rust
// igra-core/src/config/env.rs

use std::path::PathBuf;
use super::types::*;

/// All environment variables used by igra
pub mod vars {
    pub const CONFIG_PATH: &str = "KASPA_CONFIG_PATH";
    pub const DATA_DIR: &str = "KASPA_DATA_DIR";
    pub const WALLET_SECRET: &str = "KASPA_IGRA_WALLET_SECRET";
    pub const TEST_NOW_NANOS: &str = "KASPA_IGRA_TEST_NOW_NANOS";
    pub const NODE_URL: &str = "KASPA_NODE_URL";
    pub const FINALIZE_PSKT_JSON: &str = "KASPA_FINALIZE_PSKT_JSON";
    pub const AUDIT_REQUEST_ID: &str = "KASPA_AUDIT_REQUEST_ID";
}

/// Get config path from environment or default
pub fn get_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(vars::CONFIG_PATH) {
        return Some(PathBuf::from(path));
    }

    if let Ok(data_dir) = std::env::var(vars::DATA_DIR) {
        return Some(PathBuf::from(data_dir).join("igra-config.ini"));
    }

    Some(PathBuf::from("./.igra/igra-config.ini"))
}

/// Get data directory from environment or default
pub fn get_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(vars::DATA_DIR) {
        return PathBuf::from(dir);
    }

    PathBuf::from("./.igra")
}

/// Apply environment variable overrides to config
pub fn apply_env_overrides(config: &mut AppConfig) -> Result<(), ConfigError> {
    // Override node URL if set
    if let Ok(url) = std::env::var(vars::NODE_URL) {
        config.service.node_rpc_url = url;
    }

    // Override data dir if set
    if let Ok(dir) = std::env::var(vars::DATA_DIR) {
        config.service.data_dir = PathBuf::from(dir);
    }

    Ok(())
}

/// Check if running in finalize-only mode
pub fn is_finalize_mode() -> bool {
    std::env::var(vars::FINALIZE_PSKT_JSON).is_ok()
}

/// Check if running in audit mode
pub fn is_audit_mode() -> bool {
    std::env::var(vars::AUDIT_REQUEST_ID).is_ok()
}

/// Get audit request ID if in audit mode
pub fn get_audit_request_id() -> Option<String> {
    std::env::var(vars::AUDIT_REQUEST_ID).ok()
}
```

**Step 7: Update `config/mod.rs`** (Priority: CRITICAL)

```rust
// igra-core/src/config/mod.rs

mod types;
mod loader;
mod persistence;
mod validation;
mod encryption;
mod env;

// Re-export public API
pub use types::*;
pub use env::vars;

use crate::error::ConfigError;
use crate::storage::Storage;
use std::path::Path;

/// Load configuration from storage or INI file
pub fn load_config(
    storage: &dyn Storage,
    ini_path: Option<&Path>,
) -> Result<AppConfig, ConfigError> {
    persistence::load_or_initialize(storage, ini_path)
}

/// Load configuration from INI file only (for testing)
pub fn load_config_from_ini(path: &Path) -> Result<AppConfig, ConfigError> {
    loader::load_from_ini(path)
}

/// Save configuration to storage
pub fn save_config(
    storage: &dyn Storage,
    config: &AppConfig,
) -> Result<(), ConfigError> {
    persistence::save_to_storage(storage, config)
}

/// Get wallet secret from environment
pub fn get_wallet_secret() -> Result<String, ConfigError> {
    encryption::get_wallet_secret()
}

/// Encrypt HD config mnemonics
pub fn encrypt_hd_config(
    hd_config: &mut HdConfig,
    secret: &str,
) -> Result<(), ConfigError> {
    encryption::encrypt_hd_config(hd_config, secret)
}

/// Decrypt HD config mnemonics
pub fn decrypt_hd_config(
    hd_config: &HdConfig,
    secret: &str,
) -> Result<Vec<zeroize::Zeroizing<String>>, ConfigError> {
    encryption::decrypt_hd_config(hd_config, secret)
}
```

**Migration Strategy**:
1. Create new config/ directory structure
2. Copy-paste code from config.rs into appropriate files
3. Update imports in existing code incrementally
4. Run tests after each module migration
5. Remove old config.rs when all code migrated
6. Update documentation

**Estimated Effort**: 8-12 hours
**Risk**: Medium (touches many files, but changes are mechanical)
**Benefits**:
- Much easier to navigate and maintain
- Clear separation of concerns
- Easier to test individual components
- Better for code review and auditing

---

### 1.2 Split Large Binary File

**Current State**: `igra-service/src/bin/kaspa-threshold-service.rs` (463 lines)
- CLI parsing, config loading, identity management, service initialization all mixed

**Proposed Structure**:

```
igra-service/src/bin/
├── kaspa-threshold-service.rs    # Main entry point (~100 lines)
├── cli.rs                         # CLI argument parsing
├── setup.rs                       # Service initialization
└── modes/
    ├── mod.rs
    ├── finalize.rs                # Finalize-only mode
    └── audit.rs                   # Audit mode
```

#### Implementation Plan

**Step 1: Create `bin/cli.rs`**

```rust
// igra-service/src/bin/cli.rs

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "kaspa-threshold-service")]
#[command(about = "Kaspa threshold signature service", long_about = None)]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Override data directory
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Override node RPC URL
    #[arg(short, long)]
    pub node_url: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,

    /// Finalize PSKT from JSON file
    #[arg(long)]
    pub finalize: Option<PathBuf>,

    /// Dump audit trail for request ID
    #[arg(long)]
    pub audit: Option<String>,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }

    pub fn apply_to_env(&self) {
        if let Some(config_path) = &self.config {
            std::env::set_var("KASPA_CONFIG_PATH", config_path);
        }

        if let Some(data_dir) = &self.data_dir {
            std::env::set_var("KASPA_DATA_DIR", data_dir);
        }

        if let Some(node_url) = &self.node_url {
            std::env::set_var("KASPA_NODE_URL", node_url);
        }

        if let Some(finalize_path) = &self.finalize {
            std::env::set_var("KASPA_FINALIZE_PSKT_JSON", finalize_path);
        }

        if let Some(audit_id) = &self.audit {
            std::env::set_var("KASPA_AUDIT_REQUEST_ID", audit_id);
        }
    }
}
```

**Step 2: Create `bin/setup.rs`**

```rust
// igra-service/src/bin/setup.rs

use igra_core::{config, error::Result, storage::RocksStorage};
use igra_service::service::ThresholdService;
use std::sync::{Arc, RwLock};
use tracing_subscriber;

/// Initialize logging
pub fn init_logging(level: &str) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    Ok(())
}

/// Initialize storage
pub fn init_storage(data_dir: &Path) -> Result<Arc<RwLock<RocksStorage>>> {
    let db_path = data_dir.join("data");
    let storage = RocksStorage::new(&db_path)?;
    Ok(Arc::new(RwLock::new(storage)))
}

/// Load or create configuration
pub fn init_config(
    storage: &dyn igra_core::storage::Storage,
) -> Result<config::AppConfig> {
    let config = config::load_config(storage, None)?;

    // Encrypt HD mnemonics if needed
    if let Some(mut hd_config) = config.hd.clone() {
        if hd_config.needs_encryption() {
            let secret = config::get_wallet_secret()?;
            config::encrypt_hd_config(&mut hd_config, &secret)?;

            // Save updated config
            let mut updated_config = config.clone();
            updated_config.hd = Some(hd_config);
            config::save_config(storage, &updated_config)?;

            return Ok(updated_config);
        }
    }

    Ok(config)
}

/// Initialize Iroh identity
pub fn init_iroh_identity(
    config: &config::AppConfig,
    data_dir: &Path,
) -> Result<iroh::SecretKey> {
    let identity_path = data_dir.join("iroh").join("identity.json");

    if identity_path.exists() {
        // Load existing identity
        let json = std::fs::read_to_string(&identity_path)?;
        let secret = serde_json::from_str(&json)?;
        Ok(secret)
    } else {
        // Generate new identity
        let secret = if let Some(seed_hex) = &config.iroh.signer_seed_hex {
            let seed_bytes = hex::decode(seed_hex)?;
            iroh::SecretKey::from_bytes(&seed_bytes)?
        } else {
            iroh::SecretKey::generate()
        };

        // Save identity
        std::fs::create_dir_all(identity_path.parent().unwrap())?;
        let json = serde_json::to_string(&secret)?;
        std::fs::write(&identity_path, json)?;

        Ok(secret)
    }
}

/// Build and start the threshold service
pub async fn start_service(
    config: config::AppConfig,
    storage: Arc<RwLock<RocksStorage>>,
    iroh_secret: iroh::SecretKey,
) -> Result<()> {
    let service = ThresholdService::new(config, storage, iroh_secret).await?;

    tracing::info!("Starting threshold service...");
    service.run().await?;

    Ok(())
}
```

**Step 3: Create `bin/modes/finalize.rs`**

```rust
// igra-service/src/bin/modes/finalize.rs

use igra_core::{config, error::Result, pskt, storage::RocksStorage};
use std::path::Path;

/// Finalize PSKT from JSON file
pub async fn finalize_from_json(
    json_path: &Path,
    storage: &RocksStorage,
    config: &config::AppConfig,
) -> Result<()> {
    tracing::info!("Finalize mode: loading PSKT from {}", json_path.display());

    // Load PSKT JSON
    let json = std::fs::read_to_string(json_path)?;
    let pskt_data: serde_json::Value = serde_json::from_str(&json)?;

    // Extract fields
    let request_id = pskt_data["request_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing request_id"))?;

    let pskt_blob_hex = pskt_data["pskt_blob"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing pskt_blob"))?;

    let pskt_blob = hex::decode(pskt_blob_hex)?;

    // Reconstruct PSKT
    let mut pskt = pskt::Pskt::deserialize(&pskt_blob)?;

    // Load partial signatures from storage
    let partial_sigs = storage.get_partial_sigs(request_id)?;

    tracing::info!("Found {} partial signatures", partial_sigs.len());

    // Combine signatures
    for partial_sig in partial_sigs {
        let input_index = partial_sig.input_index as usize;
        let sig_bytes = hex::decode(&partial_sig.signature_hex)?;

        pskt.inputs[input_index].partial_sigs.insert(
            partial_sig.pubkey.clone(),
            sig_bytes,
        );
    }

    // Finalize PSKT
    let finalized_tx = pskt.finalize()?;

    // Submit to Kaspa node
    let node_rpc = igra_core::rpc::create_node_rpc(&config.service.node_rpc_url).await?;
    let tx_id = node_rpc.submit_transaction(finalized_tx).await?;

    tracing::info!("Transaction submitted: {}", tx_id);
    println!("Transaction ID: {}", tx_id);

    // Update storage
    storage.update_request_final_tx(request_id, tx_id)?;

    Ok(())
}
```

**Step 4: Create `bin/modes/audit.rs`**

```rust
// igra-service/src/bin/modes/audit.rs

use igra_core::{error::Result, storage::RocksStorage};
use serde_json::json;

/// Dump audit trail for request
pub fn dump_audit_trail(
    request_id: &str,
    storage: &RocksStorage,
) -> Result<()> {
    tracing::info!("Audit mode: dumping trail for {}", request_id);

    // Load all related records
    let event = storage.get_event_by_request(request_id)?;
    let request = storage.get_request(request_id)?;
    let proposal = storage.get_proposal(request_id)?;
    let inputs = storage.get_request_inputs(request_id)?;
    let acks = storage.get_acks(request_id)?;
    let partial_sigs = storage.get_partial_sigs(request_id)?;

    // Build JSON output
    let audit = json!({
        "request_id": request_id,
        "event": event,
        "request": request,
        "proposal": proposal,
        "inputs": inputs,
        "acks": acks,
        "partial_sigs": partial_sigs,
    });

    // Pretty-print to stdout
    println!("{}", serde_json::to_string_pretty(&audit)?);

    Ok(())
}
```

**Step 5: Simplify `kaspa-threshold-service.rs`**

```rust
// igra-service/src/bin/kaspa-threshold-service.rs

mod cli;
mod setup;
mod modes;

use cli::Cli;
use igra_core::error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Cli::parse_args();

    // Initialize logging
    setup::init_logging(&args.log_level)?;

    // Apply CLI args to environment
    args.apply_to_env();

    // Initialize storage
    let data_dir = igra_core::config::env::get_data_dir();
    let storage = setup::init_storage(&data_dir)?;

    // Load configuration
    let config = setup::init_config(&*storage.read().unwrap())?;

    // Check for special modes
    if let Some(request_id) = &args.audit {
        return modes::audit::dump_audit_trail(request_id, &storage.read().unwrap());
    }

    if let Some(finalize_path) = &args.finalize {
        return modes::finalize::finalize_from_json(
            finalize_path,
            &storage.read().unwrap(),
            &config,
        ).await;
    }

    // Initialize Iroh identity
    let iroh_secret = setup::init_iroh_identity(&config, &data_dir)?;

    // Start service
    setup::start_service(config, storage, iroh_secret).await?;

    Ok(())
}
```

**Estimated Effort**: 4-6 hours
**Risk**: Low (clear separation of concerns)
**Benefits**:
- Much easier to understand main entry point
- Easier to test individual modes
- Better code organization

---

### 1.3 Split Large Transport Module

**Current State**: `igra-service/src/transport/iroh.rs` (411 lines)

**Proposed Structure**:

```
igra-service/src/transport/iroh/
├── mod.rs          # Public API and main IrohTransport impl
├── encoding.rs     # Message encoding/decoding
├── subscription.rs # Gossip subscription handling
└── filtering.rs    # Message filtering and deduplication
```

**Estimated Effort**: 3-4 hours
**Risk**: Low

---

## Part 2: Code Refactoring for Robustness

### 2.1 Improve Error Handling

**Current Issues**:
- Generic `Message(String)` error variant used as catch-all
- No error codes for API consumers
- Lost error context in some cases

**Proposed Improvements**:

#### Step 1: Add Error Codes

```rust
// igra-core/src/error.rs

use thiserror::Error;

/// Error codes for API consumers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Configuration errors (1000-1099)
    ConfigNotFound = 1000,
    ConfigInvalid = 1001,
    ConfigEncryptionFailed = 1002,

    // Storage errors (1100-1199)
    StorageRead = 1100,
    StorageWrite = 1101,
    StorageCorrupted = 1102,

    // Event validation errors (1200-1299)
    EventReplayed = 1200,
    EventSignatureInvalid = 1201,
    EventValidationFailed = 1202,

    // Policy errors (1300-1399)
    PolicyViolation = 1300,
    DestinationNotAllowed = 1301,
    AmountLimitExceeded = 1302,
    VolumeLimit Exceeded = 1303,

    // Coordination errors (1400-1499)
    ValidationHashMismatch = 1400,
    InsufficientSignatures = 1401,
    ThresholdNotMet = 1402,
    SessionTimedOut = 1403,

    // Cryptographic errors (1500-1599)
    SigningFailed = 1500,
    VerificationFailed = 1501,
    KeyDerivationFailed = 1502,

    // Network errors (1600-1699)
    TransportError = 1600,
    NodeRpcFailed = 1601,
    ConnectionFailed = 1602,

    // Generic errors (9000+)
    Unknown = 9000,
    InternalError = 9001,
}

#[derive(Debug, Error)]
pub enum ThresholdError {
    #[error("[{code}] event already processed: {event_hash}")]
    EventReplayed {
        code: ErrorCode,
        event_hash: String,
    },

    #[error("[{code}] event signature verification failed: {reason}")]
    EventSignatureInvalid {
        code: ErrorCode,
        reason: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("[{code}] destination {destination} not in allowlist")]
    DestinationNotAllowed {
        code: ErrorCode,
        destination: String,
        allowed: Vec<String>,
    },

    #[error("[{code}] amount {amount} exceeds maximum {max}")]
    AmountLimitExceeded {
        code: ErrorCode,
        amount: u64,
        max: u64,
    },

    #[error("[{code}] daily volume would exceed limit: {current} + {requested} > {limit}")]
    VolumeExceeded {
        code: ErrorCode,
        current: u64,
        requested: u64,
        limit: u64,
    },

    #[error("[{code}] validation hash mismatch")]
    ValidationHashMismatch {
        code: ErrorCode,
        expected: String,
        actual: String,
    },

    #[error("[{code}] insufficient signatures: {have}/{required}")]
    InsufficientSignatures {
        code: ErrorCode,
        have: usize,
        required: usize,
    },

    #[error("[{code}] {message}")]
    Internal {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl ThresholdError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::EventReplayed { code, .. } => *code,
            Self::EventSignatureInvalid { code, .. } => *code,
            Self::DestinationNotAllowed { code, .. } => *code,
            Self::AmountLimitExceeded { code, .. } => *code,
            Self::VolumeExceeded { code, .. } => *code,
            Self::ValidationHashMismatch { code, .. } => *code,
            Self::InsufficientSignatures { code, .. } => *code,
            Self::Internal { code, .. } => *code,
        }
    }

    /// Convert to JSON for API responses
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error_code": self.code() as u16,
            "error_message": self.to_string(),
            "error_details": self.details(),
        })
    }

    fn details(&self) -> serde_json::Value {
        match self {
            Self::DestinationNotAllowed { destination, allowed, .. } => {
                serde_json::json!({
                    "destination": destination,
                    "allowed_destinations": allowed,
                })
            }
            Self::AmountLimitExceeded { amount, max, .. } => {
                serde_json::json!({
                    "requested_amount": amount,
                    "maximum_allowed": max,
                })
            }
            Self::VolumeExceeded { current, requested, limit, .. } => {
                serde_json::json!({
                    "current_volume": current,
                    "requested_amount": requested,
                    "daily_limit": limit,
                })
            }
            _ => serde_json::json!({}),
        }
    }
}
```

**Usage Example**:

```rust
// Before:
return Err(ThresholdError::Message("destination not allowed".to_string()));

// After:
return Err(ThresholdError::DestinationNotAllowed {
    code: ErrorCode::DestinationNotAllowed,
    destination: event.recipient_address.clone(),
    allowed: policy.allowed_destinations.clone(),
});
```

**Estimated Effort**: 6-8 hours
**Benefits**:
- Clear error codes for monitoring and alerting
- Better error messages with context
- Structured error data for API consumers
- Error source chain for debugging

---

### 2.2 Add Comprehensive Audit Logging

**Current State**: Limited logging, mostly in service layer

**Proposed: Security Audit Log Module**

```rust
// igra-core/src/audit/mod.rs

use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tracing;

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Event received and validated
    EventReceived {
        event_hash: String,
        source: String,
        recipient: String,
        amount_sompi: u64,
        timestamp_ns: u64,
    },

    /// Event signature validation result
    EventSignatureValidated {
        event_hash: String,
        validator_count: usize,
        valid: bool,
        reason: Option<String>,
        timestamp_ns: u64,
    },

    /// Policy enforcement decision
    PolicyEnforced {
        request_id: String,
        event_hash: String,
        policy_type: String,
        decision: PolicyDecision,
        reason: String,
        timestamp_ns: u64,
    },

    /// Proposal validated by signer
    ProposalValidated {
        request_id: String,
        signer_peer_id: String,
        accepted: bool,
        reason: Option<String>,
        validation_hash: String,
        timestamp_ns: u64,
    },

    /// Partial signature created
    PartialSignatureCreated {
        request_id: String,
        signer_peer_id: String,
        input_count: usize,
        timestamp_ns: u64,
    },

    /// Transaction finalized
    TransactionFinalized {
        request_id: String,
        event_hash: String,
        tx_id: String,
        signature_count: usize,
        threshold_required: usize,
        timestamp_ns: u64,
    },

    /// Transaction submitted to network
    TransactionSubmitted {
        request_id: String,
        tx_id: String,
        blue_score: u64,
        timestamp_ns: u64,
    },

    /// Session timed out
    SessionTimedOut {
        request_id: String,
        event_hash: String,
        signature_count: usize,
        threshold_required: usize,
        duration_seconds: u64,
        timestamp_ns: u64,
    },

    /// Configuration changed
    ConfigurationChanged {
        change_type: String,
        old_value: Option<String>,
        new_value: String,
        changed_by: String,
        timestamp_ns: u64,
    },

    /// Storage mutation
    StorageMutated {
        operation: String,
        key_prefix: String,
        record_count: usize,
        timestamp_ns: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Allowed,
    Rejected,
}

/// Audit logger trait
pub trait AuditLogger: Send + Sync {
    fn log(&self, event: AuditEvent);
}

/// Structured audit logger using tracing
pub struct StructuredAuditLogger;

impl AuditLogger for StructuredAuditLogger {
    fn log(&self, event: AuditEvent) {
        let json = serde_json::to_string(&event).unwrap();
        tracing::info!(target: "audit", "{}", json);
    }
}

/// Audit logger that writes to dedicated file
pub struct FileAuditLogger {
    file: Arc<std::sync::Mutex<std::fs::File>>,
}

impl FileAuditLogger {
    pub fn new(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Arc::new(std::sync::Mutex::new(file)),
        })
    }
}

impl AuditLogger for FileAuditLogger {
    fn log(&self, event: AuditEvent) {
        use std::io::Write;

        let json = serde_json::to_string(&event).unwrap();
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", json).ok();
        file.flush().ok();
    }
}

/// Multi-target audit logger
pub struct MultiAuditLogger {
    loggers: Vec<Box<dyn AuditLogger>>,
}

impl MultiAuditLogger {
    pub fn new() -> Self {
        Self { loggers: vec![] }
    }

    pub fn add_logger(&mut self, logger: Box<dyn AuditLogger>) {
        self.loggers.push(logger);
    }
}

impl AuditLogger for MultiAuditLogger {
    fn log(&self, event: AuditEvent) {
        for logger in &self.loggers {
            logger.log(event.clone());
        }
    }
}

/// Global audit logger instance
static mut AUDIT_LOGGER: Option<Box<dyn AuditLogger>> = None;
static INIT: std::sync::Once = std::sync::Once::new();

/// Initialize audit logger
pub fn init_audit_logger(logger: Box<dyn AuditLogger>) {
    INIT.call_once(|| {
        unsafe {
            AUDIT_LOGGER = Some(logger);
        }
    });
}

/// Log audit event
pub fn audit(event: AuditEvent) {
    unsafe {
        if let Some(logger) = &AUDIT_LOGGER {
            logger.log(event);
        }
    }
}

// Helper macros
#[macro_export]
macro_rules! audit_event_received {
    ($event_hash:expr, $event:expr) => {
        $crate::audit::audit($crate::audit::AuditEvent::EventReceived {
            event_hash: $event_hash.to_string(),
            source: $event.source.to_string(),
            recipient: $event.recipient_address.clone(),
            amount_sompi: $event.amount_sompi,
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        })
    };
}

#[macro_export]
macro_rules! audit_policy_enforced {
    ($request_id:expr, $event_hash:expr, $policy_type:expr, $decision:expr, $reason:expr) => {
        $crate::audit::audit($crate::audit::AuditEvent::PolicyEnforced {
            request_id: $request_id.to_string(),
            event_hash: $event_hash.to_string(),
            policy_type: $policy_type.to_string(),
            decision: $decision,
            reason: $reason.to_string(),
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        })
    };
}
```

**Usage in Code**:

```rust
// In event ingestion:
audit_event_received!(event_hash, event);

// In policy enforcement:
if !policy.allowed_destinations.contains(&event.recipient_address) {
    audit_policy_enforced!(
        request_id,
        event_hash,
        "destination_allowlist",
        PolicyDecision::Rejected,
        format!("Destination {} not in allowlist", event.recipient_address)
    );
    return Err(ThresholdError::DestinationNotAllowed { ... });
}

audit_policy_enforced!(
    request_id,
    event_hash,
    "destination_allowlist",
    PolicyDecision::Allowed,
    "Destination in allowlist"
);
```

**Estimated Effort**: 8-10 hours
**Benefits**:
- Complete audit trail for security analysis
- Structured logs for parsing and analysis
- Compliance readiness (SOC2, ISO 27001)
- Incident investigation support

---

### 2.3 Optimize Storage Performance

**Current Issues**:
- Volume tracking uses full scan: O(n) where n = total requests
- No batch operations for atomic updates
- No cleanup/archival for old data

**Proposed Improvements**:

#### Step 1: Add Volume Index

```rust
// igra-core/src/storage/rocks.rs

// Add new key prefix for volume tracking
const KEY_PREFIX_VOLUME: &[u8] = b"vol:";

/// Store daily volume aggregate
/// Key format: vol:{YYYY-MM-DD} → VolumeAggregate
#[derive(Serialize, Deserialize)]
struct VolumeAggregate {
    date: String,  // YYYY-MM-DD
    total_sompi: u64,
    request_count: usize,
    last_updated_ns: u64,
}

impl RocksStorage {
    /// Update daily volume (called when request finalized)
    pub fn add_to_daily_volume(
        &self,
        amount_sompi: u64,
        timestamp_ns: u64,
    ) -> Result<()> {
        let date = format_date_from_nanos(timestamp_ns);
        let key = format!("{}:{}", KEY_PREFIX_VOLUME, date);

        // Load existing aggregate or create new
        let mut aggregate = match self.get(&key.as_bytes())? {
            Some(bytes) => bincode::deserialize(&bytes)?,
            None => VolumeAggregate {
                date: date.clone(),
                total_sompi: 0,
                request_count: 0,
                last_updated_ns: timestamp_ns,
            },
        };

        // Update aggregate
        aggregate.total_sompi += amount_sompi;
        aggregate.request_count += 1;
        aggregate.last_updated_ns = timestamp_ns;

        // Save
        let bytes = bincode::serialize(&aggregate)?;
        self.insert(&key.as_bytes(), &bytes)?;

        Ok(())
    }

    /// Get volume for specific date
    pub fn get_volume_for_date(&self, date: &str) -> Result<u64> {
        let key = format!("{}:{}", KEY_PREFIX_VOLUME, date);
        match self.get(&key.as_bytes())? {
            Some(bytes) => {
                let aggregate: VolumeAggregate = bincode::deserialize(&bytes)?;
                Ok(aggregate.total_sompi)
            }
            None => Ok(0),
        }
    }

    /// Get volume since timestamp (optimized)
    pub fn get_volume_since_optimized(&self, since_ns: u64) -> Result<u64> {
        let start_date = format_date_from_nanos(since_ns);
        let now_date = format_date_from_nanos(now_nanos());

        let mut total = 0u64;
        let mut current_date = parse_date(&start_date);

        // Iterate through dates (typically just 1-2 days)
        while format_date(&current_date) <= now_date {
            let date_str = format_date(&current_date);
            total += self.get_volume_for_date(&date_str)?;
            current_date += chrono::Duration::days(1);
        }

        Ok(total)
    }
}

fn format_date_from_nanos(timestamp_ns: u64) -> String {
    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(
        (timestamp_ns / 1_000_000_000) as i64,
        (timestamp_ns % 1_000_000_000) as u32,
    ).unwrap();
    datetime.format("%Y-%m-%d").to_string()
}
```

**Complexity Improvement**: O(n) → O(d) where d = number of days (typically 1-2)

#### Step 2: Add Batch Operations

```rust
// igra-core/src/storage/mod.rs

pub trait Storage: Send + Sync {
    // ... existing methods ...

    /// Begin a batch transaction
    fn begin_batch(&self) -> Result<Box<dyn BatchTransaction + '_>>;
}

/// Batch transaction for atomic multi-record operations
pub trait BatchTransaction {
    /// Insert record in batch
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Delete record in batch
    fn delete(&mut self, key: &[u8]) -> Result<()>;

    /// Commit batch atomically
    fn commit(self: Box<Self>) -> Result<()>;

    /// Rollback batch (implicit on drop)
    fn rollback(self: Box<Self>);
}

// igra-core/src/storage/rocks.rs

impl Storage for RocksStorage {
    fn begin_batch(&self) -> Result<Box<dyn BatchTransaction + '_>> {
        Ok(Box::new(RocksBatch {
            db: &self.db,
            batch: rocksdb::WriteBatch::default(),
        }))
    }
}

struct RocksBatch<'a> {
    db: &'a rocksdb::DB,
    batch: rocksdb::WriteBatch,
}

impl<'a> BatchTransaction for RocksBatch<'a> {
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.batch.put(key, value);
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.batch.delete(key);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<()> {
        self.db.write(self.batch)
            .map_err(|e| ThresholdError::StorageWrite(e.to_string()))?;
        Ok(())
    }

    fn rollback(self: Box<Self>) {
        // Batch is dropped without commit
    }
}
```

**Usage Example**:

```rust
// Atomic update of multiple records
let mut batch = storage.begin_batch()?;

batch.insert(event_key, &event_bytes)?;
batch.insert(request_key, &request_bytes)?;
batch.insert(proposal_key, &proposal_bytes)?;

batch.commit()?; // All or nothing
```

#### Step 3: Add Cleanup Operations

```rust
// igra-core/src/storage/rocks.rs

impl RocksStorage {
    /// Archive old completed requests (> 30 days)
    pub fn archive_old_requests(&self, before_ns: u64) -> Result<usize> {
        let mut archived = 0;
        let mut batch = self.begin_batch()?;

        // Iterate through all requests
        let prefix = KEY_PREFIX_REQUEST;
        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            let (key, value) = item?;
            let request: SigningRequest = bincode::deserialize(&value)?;

            // Check if old and completed
            if let Some(final_tx_id) = request.final_tx_id {
                if request.created_at_ns < before_ns {
                    // Archive to separate key prefix
                    let archive_key = format!("archive:{}", String::from_utf8_lossy(&key));
                    batch.insert(archive_key.as_bytes(), &value)?;
                    batch.delete(&key)?;
                    archived += 1;
                }
            }
        }

        batch.commit()?;
        Ok(archived)
    }

    /// Permanently delete archived requests (> 90 days)
    pub fn delete_old_archives(&self, before_ns: u64) -> Result<usize> {
        let mut deleted = 0;
        let mut batch = self.begin_batch()?;

        let prefix = b"archive:";
        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            let (key, value) = item?;
            let request: SigningRequest = bincode::deserialize(&value)?;

            if request.created_at_ns < before_ns {
                batch.delete(&key)?;
                deleted += 1;
            }
        }

        batch.commit()?;
        Ok(deleted)
    }

    /// Compact database to reclaim space
    pub fn compact(&self) -> Result<()> {
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
        Ok(())
    }
}
```

**Estimated Effort**: 10-12 hours
**Benefits**:
- 100x+ performance improvement for volume tracking
- Atomic multi-record updates prevent inconsistent state
- Reduced storage growth over time
- Better operational hygiene

---

### 2.4 Add Domain Type Wrappers

**Current Issue**: Primitive types used for domain concepts (request_id, peer_id are Strings)

**Proposed: Newtype Pattern**

```rust
// igra-core/src/types.rs (new module)

use serde::{Deserialize, Serialize};
use std::fmt;

/// Request ID (derived from event hash)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    /// Create from event hash
    pub fn from_event_hash(event_hash: &Hash32) -> Self {
        Self(format!("req-{}", hex::encode(event_hash)))
    }

    /// Parse from string with validation
    pub fn from_str(s: &str) -> Result<Self, ThresholdError> {
        if s.starts_with("req-") && s.len() == 68 { // "req-" + 64 hex chars
            Ok(Self(s.to_string()))
        } else {
            Err(ThresholdError::InvalidRequestId(s.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Peer ID for transport layer
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerId(String);

impl PeerId {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Session ID for coordination
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    pub fn from_request_id(request_id: &RequestId) -> Self {
        Self(request_id.0.clone())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Transaction ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(String);

impl TransactionId {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<kaspa_consensus_core::tx::TransactionId> for TransactionId {
    fn from(tx_id: kaspa_consensus_core::tx::TransactionId) -> Self {
        Self(tx_id.to_string())
    }
}
```

**Benefits**:
- Type safety prevents mixing different ID types
- Self-documenting code
- Easier to add validation
- Compiler catches type errors

**Estimated Effort**: 6-8 hours (requires updating many function signatures)

---

## Part 3: Improvements for Auditability

### 3.1 Add State Machine Documentation

Create explicit state machine diagram and validation:

```rust
// igra-core/src/state_machine.rs (new module)

use crate::model::RequestStatus;

/// Valid state transitions
pub const VALID_TRANSITIONS: &[(RequestStatus, RequestStatus)] = &[
    (RequestStatus::Pending, RequestStatus::Approved),
    (RequestStatus::Pending, RequestStatus::Rejected),
    (RequestStatus::Pending, RequestStatus::Expired),
    (RequestStatus::Approved, RequestStatus::Finalized),
    (RequestStatus::Approved, RequestStatus::Expired),
    (RequestStatus::Approved, RequestStatus::Aborted),
];

/// Validate state transition
pub fn validate_transition(
    from: RequestStatus,
    to: RequestStatus,
) -> Result<(), ThresholdError> {
    if from == to {
        return Ok(()); // Same state is always valid
    }

    if VALID_TRANSITIONS.contains(&(from, to)) {
        Ok(())
    } else {
        Err(ThresholdError::InvalidStateTransition {
            from: format!("{:?}", from),
            to: format!("{:?}", to),
        })
    }
}

/// Check if state is terminal
pub fn is_terminal(status: RequestStatus) -> bool {
    matches!(
        status,
        RequestStatus::Finalized
            | RequestStatus::Rejected
            | RequestStatus::Expired
            | RequestStatus::Aborted
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(validate_transition(
            RequestStatus::Pending,
            RequestStatus::Approved
        ).is_ok());

        assert!(validate_transition(
            RequestStatus::Approved,
            RequestStatus::Finalized
        ).is_ok());
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(validate_transition(
            RequestStatus::Finalized,
            RequestStatus::Pending
        ).is_err());

        assert!(validate_transition(
            RequestStatus::Rejected,
            RequestStatus::Approved
        ).is_err());
    }
}
```

**Add diagram to documentation**:

```
docs/architecture/STATE_MACHINE.md:

# Signing Request State Machine

## States

- **Pending**: Request received, waiting for validation
- **Approved**: Request validated by signers, collecting signatures
- **Finalized**: Threshold met, transaction submitted
- **Rejected**: Policy violation or validation failed
- **Expired**: Session timeout reached
- **Aborted**: Manual abort or coordinator failure

## Transitions

```
       ┌─────────┐
       │ Pending │
       └────┬────┘
            │
    ┌───────┼───────┐
    │       │       │
    ▼       ▼       ▼
┌────────┐ ┌──────┐ ┌─────────┐
│Rejected│ │Approved│ │Expired │
└────────┘ └───┬────┘ └─────────┘
               │
       ┌───────┼───────┐
       │       │       │
       ▼       ▼       ▼
┌──────────┐ ┌──────┐ ┌────────┐
│Finalized │ │Aborted│ │Expired │
└──────────┘ └───────┘ └────────┘
```

## Invariants

1. Once in terminal state (Finalized, Rejected, Expired, Aborted), cannot transition
2. Finalized requires threshold signatures collected
3. Rejected requires policy violation or validation failure
4. Expired requires session_timeout elapsed without threshold
```

**Estimated Effort**: 3-4 hours
**Benefits**:
- Clear understanding of system behavior
- Prevents invalid state transitions
- Easier to audit and test
- Self-documenting system

---

### 3.2 Add Request Lifecycle Hooks

Allow auditors to trace complete request lifecycle:

```rust
// igra-core/src/lifecycle.rs (new module)

use crate::model::{SigningEvent, SigningRequest, RequestStatus};

/// Lifecycle event observer
pub trait LifecycleObserver: Send + Sync {
    fn on_event_received(&self, event: &SigningEvent, event_hash: &Hash32);
    fn on_request_created(&self, request: &SigningRequest);
    fn on_status_changed(&self, request_id: &str, old_status: RequestStatus, new_status: RequestStatus);
    fn on_signature_added(&self, request_id: &str, signer_peer_id: &str, input_index: u32);
    fn on_threshold_met(&self, request_id: &str, signature_count: usize, threshold: usize);
    fn on_finalized(&self, request_id: &str, tx_id: &str);
    fn on_failed(&self, request_id: &str, reason: &str);
}

/// Composite observer that notifies multiple observers
pub struct CompositeObserver {
    observers: Vec<Box<dyn LifecycleObserver>>,
}

impl CompositeObserver {
    pub fn new() -> Self {
        Self { observers: vec![] }
    }

    pub fn add_observer(&mut self, observer: Box<dyn LifecycleObserver>) {
        self.observers.push(observer);
    }
}

impl LifecycleObserver for CompositeObserver {
    fn on_event_received(&self, event: &SigningEvent, event_hash: &Hash32) {
        for observer in &self.observers {
            observer.on_event_received(event, event_hash);
        }
    }

    fn on_request_created(&self, request: &SigningRequest) {
        for observer in &self.observers {
            observer.on_request_created(request);
        }
    }

    fn on_status_changed(&self, request_id: &str, old_status: RequestStatus, new_status: RequestStatus) {
        for observer in &self.observers {
            observer.on_status_changed(request_id, old_status, new_status);
        }
    }

    // ... implement other methods similarly
}

/// Audit logging observer
pub struct AuditLoggingObserver;

impl LifecycleObserver for AuditLoggingObserver {
    fn on_event_received(&self, event: &SigningEvent, event_hash: &Hash32) {
        audit_event_received!(event_hash, event);
    }

    fn on_finalized(&self, request_id: &str, tx_id: &str) {
        crate::audit::audit(crate::audit::AuditEvent::TransactionFinalized {
            request_id: request_id.to_string(),
            event_hash: "".to_string(), // Would need to look up
            tx_id: tx_id.to_string(),
            signature_count: 0, // Would need to look up
            threshold_required: 0, // Would need to look up
            timestamp_ns: now_nanos(),
        });
    }

    // ... implement other methods
}
```

**Estimated Effort**: 4-6 hours
**Benefits**:
- Complete visibility into request lifecycle
- Easy to add new observability without modifying core code
- Supports custom audit requirements
- Decouples logging from business logic

---

## Part 4: Implementation Roadmap

### Phase 1: Critical Refactoring (Priority 1) - Week 1

**Day 1-2: Split config.rs**
- Create config/ directory structure
- Extract types, loader, persistence, validation, encryption, env
- Update imports incrementally
- Run tests after each step

**Day 3: Add error codes and context**
- Update ThresholdError with error codes
- Add structured error details
- Update error construction throughout codebase

**Day 4-5: Optimize storage**
- Add volume index
- Implement batch operations
- Add cleanup operations
- Benchmark performance improvements

**Week 1 Deliverables**:
- ✅ config.rs split into 7 focused modules
- ✅ Error codes and structured errors
- ✅ Storage performance improvements
- ✅ All tests passing

### Phase 2: Robustness Improvements (Priority 2) - Week 2

**Day 6-7: Add audit logging**
- Create audit module
- Implement audit events
- Add audit logger implementations
- Integrate into coordination flow

**Day 8: Split binary file**
- Create bin/ modules (cli, setup, modes)
- Extract finalize and audit modes
- Simplify main entry point

**Day 9-10: Add domain types**
- Create types module with newtypes
- Update function signatures
- Update tests

**Week 2 Deliverables**:
- ✅ Comprehensive audit logging
- ✅ Simplified binary structure
- ✅ Type-safe domain types

### Phase 3: Auditability (Priority 3) - Week 3

**Day 11: State machine documentation**
- Add state machine module
- Create validation functions
- Write docs/architecture/STATE_MACHINE.md

**Day 12: Lifecycle hooks**
- Create lifecycle observer pattern
- Implement audit logging observer
- Integrate into coordination

**Day 13-14: Documentation and testing**
- Update all documentation
- Add tests for new modules
- Performance benchmarks

**Week 3 Deliverables**:
- ✅ State machine validation
- ✅ Lifecycle observability
- ✅ Updated documentation

### Phase 4: Polish and Validation (Week 4)

**Day 15-16: Integration testing**
- Test all refactored modules
- Performance regression testing
- Security audit of changes

**Day 17-18: Code review and documentation**
- Internal code review
- Update README and guides
- Create migration guide

**Day 19-20: Release preparation**
- Create release notes
- Version bump
- Tag release

---

## Summary

### Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Largest file | 784 lines | <250 lines | 3x reduction |
| Config complexity | 1 huge file | 7 focused modules | Much clearer |
| Error context | Limited | Rich, structured | Better debugging |
| Volume tracking | O(n) scan | O(d) index | 100x+ faster |
| Audit logging | Minimal | Comprehensive | Production-ready |
| Type safety | Strings | Newtypes | Compiler-enforced |
| State validation | None | Explicit | Prevents bugs |

### Risk Assessment

| Change | Risk Level | Mitigation |
|--------|-----------|------------|
| Config split | Medium | Incremental migration, extensive testing |
| Error codes | Low | Backward compatible additions |
| Storage optimization | Medium | Careful transaction handling, benchmarks |
| Audit logging | Low | Pure additions, no breaking changes |
| Binary split | Low | Clear separation, isolated changes |
| Domain types | Medium | Type system catches errors |

### Total Estimated Effort

- Phase 1 (Critical): 40 hours (1 week)
- Phase 2 (Robustness): 40 hours (1 week)
- Phase 3 (Auditability): 40 hours (1 week)
- Phase 4 (Polish): 40 hours (1 week)

**Total: 160 hours (~4 weeks)**

### Expected Outcomes

1. **Maintainability**: Code is significantly easier to navigate and modify
2. **Robustness**: Better error handling, atomicity, and performance
3. **Auditability**: Complete audit trail with structured logging
4. **Type Safety**: Domain types prevent entire classes of bugs
5. **Documentation**: Clear state machine and lifecycle documentation

### Success Criteria

- ✅ All tests pass
- ✅ No performance regressions (benchmark suite)
- ✅ Code coverage maintained or improved
- ✅ Documentation updated
- ✅ External code review passed
- ✅ Security audit findings addressed

---

**Document Version**: 1.0
**Last Updated**: 2025-12-31
**Status**: Ready for Implementation
**Approver**: [Pending]
