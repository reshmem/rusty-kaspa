use crate::domain::{FeePaymentMode, GroupConfig, GroupPolicy};
use crate::infrastructure::rpc::CircuitBreakerConfig;
use figment::value::{Dict, Map};
use serde::{Deserialize, Serialize};

/// Type of key material used for signing (per-signer/profile).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// Load a BIP39 mnemonic from the SecretStore and derive the signing key.
    #[default]
    #[serde(alias = "mnemonic")]
    HdMnemonic,
    /// Load a raw secp256k1 private key (32 bytes) from the SecretStore and sign directly.
    #[serde(alias = "raw", alias = "private_key")]
    RawPrivateKey,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HdMnemonic => write!(f, "hd_mnemonic"),
            Self::RawPrivateKey => write!(f, "raw_private_key"),
        }
    }
}

/// Base configuration for the application.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Network mode: mainnet, testnet, devnet.
    ///
    /// Used by `infrastructure::network_mode` validation to prevent configuration drift.
    #[serde(default)]
    pub network: Option<String>,
    /// Active signer profile to load from `[profiles.<name>]`.
    ///
    /// `kaspa-threshold-service` also supports selecting the active profile via CLI `--profile`.
    /// CLI `--profile` takes precedence.
    #[serde(default)]
    pub active_profile: Option<String>,
    /// Allow remote RPC endpoint in mainnet (NOT RECOMMENDED).
    ///
    /// This is only used for security validation; RPC behavior itself is unchanged.
    #[serde(default)]
    pub allow_remote_rpc: bool,
    #[serde(default)]
    pub node_rpc_url: String,
    #[serde(default)]
    pub data_dir: String,
    /// Devnet-only escape hatch: wipe RocksDB if schema version mismatches.
    #[serde(default)]
    pub allow_schema_wipe: bool,
    /// Circuit breaker settings for node RPC calls.
    #[serde(default)]
    pub node_rpc_circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub pskt: PsktBuildConfig,
    #[serde(default)]
    pub hd: Option<PsktHdConfig>,
    /// Use encrypted secrets file (`secrets.bin`) via `FileSecretStore`.
    /// When false, uses `EnvSecretStore` (devnet/CI).
    #[serde(default)]
    pub use_encrypted_secrets: bool,
    /// Optional explicit path to the encrypted secrets file (defaults to `${data_dir}/secrets.bin`).
    #[serde(default)]
    pub secrets_file: Option<String>,
    /// Optional path for key audit log (defaults to `${data_dir}/key-audit.log`).
    #[serde(default)]
    pub key_audit_log_path: Option<String>,

    /// Enable passphrase rotation enforcement for encrypted secrets.
    ///
    /// Defaults by network mode:
    /// - mainnet: enabled
    /// - testnet: enabled
    /// - devnet: disabled
    #[serde(default)]
    pub passphrase_rotation_enabled: Option<bool>,

    /// Warning threshold (days since last rotation).
    ///
    /// Defaults by network mode:
    /// - mainnet: 60
    /// - testnet: 90
    /// - devnet: 0
    #[serde(default)]
    pub passphrase_rotation_warn_days: Option<u64>,

    /// Error threshold (days since last rotation).
    ///
    /// Defaults by network mode:
    /// - mainnet: 90
    /// - testnet: 0 (warn-only)
    /// - devnet: 0
    #[serde(default)]
    pub passphrase_rotation_error_days: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PsktHdConfig {
    /// How this signer derives its private key for PSKT signing.
    ///
    /// Defaults to `hd_mnemonic` (backwards compatible).
    #[serde(default)]
    pub key_type: KeyType,
    #[serde(default)]
    pub xpubs: Vec<String>,
    #[serde(default)]
    pub required_sigs: usize,
    /// Derivation path used to derive per-signer pubkeys for the multisig redeem script.
    /// This is signer policy and must not be provided per-event.
    #[serde(default)]
    pub derivation_path: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PsktBuildConfig {
    #[serde(default)]
    pub node_rpc_url: String,
    #[serde(default)]
    pub source_addresses: Vec<String>,
    #[serde(default)]
    pub redeem_script_hex: String,
    #[serde(default)]
    pub sig_op_count: u8,
    #[serde(default)]
    pub outputs: Vec<PsktOutput>,
    #[serde(default)]
    pub fee_payment_mode: FeePaymentMode,
    #[serde(default)]
    pub fee_sompi: Option<u64>,
    #[serde(default)]
    pub change_address: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PsktOutput {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub amount_sompi: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub service: ServiceConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub signing: SigningConfig,
    #[serde(default)]
    pub rpc: RpcConfig,
    #[serde(default)]
    pub policy: GroupPolicy,
    #[serde(default)]
    pub group: Option<GroupConfig>,
    #[serde(default)]
    pub two_phase: crate::domain::coordination::TwoPhaseConfig,
    #[serde(default)]
    pub hyperlane: HyperlaneConfig,
    #[serde(default)]
    pub layerzero: LayerZeroConfig,
    #[serde(default)]
    pub iroh: IrohRuntimeConfig,

    /// Profile overrides (e.g. `profiles.signer-1.*`) - used by the loader.
    #[serde(default, skip_serializing)]
    pub profiles: Option<Map<String, Dict>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub test_mode: bool,
    #[serde(default)]
    pub test_recipient: Option<String>,
    #[serde(default)]
    pub test_amount_sompi: Option<u64>,
    #[serde(default)]
    pub hd_test_derivation_path: Option<String>,
    #[serde(default)]
    pub session_timeout_seconds: u64,
    #[serde(default)]
    pub session_expiry_seconds: Option<u64>,
    /// How often to run CRDT garbage collection (completed states). `None` uses defaults.
    #[serde(default)]
    pub crdt_gc_interval_seconds: Option<u64>,
    /// How long to retain completed CRDT states. `None` uses defaults.
    #[serde(default)]
    pub crdt_gc_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningConfig {
    #[serde(default = "default_signing_backend")]
    pub backend: String,
}

fn default_signing_backend() -> String {
    "threshold".to_string()
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self { backend: default_signing_backend() }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RpcConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub rate_limit_rps: Option<u32>,
    #[serde(default)]
    pub rate_limit_burst: Option<u32>,
    /// How long `hyperlane.mailbox_process` waits for transaction completion before returning.
    #[serde(default)]
    pub hyperlane_mailbox_wait_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HyperlaneConfig {
    #[serde(default)]
    pub validators: Vec<String>,
    /// Threshold to use when only legacy flat validators are provided (no domain sections).
    #[serde(default)]
    pub threshold: Option<u8>,
    #[serde(default)]
    pub events_dir: Option<String>,
    #[serde(default)]
    pub poll_secs: u64,
    /// Optional per-destination-domain validator sets (preferred for ISM parity).
    #[serde(default)]
    pub domains: Vec<HyperlaneDomainConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HyperlaneDomainConfig {
    /// Destination domain (u32) as understood by Hyperlane ISM.
    pub domain: u32,
    /// secp256k1 ECDSA validator pubkeys (hex).
    #[serde(default)]
    pub validators: Vec<String>,
    /// Required quorum for this domain.
    #[serde(default)]
    pub threshold: u8,
    /// ISM mode for this domain.
    #[serde(default = "default_ism_mode")]
    pub mode: HyperlaneIsmMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HyperlaneIsmMode {
    MessageIdMultisig,
    MerkleRootMultisig,
}

impl Default for HyperlaneIsmMode {
    fn default() -> Self {
        default_ism_mode()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LayerZeroConfig {
    #[serde(default)]
    pub endpoint_pubkeys: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IrohRuntimeConfig {
    #[serde(default)]
    pub peer_id: Option<String>,
    #[serde(default)]
    pub signer_seed_hex: Option<String>,
    #[serde(default)]
    pub verifier_keys: Vec<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub network_id: u8,
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default)]
    pub bootstrap_addrs: Vec<String>,
    #[serde(default)]
    pub bind_port: Option<u16>,
    #[serde(default)]
    pub discovery: IrohDiscoveryConfig,
    #[serde(default)]
    pub relay: IrohRelayConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrohDiscoveryConfig {
    /// Enable pkarr DHT discovery.
    #[serde(default)]
    pub enable_pkarr: bool,
    /// Enable DNS discovery.
    #[serde(default)]
    pub enable_dns: bool,
    /// DNS discovery domain (e.g. "discovery.example.com").
    #[serde(default)]
    pub dns_domain: Option<String>,
}

impl Default for IrohDiscoveryConfig {
    fn default() -> Self {
        Self { enable_pkarr: false, enable_dns: false, dns_domain: None }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IrohRelayConfig {
    /// Enable relay support for NAT traversal.
    #[serde(default)]
    pub enable: bool,
    /// Custom relay URL. If omitted, uses Iroh's default relay map.
    #[serde(default)]
    pub custom_url: Option<String>,
}

impl Default for IrohRelayConfig {
    fn default() -> Self {
        Self { enable: false, custom_url: None }
    }
}

pub fn default_ism_mode() -> HyperlaneIsmMode {
    HyperlaneIsmMode::MessageIdMultisig
}
