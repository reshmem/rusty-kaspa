use crate::domain::{FeePaymentMode, GroupConfig, GroupPolicy};
use figment::value::{Dict, Map};
use kaspa_wallet_core::encryption::Encryptable;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use serde::{Deserialize, Serialize};

/// Base configuration for the application.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default)]
    pub node_rpc_url: String,
    #[serde(default)]
    pub data_dir: String,
    #[serde(default)]
    pub pskt: PsktBuildConfig,
    #[serde(default)]
    pub hd: Option<PsktHdConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PsktHdConfig {
    #[serde(default, skip_serializing)]
    pub mnemonics: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_mnemonics: Option<Encryptable<Vec<PrvKeyData>>>,
    #[serde(default)]
    pub xpubs: Vec<String>,
    #[serde(default)]
    pub required_sigs: usize,
    #[serde(default)]
    pub passphrase: Option<String>,
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
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SigningConfig {
    #[serde(default)]
    pub backend: String,
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
    pub default_derivation_path: Option<String>,
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
}

pub fn default_ism_mode() -> HyperlaneIsmMode {
    HyperlaneIsmMode::MessageIdMultisig
}
