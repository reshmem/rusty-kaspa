use crate::model::{GroupConfig, GroupPolicy};
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
    pub fee_payment_mode: crate::model::FeePaymentMode,
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
}

pub fn default_ism_mode() -> HyperlaneIsmMode {
    HyperlaneIsmMode::MessageIdMultisig
}

impl AppConfig {
    /// Merge fields from `other`, overriding only when `other` provides a non-empty value.
    pub fn merge_from(&mut self, other: &AppConfig) {
        self.service.merge_from(&other.service);
        self.runtime.merge_from(&other.runtime);
        self.signing.merge_from(&other.signing);
        self.rpc.merge_from(&other.rpc);
        if other.policy != GroupPolicy::default() {
            self.policy = other.policy.clone();
        }
        if let Some(ref grp) = other.group {
            self.group = Some(grp.clone());
        }
        self.hyperlane.merge_from(&other.hyperlane);
        self.layerzero.merge_from(&other.layerzero);
        self.iroh.merge_from(&other.iroh);
    }
}

impl ServiceConfig {
    fn merge_from(&mut self, other: &ServiceConfig) {
        if !other.node_rpc_url.trim().is_empty() {
            self.node_rpc_url = other.node_rpc_url.clone();
        }
        if !other.data_dir.trim().is_empty() {
            self.data_dir = other.data_dir.clone();
        }
        self.pskt.merge_from(&other.pskt);
        match (&mut self.hd, &other.hd) {
            (Some(existing), Some(incoming)) => existing.merge_from(incoming),
            (slot @ None, Some(incoming)) => *slot = Some(incoming.clone()),
            _ => {}
        }
    }
}

impl PsktHdConfig {
    fn merge_from(&mut self, other: &PsktHdConfig) {
        if let Some(ref enc) = other.encrypted_mnemonics {
            self.encrypted_mnemonics = Some(enc.clone());
        }
        if !other.xpubs.is_empty() {
            self.xpubs = other.xpubs.clone();
        }
        if other.required_sigs != 0 {
            self.required_sigs = other.required_sigs;
        }
        if let Some(ref pass) = other.passphrase {
            self.passphrase = Some(pass.clone());
        }
    }
}

impl PsktBuildConfig {
    fn merge_from(&mut self, other: &PsktBuildConfig) {
        if !other.node_rpc_url.trim().is_empty() {
            self.node_rpc_url = other.node_rpc_url.clone();
        }
        if !other.source_addresses.is_empty() {
            self.source_addresses = other.source_addresses.clone();
        }
        if !other.redeem_script_hex.trim().is_empty() {
            self.redeem_script_hex = other.redeem_script_hex.clone();
        }
        if other.sig_op_count != 0 {
            self.sig_op_count = other.sig_op_count;
        }
        if !other.outputs.is_empty() {
            self.outputs = other.outputs.clone();
        }
        self.fee_payment_mode = other.fee_payment_mode.clone();
        if other.fee_sompi.is_some() {
            self.fee_sompi = other.fee_sompi;
        }
        if let Some(ref change) = other.change_address {
            self.change_address = Some(change.clone());
        }
    }
}

impl RuntimeConfig {
    fn merge_from(&mut self, other: &RuntimeConfig) {
        if other.test_mode {
            self.test_mode = true;
        }
        if other.test_recipient.is_some() {
            self.test_recipient = other.test_recipient.clone();
        }
        if other.test_amount_sompi.is_some() {
            self.test_amount_sompi = other.test_amount_sompi;
        }
        if other.hd_test_derivation_path.is_some() {
            self.hd_test_derivation_path = other.hd_test_derivation_path.clone();
        }
        if other.session_timeout_seconds != 0 {
            self.session_timeout_seconds = other.session_timeout_seconds;
        }
    }
}

impl SigningConfig {
    fn merge_from(&mut self, other: &SigningConfig) {
        if !other.backend.trim().is_empty() {
            self.backend = other.backend.clone();
        }
    }
}

impl RpcConfig {
    fn merge_from(&mut self, other: &RpcConfig) {
        if !other.addr.trim().is_empty() {
            self.addr = other.addr.clone();
        }
        if other.token.is_some() {
            self.token = other.token.clone();
        }
        self.enabled = other.enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_overrides_non_empty() {
        let mut base = AppConfig::default();
        base.service.node_rpc_url = "base".into();
        base.runtime.session_timeout_seconds = 10;
        let mut incoming = AppConfig::default();
        incoming.service.node_rpc_url = "new".into();
        incoming.runtime.session_timeout_seconds = 20;

        base.merge_from(&incoming);
        assert_eq!(base.service.node_rpc_url, "new");
        assert_eq!(base.runtime.session_timeout_seconds, 20);
    }

    #[test]
    fn merge_keeps_base_when_incoming_empty() {
        let mut base = AppConfig::default();
        base.service.node_rpc_url = "base".into();
        let incoming = AppConfig::default();
        base.merge_from(&incoming);
        assert_eq!(base.service.node_rpc_url, "base");
    }
}

impl HyperlaneConfig {
    fn merge_from(&mut self, other: &HyperlaneConfig) {
        if !other.validators.is_empty() {
            self.validators = other.validators.clone();
        }
        if other.threshold.is_some() {
            self.threshold = other.threshold;
        }
        if other.events_dir.is_some() {
            self.events_dir = other.events_dir.clone();
        }
        if other.poll_secs != 0 {
            self.poll_secs = other.poll_secs;
        }
        if !other.domains.is_empty() {
            self.domains = other.domains.clone();
        }
    }
}

impl LayerZeroConfig {
    fn merge_from(&mut self, other: &LayerZeroConfig) {
        if !other.endpoint_pubkeys.is_empty() {
            self.endpoint_pubkeys = other.endpoint_pubkeys.clone();
        }
    }
}

impl IrohRuntimeConfig {
    fn merge_from(&mut self, other: &IrohRuntimeConfig) {
        if other.peer_id.is_some() {
            self.peer_id = other.peer_id.clone();
        }
        if other.signer_seed_hex.is_some() {
            self.signer_seed_hex = other.signer_seed_hex.clone();
        }
        if !other.verifier_keys.is_empty() {
            self.verifier_keys = other.verifier_keys.clone();
        }
        if other.group_id.is_some() {
            self.group_id = other.group_id.clone();
        }
        if other.network_id != 0 {
            self.network_id = other.network_id;
        }
        if !other.bootstrap.is_empty() {
            self.bootstrap = other.bootstrap.clone();
        }
        if !other.bootstrap_addrs.is_empty() {
            self.bootstrap_addrs = other.bootstrap_addrs.clone();
        }
        if other.bind_port.is_some() {
            self.bind_port = other.bind_port;
        }
    }
}
