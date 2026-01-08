#![allow(dead_code, unused_imports, unused_variables, unused_mut, unused_constants)]

use crate::integration_harness::test_keys::TestKeyGenerator;
use igra_core::config::{AppConfig, PsktBuildConfig, PsktOutput, ServiceConfig};
use igra_core::model::{EventSource, GroupPolicy, SigningEvent};
use igra_core::rpc::UtxoWithOutpoint;
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const SOMPI_PER_KAS: u64 = 100_000_000;

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().expect("env lock")
}

pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    lock_env()
}

pub fn config_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("igra repo root").to_path_buf()
}

pub fn load_app_config_from_path(path: &Path) -> igra_core::config::AppConfig {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");

    env::set_var("KASPA_CONFIG_PATH", path);
    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let config = igra_core::config::load_app_config().expect("load app config");

    env::remove_var("KASPA_CONFIG_PATH");
    env::remove_var("KASPA_DATA_DIR");

    config
}

pub fn load_app_config_from_profile(path: &Path, profile: &str) -> igra_core::config::AppConfig {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");

    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let config = igra_core::config::load_app_config_from_profile_path(path, profile).expect("load app config");

    env::remove_var("KASPA_DATA_DIR");

    config
}

pub fn signing_event_for(destination_address: String, amount_sompi: u64, source: EventSource) -> SigningEvent {
    SigningEvent {
        event_id: "event-1".to_string(),
        event_source: source,
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address,
        amount_sompi,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

pub struct TestDataFactory;

impl TestDataFactory {
    pub fn create_hyperlane_event(recipient: String, amount: u64, nonce: u64, timestamp_nanos: u64) -> SigningEvent {
        let mut metadata = BTreeMap::new();
        metadata.insert("nonce".to_string(), nonce.to_string());
        SigningEvent {
            event_id: format!("hyperlane-{nonce}"),
            event_source: EventSource::Hyperlane { domain: "devnet".to_string(), sender: "hyperlane-bridge".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: recipient,
            amount_sompi: amount,
            metadata,
            timestamp_nanos,
            signature: None,
        }
    }

    pub fn create_utxo_set(address: &Address, count: usize, amount_per_utxo: u64) -> Vec<UtxoWithOutpoint> {
        (0..count)
            .map(|idx| {
                let hash = blake3::hash(format!("utxo-{idx}").as_bytes());
                UtxoWithOutpoint {
                    address: Some(address.clone()),
                    outpoint: TransactionOutpoint::new(TransactionId::from_slice(hash.as_bytes()), idx as u32),
                    entry: UtxoEntry::new(amount_per_utxo, pay_to_address_script(address), 0, false),
                }
            })
            .collect()
    }

    pub fn create_config_2of3(data_dir: &Path) -> AppConfig {
        Self::create_config_m_of_n(data_dir, 2, 3)
    }

    pub fn create_config_m_of_n(data_dir: &Path, threshold_m: usize, threshold_n: usize) -> AppConfig {
        let keygen = TestKeyGenerator::new("test-config");
        let source_address = keygen.generate_kaspa_address(0, Prefix::Devnet).to_string();
        let change_address = keygen.generate_kaspa_address(1, Prefix::Devnet).to_string();
        let redeem_script = keygen.generate_redeem_script(threshold_m, threshold_n);

        let pskt = PsktBuildConfig {
            node_rpc_url: String::new(),
            source_addresses: vec![source_address.clone()],
            redeem_script_hex: hex::encode(redeem_script),
            sig_op_count: threshold_m as u8,
            outputs: vec![PsktOutput { address: source_address, amount_sompi: 1_000_000 }],
            fee_payment_mode: igra_core::model::FeePaymentMode::RecipientPays,
            fee_sompi: Some(0),
            change_address: Some(change_address),
        };

        AppConfig {
            service: ServiceConfig { node_rpc_url: String::new(), data_dir: data_dir.to_string_lossy().to_string(), pskt, hd: None },
            runtime: igra_core::config::RuntimeConfig::default(),
            signing: igra_core::config::SigningConfig { backend: "threshold".to_string() },
            rpc: igra_core::config::RpcConfig::default(),
            policy: GroupPolicy::default(),
            group: None,
            hyperlane: igra_core::config::HyperlaneConfig::default(),
            layerzero: igra_core::config::LayerZeroConfig::default(),
            iroh: igra_core::config::IrohRuntimeConfig::default(),
        }
    }

    pub fn create_policy_restrictive(allowed_destinations: Vec<String>) -> GroupPolicy {
        GroupPolicy {
            allowed_destinations,
            min_amount_sompi: Some(1_000_000),
            max_amount_sompi: Some(1_000_000_000),
            max_daily_volume_sompi: Some(10_000_000_000),
            require_reason: true,
        }
    }
}
