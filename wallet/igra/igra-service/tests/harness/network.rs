#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

use super::mocks::MockKaspaNode;
use igra_core::foundation::ThresholdError;
use igra_core::foundation::{PeerId, RequestId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::iroh::mock::{MockHub, MockTransport};
use igra_service::service::flow::ServiceFlow;
use iroh::discovery::static_provider::StaticProvider;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

pub struct TestIrohNetwork {
    pub endpoints: Vec<Endpoint>,
    pub gossips: Vec<Gossip>,
    _routers: Vec<Router>,
}

impl TestIrohNetwork {
    pub async fn new(count: usize) -> Result<Self, ThresholdError> {
        let discovery = StaticProvider::new();
        let mut endpoints = Vec::with_capacity(count);
        let mut gossips = Vec::with_capacity(count);
        let mut routers = Vec::with_capacity(count);

        for _ in 0..count {
            let endpoint = Endpoint::builder()
                .discovery(discovery.clone())
                .relay_mode(iroh::RelayMode::Disabled)
                .bind()
                .await
                .map_err(|err| ThresholdError::Message(err.to_string()))?;
            let gossip = Gossip::builder().spawn(endpoint.clone());
            let router =
                iroh::protocol::Router::builder(endpoint.clone()).accept(iroh_gossip::net::GOSSIP_ALPN, gossip.clone()).spawn();
            discovery.add_endpoint_info(endpoint.addr());
            endpoints.push(endpoint);
            gossips.push(gossip);
            routers.push(router);
        }

        Ok(Self { endpoints, gossips, _routers: routers })
    }

    pub async fn connect_all(&self, timeout: Duration) {
        for from in &self.endpoints {
            for to in &self.endpoints {
                if from.id() == to.id() {
                    continue;
                }
                let _ = tokio::time::timeout(timeout, from.connect(to.addr(), iroh_gossip::net::GOSSIP_ALPN)).await;
            }
        }
    }

    pub async fn join_group(&self, topic_id: TopicId, timeout: Duration) -> bool {
        for (idx, gossip) in self.gossips.iter().enumerate() {
            let peers = self
                .endpoints
                .iter()
                .enumerate()
                .filter(|(peer_idx, _)| *peer_idx != idx)
                .map(|(_, endpoint)| endpoint.id())
                .collect::<Vec<_>>();
            let joined = tokio::time::timeout(timeout, gossip.subscribe_and_join(topic_id, peers)).await;
            if joined.is_err() {
                return false;
            }
        }
        true
    }
}

pub struct TestNode {
    pub peer_id: PeerId,
    pub storage: Arc<RocksStorage>,
    pub transport: Arc<MockTransport>,
    pub flow: Arc<ServiceFlow>,
    pub config: Arc<igra_core::infrastructure::config::AppConfig>,
    pub is_connected: bool,
}

pub struct TestNetwork {
    pub nodes: Vec<TestNode>,
    pub rpc: Arc<MockKaspaNode>,
    pub hub: Arc<MockHub>,
    pub threshold_m: usize,
    pub threshold_n: usize,
    pub group_id: [u8; 32],
    _temp_dir: TempDir,
}

impl TestNetwork {
    pub fn new(threshold_m: usize, threshold_n: usize) -> Result<Self, ThresholdError> {
        let hub = Arc::new(MockHub::new());
        let rpc = Arc::new(MockKaspaNode::new());
        let seed = format!("test-network-{threshold_m}-{threshold_n}");
        let group_id = *blake3::hash(seed.as_bytes()).as_bytes();
        let temp_dir = TempDir::new().map_err(|err| ThresholdError::Message(err.to_string()))?;

        let mut nodes = Vec::with_capacity(threshold_n);
        for idx in 0..threshold_n {
            let peer_id = PeerId::from(format!("signer-{}", idx + 1));
            let storage = Arc::new(
                RocksStorage::open_in_dir(temp_dir.path().join(peer_id.as_str()))
                    .map_err(|err| ThresholdError::Message(err.to_string()))?,
            );
            let transport = Arc::new(MockTransport::new(hub.clone(), peer_id.clone(), group_id, 0));
            let flow = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage.clone(), transport.clone())?);
            let config = Arc::new(TestDataFactory::create_config_m_of_n(temp_dir.path(), threshold_m, threshold_n));
            nodes.push(TestNode { peer_id, storage, transport, flow, config, is_connected: true });
        }

        Ok(Self { nodes, rpc, hub, threshold_m, threshold_n, group_id, _temp_dir: temp_dir })
    }

    pub async fn wait_for_proposal(&self, request_id: &str, timeout: Duration) -> Result<(), ThresholdError> {
        let deadline = std::time::Instant::now() + timeout;
        let request_id = RequestId::from(request_id);
        loop {
            let mut all_have = true;
            for node in &self.nodes {
                if node.storage.get_proposal(&request_id)?.is_none() {
                    all_have = false;
                    break;
                }
            }
            if all_have {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                return Err(ThresholdError::Message("timeout waiting for proposal".to_string()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn wait_for_threshold(&self, request_id: &str, timeout: Duration) -> Result<(), ThresholdError> {
        let deadline = std::time::Instant::now() + timeout;
        let request_id = RequestId::from(request_id);
        loop {
            let sigs = self.nodes[0].storage.list_partial_sigs(&request_id)?;
            if sigs.len() >= self.threshold_m {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                return Err(ThresholdError::Message(format!(
                    "timeout waiting for threshold (have {} of {})",
                    sigs.len(),
                    self.threshold_m
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn wait_for_finalization(&self, request_id: &str, timeout: Duration) -> Result<(), ThresholdError> {
        let deadline = std::time::Instant::now() + timeout;
        let request_id = RequestId::from(request_id);
        loop {
            if let Some(req) = self.nodes[0].storage.get_request(&request_id)? {
                if req.final_tx_id.is_some() {
                    return Ok(());
                }
            }
            if std::time::Instant::now() > deadline {
                return Err(ThresholdError::Message("timeout waiting for finalization".to_string()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_txscript::standard::multisig_redeem_script;
use secp256k1::{Keypair, Secp256k1};
use sha3::{Digest, Keccak256};

pub const SIGNER_MNEMONICS: [&str; 3] = [
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
];

pub const IROH_PEERS: [&str; 3] = ["signer-1", "signer-2", "signer-3"];

pub const IROH_SEED_HEX: [&str; 3] = [
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
];

pub struct TestKeyGenerator {
    seed: [u8; 32],
}

impl TestKeyGenerator {
    pub fn new(seed: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        Self { seed: *hash.as_bytes() }
    }

    pub fn generate_kaspa_keypair(&self, index: u32) -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        let mut input = self.seed.to_vec();
        input.extend_from_slice(&index.to_le_bytes());
        let mut hasher = blake3::Hasher::new();
        hasher.update(&input);
        let key_bytes = hasher.finalize();

        let secret = secp256k1::SecretKey::from_slice(key_bytes.as_bytes()).expect("secret key");
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        (secret, public)
    }

    pub fn generate_kaspa_keypair_full(&self, index: u32) -> Keypair {
        let secp = Secp256k1::new();
        let (secret, _) = self.generate_kaspa_keypair(index);
        Keypair::from_secret_key(&secp, &secret)
    }

    pub fn generate_kaspa_address(&self, index: u32, network: Prefix) -> Address {
        let (_, pubkey) = self.generate_kaspa_keypair(index);
        let (xonly, _) = pubkey.x_only_public_key();
        Address::new(network, Version::PubKey, &xonly.serialize())
    }

    pub fn generate_validator_keypair(&self, index: u32) -> (secp256k1::SecretKey, String) {
        let (secret, pubkey) = self.generate_kaspa_keypair(1000 + index);
        let pubkey_bytes = &pubkey.serialize_uncompressed()[1..];
        let mut hasher = Keccak256::new();
        hasher.update(pubkey_bytes);
        let hash = hasher.finalize();
        let eth_address = format!("0x{}", hex::encode(&hash[12..]));
        (secret, eth_address)
    }

    pub fn generate_redeem_script(&self, m: usize, n: usize) -> Vec<u8> {
        let mut pubkeys = Vec::with_capacity(n);
        for idx in 0..n {
            let (_, pubkey) = self.generate_kaspa_keypair(idx as u32);
            let (xonly, _) = pubkey.x_only_public_key();
            pubkeys.push(xonly.serialize());
        }
        multisig_redeem_script(pubkeys.iter(), m).expect("redeem script")
    }
}

use std::env;
use std::path::{Path, PathBuf};

use igra_core::domain::{EventSource, GroupPolicy, SigningEvent};
use igra_core::infrastructure::config::{AppConfig, PsktBuildConfig, PsktOutput, ServiceConfig, SigningConfig};
use igra_core::infrastructure::rpc::UtxoWithOutpoint;
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use std::collections::BTreeMap;

pub const SOMPI_PER_KAS: u64 = 100_000_000;

pub fn config_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("igra repo root").to_path_buf()
}

pub fn load_app_config_from_profile(path: &Path, profile: &str) -> AppConfig {
    let data_dir = tempfile::tempdir().expect("temp data dir");
    let _data_dir_env = super::cleanup::ScopedEnvVar::set("KASPA_DATA_DIR", data_dir.path());
    let _wallet_secret_env = super::cleanup::ScopedEnvVar::set("KASPA_IGRA_WALLET_SECRET", "test-secret");
    igra_core::infrastructure::config::load_app_config_from_profile_path(path, profile).expect("load app config")
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
            fee_payment_mode: igra_core::domain::FeePaymentMode::RecipientPays,
            fee_sompi: Some(0),
            change_address: Some(change_address),
        };

        AppConfig {
            service: ServiceConfig { node_rpc_url: String::new(), data_dir: data_dir.to_string_lossy().to_string(), pskt, hd: None },
            runtime: Default::default(),
            signing: SigningConfig { backend: "threshold".to_string() },
            rpc: Default::default(),
            policy: GroupPolicy::default(),
            group: None,
            hyperlane: Default::default(),
            layerzero: Default::default(),
            iroh: Default::default(),
            profiles: None,
        }
    }
}
