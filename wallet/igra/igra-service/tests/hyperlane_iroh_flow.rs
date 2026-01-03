use igra_core::coordination::hashes::event_hash_without_signature;
use igra_core::error::ThresholdError;
use igra_core::event::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, SigningEvent};
use igra_core::rpc::{UnimplementedRpc, UtxoWithOutpoint};
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
use igra_core::types::{PeerId, RequestId};
use igra_core::validation::CompositeVerifier;
use igra_service::service::coordination::run_coordination_loop;
use igra_service::service::flow::ServiceFlow;
use igra_service::transport::iroh::{IrohConfig, IrohTransport};
use iroh::discovery::static_provider::StaticProvider;
use iroh::RelayMode;
use iroh_gossip::proto::TopicId;
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_wallet_core::prelude::Address;
use secp256k1::{ecdsa::Signature as SecpSignature, Message, PublicKey, Secp256k1, SecretKey};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const KASPA_SOMPI_PER_KAS: u64 = 100_000_000;

fn config_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("igra repo root")
        .to_path_buf()
}

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().expect("env lock")
}

fn load_from_ini_profile(config_path: &Path, profile: &str) -> igra_core::config::AppConfig {
    let _guard = lock_env();
    let data_dir = tempfile::tempdir().expect("temp data dir");

    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let config = igra_core::config::load_app_config_from_profile_path(config_path, profile)
        .expect("load app config");

    env::remove_var("KASPA_DATA_DIR");

    config
}

fn parse_group_id(hex_value: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_value.trim()).expect("group_id hex");
    bytes.as_slice().try_into().expect("group_id 32 bytes")
}

fn group_topic_id(group_id: &[u8; 32], network_id: u8) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kaspa-sign/v1");
    hasher.update(&[network_id]);
    hasher.update(group_id);
    *hasher.finalize().as_bytes()
}

fn build_hyperlane_signature(event: &SigningEvent, keys: &[SecretKey]) -> Vec<u8> {
    let hash = event_hash_without_signature(event).expect("event hash");
    let message = Message::from_digest_slice(&hash).expect("message");
    let secp = Secp256k1::new();
    let mut out = Vec::new();
    for key in keys {
        let sig: SecpSignature = secp.sign_ecdsa(&message, key);
        out.extend_from_slice(&sig.serialize_compact());
    }
    out
}

async fn build_iroh_stack(
    discovery: StaticProvider,
) -> Result<(iroh::Endpoint, iroh_gossip::net::Gossip, iroh::protocol::Router), ThresholdError> {
    let endpoint = iroh::Endpoint::builder()
        .discovery(discovery)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
    let router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(iroh_gossip::net::GOSSIP_ALPN, gossip.clone())
        .spawn();
    Ok((endpoint, gossip, router))
}

async fn connect_endpoint(from: &iroh::Endpoint, to: &iroh::Endpoint, timeout: Duration) {
    let _ = tokio::time::timeout(timeout, from.connect(to.addr(), iroh_gossip::net::GOSSIP_ALPN)).await;
}

async fn join_topic(
    gossip: &iroh_gossip::net::Gossip,
    topic_id: TopicId,
    peers: Vec<iroh::EndpointId>,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, gossip.subscribe_and_join(topic_id, peers)).await.is_ok()
}

#[tokio::test]
async fn hyperlane_request_over_iroh_reaches_finalized_state() {
    env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-test-secret-please-change");

    let root = config_root();
    let signer_config = root.join("artifacts/igra-config.ini");
    let signer_profiles = ["signer-1", "signer-2", "signer-3"];
    let configs = signer_profiles
        .iter()
        .map(|profile| load_from_ini_profile(&signer_config, profile))
        .collect::<Vec<_>>();

    let group_id_hex = configs[0].iroh.group_id.clone().expect("group_id");
    let group_id = parse_group_id(&group_id_hex);

    let discovery = StaticProvider::new();
    let (endpoint_a, gossip_a, _router_a) = match build_iroh_stack(discovery.clone()).await {
        Ok(stack) => stack,
        Err(err) => {
            eprintln!("skipping: iroh bind failed for stack A: {err}");
            env::remove_var("KASPA_IGRA_WALLET_SECRET");
            return;
        }
    };
    let (endpoint_b, gossip_b, _router_b) = match build_iroh_stack(discovery.clone()).await {
        Ok(stack) => stack,
        Err(err) => {
            eprintln!("skipping: iroh bind failed for stack B: {err}");
            env::remove_var("KASPA_IGRA_WALLET_SECRET");
            return;
        }
    };
    let (endpoint_c, gossip_c, _router_c) = match build_iroh_stack(discovery.clone()).await {
        Ok(stack) => stack,
        Err(err) => {
            eprintln!("skipping: iroh bind failed for stack C: {err}");
            env::remove_var("KASPA_IGRA_WALLET_SECRET");
            return;
        }
    };

    discovery.add_endpoint_info(endpoint_a.addr());
    discovery.add_endpoint_info(endpoint_b.addr());
    discovery.add_endpoint_info(endpoint_c.addr());

    let connect_timeout = Duration::from_secs(5);
    connect_endpoint(&endpoint_a, &endpoint_b, connect_timeout).await;
    connect_endpoint(&endpoint_a, &endpoint_c, connect_timeout).await;
    connect_endpoint(&endpoint_b, &endpoint_a, connect_timeout).await;
    connect_endpoint(&endpoint_b, &endpoint_c, connect_timeout).await;
    connect_endpoint(&endpoint_c, &endpoint_a, connect_timeout).await;
    connect_endpoint(&endpoint_c, &endpoint_b, connect_timeout).await;

    let signer_ids = ["signer-1", "signer-2", "signer-3"];
    let signer_seeds = [
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").expect("seed1"),
        hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").expect("seed2"),
        hex::decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f").expect("seed3"),
    ];

    let mut verifier_keys = HashMap::new();
    let mut signers = Vec::new();
    for (id, seed) in signer_ids.iter().zip(signer_seeds.iter()) {
        let seed_bytes: [u8; 32] = seed.as_slice().try_into().expect("seed bytes");
        let peer_id = PeerId::from(*id);
        let signer = Arc::new(Ed25519Signer::from_seed(peer_id.clone(), seed_bytes));
        verifier_keys.insert(peer_id, signer.verifying_key());
        signers.push(signer);
    }

    let verifier = Arc::new(StaticEd25519Verifier::new(verifier_keys));

    let bootstrap_a = vec![endpoint_b.id().to_string(), endpoint_c.id().to_string()];
    let bootstrap_b = vec![endpoint_a.id().to_string(), endpoint_c.id().to_string()];
    let bootstrap_c = vec![endpoint_a.id().to_string(), endpoint_b.id().to_string()];

    let iroh_config_a = IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_a };
    let iroh_config_b = IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_b };
    let iroh_config_c = IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_c };

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let storage_a = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("a")).expect("storage a"));
    let storage_b = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("b")).expect("storage b"));
    let storage_c = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("c")).expect("storage c"));

    let app_a = Arc::new(configs[0].clone());
    let app_b = Arc::new(configs[1].clone());
    let app_c = Arc::new(configs[2].clone());

    let peer_a = app_a.iroh.peer_id.clone().expect("peer a");
    let peer_b = app_b.iroh.peer_id.clone().expect("peer b");
    let peer_c = app_c.iroh.peer_id.clone().expect("peer c");

    let topic_id = TopicId::from(group_topic_id(&group_id, 0));
    let join_timeout = Duration::from_secs(5);
    if !join_topic(&gossip_a, topic_id, vec![endpoint_b.id(), endpoint_c.id()], join_timeout).await
        || !join_topic(&gossip_b, topic_id, vec![endpoint_a.id(), endpoint_c.id()], join_timeout).await
        || !join_topic(&gossip_c, topic_id, vec![endpoint_a.id(), endpoint_b.id()], join_timeout).await
    {
        eprintln!("skipping: iroh group join timed out");
        env::remove_var("KASPA_IGRA_WALLET_SECRET");
        return;
    }

    let transport_a = Arc::new(IrohTransport::new(gossip_a, signers[0].clone(), verifier.clone(), storage_a.clone(), iroh_config_a)
        .expect("transport a"));
    let transport_b = Arc::new(IrohTransport::new(gossip_b, signers[1].clone(), verifier.clone(), storage_b.clone(), iroh_config_b)
        .expect("transport b"));
    let transport_c = Arc::new(IrohTransport::new(gossip_c, signers[2].clone(), verifier.clone(), storage_c.clone(), iroh_config_c)
        .expect("transport c"));

    let rpc = Arc::new(UnimplementedRpc::new());
    let flow_a = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage_a.clone(), transport_a.clone()).expect("flow a"));
    let flow_b = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage_b.clone(), transport_b.clone()).expect("flow b"));
    let flow_c = Arc::new(ServiceFlow::new_with_rpc(rpc.clone(), storage_c.clone(), transport_c.clone()).expect("flow c"));

    let loop_a = tokio::spawn(run_coordination_loop(
        app_a.clone(),
        flow_a.clone(),
        transport_a.clone(),
        storage_a.clone(),
        PeerId::from(peer_a.clone()),
        group_id,
    ));
    let loop_b = tokio::spawn(run_coordination_loop(
        app_b.clone(),
        flow_b.clone(),
        transport_b.clone(),
        storage_b.clone(),
        PeerId::from(peer_b.clone()),
        group_id,
    ));
    let loop_c = tokio::spawn(run_coordination_loop(
        app_c.clone(),
        flow_c.clone(),
        transport_c.clone(),
        storage_c.clone(),
        PeerId::from(peer_c.clone()),
        group_id,
    ));

    let source_address = app_a
        .service
        .pskt
        .source_addresses
        .first()
        .expect("source address")
        .clone();
    let source_address = Address::constructor(&source_address);
    let utxo_amount = 100 * KASPA_SOMPI_PER_KAS;
    let utxo = UtxoWithOutpoint {
        address: Some(source_address.clone()),
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[9u8; 32]), 0),
        entry: UtxoEntry::new(utxo_amount, pay_to_address_script(&source_address), 0, false),
    };
    rpc.push_utxo(utxo);

    let destination = app_a
        .policy
        .allowed_destinations
        .first()
        .cloned()
        .expect("destination");

    let signing_event = SigningEvent {
        event_id: "hyperlane-req-1".to_string(),
        event_source: EventSource::Hyperlane {
            domain: "devnet".to_string(),
            sender: "hyperlane-bridge".to_string(),
        },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: destination.clone(),
        amount_sompi: 50 * KASPA_SOMPI_PER_KAS,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    };

    let validator_keys = [
        SecretKey::from_slice(&[11u8; 32]).expect("validator1"),
        SecretKey::from_slice(&[12u8; 32]).expect("validator2"),
    ];
    let validator_pubkeys = validator_keys
        .iter()
        .map(|key| PublicKey::from_secret_key(&Secp256k1::new(), key))
        .collect::<Vec<_>>();

    let signature = build_hyperlane_signature(&signing_event, &validator_keys);

    let signing_event_wire = SigningEventWire {
        event_id: signing_event.event_id.clone(),
        event_source: signing_event.event_source.clone(),
        derivation_path: signing_event.derivation_path.clone(),
        derivation_index: signing_event.derivation_index,
        destination_address: signing_event.destination_address.clone(),
        amount_sompi: signing_event.amount_sompi,
        metadata: signing_event.metadata.clone(),
        timestamp_nanos: signing_event.timestamp_nanos,
        signature_hex: None,
        signature: Some(signature),
    };

    let event_ctx = EventContext {
        processor: flow_a.clone(),
        config: app_a.service.clone(),
        message_verifier: Arc::new(CompositeVerifier::new(validator_pubkeys, Vec::new())),
        storage: storage_a.clone(),
    };

    let params = SigningEventParams {
        session_id_hex: hex::encode([1u8; 32]),
        request_id: "req-hyperlane-1".to_string(),
        coordinator_peer_id: peer_a.clone(),
        expires_at_nanos: 0,
        signing_event: signing_event_wire,
    };

    tokio::time::sleep(Duration::from_millis(500)).await;
    submit_signing_event(&event_ctx, params).await.expect("submit event");

    let request_id = RequestId::from("req-hyperlane-1");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for finalization");
        }
        if let Ok(Some(request)) = storage_a.get_request(&request_id) {
            if matches!(request.decision, igra_core::model::RequestDecision::Finalized) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert!(!rpc.submitted_transactions().is_empty(), "transaction ready to submit");

    loop_a.abort();
    loop_b.abort();
    loop_c.abort();

    env::remove_var("KASPA_IGRA_WALLET_SECRET");
}
