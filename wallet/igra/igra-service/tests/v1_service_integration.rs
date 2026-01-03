use igra_core::config::{PsktBuildConfig, PsktOutput, ServiceConfig};
use igra_core::event::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::hd::derivation_path_from_index;
use igra_core::model::EventSource;
use igra_core::storage::rocks::RocksStorage;
use igra_core::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
use igra_core::types::PeerId;
use igra_core::validation::NoopVerifier;
use igra_service::service::flow::ServiceFlow;
use igra_service::api::json_rpc::RpcState;
use igra_service::service::metrics::Metrics;
use igra_service::transport::iroh::IrohConfig;
use iroh::RelayMode;
use iroh::discovery::static_provider::StaticProvider;
use std::collections::BTreeMap;
use std::sync::Arc;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn decode_hash32(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value.trim()).expect("hex decode");
    let array: [u8; 32] = bytes.as_slice().try_into().expect("32-byte hash");
    array
}

#[tokio::test]
async fn v1_service_signing_event_builds_pskt() {
    let node_url = env("KASPA_NODE_URL").unwrap_or_else(|| "grpc://127.0.0.1:16110".to_string());
    let source_addresses = env("KASPA_SOURCE_ADDRESSES").unwrap_or_default();
    let redeem_script_hex = env("KASPA_REDEEM_SCRIPT_HEX").unwrap_or_default();
    let recipient = env("KASPA_RECIPIENT_ADDRESS").unwrap_or_default();
    let amount_sompi = env("KASPA_RECIPIENT_AMOUNT").and_then(|v| v.parse().ok()).unwrap_or(0);
    let derivation_index = env("KASPA_SIGNING_DERIVATION_INDEX")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if source_addresses.is_empty() || redeem_script_hex.is_empty() || recipient.is_empty() || amount_sompi == 0 {
        eprintln!("set KASPA_SOURCE_ADDRESSES,KASPA_REDEEM_SCRIPT_HEX,KASPA_RECIPIENT_ADDRESS,KASPA_RECIPIENT_AMOUNT to run");
        return;
    }

    let source_addresses = source_addresses
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>();

    let config = ServiceConfig {
        node_rpc_url: node_url.clone(),
        data_dir: String::new(),
        pskt: PsktBuildConfig {
            node_rpc_url: node_url,
            source_addresses,
            redeem_script_hex,
            sig_op_count: 2,
            outputs: vec![PsktOutput { address: recipient.clone(), amount_sompi }],
            fee_payment_mode: igra_core::model::FeePaymentMode::RecipientPays,
            fee_sompi: None,
            change_address: None,
        },
        hd: None,
    };

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("rocksdb open"));
    let discovery = StaticProvider::new();
    let endpoint = iroh::Endpoint::builder()
        .discovery(discovery)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("endpoint");
    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
    let _router = iroh::protocol::Router::builder(endpoint)
        .accept(iroh_gossip::net::GOSSIP_ALPN, gossip.clone())
        .spawn();

    let signer = Arc::new(Ed25519Signer::from_seed(PeerId::from("coordinator-test"), [1u8; 32]));
    let mut keys = std::collections::HashMap::new();
    keys.insert(PeerId::from("coordinator-test"), signer.verifying_key());
    let verifier = Arc::new(StaticEd25519Verifier::new(keys));
    let iroh_config = IrohConfig {
        network_id: 0,
        group_id: [9u8; 32],
        bootstrap_nodes: Vec::new(),
    };

    let flow = Arc::new(
        ServiceFlow::new_with_iroh(&config, storage.clone(), gossip, signer, verifier, iroh_config)
            .await
            .expect("service flow"),
    );

    let event_ctx = EventContext {
        processor: flow.clone(),
        config: config.clone(),
        message_verifier: Arc::new(NoopVerifier),
        storage: storage.clone(),
    };
    let metrics = Arc::new(Metrics::new().expect("metrics"));
    let state = RpcState {
        event_ctx,
        rpc_token: None,
        node_rpc_url: config.node_rpc_url.clone(),
        metrics,
        hyperlane_ism: None,
        group_id_hex: None,
        coordinator_peer_id: "test-peer".to_string(),
    };

    let session_id_hex = hex::encode([7u8; 32]);
    let signing_event = SigningEventWire {
        event_id: "event-001".to_string(),
        event_source: EventSource::Api { issuer: "integration-test".to_string() },
        derivation_path: derivation_path_from_index(derivation_index),
        derivation_index: Some(derivation_index),
        destination_address: recipient,
        amount_sompi,
        metadata: BTreeMap::new(),
        timestamp_nanos: 0,
        signature_hex: None,
        signature: None,
    };

    let params = SigningEventParams {
        session_id_hex,
        request_id: "request-001".to_string(),
        coordinator_peer_id: "coordinator-test".to_string(),
        expires_at_nanos: 0,
        signing_event,
    };

    let result = submit_signing_event(&state.event_ctx, params).await.expect("submit signing event");
    let event_hash = decode_hash32(&result.event_hash_hex);
    let stored = flow.storage().get_event(&event_hash).expect("storage get event");
    let stored = stored.expect("stored event");

    assert_eq!(stored.derivation_index, Some(derivation_index));
    assert_eq!(stored.derivation_path, derivation_path_from_index(derivation_index));
}
