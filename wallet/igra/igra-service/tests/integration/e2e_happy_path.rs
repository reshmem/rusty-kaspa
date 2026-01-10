//! End-to-end happy path scenarios.

use crate::harness::{
    assert_request_finalized, config_root, load_app_config_from_profile, signing_event_for, MockHyperlaneValidator, MockKaspaNode,
    TestIrohNetwork, TestKeyGenerator, IROH_PEERS, IROH_SEED_HEX, SIGNER_MNEMONICS, SOMPI_PER_KAS,
};
use igra_core::application::{submit_signing_event, Coordinator, EventContext, SigningEventParams, SigningEventWire};
use igra_core::domain::pskt::multisig::{
    apply_partial_sigs, build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput,
};
use igra_core::domain::signing::threshold::ThresholdSigner;
use igra_core::domain::signing::SignerBackend;
use igra_core::domain::validation::CompositeVerifier;
use igra_core::domain::{EventSource, PartialSigRecord, RequestDecision, SigningEvent};
use igra_core::foundation::{PeerId, RequestId, SessionId, SigningKeypair, TransactionId as RequestTransactionId};
use igra_core::infrastructure::rpc::{NodeRpc, UnimplementedRpc, UtxoWithOutpoint};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use igra_core::infrastructure::transport::Transport;
use igra_service::service::coordination::run_coordination_loop;
use igra_service::service::flow::ServiceFlow;
use igra_service::transport::iroh::{IrohConfig, IrohTransport};
use kaspa_bip32::Prefix;
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::standard::{multisig_redeem_script, pay_to_script_hash_script};
use kaspa_wallet_core::account::variants::multisig::MULTISIG_ACCOUNT_KIND;
use kaspa_wallet_core::derivation::create_xpub_from_mnemonic;
use kaspa_wallet_core::prelude::{AccountKind, Address};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;
use tempfile::TempDir;

fn ensure_wallet_secret() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-test-secret-please-change");
    });
}

fn group_topic_id(group_id: &[u8; 32], network_id: u8) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kaspa-sign/v1");
    hasher.update(&[network_id]);
    hasher.update(group_id);
    *hasher.finalize().as_bytes()
}

fn parse_group_id(hex_value: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_value.trim()).expect("group_id hex");
    bytes.as_slice().try_into().expect("group_id 32 bytes")
}

fn build_event(event_id: &str, amount_sompi: u64, destination: &str) -> SigningEvent {
    SigningEvent {
        event_id: event_id.to_string(),
        event_source: EventSource::Api { issuer: "integration-tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: destination.to_string(),
        amount_sompi,
        metadata: std::collections::BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

fn build_pskt_bundle(keygen: &TestKeyGenerator, m: usize, n: usize, amount_sompi: u64) -> PsktBundle {
    let mut keypairs = Vec::with_capacity(n);
    let mut pubkeys = Vec::with_capacity(n);
    let mut xonly = Vec::with_capacity(n);

    for idx in 0..n {
        let kp = keygen.generate_kaspa_keypair_full(idx as u32);
        let (x, _) = kp.public_key().x_only_public_key();
        xonly.push(x.serialize());
        pubkeys.push(kp.public_key());
        keypairs.push(SigningKeypair::from_keypair(&kp));
    }

    let redeem_script = multisig_redeem_script(xonly.iter(), m).expect("redeem");
    let spk = pay_to_script_hash_script(&redeem_script);
    let input = MultisigInput {
        utxo_entry: UtxoEntry::new(amount_sompi + 1_000_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[11u8; 32]), 0),
        redeem_script,
        sig_op_count: m as u8,
    };
    let destination = Address::constructor("kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3");
    let output = MultisigOutput { amount: amount_sompi, script_public_key: pay_to_address_script(&destination) };

    let pskt = build_pskt(&[input], &[output]).expect("pskt");
    let pskt_blob = serialize_pskt(&pskt.pskt).expect("serialize");
    let signer_pskt = pskt.pskt.signer();
    let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input = input_hashes(&signer_pskt).expect("input hashes");
    PsktBundle { keypairs, pubkeys, pskt_blob, tx_hash, per_input }
}

struct PsktBundle {
    keypairs: Vec<SigningKeypair>,
    pubkeys: Vec<secp256k1::PublicKey>,
    pskt_blob: Vec<u8>,
    tx_hash: [u8; 32],
    per_input: Vec<[u8; 32]>,
}

mod legacy_rpc_integration_env {
    use igra_core::infrastructure::config::{PsktBuildConfig, PsktOutput};
    use igra_core::infrastructure::rpc::GrpcNodeRpc;
    use igra_service::service::build_pskt_with_client;

    fn env(key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.trim().is_empty())
    }

    #[tokio::test]
    async fn test_rpc_utxo_flow_when_env_configured_then_builds_pskt() {
        let node_url = env("KASPA_NODE_URL").unwrap_or_else(|| "grpc://127.0.0.1:16110".to_string());
        let source_addresses = env("KASPA_SOURCE_ADDRESSES").unwrap_or_default();
        let redeem_script_hex = env("KASPA_REDEEM_SCRIPT_HEX").unwrap_or_default();
        let recipient = env("KASPA_RECIPIENT_ADDRESS").unwrap_or_default();
        let amount_sompi = env("KASPA_RECIPIENT_AMOUNT").and_then(|v| v.parse().ok()).unwrap_or(0);

        if source_addresses.is_empty() || redeem_script_hex.is_empty() || recipient.is_empty() || amount_sompi == 0 {
            eprintln!("set KASPA_SOURCE_ADDRESSES,KASPA_REDEEM_SCRIPT_HEX,KASPA_RECIPIENT_ADDRESS,KASPA_RECIPIENT_AMOUNT to run");
            return;
        }

        let rpc = GrpcNodeRpc::connect(node_url.clone()).await.expect("grpc connect");

        let config = PsktBuildConfig {
            node_rpc_url: node_url,
            source_addresses: source_addresses
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>(),
            redeem_script_hex,
            sig_op_count: 2,
            outputs: vec![PsktOutput { address: recipient, amount_sompi }],
            fee_payment_mode: igra_core::domain::FeePaymentMode::RecipientPays,
            fee_sompi: None,
            change_address: None,
        };

        let (_selection, build) = build_pskt_with_client(&rpc, &config).await.expect("pskt build");

        assert!(!build.pskt.inputs.is_empty(), "expected at least one input from RPC utxos");
    }
}

#[path = "harness_smoke.rs"]
mod harness_smoke;
#[path = "hyperlane_iroh_flow.rs"]
mod hyperlane_iroh_flow;
#[path = "hyperlane_rpc.rs"]
mod hyperlane_rpc;
#[path = "v1_service_integration.rs"]
mod v1_service_integration;

#[path = "rpc/authentication.rs"]
mod rpc_authentication;
#[path = "rpc/event_submission.rs"]
mod rpc_event_submission;
#[path = "rpc/health_ready_metrics.rs"]
mod rpc_health_ready_metrics;

mod legacy_core_event_ingestion {
    use async_trait::async_trait;
    use igra_core::domain::hashes::event_hash;
    use igra_core::domain::validation::NoopVerifier;
    use igra_core::domain::{EventSource, SigningEvent};
    use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::infrastructure::storage::{RocksStorage, Storage};
    use igra_core::{
        application::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire},
        ThresholdError,
    };
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct RecordingProcessor {
        calls: Arc<Mutex<Vec<RequestId>>>,
    }

    #[async_trait]
    impl EventProcessor for RecordingProcessor {
        async fn handle_signing_event(
            &self,
            _config: &ServiceConfig,
            _session_id: SessionId,
            request_id: RequestId,
            _signing_event: SigningEvent,
            _expires_at_nanos: u64,
            _coordinator_peer_id: PeerId,
        ) -> Result<Hash32, ThresholdError> {
            self.calls.lock().expect("lock").push(request_id);
            Ok([0u8; 32])
        }
    }

    #[tokio::test]
    async fn test_event_ingestion_when_submitted_then_stores_event_and_calls_processor() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let ctx = EventContext {
            processor: Arc::new(RecordingProcessor { calls: calls.clone() }),
            config: ServiceConfig::default(),
            message_verifier: Arc::new(NoopVerifier),
            storage: storage.clone(),
        };

        let signing_event = SigningEventWire {
            event_id: "event-1".to_string(),
            event_source: EventSource::Api { issuer: "tests".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            amount_sompi: 123,
            metadata: BTreeMap::new(),
            timestamp_nanos: 1,
            signature_hex: None,
            signature: None,
        };

        let params = SigningEventParams {
            session_id_hex: hex::encode([1u8; 32]),
            request_id: "req-1".to_string(),
            coordinator_peer_id: "peer-1".to_string(),
            expires_at_nanos: 0,
            signing_event,
        };

        let result = submit_signing_event(&ctx, params).await.expect("submit");
        let stored = storage
            .get_event(&hex::decode(&result.event_hash_hex).expect("hash hex").as_slice().try_into().expect("hash"))
            .expect("get event");
        assert!(stored.is_some());

        let call_list = calls.lock().expect("lock");
        assert_eq!(call_list.len(), 1);
        assert_eq!(call_list[0], RequestId::from("req-1"));

        let event = stored.expect("event");
        let computed = event_hash(&event).expect("event hash");
        assert_eq!(hex::encode(computed), result.event_hash_hex);
    }
}

#[tokio::test]
async fn happy_path_hyperlane_2_of_3() {
    ensure_wallet_secret();
    if !crate::harness::iroh_bind_tests_enabled() {
        eprintln!("skipping: set IGRA_TEST_IROH_BIND=1 to run iroh bind tests");
        return;
    }

    let root = config_root();
    let signer_config = root.join("artifacts/igra-config.toml");
    let signer_profiles = ["signer-1", "signer-2", "signer-3"];

    let mut configs = signer_profiles.iter().map(|profile| load_app_config_from_profile(&signer_config, profile)).collect::<Vec<_>>();

    let group_id_hex = configs[0].iroh.group_id.clone().expect("group_id");
    let group_id = parse_group_id(&group_id_hex);

    let account_kind = AccountKind::from(MULTISIG_ACCOUNT_KIND);
    let xpub_b = create_xpub_from_mnemonic(SIGNER_MNEMONICS[1], account_kind, 0)
        .await
        .expect("xpub b")
        .to_string(Some(Prefix::KPUB))
        .to_string();
    let xpub_c = create_xpub_from_mnemonic(SIGNER_MNEMONICS[2], account_kind, 0)
        .await
        .expect("xpub c")
        .to_string(Some(Prefix::KPUB))
        .to_string();

    if let Some(hd) = configs[0].service.hd.as_mut() {
        hd.xpubs = vec![xpub_b, xpub_c];
    }

    let network = match TestIrohNetwork::new(3).await {
        Ok(network) => network,
        Err(err) => {
            eprintln!("skipping: iroh bind failed: {err}");
            return;
        }
    };
    network.connect_all(Duration::from_secs(5)).await;
    let topic_id = iroh_gossip::proto::TopicId::from(group_topic_id(&group_id, 0));
    if !network.join_group(topic_id, Duration::from_secs(5)).await {
        eprintln!("skipping: iroh group join timed out");
        return;
    }

    let mut verifier_keys = HashMap::new();
    let mut signers = Vec::new();
    for (peer_id, seed_hex) in IROH_PEERS.iter().zip(IROH_SEED_HEX.iter()) {
        let seed = hex::decode(seed_hex).expect("seed hex");
        let seed_bytes: [u8; 32] = seed.as_slice().try_into().expect("seed bytes");
        let peer_id = PeerId::from(*peer_id);
        let signer = Arc::new(Ed25519Signer::from_seed(peer_id.clone(), seed_bytes));
        verifier_keys.insert(peer_id, signer.verifying_key());
        signers.push(signer);
    }
    let verifier = Arc::new(StaticEd25519Verifier::new(verifier_keys));

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let storage_a = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("a")).expect("storage a"));
    let storage_b = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("b")).expect("storage b"));
    let storage_c = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("c")).expect("storage c"));

    let bootstrap_a = vec![network.endpoints[1].id().to_string(), network.endpoints[2].id().to_string()];
    let bootstrap_b = vec![network.endpoints[0].id().to_string(), network.endpoints[2].id().to_string()];
    let bootstrap_c = vec![network.endpoints[0].id().to_string(), network.endpoints[1].id().to_string()];

    let transport_a = Arc::new(
        IrohTransport::new(
            network.gossips[0].clone(),
            signers[0].clone(),
            verifier.clone(),
            storage_a.clone(),
            IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_a },
        )
        .expect("transport a"),
    );
    let transport_b = Arc::new(
        IrohTransport::new(
            network.gossips[1].clone(),
            signers[1].clone(),
            verifier.clone(),
            storage_b.clone(),
            IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_b },
        )
        .expect("transport b"),
    );
    let transport_c = Arc::new(
        IrohTransport::new(
            network.gossips[2].clone(),
            signers[2].clone(),
            verifier.clone(),
            storage_c.clone(),
            IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_c },
        )
        .expect("transport c"),
    );

    let rpc = Arc::new(MockKaspaNode::new());
    let rpc_dyn: Arc<dyn NodeRpc> = rpc.clone();

    let flow_a = Arc::new(ServiceFlow::new_with_rpc(rpc_dyn.clone(), storage_a.clone(), transport_a.clone()).expect("flow a"));
    let flow_b = Arc::new(ServiceFlow::new_with_rpc(rpc_dyn.clone(), storage_b.clone(), transport_b.clone()).expect("flow b"));
    let flow_c = Arc::new(ServiceFlow::new_with_rpc(rpc_dyn, storage_c.clone(), transport_c.clone()).expect("flow c"));

    let app_a = Arc::new(configs.remove(0));
    let app_b = Arc::new(configs.remove(0));
    let app_c = Arc::new(configs.remove(0));

    let loop_a = tokio::spawn(run_coordination_loop(
        app_a.clone(),
        flow_a.clone(),
        transport_a.clone(),
        storage_a.clone(),
        PeerId::from(IROH_PEERS[0]),
        group_id,
    ));
    let loop_b = tokio::spawn(run_coordination_loop(
        app_b.clone(),
        flow_b.clone(),
        transport_b.clone(),
        storage_b.clone(),
        PeerId::from(IROH_PEERS[1]),
        group_id,
    ));
    let loop_c = tokio::spawn(run_coordination_loop(
        app_c.clone(),
        flow_c.clone(),
        transport_c.clone(),
        storage_c.clone(),
        PeerId::from(IROH_PEERS[2]),
        group_id,
    ));

    let source_address = app_a.service.pskt.source_addresses.first().expect("source address").clone();
    let source_address = Address::constructor(&source_address);
    let utxo_amount = 100 * SOMPI_PER_KAS;
    let utxo = UtxoWithOutpoint {
        address: Some(source_address.clone()),
        outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[9u8; 32]), 0),
        entry: UtxoEntry::new(utxo_amount, pay_to_address_script(&source_address), 0, false),
    };
    rpc.add_utxo(utxo);

    let destination = app_a.policy.allowed_destinations.first().cloned().expect("destination");

    let signing_event = signing_event_for(
        destination.clone(),
        50 * SOMPI_PER_KAS,
        EventSource::Hyperlane { domain: "devnet".to_string(), sender: "hyperlane-bridge".to_string() },
    );

    let hyperlane = MockHyperlaneValidator::new(2, 2);
    let signature = hyperlane.sign_with_quorum(&signing_event).expect("hyperlane signature");
    let validator_pubkeys = hyperlane.get_validator_pubkeys();

    let event_ctx = EventContext {
        processor: flow_a.clone(),
        config: app_a.service.clone(),
        message_verifier: Arc::new(CompositeVerifier::new(validator_pubkeys, 1, Vec::new())),
        storage: storage_a.clone(),
    };

    let params = SigningEventParams {
        session_id_hex: hex::encode([1u8; 32]),
        request_id: "req-happy-path".to_string(),
        coordinator_peer_id: IROH_PEERS[0].to_string(),
        expires_at_nanos: 0,
        signing_event: SigningEventWire {
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
        },
    };

    submit_signing_event(&event_ctx, params).await.expect("submit event");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let request_id = RequestId::from("req-happy-path");
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for finalization");
        }
        if let Ok(Some(request)) = storage_a.get_request(&request_id) {
            if matches!(request.decision, RequestDecision::Finalized) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    assert_request_finalized(storage_a.as_ref(), "req-happy-path");
    assert!(!rpc.submitted_transactions().is_empty(), "expected submitted tx");

    loop_a.abort();
    loop_b.abort();
    loop_c.abort();
}

#[tokio::test]
async fn happy_path_threshold_3_of_5_all_signers() {
    let keygen = TestKeyGenerator::new("3of5-all");
    let PsktBundle { keypairs, pubkeys, pskt_blob, tx_hash, per_input } = build_pskt_bundle(&keygen, 3, 5, 50 * SOMPI_PER_KAS);

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("coordinator"), [5u8; 32], 0));
    let _subscription = transport.subscribe_group([5u8; 32]).await.expect("proposal subscription");
    let coordinator = Coordinator::new(transport, storage.clone());
    let rpc = Arc::new(UnimplementedRpc::new());

    let event =
        build_event("event-3of5-all", 50 * SOMPI_PER_KAS, "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3");
    let request_id = RequestId::from("req-3of5-all");
    coordinator
        .propose_session(
            SessionId::from([1u8; 32]),
            request_id.clone(),
            event.clone(),
            pskt_blob.clone(),
            tx_hash,
            &per_input,
            0,
            PeerId::from("coordinator"),
        )
        .await
        .expect("proposal");

    for (idx, kp) in keypairs.iter().enumerate() {
        let signer = ThresholdSigner::new(kp.clone());
        let sigs = signer.sign(&pskt_blob, &request_id).expect("sign");
        for sig in sigs.signatures_produced {
            storage
                .insert_partial_sig(
                    &request_id,
                    PartialSigRecord {
                        signer_peer_id: PeerId::from(format!("signer-{}", idx + 1)),
                        input_index: sig.input_index,
                        pubkey: sig.pubkey,
                        signature: sig.signature,
                        timestamp_nanos: 0,
                    },
                )
                .expect("partial sig");
        }
    }

    let combined = apply_partial_sigs(&pskt_blob, &storage.list_partial_sigs(&request_id).expect("partials")).expect("apply partials");
    let tx_id = coordinator
        .finalize_and_submit_multisig(&*rpc, &request_id, combined, 3, &pubkeys, &kaspa_consensus_core::config::params::DEVNET_PARAMS)
        .await
        .expect("finalize");

    let request = storage.get_request(&request_id).expect("request").expect("request");
    assert!(matches!(request.decision, RequestDecision::Finalized));
    assert_eq!(request.final_tx_id, Some(RequestTransactionId::from(tx_id)));
}

#[tokio::test]
async fn happy_path_threshold_3_of_5_exactly_three_signers() {
    let keygen = TestKeyGenerator::new("3of5-exact");
    let PsktBundle { keypairs, pubkeys, pskt_blob, tx_hash, per_input } = build_pskt_bundle(&keygen, 3, 5, 25 * SOMPI_PER_KAS);

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("coordinator"), [6u8; 32], 0));
    let _subscription = transport.subscribe_group([6u8; 32]).await.expect("proposal subscription");
    let coordinator = Coordinator::new(transport, storage.clone());
    let rpc = Arc::new(UnimplementedRpc::new());

    let event =
        build_event("event-3of5-exact", 25 * SOMPI_PER_KAS, "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3");
    let request_id = RequestId::from("req-3of5-exact");
    coordinator
        .propose_session(
            SessionId::from([2u8; 32]),
            request_id.clone(),
            event.clone(),
            pskt_blob.clone(),
            tx_hash,
            &per_input,
            0,
            PeerId::from("coordinator"),
        )
        .await
        .expect("proposal");

    for (idx, kp) in keypairs.iter().take(3).enumerate() {
        let signer = ThresholdSigner::new(kp.clone());
        let sigs = signer.sign(&pskt_blob, &request_id).expect("sign");
        for sig in sigs.signatures_produced {
            storage
                .insert_partial_sig(
                    &request_id,
                    PartialSigRecord {
                        signer_peer_id: PeerId::from(format!("signer-{}", idx + 1)),
                        input_index: sig.input_index,
                        pubkey: sig.pubkey,
                        signature: sig.signature,
                        timestamp_nanos: 0,
                    },
                )
                .expect("partial sig");
        }
    }

    let combined = apply_partial_sigs(&pskt_blob, &storage.list_partial_sigs(&request_id).expect("partials")).expect("apply partials");
    let tx_id = coordinator
        .finalize_and_submit_multisig(&*rpc, &request_id, combined, 3, &pubkeys, &kaspa_consensus_core::config::params::DEVNET_PARAMS)
        .await
        .expect("finalize");

    let request = storage.get_request(&request_id).expect("request").expect("request");
    assert!(matches!(request.decision, RequestDecision::Finalized));
    assert_eq!(request.final_tx_id, Some(RequestTransactionId::from(tx_id)));
}

#[tokio::test]
async fn happy_path_threshold_3_of_5_insufficient_signers() {
    let keygen = TestKeyGenerator::new("3of5-insufficient");
    let PsktBundle { keypairs, pubkeys, pskt_blob, tx_hash, per_input } = build_pskt_bundle(&keygen, 3, 5, 10 * SOMPI_PER_KAS);

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("coordinator"), [7u8; 32], 0));
    let _subscription = transport.subscribe_group([7u8; 32]).await.expect("proposal subscription");
    let coordinator = Coordinator::new(transport, storage.clone());
    let rpc = Arc::new(UnimplementedRpc::new());

    let event = build_event(
        "event-3of5-insufficient",
        10 * SOMPI_PER_KAS,
        "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3",
    );
    let request_id = RequestId::from("req-3of5-insufficient");
    coordinator
        .propose_session(
            SessionId::from([3u8; 32]),
            request_id.clone(),
            event.clone(),
            pskt_blob.clone(),
            tx_hash,
            &per_input,
            0,
            PeerId::from("coordinator"),
        )
        .await
        .expect("proposal");

    for (idx, kp) in keypairs.iter().take(2).enumerate() {
        let signer = ThresholdSigner::new(kp.clone());
        let sigs = signer.sign(&pskt_blob, &request_id).expect("sign");
        for sig in sigs.signatures_produced {
            storage
                .insert_partial_sig(
                    &request_id,
                    PartialSigRecord {
                        signer_peer_id: PeerId::from(format!("signer-{}", idx + 1)),
                        input_index: sig.input_index,
                        pubkey: sig.pubkey,
                        signature: sig.signature,
                        timestamp_nanos: 0,
                    },
                )
                .expect("partial sig");
        }
    }

    let combined = apply_partial_sigs(&pskt_blob, &storage.list_partial_sigs(&request_id).expect("partials")).expect("apply partials");
    let err = coordinator
        .finalize_and_submit_multisig(&*rpc, &request_id, combined, 3, &pubkeys, &kaspa_consensus_core::config::params::DEVNET_PARAMS)
        .await
        .expect_err("expected insufficient signatures");
    assert!(err.to_string().contains("insufficient signatures"));
}
