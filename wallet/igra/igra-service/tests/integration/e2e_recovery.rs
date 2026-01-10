//! End-to-end recovery and failure scenarios.

use crate::harness::{
    assert_request_finalized, config_root, load_app_config_from_profile, signing_event_for, MockHyperlaneValidator, MockKaspaNode,
    TestIrohNetwork, IROH_PEERS, IROH_SEED_HEX, SIGNER_MNEMONICS, SOMPI_PER_KAS,
};
use igra_core::application::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::domain::hashes::{event_hash, validation_hash};
use igra_core::domain::pskt::multisig::{build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
use igra_core::domain::validation::CompositeVerifier;
use igra_core::domain::{EventSource, PartialSigRecord, RequestDecision, SigningRequest, StoredProposal};
use igra_core::foundation::{PeerId, RequestId, SessionId};
use igra_core::infrastructure::rpc::{NodeRpc, UnimplementedRpc, UtxoWithOutpoint};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use igra_core::infrastructure::transport::{ProposedSigningSession, Transport};
use igra_service::service::coordination::{collect_and_finalize, run_coordination_loop};
use igra_service::service::flow::ServiceFlow;
use igra_service::transport::iroh::{IrohConfig, IrohTransport};
use kaspa_bip32::Prefix;
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::standard::{multisig_redeem_script, pay_to_script_hash_script};
use kaspa_wallet_core::account::variants::multisig::MULTISIG_ACCOUNT_KIND;
use kaspa_wallet_core::derivation::create_xpub_from_mnemonic;
use kaspa_wallet_core::prelude::{AccountKind, Address};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Once;
use std::time::Duration;
use tokio::task::JoinHandle;

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

fn pid(value: &str) -> PeerId {
    PeerId::from(value)
}

fn rid(value: &str) -> RequestId {
    RequestId::from(value)
}

fn sid(value: [u8; 32]) -> SessionId {
    SessionId::from(value)
}

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn build_multisig_input() -> MultisigInput {
    let kp1 = test_keypair(1);
    let kp2 = test_keypair(2);
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
    let redeem = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");
    let spk = pay_to_script_hash_script(&redeem);
    let tx_id = KaspaTransactionId::from_slice(&[5u8; 32]);
    MultisigInput {
        utxo_entry: UtxoEntry::new(100_000_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(tx_id, 0),
        redeem_script: redeem,
        sig_op_count: 2,
    }
}

fn output_for_address(address: &str, amount: u64) -> MultisigOutput {
    let addr = Address::constructor(address);
    MultisigOutput { amount, script_public_key: pay_to_address_script(&addr) }
}

fn build_pskt_blob_with_output(output: MultisigOutput) -> (Vec<u8>, [u8; 32], Vec<[u8; 32]>) {
    let input = build_multisig_input();
    let pskt = build_pskt(&[input], &[output]).expect("pskt");
    let blob = serialize_pskt(&pskt.pskt).expect("serialize pskt");
    let signer_pskt = pskt.pskt.signer();
    let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input_hashes = input_hashes(&signer_pskt).expect("input hashes");
    (blob, tx_hash, per_input_hashes)
}

fn spawn_loop(
    app: Arc<igra_core::infrastructure::config::AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<IrohTransport>,
    storage: Arc<RocksStorage>,
    local_peer_id: PeerId,
    group_id: [u8; 32],
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let _ = run_coordination_loop(app, flow, transport, storage, local_peer_id, group_id).await;
    })
}

async fn wait_for_request(storage: &RocksStorage, request_id: &RequestId, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        if let Ok(Some(_)) = storage.get_request(request_id) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_partials(storage: &RocksStorage, request_id: &RequestId, min: usize, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        if let Ok(partials) = storage.list_partial_sigs(request_id) {
            if partials.len() >= min {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_finalized(storage: &RocksStorage, request_id: &RequestId, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        if let Ok(Some(request)) = storage.get_request(request_id) {
            if matches!(request.decision, RequestDecision::Finalized) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_rejected_acks(storage: &RocksStorage, request_id: &RequestId, expected: usize, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        if let Ok(acks) = storage.list_signer_acks(request_id) {
            let rejected = acks.iter().filter(|ack| !ack.accept).count();
            if rejected >= expected {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn load_proposal(storage: &RocksStorage, request_id: &RequestId) -> ProposedSigningSession {
    let proposal = storage.get_proposal(request_id).expect("proposal read").expect("proposal");
    let request = storage.get_request(request_id).expect("request read").expect("request");
    ProposedSigningSession {
        request_id: request_id.clone(),
        session_id: proposal.session_id,
        signing_event: proposal.signing_event,
        event_hash: proposal.event_hash,
        validation_hash: proposal.validation_hash,
        coordinator_peer_id: request.coordinator_peer_id,
        expires_at_nanos: request.expires_at_nanos,
        kpsbt_blob: proposal.kpsbt_blob,
    }
}

struct ThreeNodeSetup {
    group_id: [u8; 32],
    #[allow(dead_code)]
    network: TestIrohNetwork,
    app_a: Arc<igra_core::infrastructure::config::AppConfig>,
    app_b: Arc<igra_core::infrastructure::config::AppConfig>,
    app_c: Arc<igra_core::infrastructure::config::AppConfig>,
    storage_a: Arc<RocksStorage>,
    storage_b: Arc<RocksStorage>,
    storage_c: Arc<RocksStorage>,
    transport_a: Arc<IrohTransport>,
    transport_b: Arc<IrohTransport>,
    transport_c: Arc<IrohTransport>,
    flow_a: Arc<ServiceFlow>,
    flow_b: Arc<ServiceFlow>,
    flow_c: Arc<ServiceFlow>,
    rpc: Arc<MockKaspaNode>,
    _temp_dir: tempfile::TempDir,
}

impl ThreeNodeSetup {
    async fn new(timeout_secs: Option<u64>) -> Result<Self, String> {
        if !crate::harness::iroh_bind_tests_enabled() {
            return Err("set IGRA_TEST_IROH_BIND=1 to run iroh bind tests".to_string());
        }

        let root = config_root();
        let signer_config = root.join("artifacts/igra-config.toml");
        let signer_profiles = ["signer-1", "signer-2", "signer-3"];

        let mut configs =
            signer_profiles.iter().map(|profile| load_app_config_from_profile(&signer_config, profile)).collect::<Vec<_>>();

        if let Some(timeout) = timeout_secs {
            configs[0].runtime.session_timeout_seconds = timeout;
        }

        let group_id_hex = configs[0].iroh.group_id.clone().ok_or_else(|| "group_id missing".to_string())?;
        let group_id = parse_group_id(&group_id_hex);

        let account_kind = AccountKind::from(MULTISIG_ACCOUNT_KIND);
        let xpub_b = create_xpub_from_mnemonic(SIGNER_MNEMONICS[1], account_kind, 0)
            .await
            .map_err(|err| err.to_string())?
            .to_string(Some(Prefix::KPUB))
            .to_string();
        let xpub_c = create_xpub_from_mnemonic(SIGNER_MNEMONICS[2], account_kind, 0)
            .await
            .map_err(|err| err.to_string())?
            .to_string(Some(Prefix::KPUB))
            .to_string();

        if let Some(hd) = configs[0].service.hd.as_mut() {
            hd.xpubs = vec![xpub_b, xpub_c];
        }

        let network = TestIrohNetwork::new(3).await.map_err(|err| format!("iroh bind failed: {err}"))?;
        network.connect_all(Duration::from_secs(5)).await;
        let topic_id = iroh_gossip::proto::TopicId::from(group_topic_id(&group_id, 0));
        if !network.join_group(topic_id, Duration::from_secs(5)).await {
            return Err("iroh group join timed out".to_string());
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

        let temp_dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let storage_a = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("a")).map_err(|err| err.to_string())?);
        let storage_b = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("b")).map_err(|err| err.to_string())?);
        let storage_c = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("c")).map_err(|err| err.to_string())?);

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
            .map_err(|err| err.to_string())?,
        );
        let transport_b = Arc::new(
            IrohTransport::new(
                network.gossips[1].clone(),
                signers[1].clone(),
                verifier.clone(),
                storage_b.clone(),
                IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_b },
            )
            .map_err(|err| err.to_string())?,
        );
        let transport_c = Arc::new(
            IrohTransport::new(
                network.gossips[2].clone(),
                signers[2].clone(),
                verifier.clone(),
                storage_c.clone(),
                IrohConfig { network_id: 0, group_id, bootstrap_nodes: bootstrap_c },
            )
            .map_err(|err| err.to_string())?,
        );

        let rpc = Arc::new(MockKaspaNode::new());
        let rpc_dyn: Arc<dyn NodeRpc> = rpc.clone();
        let flow_a = Arc::new(
            ServiceFlow::new_with_rpc(rpc_dyn.clone(), storage_a.clone(), transport_a.clone()).map_err(|err| err.to_string())?,
        );
        let flow_b = Arc::new(
            ServiceFlow::new_with_rpc(rpc_dyn.clone(), storage_b.clone(), transport_b.clone()).map_err(|err| err.to_string())?,
        );
        let flow_c =
            Arc::new(ServiceFlow::new_with_rpc(rpc_dyn, storage_c.clone(), transport_c.clone()).map_err(|err| err.to_string())?);

        let app_a = Arc::new(configs.remove(0));
        let app_b = Arc::new(configs.remove(0));
        let app_c = Arc::new(configs.remove(0));

        Ok(Self {
            group_id,
            network,
            app_a,
            app_b,
            app_c,
            storage_a,
            storage_b,
            storage_c,
            transport_a,
            transport_b,
            transport_c,
            flow_a,
            flow_b,
            flow_c,
            rpc,
            _temp_dir: temp_dir,
        })
    }

    fn add_single_utxo(&self) {
        let source_address = self.app_a.service.pskt.source_addresses.first().expect("source address").clone();
        let source_address = Address::constructor(&source_address);
        let utxo_amount = 100 * SOMPI_PER_KAS;
        let utxo = UtxoWithOutpoint {
            address: Some(source_address.clone()),
            outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[9u8; 32]), 0),
            entry: UtxoEntry::new(utxo_amount, pay_to_address_script(&source_address), 0, false),
        };
        self.rpc.add_utxo(utxo);
    }

    fn destination(&self) -> String {
        self.app_a.policy.allowed_destinations.first().cloned().expect("destination")
    }
}

fn signing_params(
    request_id: &str,
    session_seed: u8,
    coordinator_peer_id: &str,
    event: &igra_core::domain::SigningEvent,
    signature: Vec<u8>,
) -> SigningEventParams {
    SigningEventParams {
        session_id_hex: hex::encode([session_seed; 32]),
        request_id: request_id.to_string(),
        coordinator_peer_id: coordinator_peer_id.to_string(),
        expires_at_nanos: 0,
        signing_event: SigningEventWire {
            event_id: event.event_id.clone(),
            event_source: event.event_source.clone(),
            derivation_path: event.derivation_path.clone(),
            derivation_index: event.derivation_index,
            destination_address: event.destination_address.clone(),
            amount_sompi: event.amount_sompi,
            metadata: event.metadata.clone(),
            timestamp_nanos: event.timestamp_nanos,
            signature_hex: None,
            signature: Some(signature),
        },
    }
}

#[tokio::test]
async fn coordinator_failure_after_proposal() {
    ensure_wallet_secret();

    let setup = match ThreeNodeSetup::new(None).await {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("skipping: {err}");
            return;
        }
    };

    setup.add_single_utxo();

    let loop_a = spawn_loop(
        setup.app_a.clone(),
        setup.flow_a.clone(),
        setup.transport_a.clone(),
        setup.storage_a.clone(),
        pid(IROH_PEERS[0]),
        setup.group_id,
    );
    let loop_b = spawn_loop(
        setup.app_b.clone(),
        setup.flow_b.clone(),
        setup.transport_b.clone(),
        setup.storage_b.clone(),
        pid(IROH_PEERS[1]),
        setup.group_id,
    );
    let loop_c = spawn_loop(
        setup.app_c.clone(),
        setup.flow_c.clone(),
        setup.transport_c.clone(),
        setup.storage_c.clone(),
        pid(IROH_PEERS[2]),
        setup.group_id,
    );

    let destination = setup.destination();
    let signing_event = signing_event_for(
        destination,
        50 * SOMPI_PER_KAS,
        EventSource::Hyperlane { domain: "devnet".to_string(), sender: "hyperlane-bridge".to_string() },
    );
    let hyperlane = MockHyperlaneValidator::new(2, 2);
    let signature = hyperlane.sign_with_quorum(&signing_event).expect("hyperlane signature");
    let validator_pubkeys = hyperlane.get_validator_pubkeys();

    let event_ctx = EventContext {
        processor: setup.flow_a.clone(),
        config: setup.app_a.service.clone(),
        message_verifier: Arc::new(CompositeVerifier::new(validator_pubkeys, 1, Vec::new())),
        storage: setup.storage_a.clone(),
    };

    let request_id = rid("req-coordinator-failure");
    let params = signing_params(request_id.as_str(), 2, IROH_PEERS[0], &signing_event, signature);
    submit_signing_event(&event_ctx, params).await.expect("submit event");

    assert!(wait_for_request(&setup.storage_b, &request_id, Duration::from_secs(5)).await, "proposal did not reach signer b");

    loop_a.abort();

    assert!(wait_for_partials(&setup.storage_b, &request_id, 1, Duration::from_secs(5)).await, "signer b did not publish partial");
    assert!(wait_for_partials(&setup.storage_c, &request_id, 1, Duration::from_secs(5)).await, "signer c did not publish partial");

    let loop_a = spawn_loop(
        setup.app_a.clone(),
        setup.flow_a.clone(),
        setup.transport_a.clone(),
        setup.storage_a.clone(),
        pid(IROH_PEERS[0]),
        setup.group_id,
    );

    let proposal = load_proposal(setup.storage_a.as_ref(), &request_id);
    setup.transport_a.publish_proposal(proposal).await.expect("re-broadcast proposal");

    assert!(
        wait_for_finalized(&setup.storage_a, &request_id, Duration::from_secs(10)).await,
        "coordinator did not finalize after restart"
    );
    assert_request_finalized(setup.storage_a.as_ref(), request_id.as_str());
    assert!(!setup.rpc.submitted_transactions().is_empty(), "expected submitted tx");

    loop_a.abort();
    loop_b.abort();
    loop_c.abort();
}

#[tokio::test]
async fn timeout_with_insufficient_signatures() {
    ensure_wallet_secret();

    let setup = match ThreeNodeSetup::new(Some(1)).await {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("skipping: {err}");
            return;
        }
    };

    setup.add_single_utxo();

    let loop_a = spawn_loop(
        setup.app_a.clone(),
        setup.flow_a.clone(),
        setup.transport_a.clone(),
        setup.storage_a.clone(),
        pid(IROH_PEERS[0]),
        setup.group_id,
    );
    let loop_b = spawn_loop(
        setup.app_b.clone(),
        setup.flow_b.clone(),
        setup.transport_b.clone(),
        setup.storage_b.clone(),
        pid(IROH_PEERS[1]),
        setup.group_id,
    );

    let destination = setup.destination();
    let signing_event = signing_event_for(
        destination,
        50 * SOMPI_PER_KAS,
        EventSource::Hyperlane { domain: "devnet".to_string(), sender: "hyperlane-bridge".to_string() },
    );
    let hyperlane = MockHyperlaneValidator::new(2, 2);
    let signature = hyperlane.sign_with_quorum(&signing_event).expect("hyperlane signature");
    let validator_pubkeys = hyperlane.get_validator_pubkeys();

    let event_ctx = EventContext {
        processor: setup.flow_a.clone(),
        config: setup.app_a.service.clone(),
        message_verifier: Arc::new(CompositeVerifier::new(validator_pubkeys, 1, Vec::new())),
        storage: setup.storage_a.clone(),
    };

    let request_id = rid("req-timeout");
    let params = signing_params(request_id.as_str(), 3, IROH_PEERS[0], &signing_event, signature);
    submit_signing_event(&event_ctx, params).await.expect("submit event");

    assert!(wait_for_request(&setup.storage_b, &request_id, Duration::from_secs(5)).await, "proposal did not reach signer b");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let request = setup.storage_a.get_request(&request_id).expect("request read").expect("request");
    assert!(matches!(request.decision, RequestDecision::Pending));
    assert!(setup.rpc.submitted_transactions().is_empty(), "unexpected tx submission");

    loop_a.abort();
    loop_b.abort();
}

#[tokio::test]
async fn redundant_proposers_deduplicate() {
    ensure_wallet_secret();

    let setup = match ThreeNodeSetup::new(None).await {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("skipping: {err}");
            return;
        }
    };

    setup.add_single_utxo();

    let loop_a = spawn_loop(
        setup.app_a.clone(),
        setup.flow_a.clone(),
        setup.transport_a.clone(),
        setup.storage_a.clone(),
        pid(IROH_PEERS[0]),
        setup.group_id,
    );
    let loop_c = spawn_loop(
        setup.app_c.clone(),
        setup.flow_c.clone(),
        setup.transport_c.clone(),
        setup.storage_c.clone(),
        pid(IROH_PEERS[2]),
        setup.group_id,
    );

    let destination = setup.destination();
    let signing_event = signing_event_for(
        destination,
        50 * SOMPI_PER_KAS,
        EventSource::Hyperlane { domain: "devnet".to_string(), sender: "hyperlane-bridge".to_string() },
    );
    let hyperlane = MockHyperlaneValidator::new(2, 2);
    let signature = hyperlane.sign_with_quorum(&signing_event).expect("hyperlane signature");
    let validator_pubkeys = hyperlane.get_validator_pubkeys();

    let event_ctx_a = EventContext {
        processor: setup.flow_a.clone(),
        config: setup.app_a.service.clone(),
        message_verifier: Arc::new(CompositeVerifier::new(validator_pubkeys.clone(), 1, Vec::new())),
        storage: setup.storage_a.clone(),
    };

    let request_a = rid("req-redundant-a");
    let params_a = signing_params(request_a.as_str(), 4, IROH_PEERS[0], &signing_event, signature.clone());
    submit_signing_event(&event_ctx_a, params_a).await.expect("submit event a");

    assert!(wait_for_finalized(&setup.storage_a, &request_a, Duration::from_secs(10)).await, "primary proposal did not finalize");

    let event_ctx_b = EventContext {
        processor: setup.flow_b.clone(),
        config: setup.app_b.service.clone(),
        message_verifier: Arc::new(CompositeVerifier::new(validator_pubkeys, 1, Vec::new())),
        storage: setup.storage_b.clone(),
    };

    let request_b = rid("req-redundant-b");
    let params_b = signing_params(request_b.as_str(), 5, IROH_PEERS[1], &signing_event, signature);
    submit_signing_event(&event_ctx_b, params_b).await.expect("submit event b");

    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(setup.storage_a.get_request(&request_b).expect("request read").is_none());
    assert!(setup.storage_c.get_request(&request_b).expect("request read").is_none());
    assert!(setup.storage_b.get_request(&request_b).expect("request read").is_some());

    loop_a.abort();
    loop_c.abort();
}

#[tokio::test]
async fn partitioned_signer_recovers_after_rebroadcast() {
    ensure_wallet_secret();

    let setup = match ThreeNodeSetup::new(None).await {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("skipping: {err}");
            return;
        }
    };

    setup.add_single_utxo();

    let loop_a = spawn_loop(
        setup.app_a.clone(),
        setup.flow_a.clone(),
        setup.transport_a.clone(),
        setup.storage_a.clone(),
        pid(IROH_PEERS[0]),
        setup.group_id,
    );
    let loop_b = spawn_loop(
        setup.app_b.clone(),
        setup.flow_b.clone(),
        setup.transport_b.clone(),
        setup.storage_b.clone(),
        pid(IROH_PEERS[1]),
        setup.group_id,
    );

    let destination = setup.destination();
    let signing_event = signing_event_for(
        destination,
        50 * SOMPI_PER_KAS,
        EventSource::Hyperlane { domain: "devnet".to_string(), sender: "hyperlane-bridge".to_string() },
    );
    let hyperlane = MockHyperlaneValidator::new(2, 2);
    let signature = hyperlane.sign_with_quorum(&signing_event).expect("hyperlane signature");
    let validator_pubkeys = hyperlane.get_validator_pubkeys();

    let event_ctx = EventContext {
        processor: setup.flow_a.clone(),
        config: setup.app_a.service.clone(),
        message_verifier: Arc::new(CompositeVerifier::new(validator_pubkeys, 1, Vec::new())),
        storage: setup.storage_a.clone(),
    };

    let request_id = rid("req-partition");
    let params = signing_params(request_id.as_str(), 6, IROH_PEERS[0], &signing_event, signature);
    submit_signing_event(&event_ctx, params).await.expect("submit event");

    assert!(wait_for_finalized(&setup.storage_a, &request_id, Duration::from_secs(10)).await, "coordinator did not finalize");

    assert!(setup.storage_c.get_request(&request_id).expect("request read").is_none());

    let loop_c = spawn_loop(
        setup.app_c.clone(),
        setup.flow_c.clone(),
        setup.transport_c.clone(),
        setup.storage_c.clone(),
        pid(IROH_PEERS[2]),
        setup.group_id,
    );

    let proposal = load_proposal(setup.storage_a.as_ref(), &request_id);
    setup.transport_a.publish_proposal(proposal).await.expect("rebroadcast proposal");
    assert!(
        wait_for_request(&setup.storage_c, &request_id, Duration::from_secs(5)).await,
        "partitioned signer did not ingest proposal"
    );

    let request = setup.storage_a.get_request(&request_id).expect("request read").expect("request");
    let tx_id = request.final_tx_id.expect("final tx id");
    setup.transport_a.publish_finalize(request.session_id, &request_id, *tx_id.as_hash()).await.expect("rebroadcast finalize");

    assert!(
        wait_for_finalized(&setup.storage_c, &request_id, Duration::from_secs(5)).await,
        "partitioned signer did not record finalization"
    );

    loop_a.abort();
    loop_b.abort();
    loop_c.abort();
}

#[tokio::test]
async fn malformed_proposal_rejected_by_signers() {
    ensure_wallet_secret();

    let setup = match ThreeNodeSetup::new(Some(2)).await {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("skipping: {err}");
            return;
        }
    };

    let loop_a = spawn_loop(
        setup.app_a.clone(),
        setup.flow_a.clone(),
        setup.transport_a.clone(),
        setup.storage_a.clone(),
        pid(IROH_PEERS[0]),
        setup.group_id,
    );
    let loop_b = spawn_loop(
        setup.app_b.clone(),
        setup.flow_b.clone(),
        setup.transport_b.clone(),
        setup.storage_b.clone(),
        pid(IROH_PEERS[1]),
        setup.group_id,
    );
    let loop_c = spawn_loop(
        setup.app_c.clone(),
        setup.flow_c.clone(),
        setup.transport_c.clone(),
        setup.storage_c.clone(),
        pid(IROH_PEERS[2]),
        setup.group_id,
    );

    let destination = setup.destination();
    let signing_event = signing_event_for(destination.clone(), 50 * SOMPI_PER_KAS, EventSource::Api { issuer: "tests".to_string() });
    let event_hash = event_hash(&signing_event).expect("event hash");

    let (_valid_blob, tx_hash, per_input_hashes) = build_pskt_blob_with_output(output_for_address(&destination, 50 * SOMPI_PER_KAS));
    let validation_hash = validation_hash(&event_hash, &tx_hash, &per_input_hashes);
    let attacker_output =
        output_for_address("kaspadev:qrz9yajzk65v0wyrk0s54drcauzd8rlgaagrl74cjmj042w4crqkust5wycfq", 50 * SOMPI_PER_KAS);
    let (tampered_blob, _, _) = build_pskt_blob_with_output(attacker_output);

    setup.storage_a.insert_event(event_hash, signing_event.clone()).expect("event insert");
    setup
        .storage_a
        .insert_request(SigningRequest {
            request_id: rid("req-malformed"),
            session_id: sid([9u8; 32]),
            event_hash,
            coordinator_peer_id: pid(IROH_PEERS[0]),
            tx_template_hash: tx_hash,
            validation_hash,
            decision: RequestDecision::Pending,
            expires_at_nanos: 0,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        })
        .expect("request insert");
    setup
        .storage_a
        .insert_proposal(
            &rid("req-malformed"),
            StoredProposal {
                request_id: rid("req-malformed"),
                session_id: sid([9u8; 32]),
                event_hash,
                validation_hash,
                signing_event: signing_event.clone(),
                kpsbt_blob: tampered_blob.clone(),
            },
        )
        .expect("proposal insert");

    let proposal = ProposedSigningSession {
        request_id: rid("req-malformed"),
        session_id: sid([9u8; 32]),
        signing_event,
        event_hash,
        validation_hash,
        coordinator_peer_id: pid(IROH_PEERS[0]),
        expires_at_nanos: 0,
        kpsbt_blob: tampered_blob,
    };

    setup.transport_a.publish_proposal(proposal).await.expect("publish proposal");

    assert!(
        wait_for_rejected_acks(&setup.storage_a, &rid("req-malformed"), 2, Duration::from_secs(5)).await,
        "expected rejected acks"
    );
    let acks = setup.storage_a.list_signer_acks(&rid("req-malformed")).expect("acks list");
    assert!(acks.iter().any(|ack| ack.reason.as_deref() == Some("validation_hash_mismatch")), "expected validation_hash_mismatch");

    let partials = setup.storage_a.list_partial_sigs(&rid("req-malformed")).expect("partials");
    assert!(partials.is_empty(), "unexpected partial signatures");

    loop_a.abort();
    loop_b.abort();
    loop_c.abort();
}

#[tokio::test]
async fn invalid_partials_do_not_finalize() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, pid("peer-1"), [4u8; 32], 0));
    let rpc = Arc::new(UnimplementedRpc::new());
    let flow = Arc::new(ServiceFlow::new_with_rpc(rpc, storage.clone(), transport.clone()).expect("flow"));

    let destination = "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3";
    let signing_event =
        signing_event_for(destination.to_string(), 50 * SOMPI_PER_KAS, EventSource::Api { issuer: "tests".to_string() });
    let event_hash = event_hash(&signing_event).expect("event hash");
    let (pskt_blob, tx_hash, per_input_hashes) = build_pskt_blob_with_output(output_for_address(destination, 50 * SOMPI_PER_KAS));
    let validation_hash = validation_hash(&event_hash, &tx_hash, &per_input_hashes);

    storage.insert_event(event_hash, signing_event.clone()).expect("event insert");
    let request_id = rid("req-invalid-partials");
    storage
        .insert_request(SigningRequest {
            request_id: request_id.clone(),
            session_id: sid([1u8; 32]),
            event_hash,
            coordinator_peer_id: pid("peer-1"),
            tx_template_hash: tx_hash,
            validation_hash,
            decision: RequestDecision::Pending,
            expires_at_nanos: 0,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        })
        .expect("request insert");
    storage
        .insert_proposal(
            &request_id,
            StoredProposal {
                request_id: request_id.clone(),
                session_id: sid([1u8; 32]),
                event_hash,
                validation_hash,
                signing_event: signing_event.clone(),
                kpsbt_blob: pskt_blob,
            },
        )
        .expect("proposal insert");

    storage
        .insert_partial_sig(
            &request_id,
            PartialSigRecord {
                signer_peer_id: pid("peer-2"),
                input_index: 0,
                pubkey: vec![1, 2, 3],
                signature: vec![4, 5, 6],
                timestamp_nanos: 10,
            },
        )
        .expect("partial insert");
    storage
        .insert_partial_sig(
            &request_id,
            PartialSigRecord {
                signer_peer_id: pid("peer-3"),
                input_index: 0,
                pubkey: vec![7, 8, 9],
                signature: vec![10, 11, 12],
                timestamp_nanos: 11,
            },
        )
        .expect("partial insert");

    let mut app_config = igra_core::infrastructure::config::AppConfig::default();
    app_config.service.pskt.sig_op_count = 2;
    app_config.runtime.session_timeout_seconds = 1;

    let result = collect_and_finalize(
        Arc::new(app_config),
        flow,
        transport,
        storage.clone(),
        sid([1u8; 32]),
        request_id.clone(),
        signing_event,
    )
    .await;
    assert!(result.is_err(), "expected finalize error");

    let request = storage.get_request(&request_id).expect("request read").expect("request");
    assert!(matches!(request.decision, RequestDecision::Pending));
}

mod legacy_coordinator_failure_timeout {
    use igra_core::domain::hashes::{event_hash, validation_hash};
    use igra_core::domain::pskt::multisig::{
        build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput,
    };
    use igra_core::domain::{EventSource, PartialSigRecord, RequestDecision, SigningEvent, SigningRequest, StoredProposal};
    use igra_core::foundation::{PeerId, RequestId, SessionId};
    use igra_core::infrastructure::config::AppConfig;
    use igra_core::infrastructure::rpc::UnimplementedRpc;
    use igra_core::infrastructure::storage::{RocksStorage, Storage};
    use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
    use igra_service::service::coordination::collect_and_finalize;
    use igra_service::service::flow::ServiceFlow;
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
    use kaspa_txscript::standard::multisig_redeem_script;
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
        Keypair::from_secret_key(&secp, &secret)
    }

    fn build_test_pskt() -> (Vec<u8>, Vec<[u8; 32]>) {
        let kp1 = test_keypair(1);
        let kp2 = test_keypair(2);
        let (x1, _) = kp1.public_key().x_only_public_key();
        let (x2, _) = kp2.public_key().x_only_public_key();
        let redeem = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");
        let spk = kaspa_txscript::standard::pay_to_script_hash_script(&redeem);
        let tx_id = KaspaTransactionId::from_slice(&[9u8; 32]);
        let input = MultisigInput {
            utxo_entry: UtxoEntry::new(10_000, spk, 0, false),
            previous_outpoint: TransactionOutpoint::new(tx_id, 0),
            redeem_script: redeem.clone(),
            sig_op_count: 2,
        };
        let output = MultisigOutput { amount: 9_000, script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]) };
        let pskt = build_pskt(&[input], &[output]).expect("pskt");
        let pskt_blob = serialize_pskt(&pskt.pskt).expect("serialize");
        let signer = pskt.pskt.signer();
        let hashes = input_hashes(&signer).expect("input hashes");
        (pskt_blob, hashes)
    }

    fn test_event() -> SigningEvent {
        SigningEvent {
            event_id: "event-1".to_string(),
            event_source: EventSource::Api { issuer: "tests".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
            amount_sompi: 123,
            metadata: BTreeMap::new(),
            timestamp_nanos: 1,
            signature: None,
        }
    }

    #[tokio::test]
    async fn test_coordinator_finalize_when_partial_responses_then_times_out() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let hub = Arc::new(MockHub::new());
        let transport = Arc::new(MockTransport::new(hub, PeerId::from("peer-1"), [7u8; 32], 0));
        let rpc = Arc::new(UnimplementedRpc::new());
        let flow = Arc::new(ServiceFlow::new_with_rpc(rpc, storage.clone(), transport.clone()).expect("flow"));

        let (pskt_blob, per_input) = build_test_pskt();
        let event = test_event();
        let ev_hash = event_hash(&event).expect("event hash");
        let signer_pskt = igra_core::domain::pskt::multisig::deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
        let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
        let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

        storage.insert_event(ev_hash, event.clone()).expect("event insert");
        storage
            .insert_request(SigningRequest {
                request_id: RequestId::from("req-1"),
                session_id: SessionId::from([1u8; 32]),
                event_hash: ev_hash,
                coordinator_peer_id: PeerId::from("peer-1"),
                tx_template_hash: tx_hash,
                validation_hash: val_hash,
                decision: RequestDecision::Pending,
                expires_at_nanos: 0,
                final_tx_id: None,
                final_tx_accepted_blue_score: None,
            })
            .expect("request insert");
        storage
            .insert_proposal(
                &RequestId::from("req-1"),
                StoredProposal {
                    request_id: RequestId::from("req-1"),
                    session_id: SessionId::from([1u8; 32]),
                    event_hash: ev_hash,
                    validation_hash: val_hash,
                    signing_event: event.clone(),
                    kpsbt_blob: pskt_blob,
                },
            )
            .expect("proposal insert");

        storage
            .insert_partial_sig(
                &RequestId::from("req-1"),
                PartialSigRecord {
                    signer_peer_id: PeerId::from("peer-2"),
                    input_index: 0,
                    pubkey: vec![1, 2, 3],
                    signature: vec![4, 5, 6],
                    timestamp_nanos: 10,
                },
            )
            .expect("partial insert");

        let mut app_config = AppConfig::default();
        app_config.runtime.session_timeout_seconds = 1;
        app_config.service.pskt.sig_op_count = 2;

        tokio::time::timeout(
            Duration::from_secs(2),
            collect_and_finalize(
                Arc::new(app_config),
                flow,
                transport,
                storage.clone(),
                SessionId::from([1u8; 32]),
                RequestId::from("req-1"),
                event,
            ),
        )
        .await
        .expect("timeout")
        .expect("collect");

        let request = storage.get_request(&RequestId::from("req-1")).expect("get request");
        assert!(request.is_some());
        assert!(matches!(request.unwrap().decision, RequestDecision::Pending));
    }
}

mod legacy_iroh_transport {
    mod iroh_tests {
        use igra_core::domain::{EventSource, SigningEvent};
        use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
        use igra_core::infrastructure::storage::RocksStorage;
        use igra_core::infrastructure::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
        use igra_core::infrastructure::transport::{ProposedSigningSession, Transport};
        use igra_service::transport::iroh::{IrohConfig, IrohTransport};
        use iroh::discovery::static_provider::StaticProvider;
        use iroh::RelayMode;
        use iroh_gossip::proto::TopicId;
        use std::collections::BTreeMap;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::time::{timeout, Duration};

        fn group_topic_id(group_id: &Hash32, network_id: u8) -> Hash32 {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"kaspa-sign/v1");
            hasher.update(&[network_id]);
            hasher.update(group_id);
            *hasher.finalize().as_bytes()
        }

        #[tokio::test]
        async fn iroh_transport_receives_published_proposal() {
            if !crate::harness::iroh_bind_tests_enabled() {
                eprintln!("skipping: set IGRA_TEST_IROH_BIND=1 to run iroh bind tests");
                return;
            }
            let discovery = StaticProvider::new();
            let endpoint_a = match iroh::Endpoint::builder().discovery(discovery.clone()).relay_mode(RelayMode::Disabled).bind().await
            {
                Ok(endpoint) => endpoint,
                Err(err) => {
                    eprintln!("skipping: bind endpoint A failed: {err}");
                    return;
                }
            };
            let endpoint_b = match iroh::Endpoint::builder().discovery(discovery.clone()).relay_mode(RelayMode::Disabled).bind().await
            {
                Ok(endpoint) => endpoint,
                Err(err) => {
                    eprintln!("skipping: bind endpoint B failed: {err}");
                    return;
                }
            };
            discovery.add_endpoint_info(endpoint_a.addr());
            discovery.add_endpoint_info(endpoint_b.addr());
            let gossip_a = iroh_gossip::net::Gossip::builder().spawn(endpoint_a.clone());
            let gossip_b = iroh_gossip::net::Gossip::builder().spawn(endpoint_b.clone());
            let _router_a =
                iroh::protocol::Router::builder(endpoint_a.clone()).accept(iroh_gossip::net::GOSSIP_ALPN, gossip_a.clone()).spawn();
            let _router_b =
                iroh::protocol::Router::builder(endpoint_b.clone()).accept(iroh_gossip::net::GOSSIP_ALPN, gossip_b.clone()).spawn();
            let _conn_a = match endpoint_a.connect(endpoint_b.addr(), iroh_gossip::net::GOSSIP_ALPN).await {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("skipping: connect A->B failed: {err}");
                    return;
                }
            };
            let _conn_b = match endpoint_b.connect(endpoint_a.addr(), iroh_gossip::net::GOSSIP_ALPN).await {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("skipping: connect B->A failed: {err}");
                    return;
                }
            };
            let group_id = [9u8; 32];
            let topic_id = TopicId::from(group_topic_id(&group_id, 0));
            let _warm_a = match timeout(Duration::from_secs(5), gossip_a.subscribe_and_join(topic_id, vec![endpoint_b.id()])).await {
                Ok(Ok(topic)) => topic,
                Ok(Err(err)) => {
                    eprintln!("skipping: join A failed: {err}");
                    return;
                }
                Err(_) => {
                    eprintln!("skipping: join A timed out");
                    return;
                }
            };
            let _warm_b = match timeout(Duration::from_secs(5), gossip_b.subscribe_and_join(topic_id, vec![endpoint_a.id()])).await {
                Ok(Ok(topic)) => topic,
                Ok(Err(err)) => {
                    eprintln!("skipping: join B failed: {err}");
                    return;
                }
                Err(_) => {
                    eprintln!("skipping: join B timed out");
                    return;
                }
            };

            let peer_id = PeerId::from("peer-1");
            let signer = Arc::new(Ed25519Signer::from_seed(peer_id.clone(), [7u8; 32]));
            let signer_key = signer.verifying_key();
            let mut keys = HashMap::new();
            keys.insert(peer_id.clone(), signer_key);
            let verifier = Arc::new(StaticEd25519Verifier::new(keys));

            let config_a = IrohConfig { network_id: 0, group_id, bootstrap_nodes: vec![endpoint_b.id().to_string()] };
            let config_b = IrohConfig { network_id: 0, group_id, bootstrap_nodes: vec![endpoint_a.id().to_string()] };

            let temp_dir = tempfile::tempdir().expect("temp dir");
            let storage_a = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("a")).expect("rocksdb open a"));
            let storage_b = Arc::new(RocksStorage::open_in_dir(temp_dir.path().join("b")).expect("rocksdb open b"));
            let transport_a = IrohTransport::new(gossip_a, signer, verifier, storage_a, config_a).expect("create transport A");

            let peer_id_b = PeerId::from("peer-2");
            let signer_b = Arc::new(Ed25519Signer::from_seed(peer_id_b.clone(), [8u8; 32]));
            let mut keys_b = HashMap::new();
            keys_b.insert(peer_id.clone(), signer_key);
            keys_b.insert(peer_id_b.clone(), signer_b.verifying_key());
            let verifier_b = Arc::new(StaticEd25519Verifier::new(keys_b));
            let transport_b = IrohTransport::new(gossip_b, signer_b, verifier_b, storage_b, config_b).expect("create transport B");

            let signing_event = SigningEvent {
                event_id: "event-1".to_string(),
                event_source: EventSource::Manual { operator: "test".to_string() },
                derivation_path: "m/45'/111111'/0'/0/0".to_string(),
                derivation_index: Some(0),
                destination_address: "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs7p4x9".to_string(),
                amount_sompi: 1234,
                metadata: BTreeMap::new(),
                timestamp_nanos: 0,
                signature: None,
            };

            let session_id = SessionId::from([1u8; 32]);
            let proposal = ProposedSigningSession {
                request_id: RequestId::from("request-1"),
                session_id,
                signing_event,
                event_hash: [2u8; 32],
                validation_hash: [3u8; 32],
                coordinator_peer_id: peer_id.clone(),
                expires_at_nanos: 0,
                kpsbt_blob: Vec::new(),
            };

            let mut subscription = transport_b.subscribe_group(group_id).await.expect("subscribe group");
            tokio::time::sleep(Duration::from_millis(500)).await;
            transport_a.publish_proposal(proposal).await.expect("publish proposal");

            let received = timeout(Duration::from_secs(5), subscription.next())
                .await
                .expect("timeout waiting for proposal")
                .expect("subscription closed")
                .expect("proposal envelope error");

            assert_eq!(received.session_id, session_id);
        }
    }
}

#[path = "security/dos_resistance.rs"]
mod security_dos_resistance;
#[path = "security/malicious_coordinator.rs"]
mod security_malicious_coordinator;
#[path = "security/replay_attack.rs"]
mod security_replay_attack;
#[path = "security/timing_attacks.rs"]
mod security_timing_attacks;

#[path = "storage/audit_trail.rs"]
mod storage_audit_trail;
#[path = "storage/persistence.rs"]
mod storage_persistence;
#[path = "storage/replay_prevention.rs"]
mod storage_replay_prevention;
#[path = "storage/volume_tracking.rs"]
mod storage_volume_tracking;

mod legacy_core_replay_protection {
    use async_trait::async_trait;
    use igra_core::application::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
    use igra_core::domain::validation::NoopVerifier;
    use igra_core::domain::{EventSource, SigningEvent};
    use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
    use igra_core::infrastructure::config::{AppConfig, ServiceConfig};
    use igra_core::infrastructure::storage::RocksStorage;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct DummyProcessor;

    #[async_trait]
    impl EventProcessor for DummyProcessor {
        async fn handle_signing_event(
            &self,
            _config: &ServiceConfig,
            _session_id: SessionId,
            _request_id: RequestId,
            _signing_event: SigningEvent,
            _expires_at_nanos: u64,
            _coordinator_peer_id: PeerId,
        ) -> Result<Hash32, igra_core::ThresholdError> {
            Ok([0u8; 32])
        }
    }

    #[tokio::test]
    async fn test_replay_protection_when_duplicate_event_submitted_then_rejected() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
        let config = AppConfig::default();
        let event_ctx = EventContext {
            processor: Arc::new(DummyProcessor),
            config: config.service.clone(),
            message_verifier: Arc::new(NoopVerifier),
            storage: storage.clone(),
        };

        let params1 = SigningEventParams {
            session_id_hex: hex::encode([1u8; 32]),
            request_id: "req-1".to_string(),
            coordinator_peer_id: "peer-1".to_string(),
            expires_at_nanos: 0,
            signing_event: SigningEventWire {
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
            },
        };

        let params2 = SigningEventParams {
            session_id_hex: hex::encode([1u8; 32]),
            request_id: "req-1".to_string(),
            coordinator_peer_id: "peer-1".to_string(),
            expires_at_nanos: 0,
            signing_event: SigningEventWire {
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
            },
        };

        submit_signing_event(&event_ctx, params1).await.expect("first submit");
        let result = submit_signing_event(&event_ctx, params2).await;
        assert!(result.is_err());
    }
}

mod legacy_core_transaction_monitoring {
    use igra_core::application::TransactionMonitor;
    use igra_core::infrastructure::rpc::UnimplementedRpc;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_transaction_monitor_when_blue_score_passes_threshold_then_confirms() {
        let rpc = Arc::new(UnimplementedRpc::new());
        rpc.set_blue_score(10);
        let monitor = TransactionMonitor::new(rpc.clone(), 5, Duration::from_millis(10));

        let task = tokio::spawn(async move { monitor.monitor_until_confirmed(8).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        rpc.set_blue_score(20);

        let result = task.await.expect("join").expect("monitor");
        assert!(result >= 13);
    }
}
