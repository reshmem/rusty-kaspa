//! End-to-end threshold scenarios.

use igra_core::application::Coordinator;
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::signing::SignerBackend;
use igra_core::domain::{EventSource, PartialSigRecord, RequestDecision, SigningEvent};
use igra_core::foundation::{derive_keypair_from_key_data, PeerId, RequestId, SessionId, SigningKeypair, TransactionId as RequestTransactionId};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::rpc::UnimplementedRpc;
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use igra_core::infrastructure::transport::Transport;
use kaspa_consensus_core::config::params::DEVNET_PARAMS;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::multisig_redeem_script;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

#[path = "cryptography/transport_auth.rs"]
mod cryptography_transport_auth;
#[path = "determinism/pskt_cross_signer.rs"]
mod determinism_pskt_cross_signer;

mod legacy_core_full_signing_flow {
    use igra_core::application::signer::ProposalValidationRequestBuilder;
    use igra_core::application::{Coordinator, Signer};
    use igra_core::domain::hashes::{event_hash, validation_hash};
    use igra_core::domain::pskt::multisig::{build_pskt, deserialize_pskt_signer, serialize_pskt, MultisigInput, MultisigOutput};
    use igra_core::domain::signing::threshold::ThresholdSigner;
    use igra_core::domain::{EventSource, SigningEvent};
    use igra_core::foundation::{PeerId, RequestId, SessionId, SigningKeypair};
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::infrastructure::transport::Transport;
    use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
    use igra_core::infrastructure::transport::messages::TransportMessage;
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
    use kaspa_txscript::standard::multisig_redeem_script;
    use secp256k1::{Keypair, Secp256k1, SecretKey};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::time::{timeout, Duration};

    fn test_keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
        Keypair::from_secret_key(&secp, &secret)
    }

    fn build_test_pskt() -> (Vec<u8>, Vec<SigningKeypair>) {
        let kp1_raw = test_keypair(1);
        let kp2_raw = test_keypair(2);
        let (x1, _) = kp1_raw.public_key().x_only_public_key();
        let (x2, _) = kp2_raw.public_key().x_only_public_key();
        let redeem = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");
        let spk = kaspa_txscript::standard::pay_to_script_hash_script(&redeem);
        let tx_id = TransactionId::from_slice(&[9u8; 32]);
        let input = MultisigInput {
            utxo_entry: UtxoEntry::new(10_000, spk, 0, false),
            previous_outpoint: TransactionOutpoint::new(tx_id, 0),
            redeem_script: redeem.clone(),
            sig_op_count: 2,
        };
        let output = MultisigOutput {
            amount: 9_000,
            script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]),
        };
        let pskt = build_pskt(&[input], &[output]).expect("pskt");
        let kp1 = SigningKeypair::from_keypair(&kp1_raw);
        let kp2 = SigningKeypair::from_keypair(&kp2_raw);
        (serialize_pskt(&pskt).expect("serialize"), vec![kp1, kp2])
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
    async fn test_signing_flow_when_partial_sig_submitted_then_propagates() {
        let _guard = crate::harness::env_lock();
        std::env::set_var("KASPA_IGRA_TEST_NOW_NANOS", "0");
        let hub = Arc::new(MockHub::new());
        let group_id = [7u8; 32];
        let transport_a = Arc::new(MockTransport::new(hub.clone(), PeerId::from("peer-a"), group_id, 0));
        let transport_b = Arc::new(MockTransport::new(hub, PeerId::from("peer-b"), group_id, 0));

        let temp_a = TempDir::new().expect("temp");
        let temp_b = TempDir::new().expect("temp");
        let storage_a = Arc::new(RocksStorage::open_in_dir(temp_a.path()).expect("storage a"));
        let storage_b = Arc::new(RocksStorage::open_in_dir(temp_b.path()).expect("storage b"));

        let coordinator = Coordinator::new(transport_a.clone(), storage_a.clone());
        let signer = Signer::new(transport_b.clone(), storage_b.clone());

        let mut proposal_stream = transport_b.subscribe_group(group_id).await.expect("subscribe group");

        let (pskt_blob, keypairs) = build_test_pskt();
        let signer_pskt = deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
        let tx_hash = igra_core::domain::pskt::multisig::tx_template_hash(&signer_pskt).expect("tx hash");
        let per_input = igra_core::domain::pskt::multisig::input_hashes(&signer_pskt).expect("input hashes");
        let event = test_event();
        let ev_hash = event_hash(&event).expect("event hash");
        let _val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

        coordinator
            .propose_session(
                SessionId::from([1u8; 32]),
                RequestId::from("req-1"),
                event.clone(),
                pskt_blob.clone(),
                tx_hash,
                &per_input,
                0,
                PeerId::from("peer-a"),
            )
            .await
            .expect("propose");

        let envelope = timeout(Duration::from_secs(2), proposal_stream.next())
            .await
            .expect("timeout")
            .expect("closed")
            .expect("envelope");

        let TransportMessage::SigningEventPropose(proposal) = envelope.payload else {
            panic!("unexpected payload");
        };

        let ack = signer
            .validate_proposal(
                ProposalValidationRequestBuilder::new(proposal.request_id.clone(), envelope.session_id, proposal.signing_event.clone())
                    .expected_group_id(group_id)
                    .proposal_group_id(envelope.group_id)
                    .expected_event_hash(proposal.event_hash)
                    .kpsbt_blob(&proposal.kpsbt_blob)
                    .tx_template_hash(tx_hash)
                    .expected_validation_hash(proposal.validation_hash)
                    .coordinator_peer_id(proposal.coordinator_peer_id.clone())
                    .expires_at_nanos(proposal.expires_at_nanos)
                    .build()
                    .expect("build request"),
                &PeerId::from("peer-b"),
            )
            .expect("ack");
        assert!(ack.accept);

        let mut session_stream = transport_a.subscribe_session(envelope.session_id).await.expect("subscribe session");

        let backend = ThresholdSigner::new(keypairs[0].clone());
        signer
            .sign_and_submit_backend(envelope.session_id, &proposal.request_id, &proposal.kpsbt_blob, &backend, &PeerId::from("peer-b"))
            .await
            .expect("sign");

        let sig_env = timeout(Duration::from_secs(2), session_stream.next())
            .await
            .expect("timeout")
            .expect("closed")
            .expect("env");
        match sig_env.payload {
            TransportMessage::PartialSigSubmit(sig) => {
                assert_eq!(sig.request_id, proposal.request_id);
            }
            _ => panic!("expected partial sig"),
        }

        std::env::remove_var("KASPA_IGRA_TEST_NOW_NANOS");
    }
}

fn config_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("igra repo root").to_path_buf()
}

fn load_from_ini_profile(config_path: &Path, profile: &str) -> AppConfig {
    let data_dir = tempfile::tempdir().expect("temp data dir");

    env::set_var("KASPA_DATA_DIR", data_dir.path());

    let config = igra_core::infrastructure::config::load_app_config_from_profile_path(config_path, profile).expect("load app config");

    env::remove_var("KASPA_DATA_DIR");
    config
}

fn keypair_from_config(config: &AppConfig, derivation_path: &str) -> SigningKeypair {
    let hd = config.service.hd.as_ref().expect("hd config");
    let key_data = hd.decrypt_mnemonics().expect("decrypt mnemonics");
    let key_data = key_data.first().expect("mnemonic missing");
    derive_keypair_from_key_data(key_data, derivation_path, None).expect("derive keypair")
}

#[tokio::test]
async fn two_of_three_signing_flow_finalizes() {
    let _guard = crate::harness::env_lock();
    let root = config_root();
    let signer_config = root.join("artifacts/igra-config.ini");
    let signer_profiles = ["signer-1", "signer-2", "signer-3"];

    env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-test-secret-please-change");

    let configs = signer_profiles.iter().map(|profile| load_from_ini_profile(&signer_config, profile)).collect::<Vec<_>>();

    let derivation_path = "m/45'/111111'/0'/0/0";
    let keypairs = configs
        .iter()
        .map(|config| (PeerId::from(config.iroh.peer_id.clone().expect("peer id")), keypair_from_config(config, derivation_path)))
        .collect::<Vec<_>>();

    let public_keys = keypairs.iter().map(|(_, kp)| kp.public_key()).collect::<Vec<_>>();
    let xonly_keys = public_keys.iter().map(|pk| pk.x_only_public_key().0.serialize()).collect::<Vec<_>>();

    let redeem = multisig_redeem_script(xonly_keys.iter(), 2).expect("redeem script");
    let spk = kaspa_txscript::standard::pay_to_script_hash_script(&redeem);
    let tx_id = KaspaTransactionId::from_slice(&[9u8; 32]);
    let input = pskt_multisig::MultisigInput {
        utxo_entry: UtxoEntry::new(10_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(tx_id, 0),
        redeem_script: redeem.clone(),
        sig_op_count: 2,
    };
    let output = pskt_multisig::MultisigOutput { amount: 9_000, script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]) };
    let pskt = pskt_multisig::build_pskt(&[input], &[output]).expect("pskt build");
    let pskt_blob = pskt_multisig::serialize_pskt(&pskt).expect("pskt serialize");
    let signer_pskt = pskt_multisig::deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
    let tx_template_hash = pskt_multisig::tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input_hashes = pskt_multisig::input_hashes(&signer_pskt).expect("input hashes");

    let signing_event = SigningEvent {
        event_id: "event-2of3".to_string(),
        event_source: EventSource::Api { issuer: "integration-test".to_string() },
        derivation_path: derivation_path.to_string(),
        derivation_index: Some(0),
        destination_address: configs[0].runtime.test_recipient.clone().expect("test recipient"),
        amount_sompi: 123,
        metadata: Default::default(),
        timestamp_nanos: 1,
        signature: None,
    };

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("signer-1"), [7u8; 32], 0));
    let _proposal_subscription = transport.subscribe_group([7u8; 32]).await.expect("proposal subscription");
    let coordinator = Coordinator::new(transport, storage.clone());

    let session_id = SessionId::from([1u8; 32]);
    let request_id = RequestId::from("req-2of3");

    coordinator
        .propose_session(
            session_id,
            request_id.clone(),
            signing_event,
            pskt_blob.clone(),
            tx_template_hash,
            &per_input_hashes,
            0,
            PeerId::from("signer-1"),
        )
        .await
        .expect("proposal");

    for (peer_id, keypair) in keypairs.iter().take(2) {
        let signer = igra_core::domain::signing::threshold::ThresholdSigner::new(keypair.clone());
        let sigs = signer.sign(&pskt_blob, &request_id).expect("sign pskt");
        for sig in sigs {
            storage
                .insert_partial_sig(
                    &request_id,
                    PartialSigRecord {
                        signer_peer_id: peer_id.clone(),
                        input_index: sig.input_index,
                        pubkey: sig.pubkey,
                        signature: sig.signature,
                        timestamp_nanos: 0,
                    },
                )
                .expect("insert partial sig");
        }
    }

    let partials = storage.list_partial_sigs(&request_id).expect("list partials");
    let combined = pskt_multisig::apply_partial_sigs(&pskt_blob, &partials).expect("apply partials");

    let rpc = Arc::new(UnimplementedRpc::new());
    let tx_id = coordinator
        .finalize_and_submit_multisig(&*rpc, &request_id, combined, 2, &public_keys, &DEVNET_PARAMS)
        .await
        .expect("finalize");

    assert!(!rpc.submitted_transactions().is_empty(), "transaction submitted");
    let stored = storage.get_request(&request_id).expect("stored request").expect("request");
    assert!(matches!(stored.decision, RequestDecision::Finalized));
    assert_eq!(stored.final_tx_id, Some(RequestTransactionId::from(tx_id)));

}
