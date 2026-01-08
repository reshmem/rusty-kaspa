use igra_core::coordination::coordinator::Coordinator;
use igra_core::coordination::hashes::{event_hash, validation_hash};
use igra_core::coordination::signer::{ProposalValidationRequestBuilder, Signer};
use igra_core::model::{EventSource, SigningEvent};
use igra_core::pskt::multisig::{build_pskt, deserialize_pskt_signer, serialize_pskt, MultisigInput, MultisigOutput};
use igra_core::signing::ThresholdSigner;
use igra_core::storage::rocks::RocksStorage;
use igra_core::transport::mock::{MockHub, MockTransport};
use igra_core::transport::TransportMessage;
use igra_core::types::{PeerId, RequestId, SessionId};
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

fn build_test_pskt() -> (Vec<u8>, Vec<Keypair>) {
    let kp1 = test_keypair(1);
    let kp2 = test_keypair(2);
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
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
async fn signing_flow_propagates_partial_sig() {
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

    let (pskt_blob, keypairs) = build_test_pskt();
    let signer_pskt = deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
    let tx_hash = igra_core::pskt::multisig::tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input = igra_core::pskt::multisig::input_hashes(&signer_pskt).expect("input hashes");
    let event = test_event();
    let ev_hash = event_hash(&event).expect("event hash");
    let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

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

    let mut proposal_stream = transport_b.subscribe_group(group_id).await.expect("subscribe group");
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
                .expected_event_hash(proposal.event_hash)
                .kpsbt_blob(&proposal.kpsbt_blob)
                .tx_template_hash(tx_hash)
                .expected_validation_hash(proposal.validation_hash)
                .coordinator_peer_id(proposal.coordinator_peer_id.clone())
                .expires_at_nanos(proposal.expires_at_nanos)
                .build()
                .expect("build request"),
        )
        .expect("ack");
    assert!(ack.accept);

    let backend = ThresholdSigner::new(keypairs[0].clone());
    signer
        .sign_and_submit_backend(envelope.session_id, &proposal.request_id, &proposal.kpsbt_blob, &backend)
        .await
        .expect("sign");

    let mut session_stream = transport_a
        .subscribe_session(envelope.session_id)
        .await
        .expect("subscribe session");
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
}
