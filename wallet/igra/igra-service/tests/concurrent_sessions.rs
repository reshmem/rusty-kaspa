use igra_core::config::AppConfig;
use igra_core::coordination::hashes::{event_hash, validation_hash};
use igra_core::model::{EventSource, RequestDecision, SigningEvent, SigningRequest, StoredProposal};
use igra_core::pskt::multisig::{build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
use igra_core::rpc::UnimplementedRpc;
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::transport::mock::{MockHub, MockTransport};
use igra_core::types::{PeerId, RequestId, SessionId};
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
    let output = MultisigOutput {
        amount: 9_000,
        script_public_key: ScriptPublicKey::from_vec(0, vec![1, 2, 3]),
    };
    let pskt = build_pskt(&[input], &[output]).expect("pskt");
    let pskt_blob = serialize_pskt(&pskt).expect("serialize");
    let signer = pskt.signer();
    let hashes = input_hashes(&signer).expect("input hashes");
    (pskt_blob, hashes)
}

fn test_event(event_id: &str) -> SigningEvent {
    SigningEvent {
        event_id: event_id.to_string(),
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
async fn concurrent_sessions_timeout_independently() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("peer-1"), [7u8; 32], 0));
    let rpc = Arc::new(UnimplementedRpc::new());
    let flow = Arc::new(ServiceFlow::new_with_rpc(rpc, storage.clone(), transport.clone()).expect("flow"));

    for idx in 1..=2 {
        let request_id = RequestId::from(format!("req-{}", idx));
        let session_id = SessionId::from([idx as u8; 32]);
        let (pskt_blob, per_input) = build_test_pskt();
        let event = test_event(&format!("event-{}", idx));
        let ev_hash = event_hash(&event).expect("event hash");
        let signer_pskt = igra_core::pskt::multisig::deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
        let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
        let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

        storage.insert_event(ev_hash, event.clone()).expect("event insert");
        storage
            .insert_request(SigningRequest {
                request_id: request_id.clone(),
                session_id,
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
                &request_id,
                StoredProposal {
                    request_id: request_id.clone(),
                    session_id,
                    event_hash: ev_hash,
                    validation_hash: val_hash,
                    signing_event: event,
                    kpsbt_blob: pskt_blob,
                },
            )
            .expect("proposal insert");
    }

    let mut app_config = AppConfig::default();
    app_config.runtime.session_timeout_seconds = 1;
    let app_config = Arc::new(app_config);

    let t1 = collect_and_finalize(
        app_config.clone(),
        flow.clone(),
        transport.clone(),
        storage.clone(),
        SessionId::from([1u8; 32]),
        RequestId::from("req-1"),
        test_event("event-1"),
    );
    let t2 = collect_and_finalize(
        app_config.clone(),
        flow,
        transport,
        storage.clone(),
        SessionId::from([2u8; 32]),
        RequestId::from("req-2"),
        test_event("event-2"),
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), futures_util::future::join(t1, t2))
        .await
        .expect("timeout");

    let r1 = storage.get_request(&RequestId::from("req-1")).expect("request1");
    let r2 = storage.get_request(&RequestId::from("req-2")).expect("request2");
    assert!(matches!(r1.unwrap().decision, RequestDecision::Pending));
    assert!(matches!(r2.unwrap().decision, RequestDecision::Pending));
}
