//! End-to-end concurrent sessions scenarios.

use crate::harness::TestKeyGenerator;
use igra_core::application::Coordinator;
use igra_core::domain::pskt::multisig::{apply_partial_sigs, build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
use igra_core::domain::signing::threshold::ThresholdSigner;
use igra_core::domain::signing::SignerBackend;
use igra_core::domain::{EventSource, PartialSigRecord, RequestDecision, SigningEvent};
use igra_core::foundation::{PeerId, RequestId, SessionId, SigningKeypair};
use igra_core::infrastructure::rpc::UnimplementedRpc;
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use igra_core::infrastructure::transport::Transport;
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::{multisig_redeem_script, pay_to_script_hash_script};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn build_pskt_blob(redeem_script: &[u8], amount: u64) -> (Vec<u8>, [u8; 32], Vec<[u8; 32]>) {
    let spk = pay_to_script_hash_script(redeem_script);
    let input = MultisigInput {
        utxo_entry: UtxoEntry::new(amount + 1_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[5u8; 32]), 0),
        redeem_script: redeem_script.to_vec(),
        sig_op_count: 2,
    };
    let output = MultisigOutput { amount, script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, vec![1, 2, 3]) };
    let pskt = build_pskt(&[input], &[output]).expect("pskt");
    let pskt_blob = serialize_pskt(&pskt).expect("serialize pskt");
    let signer_pskt = pskt.signer();
    let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input = input_hashes(&signer_pskt).expect("input hashes");
    (pskt_blob, tx_hash, per_input)
}

fn build_event(event_id: &str, amount: u64) -> SigningEvent {
    SigningEvent {
        event_id: event_id.to_string(),
        event_source: EventSource::Api { issuer: "integration-tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: amount,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

#[tokio::test]
async fn test_interleaved_session_processing() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("coordinator"), [7u8; 32], 0));
    let _subscription = transport.subscribe_group([7u8; 32]).await.expect("proposal subscription");
    let coordinator = Coordinator::new(transport, storage.clone());
    let rpc = Arc::new(UnimplementedRpc::new());

    let keygen = TestKeyGenerator::new("interleaved");
    let kp1_raw = keygen.generate_kaspa_keypair_full(1);
    let kp2_raw = keygen.generate_kaspa_keypair_full(2);
    let (x1, _) = kp1_raw.public_key().x_only_public_key();
    let (x2, _) = kp2_raw.public_key().x_only_public_key();
    let kp1 = SigningKeypair::from_keypair(&kp1_raw);
    let kp2 = SigningKeypair::from_keypair(&kp2_raw);
    let redeem_script = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");

    let session_a = SessionId::from([1u8; 32]);
    let session_b = SessionId::from([2u8; 32]);
    let request_a = RequestId::from("req-a");
    let request_b = RequestId::from("req-b");
    let event_a = build_event("event-a", 5_000_000_000);
    let event_b = build_event("event-b", 10_000_000_000);

    let (pskt_a, tx_hash_a, per_input_a) = build_pskt_blob(&redeem_script, event_a.amount_sompi);
    let (pskt_b, tx_hash_b, per_input_b) = build_pskt_blob(&redeem_script, event_b.amount_sompi);

    coordinator
        .propose_session(
            session_a,
            request_a.clone(),
            event_a.clone(),
            pskt_a.clone(),
            tx_hash_a,
            &per_input_a,
            0,
            PeerId::from("coordinator"),
        )
        .await
        .expect("proposal a");
    coordinator
        .propose_session(
            session_b,
            request_b.clone(),
            event_b.clone(),
            pskt_b.clone(),
            tx_hash_b,
            &per_input_b,
            0,
            PeerId::from("coordinator"),
        )
        .await
        .expect("proposal b");

    let signers = [ThresholdSigner::new(kp1.clone()), ThresholdSigner::new(kp2.clone())];
    for (idx, signer) in signers.iter().enumerate() {
        let sigs_a = signer.sign(&pskt_a, &request_a).expect("sign a");
        let sigs_b = signer.sign(&pskt_b, &request_b).expect("sign b");
        for sig in sigs_a {
            storage
                .insert_partial_sig(
                    &request_a,
                    PartialSigRecord {
                        signer_peer_id: PeerId::from(format!("signer-{}", idx + 1)),
                        input_index: sig.input_index,
                        pubkey: sig.pubkey,
                        signature: sig.signature,
                        timestamp_nanos: 0,
                    },
                )
                .expect("partial a");
        }
        for sig in sigs_b {
            storage
                .insert_partial_sig(
                    &request_b,
                    PartialSigRecord {
                        signer_peer_id: PeerId::from(format!("signer-{}", idx + 1)),
                        input_index: sig.input_index,
                        pubkey: sig.pubkey,
                        signature: sig.signature,
                        timestamp_nanos: 0,
                    },
                )
                .expect("partial b");
        }
    }

    let public_keys = vec![kp1.public_key(), kp2.public_key()];
    let combined_a =
        apply_partial_sigs(&pskt_a, &storage.list_partial_sigs(&request_a).expect("partials a")).expect("apply a");
    let combined_b =
        apply_partial_sigs(&pskt_b, &storage.list_partial_sigs(&request_b).expect("partials b")).expect("apply b");

    coordinator
        .finalize_and_submit_multisig(
            &*rpc,
            &request_a,
            combined_a,
            2,
            &public_keys,
            &kaspa_consensus_core::config::params::DEVNET_PARAMS,
        )
        .await
        .expect("finalize a");
    coordinator
        .finalize_and_submit_multisig(
            &*rpc,
            &request_b,
            combined_b,
            2,
            &public_keys,
            &kaspa_consensus_core::config::params::DEVNET_PARAMS,
        )
        .await
        .expect("finalize b");

    let req_a = storage.get_request(&request_a).expect("request a").expect("request a");
    let req_b = storage.get_request(&request_b).expect("request b").expect("request b");
    assert!(matches!(req_a.decision, RequestDecision::Finalized));
    assert!(matches!(req_b.decision, RequestDecision::Finalized));
    assert_eq!(rpc.submitted_transactions().len(), 2, "expected two finalized transactions");
}

mod legacy_concurrent_sessions_timeout {
    use igra_core::domain::hashes::{event_hash, validation_hash};
    use igra_core::domain::pskt::multisig::{build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
    use igra_core::domain::{EventSource, RequestDecision, SigningEvent, SigningRequest, StoredProposal};
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
    async fn test_concurrent_sessions_when_multiple_pending_then_timeout_independently() {
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
            let signer_pskt = igra_core::domain::pskt::multisig::deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
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
            flow.clone(),
            transport.clone(),
            storage.clone(),
            SessionId::from([2u8; 32]),
            RequestId::from("req-2"),
            test_event("event-2"),
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            let _ = tokio::join!(t1, t2);
        })
        .await
        .expect("timeout");

        let req1 = storage.get_request(&RequestId::from("req-1")).expect("get req1").expect("req1");
        let req2 = storage.get_request(&RequestId::from("req-2")).expect("get req2").expect("req2");
        assert!(matches!(req1.decision, RequestDecision::Pending));
        assert!(matches!(req2.decision, RequestDecision::Pending));
    }
}

#[path = "performance/concurrent_capacity.rs"]
mod perf_concurrent_capacity;
#[path = "performance/memory_usage.rs"]
mod perf_memory_usage;
#[path = "performance/pskt_build_latency.rs"]
mod perf_pskt_build_latency;
#[path = "performance/signature_throughput.rs"]
mod perf_signature_throughput;
