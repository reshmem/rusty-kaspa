use crate::integration_harness::test_keys::TestKeyGenerator;
use igra_core::coordination::coordinator::Coordinator;
use igra_core::hd::SigningKeypair;
use igra_core::model::{EventSource, RequestDecision, SigningEvent};
use igra_core::pskt::multisig::{build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
use igra_core::rpc::UnimplementedRpc;
use igra_core::signing::threshold::ThresholdSigner;
use igra_core::signing::SignerBackend;
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::transport::mock::{MockHub, MockTransport};
use igra_core::transport::Transport;
use igra_core::types::{PeerId, RequestId, SessionId};
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
        let sigs_a = signer.sign(&pskt_a).expect("sign a");
        let sigs_b = signer.sign(&pskt_b).expect("sign b");
        for sig in sigs_a {
            storage
                .insert_partial_sig(
                    &request_a,
                    igra_core::model::PartialSigRecord {
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
                    igra_core::model::PartialSigRecord {
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
        igra_core::pskt::multisig::apply_partial_sigs(&pskt_a, &storage.list_partial_sigs(&request_a).expect("partials a"))
            .expect("apply a");
    let combined_b =
        igra_core::pskt::multisig::apply_partial_sigs(&pskt_b, &storage.list_partial_sigs(&request_b).expect("partials b"))
            .expect("apply b");

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
