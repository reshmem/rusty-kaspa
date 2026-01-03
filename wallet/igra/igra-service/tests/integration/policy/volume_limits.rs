use crate::integration_harness::test_data::env_lock;
use crate::integration_harness::test_keys::TestKeyGenerator;
use igra_core::coordination::hashes::{event_hash, validation_hash};
use igra_core::coordination::signer::Signer;
use igra_core::error::ThresholdError;
use igra_core::model::{EventSource, GroupPolicy, RequestDecision, SigningEvent, SigningRequest};
use igra_core::pskt::multisig::{build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::transport::mock::{MockHub, MockTransport};
use igra_core::types::{PeerId, RequestId, SessionId, TransactionId as RequestTransactionId};
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::{multisig_redeem_script, pay_to_script_hash_script};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn build_pskt_blob(redeem_script: &[u8], amount: u64) -> (Vec<u8>, [u8; 32], Vec<[u8; 32]>) {
    let spk = pay_to_script_hash_script(redeem_script);
    let input = MultisigInput {
        utxo_entry: UtxoEntry::new(amount + 1_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(KaspaTransactionId::from_slice(&[7u8; 32]), 0),
        redeem_script: redeem_script.to_vec(),
        sig_op_count: 2,
    };
    let output = MultisigOutput {
        amount,
        script_public_key: kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, vec![1, 2, 3]),
    };
    let pskt = build_pskt(&[input], &[output]).expect("pskt");
    let pskt_blob = serialize_pskt(&pskt).expect("serialize pskt");
    let signer_pskt = pskt.signer();
    let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input = input_hashes(&signer_pskt).expect("input hashes");
    (pskt_blob, tx_hash, per_input)
}

fn build_event(amount: u64, timestamp_nanos: u64) -> SigningEvent {
    SigningEvent {
        event_id: format!("volume-{}", timestamp_nanos),
        event_source: EventSource::Api {
            issuer: "integration-tests".to_string(),
        },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3"
            .to_string(),
        amount_sompi: amount,
        metadata: BTreeMap::new(),
        timestamp_nanos,
        signature: None,
    }
}

#[tokio::test]
async fn test_daily_volume_limit_with_reset() -> Result<(), ThresholdError> {
    let _guard = env_lock();
    let nanos_per_day = 24u64 * 60 * 60 * 1_000_000_000;
    let day1 = 1_700_000_000_000_000_000u64;
    std::env::set_var("KASPA_IGRA_TEST_NOW_NANOS", day1.to_string());

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("signer-1"), [3u8; 32], 0));
    let signer = Signer::new(transport, storage.clone());

    let keygen = TestKeyGenerator::new("volume-limit");
    let kp1 = keygen.generate_kaspa_keypair_full(1);
    let kp2 = keygen.generate_kaspa_keypair_full(2);
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
    let redeem_script = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");

    let policy = GroupPolicy {
        max_daily_volume_sompi: Some(100_000_000_000),
        ..Default::default()
    };

    for idx in 0..5u64 {
        let event = build_event(20_000_000_000, day1 + idx);
        let ev_hash = event_hash(&event)?;
        storage.insert_event(ev_hash, event)?;
        storage.insert_request(SigningRequest {
            request_id: RequestId::from(format!("req-{}", idx)),
            session_id: SessionId::from([idx as u8; 32]),
            event_hash: ev_hash,
            coordinator_peer_id: PeerId::from("peer-1"),
            tx_template_hash: [0u8; 32],
            validation_hash: [0u8; 32],
            decision: RequestDecision::Finalized,
            expires_at_nanos: 0,
            final_tx_id: Some(RequestTransactionId::from([1u8; 32])),
            final_tx_accepted_blue_score: None,
        })?;
    }

    let event_exceed = build_event(1_000_000_000, day1 + 10);
    let ev_hash = event_hash(&event_exceed)?;
    let (pskt_blob, tx_hash, per_input) = build_pskt_blob(&redeem_script, event_exceed.amount_sompi);
    let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);
    let ack = signer
        .validate_proposal(
            &RequestId::from("req-exceed"),
            SessionId::from([9u8; 32]),
            event_exceed,
            ev_hash,
            &pskt_blob,
            tx_hash,
            val_hash,
            PeerId::from("peer-1"),
            0,
            Some(&policy),
            None,
        )
        .expect("ack");
    assert!(!ack.accept, "expected rejection due to daily volume limit");
    assert!(
        ack.reason.unwrap_or_default().contains("daily volume exceeded"),
        "expected daily volume limit error"
    );

    let day2 = day1 + nanos_per_day + 1;
    std::env::set_var("KASPA_IGRA_TEST_NOW_NANOS", day2.to_string());

    let event_ok = build_event(20_000_000_000, day2 + 5);
    let ev_hash_ok = event_hash(&event_ok)?;
    let (pskt_blob_ok, tx_hash_ok, per_input_ok) = build_pskt_blob(&redeem_script, event_ok.amount_sompi);
    let val_hash_ok = validation_hash(&ev_hash_ok, &tx_hash_ok, &per_input_ok);
    let ack_ok = signer
        .validate_proposal(
            &RequestId::from("req-ok"),
            SessionId::from([10u8; 32]),
            event_ok,
            ev_hash_ok,
            &pskt_blob_ok,
            tx_hash_ok,
            val_hash_ok,
            PeerId::from("peer-1"),
            0,
            Some(&policy),
            None,
        )
        .expect("ack");
    assert!(ack_ok.accept, "expected acceptance after daily reset");

    std::env::remove_var("KASPA_IGRA_TEST_NOW_NANOS");
    Ok(())
}
