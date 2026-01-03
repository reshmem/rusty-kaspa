use igra_core::coordination::hashes::{event_hash, validation_hash};
use igra_core::coordination::signer::Signer;
use igra_core::model::{EventSource, GroupPolicy, SigningEvent};
use igra_core::pskt::multisig::{build_pskt, deserialize_pskt_signer, serialize_pskt, MultisigInput, MultisigOutput};
use igra_core::storage::rocks::RocksStorage;
use igra_core::transport::mock::{MockHub, MockTransport};
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::standard::multisig_redeem_script;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn build_test_pskt() -> Vec<u8> {
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
    serialize_pskt(&pskt).expect("serialize")
}

fn test_event(destination: &str, amount: u64) -> SigningEvent {
    SigningEvent {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: destination.to_string(),
        amount_sompi: amount,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

#[test]
fn policy_rejects_disallowed_destination() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, "peer-1".to_string(), [1u8; 32], 0));
    let signer = Signer::new(transport, storage);

    let pskt_blob = build_test_pskt();
    let signer_pskt = deserialize_pskt_signer(&pskt_blob).expect("signer pskt");
    let tx_hash = igra_core::pskt::multisig::tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input = igra_core::pskt::multisig::input_hashes(&signer_pskt).expect("input hashes");

    let event = test_event("kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqs7p4x9", 100);
    let ev_hash = event_hash(&event).expect("event hash");
    let val_hash = validation_hash(&ev_hash, &tx_hash, &per_input);

    let policy = GroupPolicy {
        allowed_destinations: vec!["kaspatest:allowed".to_string()],
        min_amount_sompi: None,
        max_amount_sompi: None,
        max_daily_volume_sompi: None,
        require_reason: false,
    };

    let ack = signer
        .validate_proposal(
            "req-1",
            [2u8; 32],
            event,
            ev_hash,
            &pskt_blob,
            tx_hash,
            val_hash,
            "peer-1".to_string(),
            0,
            Some(&policy),
            None,
        )
        .expect("ack");

    assert!(!ack.accept);
}
