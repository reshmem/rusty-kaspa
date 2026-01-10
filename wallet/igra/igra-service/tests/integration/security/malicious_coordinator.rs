use igra_core::application::signer::ProposalValidationRequestBuilder;
use igra_core::application::Signer;
use igra_core::domain::hashes::{event_hash, validation_hash};
use igra_core::domain::pskt::multisig::{build_pskt, input_hashes, serialize_pskt, tx_template_hash, MultisigInput, MultisigOutput};
use igra_core::domain::{EventSource, SigningEvent};
use igra_core::foundation::{PeerId, RequestId, SessionId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::mock::{MockHub, MockTransport};
use kaspa_consensus_core::tx::{TransactionId as KaspaTransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::standard::multisig_redeem_script;
use kaspa_wallet_core::prelude::Address;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn test_event(destination_address: String, amount_sompi: u64) -> SigningEvent {
    SigningEvent {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address,
        amount_sompi,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

fn build_inputs() -> MultisigInput {
    let kp1 = test_keypair(1);
    let kp2 = test_keypair(2);
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
    let redeem = multisig_redeem_script([x1.serialize(), x2.serialize()].iter(), 2).expect("redeem");
    let spk = kaspa_txscript::standard::pay_to_script_hash_script(&redeem);
    let tx_id = KaspaTransactionId::from_slice(&[9u8; 32]);
    MultisigInput {
        utxo_entry: UtxoEntry::new(100_000_000, spk, 0, false),
        previous_outpoint: TransactionOutpoint::new(tx_id, 0),
        redeem_script: redeem,
        sig_op_count: 2,
    }
}

fn output_to_address(address: &str, amount: u64) -> MultisigOutput {
    let address = Address::constructor(address);
    let script_public_key = pay_to_address_script(&address);
    MultisigOutput { amount, script_public_key }
}

#[tokio::test]
async fn malicious_coordinator_tampered_pskt_is_rejected() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let hub = Arc::new(MockHub::new());
    let transport = Arc::new(MockTransport::new(hub, PeerId::from("peer-1"), [7u8; 32], 0));
    let signer = Signer::new(transport, storage.clone());

    let destination = "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3";
    let attacker_destination = "kaspadev:qrz9yajzk65v0wyrk0s54drcauzd8rlgaagrl74cjmj042w4crqkust5wycfq";

    let event = test_event(destination.to_string(), 50_000_000);
    let expected_event_hash = event_hash(&event).expect("event hash");

    let input = build_inputs();
    let output = output_to_address(destination, 50_000_000);
    let pskt = build_pskt(std::slice::from_ref(&input), std::slice::from_ref(&output)).expect("pskt");
    let signer_pskt = pskt.pskt.signer();
    let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input_hashes = input_hashes(&signer_pskt).expect("input hashes");
    let expected_validation = validation_hash(&expected_event_hash, &tx_hash, &per_input_hashes);

    let tampered_output = output_to_address(attacker_destination, 50_000_000);
    let tampered_pskt = build_pskt(&[input], &[tampered_output]).expect("tampered pskt");
    let tampered_blob = serialize_pskt(&tampered_pskt.pskt).expect("serialize tampered");

    let request_id = RequestId::from("req-1");
    let ack = signer
        .validate_proposal(
            ProposalValidationRequestBuilder::new(request_id.clone(), SessionId::from([1u8; 32]), event.clone())
                .expected_group_id([7u8; 32])
                .proposal_group_id([7u8; 32])
                .expected_event_hash(expected_event_hash)
                .kpsbt_blob(&tampered_blob)
                .tx_template_hash(tx_hash)
                .expected_validation_hash(expected_validation)
                .coordinator_peer_id(PeerId::from("peer-1"))
                .expires_at_nanos(0)
                .build()
                .expect("build request"),
            &PeerId::from("peer-1"),
        )
        .expect("validate proposal");

    assert!(!ack.accept, "tampered proposal should be rejected");
    assert_eq!(ack.reason.as_deref(), Some("tx_template_hash_mismatch"));

    assert!(storage.get_request(&request_id).expect("request read").is_none());
    assert!(storage.get_proposal(&request_id).expect("proposal read").is_none());
}
