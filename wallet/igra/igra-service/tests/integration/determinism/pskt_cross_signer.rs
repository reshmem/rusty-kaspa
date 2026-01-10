use crate::harness::{MockKaspaNode, TestDataFactory, TestKeyGenerator};
use igra_core::infrastructure::config::{PsktBuildConfig, PsktOutput};
use igra_core::domain::hashes::{event_hash, validation_hash};
use igra_core::domain::{EventSource, FeePaymentMode, SigningEvent};
use igra_core::domain::pskt::multisig::{input_hashes, serialize_pskt, to_signer, tx_template_hash};
use igra_core::infrastructure::rpc::kaspa_integration::build_pskt_with_client;
use kaspa_addresses::Prefix;
use std::collections::BTreeMap;

fn build_event(recipient: &str, amount_sompi: u64) -> SigningEvent {
    SigningEvent {
        event_id: "event-determinism".to_string(),
        event_source: EventSource::Api { issuer: "integration-tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: recipient.to_string(),
        amount_sompi,
        metadata: BTreeMap::new(),
        timestamp_nanos: 42,
        signature: None,
    }
}

fn build_config(
    source_address: &str,
    change_address: &str,
    redeem_script_hex: &str,
    fee_payment_mode: FeePaymentMode,
    fee_sompi: u64,
    output_address: &str,
    amount_sompi: u64,
) -> PsktBuildConfig {
    PsktBuildConfig {
        node_rpc_url: String::new(),
        source_addresses: vec![source_address.to_string()],
        redeem_script_hex: redeem_script_hex.to_string(),
        sig_op_count: 2,
        outputs: vec![PsktOutput { address: output_address.to_string(), amount_sompi }],
        fee_payment_mode,
        fee_sompi: Some(fee_sompi),
        change_address: Some(change_address.to_string()),
    }
}

#[tokio::test]
async fn test_pskt_determinism_across_signers() {
    let keygen = TestKeyGenerator::new("pskt-determinism");
    let source_address = keygen.generate_kaspa_address(0, Prefix::Devnet);
    let change_address = keygen.generate_kaspa_address(1, Prefix::Devnet);
    let recipient_address = keygen.generate_kaspa_address(2, Prefix::Devnet);
    let redeem_script_hex = hex::encode(keygen.generate_redeem_script(2, 3));

    let utxos = TestDataFactory::create_utxo_set(&source_address, 20, 5_000_000_000);
    let mut utxos_b = utxos.clone();
    utxos_b.reverse();
    let mut utxos_c = utxos.clone();
    utxos_c.rotate_left(7);

    let rpc_a = MockKaspaNode::new();
    let rpc_b = MockKaspaNode::new();
    let rpc_c = MockKaspaNode::new();
    for utxo in utxos {
        rpc_a.add_utxo(utxo);
    }
    for utxo in utxos_b {
        rpc_b.add_utxo(utxo);
    }
    for utxo in utxos_c {
        rpc_c.add_utxo(utxo);
    }

    let event = build_event(&recipient_address.to_string(), 10_000_000_000);
    let ev_hash = event_hash(&event).expect("event hash");

    let fee_modes = [
        FeePaymentMode::RecipientPays,
        FeePaymentMode::SignersPay,
        FeePaymentMode::Split { recipient_parts: 1, signer_parts: 1 },
    ];

    for mode in fee_modes {
        let config = build_config(
            &source_address.to_string(),
            &change_address.to_string(),
            &redeem_script_hex,
            mode,
            500_000,
            &recipient_address.to_string(),
            event.amount_sompi,
        );

        let (pskt_a, tx_hash_a, val_hash_a) = build_pskt_state(&rpc_a, &config, &ev_hash).await;
        let (pskt_b, tx_hash_b, val_hash_b) = build_pskt_state(&rpc_b, &config, &ev_hash).await;
        let (pskt_c, tx_hash_c, val_hash_c) = build_pskt_state(&rpc_c, &config, &ev_hash).await;

        assert_eq!(pskt_a, pskt_b, "node 0 and 1 PSKTs differ");
        assert_eq!(pskt_b, pskt_c, "node 1 and 2 PSKTs differ");
        assert_eq!(tx_hash_a, tx_hash_b, "node 0 and 1 tx hashes differ");
        assert_eq!(tx_hash_b, tx_hash_c, "node 1 and 2 tx hashes differ");
        assert_eq!(val_hash_a, val_hash_b, "node 0 and 1 validation hashes differ");
        assert_eq!(val_hash_b, val_hash_c, "node 1 and 2 validation hashes differ");
    }
}

async fn build_pskt_state(rpc: &MockKaspaNode, config: &PsktBuildConfig, event_hash: &[u8; 32]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let pskt = build_pskt_with_client(rpc, config).await.expect("pskt build");
    let pskt_blob = serialize_pskt(&pskt).expect("serialize pskt");
    let signer_pskt = to_signer(pskt);
    let tx_hash = tx_template_hash(&signer_pskt).expect("tx hash");
    let per_input = input_hashes(&signer_pskt).expect("input hashes");
    let val_hash = validation_hash(event_hash, &tx_hash, &per_input);
    (pskt_blob, tx_hash, val_hash)
}
