use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::standard::multisig_redeem_script;
use kaspa_wallet_core::prelude::Address;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use std::time::Instant;

use igra_core::config::{PsktBuildConfig, PsktOutput};
use igra_core::pskt::builder::build_pskt_with_client;
use igra_core::rpc::UtxoWithOutpoint;

#[path = "../../integration_harness/mock_node.rs"]
mod mock_node;
use mock_node::MockKaspaNode;

fn test_keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    Keypair::from_secret_key(&secp, &secret)
}

fn redeem_script_hex() -> String {
    let kp1 = test_keypair(1);
    let kp2 = test_keypair(2);
    let kp3 = test_keypair(3);
    let (x1, _) = kp1.public_key().x_only_public_key();
    let (x2, _) = kp2.public_key().x_only_public_key();
    let (x3, _) = kp3.public_key().x_only_public_key();
    let redeem = multisig_redeem_script(
        [x1.serialize(), x2.serialize(), x3.serialize()].iter(),
        2,
    )
    .expect("redeem");
    hex::encode(redeem)
}

#[tokio::test]
async fn pskt_build_latency_smoke() {
    let rpc = MockKaspaNode::new();
    let address = "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3";
    let addr = Address::constructor(address);

    for idx in 0..50u32 {
        let utxo = UtxoWithOutpoint {
            address: Some(addr.clone()),
            outpoint: TransactionOutpoint::new(TransactionId::from_slice(&[idx as u8; 32]), idx),
            entry: UtxoEntry::new(1_000_000, pay_to_address_script(&addr), 0, false),
        };
        rpc.add_utxo(utxo);
    }

    let config = PsktBuildConfig {
        node_rpc_url: String::new(),
        source_addresses: vec![address.to_string()],
        redeem_script_hex: redeem_script_hex(),
        sig_op_count: 2,
        outputs: vec![PsktOutput {
            address: address.to_string(),
            amount_sompi: 10_000_000,
        }],
        fee_payment_mode: igra_core::model::FeePaymentMode::RecipientPays,
        fee_sompi: Some(0),
        change_address: None,
    };

    let start = Instant::now();
    for _ in 0..10 {
        let pskt = build_pskt_with_client(&rpc, &config).await.expect("pskt build");
        assert!(!pskt.inputs.is_empty(), "expected inputs");
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs_f64() < 2.0, "pskt builds too slow: {elapsed:?}");
}
