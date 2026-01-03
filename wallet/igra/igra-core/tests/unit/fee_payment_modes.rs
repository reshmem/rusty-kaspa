use igra_core::config::PsktBuildConfig;
use igra_core::model::FeePaymentMode;
use igra_core::pskt::builder::build_pskt_with_client;
use igra_core::rpc::{NodeRpc, UtxoWithOutpoint};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;

struct TestRpc {
    utxos: Vec<UtxoWithOutpoint>,
}

#[async_trait::async_trait]
impl NodeRpc for TestRpc {
    async fn get_utxos_by_addresses(&self, _addresses: &[Address]) -> Result<Vec<UtxoWithOutpoint>, igra_core::error::ThresholdError> {
        Ok(self.utxos.clone())
    }

    async fn submit_transaction(
        &self,
        _tx: kaspa_consensus_core::tx::Transaction,
    ) -> Result<kaspa_consensus_core::tx::TransactionId, igra_core::error::ThresholdError> {
        Ok(TransactionId::from_slice(&[0u8; 32]))
    }

    async fn get_virtual_selected_parent_blue_score(&self) -> Result<u64, igra_core::error::ThresholdError> {
        Ok(0)
    }
}

fn build_rpc(amount: u64, address: &Address) -> TestRpc {
    let entry = UtxoEntry::new(amount, pay_to_address_script(address), 0, false);
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&[9u8; 32]), 0);
    let utxo = UtxoWithOutpoint {
        address: Some(address.clone()),
        outpoint,
        entry,
    };
    TestRpc { utxos: vec![utxo] }
}

fn base_config(address: &str) -> PsktBuildConfig {
    PsktBuildConfig {
        node_rpc_url: String::new(),
        source_addresses: vec![address.to_string()],
        redeem_script_hex: "00".to_string(),
        sig_op_count: 2,
        outputs: vec![igra_core::config::PsktOutput { address: address.to_string(), amount_sompi: 1000 }],
        fee_payment_mode: FeePaymentMode::RecipientPays,
        fee_sompi: Some(100),
        change_address: Some(address.to_string()),
    }
}

#[tokio::test]
async fn fee_recipient_pays() {
    let address = "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p";
    let addr = Address::constructor(address);
    let rpc = build_rpc(2000, &addr);
    let mut config = base_config(address);
    config.fee_payment_mode = FeePaymentMode::RecipientPays;
    let pskt = build_pskt_with_client(&rpc, &config).await.expect("pskt");
    assert_eq!(pskt.outputs[0].amount, 900);
    assert_eq!(pskt.outputs[1].amount, 1100);
}

#[tokio::test]
async fn fee_signers_pay() {
    let address = "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p";
    let addr = Address::constructor(address);
    let rpc = build_rpc(2000, &addr);
    let mut config = base_config(address);
    config.fee_payment_mode = FeePaymentMode::SignersPay;
    let pskt = build_pskt_with_client(&rpc, &config).await.expect("pskt");
    assert_eq!(pskt.outputs[0].amount, 1000);
    assert_eq!(pskt.outputs[1].amount, 900);
}

#[tokio::test]
async fn fee_split() {
    let address = "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p";
    let addr = Address::constructor(address);
    let rpc = build_rpc(2000, &addr);
    let mut config = base_config(address);
    config.fee_payment_mode = FeePaymentMode::Split { recipient_portion: 0.5 };
    let pskt = build_pskt_with_client(&rpc, &config).await.expect("pskt");
    assert_eq!(pskt.outputs[0].amount, 950);
    assert_eq!(pskt.outputs[1].amount, 1000);
}
