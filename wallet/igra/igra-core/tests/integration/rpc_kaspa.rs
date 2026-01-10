use igra_core::domain::FeePaymentMode;
use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::config::{PsktBuildConfig, PsktOutput};
use igra_core::infrastructure::rpc::kaspa_integration::build_pskt_with_client;
use igra_core::infrastructure::rpc::{NodeRpc, UtxoWithOutpoint};
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_txscript::pay_to_address_script;

struct TestRpc {
    utxos: Vec<UtxoWithOutpoint>,
}

#[async_trait::async_trait]
impl NodeRpc for TestRpc {
    async fn get_utxos_by_addresses(&self, _addresses: &[Address]) -> Result<Vec<UtxoWithOutpoint>, ThresholdError> {
        Ok(self.utxos.clone())
    }

    async fn submit_transaction(
        &self,
        _tx: kaspa_consensus_core::tx::Transaction,
    ) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
        Ok(TransactionId::from_slice(&[0u8; 32]))
    }

    async fn get_virtual_selected_parent_blue_score(&self) -> Result<u64, ThresholdError> {
        Ok(0)
    }
}

fn build_rpc(amount: u64, address: &Address) -> TestRpc {
    let entry = UtxoEntry::new(amount, pay_to_address_script(address), 0, false);
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&[9u8; 32]), 0);
    let utxo = UtxoWithOutpoint { address: Some(address.clone()), outpoint, entry };
    TestRpc { utxos: vec![utxo] }
}

fn base_config(address: &str) -> PsktBuildConfig {
    PsktBuildConfig {
        node_rpc_url: String::new(),
        source_addresses: vec![address.to_string()],
        redeem_script_hex: "00".to_string(),
        sig_op_count: 2,
        outputs: vec![PsktOutput { address: address.to_string(), amount_sompi: 1000 }],
        fee_payment_mode: FeePaymentMode::RecipientPays,
        fee_sompi: Some(100),
        change_address: Some(address.to_string()),
    }
}

#[tokio::test]
async fn test_pskt_builder_when_fee_recipient_pays_then_first_output_reduced() {
    let address = "kaspatest:qz0hz8jkn6ptfhq3v9fg3jhqw5jtsfgy62wan8dhe8fqkhdqsahswcpe2ch3m";
    let addr: Address = address.try_into().expect("valid address");
    let rpc = build_rpc(2000, &addr);
    let mut config = base_config(address);
    config.fee_payment_mode = FeePaymentMode::RecipientPays;
    let (_selection, build) = build_pskt_with_client(&rpc, &config).await.expect("pskt");
    let pskt = build.pskt;
    assert_eq!(pskt.outputs[0].amount, 900);
    assert_eq!(pskt.outputs[1].amount, 1100);
}

#[tokio::test]
async fn test_pskt_builder_when_fee_signers_pay_then_change_reduced() {
    let address = "kaspatest:qz0hz8jkn6ptfhq3v9fg3jhqw5jtsfgy62wan8dhe8fqkhdqsahswcpe2ch3m";
    let addr: Address = address.try_into().expect("valid address");
    let rpc = build_rpc(2000, &addr);
    let mut config = base_config(address);
    config.fee_payment_mode = FeePaymentMode::SignersPay;
    let (_selection, build) = build_pskt_with_client(&rpc, &config).await.expect("pskt");
    let pskt = build.pskt;
    assert_eq!(pskt.outputs[0].amount, 1000);
    assert_eq!(pskt.outputs[1].amount, 900);
}

#[tokio::test]
async fn test_pskt_builder_when_fee_split_then_outputs_adjusted() {
    let address = "kaspatest:qz0hz8jkn6ptfhq3v9fg3jhqw5jtsfgy62wan8dhe8fqkhdqsahswcpe2ch3m";
    let addr: Address = address.try_into().expect("valid address");
    let rpc = build_rpc(2000, &addr);
    let mut config = base_config(address);
    config.fee_payment_mode = FeePaymentMode::Split { recipient_parts: 1, signer_parts: 1 };
    let (_selection, build) = build_pskt_with_client(&rpc, &config).await.expect("pskt");
    let pskt = build.pskt;
    assert_eq!(pskt.outputs[0].amount, 950);
    assert_eq!(pskt.outputs[1].amount, 1000);
}
