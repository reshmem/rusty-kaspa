use igra_core::config::{PsktBuildConfig, PsktOutput};
use igra_core::rpc::grpc::GrpcNodeRpc;
use igra_service::service::build_pskt_with_client;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

#[tokio::test]
async fn rpc_utxo_flow_builds_pskt() {
    let node_url = env("KASPA_NODE_URL").unwrap_or_else(|| "grpc://127.0.0.1:16110".to_string());
    let source_addresses = env("KASPA_SOURCE_ADDRESSES").unwrap_or_default();
    let redeem_script_hex = env("KASPA_REDEEM_SCRIPT_HEX").unwrap_or_default();
    let recipient = env("KASPA_RECIPIENT_ADDRESS").unwrap_or_default();
    let amount_sompi = env("KASPA_RECIPIENT_AMOUNT").and_then(|v| v.parse().ok()).unwrap_or(0);

    if source_addresses.is_empty() || redeem_script_hex.is_empty() || recipient.is_empty() || amount_sompi == 0 {
        eprintln!("set KASPA_SOURCE_ADDRESSES,KASPA_REDEEM_SCRIPT_HEX,KASPA_RECIPIENT_ADDRESS,KASPA_RECIPIENT_AMOUNT to run");
        return;
    }

    let rpc = GrpcNodeRpc::connect(node_url.clone()).await.expect("grpc connect");

    let config = PsktBuildConfig {
        node_rpc_url: node_url,
        source_addresses: source_addresses
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>(),
        redeem_script_hex,
        sig_op_count: 2,
        outputs: vec![PsktOutput { address: recipient, amount_sompi }],
        fee_payment_mode: igra_core::model::FeePaymentMode::RecipientPays,
        fee_sompi: None,
        change_address: None,
    };

    let pskt = build_pskt_with_client(&rpc, &config).await.expect("pskt build");

    assert!(!pskt.inputs.is_empty(), "expected at least one input from RPC utxos");
}
