use crate::domain::pskt::builder::build_pskt_from_utxos;
use crate::domain::pskt::params::{PsktOutputParams, PsktParams, UtxoInput};
use crate::foundation::ThresholdError;
use crate::infrastructure::config::PsktBuildConfig;
use crate::infrastructure::rpc::{GrpcNodeRpc, NodeRpc};
use kaspa_addresses::Address;

pub async fn submit_transaction(
    rpc: &dyn NodeRpc,
    tx: kaspa_consensus_core::tx::Transaction,
) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
    rpc.submit_transaction(tx).await
}

pub async fn build_pskt_via_rpc(
    config: &PsktBuildConfig,
) -> Result<kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Updater>, ThresholdError> {
    let rpc = GrpcNodeRpc::connect(config.node_rpc_url.clone()).await?;
    build_pskt_with_client(&rpc, config).await
}

pub async fn build_pskt_with_client(
    rpc: &dyn NodeRpc,
    config: &PsktBuildConfig,
) -> Result<kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Updater>, ThresholdError> {
    let redeem_script = hex::decode(&config.redeem_script_hex)?;

    let params = PsktParams {
        source_addresses: config.source_addresses.clone(),
        outputs: config
            .outputs
            .iter()
            .map(|out| PsktOutputParams { address: out.address.clone(), amount_sompi: out.amount_sompi })
            .collect(),
        redeem_script,
        sig_op_count: config.sig_op_count,
        fee_payment_mode: config.fee_payment_mode.clone(),
        fee_sompi: config.fee_sompi,
        change_address: config.change_address.clone(),
    };

    let addresses = params.source_addresses.iter().map(|addr| Address::constructor(addr)).collect::<Vec<_>>();
    let mut utxos = rpc.get_utxos_by_addresses(&addresses).await?;

    let inputs = utxos
        .drain(..)
        .map(|utxo| UtxoInput { outpoint: utxo.outpoint, entry: utxo.entry })
        .collect::<Vec<_>>();

    build_pskt_from_utxos(&params, inputs)
}

pub async fn build_pskt_from_rpc(
    rpc: &dyn NodeRpc,
    config: &PsktBuildConfig,
) -> Result<kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Updater>, ThresholdError> {
    build_pskt_with_client(rpc, config).await
}
