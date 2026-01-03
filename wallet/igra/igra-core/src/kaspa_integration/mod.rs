use crate::error::ThresholdError;
use crate::pskt::builder::build_pskt_with_client;
use crate::rpc::NodeRpc;

pub use crate::pskt::builder::build_pskt_with_client as build_pskt;

pub async fn submit_transaction(
    rpc: &dyn NodeRpc,
    tx: kaspa_consensus_core::tx::Transaction,
) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
    rpc.submit_transaction(tx).await
}

pub async fn build_pskt_from_rpc(
    rpc: &dyn NodeRpc,
    config: &crate::config::PsktBuildConfig,
) -> Result<kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Updater>, ThresholdError> {
    build_pskt_with_client(rpc, config).await
}
