use igra_core::config;
use igra_core::error::ThresholdError;
use igra_core::pskt::multisig as pskt_multisig;
use igra_core::rpc::grpc::GrpcNodeRpc;
use igra_core::rpc::NodeRpc;
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::types::RequestId;
use igra_service::service::coordination;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct FinalizePayload {
    request_id: String,
    pskt_blob: String,
}

/// Finalize PSKT from JSON file.
pub async fn finalize_from_json(
    json_path: &Path,
    storage: &RocksStorage,
    app_config: &config::AppConfig,
) -> Result<(), ThresholdError> {
    tracing::info!("Finalize mode: loading PSKT from {}", json_path.display());

    let json = std::fs::read_to_string(json_path).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let payload: FinalizePayload = serde_json::from_str(&json).map_err(|err| ThresholdError::Message(err.to_string()))?;

    let request_id = RequestId::from(payload.request_id);
    let proposal = storage
        .get_proposal(&request_id)?
        .ok_or_else(|| ThresholdError::KeyNotFound(format!("missing proposal for {}", request_id)))?;
    let partial_sigs = storage.list_partial_sigs(&request_id)?;

    let pskt_blob = hex::decode(payload.pskt_blob.trim()).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let pskt = pskt_multisig::apply_partial_sigs(&pskt_blob, &partial_sigs)?;

    let required = app_config.service.pskt.sig_op_count as usize;
    let ordered_pubkeys = coordination::derive_ordered_pubkeys(&app_config.service, &proposal.signing_event)?;
    let params = coordination::params_for_network_id(app_config.iroh.network_id);

    let finalizer = pskt_multisig::finalize_multisig(pskt, required, &ordered_pubkeys)?;
    let tx = pskt_multisig::extract_tx(finalizer, params)?;
    let rpc = GrpcNodeRpc::connect(app_config.service.node_rpc_url.clone()).await?;
    let tx_id = rpc.submit_transaction(tx).await?;
    storage.update_request_final_tx(&request_id, igra_core::types::TransactionId::from(tx_id))?;

    tracing::info!("Transaction submitted: {}", tx_id);
    println!("Transaction ID: {}", tx_id);

    Ok(())
}
