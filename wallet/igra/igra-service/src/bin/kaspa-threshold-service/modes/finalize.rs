use igra_core::application::pskt_multisig;
use igra_core::application::PartialSigRecord;
use igra_core::foundation::{EventId, PeerId, ThresholdError, TransactionId};
use igra_core::infrastructure::config;
use igra_core::infrastructure::rpc::GrpcNodeRpc;
use igra_core::infrastructure::rpc::NodeRpc;
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::storage::Storage;
use igra_service::service::coordination::{derive_ordered_pubkeys, params_for_network_id};
use log::info;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct FinalizePayload {
    #[serde(alias = "request_id")]
    event_id: String,
    pskt_blob: String,
}

/// Finalize PSKT from JSON file.
pub async fn finalize_from_json(
    json_path: &Path,
    storage: &RocksStorage,
    app_config: &config::AppConfig,
) -> Result<(), ThresholdError> {
    info!("Finalize mode: loading PSKT from {}", json_path.display());

    let json = std::fs::read_to_string(json_path).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let payload: FinalizePayload = serde_json::from_str(&json)?;

    let event_id: EventId = payload.event_id.parse()?;
    let pskt_blob = hex::decode(payload.pskt_blob.trim()).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let signer_pskt = pskt_multisig::deserialize_pskt_signer(&pskt_blob)?;
    let tx_template_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;

    let state = storage
        .get_event_crdt(&event_id, &tx_template_hash)?
        .ok_or_else(|| ThresholdError::KeyNotFound(format!("missing CRDT state for event_id={}", event_id)))?;

    let partial_sigs = state
        .signatures
        .into_iter()
        .map(|s| PartialSigRecord {
            signer_peer_id: s.signer_peer_id,
            input_index: s.input_index,
            pubkey: s.pubkey,
            signature: s.signature,
            timestamp_nanos: s.timestamp_nanos,
        })
        .collect::<Vec<_>>();

    let pskt = pskt_multisig::apply_partial_sigs(&pskt_blob, &partial_sigs)?;

    let required = app_config.service.pskt.sig_op_count as usize;
    let ordered_pubkeys = derive_ordered_pubkeys(&app_config.service)?;
    let params = params_for_network_id(app_config.iroh.network_id);

    let finalize_result = pskt_multisig::finalize_multisig(pskt, required, &ordered_pubkeys)?;
    let tx_result = pskt_multisig::extract_tx(finalize_result.pskt, params)?;
    let tx = tx_result.tx;
    let rpc = GrpcNodeRpc::connect(app_config.service.node_rpc_url.clone()).await?;
    let tx_id = rpc.submit_transaction(tx).await?;
    let blue_score = rpc.get_virtual_selected_parent_blue_score().await.ok();
    let submitter_peer_id = PeerId::from("manual-finalize");
    let now = igra_core::foundation::now_nanos();
    storage.mark_crdt_completed(&event_id, &tx_template_hash, TransactionId::from(tx_id), &submitter_peer_id, now, blue_score)?;

    info!("Transaction submitted: {}", tx_id);
    println!("Transaction ID: {}", tx_id);

    Ok(())
}
