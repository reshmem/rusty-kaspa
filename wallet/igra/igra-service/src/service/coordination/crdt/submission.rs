use super::broadcast::broadcast_local_state;
use super::types::CrdtHandlerContext;
use crate::service::coordination::{derive_ordered_pubkeys, params_for_network_id};
use crate::service::flow::ServiceFlow;
use igra_core::application::pskt_multisig;
use igra_core::application::PartialSigRecord;
use igra_core::application::SourceType;
use igra_core::application::StoredEventCrdt;
use igra_core::foundation::{now_nanos, EventId, MetadataKey, ThresholdError, TransactionId, TxTemplateHash};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::{HyperlaneDeliveredMessage, HyperlaneDeliveryRecord, HyperlaneMessageRecord, Storage};
use log::{info, warn};
use std::sync::Arc;

pub(crate) async fn maybe_submit_and_broadcast(
    ctx: &CrdtHandlerContext<'_>,
    event_id: &EventId,
    tx_template_hash: &TxTemplateHash,
) -> Result<(), ThresholdError> {
    let state = ctx.storage.get_event_crdt(event_id, tx_template_hash)?.ok_or_else(|| ThresholdError::MissingCrdtState {
        event_id: event_id.to_string(),
        tx_template_hash: tx_template_hash.to_string(),
        context: "maybe_submit_and_broadcast".to_string(),
    })?;

    if state.completion.is_some() {
        return Ok(());
    }

    // IMPORTANT: `sig_op_count` is *not* the multisig threshold.
    // - `sig_op_count` must be an upper bound for the number of sigops executed by the redeem script (≈ N).
    // - required signatures is the multisig threshold (M) and controls how many signatures we push to the script.
    let required_signatures = ctx
        .app_config
        .group
        .as_ref()
        .map(|g| usize::from(g.threshold_m))
        .or_else(|| ctx.app_config.service.hd.as_ref().map(|hd| hd.required_sigs))
        .ok_or_else(|| ThresholdError::ConfigError("missing group.threshold_m or service.hd.required_sigs".to_string()))?;
    if required_signatures == 0 {
        return Err(ThresholdError::ConfigError("required signatures must be > 0".to_string()));
    }

    let Some(kpsbt_blob) = state.kpsbt_blob.as_deref() else {
        return Ok(());
    };
    let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
    let input_count = signer_pskt.inputs.len();

    if !ctx.storage.crdt_has_threshold(event_id, tx_template_hash, input_count, required_signatures)? {
        return Ok(());
    }

    info!(
        "threshold reached, attempting submission event_id={:#x} tx_template_hash={:#x} sig_count={} required={}",
        event_id,
        tx_template_hash,
        state.signatures.len(),
        required_signatures
    );

    let tx_id = attempt_submission(ctx.app_config, ctx.flow, &state).await?;
    let tx_id = TransactionId::from(tx_id);

    let now = now_nanos();
    let blue_score = ctx.flow.rpc().get_virtual_selected_parent_blue_score().await.ok();
    let (_, changed) = ctx.storage.mark_crdt_completed(event_id, tx_template_hash, tx_id, ctx.local_peer_id, now, blue_score)?;
    if changed {
        info!("CRDT completion recorded event_id={:#x} tx_template_hash={:#x} tx_id={:#x}", event_id, tx_template_hash, tx_id);
        if let Ok(state) = ctx.storage.get_event_crdt(event_id, tx_template_hash) {
            if let Some(state) = state {
                if let Err(err) = maybe_index_hyperlane_delivery(ctx.flow, ctx.storage, event_id, &state).await {
                    warn!("failed to index hyperlane delivery event_id={:#x} error={}", event_id, err);
                }
            }
        }
        broadcast_local_state(ctx.transport, ctx.storage, ctx.phase_storage, ctx.local_peer_id, event_id, tx_template_hash).await?;
    }

    Ok(())
}

pub(crate) async fn handle_completion_if_present(
    ctx: &CrdtHandlerContext<'_>,
    event_id: &EventId,
    state: &StoredEventCrdt,
) -> Result<bool, ThresholdError> {
    if state.completion.is_none() {
        return Ok(false);
    }
    let now = now_nanos();
    if let Err(err) = maybe_index_hyperlane_delivery(ctx.flow, ctx.storage, event_id, state).await {
        warn!("failed to index hyperlane delivery event_id={:#x} error={}", event_id, err);
    }
    ctx.phase_storage.mark_completed(event_id, now)?;
    Ok(true)
}

async fn maybe_index_hyperlane_delivery(
    flow: &ServiceFlow,
    storage: &Arc<dyn Storage>,
    event_id: &EventId,
    state: &StoredEventCrdt,
) -> Result<(), ThresholdError> {
    let Some(completion) = state.completion.as_ref() else {
        return Ok(());
    };
    let Some(event) = storage.get_event(event_id)? else {
        return Ok(());
    };
    if !matches!(event.event.source, SourceType::Hyperlane { .. }) {
        return Ok(());
    }

    let message_id = event.event.external_id;
    if storage.hyperlane_is_message_delivered(&message_id)? {
        return Ok(());
    }

    let daa_score = match flow.kaspa_query().get_virtual_daa_score().await {
        Ok(score) => score,
        Err(_) => completion.blue_score.unwrap_or(0),
    };
    let tx_id = completion.tx_id;
    let delivery = HyperlaneDeliveryRecord { message_id, tx_id, daa_score, timestamp_nanos: completion.timestamp_nanos };

    let meta = &event.audit.source_data;
    let origin = meta.get(MetadataKey::HyperlaneMsgOrigin.as_str()).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let destination = meta.get(MetadataKey::HyperlaneMsgDestination.as_str()).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let nonce = meta.get(MetadataKey::HyperlaneMsgNonce.as_str()).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let sender = meta
        .get(MetadataKey::HyperlaneMsgSender.as_str())
        .and_then(|v| igra_core::foundation::parse_hex_32bytes(v).ok())
        .unwrap_or([0u8; 32]);
    let recipient = meta
        .get(MetadataKey::HyperlaneMsgRecipient.as_str())
        .and_then(|v| igra_core::foundation::parse_hex_32bytes(v).ok())
        .unwrap_or([0u8; 32]);
    let body_hex = meta.get(MetadataKey::HyperlaneMsgBodyHex.as_str()).cloned().unwrap_or_default();
    let log_index = storage.hyperlane_get_delivered_count().unwrap_or(0);

    let message =
        HyperlaneMessageRecord { message_id, sender, recipient, origin, destination, body_hex, nonce, tx_id, daa_score, log_index };
    let delivered = HyperlaneDeliveredMessage { delivery, message };
    let inserted = storage.hyperlane_mark_delivered(&delivered)?;
    if inserted {
        info!(
            "indexed hyperlane delivery message_id={:#x} event_id={:#x} tx_id={:#x} daa_score={}",
            message_id, event_id, tx_id, daa_score
        );
    }
    Ok(())
}

async fn attempt_submission(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    state: &StoredEventCrdt,
) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
    let Some(kpsbt_blob) = state.kpsbt_blob.as_deref() else {
        return Err(ThresholdError::MissingKpsbtBlob {
            event_id: state.event_id.to_string(),
            tx_template_hash: state.tx_template_hash.to_string(),
            context: "attempt_submission".to_string(),
        });
    };

    let partials = state
        .signatures
        .iter()
        .map(|s| PartialSigRecord {
            signer_peer_id: s.signer_peer_id.clone(),
            input_index: s.input_index,
            pubkey: s.pubkey.clone(),
            signature: s.signature.clone(),
            timestamp_nanos: s.timestamp_nanos,
        })
        .collect::<Vec<_>>();

    let pskt = pskt_multisig::apply_partial_sigs(kpsbt_blob, &partials)?;

    let required = app_config
        .group
        .as_ref()
        .map(|g| usize::from(g.threshold_m))
        .or_else(|| app_config.service.hd.as_ref().map(|hd| hd.required_sigs))
        .ok_or_else(|| ThresholdError::ConfigError("missing group.threshold_m or service.hd.required_sigs".to_string()))?;
    let ordered_pubkeys = derive_ordered_pubkeys(&app_config.service)?;
    let params = params_for_network_id(app_config.iroh.network_id);

    if required == 0 || required > ordered_pubkeys.len() {
        return Err(ThresholdError::ConfigError(format!(
            "invalid required signatures: required={required} pubkey_count={}",
            ordered_pubkeys.len()
        )));
    }

    flow.finalize_and_submit(state.event_id, pskt, required, &ordered_pubkeys, params).await
}
