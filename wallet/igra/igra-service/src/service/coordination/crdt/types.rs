use crate::service::flow::ServiceFlow;
use igra_core::application::pskt_multisig;
use igra_core::application::{CrdtOperations, CrdtSigningMaterial, StoredEvent};
use igra_core::foundation::{now_nanos, EventId, PeerId, ThresholdError, TxTemplateHash};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::RecordSignedHashResult;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::Transport;
use log::{debug, warn};
use std::sync::Arc;

pub struct CrdtHandlerContext<'a> {
    pub app_config: &'a AppConfig,
    pub flow: &'a ServiceFlow,
    pub transport: &'a Arc<dyn Transport>,
    pub storage: &'a Arc<dyn Storage>,
    pub phase_storage: &'a Arc<dyn PhaseStorage>,
    pub local_peer_id: &'a PeerId,
}

pub(crate) async fn validate_commit_candidate(
    ctx: &CrdtHandlerContext<'_>,
    event_id: &EventId,
    tx_template_hash: &TxTemplateHash,
    signing_material: &CrdtSigningMaterial,
    kpsbt_blob: &[u8],
) -> Result<(), ThresholdError> {
    let now = now_nanos();

    let policy_event = StoredEvent {
        event: signing_material.event.clone(),
        received_at_nanos: now,
        audit: signing_material.audit.clone(),
        proof: signing_material.proof.clone(),
    };

    // Verify source proof before accepting any commit fast-forward.
    let pipeline = igra_core::application::signing_pipeline::SigningPipeline::new(
        ctx.flow.message_verifier_ref(),
        &ctx.app_config.policy,
        ctx.storage.as_ref(),
        now,
    );
    pipeline.verify_and_enforce(&policy_event)?;

    // Verify the sender's PSKT matches the claimed tx_template_hash.
    //
    // NOTE: We intentionally do NOT rebuild the PSKT from local RPC state here, since UTXO
    // selection can diverge between nodes. Two-phase ensures we converge by accepting a
    // canonical proposal (including its PSKT), not by independently rebuilding it.
    pskt_multisig::validate_kpsbt_blob_matches_tx_template_hash(kpsbt_blob, tx_template_hash)?;

    let inserted = ctx.storage.insert_event_if_not_exists(*event_id, policy_event)?;
    if inserted {
        debug!("stored event from commit candidate event_id={:#x} tx_template_hash={:#x}", event_id, tx_template_hash);
    }
    Ok(())
}

pub(crate) fn sanitize_signing_material<'a>(
    event_id: &EventId,
    signing_material: Option<&'a CrdtSigningMaterial>,
) -> Option<&'a CrdtSigningMaterial> {
    let material = signing_material?;
    if let Err(err) = CrdtOperations::validate_source_data(&material.audit.source_data) {
        warn!("rejecting CRDT signing_material due to invalid source_data event_id={:#x} error={}", event_id, err);
        return None;
    }
    let computed_event_id = CrdtOperations::compute_event_id(&material.event);
    if computed_event_id != *event_id {
        warn!("rejecting CRDT signing_material due to mismatched event_id expected={:#x} computed={:#x}", event_id, computed_event_id);
        return None;
    }
    Some(material)
}

pub(crate) fn sanitize_kpsbt_blob<'a>(tx_template_hash: &TxTemplateHash, kpsbt_blob: Option<&'a [u8]>) -> Option<&'a [u8]> {
    let blob = kpsbt_blob?;
    let pskt = match pskt_multisig::deserialize_pskt_signer(blob) {
        Ok(pskt) => pskt,
        Err(err) => {
            warn!("rejecting CRDT kpsbt_blob due to decode failure tx_template_hash={:#x} error={}", tx_template_hash, err);
            return None;
        }
    };
    match pskt_multisig::tx_template_hash(&pskt) {
        Ok(computed) if computed == *tx_template_hash => Some(blob),
        Ok(computed) => {
            warn!(
                "rejecting CRDT kpsbt_blob due to tx_template_hash mismatch expected={:#x} computed={:#x}",
                tx_template_hash, computed
            );
            None
        }
        Err(err) => {
            warn!(
                "rejecting CRDT kpsbt_blob due to tx_template_hash computation failure expected={:#x} error={}",
                tx_template_hash, err
            );
            None
        }
    }
}

fn signed_hash_conflict(event_id: &EventId, existing: TxTemplateHash, attempted: TxTemplateHash) -> ThresholdError {
    ThresholdError::SignedHashConflict {
        event_id: event_id.to_string(),
        existing: existing.to_string(),
        attempted: attempted.to_string(),
    }
}

pub(crate) fn record_signed_hash_or_conflict(
    phase_storage: &Arc<dyn PhaseStorage>,
    event_id: &EventId,
    tx_template_hash: TxTemplateHash,
    now: u64,
) -> Result<(), ThresholdError> {
    match phase_storage.record_signed_hash(event_id, tx_template_hash, now)? {
        RecordSignedHashResult::Set | RecordSignedHashResult::AlreadySame => Ok(()),
        RecordSignedHashResult::Conflict { existing, attempted } => Err(signed_hash_conflict(event_id, existing, attempted)),
    }
}

pub(crate) fn signed_hash_conflict_error(event_id: &EventId, existing: TxTemplateHash, attempted: TxTemplateHash) -> ThresholdError {
    signed_hash_conflict(event_id, existing, attempted)
}
