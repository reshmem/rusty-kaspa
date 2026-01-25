use super::submission::handle_completion_if_present;
use super::types::{sanitize_kpsbt_blob, sanitize_signing_material, validate_commit_candidate, CrdtHandlerContext};
use super::{maybe_sign_and_broadcast, maybe_submit_and_broadcast};
use igra_core::application::StoredEvent;
use igra_core::foundation::{now_nanos, EventId, PeerId, ThresholdError, TxTemplateHash};
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::Transport;
use igra_core::infrastructure::transport::messages::{EventCrdtState, EventStateBroadcast};
use log::{debug, info, warn};
use std::sync::Arc;

pub async fn handle_crdt_broadcast(ctx: &CrdtHandlerContext<'_>, broadcast: EventStateBroadcast) -> Result<(), ThresholdError> {
    let event_id = broadcast.event_id;
    let tx_template_hash = broadcast.tx_template_hash;

    handle_fast_forward_if_needed(ctx, &broadcast).await?;
    if !should_merge_broadcast(ctx, &event_id, &tx_template_hash)? {
        return Ok(());
    }

    warn_if_local_has_other_hashes(ctx, &event_id, &tx_template_hash);

    info!(
        "received CRDT broadcast event_id={:#x} tx_template_hash={:#x} from_peer={} sig_count={} completed={}",
        event_id,
        tx_template_hash,
        broadcast.sender_peer_id,
        broadcast.state.signatures.len(),
        broadcast.state.completion.is_some()
    );

    let signing_material = sanitize_signing_material(&event_id, broadcast.state.signing_material.as_ref());
    let kpsbt_blob = sanitize_kpsbt_blob(&tx_template_hash, broadcast.state.kpsbt_blob.as_deref());
    if signing_material.is_none() && broadcast.state.signing_material.is_some() {
        ctx.flow.metrics().inc_tx_template_hash_mismatch("signing_material_invalid");
    }
    if kpsbt_blob.is_none() && broadcast.state.kpsbt_blob.is_some() {
        ctx.flow.metrics().inc_tx_template_hash_mismatch("kpsbt_blob_invalid");
    }

    let (local_state, changed) =
        ctx.storage.merge_event_crdt(&event_id, &tx_template_hash, &broadcast.state, signing_material, kpsbt_blob)?;
    if !changed {
        debug!("CRDT merge no-op event_id={:#x} tx_template_hash={:#x}", event_id, tx_template_hash);
        return Ok(());
    }

    info!(
        "CRDT merged event_id={:#x} tx_template_hash={:#x} local_sig_count={} completed={}",
        event_id,
        tx_template_hash,
        local_state.signatures.len(),
        local_state.completion.is_some()
    );

    if handle_completion_if_present(ctx, &event_id, &local_state).await? {
        return Ok(());
    }

    maybe_sign_and_broadcast(ctx, &local_state).await?;
    maybe_submit_and_broadcast(ctx, &event_id, &tx_template_hash).await?;
    Ok(())
}

pub async fn broadcast_local_state(
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    event_id: &EventId,
    tx_template_hash: &TxTemplateHash,
) -> Result<(), ThresholdError> {
    let state = storage.get_event_crdt(event_id, tx_template_hash)?.ok_or_else(|| ThresholdError::MissingCrdtState {
        event_id: event_id.to_string(),
        tx_template_hash: tx_template_hash.to_string(),
        context: "broadcast_local_state".to_string(),
    })?;

    let crdt_state = EventCrdtState::from(&state);
    let phase_context = phase_storage.get_phase(event_id)?.and_then(|phase| {
        if phase.canonical_hash == Some(*tx_template_hash) && phase.phase == igra_core::application::EventPhase::Committed {
            Some(igra_core::application::PhaseContext { round: phase.round, phase: igra_core::application::EventPhase::Committed })
        } else {
            None
        }
    });

    transport
        .publish_event_state(EventStateBroadcast {
            event_id: *event_id,
            tx_template_hash: *tx_template_hash,
            state: crdt_state,
            sender_peer_id: local_peer_id.clone(),
            phase_context,
        })
        .await
}

async fn handle_fast_forward_if_needed(ctx: &CrdtHandlerContext<'_>, broadcast: &EventStateBroadcast) -> Result<(), ThresholdError> {
    let Some(phase_ctx) = broadcast.phase_context else {
        return Ok(());
    };
    if !matches!(phase_ctx.phase, igra_core::application::EventPhase::Committed | igra_core::application::EventPhase::Completed) {
        return Ok(());
    }

    let event_id = broadcast.event_id;
    let tx_template_hash = broadcast.tx_template_hash;

    let Some(signing_material) = sanitize_signing_material(&event_id, broadcast.state.signing_material.as_ref()) else {
        return Ok(());
    };

    let Some(kpsbt_blob) = sanitize_kpsbt_blob(&tx_template_hash, broadcast.state.kpsbt_blob.as_deref()) else {
        if broadcast.state.kpsbt_blob.is_none() {
            let now = now_nanos();
            let policy_event = StoredEvent {
                event: signing_material.event.clone(),
                received_at_nanos: now,
                audit: signing_material.audit.clone(),
                proof: signing_material.proof.clone(),
            };
            let pipeline = igra_core::application::signing_pipeline::SigningPipeline::new(
                ctx.flow.message_verifier_ref(),
                &ctx.app_config.policy,
                ctx.storage.as_ref(),
                now,
            );
            pipeline.verify_and_enforce(&policy_event)?;
            return Err(ThresholdError::PsktMismatch {
                expected: tx_template_hash.to_string(),
                actual: "missing kpsbt_blob".to_string(),
            });
        }
        return Ok(());
    };

    validate_commit_candidate(ctx, &event_id, &tx_template_hash, signing_material, kpsbt_blob).await?;

    if let Some(active) = ctx.storage.get_event_active_template_hash(&event_id)? {
        if active != tx_template_hash {
            ctx.flow.metrics().inc_tx_template_hash_mismatch("two_phase_fast_forward_active_mismatch");
            return Ok(());
        }
    } else {
        ctx.storage.set_event_active_template_hash(&event_id, &tx_template_hash)?;
    }

    let now = now_nanos();
    let committed = ctx.phase_storage.mark_committed(&event_id, phase_ctx.round, tx_template_hash, now)?;
    if committed {
        info!(
            "two-phase fast-forward committed event_id={:#x} round={} canonical_hash={:#x} phase={:?}",
            event_id, phase_ctx.round, tx_template_hash, phase_ctx.phase
        );
    }
    if phase_ctx.phase == igra_core::application::EventPhase::Completed {
        ctx.phase_storage.mark_completed(&event_id, now)?;
    }
    Ok(())
}

fn should_merge_broadcast(
    ctx: &CrdtHandlerContext<'_>,
    event_id: &EventId,
    tx_template_hash: &TxTemplateHash,
) -> Result<bool, ThresholdError> {
    let phase = ctx.phase_storage.get_phase(event_id)?;
    match phase.as_ref().map(|p| p.phase) {
        Some(igra_core::application::EventPhase::Committed) => {
            if phase.as_ref().and_then(|p| p.canonical_hash) != Some(*tx_template_hash) {
                ctx.flow.metrics().inc_tx_template_hash_mismatch("two_phase_non_canonical");
                return Ok(false);
            }
        }
        Some(igra_core::application::EventPhase::Completed) | Some(igra_core::application::EventPhase::Abandoned) => {
            return Ok(false);
        }
        _ => {
            // Pre-commit: do not merge CRDT state (avoids early active-template lock).
            return Ok(false);
        }
    }
    Ok(true)
}

fn warn_if_local_has_other_hashes(ctx: &CrdtHandlerContext<'_>, event_id: &EventId, tx_template_hash: &TxTemplateHash) {
    let Ok(existing) = ctx.storage.list_event_crdts_for_event(event_id) else { return };
    let mut other_hashes =
        existing.iter().filter(|s| s.tx_template_hash != *tx_template_hash).map(|s| s.tx_template_hash).collect::<Vec<_>>();
    other_hashes.sort();
    other_hashes.dedup();
    if other_hashes.is_empty() {
        return;
    }

    warn!(
        "received CRDT broadcast with tx_template_hash mismatch against local states event_id={:#x} received_tx_template_hash={:#x} local_other_tx_template_hashes={}",
        event_id,
        tx_template_hash,
        other_hashes.iter().take(3).map(|h| format!("{h:#x}")).collect::<Vec<_>>().join(",")
    );
    ctx.flow.metrics().inc_tx_template_hash_mismatch("network");
}
