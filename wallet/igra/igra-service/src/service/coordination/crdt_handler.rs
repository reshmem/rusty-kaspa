use crate::service::coordination::{derive_ordered_pubkeys, params_for_network_id};
use crate::service::flow::ServiceFlow;
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::{CrdtSigningMaterial, PartialSigRecord, StoredEvent};
use igra_core::foundation::{EventId, PeerId, ThresholdError, TransactionId, TxTemplateHash};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::RecordSignedHashResult;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::storage::{HyperlaneDeliveredMessage, HyperlaneDeliveryRecord, HyperlaneMessageRecord};
use igra_core::infrastructure::transport::iroh::traits::Transport;
use igra_core::infrastructure::transport::messages::{EventCrdtState, EventStateBroadcast, StateSyncRequest, StateSyncResponse};
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::Arc;

pub struct CrdtHandlerContext<'a> {
    pub app_config: &'a AppConfig,
    pub flow: &'a ServiceFlow,
    pub transport: &'a Arc<dyn Transport>,
    pub storage: &'a Arc<dyn Storage>,
    pub phase_storage: &'a Arc<dyn PhaseStorage>,
    pub local_peer_id: &'a PeerId,
}

async fn validate_commit_candidate(
    ctx: &CrdtHandlerContext<'_>,
    event_id: &EventId,
    tx_template_hash: &TxTemplateHash,
    signing_material: &igra_core::domain::CrdtSigningMaterial,
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

fn sanitize_signing_material<'a>(
    event_id: &EventId,
    signing_material: Option<&'a CrdtSigningMaterial>,
) -> Option<&'a CrdtSigningMaterial> {
    let material = signing_material?;
    if let Err(err) = igra_core::domain::normalization::validate_source_data(&material.audit.source_data) {
        warn!("rejecting CRDT signing_material due to invalid source_data event_id={:#x} error={}", event_id, err);
        return None;
    }
    let computed_event_id = igra_core::domain::hashes::compute_event_id(&material.event);
    if computed_event_id != *event_id {
        warn!("rejecting CRDT signing_material due to mismatched event_id expected={:#x} computed={:#x}", event_id, computed_event_id);
        return None;
    }
    Some(material)
}

fn sanitize_kpsbt_blob<'a>(tx_template_hash: &TxTemplateHash, kpsbt_blob: Option<&'a [u8]>) -> Option<&'a [u8]> {
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

fn record_signed_hash_or_conflict(
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

async fn handle_fast_forward_if_needed(ctx: &CrdtHandlerContext<'_>, broadcast: &EventStateBroadcast) -> Result<(), ThresholdError> {
    let Some(phase_ctx) = broadcast.phase_context else {
        return Ok(());
    };
    if !matches!(
        phase_ctx.phase,
        igra_core::domain::coordination::EventPhase::Committed | igra_core::domain::coordination::EventPhase::Completed
    ) {
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
    if phase_ctx.phase == igra_core::domain::coordination::EventPhase::Completed {
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
        Some(igra_core::domain::coordination::EventPhase::Committed) => {
            if phase.as_ref().and_then(|p| p.canonical_hash) != Some(*tx_template_hash) {
                ctx.flow.metrics().inc_tx_template_hash_mismatch("two_phase_non_canonical");
                return Ok(false);
            }
        }
        Some(igra_core::domain::coordination::EventPhase::Completed)
        | Some(igra_core::domain::coordination::EventPhase::Abandoned) => {
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

async fn handle_completion(
    ctx: &CrdtHandlerContext<'_>,
    event_id: &EventId,
    state: &igra_core::domain::StoredEventCrdt,
) -> Result<bool, ThresholdError> {
    if state.completion.is_none() {
        return Ok(false);
    }
    let now = igra_core::foundation::now_nanos();
    if let Err(err) = maybe_index_hyperlane_delivery(ctx.flow, ctx.storage, event_id, state).await {
        warn!("failed to index hyperlane delivery event_id={:#x} error={}", event_id, err);
    }
    ctx.phase_storage.mark_completed(event_id, now)?;
    Ok(true)
}

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

    if handle_completion(ctx, &event_id, &local_state).await? {
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
        if phase.canonical_hash == Some(*tx_template_hash) && phase.phase == igra_core::domain::coordination::EventPhase::Committed {
            Some(igra_core::domain::coordination::PhaseContext {
                round: phase.round,
                phase: igra_core::domain::coordination::EventPhase::Committed,
            })
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

pub async fn handle_state_sync_request(
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    local_peer_id: &PeerId,
    request: StateSyncRequest,
) -> Result<(), ThresholdError> {
    if request.requester_peer_id == *local_peer_id {
        return Ok(());
    }

    if request.event_ids.is_empty() {
        return Ok(());
    }

    // Bound the work to avoid unbounded CPU/memory on malformed requests.
    const MAX_EVENTS_PER_REQUEST: usize = 256;
    let event_ids = request.event_ids.into_iter().take(MAX_EVENTS_PER_REQUEST).collect::<Vec<_>>();

    debug!("state sync request received requester_peer_id={} event_count={}", request.requester_peer_id, event_ids.len());

    let mut states_out = Vec::new();
    for event_id in event_ids {
        let crdts = storage.list_event_crdts_for_event(&event_id)?;
        for state in crdts {
            let crdt_state = EventCrdtState::from(&state);
            states_out.push((state.event_id, state.tx_template_hash, crdt_state));
        }
    }

    if states_out.is_empty() {
        debug!("state sync request has no matching local states requester_peer_id={}", request.requester_peer_id);
        return Ok(());
    }

    debug!(
        "sending state sync response requester_peer_id={} state_count={} event_ids={}",
        request.requester_peer_id,
        states_out.len(),
        states_out.iter().take(3).map(|(eid, _, _)| format!("{eid:#x}")).collect::<Vec<_>>().join(",")
    );
    transport.publish_state_sync_response(StateSyncResponse { states: states_out }).await
}

pub async fn handle_state_sync_response(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    response: StateSyncResponse,
) -> Result<(), ThresholdError> {
    let ctx = CrdtHandlerContext { app_config, flow, transport, storage, phase_storage, local_peer_id };
    if response.states.is_empty() {
        return Ok(());
    }

    debug!(
        "state sync response received state_count={} event_ids={}",
        response.states.len(),
        response.states.iter().take(3).map(|(eid, _, _)| format!("{eid:#x}")).collect::<Vec<_>>().join(",")
    );

    for (event_id, tx_template_hash, incoming) in response.states {
        let mut phase = phase_storage.get_phase(&event_id)?;

        // State sync can be the first thing a lagging node sees. If we have enough data to validate,
        // use it to fast-forward into Committed so we can merge and sign.
        if !matches!(
            phase.as_ref().map(|p| p.phase),
            Some(igra_core::domain::coordination::EventPhase::Committed)
                | Some(igra_core::domain::coordination::EventPhase::Completed)
                | Some(igra_core::domain::coordination::EventPhase::Abandoned)
        ) {
            let Some(signing_material) = sanitize_signing_material(&event_id, incoming.signing_material.as_ref()) else {
                continue;
            };
            let Some(kpsbt_blob) = sanitize_kpsbt_blob(&tx_template_hash, incoming.kpsbt_blob.as_deref()) else {
                continue;
            };
            validate_commit_candidate(&ctx, &event_id, &tx_template_hash, signing_material, kpsbt_blob).await?;
            if let Some(active) = storage.get_event_active_template_hash(&event_id)? {
                if active != tx_template_hash {
                    continue;
                }
            } else {
                storage.set_event_active_template_hash(&event_id, &tx_template_hash)?;
            }

            let now = now_nanos();
            let round = phase.as_ref().map(|p| p.round).unwrap_or(0);
            let committed = phase_storage.mark_committed(&event_id, round, tx_template_hash, now)?;
            if committed {
                info!(
                    "state sync fast-forward committed event_id={:#x} round={} canonical_hash={:#x}",
                    event_id, round, tx_template_hash
                );
            }
            phase = phase_storage.get_phase(&event_id)?;
        }

        match phase.as_ref().map(|p| p.phase) {
            Some(igra_core::domain::coordination::EventPhase::Committed) => {
                if phase.as_ref().and_then(|p| p.canonical_hash) != Some(tx_template_hash) {
                    continue;
                }
            }
            Some(igra_core::domain::coordination::EventPhase::Completed)
            | Some(igra_core::domain::coordination::EventPhase::Abandoned) => continue,
            _ => continue,
        }

        let signing_material = sanitize_signing_material(&event_id, incoming.signing_material.as_ref());
        let kpsbt_blob = sanitize_kpsbt_blob(&tx_template_hash, incoming.kpsbt_blob.as_deref());
        if signing_material.is_none() && incoming.signing_material.is_some() {
            flow.metrics().inc_tx_template_hash_mismatch("signing_material_invalid");
        }
        if kpsbt_blob.is_none() && incoming.kpsbt_blob.is_some() {
            flow.metrics().inc_tx_template_hash_mismatch("kpsbt_blob_invalid");
        }

        let (local_state, changed) =
            storage.merge_event_crdt(&event_id, &tx_template_hash, &incoming, signing_material, kpsbt_blob)?;
        if !changed {
            continue;
        }

        debug!(
            "state sync merged event_id={:#x} tx_template_hash={:#x} local_sig_count={} completed={}",
            event_id,
            tx_template_hash,
            local_state.signatures.len(),
            local_state.completion.is_some()
        );

        if local_state.completion.is_some() {
            let now = igra_core::foundation::now_nanos();
            phase_storage.mark_completed(&event_id, now)?;
            continue;
        }

        maybe_sign_and_broadcast(&ctx, &local_state).await?;
        maybe_submit_and_broadcast(&ctx, &event_id, &tx_template_hash).await?;
    }

    Ok(())
}

pub async fn run_anti_entropy_loop(
    storage: Arc<dyn Storage>,
    phase_storage: Arc<dyn PhaseStorage>,
    transport: Arc<dyn Transport>,
    local_peer_id: PeerId,
    interval_secs: u64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        match storage.list_pending_event_crdts() {
            Ok(pending) => {
                if !pending.is_empty() {
                    let mut uniq = HashSet::new();
                    let mut event_ids = Vec::new();
                    for state in &pending {
                        if uniq.insert(state.event_id) {
                            event_ids.push(state.event_id);
                        }
                    }

                    if !event_ids.is_empty() {
                        if let Err(err) = transport
                            .publish_state_sync_request(StateSyncRequest { event_ids, requester_peer_id: local_peer_id.clone() })
                            .await
                        {
                            debug!("anti-entropy state sync request failed error={} pending_count={}", err, pending.len());
                        }
                    }
                }

                for state in pending {
                    if let Err(err) = broadcast_local_state(
                        &transport,
                        &storage,
                        &phase_storage,
                        &local_peer_id,
                        &state.event_id,
                        &state.tx_template_hash,
                    )
                    .await
                    {
                        debug!(
                            "anti-entropy broadcast failed event_id={:#x} tx_template_hash={:#x} error={}",
                            state.event_id, state.tx_template_hash, err
                        );
                    }
                }
            }
            Err(err) => warn!("failed to list pending CRDT events: {}", err),
        }

        // Proposal anti-entropy (two-phase): rebroadcast our own proposal while the event is in `Proposing`.
        //
        // This improves liveness under message loss / late joiners, without requiring relays (we only broadcast
        // proposals where `proposer_peer_id == local_peer_id`).
        if let Err(err) = broadcast_pending_proposals(&phase_storage, &transport, &local_peer_id).await {
            warn!("failed to broadcast pending proposals: {}", err);
        }
    }
}

async fn broadcast_pending_proposals(
    phase_storage: &Arc<dyn PhaseStorage>,
    transport: &Arc<dyn Transport>,
    local_peer_id: &PeerId,
) -> Result<(), ThresholdError> {
    const MAX_PROPOSALS_PER_TICK: usize = 64;

    let proposing = phase_storage.get_events_in_phase(igra_core::domain::coordination::EventPhase::Proposing)?;
    if proposing.is_empty() {
        return Ok(());
    }

    let mut sent = 0usize;
    for event_id in proposing {
        if sent >= MAX_PROPOSALS_PER_TICK {
            break;
        }

        let Some(phase) = phase_storage.get_phase(&event_id)? else {
            continue;
        };
        if phase.phase != igra_core::domain::coordination::EventPhase::Proposing {
            continue;
        }

        let proposals = phase_storage.get_proposals(&event_id, phase.round)?;
        let Some(own) = proposals.iter().find(|p| p.proposer_peer_id == *local_peer_id) else {
            continue;
        };

        transport.publish_proposal(own.clone()).await?;
        sent += 1;
    }

    Ok(())
}

pub(crate) async fn maybe_sign_and_broadcast(
    ctx: &CrdtHandlerContext<'_>,
    state: &igra_core::domain::StoredEventCrdt,
) -> Result<(), ThresholdError> {
    if state.completion.is_some() {
        return Ok(());
    }

    if let Some(existing) = ctx.phase_storage.get_signed_hash(&state.event_id)? {
        if existing != state.tx_template_hash {
            return Err(signed_hash_conflict(&state.event_id, existing, state.tx_template_hash));
        }
    }

    if state.signatures.iter().any(|s| &s.signer_peer_id == ctx.local_peer_id) {
        let now = now_nanos();
        record_signed_hash_or_conflict(ctx.phase_storage, &state.event_id, state.tx_template_hash, now)?;
        return Ok(());
    }

    let Some(signing_material) = state.signing_material.as_ref() else {
        debug!(
            "missing signing_material locally; cannot sign event_id={:#x} tx_template_hash={:#x}",
            state.event_id, state.tx_template_hash
        );
        return Ok(());
    };

    let now = now_nanos();

    // Fix #2: ensure we also have an event record for gossip-only ingests
    // (required for accurate daily volume tracking on completion).
    let policy_event = StoredEvent {
        event: signing_material.event.clone(),
        received_at_nanos: now,
        audit: signing_material.audit.clone(),
        proof: signing_material.proof.clone(),
    };
    let inserted = ctx.storage.insert_event_if_not_exists(state.event_id, policy_event.clone())?;
    if inserted {
        debug!(
            "stored event from CRDT signing material event_id={:#x} tx_template_hash={:#x}",
            state.event_id, state.tx_template_hash
        );
    }

    // Fix #1: verify source proof before signing any gossip-originated event.
    let pipeline = igra_core::application::signing_pipeline::SigningPipeline::new(
        ctx.flow.message_verifier_ref(),
        &ctx.app_config.policy,
        ctx.storage.as_ref(),
        now,
    );
    pipeline.verify_and_enforce(&policy_event)?;

    // Fix #3: rebuild the PSKT locally from the verified event data and ensure it matches the CRDT tx_template_hash.
    let kpsbt_blob = state.kpsbt_blob.as_deref().ok_or_else(|| ThresholdError::MissingKpsbtBlob {
        event_id: state.event_id.to_string(),
        tx_template_hash: state.tx_template_hash.to_string(),
        context: "maybe_sign_and_broadcast".to_string(),
    })?;
    pskt_multisig::validate_kpsbt_blob_matches_tx_template_hash(kpsbt_blob, &state.tx_template_hash)?;
    let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;

    let input_count = signer_pskt.inputs.len();
    let (pubkey, sigs) = igra_core::application::pskt_signing::sign_pskt_with_app_config(
        ctx.app_config,
        &ctx.flow.key_context(),
        signer_pskt,
        igra_core::application::pskt_signing::PsktSigningContext {
            event_id: &state.event_id,
            tx_template_hash: &state.tx_template_hash,
            purpose: "maybe_sign_and_broadcast",
        },
    )
    .await?;
    for (input_index, signature) in sigs {
        ctx.storage.add_signature_to_crdt(
            &state.event_id,
            &state.tx_template_hash,
            input_index,
            &pubkey,
            &signature,
            ctx.local_peer_id,
            now,
        )?;
    }
    info!(
        "signed and stored CRDT signatures event_id={:#x} tx_template_hash={:#x} input_count={}",
        state.event_id, state.tx_template_hash, input_count
    );

    record_signed_hash_or_conflict(ctx.phase_storage, &state.event_id, state.tx_template_hash, now)?;

    broadcast_local_state(ctx.transport, ctx.storage, ctx.phase_storage, ctx.local_peer_id, &state.event_id, &state.tx_template_hash)
        .await?;
    Ok(())
}

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

async fn maybe_index_hyperlane_delivery(
    flow: &ServiceFlow,
    storage: &Arc<dyn Storage>,
    event_id: &EventId,
    state: &igra_core::domain::StoredEventCrdt,
) -> Result<(), ThresholdError> {
    let Some(completion) = state.completion.as_ref() else {
        return Ok(());
    };
    let Some(event) = storage.get_event(event_id)? else {
        return Ok(());
    };
    if !matches!(event.event.source, igra_core::domain::SourceType::Hyperlane { .. }) {
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
    let origin = meta.get("hyperlane.msg.origin").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let destination = meta.get("hyperlane.msg.destination").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let nonce = meta.get("hyperlane.msg.nonce").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let sender = meta.get("hyperlane.msg.sender").and_then(|v| igra_core::foundation::parse_hex_32bytes(v).ok()).unwrap_or([0u8; 32]);
    let recipient =
        meta.get("hyperlane.msg.recipient").and_then(|v| igra_core::foundation::parse_hex_32bytes(v).ok()).unwrap_or([0u8; 32]);
    let body_hex = meta.get("hyperlane.msg.body_hex").cloned().unwrap_or_default();
    let log_index = match storage.hyperlane_get_delivered_count() {
        Ok(count) => count,
        Err(_) => 0,
    };

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
    state: &igra_core::domain::StoredEventCrdt,
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

fn now_nanos() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}
