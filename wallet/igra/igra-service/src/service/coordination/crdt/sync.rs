use super::broadcast::broadcast_local_state;
use super::types::{sanitize_kpsbt_blob, sanitize_signing_material, validate_commit_candidate, CrdtHandlerContext};
use super::{maybe_sign_and_broadcast, maybe_submit_and_broadcast};
use crate::service::flow::ServiceFlow;
use igra_core::foundation::{now_nanos, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::Transport;
use igra_core::infrastructure::transport::messages::{EventCrdtState, StateSyncRequest, StateSyncResponse};
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::Arc;

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
            Some(igra_core::application::EventPhase::Committed)
                | Some(igra_core::application::EventPhase::Completed)
                | Some(igra_core::application::EventPhase::Abandoned)
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
            Some(igra_core::application::EventPhase::Committed) => {
                if phase.as_ref().and_then(|p| p.canonical_hash) != Some(tx_template_hash) {
                    continue;
                }
            }
            Some(igra_core::application::EventPhase::Completed) | Some(igra_core::application::EventPhase::Abandoned) => continue,
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
            let now = now_nanos();
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

    let proposing = phase_storage.get_events_in_phase(igra_core::application::EventPhase::Proposing)?;
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
        if phase.phase != igra_core::application::EventPhase::Proposing {
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
