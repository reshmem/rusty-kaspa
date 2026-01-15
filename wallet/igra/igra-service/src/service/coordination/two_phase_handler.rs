use crate::service::coordination::crdt_handler::{maybe_sign_and_broadcast, maybe_submit_and_broadcast};
use crate::service::flow::ServiceFlow;
use igra_core::domain::coordination::{EventPhase, PhaseContext, ProposalBroadcast, TwoPhaseConfig};
use igra_core::domain::{CrdtSigningMaterial, StoredEvent};
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::phase::{PhaseStorage, StoreProposalResult};
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::Transport;
use igra_core::infrastructure::transport::messages::{EventCrdtState, EventStateBroadcast};
use kaspa_addresses::Address;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::Arc;

fn should_bump_round_after_commit_failure(err: &ThresholdError) -> bool {
    matches!(err, ThresholdError::UtxoMissing { .. } | ThresholdError::UtxoBelowMinDepth { .. })
}

async fn publish_local_proposal_if_missing(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    event_id: Hash32,
    round: u32,
) -> Result<(), ThresholdError> {
    let Some(phase) = phase_storage.get_phase(&event_id)? else { return Ok(()) };
    if phase.phase.is_terminal() || phase.phase == EventPhase::Committed {
        return Ok(());
    }
    if phase.round != round {
        return Ok(());
    }
    if phase_storage.has_proposal_from(&event_id, round, local_peer_id)? {
        return Ok(());
    }

    let Some(event) = storage.get_event(&event_id)? else {
        return Ok(());
    };

    let now_ns = igra_core::foundation::now_nanos();
    let (proposal, _anchor) = igra_core::application::two_phase::build_local_proposal_for_round(
        flow.rpc().as_ref(),
        &app_config.service,
        &event,
        local_peer_id,
        round,
        now_ns,
    )
    .await?;

    match phase_storage.store_proposal(&proposal)? {
        StoreProposalResult::Stored | StoreProposalResult::DuplicateFromPeer => {
            phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
            transport.publish_proposal(proposal.clone()).await?;
            info!(
                "two-phase published local proposal (on receive) event_id={} round={} tx_template_hash={}",
                hex::encode(event_id),
                round,
                hex::encode(proposal.tx_template_hash)
            );
        }
        _ => {}
    }

    Ok(())
}

pub async fn handle_proposal_broadcast(
    app_config: &AppConfig,
    two_phase: &TwoPhaseConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    sender_peer_id: &PeerId,
    proposal: ProposalBroadcast,
) -> Result<(), ThresholdError> {
    if proposal.proposer_peer_id != *sender_peer_id {
        return Err(ThresholdError::InvalidPeerIdentity);
    }

    proposal.validate_structure().map_err(|e| ThresholdError::ProposalValidationFailed { details: e.to_string() })?;
    proposal.verify_hash_consistency().map_err(|e| ThresholdError::ProposalValidationFailed { details: e.to_string() })?;

    // Verify signing material hashes to the claimed event_id.
    let computed_event_id = igra_core::domain::hashes::compute_event_id(&proposal.signing_material.event);
    if computed_event_id != proposal.event_id {
        return Err(ThresholdError::ProposalEventIdMismatch {
            claimed: hex::encode(proposal.event_id),
            computed: hex::encode(computed_event_id),
        });
    }

    // Verify external message proof for the event (cheap gating for DoS/bugs).
    let stored = stored_event_from_signing_material(&proposal.signing_material);
    let report = flow.message_verifier().verify(&stored)?;
    if !report.valid {
        return Err(ThresholdError::EventSignatureInvalid);
    }

    // Enforce policy (same as signing path).
    crate::service::coordination::crdt_handler::validate_before_signing(flow, &app_config.policy, &stored).await?;

    // Ensure we persist the event (idempotent).
    let _ = storage.insert_event_if_not_exists(proposal.event_id, stored)?;

    match phase_storage.store_proposal(&proposal)? {
        StoreProposalResult::Stored => {
            let count = phase_storage.proposal_count(&proposal.event_id, proposal.round)?;
            info!(
                "two-phase stored proposal event_id={} round={} proposer_peer_id={} tx_template_hash={} proposal_count={}",
                hex::encode(proposal.event_id),
                proposal.round,
                proposal.proposer_peer_id,
                hex::encode(proposal.tx_template_hash),
                count
            );
            try_commit_and_sign(
                app_config,
                two_phase,
                flow,
                transport,
                storage,
                phase_storage,
                local_peer_id,
                proposal.event_id,
                proposal.round,
            )
            .await?;

            if let Err(err) = publish_local_proposal_if_missing(
                app_config,
                flow,
                transport,
                storage,
                phase_storage,
                local_peer_id,
                proposal.event_id,
                proposal.round,
            )
            .await
            {
                warn!(
                    "two-phase failed to publish local proposal on receive event_id={} round={} error={}",
                    hex::encode(proposal.event_id),
                    proposal.round,
                    err
                );
            }
        }
        StoreProposalResult::DuplicateFromPeer => {
            debug!(
                "two-phase duplicate proposal event_id={} round={} proposer_peer_id={} tx_template_hash={}",
                hex::encode(proposal.event_id),
                proposal.round,
                proposal.proposer_peer_id,
                hex::encode(proposal.tx_template_hash)
            );
            try_commit_and_sign(
                app_config,
                two_phase,
                flow,
                transport,
                storage,
                phase_storage,
                local_peer_id,
                proposal.event_id,
                proposal.round,
            )
            .await?;

            if let Err(err) = publish_local_proposal_if_missing(
                app_config,
                flow,
                transport,
                storage,
                phase_storage,
                local_peer_id,
                proposal.event_id,
                proposal.round,
            )
            .await
            {
                warn!(
                    "two-phase failed to publish local proposal on receive event_id={} round={} error={}",
                    hex::encode(proposal.event_id),
                    proposal.round,
                    err
                );
            }
        }
        StoreProposalResult::Equivocation { existing_hash, new_hash } => {
            warn!(
                "equivocation detected event_id={} proposer_peer_id={} existing_hash={} new_hash={}",
                hex::encode(proposal.event_id),
                proposal.proposer_peer_id,
                hex::encode(existing_hash),
                hex::encode(new_hash)
            );
        }
        StoreProposalResult::PhaseTooLate => {}
        StoreProposalResult::RoundMismatch { expected, got } => {
            if got <= expected {
                debug!(
                    "proposal round mismatch (stale) event_id={} expected_round={} got_round={}",
                    hex::encode(proposal.event_id),
                    expected,
                    got
                );
                return Ok(());
            }

            // We're behind. Adopt the higher round and retry storing this proposal.
            let now_ns = igra_core::foundation::now_nanos();
            let adopted = phase_storage.adopt_round_if_behind(&proposal.event_id, got, now_ns)?;
            if adopted {
                let _ = phase_storage.clear_stale_proposals(&proposal.event_id, got)?;
                info!(
                    "two-phase adopted higher round event_id={} from_round={} to_round={}",
                    hex::encode(proposal.event_id),
                    expected,
                    got
                );
            }

            match phase_storage.store_proposal(&proposal)? {
                StoreProposalResult::Stored => {
                    let count = phase_storage.proposal_count(&proposal.event_id, proposal.round)?;
                    info!(
                        "two-phase stored proposal event_id={} round={} proposer_peer_id={} tx_template_hash={} proposal_count={}",
                        hex::encode(proposal.event_id),
                        proposal.round,
                        proposal.proposer_peer_id,
                        hex::encode(proposal.tx_template_hash),
                        count
                    );
                    try_commit_and_sign(
                        app_config,
                        two_phase,
                        flow,
                        transport,
                        storage,
                        phase_storage,
                        local_peer_id,
                        proposal.event_id,
                        proposal.round,
                    )
                    .await?;

                    if let Err(err) = publish_local_proposal_if_missing(
                        app_config,
                        flow,
                        transport,
                        storage,
                        phase_storage,
                        local_peer_id,
                        proposal.event_id,
                        proposal.round,
                    )
                    .await
                    {
                        warn!(
                            "two-phase failed to publish local proposal on receive event_id={} round={} error={}",
                            hex::encode(proposal.event_id),
                            proposal.round,
                            err
                        );
                    }
                }
                StoreProposalResult::DuplicateFromPeer => {
                    try_commit_and_sign(
                        app_config,
                        two_phase,
                        flow,
                        transport,
                        storage,
                        phase_storage,
                        local_peer_id,
                        proposal.event_id,
                        proposal.round,
                    )
                    .await?;

                    if let Err(err) = publish_local_proposal_if_missing(
                        app_config,
                        flow,
                        transport,
                        storage,
                        phase_storage,
                        local_peer_id,
                        proposal.event_id,
                        proposal.round,
                    )
                    .await
                    {
                        warn!(
                            "two-phase failed to publish local proposal on receive event_id={} round={} error={}",
                            hex::encode(proposal.event_id),
                            proposal.round,
                            err
                        );
                    }
                }
                StoreProposalResult::Equivocation { existing_hash, new_hash } => {
                    warn!(
                        "equivocation detected event_id={} proposer_peer_id={} existing_hash={} new_hash={}",
                        hex::encode(proposal.event_id),
                        proposal.proposer_peer_id,
                        hex::encode(existing_hash),
                        hex::encode(new_hash)
                    );
                }
                StoreProposalResult::PhaseTooLate | StoreProposalResult::RoundMismatch { .. } => {}
            }
        }
    }

    Ok(())
}

pub async fn try_commit_and_sign(
    app_config: &AppConfig,
    two_phase: &TwoPhaseConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
    event_id: Hash32,
    round: u32,
) -> Result<(), ThresholdError> {
    let Some(phase) = phase_storage.get_phase(&event_id)? else {
        return Ok(());
    };
    if phase.phase != EventPhase::Proposing || phase.round != round {
        return Ok(());
    }

    let proposals = phase_storage.get_proposals(&event_id, round)?;
    let commit_quorum = usize::from(two_phase.commit_quorum);
    let Some(canonical) = igra_core::domain::coordination::selection::select_canonical_proposal_for_commit(&proposals, commit_quorum) else {
        return Ok(());
    };

    let canonical_hash = canonical.tx_template_hash;

    if two_phase.revalidate_inputs_on_commit {
        if let Err(err) = revalidate_inputs(flow, &app_config.service, &canonical, two_phase.min_input_score_depth).await {
            warn!(
                "two-phase commit revalidation failed event_id={} round={} canonical_hash={} error={}",
                hex::encode(event_id),
                round,
                hex::encode(canonical_hash),
                err
            );

            if should_bump_round_after_commit_failure(&err) {
                let now = igra_core::foundation::now_nanos();
                if phase_storage.fail_and_bump_round(&event_id, round, now)? {
                    let _ = phase_storage.clear_stale_proposals(&event_id, round.saturating_add(1))?;
                }
            }
            return Ok(());
        }
    }

    let now = igra_core::foundation::now_nanos();
    let committed = phase_storage.mark_committed(&event_id, round, canonical_hash, now)?;
    if !committed {
        return Ok(());
    }

    storage.set_event_active_template_hash(&event_id, &canonical_hash)?;

    let empty_state = EventCrdtState { signatures: vec![], completion: None, signing_material: None, kpsbt_blob: None, version: 0 };
    let _ = storage.merge_event_crdt(
        &event_id,
        &canonical_hash,
        &empty_state,
        Some(&canonical.signing_material),
        Some(&canonical.kpsbt_blob),
    )?;

    let state = storage
        .get_event_crdt(&event_id, &canonical_hash)?
        .ok_or_else(|| ThresholdError::MissingCrdtState {
            event_id: hex::encode(event_id),
            tx_template_hash: hex::encode(canonical_hash),
            context: "after commit init".to_string(),
        })?;

    info!(
        "two-phase committed event_id={} round={} canonical_hash={} proposal_count={}",
        hex::encode(event_id),
        round,
        hex::encode(canonical_hash),
        proposals.len()
    );

    transport
        .publish_event_state(EventStateBroadcast {
            event_id,
            tx_template_hash: canonical_hash,
            state: EventCrdtState::from(&state),
            sender_peer_id: local_peer_id.clone(),
            phase_context: Some(PhaseContext { round, phase: EventPhase::Committed }),
        })
        .await?;

    // Continue existing CRDT flow locally (sign + submit if threshold reached).
    maybe_sign_and_broadcast(app_config, flow, transport, storage, phase_storage, local_peer_id, &state).await?;
    maybe_submit_and_broadcast(app_config, flow, transport, storage, phase_storage, local_peer_id, &event_id, &canonical_hash).await?;

    Ok(())
}

fn stored_event_from_signing_material(material: &CrdtSigningMaterial) -> StoredEvent {
    StoredEvent {
        event: material.event.clone(),
        received_at_nanos: igra_core::foundation::now_nanos(),
        audit: material.audit.clone(),
        proof: material.proof.clone(),
    }
}

async fn revalidate_inputs(
    flow: &ServiceFlow,
    service: &igra_core::infrastructure::config::ServiceConfig,
    proposal: &ProposalBroadcast,
    min_input_score_depth: u64,
) -> Result<(), ThresholdError> {
    let tip = flow.rpc().get_virtual_selected_parent_blue_score().await?;
    igra_core::application::two_phase::revalidate_utxos_for_proposal(tip, proposal, min_input_score_depth)?;

    // Verify outpoints still appear in the node UTXO set (best-effort).
    let addresses = service.pskt.source_addresses.iter().map(|addr| Address::constructor(addr)).collect::<Vec<_>>();
    let utxos = flow.rpc().get_utxos_by_addresses(&addresses).await?;
    let available = utxos.iter().map(|u| u.outpoint).collect::<HashSet<_>>();
    for input in &proposal.utxos_used {
        if !available.contains(&input.outpoint) {
            return Err(ThresholdError::UtxoMissing { outpoint: input.outpoint.to_string() });
        }
    }
    Ok(())
}
