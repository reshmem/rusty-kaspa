use crate::service::coordination::crdt_handler::{maybe_sign_and_broadcast, maybe_submit_and_broadcast, CrdtHandlerContext};
use crate::service::flow::ServiceFlow;
use igra_core::domain::coordination::{EventPhase, PhaseContext, ProposalBroadcast, TwoPhaseConfig};
use igra_core::domain::{CrdtSigningMaterial, StoredEvent};
use igra_core::foundation::{EventId, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::phase::{PhaseStorage, StoreProposalResult};
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::Transport;
use igra_core::infrastructure::transport::messages::{EventCrdtState, EventStateBroadcast};
use kaspa_addresses::Address;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::Arc;

pub struct TwoPhaseHandlerContext<'a> {
    pub app_config: &'a AppConfig,
    pub two_phase: &'a TwoPhaseConfig,
    pub flow: &'a ServiceFlow,
    pub transport: &'a Arc<dyn Transport>,
    pub storage: &'a Arc<dyn Storage>,
    pub phase_storage: &'a Arc<dyn PhaseStorage>,
    pub local_peer_id: &'a PeerId,
}

fn should_bump_round_after_commit_failure(err: &ThresholdError) -> bool {
    matches!(err, ThresholdError::UtxoMissing { .. } | ThresholdError::UtxoBelowMinDepth { .. })
}

async fn publish_local_proposal_if_missing(
    ctx: &TwoPhaseHandlerContext<'_>,
    event_id: EventId,
    round: u32,
) -> Result<(), ThresholdError> {
    let Some(phase) = ctx.phase_storage.get_phase(&event_id)? else { return Ok(()) };
    if phase.phase.is_terminal() || phase.phase == EventPhase::Committed {
        return Ok(());
    }
    if phase.round != round {
        return Ok(());
    }
    if ctx.phase_storage.has_proposal_from(&event_id, round, ctx.local_peer_id)? {
        return Ok(());
    }

    let Some(event) = ctx.storage.get_event(&event_id)? else {
        return Ok(());
    };

    let now_ns = igra_core::foundation::now_nanos();
    let (proposal, _anchor) = igra_core::application::two_phase::build_local_proposal_for_round(
        ctx.flow.rpc().as_ref(),
        &ctx.app_config.service,
        &event,
        ctx.local_peer_id,
        round,
        now_ns,
    )
    .await?;

    match ctx.phase_storage.store_proposal(&proposal)? {
        StoreProposalResult::Stored | StoreProposalResult::DuplicateFromPeer => {
            ctx.phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
            ctx.transport.publish_proposal(proposal.clone()).await?;
            info!(
                "two-phase published local proposal (on receive) event_id={:#x} round={} tx_template_hash={:#x}",
                event_id, round, proposal.tx_template_hash
            );
        }
        _ => {}
    }

    Ok(())
}

struct ValidatedProposal {
    proposal: ProposalBroadcast,
    stored_event: StoredEvent,
}

fn validate_proposal(
    ctx: &TwoPhaseHandlerContext<'_>,
    sender_peer_id: &PeerId,
    proposal: ProposalBroadcast,
) -> Result<ValidatedProposal, ThresholdError> {
    if proposal.proposer_peer_id != *sender_peer_id {
        return Err(ThresholdError::InvalidPeerIdentity);
    }

    proposal.validate_structure().map_err(|e| ThresholdError::ProposalValidationFailed { details: e.to_string() })?;
    proposal.verify_hash_consistency().map_err(|e| ThresholdError::ProposalValidationFailed { details: e.to_string() })?;

    let computed_event_id = igra_core::domain::hashes::compute_event_id(&proposal.signing_material.event);
    if computed_event_id != proposal.event_id {
        return Err(ThresholdError::ProposalEventIdMismatch {
            claimed: proposal.event_id.to_string(),
            computed: computed_event_id.to_string(),
        });
    }

    let stored_event = stored_event_from_signing_material(&proposal.signing_material);
    let now = igra_core::foundation::now_nanos();
    let pipeline = igra_core::application::signing_pipeline::SigningPipeline::new(
        ctx.flow.message_verifier_ref(),
        &ctx.app_config.policy,
        ctx.storage.as_ref(),
        now,
    );
    pipeline.verify_and_enforce(&stored_event)?;

    Ok(ValidatedProposal { proposal, stored_event })
}

fn store_proposal_with_retry(
    ctx: &TwoPhaseHandlerContext<'_>,
    proposal: &ProposalBroadcast,
) -> Result<StoreProposalResult, ThresholdError> {
    match ctx.phase_storage.store_proposal(proposal)? {
        StoreProposalResult::RoundMismatch { expected, got } => {
            if got <= expected {
                debug!(
                    "proposal round mismatch (stale) event_id={:#x} expected_round={} got_round={}",
                    proposal.event_id, expected, got
                );
                return Ok(StoreProposalResult::RoundMismatch { expected, got });
            }

            let now_ns = igra_core::foundation::now_nanos();
            let adopted = ctx.phase_storage.adopt_round_if_behind(&proposal.event_id, got, now_ns)?;
            if adopted {
                let cleared = ctx.phase_storage.clear_stale_proposals(&proposal.event_id, got)?;
                info!(
                    "two-phase adopted higher round event_id={:#x} from_round={} to_round={} cleared_stale={}",
                    proposal.event_id, expected, got, cleared
                );
            }
            ctx.phase_storage.store_proposal(proposal)
        }
        other => Ok(other),
    }
}

async fn after_proposal_stored(
    ctx: &TwoPhaseHandlerContext<'_>,
    proposal: &ProposalBroadcast,
    result: &StoreProposalResult,
) -> Result<(), ThresholdError> {
    match result {
        StoreProposalResult::Stored => {
            let count = ctx.phase_storage.proposal_count(&proposal.event_id, proposal.round)?;
            info!(
                "two-phase stored proposal event_id={:#x} round={} proposer_peer_id={} tx_template_hash={:#x} proposal_count={}",
                proposal.event_id, proposal.round, proposal.proposer_peer_id, proposal.tx_template_hash, count
            );
        }
        StoreProposalResult::DuplicateFromPeer => {
            debug!(
                "two-phase duplicate proposal event_id={:#x} round={} proposer_peer_id={} tx_template_hash={:#x}",
                proposal.event_id, proposal.round, proposal.proposer_peer_id, proposal.tx_template_hash
            );
        }
        StoreProposalResult::Equivocation { existing_hash, new_hash } => {
            warn!(
                "equivocation detected event_id={:#x} round={} proposer_peer_id={} existing_hash={:#x} new_hash={:#x}",
                proposal.event_id, proposal.round, proposal.proposer_peer_id, existing_hash, new_hash
            );
        }
        StoreProposalResult::PhaseTooLate => return Ok(()),
        StoreProposalResult::RoundMismatch { .. } => return Ok(()),
    }

    if matches!(result, StoreProposalResult::Stored | StoreProposalResult::DuplicateFromPeer) {
        try_commit_and_sign(ctx, proposal.event_id, proposal.round).await?;
        if let Err(err) = publish_local_proposal_if_missing(ctx, proposal.event_id, proposal.round).await {
            warn!(
                "two-phase failed to publish local proposal on receive event_id={:#x} round={} error={}",
                proposal.event_id, proposal.round, err
            );
        }
    }

    Ok(())
}

pub async fn handle_proposal_broadcast(
    ctx: &TwoPhaseHandlerContext<'_>,
    sender_peer_id: &PeerId,
    proposal: ProposalBroadcast,
) -> Result<(), ThresholdError> {
    let ValidatedProposal { proposal, stored_event } = validate_proposal(ctx, sender_peer_id, proposal)?;
    let inserted = ctx.storage.insert_event_if_not_exists(proposal.event_id, stored_event)?;
    if inserted {
        debug!("stored event from proposal broadcast event_id={:#x} round={}", proposal.event_id, proposal.round);
    }

    let result = store_proposal_with_retry(ctx, &proposal)?;
    after_proposal_stored(ctx, &proposal, &result).await?;
    Ok(())
}

pub async fn try_commit_and_sign(ctx: &TwoPhaseHandlerContext<'_>, event_id: EventId, round: u32) -> Result<(), ThresholdError> {
    let Some(phase) = ctx.phase_storage.get_phase(&event_id)? else {
        return Ok(());
    };
    if phase.phase != EventPhase::Proposing || phase.round != round {
        return Ok(());
    }

    let proposals = ctx.phase_storage.get_proposals(&event_id, round)?;
    let commit_quorum = usize::from(ctx.two_phase.commit_quorum);
    let Some(canonical) = igra_core::domain::coordination::selection::select_canonical_proposal_for_commit(&proposals, commit_quorum)
    else {
        return Ok(());
    };

    let canonical_hash = canonical.tx_template_hash;

    if ctx.two_phase.revalidate_inputs_on_commit {
        if let Err(err) = revalidate_inputs(ctx.flow, &ctx.app_config.service, &canonical, ctx.two_phase.min_input_score_depth).await {
            warn!(
                "two-phase commit revalidation failed event_id={:#x} round={} canonical_hash={:#x} error={}",
                event_id, round, canonical_hash, err
            );

            if should_bump_round_after_commit_failure(&err) {
                let now = igra_core::foundation::now_nanos();
                if ctx.phase_storage.fail_and_bump_round(&event_id, round, now)? {
                    let cleared = ctx.phase_storage.clear_stale_proposals(&event_id, round.saturating_add(1))?;
                    debug!(
                        "two-phase bumped round after commit failure event_id={:#x} from_round={} cleared_stale={}",
                        event_id, round, cleared
                    );
                }
            }
            return Ok(());
        }
    }

    let now = igra_core::foundation::now_nanos();
    let committed = ctx.phase_storage.mark_committed(&event_id, round, canonical_hash, now)?;
    if !committed {
        return Ok(());
    }

    ctx.storage.set_event_active_template_hash(&event_id, &canonical_hash)?;

    let empty_state = EventCrdtState { signatures: vec![], completion: None, signing_material: None, kpsbt_blob: None, version: 0 };
    let (state, _changed) = ctx.storage.merge_event_crdt(
        &event_id,
        &canonical_hash,
        &empty_state,
        Some(&canonical.signing_material),
        Some(&canonical.kpsbt_blob),
    )?;

    info!(
        "two-phase committed event_id={:#x} round={} canonical_hash={:#x} proposal_count={}",
        event_id,
        round,
        canonical_hash,
        proposals.len()
    );

    ctx.transport
        .publish_event_state(EventStateBroadcast {
            event_id,
            tx_template_hash: canonical_hash,
            state: EventCrdtState::from(&state),
            sender_peer_id: ctx.local_peer_id.clone(),
            phase_context: Some(PhaseContext { round, phase: EventPhase::Committed }),
        })
        .await?;

    // Continue existing CRDT flow locally (sign + submit if threshold reached).
    let crdt_ctx = CrdtHandlerContext {
        app_config: ctx.app_config,
        flow: ctx.flow,
        transport: ctx.transport,
        storage: ctx.storage,
        phase_storage: ctx.phase_storage,
        local_peer_id: ctx.local_peer_id,
    };
    maybe_sign_and_broadcast(&crdt_ctx, &state).await?;
    maybe_submit_and_broadcast(&crdt_ctx, &event_id, &canonical_hash).await?;

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
