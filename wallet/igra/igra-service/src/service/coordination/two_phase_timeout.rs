use crate::service::coordination::two_phase_handler::{try_commit_and_sign, TwoPhaseHandlerContext};
use crate::service::flow::ServiceFlow;
use igra_core::domain::coordination::{EventPhase, TwoPhaseConfig};
use igra_core::foundation::{now_nanos, EventId, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::Transport;
use log::{debug, info, warn};
use std::sync::Arc;
use std::time::Duration;

const TICK_INTERVAL: Duration = Duration::from_secs(1);
const NS_PER_MS: u64 = 1_000_000;
const TERMINAL_PHASE_TTL_NS: u64 = 60 * 60 * 1_000_000_000;

pub async fn run_two_phase_tick_loop(
    app_config: Arc<AppConfig>,
    two_phase: TwoPhaseConfig,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    phase_storage: Arc<dyn PhaseStorage>,
    local_peer_id: PeerId,
) {
    let mut interval = tokio::time::interval(TICK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        if let Err(err) = on_tick(&app_config, &two_phase, flow.as_ref(), &transport, &storage, &phase_storage, &local_peer_id).await {
            warn!("two-phase tick failed error={}", err);
        }
    }
}

async fn on_tick(
    app_config: &AppConfig,
    two_phase: &TwoPhaseConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    phase_storage: &Arc<dyn PhaseStorage>,
    local_peer_id: &PeerId,
) -> Result<(), ThresholdError> {
    let now = now_nanos();
    let ctx = TwoPhaseHandlerContext { app_config, two_phase, flow, transport, storage, phase_storage, local_peer_id };

    // Proposing events: check for timeout.
    for event_id in phase_storage.get_events_in_phase(EventPhase::Proposing)? {
        let Some(phase) = phase_storage.get_phase(&event_id)? else { continue };
        if phase.phase != EventPhase::Proposing {
            continue;
        }
        if !phase.is_timeout_expired(now, two_phase.proposal_timeout_ms) {
            continue;
        }

        // Last chance: commit if quorum formed.
        if let Err(err) = try_commit_and_sign(&ctx, event_id, phase.round).await {
            warn!(
                "two-phase commit attempt failed; will retry via timeout path event_id={:#x} round={} error={}",
                event_id, phase.round, err
            );
        }

        // If still proposing after commit attempt, fail this round.
        let Some(after) = phase_storage.get_phase(&event_id)? else { continue };
        if after.phase == EventPhase::Committed || after.phase == EventPhase::Completed {
            continue;
        }

        if after.retry_count >= two_phase.retry.max_retries {
            info!("two-phase abandon after max retries event_id={:#x} retries={}", event_id, after.retry_count);
            phase_storage.mark_abandoned(&event_id, now)?;
            continue;
        }

        info!("two-phase timeout without quorum event_id={:#x} round={} retry_count={}", event_id, after.round, after.retry_count);
        let bumped = phase_storage.fail_and_bump_round(&event_id, after.round, now)?;
        if bumped {
            let cleared = phase_storage.clear_stale_proposals(&event_id, after.round.saturating_add(1))?;
            debug!(
                "two-phase cleared stale proposals after bump event_id={:#x} before_round={} cleared={}",
                event_id,
                after.round.saturating_add(1),
                cleared
            );
        }
    }

    // Failed events: retry after backoff.
    for event_id in phase_storage.get_events_in_phase(EventPhase::Failed)? {
        let Some(phase) = phase_storage.get_phase(&event_id)? else { continue };
        if phase.phase != EventPhase::Failed {
            continue;
        }

        let delay_ms = jittered_delay_ms(two_phase, &event_id, local_peer_id, phase.retry_count);
        let elapsed_ms = now.saturating_sub(phase.phase_started_at_ns) / NS_PER_MS;
        if elapsed_ms < delay_ms {
            continue;
        }

        let Some(event) = storage.get_event(&event_id)? else {
            debug!("two-phase retry skipped: missing event event_id={:#x}", event_id);
            continue;
        };

        let (proposal, _anchor) = match igra_core::application::two_phase::build_local_proposal_for_round(
            flow.rpc().as_ref(),
            &app_config.service,
            &flow.key_context(),
            &event,
            local_peer_id,
            phase.round,
            now,
        )
        .await
        {
            Ok(out) => out,
            Err(err) => {
                warn!(
                    "two-phase failed to build local proposal on retry event_id={:#x} round={} error={}",
                    event_id, phase.round, err
                );
                continue;
            }
        };

        let store_result = phase_storage.store_proposal(&proposal)?;
        if matches!(store_result, igra_core::infrastructure::storage::phase::StoreProposalResult::Stored) {
            debug!(
                "two-phase stored retry proposal event_id={:#x} round={} tx_template_hash={:#x}",
                event_id, phase.round, proposal.tx_template_hash
            );
        }
        phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
        if let Err(err) = transport.publish_proposal(proposal.clone()).await {
            warn!("two-phase failed to publish local proposal on retry event_id={:#x} round={} error={}", event_id, phase.round, err);
            continue;
        }
        info!(
            "two-phase published local proposal (retry) event_id={:#x} round={} retry_count={} tx_template_hash={:#x}",
            event_id, phase.round, phase.retry_count, proposal.tx_template_hash
        );

        if let Err(err) = try_commit_and_sign(&ctx, event_id, phase.round).await {
            warn!("two-phase commit attempt failed after retry proposal event_id={:#x} round={} error={}", event_id, phase.round, err);
        }
    }

    // Optional GC (very lightweight for now): clean terminal phases after 1 hour.
    let cutoff = now.saturating_sub(TERMINAL_PHASE_TTL_NS);
    let gc_deleted = phase_storage.gc_events_older_than(cutoff)?;
    if gc_deleted > 0 {
        debug!("two-phase GC deleted terminal events deleted={} cutoff_nanos={}", gc_deleted, cutoff);
    }

    Ok(())
}

fn jittered_delay_ms(two_phase: &TwoPhaseConfig, event_id: &EventId, local_peer_id: &PeerId, retry_count: u32) -> u64 {
    let base = two_phase.retry.delay_for_retry(retry_count);
    let jitter = two_phase.retry.jitter_ms;
    if jitter == 0 {
        return base;
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(event_id.as_hash());
    hasher.update(local_peer_id.as_str().as_bytes());
    hasher.update(&retry_count.to_le_bytes());
    let digest = hasher.finalize();

    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest.as_bytes()[..8]);
    let rnd = u64::from_le_bytes(first8);

    let span = jitter.saturating_mul(2).saturating_add(1);
    let offset = (rnd % span) as i64 - jitter as i64;

    if offset.is_negative() {
        base.saturating_sub(offset.unsigned_abs())
    } else {
        base.saturating_add(offset as u64)
    }
}
