use igra_core::application::EventPhase;
use igra_core::foundation::{now_nanos, EventId, ThresholdError};
use igra_core::infrastructure::storage::phase::PhaseStorage;
use igra_core::infrastructure::storage::Storage;
use log::{info, warn};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const REPORT_INTERVAL: Duration = Duration::from_secs(10 * 60);
const MAX_EVENTS_TO_LOG: usize = 500;

pub async fn run_unfinalized_event_reporter_loop(storage: Arc<dyn Storage>, phase_storage: Arc<dyn PhaseStorage>) {
    let mut interval = tokio::time::interval(REPORT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        if let Err(err) = report_unfinalized_events(storage.as_ref(), phase_storage.as_ref()) {
            warn!("unfinalized event report failed error={}", err);
        }
    }
}

fn report_unfinalized_events(storage: &dyn Storage, phase_storage: &dyn PhaseStorage) -> Result<(), ThresholdError> {
    let now = now_nanos();

    let phases = [EventPhase::Proposing, EventPhase::Committed, EventPhase::Failed, EventPhase::Abandoned];
    let mut counts_by_phase: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut unfinalized: Vec<(EventId, EventPhase, u32, u32, u64)> = Vec::new();

    for phase in phases {
        let event_ids = phase_storage.get_events_in_phase(phase)?;
        counts_by_phase.insert(phase_label(phase), event_ids.len());

        for event_id in event_ids {
            let completion = storage.get_event_completion(&event_id)?;
            if completion.is_some() {
                continue;
            }
            let Some(phase_state) = phase_storage.get_phase(&event_id)? else { continue };
            if phase_state.phase != phase {
                continue;
            }
            let age_seconds = now.saturating_sub(phase_state.phase_started_at_ns) / 1_000_000_000;
            unfinalized.push((event_id, phase_state.phase, phase_state.round, phase_state.retry_count, age_seconds));
        }
    }

    let total_unfinalized = unfinalized.len();
    if total_unfinalized == 0 {
        info!(
            "unfinalized events report: none (counts proposing={} committed={} failed={} abandoned={})",
            counts_by_phase.get("proposing").copied().unwrap_or(0),
            counts_by_phase.get("committed").copied().unwrap_or(0),
            counts_by_phase.get("failed").copied().unwrap_or(0),
            counts_by_phase.get("abandoned").copied().unwrap_or(0),
        );
        return Ok(());
    }

    unfinalized.sort_by(|a, b| b.4.cmp(&a.4).then_with(|| a.0.cmp(&b.0)));

    let truncated = total_unfinalized.saturating_sub(MAX_EVENTS_TO_LOG);
    let to_log = unfinalized.into_iter().take(MAX_EVENTS_TO_LOG).collect::<Vec<_>>();

    warn!(
        "unfinalized events report: total={} (counts proposing={} committed={} failed={} abandoned={}){}",
        total_unfinalized,
        counts_by_phase.get("proposing").copied().unwrap_or(0),
        counts_by_phase.get("committed").copied().unwrap_or(0),
        counts_by_phase.get("failed").copied().unwrap_or(0),
        counts_by_phase.get("abandoned").copied().unwrap_or(0),
        if truncated > 0 { format!(" truncated={}", truncated) } else { "".to_string() }
    );

    for (event_id, phase, round, retry_count, age_seconds) in to_log {
        let event = storage.get_event(&event_id)?;
        let external_id = event.as_ref().map(|e| e.audit.external_id_raw.as_str()).unwrap_or("-");
        warn!(
            "unfinalized event event_id={:#x} phase={} round={} retry_count={} age_seconds={} external_id={}",
            event_id,
            phase_label(phase),
            round,
            retry_count,
            age_seconds,
            external_id
        );
    }

    Ok(())
}

fn phase_label(phase: EventPhase) -> &'static str {
    match phase {
        EventPhase::Unknown => "unknown",
        EventPhase::Proposing => "proposing",
        EventPhase::Committed => "committed",
        EventPhase::Completed => "completed",
        EventPhase::Failed => "failed",
        EventPhase::Abandoned => "abandoned",
    }
}
