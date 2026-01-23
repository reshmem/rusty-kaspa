use super::types::{json_err, json_ok, RpcErrorCode};
use crate::api::state::RpcState;
use axum::http::HeaderMap;
use igra_core::domain::coordination::EventPhase;
use igra_core::foundation::{EventId, TransactionId, TxTemplateHash};
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Deserialize)]
pub struct EventsStatusParams {
    /// Maximum number of unfinalized events to return (sorted by age desc).
    pub limit: Option<usize>,
    /// Only include unfinalized events older than this age (seconds).
    pub min_age_seconds: Option<u64>,
    /// Include completed events in `counts_by_phase`.
    pub include_completed: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct EventsStatusResult {
    pub now_ns: u64,
    pub counts_by_phase: BTreeMap<String, u64>,
    pub unfinalized: Vec<EventStatusItem>,
}

#[derive(Debug, Serialize)]
pub struct EventStatusItem {
    pub event_id_hex: EventId,
    pub phase: String,
    pub round: u32,
    pub retry_count: u32,
    pub phase_started_at_ns: u64,
    pub age_seconds: u64,
    pub external_id: Option<String>,
    pub source: Option<String>,
    pub active_template_hash_hex: Option<TxTemplateHash>,
    pub canonical_hash_hex: Option<TxTemplateHash>,
    pub own_proposal_hash_hex: Option<TxTemplateHash>,
    pub completion_tx_id_hex: Option<TransactionId>,
}

pub async fn handle_events_status(
    state: &RpcState,
    id: serde_json::Value,
    _headers: &HeaderMap,
    params: Option<serde_json::Value>,
) -> serde_json::Value {
    let params: EventsStatusParams = match params {
        None => EventsStatusParams::default(),
        Some(value) => match serde_json::from_value(value) {
            Ok(parsed) => parsed,
            Err(err) => return json_err(id, RpcErrorCode::InvalidParams, err.to_string()),
        },
    };

    let now_ns = igra_core::foundation::now_nanos();
    let include_completed = params.include_completed.unwrap_or(true);
    let limit = params.limit.unwrap_or(100);
    let min_age_seconds = params.min_age_seconds.unwrap_or(0);

    let phases = if include_completed {
        vec![EventPhase::Proposing, EventPhase::Committed, EventPhase::Failed, EventPhase::Abandoned, EventPhase::Completed]
    } else {
        vec![EventPhase::Proposing, EventPhase::Committed, EventPhase::Failed, EventPhase::Abandoned]
    };

    let mut counts_by_phase: BTreeMap<String, u64> = BTreeMap::new();
    let mut event_ids: BTreeSet<EventId> = BTreeSet::new();
    for phase in phases {
        match state.event_ctx.phase_storage.get_events_in_phase(phase) {
            Ok(ids) => {
                counts_by_phase.insert(phase_to_string(phase), ids.len() as u64);
                event_ids.extend(ids);
            }
            Err(err) => return json_err(id, RpcErrorCode::InternalError, err.to_string()),
        }
    }

    let mut unfinalized = Vec::new();
    for event_id in event_ids {
        let phase_state = match state.event_ctx.phase_storage.get_phase(&event_id) {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(err) => return json_err(id, RpcErrorCode::InternalError, err.to_string()),
        };

        if phase_state.phase == EventPhase::Completed {
            continue;
        }

        let age_ns = now_ns.saturating_sub(phase_state.phase_started_at_ns);
        let age_seconds = age_ns / 1_000_000_000;
        if age_seconds < min_age_seconds {
            continue;
        }

        let event = match state.event_ctx.storage.get_event(&event_id) {
            Ok(value) => value,
            Err(err) => return json_err(id, RpcErrorCode::InternalError, err.to_string()),
        };
        let completion = match state.event_ctx.storage.get_event_completion(&event_id) {
            Ok(value) => value,
            Err(err) => return json_err(id, RpcErrorCode::InternalError, err.to_string()),
        };

        let active_template_hash_hex = match state.event_ctx.storage.get_event_active_template_hash(&event_id) {
            Ok(value) => value,
            Err(err) => return json_err(id, RpcErrorCode::InternalError, err.to_string()),
        };

        unfinalized.push(EventStatusItem {
            event_id_hex: event_id,
            phase: phase_to_string(phase_state.phase),
            round: phase_state.round,
            retry_count: phase_state.retry_count,
            phase_started_at_ns: phase_state.phase_started_at_ns,
            age_seconds,
            external_id: event.as_ref().map(|e| e.audit.external_id_raw.clone()),
            source: event.as_ref().map(|e| format!("{:?}", e.event.source)),
            active_template_hash_hex,
            canonical_hash_hex: phase_state.canonical_hash,
            own_proposal_hash_hex: phase_state.own_proposal_hash,
            completion_tx_id_hex: completion.map(|c| c.tx_id),
        });
    }

    unfinalized.sort_by(|a, b| b.age_seconds.cmp(&a.age_seconds).then_with(|| a.event_id_hex.cmp(&b.event_id_hex)));
    if unfinalized.len() > limit {
        unfinalized.truncate(limit);
    }

    debug!("events.status tracked={} unfinalized_returned={}", counts_by_phase.values().sum::<u64>(), unfinalized.len());

    json_ok(id, EventsStatusResult { now_ns, counts_by_phase, unfinalized })
}

fn phase_to_string(phase: EventPhase) -> String {
    match phase {
        EventPhase::Unknown => "unknown",
        EventPhase::Proposing => "proposing",
        EventPhase::Committed => "committed",
        EventPhase::Completed => "completed",
        EventPhase::Failed => "failed",
        EventPhase::Abandoned => "abandoned",
    }
    .to_string()
}
