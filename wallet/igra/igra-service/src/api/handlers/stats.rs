use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub uptime_seconds: u64,
    pub submitted_events_total: u64,
    pub submitted_events_signing_event_total: u64,
    pub submitted_events_hyperlane_total: u64,
    pub tx_submissions_total: u64,
    pub tx_submissions_ok_total: u64,
    pub tx_submissions_duplicate_total: u64,
    pub tx_submissions_error_total: u64,
}

pub async fn get_stats(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let snapshot = state.metrics.snapshot();
    Json(StatsResponse {
        uptime_seconds: snapshot.uptime.as_secs(),
        submitted_events_total: snapshot.submitted_events_total,
        submitted_events_signing_event_total: snapshot.submitted_events_signing_event_total,
        submitted_events_hyperlane_total: snapshot.submitted_events_hyperlane_total,
        tx_submissions_total: snapshot.tx_submissions_total,
        tx_submissions_ok_total: snapshot.tx_submissions_ok_total,
        tx_submissions_duplicate_total: snapshot.tx_submissions_duplicate_total,
        tx_submissions_error_total: snapshot.tx_submissions_error_total,
    })
    .into_response()
}
