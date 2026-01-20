use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const HYPERLANE_FINALITY_DEPTH_DAA: u64 = 10;

#[derive(Debug, Deserialize)]
pub struct RangeParams {
    pub from: u32,
    pub to: u32,
}

#[derive(Debug, Serialize)]
pub struct FinalizedBlockResponse {
    pub finalized_block: u32,
}

#[derive(Debug, Serialize)]
pub struct DeliveryRecord {
    pub message_id: String,
    pub tx_id: String,
    pub daa_score: u64,
    pub timestamp_nanos: u64,
}

#[derive(Debug, Serialize)]
pub struct DeliveriesResponse {
    pub deliveries: Vec<DeliveryRecord>,
}

#[derive(Debug, Serialize)]
pub struct SequenceTipResponse {
    pub sequence: Option<u32>,
    pub tip: u32,
}

#[derive(Debug, Serialize)]
pub struct MessageRecord {
    pub message_id: String,
    pub sender: String,
    pub recipient: String,
    pub origin: u32,
    pub destination: u32,
    pub body: String,
    pub nonce: u32,
    pub tx_id: String,
    pub daa_score: u64,
    pub log_index: u32,
}

#[derive(Debug, Serialize)]
pub struct MessagesResponse {
    pub messages: Vec<MessageRecord>,
}

pub async fn get_finalized_block(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let virtual_daa = match state.kaspa_query.get_virtual_daa_score().await {
        Ok(score) => score,
        Err(err) => return (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    };
    let finalized = virtual_daa.saturating_sub(HYPERLANE_FINALITY_DEPTH_DAA);
    Json(FinalizedBlockResponse { finalized_block: u32::try_from(finalized).unwrap_or(u32::MAX) }).into_response()
}

pub async fn get_deliveries(State(state): State<Arc<RpcState>>, headers: HeaderMap, Query(params): Query<RangeParams>) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    match state.event_ctx.storage.hyperlane_get_deliveries_in_range(params.from as u64, params.to as u64) {
        Ok(deliveries) => {
            let deliveries = deliveries
                .into_iter()
                .map(|d| DeliveryRecord {
                    message_id: format!("0x{}", hex::encode(d.message_id)),
                    tx_id: format!("0x{}", hex::encode(d.tx_id)),
                    daa_score: d.daa_score,
                    timestamp_nanos: d.timestamp_nanos,
                })
                .collect::<Vec<_>>();
            Json(DeliveriesResponse { deliveries }).into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

pub async fn get_sequence_tip(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    let count = match state.event_ctx.storage.hyperlane_get_delivered_count() {
        Ok(count) => count,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    let tip = match state.kaspa_query.get_virtual_daa_score().await {
        Ok(score) => u32::try_from(score).unwrap_or(u32::MAX),
        Err(err) => return (StatusCode::SERVICE_UNAVAILABLE, err.to_string()).into_response(),
    };
    Json(SequenceTipResponse { sequence: if count > 0 { Some(count) } else { None }, tip }).into_response()
}

pub async fn get_messages(State(state): State<Arc<RpcState>>, headers: HeaderMap, Query(params): Query<RangeParams>) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    match state.event_ctx.storage.hyperlane_get_messages_in_range(params.from as u64, params.to as u64) {
        Ok(messages) => {
            let messages = messages
                .into_iter()
                .map(|m| MessageRecord {
                    message_id: format!("0x{}", hex::encode(m.message_id)),
                    sender: format!("0x{}", hex::encode(m.sender)),
                    recipient: format!("0x{}", hex::encode(m.recipient)),
                    origin: m.origin,
                    destination: m.destination,
                    body: m.body_hex,
                    nonce: m.nonce,
                    tx_id: format!("0x{}", hex::encode(m.tx_id)),
                    daa_score: m.daa_score,
                    log_index: m.log_index,
                })
                .collect::<Vec<_>>();
            Json(MessagesResponse { messages }).into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}
