use crate::api::handlers::hyperlane_wire::RpcHyperlaneMessage;
use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use igra_core::infrastructure::hyperlane::{decode_proof_metadata_hex, IsmVerifier};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct MailboxCountResponse {
    pub count: u32,
}

#[derive(Debug, Serialize)]
pub struct DeliveredResponse {
    pub delivered: bool,
}

#[derive(Debug, Serialize)]
pub struct DefaultIsmResponse {
    pub ism: String,
}

#[derive(Debug, Deserialize)]
pub struct EstimateCostsRequest {
    pub message: RpcHyperlaneMessage,
    pub metadata: String,
}

#[derive(Debug, Serialize)]
pub struct EstimateCostsResponse {
    pub gas_limit: String,
    pub gas_price: String,
    pub l2_gas_limit: Option<String>,
}

pub async fn get_mailbox_count(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    match state.event_ctx.storage.hyperlane_get_delivered_count() {
        Ok(count) => Json(MailboxCountResponse { count }).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

pub async fn get_message_delivered(State(state): State<Arc<RpcState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    let message_id = match parse_hash32_hex(&id) {
        Ok(id) => id,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    let message_id = igra_core::foundation::ExternalId::from(message_id);
    match state.event_ctx.storage.hyperlane_is_message_delivered(&message_id) {
        Ok(delivered) => Json(DeliveredResponse { delivered }).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

pub async fn get_default_ism(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    let Some(group_id_hex) = state.group_id_hex.as_deref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "missing group_id").into_response();
    };
    let trimmed = group_id_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.len() != 64 {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("invalid group_id length {}", trimmed.len())).into_response();
    }
    Json(DefaultIsmResponse { ism: format!("0x{}", trimmed) }).into_response()
}

pub async fn estimate_costs(
    State(state): State<Arc<RpcState>>,
    headers: HeaderMap,
    Json(req): Json<EstimateCostsRequest>,
) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let Some(ism) = state.hyperlane_ism.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "hyperlane not configured").into_response();
    };

    let message: hyperlane_core::HyperlaneMessage = req.message.into();
    let Some(set) = ism.validators_and_threshold(message.origin, message.id()) else {
        return (StatusCode::BAD_REQUEST, "unknown origin domain").into_response();
    };

    let metadata = match decode_proof_metadata_hex(set.mode.clone(), &message, &req.metadata) {
        Ok(metadata) => metadata,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    if let Err(err) = ism.verify_proof(&message, &metadata, set.mode) {
        return (StatusCode::BAD_REQUEST, err).into_response();
    }

    Json(EstimateCostsResponse { gas_limit: "100000".to_string(), gas_price: "1".to_string(), l2_gas_limit: None }).into_response()
}

fn parse_hash32_hex(value: &str) -> Result<[u8; 32], String> {
    let stripped = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped).map_err(|_| "invalid hex".to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
