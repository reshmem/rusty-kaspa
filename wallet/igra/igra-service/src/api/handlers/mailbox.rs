use crate::api::handlers::hyperlane_wire::RpcHyperlaneMessage;
use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use igra_core::foundation::{decode_hex_prefixed, GroupId};
use igra_core::infrastructure::hyperlane::IsmVerifier;
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
    let message_id: igra_core::foundation::ExternalId = match id.parse() {
        Ok(id) => id,
        Err(err) => return (StatusCode::BAD_REQUEST, format!("invalid message id: {}", err)).into_response(),
    };
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
    let group_id: GroupId = match group_id_hex.parse() {
        Ok(group_id) => group_id,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("invalid group_id: {}", err)).into_response(),
    };
    Json(DefaultIsmResponse { ism: format!("{group_id:#x}") }).into_response()
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

    // NOTE(security): this endpoint is for estimating relayer costs only.
    // We intentionally do *not* verify Hyperlane metadata here:
    // - In this Kaspa devnet implementation, the estimate is constant anyway.
    // - Authenticity is enforced in `hyperlane.mailbox_process` (and only there).
    // This keeps relayer preflight (cost estimation) from being blocked by
    // signature/quorum issues that will be surfaced again at process-time.
    let EstimateCostsRequest { message, metadata } = req;
    if let Err(err) = decode_hex_prefixed(&metadata) {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    let message: hyperlane_core::HyperlaneMessage = message.into();
    if ism.validators_and_threshold(message.origin, message.id()).is_none() {
        return (StatusCode::BAD_REQUEST, "unknown origin domain").into_response();
    }

    Json(EstimateCostsResponse { gas_limit: "100000".to_string(), gas_price: "1".to_string(), l2_gas_limit: None }).into_response()
}
