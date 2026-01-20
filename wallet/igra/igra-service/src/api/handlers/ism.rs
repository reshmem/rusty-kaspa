use crate::api::handlers::hyperlane_wire::RpcHyperlaneMessage;
use crate::api::middleware::auth::authorize_rpc;
use crate::api::state::RpcState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use igra_core::infrastructure::hyperlane::{decode_proof_metadata_hex, IsmMode, IsmVerifier};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct ModuleTypeResponse {
    pub module_type: String,
}

#[derive(Debug, Deserialize)]
pub struct DryRunVerifyRequest {
    pub message: RpcHyperlaneMessage,
    pub metadata: String,
}

#[derive(Debug, Serialize)]
pub struct DryRunVerifyResponse {
    pub success: bool,
    pub gas_estimate: Option<String>,
    pub error: Option<String>,
}

pub async fn get_module_type(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }
    let Some(ism) = state.hyperlane_ism.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "hyperlane not configured").into_response();
    };
    let Some(mode) = ism.default_mode() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "hyperlane domains not configured").into_response();
    };
    Json(ModuleTypeResponse { module_type: module_type_str(&mode).to_string() }).into_response()
}

pub async fn dry_run_verify(State(state): State<Arc<RpcState>>, headers: HeaderMap, Json(req): Json<DryRunVerifyRequest>) -> Response {
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
    let mode = set.mode;

    let metadata = match decode_proof_metadata_hex(mode.clone(), &message, &req.metadata) {
        Ok(meta) => meta,
        Err(err) => return (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    };

    match ism.verify_proof(&message, &metadata, mode) {
        Ok(_) => Json(DryRunVerifyResponse { success: true, gas_estimate: Some("100000".to_string()), error: None }).into_response(),
        Err(err) => Json(DryRunVerifyResponse { success: false, gas_estimate: None, error: Some(err) }).into_response(),
    }
}

fn module_type_str(mode: &IsmMode) -> &'static str {
    match mode {
        IsmMode::MessageIdMultisig => "message_id_multisig",
        IsmMode::MerkleRootMultisig => "merkle_root_multisig",
    }
}
