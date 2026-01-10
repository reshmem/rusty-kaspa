use super::super::middleware::auth::authorize_rpc;
use super::super::state::RpcState;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;

pub async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
    }))
}

pub async fn handle_ready(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let storage_ok = state.event_ctx.storage.health_check().is_ok();
    let node_connected = match igra_core::infrastructure::rpc::GrpcNodeRpc::connect(state.node_rpc_url.clone()).await {
        Ok(_) => true,
        Err(_) => false,
    };
    let status = if storage_ok && node_connected { "ready" } else { "degraded" };
    Json(serde_json::json!({
        "status": status,
        "storage_ok": storage_ok,
        "node_connected": node_connected,
    }))
    .into_response()
}

pub async fn handle_metrics(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    match state.metrics.encode() {
        Ok(body) => {
            let mut response = body.into_response();
            response.headers_mut().insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4"));
            response
        }
        Err(err) => {
            let mut response = format!("metrics_error: {}", err).into_response();
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}

