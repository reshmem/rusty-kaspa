use super::super::middleware::auth::authorize_rpc;
use super::super::state::RpcState;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use log::{debug, trace};
use std::sync::Arc;

pub async fn handle_health() -> impl IntoResponse {
    trace!("health check: ok");
    Json(serde_json::json!({
        "status": "healthy",
    }))
}

pub async fn handle_ready(State(state): State<Arc<RpcState>>, headers: HeaderMap) -> Response {
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        return (StatusCode::UNAUTHORIZED, err).into_response();
    }

    let storage_ok = state.event_ctx.storage.health_check().is_ok();
    let node_connected = igra_core::infrastructure::rpc::GrpcNodeRpc::connect(state.node_rpc_url.clone()).await.is_ok();
    let status = if storage_ok && node_connected { "ready" } else { "degraded" };
    if storage_ok && node_connected {
        trace!("ready check: ok storage_ok={} node_connected={}", storage_ok, node_connected);
    } else {
        debug!("ready check: degraded storage_ok={} node_connected={}", storage_ok, node_connected);
    }
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
            debug!("metrics encode failed error={}", err);
            let mut response = format!("metrics_error: {}", err).into_response();
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}
