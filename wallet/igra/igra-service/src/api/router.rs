use super::handlers::health::{handle_health, handle_metrics, handle_ready};
use super::handlers::rpc::handle_rpc;
use super::middleware::correlation::correlation_middleware;
use super::middleware::logging::logging_middleware;
use super::middleware::rate_limit::rate_limit_middleware;
use super::state::RpcState;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use igra_core::foundation::ThresholdError;
use log::{error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

pub async fn run_json_rpc_server(addr: SocketAddr, state: Arc<RpcState>) -> Result<(), ThresholdError> {
    info!("binding json-rpc server addr={}", addr);
    let app = build_router(state);
    let listener = TcpListener::bind(addr).await?;
    info!("HTTP server ready and accepting connections addr={}", addr);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.map_err(|err| {
        error!("HTTP server terminated unexpectedly addr={} error={}", addr, err);
        ThresholdError::Message(err.to_string())
    })
}

pub fn build_router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/rpc", post(handle_rpc).route_layer(axum::middleware::from_fn_with_state(state.clone(), rate_limit_middleware)))
        .route("/health", get(handle_health))
        .route("/ready", get(handle_ready))
        .route("/metrics", get(handle_metrics))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(axum::middleware::from_fn(logging_middleware))
        .layer(axum::middleware::from_fn(correlation_middleware))
        .with_state(state)
}
