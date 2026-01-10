use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use igra_core::application::{EventContext, EventProcessor};
use igra_core::domain::validation::NoopVerifier;
use igra_core::domain::SigningEvent;
use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
use igra_core::infrastructure::config::ServiceConfig;
use igra_core::infrastructure::storage::RocksStorage;
use igra_core::ThresholdError;
use igra_service::api::json_rpc::build_router;
use igra_service::api::json_rpc::RpcState;
use igra_service::service::metrics::Metrics;
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

struct DummyProcessor;

#[async_trait]
impl EventProcessor for DummyProcessor {
    async fn handle_signing_event(
        &self,
        _config: &ServiceConfig,
        _session_id: SessionId,
        _request_id: RequestId,
        _signing_event: SigningEvent,
        _expires_at_nanos: u64,
        _coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        Ok([0u8; 32])
    }
}

#[tokio::test]
async fn rpc_health_ready_metrics() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier),
        storage,
    };

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    metrics.inc_rpc_request("health", "ok");
    metrics.inc_session_stage("proposal_received");
    metrics.inc_signer_ack(true);
    metrics.inc_partial_sig();

    let state = Arc::new(RpcState {
        event_ctx: ctx,
        rpc_token: None,
        node_rpc_url: "grpc://127.0.0.1:16110".to_string(),
        metrics,
        rate_limiter: Arc::new(igra_service::api::RateLimiter::new()),
        hyperlane_ism: None,
        group_id_hex: None,
        coordinator_peer_id: "test-peer".to_string(),
        hyperlane_default_derivation_path: "m/45h/111111h/0h/0/0".to_string(),
        rate_limit_rps: 30,
        rate_limit_burst: 60,
        session_expiry_seconds: 600,
    });

    let router = build_router(state);

    let response = router
        .clone()
        .oneshot(Request::builder().method("GET").uri("/health").body(Body::empty()).expect("req"))
        .await
        .expect("health call");
    assert!(response.status().is_success());
    let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let health_body: Value = serde_json::from_slice(&bytes).expect("health json");
    assert_eq!(health_body["status"], "healthy");

    let response = router
        .clone()
        .oneshot(Request::builder().method("GET").uri("/ready").body(Body::empty()).expect("req"))
        .await
        .expect("ready call");
    assert!(response.status().is_success());
    let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let ready_body: Value = serde_json::from_slice(&bytes).expect("ready json");
    assert_eq!(ready_body["status"], "degraded");
    assert_eq!(ready_body["node_connected"], false);

    let response = router
        .oneshot(Request::builder().method("GET").uri("/metrics").body(Body::empty()).expect("req"))
        .await
        .expect("metrics call");
    assert!(response.status().is_success());
    let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let metrics_body = String::from_utf8(bytes.to_vec()).expect("metrics text");
    assert!(metrics_body.contains("rpc_requests_total"));
    assert!(metrics_body.contains("signing_sessions_total"));
    assert!(metrics_body.contains("signer_acks_total"));
    assert!(metrics_body.contains("partial_sigs_total"));
}
