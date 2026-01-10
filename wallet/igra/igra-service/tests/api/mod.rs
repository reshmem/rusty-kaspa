mod auth_test;
mod batch_test;
mod rate_limit_test;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use std::sync::Arc;
use tower::ServiceExt;

async fn call_rpc(
    router: &Router,
    client_addr: std::net::SocketAddr,
    token: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method("POST").uri("/rpc").header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {}", token));
    }

    let mut request = builder.body(Body::from(serde_json::to_string(&body).expect("serialize body"))).expect("request");
    request.extensions_mut().insert(ConnectInfo(client_addr));

    let response = router.clone().oneshot(request).await.expect("rpc response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body bytes");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn basic_state() -> Arc<igra_service::api::json_rpc::RpcState> {
    use async_trait::async_trait;
    use igra_core::application::{EventContext, EventProcessor};
    use igra_core::domain::validation::NoopVerifier;
    use igra_core::domain::SigningEvent;
    use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::ThresholdError;
    use igra_service::service::metrics::Metrics;
    use tempfile::TempDir;

    struct NoopProcessor;

    #[async_trait]
    impl EventProcessor for NoopProcessor {
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

    let temp_dir = TempDir::new().expect("temp dir");
    let dir_path = temp_dir.into_path();
    let storage = Arc::new(RocksStorage::open_in_dir(&dir_path).expect("storage"));
    let ctx = EventContext {
        processor: Arc::new(NoopProcessor),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier),
        storage,
    };

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    Arc::new(igra_service::api::json_rpc::RpcState {
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
    })
}
