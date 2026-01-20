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
    use futures_util::stream;
    use igra_core::application::EventContext;
    use igra_core::domain::coordination::TwoPhaseConfig;
    use igra_core::domain::validation::NoopVerifier;
    use igra_core::domain::GroupPolicy;
    use igra_core::foundation::{GroupId, PeerId, ThresholdError};
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::infrastructure::rpc::KaspaGrpcQueryClient;
    use igra_core::infrastructure::rpc::UnimplementedRpc;
    use igra_core::infrastructure::storage::phase::PhaseStorage;
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::infrastructure::transport::iroh::traits::{StateSyncRequest, StateSyncResponse, Transport, TransportSubscription};
    use igra_service::service::metrics::Metrics;
    use tempfile::TempDir;

    struct NoopTransport;

    #[async_trait]
    impl Transport for NoopTransport {
        async fn publish_event_state(
            &self,
            _broadcast: igra_core::infrastructure::transport::iroh::traits::EventStateBroadcast,
        ) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_proposal(&self, _proposal: igra_core::domain::coordination::ProposalBroadcast) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_state_sync_request(&self, _request: StateSyncRequest) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_state_sync_response(&self, _response: StateSyncResponse) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn subscribe_group(&self, _group_id: GroupId) -> Result<TransportSubscription, ThresholdError> {
            Ok(TransportSubscription::new(Box::pin(stream::empty())))
        }
    }

    let temp_dir = TempDir::new().expect("temp dir");
    let dir_path = temp_dir.into_path();
    let storage = Arc::new(RocksStorage::open_in_dir(&dir_path).expect("storage"));
    let phase_storage: Arc<dyn PhaseStorage> = storage.clone();
    let ctx = EventContext {
        config: ServiceConfig::default(),
        policy: GroupPolicy::default(),
        two_phase: TwoPhaseConfig::default(),
        local_peer_id: PeerId::from("test-peer"),
        message_verifier: Arc::new(NoopVerifier),
        storage,
        phase_storage,
        transport: Arc::new(NoopTransport),
        rpc: Arc::new(UnimplementedRpc::new()),
    };

    let metrics = Arc::new(Metrics::new().expect("metrics"));
    Arc::new(igra_service::api::json_rpc::RpcState {
        event_ctx: ctx,
        rpc_token: None,
        node_rpc_url: "grpc://127.0.0.1:16110".to_string(),
        kaspa_query: Arc::new(KaspaGrpcQueryClient::unimplemented()),
        metrics,
        rate_limiter: Arc::new(igra_service::api::RateLimiter::new()),
        hyperlane_ism: None,
        group_id_hex: None,
        coordinator_peer_id: "test-peer".to_string(),
        rate_limit_rps: 30,
        rate_limit_burst: 60,
        session_expiry_seconds: 600,
        hyperlane_mailbox_wait_seconds: 10,
    })
}
