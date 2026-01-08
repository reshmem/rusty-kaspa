use async_trait::async_trait;
use igra_core::error::ThresholdError;
use igra_core::event::EventContext;
use igra_core::model::{Hash32, SigningEvent};
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::validation::NoopVerifier;
use igra_service::api::json_rpc::build_router;
use igra_service::api::json_rpc::RpcState;
use igra_service::service::metrics::Metrics;
use reqwest::Client;
use serde_json::Value;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tempfile::TempDir;

struct DummyProcessor;

#[async_trait]
impl igra_core::event::EventProcessor for DummyProcessor {
    async fn handle_signing_event(
        &self,
        _config: &igra_core::config::ServiceConfig,
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
    let storage = Arc::new(igra_core::storage::rocks::RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: igra_core::config::ServiceConfig::default(),
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
        hyperlane_ism: None,
        group_id_hex: None,
        coordinator_peer_id: "test-peer".to_string(),
    });

    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    let bound_addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.expect("serve");
    });

    let client = Client::new();

    let health = client.get(format!("http://{}/health", bound_addr)).send().await.expect("health call");
    assert!(health.status().is_success());
    let health_body: Value = health.json().await.expect("health json");
    assert_eq!(health_body["status"], "healthy");

    let ready = client.get(format!("http://{}/ready", bound_addr)).send().await.expect("ready call");
    assert!(ready.status().is_success());
    let ready_body: Value = ready.json().await.expect("ready json");
    assert_eq!(ready_body["status"], "degraded");
    assert_eq!(ready_body["node_connected"], false);

    let metrics_resp = client.get(format!("http://{}/metrics", bound_addr)).send().await.expect("metrics call");
    assert!(metrics_resp.status().is_success());
    let metrics_body = metrics_resp.text().await.expect("metrics text");
    assert!(metrics_body.contains("rpc_requests_total"));
    assert!(metrics_body.contains("signing_sessions_total"));
    assert!(metrics_body.contains("signer_acks_total"));
    assert!(metrics_body.contains("partial_sigs_total"));

    server.abort();
}
