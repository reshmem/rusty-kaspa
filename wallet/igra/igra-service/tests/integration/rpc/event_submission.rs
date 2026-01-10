use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::Request;
use igra_core::application::{EventContext, EventProcessor};
use igra_core::domain::validation::NoopVerifier;
use igra_core::domain::{EventSource, SigningEvent};
use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
use igra_core::infrastructure::config::ServiceConfig;
use igra_core::infrastructure::storage::RocksStorage;
use igra_core::ThresholdError;
use igra_service::api::json_rpc::build_router;
use igra_service::api::json_rpc::RpcState;
use igra_service::service::metrics::Metrics;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

struct CountingProcessor {
    count: Arc<std::sync::Mutex<u32>>,
}

#[async_trait]
impl EventProcessor for CountingProcessor {
    async fn handle_signing_event(
        &self,
        _config: &ServiceConfig,
        session_id: SessionId,
        _request_id: RequestId,
        _signing_event: SigningEvent,
        _expires_at_nanos: u64,
        _coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        let mut guard = self.count.lock().expect("count lock");
        *guard += 1;
        Ok([session_id.as_hash()[0]; 32])
    }
}

fn signing_params_json() -> serde_json::Value {
    json!({
        "session_id_hex": hex::encode([9u8; 32]),
        "request_id": "req-rpc",
        "coordinator_peer_id": "peer-1",
        "expires_at_nanos": 0,
        "signing_event": {
            "event_id": "event-rpc",
            "event_source": EventSource::Api { issuer: "tests".to_string() },
            "derivation_path": "m/45'/111111'/0'/0/0",
            "derivation_index": 0,
            "destination_address": "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3",
            "amount_sompi": 1_000_000,
            "metadata": BTreeMap::<String, String>::new(),
            "timestamp_nanos": 1,
            "signature_hex": null,
            "signature": null,
        }
    })
}

#[tokio::test]
async fn rpc_event_submission() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let count = Arc::new(std::sync::Mutex::new(0u32));
    let processor = Arc::new(CountingProcessor { count: count.clone() });

    let ctx = EventContext { processor, config: ServiceConfig::default(), message_verifier: Arc::new(NoopVerifier), storage };

    let metrics = Arc::new(Metrics::new().expect("metrics"));
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
    let params = signing_params_json();
    let mut request = Request::builder()
        .method("POST")
        .uri("/rpc")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "method": "signing_event.submit",
                "params": params,
                "id": 1,
            }))
            .expect("json"),
        ))
        .expect("request");
    request.extensions_mut().insert(ConnectInfo("127.0.0.1:20002".parse::<std::net::SocketAddr>().expect("addr")));

    let response = router.oneshot(request).await.expect("rpc call");
    assert!(response.status().is_success());
    let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let result = body.get("result").expect("result");
    assert_eq!(result["session_id_hex"], hex::encode([9u8; 32]));

    let handled = *count.lock().expect("count lock");
    assert_eq!(handled, 1);
}
