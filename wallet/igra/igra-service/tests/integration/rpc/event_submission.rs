use async_trait::async_trait;
use igra_core::error::ThresholdError;
use igra_core::event::{EventContext, EventProcessor};
use igra_core::model::{EventSource, Hash32, SigningEvent};
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::validation::NoopVerifier;
use igra_service::api::json_rpc::build_router;
use igra_service::api::json_rpc::RpcState;
use igra_service::service::metrics::Metrics;
use reqwest::Client;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tempfile::TempDir;

struct CountingProcessor {
    count: Arc<std::sync::Mutex<u32>>,
}

#[async_trait]
impl EventProcessor for CountingProcessor {
    async fn handle_signing_event(
        &self,
        _config: &igra_core::config::ServiceConfig,
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
    let storage = Arc::new(igra_core::storage::rocks::RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let count = Arc::new(std::sync::Mutex::new(0u32));
    let processor = Arc::new(CountingProcessor { count: count.clone() });

    let ctx = EventContext {
        processor,
        config: igra_core::config::ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier),
        storage,
    };

    let metrics = Arc::new(Metrics::new().expect("metrics"));
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
    let params = signing_params_json();
    let response = client
        .post(format!("http://{}/rpc", bound_addr))
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "signing_event.submit",
            "params": params,
            "id": 1,
        }))
        .send()
        .await
        .expect("rpc call");

    assert!(response.status().is_success());
    let body: serde_json::Value = response.json().await.expect("json");
    let result = body.get("result").expect("result");
    assert_eq!(result["session_id_hex"], hex::encode([9u8; 32]));

    let handled = *count.lock().expect("count lock");
    assert_eq!(handled, 1);

    server.abort();
}
