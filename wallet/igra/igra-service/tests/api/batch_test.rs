use super::{basic_state, call_rpc};
use igra_service::api::json_rpc::build_router;
use serde_json::json;

#[tokio::test]
async fn rpc_batch_returns_array() {
    let router = build_router(basic_state());

    let body = json!([
        { "jsonrpc": "2.0", "method": "signing_event.submit", "params": {}, "id": 1 },
        { "jsonrpc": "2.0", "method": "does.not.exist", "params": {}, "id": 2 }
    ]);

    let (status, value) = call_rpc(&router, "127.0.0.1:10002".parse().expect("addr"), None, body).await;

    assert!(status.is_success());
    let arr = value.as_array().expect("array response");
    assert_eq!(arr.len(), 2);
}
