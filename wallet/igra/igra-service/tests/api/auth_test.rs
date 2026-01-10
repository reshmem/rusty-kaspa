use super::{basic_state, call_rpc};
use igra_service::api::json_rpc::build_router;
use serde_json::json;

#[tokio::test]
async fn rpc_requires_token_when_configured() {
    let mut state = (*basic_state()).clone();
    state.rpc_token = Some("secret-token".to_string());
    let state = std::sync::Arc::new(state);

    let router = build_router(state);

    let (status, body) = call_rpc(
        &router,
        "127.0.0.1:10001".parse().expect("addr"),
        None,
        json!({
            "jsonrpc": "2.0",
            "method": "signing_event.submit",
            "params": {},
            "id": 1,
        }),
    )
    .await;

    assert!(status.is_success());
    assert_eq!(body["error"]["code"], -32001);
}
