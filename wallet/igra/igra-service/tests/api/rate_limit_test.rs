use super::{basic_state, call_rpc};
use igra_service::api::json_rpc::build_router;
use serde_json::json;

#[tokio::test]
async fn rpc_rate_limit_enforced() {
    let mut state = (*basic_state()).clone();
    state.rate_limit_rps = 1;
    state.rate_limit_burst = 0;
    let state = std::sync::Arc::new(state);

    let router = build_router(state);

    for idx in 0..2 {
        let (status, _body) = call_rpc(
            &router,
            "127.0.0.1:10003".parse().expect("addr"),
            None,
            json!({ "jsonrpc": "2.0", "method": "does.not.exist", "params": {}, "id": idx }),
        )
        .await;
        if idx == 0 {
            assert!(status.is_success());
        } else {
            assert_eq!(status.as_u16(), 429);
        }
    }
}
