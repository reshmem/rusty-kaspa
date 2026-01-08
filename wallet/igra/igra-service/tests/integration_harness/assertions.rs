use igra_core::model::RequestDecision;
use igra_core::storage::Storage;
use igra_core::types::RequestId;

pub fn assert_request_finalized(storage: &dyn Storage, request_id: &str) {
    let request = storage.get_request(&RequestId::from(request_id)).expect("get request").expect("request missing");
    assert!(matches!(request.decision, RequestDecision::Finalized));
    assert!(request.final_tx_id.is_some(), "missing final tx id");
}
