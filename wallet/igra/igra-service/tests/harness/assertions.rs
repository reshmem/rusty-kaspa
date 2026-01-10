use igra_core::domain::RequestDecision;
use igra_core::foundation::RequestId;
use igra_core::infrastructure::storage::Storage;

pub fn assert_request_finalized(storage: &dyn Storage, request_id: &str) {
    let request = storage.get_request(&RequestId::from(request_id)).expect("get request").expect("request missing");
    assert!(matches!(request.decision, RequestDecision::Finalized));
    assert!(request.final_tx_id.is_some(), "missing final tx id");
}

