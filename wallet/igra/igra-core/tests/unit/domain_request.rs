use igra_core::domain::request::state_machine::{ensure_valid_transition, is_terminal, TypedSigningRequest};
use igra_core::domain::RequestDecision;
use igra_core::foundation::{PeerId, RequestId, SessionId, TransactionId};

#[test]
fn test_request_state_when_invalid_transition_then_errors() {
    let err = ensure_valid_transition(&RequestDecision::Finalized, &RequestDecision::Pending).unwrap_err();
    assert!(matches!(err, igra_core::foundation::ThresholdError::InvalidStateTransition { .. }));
}

#[test]
fn test_request_state_when_terminal_then_is_terminal_true() {
    assert!(is_terminal(&RequestDecision::Finalized));
    assert!(!is_terminal(&RequestDecision::Pending));
}

#[test]
fn test_request_typestate_when_approved_then_can_finalize() {
    let req = TypedSigningRequest::new(
        RequestId::from("req-1"),
        SessionId::from([1u8; 32]),
        [2u8; 32],
        PeerId::from("peer-1"),
        [3u8; 32],
        [4u8; 32],
        0,
    );
    let approved = req.approve().expect("approve");
    let _finalized = approved.finalize(TransactionId::from([9u8; 32]), None).expect("finalize");
}
