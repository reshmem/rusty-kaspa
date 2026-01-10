use crate::fixtures::TEST_DESTINATION_ADDRESS;
use igra_core::domain::event::{decode_session_and_request_ids, into_signing_event, SigningEventParams, SigningEventWire};
use igra_core::domain::EventSource;
use igra_core::foundation::ThresholdError;
use std::collections::BTreeMap;

#[test]
fn test_event_decode_when_session_id_invalid_length_then_errors() {
    let params = SigningEventParams {
        session_id_hex: "aa".to_string(),
        request_id: "req-1".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: SigningEventWire {
            event_id: "event-1".to_string(),
            event_source: EventSource::Api { issuer: "tests".to_string() },
            derivation_path: "m/45'/111111'/0'/0/0".to_string(),
            derivation_index: Some(0),
            destination_address: TEST_DESTINATION_ADDRESS.to_string(),
            amount_sompi: 1,
            metadata: BTreeMap::new(),
            timestamp_nanos: 1,
            signature_hex: None,
            signature: None,
        },
    };

    let err = decode_session_and_request_ids(&params).unwrap_err();
    assert!(matches!(err, ThresholdError::Message(_)));
}

#[test]
fn test_event_wire_when_derivation_index_mismatch_then_errors() {
    let wire = SigningEventWire {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: TEST_DESTINATION_ADDRESS.to_string(),
        amount_sompi: 1,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature_hex: None,
        signature: None,
    };

    let err = into_signing_event(wire).unwrap_err();
    assert!(matches!(err, ThresholdError::InvalidDerivationPath(_)));
}
