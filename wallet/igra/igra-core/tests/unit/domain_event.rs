use crate::fixtures::{TEST_DESTINATION_ADDRESS, TEST_EXTERNAL_ID_RAW, TEST_SESSION_ID_HEX};
use igra_core::domain::event::{decode_session_and_coordinator_ids, SigningEventParams, SigningEventWire};
use igra_core::domain::SourceType;
use igra_core::foundation::ThresholdError;
use std::collections::BTreeMap;

#[test]
fn test_event_decode_when_session_id_invalid_length_then_errors() {
    let params = SigningEventParams {
        session_id_hex: "aa".to_string(),
        external_request_id: None,
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        event: SigningEventWire {
            external_id: TEST_EXTERNAL_ID_RAW.to_string(),
            source: SourceType::Api,
            destination_address: TEST_DESTINATION_ADDRESS.to_string(),
            amount_sompi: 1,
            metadata: BTreeMap::new(),
            proof_hex: None,
            proof: None,
        },
    };

    let err = decode_session_and_coordinator_ids(&params).unwrap_err();
    assert!(matches!(err, ThresholdError::Message(_)));
}

#[test]
fn test_event_decode_when_coordinator_peer_id_too_long_then_errors() {
    let params = SigningEventParams {
        session_id_hex: TEST_SESSION_ID_HEX.to_string(),
        external_request_id: None,
        coordinator_peer_id: "a".repeat(300),
        expires_at_nanos: 0,
        event: SigningEventWire {
            external_id: TEST_EXTERNAL_ID_RAW.to_string(),
            source: SourceType::Api,
            destination_address: TEST_DESTINATION_ADDRESS.to_string(),
            amount_sompi: 1,
            metadata: BTreeMap::new(),
            proof_hex: None,
            proof: None,
        },
    };

    let err = decode_session_and_coordinator_ids(&params).unwrap_err();
    assert!(matches!(err, ThresholdError::Message(_)));
}
