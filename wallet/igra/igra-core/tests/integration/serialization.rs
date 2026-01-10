use igra_core::domain::{EventSource, SigningEvent};
use std::collections::BTreeMap;

#[test]
fn test_serialization_when_signing_event_json_roundtrip_then_preserves_fields() {
    let event = SigningEvent {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 123,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    };
    let json = serde_json::to_string(&event).expect("json");
    let back: SigningEvent = serde_json::from_str(&json).expect("parse");
    assert_eq!(back.event_id, "event-1");
    assert_eq!(back.amount_sompi, 123);
}

