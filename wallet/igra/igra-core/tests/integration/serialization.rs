use crate::fixtures::builders::StoredEventBuilder;
use igra_core::domain::StoredEvent;

#[test]
fn test_serialization_when_stored_event_json_roundtrip_then_preserves_fields() {
    let event = StoredEventBuilder::default().build();
    let json = serde_json::to_string(&event).expect("json");
    let back: StoredEvent = serde_json::from_str(&json).expect("parse");
    assert_eq!(back.event.amount_sompi, 123);
    assert_eq!(back.audit.destination_raw, event.audit.destination_raw);
}
