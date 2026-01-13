use igra_core::domain::audit::types::AuditEvent;

#[test]
fn test_audit_event_when_serialized_then_roundtrips() {
    let evt = AuditEvent::EventReceived {
        event_id: "deadbeef".to_string(),
        external_request_id: None,
        source: "api".to_string(),
        recipient: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 1,
        timestamp_nanos: 1,
    };
    let json = serde_json::to_string(&evt).expect("json");
    let back: AuditEvent = serde_json::from_str(&json).expect("parse");
    assert!(matches!(back, AuditEvent::EventReceived { .. }));
}
