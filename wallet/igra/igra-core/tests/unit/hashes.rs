use igra_core::coordination::hashes::{event_hash, event_hash_without_signature, validation_hash};
use igra_core::model::{EventSource, SigningEvent};
use std::collections::BTreeMap;

fn sample_event() -> SigningEvent {
    SigningEvent {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 123,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

#[test]
fn event_hash_is_stable() {
    let event = sample_event();
    let h1 = event_hash(&event).expect("hash");
    let h2 = event_hash(&event).expect("hash");
    assert_eq!(h1, h2);
}

#[test]
fn event_hash_without_signature_ignores_signature() {
    let mut event = sample_event();
    let base = event_hash_without_signature(&event).expect("hash");
    event.signature = Some(vec![1, 2, 3]);
    let updated = event_hash_without_signature(&event).expect("hash");
    assert_eq!(base, updated);
}

#[test]
fn validation_hash_changes_with_inputs() {
    let ev = sample_event();
    let ev_hash = event_hash(&ev).expect("hash");
    let tx_hash = [9u8; 32];
    let per_input_a = vec![[1u8; 32], [2u8; 32]];
    let per_input_b = vec![[3u8; 32], [4u8; 32]];
    let a = validation_hash(&ev_hash, &tx_hash, &per_input_a);
    let b = validation_hash(&ev_hash, &tx_hash, &per_input_b);
    assert_ne!(a, b);
}
