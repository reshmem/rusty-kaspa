use igra_core::domain::group_id::compute_group_id;
use igra_core::domain::hashes::{event_hash, event_hash_without_signature, validation_hash};
use igra_core::domain::{EventSource, GroupConfig, GroupMetadata, GroupPolicy, SigningEvent};
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
fn test_event_hashing_when_same_event_then_is_stable() {
    let event = sample_event();
    let h1 = event_hash(&event).expect("hash");
    let h2 = event_hash(&event).expect("hash");
    assert_eq!(h1, h2);
}

#[test]
fn test_event_hashing_when_signature_changes_then_hash_without_signature_is_stable() {
    let mut event = sample_event();
    let base = event_hash_without_signature(&event).expect("hash");
    event.signature = Some(vec![1, 2, 3]);
    let updated = event_hash_without_signature(&event).expect("hash");
    assert_eq!(base, updated);
}

#[test]
fn test_validation_hash_when_inputs_change_then_changes() {
    let ev = sample_event();
    let ev_hash = event_hash(&ev).expect("hash");
    let tx_hash = [9u8; 32];
    let per_input_a = vec![[1u8; 32], [2u8; 32]];
    let per_input_b = vec![[3u8; 32], [4u8; 32]];
    let a = validation_hash(&ev_hash, &tx_hash, &per_input_a);
    let b = validation_hash(&ev_hash, &tx_hash, &per_input_b);
    assert_ne!(a, b);
}

fn base_group_config() -> GroupConfig {
    GroupConfig {
        network_id: 0,
        threshold_m: 2,
        threshold_n: 3,
        member_pubkeys: vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
        fee_rate_sompi_per_gram: 1,
        finality_blue_score_threshold: 5,
        dust_threshold_sompi: 1,
        min_recipient_amount_sompi: 1,
        session_timeout_seconds: 60,
        group_metadata: GroupMetadata { creation_timestamp_nanos: 1, group_name: None, policy_version: 1, extra: Default::default() },
        policy: GroupPolicy::default(),
    }
}

#[test]
fn test_group_id_when_same_config_then_is_deterministic() {
    let id1 = compute_group_id(&base_group_config()).expect("group id").group_id;
    let id2 = compute_group_id(&base_group_config()).expect("group id").group_id;
    assert_eq!(id1, id2);
}

#[test]
fn test_group_id_when_threshold_changes_then_changes() {
    let mut config = base_group_config();
    let id1 = compute_group_id(&config).expect("group id").group_id;
    config.threshold_m = 3;
    let id2 = compute_group_id(&config).expect("group id").group_id;
    assert_ne!(id1, id2);
}

#[test]
fn test_group_id_when_pubkeys_change_then_changes() {
    let mut config = base_group_config();
    let id1 = compute_group_id(&config).expect("group id").group_id;
    config.member_pubkeys.push(vec![10, 11, 12]);
    let id2 = compute_group_id(&config).expect("group id").group_id;
    assert_ne!(id1, id2);
}
