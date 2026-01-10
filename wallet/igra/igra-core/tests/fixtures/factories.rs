#![allow(dead_code)]

use crate::fixtures::{TEST_COORDINATOR_PEER_ID, TEST_DERIVATION_PATH, TEST_DESTINATION_ADDRESS, TEST_EVENT_ID};
use igra_core::domain::{EventSource, GroupConfig, GroupMetadata, GroupPolicy, SigningEvent};
use std::collections::BTreeMap;

pub fn signing_event() -> SigningEvent {
    SigningEvent {
        event_id: TEST_EVENT_ID.to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: TEST_DERIVATION_PATH.to_string(),
        derivation_index: Some(0),
        destination_address: TEST_DESTINATION_ADDRESS.to_string(),
        amount_sompi: 123,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

pub fn group_policy_allow_all() -> GroupPolicy {
    GroupPolicy {
        allowed_destinations: Vec::new(),
        min_amount_sompi: None,
        max_amount_sompi: None,
        max_daily_volume_sompi: None,
        require_reason: false,
    }
}

pub fn group_config_2_of_3() -> GroupConfig {
    GroupConfig {
        network_id: 0,
        threshold_m: 2,
        threshold_n: 3,
        member_pubkeys: vec![b"pk1".to_vec(), b"pk2".to_vec(), b"pk3".to_vec()],
        fee_rate_sompi_per_gram: 1,
        finality_blue_score_threshold: 5,
        dust_threshold_sompi: 1,
        min_recipient_amount_sompi: 1,
        session_timeout_seconds: 60,
        group_metadata: GroupMetadata { creation_timestamp_nanos: 1, group_name: None, policy_version: 1, extra: Default::default() },
        policy: group_policy_allow_all(),
    }
}

pub fn coordinator_peer_id() -> String {
    TEST_COORDINATOR_PEER_ID.to_string()
}
