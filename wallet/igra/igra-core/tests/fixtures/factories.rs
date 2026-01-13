#![allow(dead_code)]

use crate::fixtures::{TEST_COORDINATOR_PEER_ID, TEST_DESTINATION_ADDRESS, TEST_EXTERNAL_ID_RAW};
use igra_core::domain::{Event, EventAuditData, GroupConfig, GroupMetadata, GroupPolicy, SourceType, StoredEvent};
use kaspa_addresses::Address;
use kaspa_txscript::pay_to_address_script;
use std::collections::BTreeMap;

pub fn stored_event() -> StoredEvent {
    let address = Address::try_from(TEST_DESTINATION_ADDRESS).expect("test destination");
    let destination = pay_to_address_script(&address);
    let external_id: [u8; 32] = hex::decode(TEST_EXTERNAL_ID_RAW.trim_start_matches("0x"))
        .expect("test external id")
        .as_slice()
        .try_into()
        .expect("external id is 32 bytes");

    StoredEvent {
        event: Event { external_id, source: SourceType::Api, destination, amount_sompi: 123 },
        received_at_nanos: 1,
        audit: EventAuditData {
            external_id_raw: TEST_EXTERNAL_ID_RAW.to_string(),
            destination_raw: TEST_DESTINATION_ADDRESS.to_string(),
            source_data: BTreeMap::new(),
        },
        proof: None,
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
