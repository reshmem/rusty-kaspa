use igra_core::domain::group_id::compute_group_id;
use igra_core::domain::hashes::{compute_event_id, validation_hash};
use igra_core::domain::{Event, GroupConfig, GroupMetadata, GroupPolicy, SourceType};
use igra_core::foundation::{ExternalId, TxTemplateHash};
use kaspa_addresses::Address;
use kaspa_txscript::pay_to_address_script;

fn sample_event() -> Event {
    let address = Address::try_from("kaspatest:qz0hz8jkn6ptfhq3v9fg3jhqw5jtsfgy62wan8dhe8fqkhdqsahswcpe2ch3m").unwrap();
    let destination = pay_to_address_script(&address);
    Event { external_id: ExternalId::new([7u8; 32]), source: SourceType::Api, destination, amount_sompi: 123 }
}

#[test]
fn test_event_id_when_same_event_then_is_stable() {
    let event = sample_event();
    let h1 = compute_event_id(&event);
    let h2 = compute_event_id(&event);
    assert_eq!(h1, h2);
}

#[test]
fn test_validation_hash_when_inputs_change_then_changes() {
    let ev_hash = compute_event_id(&sample_event());
    let tx_hash = TxTemplateHash::new([9u8; 32]);
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
