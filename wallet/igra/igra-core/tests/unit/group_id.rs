use igra_core::group_id::compute_group_id;
use igra_core::model::{GroupConfig, GroupMetadata, GroupPolicy};

fn base_config() -> GroupConfig {
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
fn group_id_is_deterministic() {
    let id1 = compute_group_id(&base_config()).expect("group id");
    let id2 = compute_group_id(&base_config()).expect("group id");
    assert_eq!(id1, id2);
}

#[test]
fn group_id_changes_with_threshold() {
    let mut config = base_config();
    let id1 = compute_group_id(&config).expect("group id");
    config.threshold_m = 3;
    let id2 = compute_group_id(&config).expect("group id");
    assert_ne!(id1, id2);
}

#[test]
fn group_id_changes_with_pubkeys() {
    let mut config = base_config();
    let id1 = compute_group_id(&config).expect("group id");
    config.member_pubkeys.push(vec![10, 11, 12]);
    config.threshold_n = 4;
    let id2 = compute_group_id(&config).expect("group id");
    assert_ne!(id1, id2);
}

#[test]
fn group_id_ignores_pubkey_order() {
    let mut config1 = base_config();
    let mut config2 = base_config();
    config2.member_pubkeys.reverse();
    let id1 = compute_group_id(&config1).expect("group id");
    let id2 = compute_group_id(&config2).expect("group id");
    assert_eq!(id1, id2);
}
