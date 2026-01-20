use crate::domain::model::GroupConfig;
use crate::foundation::{GroupId, ThresholdError};
use bincode::Options;

#[derive(Debug, Clone)]
pub struct GroupIdComputationResult {
    pub group_id: GroupId,
    pub member_count: usize,
    pub threshold_m: u16,
    pub threshold_n: u16,
    pub network_id: u8,
}

#[derive(Debug, Clone)]
pub struct GroupIdVerificationResult {
    pub matches: bool,
    pub computed: GroupId,
    pub expected: GroupId,
}

pub fn compute_group_id(config: &GroupConfig) -> Result<GroupIdComputationResult, ThresholdError> {
    let mut hasher = blake3::Hasher::new();

    hasher.update(&config.threshold_m.to_le_bytes());
    hasher.update(&config.threshold_n.to_le_bytes());

    let mut pubkeys = config.member_pubkeys.clone();
    pubkeys.sort();
    for pubkey in pubkeys {
        hasher.update(&pubkey);
    }

    hasher.update(&[config.network_id]);
    hasher.update(&config.fee_rate_sompi_per_gram.to_le_bytes());
    hasher.update(&config.finality_blue_score_threshold.to_le_bytes());
    hasher.update(&config.dust_threshold_sompi.to_le_bytes());
    hasher.update(&config.min_recipient_amount_sompi.to_le_bytes());
    hasher.update(&config.session_timeout_seconds.to_le_bytes());

    let metadata = bincode::DefaultOptions::new().with_fixint_encoding().serialize(&config.group_metadata)?;
    hasher.update(&metadata);

    let policy = bincode::DefaultOptions::new().with_fixint_encoding().serialize(&config.policy)?;
    hasher.update(&policy);

    Ok(GroupIdComputationResult {
        group_id: GroupId::from(*hasher.finalize().as_bytes()),
        member_count: config.member_pubkeys.len(),
        threshold_m: config.threshold_m,
        threshold_n: config.threshold_n,
        network_id: config.network_id,
    })
}

pub fn verify_group_id(config: &GroupConfig, expected: &GroupId) -> Result<GroupIdVerificationResult, ThresholdError> {
    let computed = compute_group_id(config)?.group_id;
    Ok(GroupIdVerificationResult { matches: &computed == expected, computed, expected: *expected })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::{GroupMetadata, GroupPolicy};

    fn base_config() -> GroupConfig {
        GroupConfig {
            network_id: 2,
            threshold_m: 2,
            threshold_n: 3,
            member_pubkeys: vec![
                hex::decode("b93ff1c2c3c89b5284e7e62c090032a3dac67a62b8b0372f9417ee5ee58b6d7b").unwrap(),
                hex::decode("a4ebef8e3553bd9bf9212c8c66c356d4beee198580cf9e85dc20a9305e5daba9").unwrap(),
                hex::decode("ca1582d546037ff74ebc280c84a40d7118c0959b7885b94eba69a578b273deec").unwrap(),
            ],
            fee_rate_sompi_per_gram: 0,
            finality_blue_score_threshold: 0,
            dust_threshold_sompi: 0,
            min_recipient_amount_sompi: 0,
            session_timeout_seconds: 60,
            group_metadata: GroupMetadata {
                creation_timestamp_nanos: 0,
                group_name: None,
                policy_version: 1,
                extra: Default::default(),
            },
            policy: GroupPolicy {
                allowed_destinations: vec![],
                min_amount_sompi: None,
                max_amount_sompi: None,
                max_daily_volume_sompi: None,
                require_reason: false,
            },
        }
    }

    #[test]
    fn verify_group_id_matches_for_computed_value() {
        let config = base_config();
        let computed = compute_group_id(&config).unwrap().group_id;
        let result = verify_group_id(&config, &computed).unwrap();
        assert!(result.matches);
        assert_eq!(result.computed, computed);
        assert_eq!(result.expected, computed);
    }

    #[test]
    fn compute_group_id_is_order_invariant_for_member_pubkeys() {
        let a = base_config();
        let mut b = base_config();
        b.member_pubkeys.reverse();
        assert_eq!(compute_group_id(&a).unwrap().group_id, compute_group_id(&b).unwrap().group_id);
    }

    #[test]
    fn compute_group_id_changes_when_policy_changes() {
        let a = base_config();
        let mut b = base_config();
        b.policy.require_reason = true;
        assert_ne!(compute_group_id(&a).unwrap().group_id, compute_group_id(&b).unwrap().group_id);
    }
}
