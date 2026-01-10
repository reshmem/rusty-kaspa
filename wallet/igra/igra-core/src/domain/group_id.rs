use crate::domain::model::GroupConfig;
use crate::foundation::{Hash32, ThresholdError};
use bincode::Options;

#[derive(Debug, Clone)]
pub struct GroupIdComputationResult {
    pub group_id: Hash32,
    pub member_count: usize,
    pub threshold_m: u16,
    pub threshold_n: u16,
    pub network_id: u8,
}

#[derive(Debug, Clone)]
pub struct GroupIdVerificationResult {
    pub matches: bool,
    pub computed: Hash32,
    pub expected: Hash32,
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
        group_id: *hasher.finalize().as_bytes(),
        member_count: config.member_pubkeys.len(),
        threshold_m: config.threshold_m,
        threshold_n: config.threshold_n,
        network_id: config.network_id,
    })
}

pub fn verify_group_id(config: &GroupConfig, expected: &Hash32) -> Result<GroupIdVerificationResult, ThresholdError> {
    let computed = compute_group_id(config)?.group_id;
    Ok(GroupIdVerificationResult { matches: &computed == expected, computed, expected: *expected })
}
