use crate::error::ThresholdError;
use crate::model::{GroupConfig, Hash32};
use bincode::Options;

pub fn compute_group_id(config: &GroupConfig) -> Result<Hash32, ThresholdError> {
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

    let metadata = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&config.group_metadata)
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    hasher.update(&metadata);

    let policy = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&config.policy)
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    hasher.update(&policy);

    Ok(*hasher.finalize().as_bytes())
}

pub fn verify_group_id(config: &GroupConfig, expected: &Hash32) -> Result<bool, ThresholdError> {
    Ok(&compute_group_id(config)? == expected)
}
