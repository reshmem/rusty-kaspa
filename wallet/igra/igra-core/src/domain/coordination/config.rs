use crate::domain::GroupConfig;
use crate::foundation::ThresholdError;
use serde::{Deserialize, Serialize};

pub const MAX_UTXOS_PER_PROPOSAL: usize = 100;
pub const MAX_OUTPUTS_PER_PROPOSAL: usize = 16;
pub const MAX_KPSBT_SIZE: usize = 64 * 1024;

pub const DEFAULT_PROPOSAL_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_MIN_INPUT_SCORE_DEPTH: u64 = 300;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub jitter_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self { max_retries: 3, base_delay_ms: 5_000, max_delay_ms: 30_000, backoff_multiplier: 2.0, jitter_ms: 250 }
    }
}

impl RetryConfig {
    pub fn delay_for_retry(&self, retry_count: u32) -> u64 {
        let exponent = retry_count.saturating_sub(1) as i32;
        let base = (self.base_delay_ms as f64) * self.backoff_multiplier.powi(exponent);
        (base.min(self.max_delay_ms as f64)) as u64
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoPhaseConfig {
    pub proposal_timeout_ms: u64,
    pub commit_quorum: u16,
    pub min_input_score_depth: u64,
    pub retry: RetryConfig,
    pub revalidate_inputs_on_commit: bool,
}

impl Default for TwoPhaseConfig {
    fn default() -> Self {
        Self {
            proposal_timeout_ms: DEFAULT_PROPOSAL_TIMEOUT_MS,
            commit_quorum: 0,
            min_input_score_depth: 0,
            retry: RetryConfig::default(),
            revalidate_inputs_on_commit: true,
        }
    }
}

impl TwoPhaseConfig {
    /// Compute effective config values given group/service settings.
    ///
    /// - If `commit_quorum == 0`, derive from `group.threshold_m` if available, otherwise from the event/script threshold.
    /// - If `min_input_score_depth == 0`, derive from `max(DEFAULT_MIN_INPUT_SCORE_DEPTH, group.finality_blue_score_threshold)`.
    pub fn effective(&self, group: Option<&GroupConfig>, required_sigs_fallback: Option<u16>) -> Result<Self, ThresholdError> {
        let mut out = self.clone();

        if out.commit_quorum == 0 {
            if let Some(group) = group {
                out.commit_quorum = group.threshold_m;
            } else {
                out.commit_quorum = required_sigs_fallback.unwrap_or(0);
            }
        }
        if out.commit_quorum == 0 {
            return Err(ThresholdError::ConfigError("two_phase.commit_quorum must be > 0".to_string()));
        }

        if out.min_input_score_depth == 0 {
            let group_finality = group.map(|g| g.finality_blue_score_threshold).unwrap_or(0);
            out.min_input_score_depth = DEFAULT_MIN_INPUT_SCORE_DEPTH.max(group_finality);
        }

        Ok(out)
    }
}
