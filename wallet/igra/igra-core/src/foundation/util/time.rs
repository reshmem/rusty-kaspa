use crate::foundation::ThresholdError;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_timestamp_nanos_env(env_var: Option<&str>) -> Result<u64, ThresholdError> {
    if let Some(var) = env_var {
        if let Ok(value) = std::env::var(var) {
            return value.parse::<u64>().map_err(|err| ThresholdError::Message(err.to_string()));
        }
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(now.as_secs().saturating_mul(1_000_000_000).saturating_add(u64::from(now.subsec_nanos())))
}

/// Returns the current wall-clock timestamp in nanoseconds.
///
/// For test determinism, this respects `TEST_NOW_NANOS_ENV_VAR` when set.
pub fn now_nanos() -> u64 {
    current_timestamp_nanos_env(Some(crate::foundation::constants::TEST_NOW_NANOS_ENV_VAR))
        .or_else(|_| current_timestamp_nanos_env(None))
        .unwrap_or(0)
}

pub fn day_start_nanos(timestamp_nanos: u64) -> u64 {
    (timestamp_nanos / crate::foundation::constants::NANOS_PER_DAY) * crate::foundation::constants::NANOS_PER_DAY
}
