//! Time utilities for consistent timestamp handling across the codebase.

use crate::error::ThresholdError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const NANOS_PER_SEC: u64 = 1_000_000_000;
pub const NANOS_PER_DAY: u64 = 24 * 60 * 60 * NANOS_PER_SEC;

/// Returns current timestamp in nanoseconds since Unix epoch.
///
/// If `env_override` is provided and set, that value is used instead (primarily for tests).
pub fn current_timestamp_nanos_env(env_override: Option<&str>) -> Result<u64, ThresholdError> {
    if let Some(var) = env_override {
        if let Ok(value) = std::env::var(var) {
            if let Ok(parsed) = value.trim().parse::<u64>() {
                return Ok(parsed);
            }
        }
    }

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ThresholdError::Message(format!("system clock before epoch: {}", e)))?;
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos() as u64;
    secs.checked_mul(NANOS_PER_SEC)
        .and_then(|v| v.checked_add(nanos))
        .ok_or_else(|| ThresholdError::Message("timestamp overflow".to_string()))
}

/// Returns current timestamp without env override.
pub fn current_timestamp_nanos() -> Result<u64, ThresholdError> {
    current_timestamp_nanos_env(None)
}

/// Start of UTC day (00:00) for a given timestamp.
pub fn day_start_nanos(timestamp_nanos: u64) -> u64 {
    (timestamp_nanos / NANOS_PER_DAY) * NANOS_PER_DAY
}

/// Adds a duration to a timestamp with overflow checking.
pub fn add_duration(timestamp_nanos: u64, duration: Duration) -> Result<u64, ThresholdError> {
    let duration_nanos = duration
        .as_secs()
        .checked_mul(NANOS_PER_SEC)
        .and_then(|v| v.checked_add(duration.subsec_nanos() as u64))
        .ok_or_else(|| ThresholdError::Message("duration overflow".to_string()))?;

    timestamp_nanos.checked_add(duration_nanos).ok_or_else(|| ThresholdError::Message("timestamp overflow".to_string()))
}
