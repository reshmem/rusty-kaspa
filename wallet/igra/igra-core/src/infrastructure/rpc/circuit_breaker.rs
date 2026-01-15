use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::foundation::CIRCUIT_BREAKER_BASE_BACKOFF_SECS;

const MAX_BACKOFF_EXPONENT_SHIFT: u32 = 30;
const JITTER_BUCKET_MODULO: u64 = 41;
const JITTER_BUCKET_HALF_RANGE: i64 = 20;
const JITTER_PPM_SCALE_FACTOR: i64 = 10_000;
const PPM_SCALE: i64 = 1_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    /// Failures before opening circuit.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Max time circuit stays open before probing (seconds).
    #[serde(default = "default_open_duration_secs")]
    pub open_duration_secs: u64,
    /// Successes required in half-open before closing.
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

const fn default_failure_threshold() -> u32 {
    5
}

const fn default_open_duration_secs() -> u64 {
    30
}

const fn default_success_threshold() -> u32 {
    2
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            open_duration_secs: default_open_duration_secs(),
            success_threshold: default_success_threshold(),
        }
    }
}

/// Circuit breaker with Closed/Open/HalfOpen states.
/// Intended to be instantiated per RPC method.
pub struct CircuitBreaker {
    cfg: CircuitBreakerConfig,
    state: parking_lot::Mutex<State>,
}

#[derive(Debug)]
enum State {
    Closed { failures: u32 },
    Open { until: Instant, open_count: u32 },
    HalfOpen { successes: u32, open_count: u32 },
}

impl Default for State {
    fn default() -> Self {
        Self::Closed { failures: 0 }
    }
}

impl CircuitBreaker {
    pub fn new(cfg: CircuitBreakerConfig) -> Self {
        Self { cfg, state: parking_lot::Mutex::new(State::default()) }
    }

    pub fn allow(&self) -> bool {
        let now = Instant::now();
        let mut guard = self.state.lock();
        match *guard {
            State::Closed { .. } => true,
            State::HalfOpen { .. } => true,
            State::Open { until, open_count } => {
                if now < until {
                    debug!(
                        "circuit breaker open; denying request open_until_ms={} open_count={}",
                        until.saturating_duration_since(now).as_millis(),
                        open_count
                    );
                    false
                } else {
                    info!("circuit breaker transitioning open->half_open open_count={}", open_count);
                    *guard = State::HalfOpen { successes: 0, open_count };
                    true
                }
            }
        }
    }

    pub fn record_success(&self) {
        let mut guard = self.state.lock();
        match *guard {
            State::Closed { failures } => {
                if failures > 0 {
                    debug!("circuit breaker success; resetting failures={}", failures);
                }
                *guard = State::Closed { failures: 0 };
            }
            State::HalfOpen { successes, .. } => {
                let next = successes.saturating_add(1);
                if next >= self.cfg.success_threshold.max(1) {
                    info!("circuit breaker transitioning half_open->closed successes={}", next);
                    *guard = State::Closed { failures: 0 };
                } else {
                    debug!("circuit breaker half-open success successes={}", next);
                    *guard = State::HalfOpen { successes: next, open_count: self.open_count(&guard) };
                }
            }
            State::Open { .. } => {
                // If callers record success without allow() (shouldn't happen), ignore.
            }
        }
    }

    pub fn record_failure(&self) {
        let mut guard = self.state.lock();
        match *guard {
            State::Closed { failures } => {
                let next = failures.saturating_add(1);
                if next >= self.cfg.failure_threshold.max(1) {
                    let (until, open_count) = self.open_until(1);
                    warn!(
                        "circuit breaker opened failures={} threshold={} open_for_ms={} open_count={}",
                        next,
                        self.cfg.failure_threshold,
                        until.saturating_duration_since(Instant::now()).as_millis(),
                        open_count
                    );
                    *guard = State::Open { until, open_count };
                } else {
                    debug!("circuit breaker recorded failure failures={} threshold={}", next, self.cfg.failure_threshold);
                    *guard = State::Closed { failures: next };
                }
            }
            State::HalfOpen { open_count, .. } => {
                let (until, next_open_count) = self.open_until(open_count.saturating_add(1));
                warn!(
                    "circuit breaker re-opened from half-open open_for_ms={} open_count={}",
                    until.saturating_duration_since(Instant::now()).as_millis(),
                    next_open_count
                );
                *guard = State::Open { until, open_count: next_open_count };
            }
            State::Open { .. } => {
                // Already open.
            }
        }
    }

    fn open_count(&self, state: &State) -> u32 {
        match *state {
            State::Closed { .. } => 0,
            State::Open { open_count, .. } => open_count,
            State::HalfOpen { open_count, .. } => open_count,
        }
    }

    fn open_until(&self, open_count: u32) -> (Instant, u32) {
        // Exponential backoff with a cap at cfg.open_duration_secs.
        let base = Duration::from_secs(CIRCUIT_BREAKER_BASE_BACKOFF_SECS);
        let max = Duration::from_secs(self.cfg.open_duration_secs.max(1));
        let shift = open_count.saturating_sub(1).min(MAX_BACKOFF_EXPONENT_SHIFT);
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        let exp = base.checked_mul(factor).unwrap_or(max);
        let capped = if exp > max { max } else { exp };

        // Jitter ±20% based on wall-clock nanos (good enough; avoids adding rand dependency).
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(0);
        let jitter_bucket = (nanos % JITTER_BUCKET_MODULO) as i64 - JITTER_BUCKET_HALF_RANGE; // [-20..20]
        let jitter_ppm = PPM_SCALE + jitter_bucket * JITTER_PPM_SCALE_FACTOR; // ±20%
        let jittered_ms = (capped.as_millis() as i64).saturating_mul(jitter_ppm) / PPM_SCALE;
        let jittered = Duration::from_millis(jittered_ms.max(1) as u64);

        (Instant::now() + jittered, open_count)
    }
}
