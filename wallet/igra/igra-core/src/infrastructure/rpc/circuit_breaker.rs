use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Simple circuit breaker for RPC calls.
pub struct CircuitBreaker {
    threshold: usize,
    cooldown: Duration,
    state: parking_lot::Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    failures: usize,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(threshold: usize, cooldown: Duration) -> Self {
        Self { threshold, cooldown, state: parking_lot::Mutex::new(State::default()) }
    }

    pub fn allow(&self) -> bool {
        let now = Instant::now();
        let mut guard = self.state.lock();

        match guard.open_until {
            Some(until) if now < until => {
                debug!(failures = guard.failures, "circuit breaker open; denying request");
                false
            }
            Some(_) => {
                info!(failures = guard.failures, "circuit breaker cooldown elapsed; closing");
                guard.failures = 0;
                guard.open_until = None;
                true
            }
            None => true,
        }
    }

    pub fn record_success(&self) {
        let mut guard = self.state.lock();
        if guard.failures > 0 || guard.open_until.is_some() {
            debug!(failures = guard.failures, "circuit breaker success; resetting");
        }
        guard.failures = 0;
        guard.open_until = None;
    }

    pub fn record_failure(&self) {
        let mut guard = self.state.lock();
        guard.failures = guard.failures.saturating_add(1);
        if guard.failures >= self.threshold && guard.open_until.is_none() {
            guard.open_until = Some(Instant::now() + self.cooldown);
            warn!(
                failures = guard.failures,
                threshold = self.threshold,
                cooldown_ms = self.cooldown.as_millis(),
                "circuit breaker opened"
            );
        } else {
            debug!(failures = guard.failures, threshold = self.threshold, "circuit breaker recorded failure");
        }
    }
}
