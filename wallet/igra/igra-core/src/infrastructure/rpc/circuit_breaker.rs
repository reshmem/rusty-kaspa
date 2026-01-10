use std::time::{Duration, Instant};

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
        Self {
            threshold,
            cooldown,
            state: parking_lot::Mutex::new(State::default()),
        }
    }

    pub fn allow(&self) -> bool {
        let now = Instant::now();
        let mut guard = self.state.lock();

        match guard.open_until {
            Some(until) if now < until => false,
            Some(_) => {
                guard.failures = 0;
                guard.open_until = None;
                true
            }
            None => true,
        }
    }

    pub fn record_success(&self) {
        let mut guard = self.state.lock();
        guard.failures = 0;
        guard.open_until = None;
    }

    pub fn record_failure(&self) {
        let mut guard = self.state.lock();
        guard.failures = guard.failures.saturating_add(1);
        if guard.failures >= self.threshold && guard.open_until.is_none() {
            guard.open_until = Some(Instant::now() + self.cooldown);
        }
    }
}
