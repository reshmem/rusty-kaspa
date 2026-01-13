use crate::api::state::RpcState;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use igra_core::foundation::{RPC_RATE_LIMIT_CLEANUP_INTERVAL_SECS, RPC_RATE_LIMIT_ENTRY_TTL_SECS, RPC_RATE_LIMIT_WINDOW_SECS};
use log::{debug, error};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct BucketState {
    window_start: Instant,
    window_count: u32,
    burst_count: u32,
    last_seen: Instant,
}

impl BucketState {
    fn new(now: Instant) -> Self {
        Self { window_start: now, window_count: 0, burst_count: 0, last_seen: now }
    }

    fn reset_window(&mut self, now: Instant) {
        self.window_start = now;
        self.window_count = 0;
        self.burst_count = 0;
    }
}

#[derive(Debug)]
struct RateLimiterState {
    per_ip: HashMap<IpAddr, BucketState>,
    last_cleanup: Instant,
}

impl RateLimiterState {
    fn new(now: Instant) -> Self {
        Self { per_ip: HashMap::new(), last_cleanup: now }
    }

    fn cleanup(&mut self, now: Instant) {
        const CLEANUP_INTERVAL: Duration = Duration::from_secs(RPC_RATE_LIMIT_CLEANUP_INTERVAL_SECS);
        const ENTRY_TTL: Duration = Duration::from_secs(RPC_RATE_LIMIT_ENTRY_TTL_SECS);

        if now.duration_since(self.last_cleanup) < CLEANUP_INTERVAL {
            return;
        }
        self.last_cleanup = now;
        let cutoff = now.checked_sub(ENTRY_TTL).unwrap_or(now);
        self.per_ip.retain(|_, bucket| bucket.last_seen >= cutoff);
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    inner: Mutex<RateLimiterState>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { inner: Mutex::new(RateLimiterState::new(Instant::now())) }
    }

    fn allow(&self, now: Instant, client_ip: IpAddr, rps: u32, burst: u32) -> bool {
        match self.inner.lock() {
            Ok(mut state) => {
                state.cleanup(now);
                let bucket = state.per_ip.entry(client_ip).or_insert_with(|| BucketState::new(now));
                bucket.last_seen = now;

                if now.duration_since(bucket.window_start) >= Duration::from_secs(RPC_RATE_LIMIT_WINDOW_SECS) {
                    bucket.reset_window(now);
                }

                if bucket.window_count < rps {
                    bucket.window_count += 1;
                    true
                } else if bucket.burst_count < burst {
                    bucket.burst_count += 1;
                    true
                } else {
                    false
                }
            }
            Err(_) => {
                error!("rate limiter lock poisoned - denying request");
                false
            }
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn rate_limit_middleware(
    State(state): State<std::sync::Arc<RpcState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let rps = state.rate_limit_rps.max(1);
    let burst = state.rate_limit_burst;
    let now = Instant::now();
    let client_ip = addr.ip();

    let allow = state.rate_limiter.allow(now, client_ip, rps, burst);

    if !allow {
        debug!("rate limit exceeded client_ip={} rps={} burst={}", client_ip, rps, burst);
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    next.run(req).await
}
