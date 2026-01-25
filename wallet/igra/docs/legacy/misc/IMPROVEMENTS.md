# Infrastructure Improvements

This document tracks opportunities to replace custom implementations with production-ready third-party libraries.

---

## Table of Contents

1. [Overview](#overview)
2. [High Priority](#high-priority)
   - [Rate Limiting](#1-rate-limiting)
   - [Retry with Backoff](#2-retry-with-backoff)
   - [Circuit Breaker](#3-circuit-breaker)
3. [Medium Priority](#medium-priority)
   - [Audit File Logging](#4-audit-file-logging)
4. [Dependencies](#dependencies)
5. [Migration Plan](#migration-plan)
6. [Checklist](#checklist)

---

## Overview

### Current State

| Component | Custom Code | Production Library |
|-----------|-------------|-------------------|
| Rate limiting (transport) | ~157 lines | `governor` |
| Rate limiting (HTTP middleware) | ~123 lines | `tower-governor` |
| Retry logic | ~36 lines | `backoff` |
| Circuit breaker | ~66 lines | `failsafe` |
| Audit file logging | ~60 lines | `tracing-appender` |
| **Total** | **~442 lines** | **~80 lines** |

### What's NOT Being Replaced

| Component | Reason |
|-----------|--------|
| RPC client (`grpc.rs`) | Already uses `kaspa_grpc_client` - just a domain abstraction |
| Error handling | Already uses `thiserror` - best practice |
| Config loading | Already uses `figment` - recently refactored |
| CLI parsing | Already uses `clap` |
| State machine | Domain-specific, clean type-state pattern |
| Validation logic | Domain-specific Hyperlane/LayerZero rules |

---

## High Priority

### 1. Rate Limiting

**Current files:**
- `igra-core/src/infrastructure/transport/rate_limiter.rs` (~157 lines)
- `igra-service/src/api/middleware/rate_limit.rs` (~123 lines)

**Problem:** Two custom token-bucket implementations with manual cleanup, no jitter, no metrics.

**Solution:** Use `governor` crate with `tower-governor` for Axum integration.

#### Current Implementation

```rust
// infrastructure/transport/rate_limiter.rs
pub struct RateLimiter {
    config: RateLimiterConfig,
    buckets: parking_lot::RwLock<HashMap<String, TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn check(&self, peer_id: &str) -> bool {
        // Manual token bucket logic...
    }

    pub fn cleanup_stale_buckets(&self) {
        // Manual cleanup logic...
    }
}
```

#### New Implementation

```rust
// infrastructure/transport/rate_limiter.rs
use governor::{Quota, RateLimiter as Governor, clock::DefaultClock, state::keyed::DashMapStateStore};
use std::num::NonZeroU32;

pub type RateLimiter = Governor<String, DashMapStateStore<String>, DefaultClock>;

pub fn create_rate_limiter(requests_per_second: u32, burst: u32) -> RateLimiter {
    let quota = Quota::per_second(NonZeroU32::new(requests_per_second).unwrap())
        .allow_burst(NonZeroU32::new(burst).unwrap());
    Governor::dashmap(quota)
}

// Usage:
pub async fn check_rate_limit(limiter: &RateLimiter, peer_id: &str) -> Result<(), RateLimitError> {
    limiter
        .check_key(&peer_id.to_string())
        .map_err(|_| RateLimitError::TooManyRequests)
}
```

#### HTTP Middleware (Axum)

```rust
// api/middleware/rate_limit.rs
use axum::{Router, extract::ConnectInfo};
use tower_governor::{GovernorLayer, GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor};

pub fn rate_limit_layer(rps: u32, burst: u32) -> GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware<BodyType>> {
    let config = GovernorConfigBuilder::default()
        .per_second(rps as u64)
        .burst_size(burst)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .unwrap();

    GovernorLayer { config }
}

// Usage in router:
let app = Router::new()
    .route("/api/sign", post(sign_handler))
    .layer(rate_limit_layer(10, 20));
```

**Benefits:**
- Production-tested (used by major Rust web services)
- Automatic cleanup (no manual `cleanup_stale_buckets`)
- Built-in jitter support
- Metrics integration ready
- ~280 lines → ~30 lines

---

### 2. Retry with Backoff

**Current file:** `igra-core/src/infrastructure/rpc/retry/mod.rs` (~36 lines)

**Problem:** Fixed delay only, no exponential backoff, no jitter.

**Solution:** Use `backoff` crate with tokio support.

#### Current Implementation

```rust
// infrastructure/rpc/retry/mod.rs
pub async fn retry<F, Fut, T>(mut attempts: usize, delay: Duration, mut op: F) -> Result<T, ThresholdError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ThresholdError>>,
{
    while attempts > 0 {
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) => {
                attempts -= 1;
                if attempts > 0 {
                    sleep(delay).await;
                }
                last_err = Some(err);
            }
        }
    }
    Err(last_err.unwrap())
}
```

#### New Implementation

```rust
// infrastructure/rpc/retry/mod.rs
use backoff::{ExponentialBackoff, ExponentialBackoffBuilder};
use backoff::future::retry;
use std::time::Duration;
use tracing::debug;

/// Default backoff configuration for RPC calls.
pub fn rpc_backoff() -> ExponentialBackoff {
    ExponentialBackoffBuilder::default()
        .with_initial_interval(Duration::from_millis(100))
        .with_max_interval(Duration::from_secs(5))
        .with_max_elapsed_time(Some(Duration::from_secs(30)))
        .with_randomization_factor(0.3)  // Jitter!
        .build()
}

/// Retry an async operation with exponential backoff.
pub async fn retry_rpc<F, Fut, T, E>(op: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, backoff::Error<E>>>,
{
    retry(rpc_backoff(), op).await
}

// Usage:
let result = retry_rpc(|| async {
    grpc_client
        .get_utxos_by_addresses(addresses.clone())
        .await
        .map_err(|e| {
            debug!(error = %e, "RPC call failed, will retry");
            backoff::Error::transient(e)
        })
}).await?;
```

**Benefits:**
- Exponential backoff (not fixed delay)
- Built-in jitter prevents thundering herd
- Configurable max elapsed time
- Distinguishes transient vs permanent errors
- ~36 lines → ~15 lines

---

### 3. Circuit Breaker

**Current file:** `igra-core/src/infrastructure/rpc/circuit_breaker.rs` (~66 lines)

**Problem:** Simple open/closed only, no half-open state, no metrics.

**Solution:** Use `failsafe` crate for comprehensive circuit breaker.

#### Current Implementation

```rust
// infrastructure/rpc/circuit_breaker.rs
pub struct CircuitBreaker {
    threshold: usize,
    cooldown: Duration,
    state: parking_lot::Mutex<State>,
}

struct State {
    failures: usize,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    pub fn allow(&self) -> bool { /* ... */ }
    pub fn record_success(&self) { /* ... */ }
    pub fn record_failure(&self) { /* ... */ }
}
```

#### New Implementation

```rust
// infrastructure/rpc/circuit_breaker.rs
use failsafe::{Config, CircuitBreaker, Error as FailsafeError};
use std::time::Duration;

/// Create a circuit breaker for RPC calls.
pub fn rpc_circuit_breaker() -> CircuitBreaker<(), ()> {
    Config::new()
        .failure_threshold(5)           // Open after 5 failures
        .success_threshold(2)           // Close after 2 successes in half-open
        .half_open_timeout(Duration::from_secs(30))  // Try again after 30s
        .build()
}

// Usage with the circuit breaker:
pub async fn call_with_breaker<F, Fut, T, E>(
    breaker: &CircuitBreaker<(), ()>,
    op: F,
) -> Result<T, CircuitBreakerError<E>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    if !breaker.is_call_permitted() {
        return Err(CircuitBreakerError::Open);
    }

    match op().await {
        Ok(v) => {
            breaker.on_success();
            Ok(v)
        }
        Err(e) => {
            breaker.on_error();
            Err(CircuitBreakerError::Inner(e))
        }
    }
}

#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    Open,
    Inner(E),
}
```

**Benefits:**
- Half-open state (gradual recovery)
- Success threshold for closing
- Thread-safe by default
- Works with async
- ~66 lines → ~25 lines

---

## Medium Priority

### 4. Audit File Logging

**Current file:** `igra-core/src/infrastructure/audit/` (~60 lines of file logger)

**Problem:** Custom rolling file implementation.

**Solution:** Use `tracing-appender` for file-based audit trails.

#### Current Implementation

```rust
// infrastructure/audit/file.rs (conceptual)
pub struct FileAuditLogger {
    path: PathBuf,
    file: Mutex<File>,
}

impl FileAuditLogger {
    pub fn log(&self, event: &AuditEvent) {
        let mut file = self.file.lock();
        writeln!(file, "{}", serde_json::to_string(event).unwrap()).ok();
    }
}
```

#### New Implementation

```rust
// infrastructure/audit/mod.rs
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;

pub fn init_audit_logging(audit_dir: &Path) -> tracing_appender::non_blocking::WorkerGuard {
    // Rolling daily audit logs
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        audit_dir,
        "audit.log",
    );

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let audit_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            meta.target().starts_with("igra::audit")
        }));

    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(audit_layer)
    ).expect("setting default subscriber");

    guard  // Keep this alive for the lifetime of the app
}

// Usage:
tracing::info!(target: "igra::audit", event = "sign_request", request_id = %id, amount = amount);
```

**Benefits:**
- Non-blocking writes (better performance)
- Automatic rotation (daily, hourly, or by size)
- Integrates with existing tracing infrastructure
- ~60 lines → ~20 lines

---

## Dependencies

Add to `igra-core/Cargo.toml`:

```toml
[dependencies]
# Resilience patterns
governor = "0.6"
backoff = { version = "0.4", features = ["tokio"] }
failsafe = "1.3"

# Audit logging (optional, if refactoring audit)
tracing-appender = "0.2"
```

Add to `igra-service/Cargo.toml`:

```toml
[dependencies]
# HTTP rate limiting middleware
tower_governor = "0.4"
```

---

## Migration Plan

### Phase 1: Add Dependencies (Non-Breaking)

Add libraries to Cargo.toml without removing existing code.

```bash
cargo add governor backoff failsafe -p igra-core
cargo add tower_governor -p igra-service
cargo check
```

### Phase 2: Implement New Modules

Create new implementations alongside existing ones:

```
infrastructure/
├── rpc/
│   ├── retry/
│   │   ├── mod.rs          # Keep old
│   │   └── backoff.rs      # New: backoff-based
│   ├── circuit_breaker.rs  # Keep old
│   └── breaker.rs          # New: failsafe-based
└── transport/
    ├── rate_limiter.rs     # Keep old
    └── governor.rs         # New: governor-based
```

### Phase 3: Switch Usage Sites

Update call sites one at a time:

1. **Rate limiting** - Update transport layer, then HTTP middleware
2. **Retry** - Update RPC calls in `kaspa_integration/`
3. **Circuit breaker** - Update RPC wrapper

### Phase 4: Remove Old Code

Once all usage sites are migrated and tests pass:

```bash
rm igra-core/src/infrastructure/transport/rate_limiter.rs
rm igra-core/src/infrastructure/rpc/retry/mod.rs
rm igra-core/src/infrastructure/rpc/circuit_breaker.rs
rm igra-service/src/api/middleware/rate_limit.rs
```

### Phase 5: Update Tests

Ensure integration tests cover:
- Rate limiting under load
- Retry with transient failures
- Circuit breaker state transitions

---

## Checklist

### Pre-Migration

- [ ] Read and understand this document
- [ ] Review current implementations
- [ ] Create feature branch: `git checkout -b feature/resilience-libs`

### Phase 1: Dependencies

- [ ] Add `governor` to igra-core
- [ ] Add `backoff` to igra-core
- [ ] Add `failsafe` to igra-core
- [ ] Add `tower_governor` to igra-service
- [ ] Run `cargo check --workspace`

### Phase 2: Rate Limiting

- [ ] Create `infrastructure/transport/governor.rs`
- [ ] Implement `create_rate_limiter()` function
- [ ] Update transport layer to use new rate limiter
- [ ] Create `api/middleware/governor.rs` for HTTP layer
- [ ] Update Axum router to use `tower_governor`
- [ ] Run tests

### Phase 3: Retry Logic

- [ ] Create `infrastructure/rpc/retry/backoff.rs`
- [ ] Implement `rpc_backoff()` configuration
- [ ] Implement `retry_rpc()` wrapper
- [ ] Update `kaspa_integration/` to use new retry
- [ ] Run tests

### Phase 4: Circuit Breaker

- [ ] Create `infrastructure/rpc/breaker.rs`
- [ ] Implement `rpc_circuit_breaker()` configuration
- [ ] Implement `call_with_breaker()` wrapper
- [ ] Update RPC calls to use new circuit breaker
- [ ] Run tests

### Phase 5: Cleanup

- [ ] Delete `infrastructure/transport/rate_limiter.rs`
- [ ] Delete `infrastructure/rpc/retry/mod.rs` (old implementation)
- [ ] Delete `infrastructure/rpc/circuit_breaker.rs`
- [ ] Delete `api/middleware/rate_limit.rs`
- [ ] Update `mod.rs` files to remove old exports
- [ ] Run full test suite

### Phase 6: Audit Logging (Optional)

- [ ] Add `tracing-appender` to igra-core
- [ ] Refactor `FileAuditLogger` to use `tracing-appender`
- [ ] Update audit initialization
- [ ] Run tests

### Post-Migration

- [ ] Create PR with all changes
- [ ] Get code review
- [ ] Merge to devel
- [ ] Monitor for issues

---

## Summary

| Improvement | Effort | Impact | Priority |
|-------------|--------|--------|----------|
| Rate limiting → governor | 3-4 hours | High (280 lines removed) | High |
| Retry → backoff | 1-2 hours | Medium (better reliability) | High |
| Circuit breaker → failsafe | 2-3 hours | Medium (half-open state) | High |
| Audit → tracing-appender | 2-3 hours | Low (cleaner code) | Medium |

**Total estimated effort:** 8-12 hours
**Total lines removed:** ~400
**Features gained:** Jitter, exponential backoff, half-open circuit breaker, rolling logs, metrics-ready

---

## References

- [governor crate](https://docs.rs/governor/latest/governor/)
- [backoff crate](https://docs.rs/backoff/latest/backoff/)
- [failsafe crate](https://docs.rs/failsafe/latest/failsafe/)
- [tower_governor crate](https://docs.rs/tower_governor/latest/tower_governor/)
- [tracing-appender crate](https://docs.rs/tracing-appender/latest/tracing_appender/)
