use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Token bucket rate limiter implementation
/// Allows burst traffic up to capacity, then enforces a steady rate
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of tokens (burst size)
    /// * `refill_rate` - Tokens added per second (sustained rate)
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Try to consume multiple tokens. Returns true if allowed, false if rate limited
    pub fn try_consume_tokens(&mut self, count: f64) -> bool {
        self.refill();
        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }

    /// Get current token count (for monitoring)
    pub fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

/// Per-peer rate limiter using token buckets
pub struct RateLimiter {
    limiters: Arc<Mutex<HashMap<String, TokenBucket>>>,
    capacity: f64,
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `capacity` - Maximum burst size per peer
    /// * `refill_rate` - Sustained rate per peer (requests per second)
    ///
    /// # Example
    /// ```ignore
    /// // Allow 10 requests burst, then 1 per second sustained
    /// let limiter = RateLimiter::new(10.0, 1.0);
    /// ```
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            limiters: Arc::new(Mutex::new(HashMap::new())),
            capacity,
            refill_rate,
        }
    }

    /// Check if a request from the given peer is allowed
    /// Returns true if allowed, false if rate limited
    pub fn check_rate_limit(&self, peer_id: &str) -> bool {
        let mut limiters = self.limiters.lock().unwrap_or_else(|err| err.into_inner());
        let bucket = limiters
            .entry(peer_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate));
        bucket.try_consume()
    }

    /// Check if a request with custom token cost is allowed
    /// Useful for size-based rate limiting (e.g., bytes / 1024 tokens)
    pub fn check_rate_limit_tokens(&self, peer_id: &str, tokens: f64) -> bool {
        let mut limiters = self.limiters.lock().unwrap_or_else(|err| err.into_inner());
        let bucket = limiters
            .entry(peer_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate));
        bucket.try_consume_tokens(tokens)
    }

    /// Remove old entries to prevent unbounded growth
    /// Call periodically from a cleanup task
    pub fn cleanup_old_entries(&self, max_age: Duration) {
        let mut limiters = self.limiters.lock().unwrap_or_else(|err| err.into_inner());
        let cutoff = Instant::now() - max_age;
        limiters.retain(|_, bucket| bucket.last_refill > cutoff);
    }

    /// Get the number of tracked peers (for monitoring)
    pub fn peer_count(&self) -> usize {
        self.limiters.lock().unwrap_or_else(|err| err.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_burst() {
        let mut bucket = TokenBucket::new(5.0, 1.0);

        // Should allow burst up to capacity
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());

        // Should deny after capacity exhausted
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(2.0, 10.0); // 10 tokens/sec

        // Exhaust tokens
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume());

        // Wait for refill (100ms = 1 token at 10/sec rate)
        thread::sleep(Duration::from_millis(150));

        // Should have 1 token available
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_rate_limiter_per_peer() {
        let limiter = RateLimiter::new(2.0, 1.0);

        // Peer A should have independent limit
        assert!(limiter.check_rate_limit("peer_a"));
        assert!(limiter.check_rate_limit("peer_a"));
        assert!(!limiter.check_rate_limit("peer_a"));

        // Peer B should have independent limit
        assert!(limiter.check_rate_limit("peer_b"));
        assert!(limiter.check_rate_limit("peer_b"));
        assert!(!limiter.check_rate_limit("peer_b"));
    }

    #[test]
    fn test_rate_limiter_tokens() {
        let limiter = RateLimiter::new(100.0, 10.0);

        // Should consume 50 tokens
        assert!(limiter.check_rate_limit_tokens("peer_a", 50.0));

        // Should have 50 remaining, allow 40
        assert!(limiter.check_rate_limit_tokens("peer_a", 40.0));

        // Should have 10 remaining, deny 20
        assert!(!limiter.check_rate_limit_tokens("peer_a", 20.0));
    }
}
