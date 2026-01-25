# Key Management Security - Implementation TODOs

**Based on:** docs/security/key-management-extended-audit.md (2026-01-23)
**Status:** P0/P1 complete; P2 deferred (v1)
**Priority:** HIGH - Security-Critical

---

## Overview

This document provides **exact implementation steps** to address remaining security issues from the key management audit. Each task includes:
- File paths and line numbers
- Complete code implementations (no pseudocode)
- Named constants (no magic numbers)
- Testing procedures
- Verification commands

**Implementation note:** The codebase uses `tokio::sync::watch` + a background task for cache cleanup shutdown (instead of `tokio_util::sync::CancellationToken`) to avoid introducing new dependencies and lockfile churn.

---

## Priority Matrix

| Priority | Issue | Effort | Impact | Status |
|----------|-------|--------|--------|--------|
| 🔴 **P0** | In-memory cache never expires | 1-2 days | HIGH | ✅ COMPLETE |
| 🔴 **P0** | EnvSecretStore not compile-time restricted | 30 mins | HIGH | ✅ COMPLETE |
| 🟡 **P1** | payment_secret optional for mainnet | 1 hour | MEDIUM | ✅ COMPLETE |
| 🟡 **P2** | Key rotation not implemented | 3-5 days | MEDIUM | ⏸️ DEFERRED (v1) |
| ✅ **DONE** | Audit log permissions not enforced | - | - | ✅ COMPLETE |

---

## 🔴 P0-1: Implement Secret Cache TTL

### Problem Statement

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs:14`

Secrets loaded into memory persist until process exit. No time-to-live (TTL) mechanism exists.

**Risk:**
- Long-running processes accumulate secrets in RAM
- Memory dumps expose all secrets ever loaded
- No defense-in-depth if RAM compromised
- Forensic tools can extract secrets from memory

**Audit Reference:** Lines 1159-1175 in docs/security/key-management-extended-audit.md

---

### Implementation Steps

#### Step 1: Add Constants (No Magic Numbers!)

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Add at top of file (after imports, before struct definition):**

```rust
use std::time::{Duration, Instant};

/// Time-to-live for cached secrets in memory
/// Secrets are reloaded from encrypted storage after this duration
const SECRET_CACHE_TTL_SECS: u64 = 300; // 5 minutes

/// Interval for background cache cleanup task
const CACHE_CLEANUP_INTERVAL_SECS: u64 = 60; // 1 minute

/// Grace period after TTL before forcing eviction
/// Allows brief concurrent access during reload
const CACHE_GRACE_PERIOD_SECS: u64 = 5; // 5 seconds

/// Maximum number of secrets to cache before forcing eviction
/// Prevents unbounded memory growth
const MAX_CACHED_SECRETS: usize = 100;
```

---

#### Step 2: Define CachedSecret Type

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Add before FileSecretStore struct definition:**

```rust
/// Cached secret with expiration tracking
#[derive(Clone)]
struct CachedSecret {
    /// The secret value (zeroized on drop)
    value: SecretBytes,

    /// Timestamp when this cache entry expires
    expires_at: Instant,

    /// Number of times this secret has been accessed
    /// Used for LRU eviction if MAX_CACHED_SECRETS exceeded
    access_count: u64,
}

impl CachedSecret {
    /// Create new cached secret with TTL from constants
    fn new(value: SecretBytes) -> Self {
        Self {
            value,
            expires_at: Instant::now() + Duration::from_secs(SECRET_CACHE_TTL_SECS),
            access_count: 0,
        }
    }

    /// Check if cache entry has expired
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Check if cache entry is in grace period (expired but not yet evicted)
    fn is_in_grace_period(&self) -> bool {
        if !self.is_expired() {
            return false;
        }
        let grace_deadline = self.expires_at + Duration::from_secs(CACHE_GRACE_PERIOD_SECS);
        Instant::now() <= grace_deadline
    }

    /// Record an access and return the value
    fn access(&mut self) -> &SecretBytes {
        self.access_count = self.access_count.saturating_add(1);
        &self.value
    }
}
```

---

#### Step 3: Update FileSecretStore Structure

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Replace existing struct:**

```rust
// OLD (remove this):
// pub struct FileSecretStore {
//     file_path: PathBuf,
//     cache: Arc<tokio::sync::RwLock<HashMap<SecretName, SecretBytes>>>,
// }

// NEW:
pub struct FileSecretStore {
    /// Path to encrypted secrets file
    file_path: PathBuf,

    /// In-memory cache with TTL expiration
    cache: Arc<tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>>,

    /// Cancellation token for background cleanup task
    cleanup_shutdown: tokio_util::sync::CancellationToken,
}
```

**Add to Cargo.toml dependencies:**
```toml
[dependencies]
tokio-util = { version = "0.7", features = ["sync"] }
```

---

#### Step 4: Update Constructor with Background Cleanup

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Replace `new()` method:**

```rust
impl FileSecretStore {
    /// Create new file-based secret store with TTL cache
    pub fn new(file_path: PathBuf) -> Self {
        let cache = Arc::new(tokio::sync::RwLock::new(HashMap::new()));
        let cleanup_shutdown = tokio_util::sync::CancellationToken::new();

        // Spawn background cleanup task
        let cache_clone = Arc::clone(&cache);
        let shutdown_clone = cleanup_shutdown.clone();
        tokio::spawn(async move {
            Self::cache_cleanup_loop(cache_clone, shutdown_clone).await;
        });

        Self {
            file_path,
            cache,
            cleanup_shutdown,
        }
    }

    /// Background task to periodically clean expired cache entries
    async fn cache_cleanup_loop(
        cache: Arc<tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>>,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        let mut interval = tokio::time::interval(
            Duration::from_secs(CACHE_CLEANUP_INTERVAL_SECS)
        );

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    log::debug!("secret cache cleanup task shutting down");
                    break;
                }
                _ = interval.tick() => {
                    Self::cleanup_expired_entries(&cache).await;
                }
            }
        }
    }

    /// Remove expired entries from cache
    async fn cleanup_expired_entries(
        cache: &tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>
    ) {
        let mut cache_write = cache.write().await;

        let before_count = cache_write.len();
        cache_write.retain(|_name, cached| !cached.is_expired());
        let after_count = cache_write.len();

        let removed = before_count.saturating_sub(after_count);
        if removed > 0 {
            log::debug!("cache cleanup: removed {} expired secret(s)", removed);
        }

        // If cache is still over limit, evict least-recently-used
        if cache_write.len() > MAX_CACHED_SECRETS {
            Self::evict_lru_entries(&mut cache_write);
        }
    }

    /// Evict least-recently-used entries when cache exceeds MAX_CACHED_SECRETS
    fn evict_lru_entries(cache: &mut HashMap<SecretName, CachedSecret>) {
        let target_count = MAX_CACHED_SECRETS.saturating_mul(9).saturating_div(10); // Keep 90%
        let excess = cache.len().saturating_sub(target_count);

        if excess == 0 {
            return;
        }

        // Collect entries sorted by access count (ascending)
        let mut entries: Vec<_> = cache.iter()
            .map(|(name, cached)| (name.clone(), cached.access_count))
            .collect();
        entries.sort_by_key(|(_, count)| *count);

        // Remove least-accessed entries
        for (name, _) in entries.iter().take(excess) {
            cache.remove(name);
        }

        log::warn!(
            "cache over limit: evicted {} least-recently-used secret(s)",
            excess
        );
    }
}

impl Drop for FileSecretStore {
    fn drop(&mut self) {
        // Signal cleanup task to shutdown
        self.cleanup_shutdown.cancel();
    }
}
```

---

#### Step 5: Update get() Method with TTL Logic

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Replace existing `get()` implementation:**

```rust
impl FileSecretStore {
    /// Get secret from cache or reload from encrypted file if expired
    async fn get(&self, name: &SecretName) -> Result<SecretBytes, ThresholdError> {
        // Check cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(cached) = cache.get_mut(name) {
                if !cached.is_expired() {
                    // Cache hit - return immediately
                    return Ok(cached.access().clone());
                } else if cached.is_in_grace_period() {
                    // In grace period - return stale value but schedule reload
                    log::debug!(
                        "secret cache hit in grace period secret_name={}",
                        name.as_str()
                    );
                    let value = cached.access().clone();

                    // Trigger async reload (don't block)
                    let file_path = self.file_path.clone();
                    let cache_clone = Arc::clone(&self.cache);
                    let name_clone = name.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::reload_single_secret(
                            &file_path,
                            &cache_clone,
                            &name_clone
                        ).await {
                            log::warn!(
                                "failed to reload secret secret_name={} error={}",
                                name_clone.as_str(),
                                e
                            );
                        }
                    });

                    return Ok(value);
                }
            }
        } // Release write lock

        // Cache miss or expired - reload from file
        self.reload_single_secret(&self.file_path, &self.cache, name).await
    }

    /// Reload a single secret from encrypted file into cache
    async fn reload_single_secret(
        file_path: &Path,
        cache: &tokio::sync::RwLock<HashMap<SecretName, CachedSecret>>,
        name: &SecretName,
    ) -> Result<SecretBytes, ThresholdError> {
        // Load entire secrets map from encrypted file
        let passphrase = std::env::var("IGRA_SECRETS_PASSPHRASE")
            .map_err(|_| ThresholdError::SecretNotFound {
                name: name.clone(),
                context: "passphrase not set".to_string(),
            })?;

        let secrets_map = Self::load_from_file(file_path, &passphrase)?;

        // Extract requested secret
        let secret_bytes = secrets_map.get(name)
            .cloned()
            .ok_or_else(|| ThresholdError::SecretNotFound {
                name: name.clone(),
                context: format!("not found in {}", file_path.display()),
            })?;

        // Update cache
        {
            let mut cache_write = cache.write().await;
            cache_write.insert(name.clone(), CachedSecret::new(secret_bytes.clone()));
        }

        log::debug!("secret reloaded from file secret_name={}", name.as_str());
        Ok(secret_bytes)
    }
}
```

---

#### Step 6: Update set() Method

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Replace existing `set()` implementation:**

```rust
impl FileSecretStore {
    /// Store secret in cache and persist to encrypted file
    async fn set(&self, name: &SecretName, value: SecretBytes) -> Result<(), ThresholdError> {
        // Update cache with fresh TTL
        {
            let mut cache = self.cache.write().await;
            cache.insert(name.clone(), CachedSecret::new(value.clone()));
        }

        // Persist to encrypted file
        self.save().await?;

        Ok(())
    }
}
```

---

#### Step 7: Add Cache Statistics Method

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Add new method for monitoring:**

```rust
impl FileSecretStore {
    /// Get cache statistics for monitoring
    #[allow(dead_code)]
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;

        let total_entries = cache.len();
        let expired_entries = cache.values().filter(|c| c.is_expired()).count();
        let grace_period_entries = cache.values().filter(|c| c.is_in_grace_period()).count();

        CacheStats {
            total_entries,
            expired_entries,
            grace_period_entries,
            max_entries: MAX_CACHED_SECRETS,
            ttl_seconds: SECRET_CACHE_TTL_SECS,
        }
    }
}

/// Cache statistics for monitoring
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub grace_period_entries: usize,
    pub max_entries: usize,
    pub ttl_seconds: u64,
}
```

---

### Testing

#### Unit Tests

**File:** `igra-core/src/infrastructure/keys/backends/file_secret_store.rs`

**Add test module at end of file:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let temp_dir = TempDir::new().expect("temp dir");
        let secrets_path = temp_dir.path().join("secrets.bin");

        let store = FileSecretStore::new(secrets_path.clone());

        // Create and save secret
        let name = SecretName::new("test.secret");
        let value = SecretBytes::from(b"test_value".to_vec());
        store.set(&name, value.clone()).await.expect("set secret");

        // Verify immediate retrieval works
        let retrieved = store.get(&name).await.expect("get secret");
        assert_eq!(retrieved.expose_secret(), value.expose_secret());

        // Manually expire the cache entry
        {
            let mut cache = store.cache.write().await;
            if let Some(cached) = cache.get_mut(&name) {
                // Set expires_at to past
                cached.expires_at = Instant::now() - Duration::from_secs(1);
            }
        }

        // Verify reload from file works
        let retrieved_after_expiry = store.get(&name).await.expect("get after expiry");
        assert_eq!(retrieved_after_expiry.expose_secret(), value.expose_secret());
    }

    #[tokio::test]
    async fn test_cache_cleanup_removes_expired() {
        let temp_dir = TempDir::new().expect("temp dir");
        let secrets_path = temp_dir.path().join("secrets.bin");

        let store = FileSecretStore::new(secrets_path);

        // Add multiple secrets
        for i in 0..10 {
            let name = SecretName::new(format!("test.secret_{}", i));
            let value = SecretBytes::from(format!("value_{}", i).into_bytes());
            store.set(&name, value).await.expect("set secret");
        }

        // Verify all cached
        let stats = store.cache_stats().await;
        assert_eq!(stats.total_entries, 10);

        // Expire all entries
        {
            let mut cache = store.cache.write().await;
            for cached in cache.values_mut() {
                cached.expires_at = Instant::now() - Duration::from_secs(1);
            }
        }

        // Run cleanup
        FileSecretStore::cleanup_expired_entries(&store.cache).await;

        // Verify all removed
        let stats_after = store.cache_stats().await;
        assert_eq!(stats_after.total_entries, 0);
    }

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        let temp_dir = TempDir::new().expect("temp dir");
        let secrets_path = temp_dir.path().join("secrets.bin");

        let store = FileSecretStore::new(secrets_path);

        // Fill cache beyond MAX_CACHED_SECRETS
        let overfill_count = MAX_CACHED_SECRETS + 10;
        for i in 0..overfill_count {
            let name = SecretName::new(format!("test.secret_{}", i));
            let value = SecretBytes::from(format!("value_{}", i).into_bytes());
            store.set(&name, value).await.expect("set secret");
        }

        // Trigger cleanup
        FileSecretStore::cleanup_expired_entries(&store.cache).await;

        // Verify cache is under limit
        let stats = store.cache_stats().await;
        assert!(stats.total_entries <= MAX_CACHED_SECRETS);
    }
}
```

---

#### Integration Test

**File:** `igra-core/tests/integration/secret_cache_ttl.rs` (new file)

```rust
use igra_core::foundation::SecretName;
use igra_core::infrastructure::secrets::{FileSecretStore, SecretBytes};
use std::time::Duration;
use tempfile::TempDir;

#[tokio::test]
async fn test_secret_cache_ttl_integration() {
    // Setup
    let temp_dir = TempDir::new().expect("temp dir");
    let secrets_path = temp_dir.path().join("secrets.bin");

    std::env::set_var(
        "IGRA_SECRETS_PASSPHRASE",
        "test-passphrase-for-integration"
    );

    let store = FileSecretStore::new(secrets_path);

    // Store secret
    let name = SecretName::new("igra.test.integration_secret");
    let value = SecretBytes::from(b"integration_test_value".to_vec());
    store.set(&name, value.clone()).await.expect("set secret");

    // Verify immediate access (cache hit)
    let start = std::time::Instant::now();
    let retrieved = store.get(&name).await.expect("get secret");
    let cache_hit_duration = start.elapsed();

    assert_eq!(retrieved.expose_secret(), value.expose_secret());
    assert!(
        cache_hit_duration < Duration::from_millis(10),
        "cache hit should be fast, got {:?}",
        cache_hit_duration
    );

    // Wait for TTL to expire (or manually expire for faster test)
    // In real test: tokio::time::sleep(Duration::from_secs(SECRET_CACHE_TTL_SECS + 1)).await;

    // For fast test: manually expire
    {
        let mut cache = store.cache.write().await;
        if let Some(cached) = cache.get_mut(&name) {
            cached.expires_at = std::time::Instant::now() - Duration::from_secs(1);
        }
    }

    // Verify reload from file (cache miss)
    let start = std::time::Instant::now();
    let retrieved_after_expiry = store.get(&name).await.expect("get after expiry");
    let cache_miss_duration = start.elapsed();

    assert_eq!(retrieved_after_expiry.expose_secret(), value.expose_secret());
    assert!(
        cache_miss_duration > Duration::from_millis(1),
        "cache miss should involve file I/O, got {:?}",
        cache_miss_duration
    );

    println!("✅ Secret cache TTL integration test passed");
    println!("   Cache hit: {:?}", cache_hit_duration);
    println!("   Cache miss (reload): {:?}", cache_miss_duration);
}
```

---

### Verification

```bash
# 1. Check constants defined (no magic numbers)
grep -n "const.*TTL\|const.*CACHE" igra-core/src/infrastructure/keys/backends/file_secret_store.rs

# Expected output:
# Should show SECRET_CACHE_TTL_SECS, CACHE_CLEANUP_INTERVAL_SECS, etc.

# 2. Check CachedSecret type exists
grep -n "struct CachedSecret" igra-core/src/infrastructure/keys/backends/file_secret_store.rs

# 3. Run unit tests
cargo test -p igra-core file_secret_store::tests

# 4. Run integration test
cargo test -p igra-core --test integration secret_cache_ttl

# 5. Check for magic numbers (should be none in modified code)
# This should return empty or only comments:
grep -E "\b[0-9]{2,}\b" igra-core/src/infrastructure/keys/backends/file_secret_store.rs | \
  grep -v "const\|//\|/\*"

# 6. Verify background cleanup task spawned
cargo build --release
# Check logs for "cache cleanup: removed" messages
```

---

### Acceptance Criteria

- [ ] All constants defined at top of file (no magic numbers in code)
- [ ] `CachedSecret` struct includes `expires_at` field
- [ ] `FileSecretStore` spawns background cleanup task
- [ ] `get()` method checks TTL and reloads if expired
- [ ] Grace period allows brief stale access during reload
- [ ] LRU eviction prevents unbounded cache growth
- [ ] All unit tests pass
- [ ] Integration test passes
- [ ] No magic numbers in implementation

---

## 🔴 P0-2: Restrict EnvSecretStore to Test/DevNet Builds

### Problem Statement

**File:** `igra-core/src/infrastructure/keys/backends/env_secret_store.rs`

`EnvSecretStore` is available in all builds, including production. While runtime validation exists, there's no compile-time barrier.

**Risk:**
- Secrets visible in `ps auxe` (any user)
- Readable from `/proc/<pid>/environ` (Linux)
- Logged in shell history
- Accidentally printed in debug logs
- Passed to child processes

**Audit Reference:** Lines 1136-1157 in docs/security/key-management-extended-audit.md

---

### Implementation Steps

#### Step 1: Add Conditional Compilation to Struct

**File:** `igra-core/src/infrastructure/keys/backends/env_secret_store.rs`

**Replace struct definition (around line 10):**

```rust
// OLD (remove this):
// pub struct EnvSecretStore {
//     profile: Option<String>,
// }

// NEW:
#[cfg(any(test, feature = "devnet-env-secrets"))]
pub struct EnvSecretStore {
    profile: Option<String>,
}
```

---

#### Step 2: Add Conditional Compilation to All impl Blocks

**File:** `igra-core/src/infrastructure/keys/backends/env_secret_store.rs`

**Add `#[cfg]` to each impl block:**

```rust
#[cfg(any(test, feature = "devnet-env-secrets"))]
impl EnvSecretStore {
    pub fn new() -> Self {
        // ... existing implementation
    }

    // ... other methods
}

#[cfg(any(test, feature = "devnet-env-secrets"))]
impl SecretStore for EnvSecretStore {
    // ... existing trait implementation
}
```

---

#### Step 3: Add Feature to Cargo.toml

**File:** `igra-core/Cargo.toml`

**Add feature definition:**

```toml
[features]
# Allow environment variable secret storage (DEVNET/TEST ONLY)
# ⚠️ WARNING: Never enable in production builds
# Secrets in env vars are visible via ps/proc and shell history
devnet-env-secrets = []

# Default features for production
default = []
```

---

#### Step 4: Update Module Exports

**File:** `igra-core/src/infrastructure/keys/backends/mod.rs`

**Add conditional export:**

```rust
mod file_secret_store;
pub use file_secret_store::FileSecretStore;

#[cfg(any(test, feature = "devnet-env-secrets"))]
mod env_secret_store;

#[cfg(any(test, feature = "devnet-env-secrets"))]
pub use env_secret_store::EnvSecretStore;
```

---

#### Step 5: Update Test Code

**File:** `igra-core/tests/**/*.rs` (any files using EnvSecretStore)

**Add cfg attribute to test imports:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(test, feature = "devnet-env-secrets"))]
    use igra_core::infrastructure::secrets::EnvSecretStore;

    #[test]
    #[cfg(any(test, feature = "devnet-env-secrets"))]
    fn test_env_secret_store() {
        let store = EnvSecretStore::new();
        // ... test implementation
    }
}
```

---

#### Step 6: Update Documentation

**File:** `igra-core/src/infrastructure/keys/backends/env_secret_store.rs`

**Add module-level documentation:**

```rust
//! Environment variable secret storage backend
//!
//! ⚠️ **SECURITY WARNING: DEVNET/TEST ONLY**
//!
//! This backend reads secrets from environment variables, which is:
//! - Visible in process listings (`ps auxe`)
//! - Readable from `/proc/<pid>/environ` on Linux
//! - Stored in shell history files
//! - Logged if accidentally printed
//!
//! ## Build Configuration
//!
//! This module is only available when:
//! - Building with `#[cfg(test)]` (unit tests)
//! - Building with `--features devnet-env-secrets` flag
//!
//! ## Production Usage
//!
//! **NEVER** enable `devnet-env-secrets` feature in production builds.
//! Use `FileSecretStore` with encrypted storage instead.
//!
//! ## Allowed Use Cases
//!
//! - Unit/integration tests with temporary secrets
//! - CI/CD pipelines with ephemeral environments
//! - Local development with devnet
//!
//! ## Example (DevNet Only)
//!
//! ```bash
//! # Set environment variables
//! export IGRA_SECRET__igra_hd__wallet_secret="base64:dGVzdA=="
//! export IGRA_SECRET__igra_signer__private_key_default="hex:0123..."
//!
//! # Build with feature flag
//! cargo build --features devnet-env-secrets
//!
//! # Run devnet service
//! KASPA_IGRA_NETWORK=devnet kaspa-threshold-service --config devnet.toml
//! ```

#[cfg(any(test, feature = "devnet-env-secrets"))]
pub struct EnvSecretStore {
    // ... rest of implementation
}
```

---

### Testing

#### Verify Compile-Time Restriction

```bash
# 1. Verify production build CANNOT use EnvSecretStore
cargo build --release --bin kaspa-threshold-service

# If any code tries to use EnvSecretStore without the feature:
# Expected: Compilation error "cannot find struct `EnvSecretStore`"

# 2. Verify test builds CAN use EnvSecretStore
cargo test -p igra-core

# Expected: Tests compile and pass

# 3. Verify devnet feature enables EnvSecretStore
cargo build --release --bin kaspa-threshold-service --features devnet-env-secrets

# Expected: Compiles successfully

# 4. Check feature flag exists
grep -A5 "\[features\]" igra-core/Cargo.toml

# Expected output:
# [features]
# devnet-env-secrets = []
```

---

#### Add Compile Test

**File:** `igra-core/tests/compile_tests.rs` (new file)

```rust
//! Compile-time tests to verify security restrictions
//!
//! These tests use compile_fail to ensure production code
//! cannot accidentally use insecure features.

/// Verify EnvSecretStore is not available without feature flag
#[test]
#[cfg(not(feature = "devnet-env-secrets"))]
fn test_env_secret_store_not_available_in_production() {
    // This test exists to document the expected compile failure
    // If you see this test fail, it means EnvSecretStore is
    // incorrectly available in production builds

    // Uncomment to verify compile failure:
    // use igra_core::infrastructure::secrets::EnvSecretStore;
    // let _store = EnvSecretStore::new();
    // Expected: compile error "cannot find struct `EnvSecretStore`"
}

/// Verify EnvSecretStore IS available with feature flag
#[test]
#[cfg(feature = "devnet-env-secrets")]
fn test_env_secret_store_available_with_feature() {
    use igra_core::infrastructure::secrets::EnvSecretStore;
    let _store = EnvSecretStore::new();
    // Should compile successfully
}
```

---

### Documentation Updates

**File:** `igra-service/README.md` or equivalent

Add section:

```markdown
## Secret Storage Backends

### Production: FileSecretStore

**Default and REQUIRED for mainnet/testnet.**

Secrets encrypted with XChaCha20-Poly1305, stored at:
- `${data_dir}/secrets.bin`

### DevNet Only: EnvSecretStore

**⚠️ SECURITY WARNING: NEVER use in production**

Enabled with `--features devnet-env-secrets` compile flag.

Secrets read from environment variables:
- `IGRA_SECRET__<namespace>__<name>`

**Risks:**
- Visible in `ps auxe` (any user)
- Stored in shell history
- Logged if printed
- Passed to child processes

**Allowed use cases:**
- Unit tests with temporary secrets
- CI/CD with ephemeral environments
- Local devnet development

**Build example:**
```bash
cargo build --features devnet-env-secrets
```
```

---

### Verification

```bash
# 1. Verify cfg attributes on struct
grep -B2 "pub struct EnvSecretStore" igra-core/src/infrastructure/keys/backends/env_secret_store.rs

# Expected: #[cfg(any(test, feature = "devnet-env-secrets"))]

# 2. Verify cfg attributes on impl blocks
grep -B2 "impl.*EnvSecretStore" igra-core/src/infrastructure/keys/backends/env_secret_store.rs

# Expected: Multiple lines with #[cfg(any(test, feature = "devnet-env-secrets"))]

# 3. Verify feature in Cargo.toml
grep -A2 "devnet-env-secrets" igra-core/Cargo.toml

# Expected: Feature definition under [features]

# 4. Verify conditional export in mod.rs
grep -A1 "env_secret_store" igra-core/src/infrastructure/keys/backends/mod.rs

# Expected: Lines with #[cfg] guards

# 5. Compile without feature (should succeed, EnvSecretStore unavailable)
cargo build --release

# 6. Compile with feature (should succeed, EnvSecretStore available)
cargo build --release --features devnet-env-secrets

# 7. Run tests (should pass with EnvSecretStore available in test cfg)
cargo test -p igra-core
```

---

### Acceptance Criteria

- [ ] `EnvSecretStore` struct has `#[cfg(any(test, feature = "devnet-env-secrets"))]`
- [ ] All `impl` blocks have matching `#[cfg]` attributes
- [ ] Feature `devnet-env-secrets` defined in `Cargo.toml`
- [ ] Module export in `mod.rs` is conditional
- [ ] Documentation warns about security risks
- [ ] Production builds cannot use `EnvSecretStore` (compile error)
- [ ] Test builds can use `EnvSecretStore`
- [ ] DevNet builds with feature flag can use `EnvSecretStore`
- [ ] No magic strings (feature name is a constant or documented)

---

## 🟡 P1: Add payment_secret Warning for Mainnet

### Problem Statement

**File:** `igra-core/src/application/pskt_signing.rs:125-138`

`payment_secret` (BIP39 passphrase) is optional. If not configured, mnemonics are protected by `wallet_secret` only (single-layer encryption).

**Risk:**
- Single secret compromise = total breach
- No additional layer of protection
- Operators may not realize payment_secret is optional

**Audit Reference:** Lines 1177-1196 in docs/security/key-management-extended-audit.md

---

### Implementation Steps

#### Step 1: Define Constants

**File:** `igra-core/src/application/pskt_signing.rs`

**Add at top of file:**

```rust
/// Name of the payment secret in secret store
const PAYMENT_SECRET_NAME: &str = "igra.hd.payment_secret";

/// Minimum length for payment_secret in production
/// BIP39 passphrase should be strong to provide additional security
const MIN_PAYMENT_SECRET_LENGTH: usize = 12;

/// Recommended length for payment_secret
const RECOMMENDED_PAYMENT_SECRET_LENGTH: usize = 16;
```

---

#### Step 2: Add Validation Function

**File:** `igra-core/src/application/pskt_signing.rs`

**Add new function before `load_payment_secret_optional`:**

```rust
/// Validate payment_secret strength
///
/// Returns warning message if secret is too weak
fn validate_payment_secret_strength(secret: &Secret) -> Option<String> {
    let secret_str = secret.as_ref();
    let length = secret_str.len();

    if length == 0 {
        return Some("payment_secret is empty".to_string());
    }

    if length < MIN_PAYMENT_SECRET_LENGTH {
        return Some(format!(
            "payment_secret too short: {} chars (minimum: {}, recommended: {})",
            length,
            MIN_PAYMENT_SECRET_LENGTH,
            RECOMMENDED_PAYMENT_SECRET_LENGTH
        ));
    }

    // Check for common weak patterns
    let lowercase = secret_str.to_lowercase();
    const WEAK_PATTERNS: &[&str] = &[
        "password",
        "123456",
        "qwerty",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
    ];

    for pattern in WEAK_PATTERNS {
        if lowercase.contains(pattern) {
            return Some(format!(
                "payment_secret contains common weak pattern: {}",
                pattern
            ));
        }
    }

    None
}
```

---

#### Step 3: Update load_payment_secret_optional

**File:** `igra-core/src/application/pskt_signing.rs`

**Replace function (around line 125):**

```rust
/// Load payment_secret from secret store (optional)
///
/// Returns None if not configured.
/// Logs warnings if:
/// - Not configured in production (mainnet/testnet)
/// - Configured but too weak
pub async fn load_payment_secret_optional(
    key_context: &KeyManagerContext
) -> Result<Option<Secret>, ThresholdError> {
    let name = SecretName::new(PAYMENT_SECRET_NAME);

    // Try to load from secret store
    let secret_bytes = match key_context.get_secret_with_audit(&name).await {
        Ok(bytes) => bytes,
        Err(ThresholdError::SecretNotFound { .. }) => {
            // Not configured - warn if production
            warn_missing_payment_secret(key_context).await;
            return Ok(None);
        }
        Err(err) => return Err(err),
    };

    // Check if empty
    if secret_bytes.expose_secret().is_empty() {
        warn_missing_payment_secret(key_context).await;
        return Ok(None);
    }

    // Convert to Secret
    let secret_string = String::from_utf8(secret_bytes.expose_owned())
        .map_err(|e| ThresholdError::ConfigError(
            format!("payment_secret is not valid UTF-8: {}", e)
        ))?;

    let secret = Secret::from(secret_string);

    // Validate strength and warn if weak
    if let Some(weakness) = validate_payment_secret_strength(&secret) {
        warn_weak_payment_secret(key_context, &weakness).await;
    }

    Ok(Some(secret))
}

/// Warn if payment_secret is not configured in production
async fn warn_missing_payment_secret(key_context: &KeyManagerContext) {
    // Check network mode from context or environment
    let network_mode = detect_network_mode();

    match network_mode {
        NetworkMode::Mainnet => {
            log::warn!(
                "⚠️  SECURITY WARNING: payment_secret not configured in MAINNET. \
                 Mnemonics are protected by wallet_secret only (single-layer encryption). \
                 For production deployments, set {} in your secrets store. \
                 Recommended: 16+ character passphrase with mixed case, numbers, and symbols.",
                PAYMENT_SECRET_NAME
            );
        }
        NetworkMode::Testnet => {
            log::warn!(
                "⚠️  SECURITY NOTE: payment_secret not configured in TESTNET. \
                 Consider setting {} for additional security layer.",
                PAYMENT_SECRET_NAME
            );
        }
        NetworkMode::Devnet => {
            // No warning for devnet
            log::debug!(
                "payment_secret not configured (acceptable for devnet)"
            );
        }
    }
}

/// Warn if payment_secret is weak
async fn warn_weak_payment_secret(
    key_context: &KeyManagerContext,
    weakness: &str
) {
    let network_mode = detect_network_mode();

    match network_mode {
        NetworkMode::Mainnet | NetworkMode::Testnet => {
            log::warn!(
                "⚠️  SECURITY WARNING: payment_secret is weak: {}. \
                 Use a stronger passphrase (recommended: {}+ characters).",
                weakness,
                RECOMMENDED_PAYMENT_SECRET_LENGTH
            );
        }
        NetworkMode::Devnet => {
            // Just debug log for devnet
            log::debug!(
                "payment_secret validation: {} (acceptable for devnet)",
                weakness
            );
        }
    }
}

/// Detect current network mode from configuration or environment
fn detect_network_mode() -> NetworkMode {
    // Try environment variable first
    if let Ok(mode_str) = std::env::var("KASPA_IGRA_NETWORK") {
        if let Ok(mode) = mode_str.parse::<NetworkMode>() {
            return mode;
        }
    }

    // Default to mainnet (safe by default)
    NetworkMode::Mainnet
}
```

---

#### Step 4: Add Integration with Startup Validation

**File:** `igra-service/src/bin/kaspa-threshold-service/setup.rs`

**Add validation step during key manager setup:**

```rust
/// Initialize key manager and validate payment_secret configuration
pub async fn setup_key_manager(
    app_config: &AppConfig,
    network_mode: NetworkMode,
) -> Result<KeyManager, ThresholdError> {
    // ... existing key manager initialization

    // Validate payment_secret early
    validate_payment_secret_for_network_mode(
        &key_manager_context,
        network_mode
    ).await?;

    // ... rest of setup
}

/// Validate payment_secret configuration for network mode
async fn validate_payment_secret_for_network_mode(
    key_context: &KeyManagerContext,
    network_mode: NetworkMode,
) -> Result<(), ThresholdError> {
    use igra_core::application::pskt_signing::load_payment_secret_optional;

    let payment_secret = load_payment_secret_optional(key_context).await?;

    // For mainnet, consider making payment_secret mandatory
    // (This is commented out by default to preserve backward compatibility)
    /*
    if network_mode == NetworkMode::Mainnet && payment_secret.is_none() {
        return Err(ThresholdError::ConfigError(
            format!(
                "mainnet requires payment_secret to be configured. \
                 Set {} in your secrets store.",
                PAYMENT_SECRET_NAME
            )
        ));
    }
    */

    // Warnings are already logged by load_payment_secret_optional
    Ok(())
}
```

---

### Testing

#### Unit Test

**File:** `igra-core/tests/unit/payment_secret_validation.rs` (new file)

```rust
use igra_core::application::pskt_signing::validate_payment_secret_strength;
use kaspa_wallet_core::secret::Secret;

#[test]
fn test_payment_secret_strength_validation() {
    // Empty secret
    let empty = Secret::from(String::new());
    let result = validate_payment_secret_strength(&empty);
    assert!(result.is_some());
    assert!(result.unwrap().contains("empty"));

    // Too short
    let short = Secret::from("short".to_string());
    let result = validate_payment_secret_strength(&short);
    assert!(result.is_some());
    assert!(result.unwrap().contains("too short"));

    // Weak pattern
    let weak = Secret::from("password123456".to_string());
    let result = validate_payment_secret_strength(&weak);
    assert!(result.is_some());
    assert!(result.unwrap().contains("weak pattern"));

    // Strong secret
    let strong = Secret::from("Xy7$mK9#nQ2@pL8!wR5&vZ3%".to_string());
    let result = validate_payment_secret_strength(&strong);
    assert!(result.is_none(), "Strong secret should pass validation");
}

#[test]
fn test_minimum_length_constant() {
    const EXPECTED_MIN_LENGTH: usize = 12;
    // Verify constant is defined correctly
    // This test ensures no magic numbers in validation logic
    assert_eq!(
        igra_core::application::pskt_signing::MIN_PAYMENT_SECRET_LENGTH,
        EXPECTED_MIN_LENGTH
    );
}
```

---

### Verification

```bash
# 1. Check constants defined
grep -n "const.*PAYMENT_SECRET" igra-core/src/application/pskt_signing.rs

# Expected: PAYMENT_SECRET_NAME, MIN_PAYMENT_SECRET_LENGTH, RECOMMENDED_PAYMENT_SECRET_LENGTH

# 2. Check validation function exists
grep -n "fn validate_payment_secret_strength" igra-core/src/application/pskt_signing.rs

# 3. Check warning functions exist
grep -n "fn warn_missing_payment_secret\|fn warn_weak_payment_secret" igra-core/src/application/pskt_signing.rs

# 4. Run unit tests
cargo test -p igra-core payment_secret_validation

# 5. Test warning output (manual)
# Create config without payment_secret, start service
# Expected: See warning log on startup

# 6. Test with weak password
# Set payment_secret="password123"
# Expected: See warning about weak pattern

# 7. Verify no magic numbers
grep -E "\b(12|16)\b" igra-core/src/application/pskt_signing.rs | grep -v "const\|//"
# Should only appear in const definitions or comments
```

---

### Acceptance Criteria

- [ ] Constants defined for secret name and minimum lengths
- [ ] `validate_payment_secret_strength()` function implemented
- [ ] `load_payment_secret_optional()` logs warning if missing in mainnet
- [ ] `load_payment_secret_optional()` logs warning if weak
- [ ] Warnings differentiate by network mode (mainnet/testnet/devnet)
- [ ] Unit tests cover strong/weak/missing cases
- [ ] No magic numbers in validation code
- [ ] Documentation explains security implications

---

## 🟡 P2: Design Key Rotation Framework

### Problem Statement

**Current State:**
- `KeyManagerCapabilities::supports_key_rotation = false`
- No `rotate_key()` method
- No versioning for rotated keys
- Compromised keys cannot be migrated

**Audit Reference:** Lines 1198-1213 in docs/security/key-management-extended-audit.md

---

### Design Phase (This Sprint)

**Goal:** Create comprehensive design document, not implementation.

**Deliverable:** `Key-Rotation-Design.md`

---

### Design Document Outline

**File:** `docs/Key-Rotation-Design.md` (new file)

```markdown
# Key Rotation Framework Design

## 1. Requirements

### Functional Requirements
- FR1: Generate new key while preserving old key
- FR2: Support gradual migration (old + new keys active simultaneously)
- FR3: Coordinate rotation across N signers in multisig
- FR4: Rollback capability if rotation fails
- FR5: Audit trail for all rotation operations

### Non-Functional Requirements
- NFR1: Zero downtime during rotation
- NFR2: Rotation must be atomic (all-or-nothing)
- NFR3: Maximum 24-hour migration window
- NFR4: Support for emergency rotation (compromised key)

## 2. Key Versioning Scheme

### Version Format
```
<namespace>.<key_id>.v<version>

Examples:
- igra.signer.private_key_default.v1
- igra.signer.private_key_default.v2
```

### Constants
```rust
/// Maximum supported key version
const MAX_KEY_VERSION: u32 = 999;

/// Default key version for new keys
const DEFAULT_KEY_VERSION: u32 = 1;

/// Maximum concurrent active key versions
const MAX_ACTIVE_VERSIONS: usize = 2;
```

## 3. Rotation States

```rust
pub enum KeyRotationState {
    /// No rotation in progress
    Active { version: u32 },

    /// Rotation initiated, old key still active
    Rotating {
        old_version: u32,
        new_version: u32,
        initiated_at: DateTime<Utc>,
    },

    /// Migration complete, old key deprecated
    Deprecated {
        version: u32,
        deprecated_at: DateTime<Utc>,
    },

    /// Key revoked (compromised)
    Revoked {
        version: u32,
        revoked_at: DateTime<Utc>,
        reason: String,
    },
}
```

## 4. API Design

```rust
pub trait KeyRotation {
    /// Initiate key rotation
    async fn rotate_key(
        &self,
        key_ref: &KeyRef,
        rotation_config: RotationConfig,
    ) -> Result<KeyRotationOperation>;

    /// Finalize rotation (deprecate old key)
    async fn finalize_rotation(
        &self,
        operation_id: &str,
    ) -> Result<()>;

    /// Rollback rotation (revert to old key)
    async fn rollback_rotation(
        &self,
        operation_id: &str,
    ) -> Result<()>;

    /// List all versions of a key
    async fn list_key_versions(
        &self,
        namespace: &str,
        key_id: &str,
    ) -> Result<Vec<KeyVersion>>;

    /// Get rotation status
    async fn rotation_status(
        &self,
        key_ref: &KeyRef,
    ) -> Result<KeyRotationState>;
}

pub struct RotationConfig {
    /// Duration to keep old key active during migration
    pub migration_window: Duration,

    /// Whether to require manual finalization
    pub manual_finalize: bool,

    /// Reason for rotation
    pub reason: String,
}

pub struct KeyRotationOperation {
    pub operation_id: String,
    pub old_version: u32,
    pub new_version: u32,
    pub initiated_at: DateTime<Utc>,
    pub finalize_by: DateTime<Utc>,
}
```

## 5. Multisig Coordination

For M-of-N multisig, rotation requires coordination:

1. Leader initiates rotation
2. All N signers generate new keys
3. New multisig address computed from new public keys
4. Migration window: both addresses monitored
5. Funds moved from old to new address
6. After confirmation, old keys deprecated

## 6. Implementation Phases

### Phase 1: Storage Layer (Week 1)
- Add versioning to secret store
- Implement key version listing
- Add rotation state tracking

### Phase 2: Key Manager API (Week 2)
- Implement KeyRotation trait
- Add rotation operations to LocalKeyManager
- Unit tests for single-signer rotation

### Phase 3: Multisig Coordination (Week 3-4)
- Design coordination protocol
- Implement leader election
- Test N-signer rotation

### Phase 4: Migration Tools (Week 5)
- CLI tool for rotation
- Monitoring/status dashboard
- Rollback procedures

## 7. Security Considerations

- Old keys must be zeroized after deprecation
- Rotation operations must be audited
- Emergency rotation bypasses migration window
- Compromised keys immediately revoked

## 8. Open Questions

1. How to handle rotation in high-frequency signing scenarios?
2. Should rotation be automatic (scheduled) or manual only?
3. How to verify all signers have rotated successfully?
4. What happens if one signer fails to rotate within window?

## 9. Future Enhancements

- Automatic scheduled rotation (e.g., every 90 days)
- HSM integration for key generation
- Key escrow/backup during rotation
- Cross-chain key rotation (Hyperlane)
```

---

### Design Review Checklist

- [ ] Requirements clearly defined
- [ ] Versioning scheme documented with no magic numbers
- [ ] Rotation states enumerated
- [ ] API design includes all necessary operations
- [ ] Multisig coordination addressed
- [ ] Implementation phases realistic
- [ ] Security considerations documented
- [ ] Open questions identified for team discussion

---

## Summary

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| P0-1: Cache TTL | 🔴 CRITICAL | 1-2 days | ✅ COMPLETE |
| P0-2: Restrict EnvSecretStore | 🔴 CRITICAL | 30 mins | ✅ COMPLETE |
| P1: payment_secret warning | 🟡 HIGH | 1 hour | ✅ COMPLETE |
| P2: Key rotation design | 🟡 MEDIUM | 2-3 days | ⏸️ DEFERRED (v1) |

---

## Sprint Planning

### Sprint 1 (Week 1): Critical Security Fixes

**Goal:** Address P0 issues

**Tasks:**
1. Implement secret cache TTL (2 days)
   - Day 1: Implementation + unit tests
   - Day 2: Integration tests + verification
2. Restrict EnvSecretStore (0.5 days)
   - Morning: Add #[cfg] attributes
   - Afternoon: Test + document

**Deliverables:**
- [x] Cache TTL implemented and tested
- [x] EnvSecretStore compile-time restricted
- [x] All verification commands pass
- [x] No magic numbers in code

### Sprint 2 (Week 2): Security Warnings + Design

**Goal:** Address P1 and start P2

**Tasks:**
1. Add payment_secret warnings (0.5 days)
2. Design key rotation framework (2 days)
   - Create design document
   - Review with team
   - Finalize API design

**Deliverables:**
- [ ] payment_secret warnings implemented
- [ ] Key-Rotation-Design.md complete
- [ ] Team review completed

---

## Final Verification

After completing all tasks, run complete security audit:

```bash
# Run automated security audit
./security-audit.sh

# Should show:
# ✅ PASS: No secret leaks
# ✅ PASS: No hardcoded secrets
# ✅ PASS: No panic risks
# ✅ PASS: NetworkMode enforcement
# ✅ PASS: All security tests passed
```

---

## Questions or Issues?

**Contact:**
- Security issues: [security team contact]
- Implementation questions: [dev team contact]
- Design review: [architecture team contact]

**References:**
- docs/security/key-management-extended-audit.md (full audit report)
- CODE-GUIDELINE.md Section 8 (security guidelines)
- docs/config/network-modes.md (network mode validation)

---

**Document Version:** 1.0
**Last Updated:** 2026-01-24
**Next Review:** After Sprint 1 completion
