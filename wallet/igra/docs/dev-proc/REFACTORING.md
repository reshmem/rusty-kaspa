# Igra Threshold Signing - Refactoring Guide

**Generated**: 2026-01-08
**Purpose**: Improve code quality, reduce complexity, eliminate repetition, and enhance maintainability

---

## Table of Contents

1. [Code Repetition (DRY Violations)](#1-code-repetition-dry-violations)
2. [Code Organization](#2-code-organization)
3. [Design Improvements](#3-design-improvements)
4. [Simplify Unnecessary Complexity](#4-simplify-unnecessary-complexity)
5. [Code Clarity & Self-Documentation](#5-code-clarity--self-documentation)
6. [Minimize Mutexes & Locks](#6-minimize-mutexes--locks)
7. [Additional Improvements](#7-additional-improvements)
8. [Implementation Roadmap](#8-implementation-roadmap)

---

## 1. Code Repetition (DRY Violations)

### REFACTOR-001: Duplicate `now_nanos()` Functions

**Problem**: 7+ identical `now_nanos()` functions scattered across codebase

**Locations**:
- `igra-service/src/bin/fake_hyperlane_ism_api.rs:30`
- `igra-service/src/transport/iroh/mod.rs:79`
- `igra-core/src/coordination/signer.rs:265`
- `igra-core/src/transport/mock.rs:66`
- `igra-core/src/audit/mod.rs:162`
- `orchestration/devnet/igra/fake_hyperlane.rs:26`

**Current Code**:
```rust
fn now_nanos() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
```

**Refactored Solution**:

Create `igra-core/src/util/time.rs`:
```rust
//! Time utilities for consistent timestamp handling across the codebase.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::error::ThresholdError;

/// Returns current timestamp in nanoseconds since Unix epoch (UTC).
///
/// # Errors
/// Returns error if system clock is before 1970 or timestamp exceeds u64::MAX.
///
/// # Example
/// ```
/// let now = current_timestamp_nanos()?;
/// assert!(now > 0);
/// ```
pub fn current_timestamp_nanos() -> Result<u64, ThresholdError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ThresholdError::Message(
            format!("System clock is before Unix epoch: {}", e)
        ))?;

    // Avoid u128 truncation - use seconds + nanoseconds
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos() as u64;

    secs.checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or_else(|| ThresholdError::Message("timestamp overflow".to_string()))
}

/// Returns timestamp in milliseconds (sufficient for most use cases, avoids overflow).
pub fn current_timestamp_millis() -> Result<u64, ThresholdError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ThresholdError::Message(format!("clock error: {}", e)))?;

    Ok(duration.as_millis() as u64)  // Safe: millis won't overflow until year 584,542,046
}

/// Calculates the start of the day for a given timestamp (midnight UTC).
///
/// # Example
/// ```
/// let now = current_timestamp_nanos()?;
/// let today = day_start_nanos(now);
/// assert!(today <= now);
/// ```
pub fn day_start_nanos(timestamp_nanos: u64) -> u64 {
    const NANOS_PER_DAY: u64 = 24 * 60 * 60 * 1_000_000_000;
    (timestamp_nanos / NANOS_PER_DAY) * NANOS_PER_DAY
}

/// Adds a duration to a timestamp with overflow checking.
pub fn add_duration(timestamp_nanos: u64, duration: Duration) -> Result<u64, ThresholdError> {
    let duration_nanos = duration.as_secs()
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(duration.subsec_nanos() as u64))
        .ok_or_else(|| ThresholdError::Message("duration overflow".to_string()))?;

    timestamp_nanos.checked_add(duration_nanos)
        .ok_or_else(|| ThresholdError::Message("timestamp + duration overflow".to_string()))
}

/// Checks if a timestamp is within a valid range.
pub fn validate_timestamp(
    timestamp_nanos: u64,
    min_offset_secs: u64,
    max_offset_secs: u64,
) -> Result<(), ThresholdError> {
    let now = current_timestamp_nanos()?;
    let min_valid = now + (min_offset_secs * 1_000_000_000);
    let max_valid = now + (max_offset_secs * 1_000_000_000);

    if timestamp_nanos < min_valid {
        return Err(ThresholdError::Message(format!(
            "timestamp {} is too early (min: {})",
            timestamp_nanos, min_valid
        )));
    }

    if timestamp_nanos > max_valid {
        return Err(ThresholdError::Message(format!(
            "timestamp {} is too far in future (max: {})",
            timestamp_nanos, max_valid
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp_nanos() {
        let now = current_timestamp_nanos().unwrap();
        // Should be after 2020-01-01
        assert!(now > 1_577_836_800_000_000_000);
    }

    #[test]
    fn test_day_start() {
        let ts = 1_609_459_200_000_000_000; // 2021-01-01 00:00:00 UTC
        assert_eq!(day_start_nanos(ts), ts);

        let ts = 1_609_545_600_000_000_000; // 2021-01-02 00:00:00 UTC
        let start = day_start_nanos(ts);
        assert_eq!(start, ts);

        let ts = 1_609_549_200_000_000_000; // 2021-01-02 01:00:00 UTC
        let start = day_start_nanos(ts);
        assert_eq!(start, 1_609_545_600_000_000_000);
    }
}
```

Update `igra-core/src/lib.rs`:
```rust
pub mod util;
```

Add `igra-core/src/util/mod.rs`:
```rust
pub mod time;
pub mod encoding;  // For hex helpers (see REFACTOR-003)
pub mod conversion;  // For type conversions (see REFACTOR-004)
```

**Benefits**:
- ✅ Single source of truth for timestamp logic
- ✅ Proper error handling (no silent unwrap)
- ✅ Overflow protection
- ✅ Well-documented with examples
- ✅ Easy to test
- ✅ Easy to mock for testing (can use env var or feature flag)

**Migration Path**:
```bash
# Find all usages
rg "now_nanos\(\)" --files-with-matches

# Replace with:
use igra_core::util::time::current_timestamp_nanos;
let now = current_timestamp_nanos()?;
```

---

### REFACTOR-002: Excessive `.map_err()` Boilerplate

**Problem**: 132+ instances of `.map_err(|err| ThresholdError::Message(err.to_string()))`

**Current Code** (repeated everywhere):
```rust
hex::decode(&config.redeem_script_hex)
    .map_err(|err| ThresholdError::Message(err.to_string()))?;

toml::from_str(&contents)
    .map_err(|err| ThresholdError::Message(err.to_string()))?;

self.db.get_cf(cf, key)
    .map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Refactored Solution**:

Implement `From` traits for common error types:

```rust
// In igra-core/src/error.rs

use std::io;
use std::fmt;

impl From<hex::FromHexError> for ThresholdError {
    fn from(err: hex::FromHexError) -> Self {
        ThresholdError::Message(format!("hex decode error: {}", err))
    }
}

impl From<toml::de::Error> for ThresholdError {
    fn from(err: toml::de::Error) -> Self {
        ThresholdError::ConfigError(format!("TOML parsing error: {}", err))
    }
}

impl From<rocksdb::Error> for ThresholdError {
    fn from(err: rocksdb::Error) -> Self {
        ThresholdError::StorageError(err.to_string())
    }
}

impl From<bincode::Error> for ThresholdError {
    fn from(err: bincode::Error) -> Self {
        ThresholdError::StorageError(format!("serialization error: {}", err))
    }
}

impl From<io::Error> for ThresholdError {
    fn from(err: io::Error) -> Self {
        ThresholdError::Message(format!("IO error: {}", err))
    }
}

impl From<serde_json::Error> for ThresholdError {
    fn from(err: serde_json::Error) -> Self {
        ThresholdError::Message(format!("JSON error: {}", err))
    }
}

// For kaspa-specific errors
impl From<kaspa_addresses::AddressError> for ThresholdError {
    fn from(err: kaspa_addresses::AddressError) -> Self {
        ThresholdError::Message(format!("address error: {}", err))
    }
}

// Generic conversion helper for any error that implements Display
pub trait IntoThresholdError {
    fn into_threshold_error(self) -> ThresholdError;
}

impl<E: fmt::Display> IntoThresholdError for E {
    fn into_threshold_error(self) -> ThresholdError {
        ThresholdError::Message(self.to_string())
    }
}

// Extension trait for Result types
pub trait ResultExt<T> {
    fn map_storage_err(self) -> Result<T, ThresholdError>;
    fn map_config_err(self) -> Result<T, ThresholdError>;
    fn map_node_err(self) -> Result<T, ThresholdError>;
}

impl<T, E: fmt::Display> ResultExt<T> for Result<T, E> {
    fn map_storage_err(self) -> Result<T, ThresholdError> {
        self.map_err(|e| ThresholdError::StorageError(e.to_string()))
    }

    fn map_config_err(self) -> Result<T, ThresholdError> {
        self.map_err(|e| ThresholdError::ConfigError(e.to_string()))
    }

    fn map_node_err(self) -> Result<T, ThresholdError> {
        self.map_err(|e| ThresholdError::NodeRpcError(e.to_string()))
    }
}
```

**After Refactoring**:
```rust
// Before (verbose):
hex::decode(&config.redeem_script_hex)
    .map_err(|err| ThresholdError::Message(err.to_string()))?;

// After (clean):
hex::decode(&config.redeem_script_hex)?;

// Before (verbose):
self.db.get_cf(cf, key)
    .map_err(|err| ThresholdError::Message(err.to_string()))?;

// After (clean):
self.db.get_cf(cf, key)?;

// For specific error types:
something_ambiguous().map_storage_err()?;
```

**Benefits**:
- ✅ Reduces 132+ lines to simple `?`
- ✅ Better error categorization
- ✅ Consistent error handling
- ✅ More idiomatic Rust

---

### REFACTOR-003: Repeated Hex Encoding/Decoding

**Problem**: Hex encode/decode scattered throughout with repeated error handling

**Current Pattern**:
```rust
hex::encode(hash)
hex::decode(value).map_err(...)?
```

**Refactored Solution**:

Create `igra-core/src/util/encoding.rs`:
```rust
//! Encoding utilities for hex, base64, and other formats.

use crate::error::ThresholdError;

/// Encodes bytes to lowercase hex string.
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decodes hex string to bytes with validation.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ThresholdError> {
    hex::decode(s)
        .map_err(|e| ThresholdError::Message(format!("invalid hex: {}", e)))
}

/// Decodes hex and validates length.
pub fn decode_hex_exact(s: &str, expected_len: usize) -> Result<Vec<u8>, ThresholdError> {
    let bytes = decode_hex(s)?;
    if bytes.len() != expected_len {
        return Err(ThresholdError::Message(format!(
            "hex length mismatch: expected {} bytes, got {}",
            expected_len, bytes.len()
        )));
    }
    Ok(bytes)
}

/// Decodes hex to fixed-size array.
pub fn decode_hex_array<const N: usize>(s: &str) -> Result<[u8; N], ThresholdError> {
    let bytes = decode_hex(s)?;
    bytes.try_into()
        .map_err(|_| ThresholdError::Message(format!(
            "hex length mismatch: expected {} bytes, got {}",
            N, bytes.len()
        )))
}

/// Truncated hex for logging (first 8 characters).
pub fn encode_hex_short(bytes: &[u8]) -> String {
    let full = hex::encode(bytes);
    if full.len() > 8 {
        format!("{}...", &full[..8])
    } else {
        full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_exact() {
        assert!(decode_hex_exact("deadbeef", 4).is_ok());
        assert!(decode_hex_exact("deadbeef", 8).is_err());
    }

    #[test]
    fn test_decode_hex_array() {
        let result: [u8; 4] = decode_hex_array("deadbeef").unwrap();
        assert_eq!(result, [0xde, 0xad, 0xbe, 0xef]);

        assert!(decode_hex_array::<8>("deadbeef").is_err());
    }
}
```

**Usage**:
```rust
use igra_core::util::encoding::*;

// Before:
let bytes = hex::decode(&config.redeem_script_hex)
    .map_err(|e| ThresholdError::Message(e.to_string()))?;

// After:
let bytes = decode_hex(&config.redeem_script_hex)?;

// For Hash32 (32 bytes):
let hash: [u8; 32] = decode_hex_array(&hex_string)?;

// For logging:
tracing::info!("tx_id: {}", encode_hex_short(&tx_id));
```

---

### REFACTOR-004: Repeated Type Conversions

**Problem**: Unsafe `as` conversions scattered throughout codebase

**Current Code**:
```rust
slot as u32
idx as u8
rec_id as i32
portion_scaled * fee / 1_000_000
```

**Refactored Solution**:

Create `igra-core/src/util/conversion.rs`:
```rust
//! Safe type conversion utilities.

use crate::error::ThresholdError;
use std::convert::TryFrom;

/// Converts u64 to u32 with overflow check.
pub fn u64_to_u32(value: u64) -> Result<u32, ThresholdError> {
    u32::try_from(value)
        .map_err(|_| ThresholdError::Message(format!("{} exceeds u32::MAX", value)))
}

/// Converts usize to u32 with overflow check.
pub fn usize_to_u32(value: usize) -> Result<u32, ThresholdError> {
    u32::try_from(value)
        .map_err(|_| ThresholdError::Message(format!("{} exceeds u32::MAX", value)))
}

/// Converts usize to u8 with overflow check.
pub fn usize_to_u8(value: usize) -> Result<u8, ThresholdError> {
    u8::try_from(value)
        .map_err(|_| ThresholdError::Message(format!("{} exceeds u8::MAX", value)))
}

/// Converts u64 to i32 with overflow check (for recovery IDs, etc).
pub fn u64_to_i32(value: u64) -> Result<i32, ThresholdError> {
    i32::try_from(value)
        .map_err(|_| ThresholdError::Message(format!("{} exceeds i32 range", value)))
}

/// Safe percentage calculation: (value * percentage) / 100
pub fn percentage_of(value: u64, percentage: u64) -> Result<u64, ThresholdError> {
    value.checked_mul(percentage)
        .and_then(|v| v.checked_div(100))
        .ok_or_else(|| ThresholdError::Message("percentage calculation overflow".to_string()))
}

/// Safe fee split calculation using integer ratio.
pub fn split_fee(total: u64, numerator: u32, denominator: u32) -> Result<(u64, u64), ThresholdError> {
    if denominator == 0 {
        return Err(ThresholdError::Message("denominator cannot be zero".to_string()));
    }

    let first = (total as u128 * numerator as u128 / denominator as u128) as u64;
    let second = total.saturating_sub(first);

    Ok((first, second))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_conversions() {
        assert!(u64_to_u32(100).is_ok());
        assert!(u64_to_u32(u64::from(u32::MAX)).is_ok());
        assert!(u64_to_u32(u64::from(u32::MAX) + 1).is_err());
    }

    #[test]
    fn test_split_fee() {
        let (first, second) = split_fee(1000, 25, 100).unwrap();
        assert_eq!(first, 250);  // 25%
        assert_eq!(second, 750); // 75%
    }
}
```

**Usage**:
```rust
use igra_core::util::conversion::*;

// Before:
let nonce = slot as u32;  // Unsafe truncation

// After:
let nonce = u64_to_u32(slot)?;

// Before:
let rec_id = secp256k1::ecdsa::RecoveryId::from_i32(rec_id_u64 as i32)?;

// After:
let rec_id = secp256k1::ecdsa::RecoveryId::from_i32(u64_to_i32(rec_id_u64)?)?;

// Before (in fee calculation):
let portion_scaled = (recipient_portion * 1_000_000.0) as u64;

// After:
let (recipient_fee, signer_fee) = split_fee(total_fee, recipient_parts, 100)?;
```

---

### REFACTOR-005: Duplicate Storage Key Construction

**Problem**: Manual key building repeated in `storage/rocks.rs` (error-prone)

**Current Code**:
```rust
fn key_group(group_id: &Hash32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + group_id.len());
    key.extend_from_slice(b"grp:");
    key.extend_from_slice(group_id);
    key
}

fn key_event(event_hash: &Hash32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + event_hash.len());
    key.extend_from_slice(b"evt:");
    key.extend_from_slice(event_hash);
    key
}

// ... 10+ more similar functions
```

**Refactored Solution**:

```rust
// In storage/rocks.rs

/// Centralized key builder to avoid errors and ensure consistency.
struct KeyBuilder {
    buf: Vec<u8>,
}

impl KeyBuilder {
    fn new() -> Self {
        Self { buf: Vec::with_capacity(64) }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self { buf: Vec::with_capacity(capacity) }
    }

    fn prefix(mut self, prefix: &[u8]) -> Self {
        self.buf.extend_from_slice(prefix);
        self
    }

    fn hash32(mut self, hash: &Hash32) -> Self {
        self.buf.extend_from_slice(hash);
        self
    }

    fn str(mut self, s: &str) -> Self {
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    fn u32_be(mut self, value: u32) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn u64_be(mut self, value: u64) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    fn separator(mut self) -> Self {
        self.buf.push(b':');
        self
    }

    fn build(self) -> Vec<u8> {
        self.buf
    }
}

// Simplified key functions:
fn key_group(group_id: &Hash32) -> Vec<u8> {
    KeyBuilder::new().prefix(b"grp:").hash32(group_id).build()
}

fn key_event(event_hash: &Hash32) -> Vec<u8> {
    KeyBuilder::new().prefix(b"evt:").hash32(event_hash).build()
}

fn key_request(request_id: &RequestId) -> Vec<u8> {
    KeyBuilder::new().prefix(b"req:").str(request_id.as_str()).build()
}

fn key_partial_sig(request_id: &RequestId, signer_peer_id: &PeerId, input_index: u32) -> Vec<u8> {
    KeyBuilder::new()
        .prefix(b"req_sig:")
        .str(request_id.as_str())
        .separator()
        .str(signer_peer_id.as_str())
        .separator()
        .u32_be(input_index)
        .build()
}
```

**Benefits**:
- ✅ Type-safe key construction
- ✅ Harder to make mistakes
- ✅ Consistent formatting
- ✅ Easy to extend

---

### REFACTOR-006: Duplicate Config Loading Logic

**Problem**: Config loading spread across 3 files with duplicated patterns

**Files**:
- `config/loader.rs` - TOML/INI parsing
- `config/env.rs` - Environment variable handling
- `config/persistence.rs` - Database persistence
- `config/mod.rs` - Orchestration

**Refactored Solution**:

Create `igra-core/src/config/loader_unified.rs`:
```rust
//! Unified configuration loading with clear precedence.
//!
//! Loading order (lowest to highest priority):
//! 1. Default values
//! 2. Config file (TOML or INI)
//! 3. Persisted config in database
//! 4. Environment variables
//!
//! This ensures predictable behavior and makes debugging easier.

use super::*;
use crate::error::ThresholdError;
use std::path::Path;

pub struct ConfigLoader {
    data_dir: PathBuf,
}

impl ConfigLoader {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self { data_dir: data_dir.into() }
    }

    /// Load configuration with full precedence chain.
    pub fn load(&self) -> Result<AppConfig, ThresholdError> {
        // 1. Start with defaults
        let mut config = self.load_defaults()?;

        // 2. Load from file if exists
        if let Some(file_config) = self.load_from_file()? {
            config.merge(file_config);
        }

        // 3. Load from database if exists
        if let Some(db_config) = persistence::load_config_from_db(&self.data_dir)? {
            config.merge(db_config);
        }

        // 4. Apply environment overrides
        env::apply_env_overrides(&mut config)?;

        // 5. Validate final config
        validation::validate(&config)?;

        // 6. Persist for next startup
        persistence::store_config_in_db(&self.data_dir, &config)?;

        Ok(config)
    }

    fn load_defaults(&self) -> Result<AppConfig, ThresholdError> {
        // Load sensible defaults
        Ok(AppConfig::default())
    }

    fn load_from_file(&self) -> Result<Option<AppConfig>, ThresholdError> {
        let path = env::resolve_config_path(&self.data_dir).ok();
        if let Some(path) = path {
            if path.exists() {
                return Ok(Some(Self::parse_file(&path)?));
            }
        }
        Ok(None)
    }

    fn parse_file(path: &Path) -> Result<AppConfig, ThresholdError> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("toml") => loader::load_from_toml(path, path.parent().unwrap()),
            _ => loader::load_from_ini(path, path.parent().unwrap()),
        }
    }
}

// Add merge capability to AppConfig
impl AppConfig {
    /// Merges another config, with `other` taking precedence.
    pub fn merge(&mut self, other: AppConfig) {
        // Implement field-by-field merge logic
        // Only override if field is Some/non-default in `other`
    }
}
```

**Usage**:
```rust
// Before (complex):
let data_dir = env::resolve_data_dir()?;
let config = if let Some(config) = persistence::load_config_from_db(&data_dir)? {
    let mut config = config;
    env::apply_env_overrides(&mut config)?;
    config
} else {
    let path = env::resolve_config_path(&data_dir)?;
    let mut config = load_from_path(&path, &data_dir)?;
    env::apply_env_overrides(&mut config)?;
    persistence::store_config_in_db(&data_dir, &config)?;
    config
};

// After (simple):
let data_dir = resolve_data_dir()?;
let config = ConfigLoader::new(data_dir).load()?;
```

---

## 2. Code Organization

### REFACTOR-007: Create Utilities Module

**Problem**: Utility functions scattered across multiple modules

**Solution**:

Create clear module structure:
```
igra-core/src/
├── util/
│   ├── mod.rs
│   ├── time.rs           # Timestamp utilities (REFACTOR-001)
│   ├── encoding.rs       # Hex/base64 (REFACTOR-003)
│   ├── conversion.rs     # Type conversions (REFACTOR-004)
│   ├── crypto.rs         # Hashing helpers
│   └── validation.rs     # Common validation logic
├── domain/              # NEW: Domain logic
│   ├── mod.rs
│   ├── event.rs         # Move from event/mod.rs
│   ├── request.rs       # Request lifecycle
│   └── session.rs       # Session management
├── infrastructure/      # NEW: Infrastructure
│   ├── mod.rs
│   ├── storage.rs       # Move from storage/mod.rs
│   ├── transport.rs     # Move from transport/mod.rs
│   └── rpc.rs           # Move from rpc/mod.rs
└── [existing modules]
```

**Migration Plan**:
1. Create `util/` module with time, encoding, conversion
2. Update all imports gradually
3. Run tests after each module migration
4. Use deprecation warnings for old locations

---

### REFACTOR-008: Separate Domain from Infrastructure

**Problem**: Domain logic mixed with infrastructure concerns

**Current Structure**:
```rust
// coordination/signer.rs contains both:
- Business logic (validation, policy enforcement)  // DOMAIN
- Storage access                                    // INFRASTRUCTURE
- Transport operations                              // INFRASTRUCTURE
```

**Refactored Structure**:

```rust
// domain/signer.rs - Pure domain logic
pub struct SignerDomain {
    // No dependencies on Storage or Transport!
}

impl SignerDomain {
    /// Validates a signing proposal (pure function).
    pub fn validate_proposal(
        &self,
        event: &SigningEvent,
        event_hash: Hash32,
        tx_hash: Hash32,
        policy: Option<&GroupPolicy>,
    ) -> Result<ValidationResult, ThresholdError> {
        // Pure validation logic
        // Returns decision without side effects
    }

    /// Checks policy compliance (pure function).
    pub fn check_policy(
        &self,
        event: &SigningEvent,
        policy: &GroupPolicy,
        current_volume: u64,
    ) -> Result<(), ThresholdError> {
        // Pure policy check
    }
}

// coordination/signer.rs - Orchestration with infrastructure
pub struct Signer {
    domain: SignerDomain,
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
}

impl Signer {
    pub async fn handle_proposal(&self, proposal: Proposal) -> Result<(), ThresholdError> {
        // 1. Domain validation (pure)
        let validation = self.domain.validate_proposal(...)?;

        // 2. Persist (infrastructure)
        self.storage.insert_event(...)?;

        // 3. Respond (infrastructure)
        self.transport.publish_ack(...).await?;

        Ok(())
    }
}
```

**Benefits**:
- ✅ Domain logic easier to test (no mocks needed)
- ✅ Clear separation of concerns
- ✅ Can swap infrastructure without changing domain
- ✅ Business rules centralized

---

### REFACTOR-009: Group Related Types

**Problem**: Types scattered across `model.rs`, `types.rs`, and various modules

**Solution**:

Reorganize type definitions:
```
igra-core/src/
├── types/
│   ├── mod.rs
│   ├── ids.rs              # RequestId, SessionId, PeerId, TransactionId
│   ├── primitives.rs       # Hash32, Address, Amount
│   ├── event.rs            # SigningEvent, EventMetadata
│   ├── request.rs          # SigningRequest, RequestDecision
│   ├── session.rs          # Session-related types
│   ├── config.rs           # Configuration types
│   └── policy.rs           # Policy types
```

**In each file, group related types**:
```rust
// types/ids.rs
//! Identity types for entities in the system.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a signing request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ... similar for SessionId, PeerId, etc.
```

---

### REFACTOR-010: Consolidate Test Utilities

**Problem**: Test helpers duplicated across test files

**Solution**:

Create `igra-core/tests/common/mod.rs`:
```rust
//! Shared test utilities.

pub mod factories;
pub mod fixtures;
pub mod mocks;

// Re-export commonly used items
pub use factories::*;
pub use fixtures::*;
```

`igra-core/tests/common/factories.rs`:
```rust
//! Factory functions for creating test data.

use igra_core::*;

pub struct EventFactory {
    counter: std::sync::atomic::AtomicU64,
}

impl EventFactory {
    pub fn new() -> Self {
        Self { counter: std::sync::atomic::AtomicU64::new(1) }
    }

    pub fn create_event(&self, amount: u64) -> SigningEvent {
        let id = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SigningEvent {
            event_id: format!("test-event-{}", id),
            source: "test".to_string(),
            destination_address: format!("kaspa:test{}", id),
            amount_sompi: amount,
            timestamp_nanos: util::time::current_timestamp_nanos().unwrap(),
            metadata: Default::default(),
        }
    }

    pub fn create_event_with_metadata(
        &self,
        amount: u64,
        metadata: HashMap<String, String>,
    ) -> SigningEvent {
        let mut event = self.create_event(amount);
        event.metadata = metadata;
        event
    }
}

pub fn sample_config() -> AppConfig {
    // Return valid test config
    unimplemented!()
}

pub fn sample_group_config(threshold_m: u16, threshold_n: u16) -> GroupConfig {
    // Return valid test group config
    unimplemented!()
}
```

**Usage in tests**:
```rust
// Before (duplicated):
fn make_event(amount: u64) -> SigningEvent {
    SigningEvent {
        event_id: "test-1".to_string(),
        // ... lots of boilerplate
    }
}

// After (reusable):
use common::EventFactory;

#[test]
fn test_something() {
    let factory = EventFactory::new();
    let event = factory.create_event(1000);
    // ...
}
```

---

## 3. Design Improvements

### REFACTOR-011: Replace Generic `Message` Error with Specific Variants

**Problem**: 148+ uses of `ThresholdError::Message(String)` loses context

**Current Code**:
```rust
ThresholdError::Message("insufficient funds".to_string())
ThresholdError::Message(format!("invalid input index: {}", idx))
ThresholdError::Message(err.to_string())  // Original error lost!
```

**Refactored Solution**:

Expand `ThresholdError` enum:
```rust
#[derive(Debug, Error)]
pub enum ThresholdError {
    // Existing variants...

    #[error("insufficient funds: required {required}, available {available}")]
    InsufficientFunds { required: u64, available: u64 },

    #[error("invalid input index: {index} (max: {max})")]
    InvalidInputIndex { index: u32, max: u32 },

    #[error("invalid expiry: {expires_at} (current: {current})")]
    InvalidExpiry { expires_at: u64, current: u64 },

    #[error("timeout after {duration_secs} seconds")]
    Timeout { duration_secs: u64 },

    #[error("rate limited for peer {peer_id}")]
    RateLimited { peer_id: String },

    #[error("invalid message size: {size} exceeds max {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("PSKT has too many inputs: {count} exceeds max {max}")]
    TooManyInputs { count: usize, max: usize },

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("cryptographic error: {0}")]
    CryptoError(String),

    #[error("encoding error: {0}")]
    EncodingError(String),

    // Keep Message for truly generic cases
    #[error("{0}")]
    Message(String),
}
```

**Benefits**:
- ✅ Better error messages
- ✅ Structured error data (can extract fields)
- ✅ Easier to handle specific errors
- ✅ Better for metrics/monitoring

---

### REFACTOR-012: Introduce Result Type Alias

**Problem**: `Result<T, ThresholdError>` repeated everywhere

**Solution**:
```rust
// In error.rs
pub type Result<T> = std::result::Result<T, ThresholdError>;

// Usage:
// Before:
pub fn validate(...) -> Result<(), ThresholdError> { ... }

// After:
pub fn validate(...) -> Result<()> { ... }
```

Already exists in `transport/mod.rs:12`, extend to entire crate:
```rust
// In lib.rs
pub use error::{ThresholdError, Result};
```

---

### REFACTOR-013: Use Builder Pattern for Complex Constructors

**Problem**: Functions with many parameters are hard to use correctly

**Current Code**:
```rust
signer.validate_proposal(
    &request_id,
    session_id,
    signing_event,
    expected_event_hash,
    kpsbt_blob,
    tx_template_hash,
    expected_validation_hash,
    coordinator_peer_id,
    expires_at_nanos,
    policy,
    message_verifier,
) // 11 parameters!
```

**Refactored Solution**:

```rust
pub struct ProposalValidationRequest {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub signing_event: SigningEvent,
    pub expected_event_hash: Hash32,
    pub kpsbt_blob: Vec<u8>,
    pub tx_template_hash: Hash32,
    pub expected_validation_hash: Hash32,
    pub coordinator_peer_id: PeerId,
    pub expires_at_nanos: u64,
    pub policy: Option<GroupPolicy>,
    pub message_verifier: Option<Arc<dyn MessageVerifier>>,
}

impl ProposalValidationRequest {
    pub fn builder() -> ProposalValidationRequestBuilder {
        ProposalValidationRequestBuilder::default()
    }
}

pub struct ProposalValidationRequestBuilder {
    request_id: Option<RequestId>,
    session_id: Option<SessionId>,
    signing_event: Option<SigningEvent>,
    // ... all fields as Option
}

impl ProposalValidationRequestBuilder {
    pub fn request_id(mut self, id: RequestId) -> Self {
        self.request_id = Some(id);
        self
    }

    pub fn session_id(mut self, id: SessionId) -> Self {
        self.session_id = Some(id);
        self
    }

    // ... builder methods for all fields

    pub fn build(self) -> Result<ProposalValidationRequest> {
        Ok(ProposalValidationRequest {
            request_id: self.request_id.ok_or_else(|| ThresholdError::Message("request_id required".into()))?,
            session_id: self.session_id.ok_or_else(|| ThresholdError::Message("session_id required".into()))?,
            // ... all required fields
            policy: self.policy,
            message_verifier: self.message_verifier,
        })
    }
}

// Usage:
let request = ProposalValidationRequest::builder()
    .request_id(request_id)
    .session_id(session_id)
    .signing_event(event)
    .expected_event_hash(hash)
    .kpsbt_blob(blob)
    .tx_template_hash(tx_hash)
    .expected_validation_hash(validation_hash)
    .coordinator_peer_id(peer_id)
    .expires_at_nanos(expires_at)
    .policy(Some(policy))
    .message_verifier(Some(verifier))
    .build()?;

let result = signer.validate_proposal(request)?;
```

**Benefits**:
- ✅ Named parameters
- ✅ Optional parameters clear
- ✅ Compile-time checks
- ✅ Easier to extend (new optional params don't break existing code)

---

### REFACTOR-014: Extract Traits for Testability

**Problem**: Concrete types hard to mock/test

**Solution**:

Introduce traits for major abstractions:
```rust
// In domain/policies.rs
pub trait PolicyEnforcer: Send + Sync {
    fn enforce_policy(
        &self,
        event: &SigningEvent,
        policy: &GroupPolicy,
    ) -> Result<()>;
}

pub struct DefaultPolicyEnforcer {
    storage: Arc<dyn Storage>,
}

impl PolicyEnforcer for DefaultPolicyEnforcer {
    fn enforce_policy(&self, event: &SigningEvent, policy: &GroupPolicy) -> Result<()> {
        // Real implementation
    }
}

// In tests:
pub struct MockPolicyEnforcer {
    should_allow: bool,
}

impl PolicyEnforcer for MockPolicyEnforcer {
    fn enforce_policy(&self, _event: &SigningEvent, _policy: &GroupPolicy) -> Result<()> {
        if self.should_allow {
            Ok(())
        } else {
            Err(ThresholdError::DestinationNotAllowed("test".into()))
        }
    }
}
```

---

### REFACTOR-015: Use Type State Pattern for Request Lifecycle

**Problem**: Request state transitions not enforced at compile time

**Current Code**:
```rust
pub struct SigningRequest {
    pub decision: RequestDecision,  // Can be changed to anything!
    // ...
}

pub enum RequestDecision {
    Pending,
    Approved,
    Finalized,
    Rejected,
    Expired,
}
```

**Refactored Solution**:

```rust
// Use typestate pattern to enforce valid transitions
pub struct SigningRequest<State> {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub event_hash: Hash32,
    // ... common fields
    state: PhantomData<State>,
}

// State marker types
pub struct Pending;
pub struct Approved;
pub struct Finalized;
pub struct Rejected;
pub struct Expired;

impl SigningRequest<Pending> {
    pub fn new(request_id: RequestId, ...) -> Self {
        // Create new request in Pending state
    }

    pub fn approve(self) -> SigningRequest<Approved> {
        SigningRequest {
            request_id: self.request_id,
            session_id: self.session_id,
            event_hash: self.event_hash,
            state: PhantomData,
        }
    }

    pub fn reject(self, reason: String) -> SigningRequest<Rejected> {
        // Transition to Rejected
    }

    pub fn expire(self) -> SigningRequest<Expired> {
        // Transition to Expired
    }
}

impl SigningRequest<Approved> {
    pub fn finalize(self, tx_id: TransactionId) -> SigningRequest<Finalized> {
        // Only Approved requests can be finalized
    }
}

// Finalized, Rejected, Expired have no transitions (terminal states)
```

**Benefits**:
- ✅ Invalid state transitions prevented at compile time
- ✅ Can't call `finalize()` on Pending request
- ✅ Type system enforces business rules
- ✅ Self-documenting code

---

## 4. Simplify Unnecessary Complexity

### REFACTOR-016: Simplify Config Loading

**Problem**: 3-layer config loading (file → DB → env) is complex

**Current Complexity**:
- Load from DB
- If not in DB, load from file
- Apply env overrides
- Save to DB

**Simplified Solution**:

See REFACTOR-006 for unified config loader. Additionally:

```rust
// Option 1: Skip DB persistence entirely
// Configs are small, parsing is fast, DB adds complexity for little benefit

pub fn load_config() -> Result<AppConfig> {
    let path = resolve_config_path()?;
    let mut config = parse_config_file(&path)?;
    apply_env_overrides(&mut config)?;
    validate(&config)?;
    Ok(config)
}

// Option 2: Only persist if explicitly requested
pub fn load_config_with_caching(cache: bool) -> Result<AppConfig> {
    if cache {
        // Check DB first
    }
    // Load from file
    if cache {
        // Save to DB
    }
}
```

**Benefits**:
- ✅ Simpler mental model
- ✅ Less code to maintain
- ✅ Fewer failure modes
- ✅ Easier to debug

---

### REFACTOR-017: Simplify PSKT Building

**Problem**: PSKT builder has complex fee logic with float arithmetic

**Current Complexity** (builder.rs:61-103):
- Fee payment modes: RecipientPays, SignersPay, Split
- Float arithmetic for splits
- Change calculation
- Multiple validations

**Simplified Solution**:

```rust
pub struct FeeConfig {
    pub total_fee_sompi: u64,
    pub paid_by_recipient: u64,  // Must sum to total_fee_sompi
    pub paid_by_signers: u64,
}

impl FeeConfig {
    pub fn recipient_pays(fee: u64) -> Self {
        Self {
            total_fee_sompi: fee,
            paid_by_recipient: fee,
            paid_by_signers: 0,
        }
    }

    pub fn signers_pay(fee: u64) -> Self {
        Self {
            total_fee_sompi: fee,
            paid_by_recipient: 0,
            paid_by_signers: fee,
        }
    }

    pub fn split(total: u64, recipient_parts: u32, signer_parts: u32) -> Result<Self> {
        let total_parts = recipient_parts + signer_parts;
        let recipient_fee = (total * recipient_parts as u64) / total_parts as u64;
        let signer_fee = total - recipient_fee;

        Ok(Self {
            total_fee_sompi: total,
            paid_by_recipient: recipient_fee,
            paid_by_signers: signer_fee,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.paid_by_recipient + self.paid_by_signers != self.total_fee_sompi {
            return Err(ThresholdError::Message("fee split doesn't sum to total".into()));
        }
        Ok(())
    }
}

fn apply_fee(
    config: &FeeConfig,
    total_input: u64,
    outputs: &mut Vec<MultisigOutput>,
    change_address: &Address,
) -> Result<()> {
    config.validate()?;

    // Deduct recipient portion from first output
    if config.paid_by_recipient > 0 {
        let first = outputs.first_mut()
            .ok_or_else(|| ThresholdError::Message("no output to deduct fee from".into()))?;

        if first.amount < config.paid_by_recipient {
            return Err(ThresholdError::InsufficientFunds {
                required: config.paid_by_recipient,
                available: first.amount,
            });
        }

        first.amount -= config.paid_by_recipient;
    }

    // Calculate change after deducting signer portion
    let total_output: u64 = outputs.iter().map(|o| o.amount).sum();
    let required = total_output + config.paid_by_signers;

    if total_input < required {
        return Err(ThresholdError::InsufficientFunds {
            required,
            available: total_input,
        });
    }

    let change = total_input - required;
    if change > 0 {
        outputs.push(MultisigOutput {
            amount: change,
            script_public_key: pay_to_address_script(change_address),
        });
    }

    Ok(())
}
```

**Benefits**:
- ✅ No floating point
- ✅ Clearer semantics
- ✅ Easier to test
- ✅ Deterministic across platforms

---

### REFACTOR-018: Remove Unused Abstraction Layers

**Problem**: Multiple Noop implementations add complexity

**Current Code**:
- `NoopObserver` (lifecycle.rs:16)
- `NoopVerifier` (validation/verifier.rs:63)
- `NoopSignatureVerifier` (transport/mod.rs:54)
- `UnimplementedRpc` (rpc/mod.rs:19)

**Analysis**:
These are needed for testing, but create abstraction overhead.

**Simplified Solution**:

**Option 1**: Use `Option<>` instead of Noop implementations:
```rust
pub struct Signer {
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    lifecycle: Option<Arc<dyn LifecycleObserver>>,  // Instead of NoopObserver
}

impl Signer {
    pub fn new(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>) -> Self {
        Self { transport, storage, lifecycle: None }
    }

    pub fn with_observer(mut self, observer: Arc<dyn LifecycleObserver>) -> Self {
        self.lifecycle = Some(observer);
        self
    }

    fn notify_event(&self, event: &SigningEvent, hash: &Hash32) {
        if let Some(observer) = &self.lifecycle {
            observer.on_event_received(event, hash);
        }
    }
}
```

**Option 2**: Use default implementations in traits:
```rust
pub trait LifecycleObserver: Send + Sync {
    fn on_event_received(&self, _event: &SigningEvent, _hash: &Hash32) {
        // Default: do nothing
    }

    fn on_request_created(&self, _request: &SigningRequest) {
        // Default: do nothing
    }

    // ... all methods have default no-op implementations
}

// Then any type can be an observer:
impl LifecycleObserver for MyLogger {
    // Only override methods you care about
    fn on_event_received(&self, event: &SigningEvent, hash: &Hash32) {
        log::info!("Event {} received", hex::encode(hash));
    }
}
```

---

### REFACTOR-019: Consolidate Validation Logic

**Problem**: Validation scattered across multiple files

**Current State**:
- `config/validation.rs` - Config validation
- `coordination/signer.rs` - Proposal validation
- `pskt/builder.rs` - PSKT validation
- `validation/` module - Message validation

**Simplified Solution**:

Create `domain/validation/mod.rs`:
```rust
//! Centralized validation logic.

pub mod config;
pub mod event;
pub mod proposal;
pub mod pskt;

pub trait Validator<T> {
    type Error;

    fn validate(&self, value: &T) -> Result<(), Self::Error>;
}

// Common validation functions
pub fn validate_amount(amount: u64, min: Option<u64>, max: Option<u64>) -> Result<()> {
    if let Some(min) = min {
        if amount < min {
            return Err(ThresholdError::AmountTooLow { amount, min });
        }
    }

    if let Some(max) = max {
        if amount > max {
            return Err(ThresholdError::AmountTooHigh { amount, max });
        }
    }

    Ok(())
}

pub fn validate_address(address: &str, network: &NetworkType) -> Result<Address> {
    let addr = Address::try_from(address)
        .map_err(|e| ThresholdError::Message(format!("invalid address: {}", e)))?;

    // Validate network matches
    if addr.network != *network {
        return Err(ThresholdError::Message(
            format!("address network {} doesn't match expected {}", addr.network, network)
        ));
    }

    Ok(addr)
}

pub fn validate_timestamp_range(
    timestamp: u64,
    min: u64,
    max: u64,
) -> Result<()> {
    if timestamp < min || timestamp > max {
        return Err(ThresholdError::Message(
            format!("timestamp {} out of range [{}, {}]", timestamp, min, max)
        ));
    }
    Ok(())
}
```

---

## 5. Code Clarity & Self-Documentation

### REFACTOR-020: Add Comprehensive Documentation

**Problem**: Many public APIs lack documentation

**Solution**:

Document all public items with:
- Purpose and behavior
- Parameters and return values
- Error conditions
- Examples
- Related functions

**Example**:
```rust
/// Validates a signing proposal from a coordinator.
///
/// This is the core validation logic that every signer executes independently
/// to ensure the proposed transaction matches the signing event and complies
/// with group policies.
///
/// # Validation Steps
///
/// 1. **Event Hash**: Verify the provided event hash matches the computed hash
/// 2. **Message Verification**: If a verifier is provided, validate event signatures
/// 3. **Transaction Hash**: Verify PSKT transaction hash matches expected
/// 4. **Validation Hash**: Verify composite hash of event + tx + inputs
/// 5. **Policy Enforcement**: Check group policy rules (if provided)
///
/// # Parameters
///
/// - `request_id`: Unique identifier for this signing request
/// - `session_id`: Coordination session identifier
/// - `signing_event`: The event triggering this signing request
/// - `expected_event_hash`: Hash that coordinator claims for the event
/// - `kpsbt_blob`: Serialized PSKT (Partially Signed Kaspa Transaction)
/// - `tx_template_hash`: Hash of the transaction template
/// - `expected_validation_hash`: Composite hash for final validation
/// - `coordinator_peer_id`: Identity of the coordinator
/// - `expires_at_nanos`: Expiry timestamp for this signing session
/// - `policy`: Optional group policy to enforce
/// - `message_verifier`: Optional verifier for event signatures
///
/// # Returns
///
/// Returns a `SignerAck` indicating whether the signer accepts or rejects
/// the proposal, along with the reason if rejected.
///
/// # Errors
///
/// This function returns `ThresholdError` if:
/// - Event hash computation fails
/// - PSKT deserialization fails
/// - Transaction hash computation fails
/// - Storage operations fail
///
/// # Example
///
/// ```
/// # use igra_core::*;
/// # fn example(signer: &Signer) -> Result<()> {
/// let ack = signer.validate_proposal(
///     &request_id,
///     session_id,
///     signing_event,
///     expected_event_hash,
///     &kpsbt_blob,
///     tx_template_hash,
///     expected_validation_hash,
///     coordinator_peer_id,
///     expires_at_nanos,
///     Some(&policy),
///     Some(&verifier),
/// )?;
///
/// if ack.accept {
///     println!("Proposal accepted");
/// } else {
///     println!("Proposal rejected: {}", ack.reason.unwrap());
/// }
/// # Ok(())
/// # }
/// ```
///
/// # See Also
///
/// - [`submit_ack`](#method.submit_ack) - Send acknowledgment to coordinator
/// - [`submit_partial_sigs`](#method.submit_partial_sigs) - Submit signatures
pub fn validate_proposal(
    &self,
    request_id: &RequestId,
    session_id: SessionId,
    signing_event: SigningEvent,
    expected_event_hash: Hash32,
    kpsbt_blob: &[u8],
    tx_template_hash: Hash32,
    expected_validation_hash: Hash32,
    coordinator_peer_id: PeerId,
    expires_at_nanos: u64,
    policy: Option<&GroupPolicy>,
    message_verifier: Option<&dyn MessageVerifier>,
) -> Result<SignerAck, ThresholdError>
```

---

### REFACTOR-021: Improve Naming Consistency

**Problem**: Inconsistent naming conventions

**Current Issues**:
- `kpsbt_blob` vs `pskt` vs `psbt`
- `timestamp_nanos` vs `expires_at_nanos` vs `now_nanos`
- `event_hash` vs `tx_hash` vs `hash`
- `request_id` vs `request.request_id`

**Naming Guidelines**:

```rust
// Time-related: Always use full unit suffix
timestamp_nanos  // Not: timestamp, ts, time
duration_secs    // Not: duration, timeout, wait_time

// Hashes: Specify what is being hashed
event_hash          // Hash of SigningEvent
transaction_hash    // Hash of Transaction
validation_hash     // Composite hash
payload_hash        // Hash of message payload

// IDs: Always use _id suffix
request_id
session_id
peer_id
transaction_id

// Blobs: Use _bytes suffix
pskt_bytes          // Not: pskt_blob, kpsbt_blob
signature_bytes
pubkey_bytes

// Amounts: Always specify unit
amount_sompi        // Not: amount, value
fee_sompi
balance_sompi

// Collections: Use plural
utxos              // Not: utxo_list, utxo_vec
inputs
outputs
signatures

// Booleans: Use is_/has_/can_/should_ prefix
is_valid
has_expired
can_finalize
should_retry

// Functions: Use verb for actions
validate_proposal   // Not: proposal_validation
compute_hash        // Not: hash_computation
build_transaction   // Not: transaction_builder
```

---

### REFACTOR-022: Add Type Aliases for Clarity

**Problem**: Raw types obscure intent

**Current Code**:
```rust
pub fn process(data: Vec<u8>) -> Result<Vec<u8>>
pub fn validate(hash: [u8; 32]) -> bool
pub fn sign(key: Vec<u8>) -> Vec<u8>
```

**Refactored Solution**:

```rust
// In types/primitives.rs
pub type SerializedPskt = Vec<u8>;
pub type SignatureBytes = Vec<u8>;
pub type PubkeyBytes = Vec<u8>;
pub type PrivateKeyBytes = Vec<u8>;
pub type Hash32 = [u8; 32];  // Already exists
pub type AmountSompi = u64;
pub type TimestampNanos = u64;

// Usage becomes self-documenting:
pub fn process(pskt: SerializedPskt) -> Result<SerializedPskt>
pub fn validate(event_hash: Hash32) -> bool
pub fn sign(private_key: PrivateKeyBytes) -> SignatureBytes
```

---

### REFACTOR-023: Extract Magic Numbers to Constants

**Problem**: Magic numbers scattered throughout (see BUGS-056)

**Solution**:

Create `igra-core/src/constants.rs`:
```rust
//! System-wide constants.

/// Maximum message size for gossip transport (10 MB).
pub const MAX_MESSAGE_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of UTXOs in a single PSKT.
pub const MAX_PSKT_INPUTS: usize = 1000;

/// Maximum number of bootstrap peers for gossip.
pub const MAX_BOOTSTRAP_PEERS: usize = 10;

/// Fee calculation precision (6 decimal places).
pub const FEE_PRECISION_SCALE: u64 = 1_000_000;

/// Nanoseconds per day (for volume limits).
pub const NANOS_PER_DAY: u64 = 24 * 60 * 60 * 1_000_000_000;

/// Nanoseconds per second.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Default session timeout in seconds.
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 300;  // 5 minutes

/// Minimum session timeout in seconds.
pub const MIN_SESSION_TIMEOUT_SECS: u64 = 10;

/// Maximum session timeout in seconds.
pub const MAX_SESSION_TIMEOUT_SECS: u64 = 3600;  // 1 hour

/// Number of retry attempts for gossip publish.
pub const GOSSIP_PUBLISH_RETRIES: usize = 3;

/// Delay between gossip publish retries.
pub const GOSSIP_RETRY_DELAY_MS: u64 = 200;

/// Rate limiter capacity (burst size).
pub const RATE_LIMIT_CAPACITY: f64 = 100.0;

/// Rate limiter refill rate (requests per second).
pub const RATE_LIMIT_REFILL_RATE: f64 = 10.0;

/// Maximum size of event metadata in bytes.
pub const MAX_EVENT_METADATA_SIZE: usize = 10 * 1024;  // 10 KB

/// Schnorr signature size in bytes.
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;

/// Schnorr public key size in bytes.
pub const SCHNORR_PUBKEY_SIZE: usize = 32;

/// Hash size (Blake3) in bytes.
pub const HASH_SIZE: usize = 32;
```

---

## 6. Minimize Mutexes & Locks

### REFACTOR-024: Eliminate Active Sessions Mutex

**Problem**: `Arc<tokio::sync::Mutex<HashSet<SessionId>>>` in coordination.rs

**Current Code**:
```rust
let active_sessions = Arc::new(tokio::sync::Mutex::new(HashSet::new()));

// Later:
async fn mark_session_active(...) {
    let mut guard = active.lock().await;
    if guard.contains(&session_id) {
        return false;
    }
    guard.insert(session_id);
    true
}
```

**Refactored Solution**:

**Option 1**: Use dashmap (concurrent HashMap, lock-free reads)
```rust
use dashmap::DashSet;

let active_sessions = Arc::new(DashSet::new());

// No await needed!
fn mark_session_active(active: &DashSet<SessionId>, session_id: SessionId) -> bool {
    active.insert(session_id)  // Returns false if already present
}

fn clear_session_active(active: &DashSet<SessionId>, session_id: SessionId) {
    active.remove(&session_id);
}
```

**Option 2**: Use channels for session tracking
```rust
enum SessionCommand {
    Start(SessionId, oneshot::Sender<bool>),
    Complete(SessionId),
}

// Single task manages active sessions
async fn session_tracker(mut rx: mpsc::Receiver<SessionCommand>) {
    let mut active = HashSet::new();

    while let Some(cmd) = rx.recv().await {
        match cmd {
            SessionCommand::Start(id, reply) => {
                let is_new = active.insert(id);
                reply.send(is_new).ok();
            }
            SessionCommand::Complete(id) => {
                active.remove(&id);
            }
        }
    }
}

// Usage (no locks!):
let (tx, reply) = oneshot::channel();
session_tx.send(SessionCommand::Start(session_id, tx)).await?;
let can_start = reply.await?;
```

**Benefits**:
- ✅ No lock contention
- ✅ Better scalability
- ✅ Simpler reasoning (single owner)

---

### REFACTOR-025: Replace RateLimiter Mutex

**Problem**: `Arc<Mutex<HashMap<String, TokenBucket>>>` in rate_limit.rs

**Refactored Solution**:

**Option 1**: Use `dashmap::DashMap`
```rust
use dashmap::DashMap;

pub struct RateLimiter {
    limiters: Arc<DashMap<String, TokenBucket>>,
    capacity: f64,
    refill_rate: f64,
}

impl RateLimiter {
    pub fn check_rate_limit(&self, peer_id: &str) -> bool {
        let mut bucket = self.limiters
            .entry(peer_id.to_string())
            .or_insert_with(|| TokenBucket::new(self.capacity, self.refill_rate));

        bucket.try_consume()
    }

    pub fn cleanup_old_entries(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.limiters.retain(|_, bucket| bucket.last_refill > cutoff);
    }
}
```

**Option 2**: Use thread-local rate limiting (if peers are sticky to threads)
```rust
thread_local! {
    static RATE_LIMITERS: RefCell<HashMap<String, TokenBucket>> = RefCell::new(HashMap::new());
}

pub fn check_rate_limit(peer_id: &str, capacity: f64, refill_rate: f64) -> bool {
    RATE_LIMITERS.with(|limiters| {
        let mut limiters = limiters.borrow_mut();
        let bucket = limiters
            .entry(peer_id.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate));
        bucket.try_consume()
    })
}
```

---

### REFACTOR-026: Make Storage Operations Lock-Free

**Problem**: Storage already thread-safe but wrapped in Arc

**Current Code**:
```rust
pub struct ServiceFlow {
    storage: Arc<dyn Storage>,  // Arc needed for cloning
}
```

**Analysis**: RocksDB is already thread-safe internally. The Arc is only needed for shared ownership, not synchronization.

**Solution**: This is already correct! No mutex needed. Document this:

```rust
/// Storage implementation is thread-safe and can be shared via Arc.
/// RocksDB handles internal synchronization, so no additional locks are needed.
pub struct ServiceFlow {
    storage: Arc<dyn Storage>,
}
```

---

### REFACTOR-027: Use Immutable Structures

**Problem**: Mutable state requires synchronization

**Solution**:

Make data structures immutable where possible:
```rust
// Before (mutable):
pub struct Coordinator {
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    lifecycle: Arc<dyn LifecycleObserver>,  // Can be changed
}

impl Coordinator {
    pub fn set_lifecycle_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.lifecycle = observer;
    }
}

// After (immutable):
pub struct Coordinator {
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl Coordinator {
    // Lifecycle set at construction, never changes
    pub fn new(
        transport: Arc<dyn Transport>,
        storage: Arc<dyn Storage>,
        lifecycle: Arc<dyn LifecycleObserver>,
    ) -> Self {
        Self { transport, storage, lifecycle }
    }
}
```

**Benefits**:
- ✅ No interior mutability needed
- ✅ Can safely share across threads
- ✅ Easier to reason about
- ✅ No locks needed

---

### REFACTOR-028: Use Message Passing Instead of Shared State

**Problem**: Shared mutable state (even with locks) is complex

**Solution**:

Use actor pattern with message passing:
```rust
// Before: Shared state with locks
struct CoordinatorState {
    active_sessions: Arc<Mutex<HashSet<SessionId>>>,
    pending_signatures: Arc<Mutex<HashMap<RequestId, Vec<Signature>>>>,
}

// After: Actor with private state
struct CoordinatorActor {
    rx: mpsc::Receiver<CoordinatorMessage>,
    active_sessions: HashSet<SessionId>,  // Private, no lock!
    pending_signatures: HashMap<RequestId, Vec<Signature>>,  // Private, no lock!
}

enum CoordinatorMessage {
    StartSession { session_id: SessionId, reply: oneshot::Sender<bool> },
    AddSignature { request_id: RequestId, signature: Signature },
    GetSignatures { request_id: RequestId, reply: oneshot::Sender<Vec<Signature>> },
}

impl CoordinatorActor {
    async fn run(mut self) {
        while let Some(msg) = self.rx.recv().await {
            match msg {
                CoordinatorMessage::StartSession { session_id, reply } => {
                    let is_new = self.active_sessions.insert(session_id);
                    reply.send(is_new).ok();
                }
                CoordinatorMessage::AddSignature { request_id, signature } => {
                    self.pending_signatures
                        .entry(request_id)
                        .or_insert_with(Vec::new)
                        .push(signature);
                }
                CoordinatorMessage::GetSignatures { request_id, reply } => {
                    let sigs = self.pending_signatures.get(&request_id).cloned().unwrap_or_default();
                    reply.send(sigs).ok();
                }
            }
        }
    }
}

// Usage:
let (tx, rx) = mpsc::channel(100);
let actor = CoordinatorActor { rx, active_sessions: HashSet::new(), pending_signatures: HashMap::new() };
tokio::spawn(actor.run());

// No locks needed!
let (reply_tx, reply_rx) = oneshot::channel();
tx.send(CoordinatorMessage::StartSession { session_id, reply: reply_tx }).await?;
let can_start = reply_rx.await?;
```

**Benefits**:
- ✅ Zero locks
- ✅ Clear ownership
- ✅ Sequential processing (easier to reason about)
- ✅ Natural backpressure via channel bounds

---

## 7. Additional Improvements

### REFACTOR-029: Add Observability

**Problem**: Limited visibility into system behavior

**Solution**:

**Structured Logging**:
```rust
use tracing::{info, warn, error, debug, instrument};

#[instrument(
    name = "validate_proposal",
    skip(self, kpsbt_blob, message_verifier),
    fields(
        request_id = %request_id,
        session_id = %hex::encode(session_id.as_hash()),
        event_hash = %hex::encode(expected_event_hash),
    )
)]
pub fn validate_proposal(&self, ...) -> Result<SignerAck> {
    debug!("Starting proposal validation");

    let computed_hash = event_hash(&signing_event)?;
    debug!(computed = %hex::encode(computed_hash), expected = %hex::encode(expected_event_hash), "Comparing event hashes");

    if !bool::from(computed_hash.ct_eq(&expected_event_hash)) {
        warn!("Event hash mismatch");
        return Ok(SignerAck { accept: false, reason: Some("event_hash_mismatch".into()), ... });
    }

    info!(result = "accepted", "Proposal validation complete");
    Ok(...)
}
```

**Metrics**:
```rust
// In service/metrics.rs
use prometheus::{IntCounter, IntGauge, Histogram, HistogramOpts};

pub struct Metrics {
    // Counters
    pub proposals_received: IntCounter,
    pub proposals_accepted: IntCounter,
    pub proposals_rejected: IntCounter,
    pub signatures_submitted: IntCounter,
    pub transactions_finalized: IntCounter,

    // Gauges
    pub active_sessions: IntGauge,
    pub pending_requests: IntGauge,

    // Histograms
    pub proposal_validation_duration: Histogram,
    pub signature_duration: Histogram,
    pub finalization_duration: Histogram,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            proposals_received: IntCounter::new("igra_proposals_received_total", "Total proposals received")?,
            proposals_accepted: IntCounter::new("igra_proposals_accepted_total", "Proposals accepted")?,
            proposals_rejected: IntCounter::new("igra_proposals_rejected_total", "Proposals rejected")?,
            // ...
        })
    }

    pub fn register(&self, registry: &prometheus::Registry) -> Result<()> {
        registry.register(Box::new(self.proposals_received.clone()))?;
        registry.register(Box::new(self.proposals_accepted.clone()))?;
        // ...
        Ok(())
    }
}

// Usage in code:
metrics.proposals_received.inc();
let timer = metrics.proposal_validation_duration.start_timer();
// ... do work
timer.observe_duration();
```

**Health Checks**:
```rust
// In api/health.rs
pub struct HealthChecker {
    storage: Arc<dyn Storage>,
    rpc: Arc<dyn NodeRpc>,
}

#[derive(Serialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub storage_ok: bool,
    pub rpc_ok: bool,
    pub last_block: Option<u64>,
    pub uptime_seconds: u64,
}

impl HealthChecker {
    pub async fn check(&self) -> HealthStatus {
        let storage_ok = self.storage.health_check().is_ok();
        let (rpc_ok, last_block) = match self.rpc.get_blue_score().await {
            Ok(score) => (true, Some(score)),
            Err(_) => (false, None),
        };

        HealthStatus {
            healthy: storage_ok && rpc_ok,
            storage_ok,
            rpc_ok,
            last_block,
            uptime_seconds: /* calculate from startup time */,
        }
    }
}
```

---

### REFACTOR-030: Add Retry and Circuit Breaker

**Problem**: No resilience patterns for external dependencies

**Solution**:

```rust
use tokio::time::{sleep, Duration};

pub struct RetryConfig {
    pub max_attempts: usize,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
        }
    }
}

pub async fn retry_with_backoff<F, Fut, T, E>(
    config: &RetryConfig,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut delay = config.initial_delay;
    let mut last_error = None;

    for attempt in 0..config.max_attempts {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);

                if attempt + 1 < config.max_attempts {
                    sleep(delay).await;
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * config.backoff_multiplier).min(config.max_delay.as_secs_f64())
                    );
                }
            }
        }
    }

    Err(last_error.unwrap())
}

// Usage:
let result = retry_with_backoff(&RetryConfig::default(), || async {
    rpc.get_utxos_by_addresses(&addresses).await
}).await?;
```

**Circuit Breaker**:
```rust
pub struct CircuitBreaker {
    failure_threshold: usize,
    success_threshold: usize,
    timeout: Duration,
    state: Arc<Mutex<CircuitState>>,
}

enum CircuitState {
    Closed { consecutive_failures: usize },
    Open { opened_at: Instant },
    HalfOpen { consecutive_successes: usize },
}

impl CircuitBreaker {
    pub async fn call<F, Fut, T>(&self, f: F) -> Result<T, ThresholdError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, ThresholdError>>,
    {
        let state = self.state.lock().unwrap().clone();

        match state {
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() > self.timeout {
                    // Try again
                    *self.state.lock().unwrap() = CircuitState::HalfOpen { consecutive_successes: 0 };
                } else {
                    return Err(ThresholdError::Message("circuit breaker open".into()));
                }
            }
            _ => {}
        }

        match f().await {
            Ok(result) => {
                self.on_success();
                Ok(result)
            }
            Err(e) => {
                self.on_failure();
                Err(e)
            }
        }
    }

    fn on_success(&self) {
        // Transition Open -> HalfOpen -> Closed
    }

    fn on_failure(&self) {
        // Transition Closed -> Open
    }
}
```

---

### REFACTOR-031: Improve Testing Infrastructure

**Problem**: Tests are verbose and hard to set up

**Solution**:

**Test Fixtures**:
```rust
// In tests/common/fixtures.rs
pub struct TestEnvironment {
    pub temp_dir: TempDir,
    pub storage: Arc<RocksStorage>,
    pub app_config: Arc<AppConfig>,
    pub group_config: GroupConfig,
}

impl TestEnvironment {
    pub fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path())?);
        let app_config = Arc::new(Self::default_config());
        let group_config = Self::default_group_config();

        Ok(Self {
            temp_dir,
            storage,
            app_config,
            group_config,
        })
    }

    pub fn with_threshold(mut self, m: u16, n: u16) -> Self {
        self.group_config.threshold_m = m;
        self.group_config.threshold_n = n;
        self
    }

    fn default_config() -> AppConfig {
        // Return valid test config
        unimplemented!()
    }

    fn default_group_config() -> GroupConfig {
        unimplemented!()
    }
}

// Usage:
#[tokio::test]
async fn test_signing_flow() {
    let env = TestEnvironment::new().unwrap()
        .with_threshold(2, 3);

    let signer = Signer::new(env.storage.clone(), ...);
    // Test with real storage, no mocks needed
}
```

**Property-Based Testing**:
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_fee_split_always_sums_to_total(
        total in 0u64..1_000_000_000,
        parts in 1u32..100,
    ) {
        let (first, second) = split_fee(total, parts, 100 - parts).unwrap();
        assert_eq!(first + second, total);
    }

    #[test]
    fn test_timestamp_addition_never_panics(
        timestamp in 0u64..u64::MAX / 2,
        duration_secs in 0u64..1_000_000,
    ) {
        let duration = Duration::from_secs(duration_secs);
        let result = add_duration(timestamp, duration);
        // Should either succeed or return overflow error
        assert!(result.is_ok() || matches!(result, Err(ThresholdError::Message(_))));
    }
}
```

---

### REFACTOR-032: Add Configuration Validation at Startup

**Problem**: Invalid configs discovered at runtime

**Solution**:

```rust
// In bin/kaspa-threshold-service.rs

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load and validate config FIRST
    let config = load_and_validate_config()?;

    // 2. Initialize components
    let storage = init_storage(&config)?;
    let transport = init_transport(&config)?;

    // 3. Run service
    run_service(config, storage, transport).await?;

    Ok(())
}

fn load_and_validate_config() -> Result<AppConfig> {
    let config = igra_core::config::load_app_config()?;

    // Comprehensive validation
    validate_node_connectivity(&config)?;
    validate_group_config(&config)?;
    validate_signing_keys(&config)?;
    validate_directories(&config)?;

    info!("Configuration validated successfully");
    Ok(config)
}

fn validate_node_connectivity(config: &AppConfig) -> Result<()> {
    // Try to connect to Kaspa node
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let rpc = GrpcNodeRpc::connect(config.node_rpc_url.clone()).await?;
        let blue_score = rpc.get_blue_score().await?;
        info!("Connected to Kaspa node at block {}", blue_score);
        Ok(())
    })
}

fn validate_group_config(config: &AppConfig) -> Result<()> {
    if config.group.threshold_m > config.group.threshold_n {
        return Err("threshold_m must be <= threshold_n".into());
    }

    if config.group.member_pubkeys.len() != config.group.threshold_n as usize {
        return Err("member_pubkeys count must equal threshold_n".into());
    }

    Ok(())
}
```

---

## 8. Implementation Roadmap

### Phase 1: Quick Wins (1-2 weeks)

**Low Risk, High Impact**:

1. ✅ **REFACTOR-001**: Centralize timestamp utilities
   - Create `util/time.rs`
   - Replace all `now_nanos()` functions
   - Add tests

2. ✅ **REFACTOR-002**: Add `From` trait implementations
   - Implement error conversions
   - Remove `.map_err()` boilerplate
   - Clean up 100+ lines

3. ✅ **REFACTOR-003**: Hex encoding utilities
   - Create `util/encoding.rs`
   - Replace scattered hex operations

4. ✅ **REFACTOR-012**: Add Result type alias
   - Update all function signatures
   - Shorter, cleaner code

5. ✅ **REFACTOR-020**: Add documentation
   - Document public APIs
   - Add examples to key functions

### Phase 2: Structural Changes (2-3 weeks)

**Medium Risk, High Value**:

6. ✅ **REFACTOR-007**: Create utilities module
   - Organize util functions
   - Update imports

7. ✅ **REFACTOR-008**: Separate domain from infrastructure
   - Extract pure domain logic
   - Improve testability

8. ✅ **REFACTOR-009**: Reorganize type definitions
   - Create types/ module
   - Group related types

9. ✅ **REFACTOR-011**: Expand error types
   - Add specific error variants
   - Reduce generic Message usage

10. ✅ **REFACTOR-024**: Replace Mutex with DashMap
    - Eliminate active_sessions lock
    - Better performance

### Phase 3: Complexity Reduction (3-4 weeks)

**Higher Risk, Significant Simplification**:

11. ✅ **REFACTOR-016**: Simplify config loading
    - Unified loader
    - Clear precedence

12. ✅ **REFACTOR-017**: Simplify PSKT fee logic
    - Remove floating point
    - Integer-only arithmetic

13. ✅ **REFACTOR-013**: Builder patterns
    - Complex function parameters
    - Better API ergonomics

14. ✅ **REFACTOR-025**: Lock-free rate limiter
    - Use DashMap or channels
    - Eliminate contention

15. ✅ **REFACTOR-019**: Consolidate validation
    - Centralized validators
    - Consistent patterns

### Phase 4: Advanced Improvements (4-6 weeks)

**Longer-term, Architectural**:

16. ✅ **REFACTOR-015**: Type-state pattern
    - Compile-time state validation
    - Safer request lifecycle

17. ✅ **REFACTOR-028**: Message-passing architecture
    - Actor pattern for coordination
    - Eliminate shared mutable state

18. ✅ **REFACTOR-029**: Full observability
    - Structured logging
    - Comprehensive metrics
    - Health checks

19. ✅ **REFACTOR-030**: Resilience patterns
    - Retry logic
    - Circuit breakers
    - Graceful degradation

20. ✅ **REFACTOR-031**: Testing infrastructure
    - Test fixtures
    - Property-based tests
    - Integration test harness

---

## Summary

This refactoring guide addresses:

✅ **Code Repetition**: 6 major DRY violations eliminated
✅ **Organization**: Clear module structure with domain/infrastructure separation
✅ **Design**: Better abstractions, builder patterns, type-state
✅ **Complexity**: Simplified config, PSKT building, validation
✅ **Clarity**: Documentation, naming, type aliases, constants
✅ **Locks**: DashMap, message-passing, immutable structures
✅ **Extras**: Observability, resilience, testing, validation

**Total Impact**:
- **-1,000+ lines** of boilerplate code
- **-5 mutexes** replaced with lock-free alternatives
- **+comprehensive documentation** on all public APIs
- **+observability** for production operations
- **+resilience** patterns for external dependencies

**Risk Level**: Each refactoring is independently valuable and can be done incrementally without breaking existing functionality.

---

**Next Steps**:
1. Review this document with team
2. Prioritize refactorings based on current pain points
3. Create tickets for Phase 1 (quick wins)
4. Implement with test coverage
5. Document migration patterns for team

