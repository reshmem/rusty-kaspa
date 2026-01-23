# Igra Codebase - Hex String Refactoring Plan

**Date:** 2026-01-21
**Issue:** Verbose, repetitive hex parsing/encoding code throughout codebase
**Root Cause:** Types lack `FromStr` trait implementation
**Impact:** Code duplication, verbosity, maintenance burden

---

## Executive Summary

The codebase has **massive repetition** around hex string parsing:

### The Problem (Current State)

#### **🔴 CRITICAL: Same Function Defined 9 Times!**

```rust
// This appears in 9 DIFFERENT FILES with near-identical implementation:
fn parse_hash32_hex(value: &str) -> Result<Hash32, ThresholdError> {
    let stripped = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped).map_err(...)?;
    if bytes.len() != 32 {
        return Err(...);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
```

**Duplicated in:**
1. `igra-service/src/service/coordination/crdt_handler.rs:814`
2. `igra-service/src/api/handlers/mailbox.rs:109`
3. `igra-service/src/bin/kaspa-threshold-service/setup.rs:201`
4. `igra-service/src/bin/kaspa-threshold-service/modes/audit.rs:90`
5. `igra-service/src/bin/kaspa-threshold-service/modes/finalize.rs:75`
6. `igra-service/src/bin/fake_hyperlane_relayer.rs:166` (as `parse_h256`)
7. `igra-service/src/bin/fake_hyperlane_ism_api.rs:102` (as `parse_h256`)
8. `igra-service/src/api/handlers/chain.rs:169` (as `parse_tx_id_hex`)
9. `igra-service/src/api/handlers/hyperlane.rs:129` (as `parse_signature_hex`)

**Total:** ~90 lines of duplicated code

---

#### **🔴 CRITICAL: Verbose Config Access Pattern**

**Pattern appears 5+ times:**
```rust
// UGLY: 4 lines to parse a config hex string
let group_id_hex = app_config.iroh.group_id.clone().unwrap_or_default();
if group_id_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing group_id".to_string()));
}
let group_id = GroupId::from(parse_hash32_hex(&group_id_hex)?);
```

**Found in:**
1. `setup.rs:108-112` (group_id)
2. `setup.rs:87-88` (peer_id, seed_hex)
3. Similar patterns throughout API handlers

---

#### **🔴 CRITICAL: Verbose Logging**

**Current state:** Every log statement manually encodes
```rust
// Appears 100+ times across codebase
info!("event processed event_id={}", hex::encode(event_id));
warn!("failed event_id={} tx_hash={}", hex::encode(event_id), hex::encode(tx_template_hash));
debug!("CRDT merge event_id={:#x}", event_id);  // Inconsistent formatting
```

---

### The Solution (Proposed State)

#### **✅ SOLUTION: Add FromStr to All Hash Types**

```rust
// ONE implementation in foundation/types.rs
impl FromStr for EventId {
    type Err = ThresholdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(stripped)
            .map_err(|e| ThresholdError::ParseError(format!("invalid hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(ThresholdError::ParseError(
                format!("expected 32 bytes, got {}", bytes.len())
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(EventId::from(hash))
    }
}
```

**Usage:**
```rust
// CLEAN: 1 line
let group_id: GroupId = app_config.iroh.group_id.as_deref()
    .ok_or_else(|| ThresholdError::ConfigError("missing group_id".to_string()))?
    .parse()?;

// OR even simpler with helper:
let group_id = parse_required_config(&app_config.iroh.group_id, "group_id")?;
```

**Logging:**
```rust
// Types already implement Display!
info!("event processed event_id={}", event_id);
warn!("failed event_id={} tx_hash={}", event_id, tx_template_hash);
debug!("CRDT merge event_id={:#x}", event_id);  // 0x prefix with {:#x}
```

---

## Detailed Analysis

### 1. Duplicated Parse Functions

#### **1.1 parse_hash32_hex (5 copies)**

**Locations:**
- `crdt_handler.rs:814-822` - Returns `[u8; 32]` with `ThresholdError`
- `mailbox.rs:109-117` - Returns `[u8; 32]` with `String` error
- `setup.rs:201-206` - Returns `Hash32` with `ThresholdError`
- `audit.rs:90-97` - Returns `Hash32` with `ThresholdError`
- `finalize.rs:75-82` - Returns `Hash32` with `ThresholdError`

**Differences:**
- Return type: `[u8; 32]` vs `Hash32` (identical, just aliased)
- Error type: `ThresholdError` vs `String`
- Error messages vary slightly

**Refactor:**
```rust
// foundation/encoding.rs - NEW MODULE
use std::str::FromStr;

pub fn parse_hex_32bytes(s: &str) -> Result<[u8; 32], ThresholdError> {
    let stripped = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped)
        .map_err(|e| ThresholdError::ParseError(format!("invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(ThresholdError::ParseError(
            format!("expected 32 bytes, got {}", bytes.len())
        ));
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

// Add FromStr to ALL hash types via macro
macro_rules! impl_fromstr_hash {
    ($type:ident) => {
        impl std::str::FromStr for $type {
            type Err = ThresholdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok($type::from(parse_hex_32bytes(s)?))
            }
        }
    };
}

impl_fromstr_hash!(EventId);
impl_fromstr_hash!(GroupId);
impl_fromstr_hash!(SessionId);
impl_fromstr_hash!(TransactionId);
impl_fromstr_hash!(TxTemplateHash);
impl_fromstr_hash!(ExternalId);
impl_fromstr_hash!(PayloadHash);
```

**Delete 90 lines** of duplicated code, replace with:
```rust
let event_id: EventId = hex_str.parse()?;
```

---

#### **1.2 parse_h256 (2 copies)**

**Locations:**
- `fake_hyperlane_relayer.rs:166-173`
- `fake_hyperlane_ism_api.rs:102-109`

**Same issue:** Hyperlane's `H256` type also needs `FromStr`

**Refactor:**
```rust
// foundation/encoding.rs
impl FromStr for H256 {
    type Err = String;  // Match hyperlane's error type

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(stripped)
            .map_err(|e| format!("invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(H256::from(arr))
    }
}
```

---

#### **1.3 parse_seed_hex (1 copy)**

**Location:** `setup.rs:190-194`

**Refactor:** Use `parse_hex_32bytes` helper
```rust
fn parse_seed_hex(value: &str) -> Result<[u8; 32], ThresholdError> {
    parse_hex_32bytes(value)  // Reuse common implementation
}

// OR better: just use the helper directly
let seed = parse_hex_32bytes(&seed_hex)?;
```

---

### 2. Verbose Config Access Patterns

#### **2.1 The "clone unwrap_or_default is_empty" Anti-Pattern**

**Pattern (5 occurrences):**
```rust
let value_hex = config.field.clone().unwrap_or_default();
if value_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing field".to_string()));
}
let value = Type::from(parse_hash32_hex(&value_hex)?);
```

**Locations:**
1. `setup.rs:108-112` - group_id
2. `setup.rs:87-88` - peer_id + seed_hex (2 occurrences)
3. `kaspa-threshold-service.rs:236` - test_recipient
4. Similar patterns in other files

**Refactor:** Create helper function
```rust
// foundation/config_helpers.rs - NEW MODULE
use std::str::FromStr;

/// Parse required config field with automatic hex parsing
pub fn parse_required_hex<T: FromStr>(
    opt: &Option<String>,
    field_name: &str,
) -> Result<T, ThresholdError>
where
    T::Err: std::fmt::Display,
{
    opt.as_deref()
        .ok_or_else(|| ThresholdError::ConfigError(format!("missing {}", field_name)))?
        .parse()
        .map_err(|e| ThresholdError::ConfigError(
            format!("invalid {}: {}", field_name, e)
        ))
}

/// Parse optional config field with automatic hex parsing
pub fn parse_optional_hex<T: FromStr>(
    opt: &Option<String>,
) -> Result<Option<T>, ThresholdError>
where
    T::Err: std::fmt::Display,
{
    match opt.as_deref() {
        Some(s) if !s.is_empty() => Ok(Some(s.parse().map_err(|e| {
            ThresholdError::ConfigError(format!("invalid hex: {}", e))
        })?)),
        _ => Ok(None),
    }
}
```

**Usage:**
```rust
// BEFORE (4 lines):
let group_id_hex = app_config.iroh.group_id.clone().unwrap_or_default();
if group_id_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing group_id".to_string()));
}
let group_id = GroupId::from(parse_hash32_hex(&group_id_hex)?);

// AFTER (1 line):
let group_id: GroupId = parse_required_hex(&app_config.iroh.group_id, "group_id")?;
```

---

### 3. Verbose Logging Patterns

#### **3.1 Manual hex::encode in Logs**

**Current Problem:**
```rust
// Appears 100+ times:
info!("event processed event_id={}", hex::encode(event_id));
warn!("failed event_id={}", hex::encode(event_id));

// Inconsistent formatting:
debug!("event event_id={:#x}", event_id);        // 0xabcd...
info!("event event_id={:x}", event_id);          // abcd...
error!("event event_id={}", hex::encode(event_id));  // abcd...
```

**Solution:** Types **already implement Display and LowerHex!**

```rust
// foundation/types.rs:64-95 - ALREADY EXISTS!
impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::LowerHex for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;  // {:#x} adds 0x prefix
        }
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
```

**Refactor (Replace All):**
```rust
// BEFORE:
info!("event processed event_id={}", hex::encode(event_id));

// AFTER:
info!("event processed event_id={}", event_id);  // Uses Display
// OR with 0x prefix:
info!("event processed event_id={:#x}", event_id);  // Uses LowerHex
```

**Impact:** Remove `hex::encode()` from ~100+ log statements

---

#### **3.2 Type Conversion in Error Messages**

**Current Pattern:**
```rust
// Verbose:
ThresholdError::PsktMismatch {
    expected: tx_template_hash.to_string(),  // Allocates String
    actual: computed.to_string(),            // Allocates String
}

ThresholdError::EventSignatureInvalid {
    event_id: hex::encode(event_id),  // Manual encoding
    reason: format!("{:?}", report),
}
```

**Solution:** Use Display trait in error construction
```rust
// Clean:
ThresholdError::PsktMismatch {
    expected: format!("{}", tx_template_hash),  // Uses Display
    actual: format!("{}", computed),
}

// OR: Change error type to hold hash directly
ThresholdError::PsktMismatch {
    expected: tx_template_hash,  // Store TxTemplateHash directly
    actual: computed,
}
// Format on display:
impl Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThresholdError::PsktMismatch { expected, actual } =>
                write!(f, "PSKT mismatch: expected {}, got {}", expected, actual),
            // ...
        }
    }
}
```

---

### 4. API Handler Patterns

#### **4.1 Path Parameter Parsing**

**Current (Verbose):**
```rust
// api/handlers/mailbox.rs:54-57
let message_id = match parse_hash32_hex(&id) {
    Ok(id) => id,
    Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
};

// api/handlers/chain.rs:127-130
let tx_id = match parse_tx_id_hex(&hash_hex) {
    Ok(id) => id,
    Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
};
```

**Refactored:**
```rust
// With FromStr implemented:
let message_id: Hash32 = id.parse()
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid message_id: {}", e)))?;

// OR use axum::extract::Path with custom deserializer:
use axum::extract::Path;
use serde::de::Deserialize;

// Automatic parsing from URL path
async fn get_message(
    Path(message_id): Path<ExternalId>,  // Parses hex automatically!
) -> Response {
    // message_id is already parsed
}
```

---

## Comprehensive Refactoring Plan

### Phase 1: Add FromStr Implementations (1-2 hours)

**File:** `igra-core/src/foundation/types.rs`

**Add to macro:**
```rust
macro_rules! define_id_type {
    (hash $name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(Hash32);

        // ... existing Display, LowerHex, UpperHex implementations ...

        impl std::str::FromStr for $name {
            type Err = crate::foundation::ThresholdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let stripped = s.trim().trim_start_matches("0x").trim_start_matches("0X");
                let bytes = hex::decode(stripped).map_err(|e| {
                    crate::foundation::ThresholdError::ParseError(format!("invalid hex: {}", e))
                })?;
                if bytes.len() != 32 {
                    return Err(crate::foundation::ThresholdError::ParseError(
                        format!("expected 32 bytes, got {}", bytes.len())
                    ));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok($name::from(hash))
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                s.parse().expect("failed to parse hash from string")
            }
        }
    };
}
```

**Benefits:**
- ✅ One implementation for all hash types
- ✅ Automatic via macro expansion
- ✅ Consistent error messages
- ✅ FromStr trait enables `.parse()` syntax

---

### Phase 2: Add Config Helper Functions (30 minutes)

**File:** `igra-core/src/foundation/config_helpers.rs` (NEW)

```rust
use crate::foundation::ThresholdError;
use std::str::FromStr;

/// Parse required config option (returns error if None or empty)
pub fn parse_required<T>(opt: &Option<String>, field: &str) -> Result<T, ThresholdError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    opt.as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ThresholdError::ConfigError(format!("missing {}", field)))?
        .parse()
        .map_err(|e| ThresholdError::ConfigError(format!("invalid {}: {}", field, e)))
}

/// Parse optional config (returns Ok(None) if None or empty)
pub fn parse_optional<T>(opt: &Option<String>) -> Result<Option<T>, ThresholdError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match opt.as_deref() {
        Some(s) if !s.is_empty() => Ok(Some(s.parse().map_err(|e| {
            ThresholdError::ConfigError(format!("parse error: {}", e))
        })?)),
        _ => Ok(None),
    }
}

/// Parse required config with default value
pub fn parse_or_default<T>(opt: &Option<String>, default: T) -> T
where
    T: FromStr + Default,
{
    opt.as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
```

---

### Phase 3: Delete Duplicate Functions (30 minutes)

**Delete these functions:**

1. ❌ `crdt_handler.rs:814-822` - `parse_hash32_hex`
2. ❌ `mailbox.rs:109-117` - `parse_hash32_hex`
3. ❌ `setup.rs:201-206` - `parse_hash32_hex`
4. ❌ `audit.rs:90-97` - `parse_hash32_hex`
5. ❌ `finalize.rs:75-82` - `parse_hash32_hex`
6. ❌ `fake_hyperlane_relayer.rs:166-173` - `parse_h256`
7. ❌ `fake_hyperlane_ism_api.rs:102-109` - `parse_h256`
8. ❌ `chain.rs:169-180` - `parse_tx_id_hex`
9. ❌ `setup.rs:190-194` - `parse_seed_hex` (replace with common helper)

**Total saved:** ~90 lines

---

### Phase 4: Refactor Config Access (2-3 hours)

**Replace 20+ occurrences of verbose pattern:**

#### **Example 1: group_id**

**Location:** `setup.rs:108-112`

```rust
// BEFORE (4 lines):
let group_id_hex = app_config.iroh.group_id.clone().unwrap_or_default();
if group_id_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing group_id".to_string()));
}
let group_id = GroupId::from(parse_hash32_hex(&group_id_hex)?);

// AFTER (1 line):
let group_id: GroupId = parse_required(&app_config.iroh.group_id, "iroh.group_id")?;
```

---

#### **Example 2: seed_hex**

**Location:** `setup.rs:87-98`

```rust
// BEFORE (12 lines):
let peer_id_env = app_config.iroh.peer_id.clone().unwrap_or_default();
let seed_hex_env = app_config.iroh.signer_seed_hex.clone().unwrap_or_default();

let (peer_id, seed_hex) = if !peer_id_env.is_empty() && !seed_hex_env.is_empty() {
    info!("loading peer_id and seed from config");
    (PeerId::from(peer_id_env), seed_hex_env)
} else {
    info!("generating new peer_id and seed (none in config)");
    load_or_create_iroh_identity(&app_config.service.data_dir)?
};

let seed = parse_seed_hex(&seed_hex)?;

// AFTER (6 lines):
let (peer_id, seed) = match (
    app_config.iroh.peer_id.as_deref(),
    parse_optional::<[u8; 32]>(&app_config.iroh.signer_seed_hex)?
) {
    (Some(id), Some(seed)) => {
        info!("loading peer_id and seed from config");
        (PeerId::from(id), seed)
    }
    _ => {
        info!("generating new peer_id and seed (none in config)");
        load_or_create_iroh_identity(&app_config.service.data_dir)?
    }
};
```

---

### Phase 5: Refactor Logging (2-3 hours)

**Replace ~100+ occurrences:**

#### **Pattern 1: hex::encode in logs**

```rust
// BEFORE:
info!("event processed event_id={}", hex::encode(event_id));
warn!("failed event_id={} tx_hash={}", hex::encode(event_id), hex::encode(tx_template_hash));

// AFTER:
info!("event processed event_id={}", event_id);
warn!("failed event_id={} tx_hash={}", event_id, tx_template_hash);
```

**Automated refactor:**
```bash
# Find and replace in all files
find igra-service/src -name "*.rs" -exec sed -i '' \
  -e 's/hex::encode(event_id)/event_id/g' \
  -e 's/hex::encode(tx_template_hash)/tx_template_hash/g' \
  -e 's/hex::encode(group_id)/group_id/g' \
  {} \;
```

---

#### **Pattern 2: Inconsistent formatting**

**Current (inconsistent):**
```rust
debug!("event event_id={:#x}", event_id);         // 0xabcd...
info!("event event_id={:x}", event_id);           // abcd...
error!("event event_id={}", event_id);            // abcd... (via Display)
warn!("event event_id={}", hex::encode(event_id)); // abcd...
```

**Standardize:**
```rust
// Choose ONE format across codebase:

// Option 1: No prefix (Display trait)
info!("event event_id={}", event_id);

// Option 2: With 0x prefix (LowerHex with alternate)
info!("event event_id={:#x}", event_id);

// Recommendation: Use Display ({}) for most logs, {:#x} for debugging
```

---

### Phase 6: API Response Simplification (1 hour)

#### **Serde Serialization**

**Current (verbose):**
```rust
// API responses manually convert to hex
#[derive(Serialize)]
struct Response {
    event_id: String,  // Manually hex::encode
    tx_hash: String,   // Manually hex::encode
}

let response = Response {
    event_id: hex::encode(event_id),
    tx_hash: hex::encode(tx_template_hash),
};
```

**Refactored:** Types already serialize as hex via serde(transparent)!
```rust
#[derive(Serialize)]
struct Response {
    event_id: EventId,         // Automatically serializes as hex string
    tx_hash: TxTemplateHash,   // Automatically serializes as hex string
}

let response = Response {
    event_id,           // No conversion needed!
    tx_hash: tx_template_hash,
};
```

**How it works:**
```rust
// foundation/types.rs:50-52
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]  // <-- Serializes as the inner type's hex representation
pub struct EventId(Hash32);
```

**But wait:** Hash32 is `[u8; 32]`, which serializes as array by default.

**Fix:** Add custom serde implementation:
```rust
// foundation/types.rs - Add to macro
use serde::{Deserialize, Deserializer, Serialize, Serializer};

impl Serialize for $name {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for $name {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}
```

---

## Summary of All Issues Found

### Duplicate Functions (9 functions, ~90 LOC)

| Function | File | Lines | Return Type | Error Type |
|----------|------|-------|-------------|------------|
| `parse_hash32_hex` | crdt_handler.rs | 814-822 | `[u8; 32]` | ThresholdError |
| `parse_hash32_hex` | mailbox.rs | 109-117 | `[u8; 32]` | String |
| `parse_hash32_hex` | setup.rs | 201-206 | Hash32 | ThresholdError |
| `parse_hash32_hex` | audit.rs | 90-97 | Hash32 | ThresholdError |
| `parse_hash32_hex` | finalize.rs | 75-82 | Hash32 | ThresholdError |
| `parse_h256` | fake_hyperlane_relayer.rs | 166-173 | H256 | String |
| `parse_h256` | fake_hyperlane_ism_api.rs | 102-109 | H256 | String |
| `parse_tx_id_hex` | chain.rs | 169-180 | TransactionId | String |
| `parse_seed_hex` | setup.rs | 190-194 | `[u8; 32]` | ThresholdError |

---

### Verbose Config Access (5+ occurrences)

| Location | Field | Lines | Verbosity |
|----------|-------|-------|-----------|
| setup.rs | group_id | 108-112 | 4 lines → 1 line |
| setup.rs | peer_id | 87-88 | 2 lines → inline |
| setup.rs | seed_hex | 87-98 | 12 lines → 6 lines |
| kaspa-threshold-service.rs | test_recipient | 236 | 1 line → inline |

---

### Manual hex::encode in Logs (100+ occurrences)

**Estimate:** ~120 instances across codebase

**Common patterns:**
```rust
hex::encode(event_id)
hex::encode(tx_template_hash)
hex::encode(group_id)
hex::encode(session_id)
event_id.to_string() + hex conversion
```

---

### Type Conversion in Errors (20+ occurrences)

**Patterns:**
```rust
tx_template_hash.to_string()  // Should use Display
hex::encode(event_id)         // Should use Display
format!("{:?}", hash)         // Should use Display
```

---

## Implementation Checklist

### ✅ Phase 1: Foundation (1-2h)

- [ ] Add `FromStr` implementation to hash type macro in `foundation/types.rs`
- [ ] Add custom `Serialize`/`Deserialize` for hex string representation
- [ ] Add `ThresholdError::ParseError` variant if not exists
- [ ] Test with unit tests for each type
- [ ] Add example to documentation

**Test:**
```rust
#[test]
fn test_event_id_from_str() {
    let hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let id: EventId = hex.parse().unwrap();
    assert_eq!(id.to_string(), "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

    // Without 0x prefix
    let hex2 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let id2: EventId = hex2.parse().unwrap();
    assert_eq!(id, id2);

    // Invalid hex
    assert!("not-hex".parse::<EventId>().is_err());

    // Wrong length
    assert!("0xabcd".parse::<EventId>().is_err());
}
```

---

### ✅ Phase 2: Config Helpers (30min)

- [ ] Create `foundation/config_helpers.rs`
- [ ] Implement `parse_required()`
- [ ] Implement `parse_optional()`
- [ ] Implement `parse_or_default()`
- [ ] Add unit tests
- [ ] Export from `foundation/mod.rs`

---

### ✅ Phase 3: Delete Duplicates (30min)

**Delete these functions:**
- [ ] `crdt_handler.rs:814` - `parse_hash32_hex`
- [ ] `mailbox.rs:109` - `parse_hash32_hex`
- [ ] `setup.rs:201` - `parse_hash32_hex`
- [ ] `audit.rs:90` - `parse_hash32_hex`
- [ ] `finalize.rs:75` - `parse_hash32_hex`
- [ ] `fake_hyperlane_relayer.rs:166` - `parse_h256`
- [ ] `fake_hyperlane_ism_api.rs:102` - `parse_h256`
- [ ] `chain.rs:169` - `parse_tx_id_hex`
- [ ] `setup.rs:190` - `parse_seed_hex`

**Replace with:**
```rust
use std::str::FromStr;

// Direct parsing:
let event_id: EventId = hex_string.parse()?;

// With error context:
let group_id: GroupId = hex_string.parse()
    .map_err(|e| format!("invalid group_id: {}", e))?;
```

---

### ✅ Phase 4: Refactor Config Access (2-3h)

**Files to update:**
- [ ] `setup.rs:108-112` - group_id
- [ ] `setup.rs:87-98` - peer_id + seed_hex
- [ ] `kaspa-threshold-service.rs:236` - test_recipient
- [ ] All other config access patterns

**Pattern:**
```rust
// Find:
let value_hex = config.field.clone().unwrap_or_default();
if value_hex.is_empty() {
    return Err(...);
}
let value = Type::from(parse_hash32_hex(&value_hex)?);

// Replace:
use crate::foundation::config_helpers::parse_required;
let value: Type = parse_required(&config.field, "field_name")?;
```

---

### ✅ Phase 5: Refactor Logging (2-3h)

**Automated find-and-replace:**

```bash
# Remove hex::encode from logs
cd /Users/user/Source/personal/rusty-kaspa/wallet/igra

find igra-service/src igra-core/src -name "*.rs" -type f -exec sed -i '' \
  -e 's/hex::encode(event_id)/event_id/g' \
  -e 's/hex::encode(tx_template_hash)/tx_template_hash/g' \
  -e 's/hex::encode(group_id)/group_id/g' \
  -e 's/hex::encode(session_id)/session_id/g' \
  -e 's/hex::encode(\([a-z_]*\)\.event_id)/\1.event_id/g' \
  {} \;

# Manual review required for:
# - Ensure replacements are in log! macros only
# - Check formatting consistency ({} vs {:#x})
# - Verify no functional code broken
```

**Manual updates needed (~20 files):**
- Review each change
- Choose consistent format: `{}` vs `{:#x}`
- Update tests that check log output

---

### ✅ Phase 6: Simplify API Responses (1h)

**Update API handler patterns:**

```rust
// BEFORE:
#[derive(Serialize)]
struct EventResponse {
    event_id: String,  // Manual conversion
}

let resp = EventResponse {
    event_id: hex::encode(event_id),
};

// AFTER:
#[derive(Serialize)]
struct EventResponse {
    event_id: EventId,  // Auto-serializes as hex string
}

let resp = EventResponse {
    event_id,
};
```

**Files to update:**
- [ ] `api/handlers/signing_event.rs`
- [ ] `api/handlers/chain.rs`
- [ ] `api/handlers/hyperlane.rs`
- [ ] `api/handlers/mailbox.rs`

---

## Before & After Comparison

### Example: setup.rs Group ID Parsing

#### **BEFORE (Current - Verbose)**

```rust
// Lines 108-112 (5 lines)
let group_id_hex = app_config.iroh.group_id.clone().unwrap_or_default();
if group_id_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing group_id".to_string()));
}
let group_id = GroupId::from(parse_hash32_hex(&group_id_hex)?);

// Helper function (7 lines) - DUPLICATED 5 TIMES
fn parse_hash32_hex(value: &str) -> Result<Hash32, ThresholdError> {
    let bytes = hex::decode(value.trim())?;
    let array: [u8; 32] = bytes.as_slice()
        .try_into()
        .map_err(|_| ThresholdError::Message("expected 32-byte hex value".to_string()))?;
    Ok(array)
}
```

**Total:** 12 lines (5 + 7)

---

#### **AFTER (Proposed - Clean)**

```rust
// Main code (1 line)
let group_id: GroupId = parse_required(&app_config.iroh.group_id, "iroh.group_id")?;

// Helper function (1 implementation in foundation/config_helpers.rs)
// Already defined globally, no duplication
```

**Total:** 1 line (12 → 1 = **92% reduction**)

---

### Example: Logging Simplification

#### **BEFORE**

```rust
info!(
    "two-phase published local proposal event_id={} round={} tx_template_hash={}",
    hex::encode(event_id),
    0,
    hex::encode(proposal.tx_template_hash)
);
```

---

#### **AFTER**

```rust
info!(
    "two-phase published local proposal event_id={} round={} tx_template_hash={}",
    event_id,
    0,
    proposal.tx_template_hash
);
```

**Saved:** 2 function calls, cleaner code, same output

---

## Impact Analysis

### Code Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Duplicate parse functions** | 9 | 1 | **89% reduction** |
| **Lines of duplicate code** | ~90 | ~10 | **89% reduction** |
| **Config access verbosity** | 4-12 lines | 1-2 lines | **75-90% reduction** |
| **Manual hex::encode in logs** | ~120 | 0 | **100% reduction** |
| **Type conversions** | Manual | Automatic | **Simpler** |

### Development Experience

| Aspect | Before | After |
|--------|--------|-------|
| **Adding new hash field** | Write parse function + 4-line access pattern | Use `.parse()` |
| **Logging hash values** | Remember to `hex::encode()` | Just use `{}` |
| **API responses** | Manual conversion | Automatic serialization |
| **Error messages** | Inconsistent formats | Consistent via Display |
| **Config validation** | Verbose if-empty checks | One-line helper call |

---

## Detailed Refactoring Steps

### Step 1: Update foundation/types.rs

**Location:** `igra-core/src/foundation/types.rs`

**Add to line 127 (after macro definition, before type definitions):**

```rust
// Common hex parsing function (used by FromStr implementations)
fn parse_hex_hash32(s: &str) -> Result<Hash32, crate::foundation::ThresholdError> {
    let stripped = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped).map_err(|e| {
        crate::foundation::ThresholdError::ParseError(format!("invalid hex: {}", e))
    })?;
    if bytes.len() != 32 {
        return Err(crate::foundation::ThresholdError::ParseError(
            format!("expected 32 bytes, got {}", bytes.len())
        ));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
```

**Update macro at line 49 to add FromStr + improved serde:**

```rust
macro_rules! define_id_type {
    (hash $name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
        pub struct $name(Hash32);

        impl $name {
            pub const fn new(value: Hash32) -> Self {
                Self(value)
            }

            pub fn as_hash(&self) -> &Hash32 {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if f.alternate() {
                    f.write_str("0x")?;
                }
                for byte in self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }

        impl fmt::UpperHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if f.alternate() {
                    f.write_str("0x")?;
                }
                for byte in self.0 {
                    write!(f, "{:02X}", byte)?;
                }
                Ok(())
            }
        }

        // NEW: FromStr implementation
        impl std::str::FromStr for $name {
            type Err = crate::foundation::ThresholdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok($name::from(parse_hex_hash32(s)?))
            }
        }

        // NEW: Custom serde for hex string serialization
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl AsRef<Hash32> for $name {
            fn as_ref(&self) -> &Hash32 {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Deref for $name {
            type Target = Hash32;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl From<Hash32> for $name {
            fn from(value: Hash32) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Hash32 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}
```

---

### Step 2: Create Config Helpers Module

**File:** `igra-core/src/foundation/config_helpers.rs` (NEW)

```rust
use crate::foundation::ThresholdError;
use std::str::FromStr;

/// Parse required config option (error if None or empty)
pub fn parse_required<T>(opt: &Option<String>, field: &str) -> Result<T, ThresholdError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    opt.as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ThresholdError::ConfigError(format!("missing {}", field)))?
        .parse()
        .map_err(|e| ThresholdError::ConfigError(format!("invalid {}: {}", field, e)))
}

/// Parse optional config (Ok(None) if None or empty)
pub fn parse_optional<T>(opt: &Option<String>) -> Result<Option<T>, ThresholdError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match opt.as_deref() {
        Some(s) if !s.trim().is_empty() => {
            Ok(Some(s.parse().map_err(|e| {
                ThresholdError::ConfigError(format!("parse error: {}", e))
            })?))
        }
        _ => Ok(None),
    }
}

/// Parse with default value
pub fn parse_or_default<T>(opt: &Option<String>, default: T) -> T
where
    T: FromStr + Default,
{
    opt.as_deref()
        .and_then(|s| if s.trim().is_empty() { None } else { s.parse().ok() })
        .unwrap_or(default)
}

/// Parse array of hex strings
pub fn parse_hex_array<T>(values: &[String]) -> Result<Vec<T>, ThresholdError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    values
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.parse().map_err(|e| {
            ThresholdError::ConfigError(format!("invalid hex in array: {}", e))
        }))
        .collect()
}
```

**Export in `foundation/mod.rs`:**
```rust
pub mod config_helpers;
pub use config_helpers::{parse_required, parse_optional, parse_or_default, parse_hex_array};
```

---

### Step 3: Update ThresholdError

**File:** `igra-core/src/foundation/error.rs`

**Add variant if not exists:**
```rust
#[derive(Debug, thiserror::Error)]
pub enum ThresholdError {
    // ... existing variants ...

    #[error("parse error: {0}")]
    ParseError(String),

    // ... rest ...
}
```

---

### Step 4: Refactor All Call Sites

#### **Config Access Sites (5 locations)**

**File:** `setup.rs:108-112`
```rust
// BEFORE:
let group_id_hex = app_config.iroh.group_id.clone().unwrap_or_default();
if group_id_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing group_id".to_string()));
}
let group_id = GroupId::from(parse_hash32_hex(&group_id_hex)?);

// AFTER:
use crate::foundation::parse_required;
let group_id: GroupId = parse_required(&app_config.iroh.group_id, "iroh.group_id")?;
```

**File:** `setup.rs:87-98`
```rust
// BEFORE:
let peer_id_env = app_config.iroh.peer_id.clone().unwrap_or_default();
let seed_hex_env = app_config.iroh.signer_seed_hex.clone().unwrap_or_default();

let (peer_id, seed_hex) = if !peer_id_env.is_empty() && !seed_hex_env.is_empty() {
    info!("loading peer_id and seed from config");
    (PeerId::from(peer_id_env), seed_hex_env)
} else {
    info!("generating new peer_id and seed (none in config)");
    load_or_create_iroh_identity(&app_config.service.data_dir)?
};

let seed = parse_seed_hex(&seed_hex)?;

// AFTER:
use crate::foundation::{parse_optional, parse_hex_32bytes};

let (peer_id, seed) = match (
    app_config.iroh.peer_id.as_deref().map(PeerId::from),
    parse_optional::<[u8; 32]>(&app_config.iroh.signer_seed_hex)?
) {
    (Some(id), Some(seed)) => {
        info!("loading peer_id and seed from config");
        (id, seed)
    }
    _ => {
        info!("generating new peer_id and seed");
        load_or_create_iroh_identity(&app_config.service.data_dir)?
    }
};
```

---

#### **API Handler Sites (4 files)**

**File:** `mailbox.rs:54-57`
```rust
// BEFORE:
let message_id = match parse_hash32_hex(&id) {
    Ok(id) => id,
    Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
};

// AFTER:
let message_id: Hash32 = id.parse()
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid message_id: {}", e)))?;
```

**File:** `chain.rs:127-130`
```rust
// BEFORE:
let tx_id = match parse_tx_id_hex(&hash_hex) {
    Ok(id) => id,
    Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
};

// AFTER:
let tx_id: TransactionId = hash_hex.parse()
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid tx_id: {}", e)))?;
```

---

#### **Logging Sites (~100 occurrences)**

**Automated replacement script:**

```bash
#!/bin/bash
# hex-refactor.sh

FILES=$(find igra-service/src igra-core/src -name "*.rs" -type f)

for file in $FILES; do
    echo "Processing: $file"

    # Remove hex::encode from common hash types in log macros
    sed -i '' \
        -e 's/hex::encode(event_id)/event_id/g' \
        -e 's/hex::encode(tx_template_hash)/tx_template_hash/g' \
        -e 's/hex::encode(group_id)/group_id/g' \
        -e 's/hex::encode(session_id)/session_id/g' \
        -e 's/hex::encode(\([a-z_]*\)\.event_id)/\1.event_id/g' \
        -e 's/hex::encode(\([a-z_]*\)\.tx_template_hash)/\1.tx_template_hash/g' \
        "$file"
done

echo "Refactoring complete. Run tests to verify."
```

**Manual review:** Check each file for correctness after automated changes

---

## Validation & Testing

### Test Plan

**After Phase 1 (FromStr implementation):**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_types_from_str() {
        // Test EventId
        let id: EventId = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .parse()
            .unwrap();
        assert_eq!(id.to_string(), "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        // Test with 0x prefix
        let id2: EventId = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .parse()
            .unwrap();
        assert_eq!(id, id2);

        // Test round-trip
        let original = EventId::from([0x12u8; 32]);
        let hex = original.to_string();
        let parsed: EventId = hex.parse().unwrap();
        assert_eq!(original, parsed);

        // Test all hash types
        let _: GroupId = "ab".repeat(32).parse().unwrap();
        let _: SessionId = "cd".repeat(32).parse().unwrap();
        let _: TransactionId = "ef".repeat(32).parse().unwrap();
    }

    #[test]
    fn test_parse_errors() {
        // Invalid hex
        assert!("not-hex".parse::<EventId>().is_err());

        // Wrong length
        assert!("abcd".parse::<EventId>().is_err());

        // Empty
        assert!("".parse::<EventId>().is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let id = EventId::from([0xabu8; 32]);

        // Serialize
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.contains("ab"));

        // Deserialize
        let parsed: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }
}
```

**After Phase 2-6:**
- Run full test suite: `cargo test --all`
- Check CI: Ensure no regressions
- Manual testing: Verify config loading still works
- Log review: Check formatted output is correct

---

## Migration Strategy

### Approach: Incremental Rollout

**Week 1: Foundation**
- Implement FromStr in types.rs
- Create config_helpers.rs
- Add tests
- **No breaking changes yet**

**Week 2: Replace Parsing Functions**
- Delete duplicate parse_hash32_hex functions one by one
- Replace with `.parse()` calls
- Test after each file

**Week 3: Refactor Config Access**
- Update config loading patterns
- Use parse_required/parse_optional helpers
- Test configuration loading

**Week 4: Refactor Logging**
- Run automated script
- Manual review and fix
- Update tests that check log output

**Week 5: API Responses**
- Update API handlers
- Test JSON serialization
- Update API documentation

---

## Risk Mitigation

### Potential Risks

1. **Breaking serde compatibility**
   - Current: Some places may expect `[u8; 32]` array in JSON
   - After: Will serialize as hex string
   - **Mitigation:** Check API contracts, update clients if needed

2. **Log format changes**
   - Tests may expect specific log formats
   - **Mitigation:** Update test assertions

3. **Parsing errors in production**
   - Invalid hex in config will now fail at parse time
   - **Mitigation:** Add config validation tests

### Rollback Plan

- Keep changes in feature branch until fully tested
- Add feature flag for new behavior
- Gradual rollout: test → staging → production

---

## Effort Estimate

| Phase | Tasks | Effort |
|-------|-------|--------|
| 1. Foundation | Add FromStr + serde to types | 2h |
| 2. Config Helpers | Create helper module | 1h |
| 3. Delete Duplicates | Remove 9 parse functions | 1h |
| 4. Config Access | Refactor 5+ locations | 2-3h |
| 5. Logging | Automated + manual review | 3-4h |
| 6. API Responses | Update handlers | 1-2h |
| **Total** | | **10-14h** |

### ROI

**Lines of code reduced:** ~250-300 lines
**Maintainability:** Significantly improved
**Consistency:** All hex parsing uses same logic
**Developer experience:** Much simpler

---

## Code Examples

### Example 1: Full Transformation

**BEFORE (Current):**
```rust
// setup.rs:108-112 + helper function
let group_id_hex = app_config.iroh.group_id.clone().unwrap_or_default();
if group_id_hex.is_empty() {
    return Err(ThresholdError::ConfigError("missing group_id".to_string()));
}
let group_id = GroupId::from(parse_hash32_hex(&group_id_hex)?);

fn parse_hash32_hex(value: &str) -> Result<Hash32, ThresholdError> {
    let bytes = hex::decode(value.trim())?;
    let array: [u8; 32] = bytes.as_slice()
        .try_into()
        .map_err(|_| ThresholdError::Message("expected 32-byte hex value".to_string()))?;
    Ok(array)
}

// Total: 12 lines
```

**AFTER (Proposed):**
```rust
use crate::foundation::parse_required;

let group_id: GroupId = parse_required(&app_config.iroh.group_id, "iroh.group_id")?;

// Total: 1 line (foundation helper is shared, not duplicated)
```

**Reduction:** 12 lines → 1 line = **92% reduction**

---

### Example 2: Logging Transformation

**BEFORE:**
```rust
info!(
    "two-phase published proposal event_id={} round={} tx_hash={}",
    hex::encode(event_id),
    round,
    hex::encode(tx_template_hash)
);

warn!(
    "CRDT merge rejected event_id={} tx_hash={}",
    hex::encode(event_id),
    hex::encode(tx_template_hash)
);

debug!("signing event_id={:#x}", event_id);  // Inconsistent
```

**AFTER:**
```rust
info!(
    "two-phase published proposal event_id={} round={} tx_hash={}",
    event_id,
    round,
    tx_template_hash
);

warn!(
    "CRDT merge rejected event_id={} tx_hash={}",
    event_id,
    tx_template_hash
);

debug!("signing event_id={}", event_id);  // Consistent
// OR with 0x prefix:
debug!("signing event_id={:#x}", event_id);
```

**Benefits:**
- Cleaner code
- Consistent formatting
- No manual encoding
- Same output (types implement Display/LowerHex)

---

### Example 3: API Response Transformation

**BEFORE:**
```rust
#[derive(Serialize)]
struct EventStatusResponse {
    event_id: String,
    tx_id: String,
    phase: String,
}

let response = EventStatusResponse {
    event_id: hex::encode(event_id),
    tx_id: tx_id.map(|id| hex::encode(id)).unwrap_or_default(),
    phase: phase.to_string(),
};

Json(response)
```

**AFTER:**
```rust
#[derive(Serialize)]
struct EventStatusResponse {
    event_id: EventId,        // Auto-serializes as hex string
    tx_id: Option<TransactionId>,  // Auto-serializes
    phase: EventPhase,        // Already has Serialize
}

let response = EventStatusResponse {
    event_id,
    tx_id,
    phase,
};

Json(response)  // Automatic hex serialization!
```

**JSON Output (identical):**
```json
{
  "event_id": "1234567890abcdef...",
  "tx_id": "fedcba0987654321...",
  "phase": "Completed"
}
```

---

## Appendix: All Locations to Refactor

### A. Delete These Functions (9 total)

| File | Function | Lines | Notes |
|------|----------|-------|-------|
| crdt_handler.rs | parse_hash32_hex | 814-822 | Used locally |
| mailbox.rs | parse_hash32_hex | 109-117 | Used in API |
| setup.rs | parse_hash32_hex | 201-206 | Used in setup |
| audit.rs | parse_hash32_hex | 90-97 | Used in CLI mode |
| finalize.rs | parse_hash32_hex | 75-82 | Used in CLI mode |
| fake_hyperlane_relayer.rs | parse_h256 | 166-173 | Test utility |
| fake_hyperlane_ism_api.rs | parse_h256 | 102-109 | Test utility |
| chain.rs | parse_tx_id_hex | 169-180 | Used in API |
| setup.rs | parse_seed_hex | 190-194 | Used in setup |

---

### B. Refactor Config Access (5+ locations)

| File | Lines | Field | Current Lines | After Lines |
|------|-------|-------|---------------|-------------|
| setup.rs | 108-112 | group_id | 4 | 1 |
| setup.rs | 87-98 | peer_id, seed | 12 | 6 |
| kaspa-threshold-service.rs | 236 | test_recipient | 1 | inline |

---

### C. Refactor Logging (~100 locations)

**Estimated occurrences:**
- `hex::encode(event_id)` - ~40 times
- `hex::encode(tx_template_hash)` - ~30 times
- `hex::encode(group_id)` - ~10 times
- `hex::encode(session_id)` - ~20 times
- Other hash types - ~20 times

**Total:** ~120 replacements

---

### D. Update Error Construction (~20 locations)

**Pattern:**
```rust
// Find:
.to_string()  // On hash types in error construction

// Review and potentially replace with:
format!("{}", hash)  // Uses Display
// OR store hash directly in error type
```

---

## Success Criteria

### Metrics

**Code Size:**
- Delete 90+ lines of duplicate functions ✅
- Reduce config access verbosity by 75% ✅
- Remove 120+ manual hex::encode calls ✅

**Consistency:**
- All hash parsing uses FromStr ✅
- All logging uses Display/LowerHex ✅
- All config access uses helpers ✅
- All API responses auto-serialize ✅

**Developer Experience:**
- New hash fields: Just add `.parse()` ✅
- Logging: Just use `{}` ✅
- Config: Use parse_required/parse_optional ✅

### Testing

- [ ] Unit tests for FromStr implementations
- [ ] Config loading tests
- [ ] API serialization tests
- [ ] Log format tests (if any)
- [ ] Integration tests pass
- [ ] No regressions in production

---

## Conclusion

This refactoring will:

1. **Delete ~90 lines** of duplicated parsing code
2. **Simplify ~125 call sites** (config access + logging)
3. **Improve consistency** (all hex handling uses standard traits)
4. **Enhance maintainability** (DRY principle)
5. **Better developer experience** (`.parse()` just works)

**Total effort:** 10-14 hours
**Total impact:** ~250-300 lines eliminated, much cleaner codebase

**Priority:** Medium-High (not critical, but significant quality improvement)

---

**Document Version:** 1.0
**Last Updated:** 2026-01-21
**Status:** Ready for implementation
