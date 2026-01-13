# MISSED_CLEANUPS.md

Remaining work from CLEANUPS.md implementation. Generated from codebase scan.

---

## Priority HIGH

### 1. Delete `RequestId` Type

**CLEANUPS.md Section:** 3

**Current State:** `RequestId` still exists in `foundation/types.rs`

**Action:**
```rust
// DELETE from foundation/types.rs:
pub type RequestId = String;
```

**Files to update:**
- `foundation/types.rs` - delete type
- `domain/signing/threshold.rs` - change `request_id: &RequestId` to `event_id: &Hash32`
- `domain/signing/results.rs` - change `request_id: RequestId` to `event_id: Hash32`
- `domain/signing/mod.rs` - update `SignerBackend` trait
- `domain/signing/mpc.rs` - update stub
- `domain/signing/musig2.rs` - update stub
- All callers of `sign()` method

---

### 2. Add `external_request_id` to SigningEventParams

**CLEANUPS.md Section:** 3

**Current State:** No client correlation ID field

**Action:**
```rust
// ADD to SigningEventParams (or equivalent):
pub struct SigningEventParams {
    /// Client-provided correlation ID (optional, for tracing)
    pub external_request_id: Option<String>,
    // ... other fields
}
```

**Rationale:** Clients need a correlation ID they control for support tickets and internal tracing. `event_id` is computed internally.

---

### 3. Update SignerBackend Trait

**CLEANUPS.md Section:** 3

**Current State:**
```rust
fn sign(&self, kpsbt_blob: &[u8], request_id: &RequestId) -> Result<SigningResult, ThresholdError>;
```

**Action:**
```rust
fn sign(&self, kpsbt_blob: &[u8], event_id: &Hash32) -> Result<SigningResult, ThresholdError>;
```

**Files:**
- `domain/signing/mod.rs`
- `domain/signing/threshold.rs`
- `domain/signing/mpc.rs`
- `domain/signing/musig2.rs`

---

## Priority MEDIUM

### 4. Feature-Gate Memory Storage

**CLEANUPS.md Section:** 4

**Current State:** `memory.rs` always compiled

**Action:**
```rust
// In infrastructure/storage/mod.rs:
#[cfg(any(test, feature = "test-utils"))]
pub mod memory;

#[cfg(any(test, feature = "test-utils"))]
pub use memory::MemoryStorage;
```

```toml
# In Cargo.toml:
[features]
default = []
test-utils = []
```

**Rationale:** Memory storage is for tests only. Feature-gating reduces production binary size and makes intent clear.

---

### 5. Add DoS Validation for `source_data`

**CLEANUPS.md Section:** 1 (DoS Hardening)

**Current State:** No limits on `source_data` BTreeMap

**Action:**
```rust
// In normalization/shared.rs or normalization/mod.rs:

const MAX_SOURCE_DATA_KEYS: usize = 64;
const MAX_SOURCE_DATA_KEY_LEN: usize = 64;
const MAX_SOURCE_DATA_VALUE_LEN: usize = 2048;

fn validate_source_data(source_data: &BTreeMap<String, String>) -> Result<(), ThresholdError> {
    if source_data.len() > MAX_SOURCE_DATA_KEYS {
        return Err(ThresholdError::MessageTooLarge {
            size: source_data.len(),
            max: MAX_SOURCE_DATA_KEYS,
        });
    }
    for (key, value) in source_data {
        if key.len() > MAX_SOURCE_DATA_KEY_LEN {
            return Err(ThresholdError::InvalidExternalId(format!(
                "source_data key too long: {} > {}",
                key.len(),
                MAX_SOURCE_DATA_KEY_LEN
            )));
        }
        if value.len() > MAX_SOURCE_DATA_VALUE_LEN {
            return Err(ThresholdError::InvalidExternalId(format!(
                "source_data value too long: {} > {}",
                value.len(),
                MAX_SOURCE_DATA_VALUE_LEN
            )));
        }
    }
    Ok(())
}
```

---

### 6. Add Wire Protocol Versioning

**CLEANUPS.md Section:** 6.6

**Current State:** No explicit protocol version in gossip messages

**Action:**
```rust
// In infrastructure/transport/iroh/messages.rs:

/// Wire envelope with explicit protocol version.
/// Receivers MUST reject messages with unknown versions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireEnvelope {
    /// Protocol version (increment on breaking changes)
    pub protocol_version: u16,
    /// The actual message payload
    pub payload: TransportMessage,
}

pub const CURRENT_PROTOCOL_VERSION: u16 = 1;

impl WireEnvelope {
    pub fn new(payload: TransportMessage) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            payload,
        }
    }

    pub fn validate_version(&self) -> Result<(), ThresholdError> {
        if self.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ThresholdError::EncodingError(format!(
                "protocol version mismatch: expected {}, got {}",
                CURRENT_PROTOCOL_VERSION, self.protocol_version
            )));
        }
        Ok(())
    }
}
```

**Rationale:** bincode is not a stable wire format. Explicit versioning prevents "mystery split-brain" when nodes run different versions.

---

## Priority LOW

### 7. Document `canonical_external_id_from_raw` Behavior

**CLEANUPS.md Section:** 1.1 Step 4

**Current State:** Function hashes non-hex strings under domain separator

```rust
// Current behavior in normalization/shared.rs:38-55
pub fn canonical_external_id_from_raw(raw: &str) -> Result<Hash32, ThresholdError> {
    // If it looks like 32-byte hex, use it
    if let Ok(id) = parse_external_id(trimmed) {
        return Ok(id);
    }
    // Otherwise, hash it under domain separator
    const DOMAIN: &[u8] = b"igra:external_id:v1:";
    // ...
}
```

**Action:** Either:
1. Document this behavior in CLEANUPS.md as intentional, OR
2. Make it strict (reject non-hex strings)

**Recommendation:** Keep current behavior but document:
```markdown
### Non-Hex External IDs

For sources that don't provide 32-byte hex IDs (e.g., API requests with UUID strings),
`canonical_external_id_from_raw` hashes them under a domain separator:

    external_id = BLAKE3("igra:external_id:v1:" || raw_string)

This ensures:
- Deterministic mapping (same string → same event_id)
- No collisions with native 32-byte IDs (different domain)
```

---

## Already Completed ✅

For reference, these items from CLEANUPS.md are done:

| Item | Location |
|------|----------|
| Event model (`Event`, `SourceType`, `StoredEvent`) | `model.rs` |
| `external_id: Hash32` (typed) | `model.rs:13` |
| `destination: ScriptPublicKey` | `model.rs:17` |
| `EventAuditData` | `model.rs:44-50` |
| `CrdtSigningMaterial` | `model.rs:53-58` |
| Versioned event_id encoding | `hashes.rs:5-38` |
| Domain separator `igra:event:v1:` | `hashes.rs:5` |
| Explicit byte encoding | `hashes.rs:14-38` |
| Stability test | `hashes.rs:51-73` |
| Normalization module | `normalization/` |
| `normalize_hyperlane()` | `normalization/hyperlane.rs` |
| `parse_external_id()` | `normalization/shared.rs:26-36` |
| `parse_destination()` | `normalization/shared.rs:57-80` |
| `ExpectedNetwork` type | `normalization/shared.rs:7-24` |
| `thiserror` for errors | `error.rs` |
| New error variants | `error.rs:122-128` |
| Memory storage kept | `memory.rs` |
| `event_active_template` index | `memory.rs:12`, `engine.rs:156-162` |
| `event_completion` index | `memory.rs:13`, `engine.rs:163-168` |
| Schema versioning | `engine.rs:107-119` |
| `allow_schema_wipe` config | `engine.rs:26-48` |
| Circuit breaker integration | `grpc.rs:14-19, 39-42, 65-82` |
| Per-method circuit breakers | `grpc.rs:16-18` |
| Signing backend validation | `validation.rs:116-121` |
| DoS limits (address length) | `shared.rs:62-67` |
| Delete `conversion.rs` | Deleted |

---

## Checklist

### Phase 1: RequestId Removal (HIGH)
- [ ] Delete `RequestId` type from `foundation/types.rs`
- [ ] Add `external_request_id: Option<String>` to params
- [ ] Update `SignerBackend` trait to use `event_id: &Hash32`
- [ ] Update `threshold.rs` implementation
- [ ] Update `mpc.rs` stub
- [ ] Update `musig2.rs` stub
- [ ] Update `SigningResult` to use `event_id: Hash32`
- [ ] Update all callers

### Phase 2: Hardening (MEDIUM)
- [ ] Feature-gate `memory.rs` with `#[cfg(any(test, feature = "test-utils"))]`
- [ ] Add `test-utils` feature to `Cargo.toml`
- [ ] Add `validate_source_data()` function
- [ ] Call validation in normalization functions
- [ ] Add `WireEnvelope` with `protocol_version`
- [ ] Update message encoding/decoding
- [ ] Add version check on receive

### Phase 3: Documentation (LOW)
- [ ] Document `canonical_external_id_from_raw` behavior in CLEANUPS.md

---

*Generated: 2025-01-13*
*Based on: CLEANUPS.md v5.1*
