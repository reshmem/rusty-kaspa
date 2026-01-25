# TODO-FIXES.md

Technical debt and code guideline violations to address. Organized by priority.

---

## Summary

| Priority | Category | Count | Effort |
|----------|----------|-------|--------|
| **P0** | Critical bugs | 1 | 5 min |
| **P1** | DRY violations | 2 | 30 min |
| **P1** | Error handling | 3 | 2 hrs |
| **P2** | Error context | 15+ | 1 hr |
| **P3** | Refactoring | 2 | 2 hrs |

---

## P0: Critical (Fix Immediately)

### 1. `.unwrap()` in Production Code

**File:** `igra-core/src/infrastructure/config/encryption.rs`
**Line:** 51

**Current:**
```rust
pub fn decrypt_mnemonics(&self) -> Result<Vec<PrvKeyData>, ThresholdError> {
    let encrypted = match self.encrypted_mnemonics.as_ref() {
        Some(encrypted) => encrypted,
        None => return Ok(Vec::new()),
    };
    let wallet_secret = load_wallet_secret()?;
    let decrypted = encrypted.decrypt(Some(&wallet_secret)).map_err(|err| {
        warn!("failed to decrypt hd.mnemonics");
        ThresholdError::ConfigError(format!("failed to decrypt hd.mnemonics: {}", err))
    })?;
    Ok(decrypted.unwrap())  // <-- BUG: Can panic if decrypt returns Ok(None)
}
```

**Fix:**
```rust
pub fn decrypt_mnemonics(&self) -> Result<Vec<PrvKeyData>, ThresholdError> {
    let encrypted = match self.encrypted_mnemonics.as_ref() {
        Some(encrypted) => encrypted,
        None => return Ok(Vec::new()),
    };
    let wallet_secret = load_wallet_secret()?;
    let decrypted = encrypted.decrypt(Some(&wallet_secret)).map_err(|err| {
        warn!("failed to decrypt hd.mnemonics");
        ThresholdError::ConfigError(format!("failed to decrypt hd.mnemonics: {}", err))
    })?;
    decrypted.ok_or_else(|| {
        ThresholdError::ConfigError("decryption succeeded but returned no data".to_string())
    })
}
```

---

## P1: High Priority (Fix This Sprint)

### 2. Duplicate Type Conversion Code

**File:** `igra-service/src/service/coordination/crdt_handler.rs`
**Lines:** 101-122 and 158-179

**Problem:** Identical 20-line conversion block appears twice.

**Step 1:** Add `From` impl in `igra-core/src/infrastructure/transport/iroh/messages.rs`:

```rust
impl From<&crate::domain::StoredEventCrdt> for EventCrdtState {
    fn from(state: &crate::domain::StoredEventCrdt) -> Self {
        Self {
            signatures: state.signatures.iter().map(CrdtSignature::from).collect(),
            completion: state.completion.as_ref().map(CompletionRecord::from),
            signing_material: state.signing_material.clone(),
            kpsbt_blob: state.kpsbt_blob.clone(),
            version: state.version,
        }
    }
}
```

**Step 2:** Replace in `crdt_handler.rs` (two locations):

```rust
// Line ~101 (broadcast_local_state)
let crdt_state = EventCrdtState::from(&state);

// Line ~158 (handle_state_sync_request)
let crdt_state = EventCrdtState::from(&state);
```

---

### 3. Inconsistent `From` Trait Usage

**File:** `igra-service/src/service/coordination/crdt_handler.rs`
**Line:** 105

**Current:**
```rust
.map(|s| CrdtSignature {
    input_index: s.input_index,
    pubkey: s.pubkey.clone(),
    signature: s.signature.clone(),
    signer_peer_id: Some(s.signer_peer_id.clone()),
    timestamp_nanos: s.timestamp_nanos,
})
```

**Fix:** Use existing `From` impl:
```rust
.map(CrdtSignature::from)
```

Note: The `From<&CrdtSignatureRecord> for CrdtSignature` impl already exists in `messages.rs:101-110`.

---

### 4. Create Structured Error Variants

**File:** `igra-core/src/foundation/error.rs`

**Problem:** 80+ occurrences of `.map_err(|err| ThresholdError::Message(err.to_string()))` lose error context.

**Add these variants to `ThresholdError` enum:**

```rust
pub enum ThresholdError {
    // ... existing variants ...

    // NEW: Storage errors
    #[error("storage error during {operation}: {source}")]
    StorageError {
        operation: String,
        source: String,
    },

    // NEW: Serialization errors
    #[error("{format} serialization error: {source}")]
    SerializationError {
        format: String,  // "json", "borsh", etc.
        source: String,
    },

    // NEW: Crypto errors
    #[error("crypto error during {operation}: {source}")]
    CryptoError {
        operation: String,
        source: String,
    },

    // NEW: PSKT errors
    #[error("PSKT error during {operation}: {source}")]
    PsktError {
        operation: String,
        source: String,
    },

    // NEW: Transport errors
    #[error("transport error during {operation}: {source}")]
    TransportError {
        operation: String,
        source: String,
    },
}
```

**Update `ErrorCode` mapping:**
```rust
impl From<&ThresholdError> for ErrorCode {
    fn from(err: &ThresholdError) -> Self {
        match err {
            // ... existing ...
            ThresholdError::StorageError { .. } => ErrorCode::Storage,
            ThresholdError::SerializationError { .. } => ErrorCode::Serialization,
            ThresholdError::CryptoError { .. } => ErrorCode::Crypto,
            ThresholdError::PsktError { .. } => ErrorCode::Pskt,
            ThresholdError::TransportError { .. } => ErrorCode::Transport,
        }
    }
}
```

---

### 5. Migrate Top Error Sources

After adding error variants, migrate the top offenders:

#### 5a. Storage Errors (`rocks/engine.rs` - 45 occurrences)

**Current:**
```rust
self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
self.db.put_cf(cf, key, value).map_err(|err| ThresholdError::StorageError {
    operation: "put_cf".into(),
    source: err.to_string(),
})?;
```

#### 5b. PSKT Errors (`pskt/multisig.rs` - 16 occurrences)

**Current:**
```rust
.map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
.map_err(|err| ThresholdError::PsktError {
    operation: "build_input".into(),
    source: err.to_string(),
})?;
```

#### 5c. Serialization Errors (multiple files)

**Current:**
```rust
serde_json::to_vec(inner).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
serde_json::to_vec(inner).map_err(|err| ThresholdError::SerializationError {
    format: "json".into(),
    source: err.to_string(),
})?;
```

---

## P2: Medium Priority (Fix Next Sprint)

### 6. Add Context to Generic Error Messages

These error messages need more context for debugging:

| File | Line | Current Message | Add Context |
|------|------|-----------------|-------------|
| `crdt/event_state.rs` | 143 | `"missing event_id"` | Include `tx_template_hash` |
| `crdt/event_state.rs` | 146 | `"missing tx_template_hash"` | Include `event_id` |
| `pskt/fee.rs` | 13 | `"fee split parts must not both be zero"` | Include split values |
| `pskt/fee.rs` | 29 | `"missing recipient output"` | Include output count |
| `event_processor.rs` | 217 | `"signing_event missing destination_address or amount"` | Include `event_id` |
| `filtering.rs` | 65 | `"payload hash mismatch"` | Include expected/actual hashes |
| `filtering.rs` | 74 | `"invalid signature"` | Include `peer_id` |
| `messages.rs` | 120 | `"missing signer_peer_id in CRDT signature"` | Include `input_index` |
| `subscription.rs` | 69 | `"iroh gossip stream lagged"` | Include `group_id` |
| `retry/mod.rs` | 35 | `"retry exhausted"` | Include attempt count |

**Example fix for `event_state.rs:143`:**

```rust
// Current
if self.event_id == [0u8; 32] {
    return Err(ThresholdError::Message("missing event_id".to_string()));
}

// Fixed
if self.event_id == [0u8; 32] {
    return Err(ThresholdError::Message(format!(
        "missing event_id in CRDT, tx_template_hash={}",
        hex::encode(self.tx_template_hash)
    )));
}
```

---

### 7. Add Missing Log Context

**File:** `igra-service/src/service/coordination/crdt_handler.rs`

#### Line 205:
```rust
// Current
debug!("state sync response received state_count={}", response.states.len());

// Fixed
debug!(
    "state sync response received state_count={} event_ids={}",
    response.states.len(),
    response.states.iter()
        .take(3)
        .map(|(eid, _, _)| hex::encode(eid))
        .collect::<Vec<_>>()
        .join(",")
);
```

#### Line 265:
```rust
// Current
debug!("anti-entropy state sync request failed error={}", err);

// Fixed
debug!(
    "anti-entropy state sync request failed error={} pending_count={}",
    err,
    pending.len()
);
```

---

## P3: Low Priority (Backlog)

### 8. Consider Splitting Storage Trait

**File:** `igra-core/src/infrastructure/storage/traits.rs`

The `Storage` trait has 23 methods. Consider splitting into focused traits:

```rust
// Group-related operations
pub trait GroupStorage: Send + Sync {
    fn upsert_group_config(&self, group_id: Hash32, config: GroupConfig) -> Result<()>;
    fn get_group_config(&self, group_id: &Hash32) -> Result<Option<GroupConfig>>;
}

// Event-related operations
pub trait EventStorage: Send + Sync {
    fn insert_event(&self, event_id: Hash32, event: StoredEvent) -> Result<()>;
    fn get_event(&self, event_id: &Hash32) -> Result<Option<StoredEvent>>;
    fn insert_event_if_not_exists(&self, event_id: Hash32, event: StoredEvent) -> Result<bool>;
}

// CRDT-related operations
pub trait CrdtStorage: Send + Sync {
    fn get_event_crdt(&self, event_id: &Hash32, tx_template_hash: &Hash32) -> Result<Option<StoredEventCrdt>>;
    fn merge_event_crdt(&self, ...) -> Result<(StoredEventCrdt, bool)>;
    fn add_signature_to_crdt(&self, ...) -> Result<(StoredEventCrdt, bool)>;
    fn mark_crdt_completed(&self, ...) -> Result<(StoredEventCrdt, bool)>;
    fn crdt_has_threshold(&self, ...) -> Result<bool>;
    fn list_pending_event_crdts(&self) -> Result<Vec<StoredEventCrdt>>;
    fn list_event_crdts_for_event(&self, event_id: &Hash32) -> Result<Vec<StoredEventCrdt>>;
}

// Message deduplication
pub trait SeenStorage: Send + Sync {
    fn mark_seen_message(&self, ...) -> Result<bool>;
    fn cleanup_seen_messages(&self, older_than_nanos: u64) -> Result<usize>;
}

// Compose for full storage
pub trait Storage: GroupStorage + EventStorage + CrdtStorage + SeenStorage {
    fn get_event_active_template_hash(&self, event_id: &Hash32) -> Result<Option<Hash32>>;
    fn set_event_active_template_hash(&self, event_id: &Hash32, tx_template_hash: &Hash32) -> Result<()>;
    fn get_event_completion(&self, event_id: &Hash32) -> Result<Option<StoredCompletionRecord>>;
    fn set_event_completion(&self, event_id: &Hash32, completion: &StoredCompletionRecord) -> Result<()>;
    fn crdt_storage_stats(&self) -> Result<CrdtStorageStats>;
    fn cleanup_completed_event_crdts(&self, older_than_nanos: u64) -> Result<usize>;
    fn get_volume_since(&self, timestamp_nanos: u64) -> Result<u64>;
    fn begin_batch(&self) -> Result<Box<dyn BatchTransaction + '_>>;
    fn health_check(&self) -> Result<()>;
}
```

**Note:** This is a larger refactor. Only do if adding new storage functionality (e.g., two-phase protocol).

---

### 9. Helper Macros for Common Error Patterns

Consider adding macros to reduce boilerplate:

```rust
// In foundation/error.rs

/// Convert any error to ThresholdError::StorageError
macro_rules! storage_err {
    ($op:expr, $err:expr) => {
        ThresholdError::StorageError {
            operation: $op.into(),
            source: $err.to_string(),
        }
    };
}

/// Convert any error to ThresholdError::SerializationError
macro_rules! serde_err {
    ($fmt:expr, $err:expr) => {
        ThresholdError::SerializationError {
            format: $fmt.into(),
            source: $err.to_string(),
        }
    };
}

// Usage:
self.db.put_cf(cf, key, value).map_err(|e| storage_err!("put_cf", e))?;
serde_json::to_vec(data).map_err(|e| serde_err!("json", e))?;
```

---

## Checklist

### P0 (Do Now)
- [ ] Fix `encryption.rs:51` unwrap

### P1 (This Sprint)
- [ ] Add `From<&StoredEventCrdt> for EventCrdtState`
- [ ] Remove duplicate conversion in `crdt_handler.rs` (2 locations)
- [ ] Use `CrdtSignature::from` consistently
- [ ] Add structured error variants to `ThresholdError`
- [ ] Migrate storage errors in `rocks/engine.rs`
- [ ] Migrate PSKT errors in `pskt/multisig.rs`

### P2 (Next Sprint)
- [ ] Add context to 10 generic error messages
- [ ] Add log context in `crdt_handler.rs` (2 locations)

### P3 (Backlog)
- [ ] Consider splitting `Storage` trait
- [ ] Add error helper macros

---

*Generated: 2025-01-14*
*Based on: CODE-GUIDELINE.md violations scan*
