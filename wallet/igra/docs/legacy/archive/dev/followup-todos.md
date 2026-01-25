# FOLLOWUP-TODO-FIXES.md

Follow-up technical debt from remaining `ThresholdError::Message` occurrences. Organized by priority.

---

## Summary

| Priority | Category | Count | Effort |
|----------|----------|-------|--------|
| **P1** | Hot path errors | 7 | 30 min |
| **P2** | Infrastructure errors | 18 | 1 hr |
| **P3** | Startup/CLI errors | 31 | 1 hr |
| **Skip** | Tests/CLI binaries | 34+ | N/A |

---

## P1: High Priority (Hot Path Errors)

These errors occur during runtime signing/coordination and need structured variants for debugging.

### 1. CRDT Handler Missing State Errors

**File:** `igra-service/src/service/coordination/crdt_handler.rs`

#### Lines 99, 382: Missing CRDT state

**Current:**
```rust
.ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;
```

**Fix:**
```rust
.ok_or_else(|| ThresholdError::KeyNotFound(format!(
    "CRDT state event_id={} tx_template_hash={}",
    hex::encode(event_id),
    hex::encode(tx_template_hash)
)))?;
```

#### Line 446: Policy rejection

**Current:**
```rust
return Err(ThresholdError::Message("policy rejected signing event".to_string()));
```

**Fix:** Add new error variant or use existing with context:
```rust
return Err(ThresholdError::Message(format!(
    "policy rejected signing event event_id={} reason={}",
    hex::encode(event.event.external_id),
    result.failed_check.map(|c| format!("{:?}", c)).unwrap_or_default()
)));
```

#### Line 479: Missing kpsbt_blob

**Current:**
```rust
return Err(ThresholdError::Message("missing kpsbt_blob".to_string()));
```

**Fix:**
```rust
return Err(ThresholdError::PsktError {
    operation: "attempt_submission".into(),
    details: format!("missing kpsbt_blob event_id={}", hex::encode(state.event_id)),
});
```

---

### 2. Event Processor Context Errors

**File:** `igra-core/src/application/event_processor.rs`

#### Line 217: Missing destination/amount

**Current:**
```rust
return Err(ThresholdError::Message(format!(
    "signing_event missing destination_address or amount destination={:?} amount={:?}",
    event.destination_address, event.amount_sompi
)));
```

**Fix:** Already has context, but should include event_id:
```rust
return Err(ThresholdError::ConfigError(format!(
    "signing_event missing destination_address or amount event_id={} destination={:?} amount={:?}",
    hex::encode(compute_event_id(&event)),
    event.destination_address,
    event.amount_sompi
)));
```

#### Line 230: Missing HD config

**Current:**
```rust
let hd = config.hd.as_ref().ok_or_else(|| ThresholdError::Message("missing redeem script or HD config".to_string()))?;
```

**Fix:**
```rust
let hd = config.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError(
    "missing redeem script or HD config for PSKT building".to_string()
))?;
```

#### Line 293: Missing CRDT after signing

**Current:**
```rust
.ok_or_else(|| ThresholdError::Message("missing CRDT state after signing".to_string()))?;
```

**Fix:**
```rust
.ok_or_else(|| ThresholdError::KeyNotFound(format!(
    "CRDT state after signing event_id={} tx_template_hash={}",
    hex::encode(event_id),
    hex::encode(tx_template_hash)
)))?;
```

---

## P2: Medium Priority (Infrastructure Errors)

### 3. HD/Crypto Key Derivation

**File:** `igra-core/src/foundation/hd.rs`

#### Line 32: SecretKey parsing

**Current:**
```rust
let secret = SecretKey::from_slice(&self.secret_bytes).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
let secret = SecretKey::from_slice(&self.secret_bytes).map_err(|err| ThresholdError::CryptoError {
    operation: "secret_key_from_slice".into(),
    details: err.to_string(),
})?;
```

#### Lines 62, 92: xprv derivation

**Current:**
```rust
let xprv = key_data.get_xprv(inputs.payment_secret).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
let xprv = key_data.get_xprv(inputs.payment_secret).map_err(|err| ThresholdError::CryptoError {
    operation: "get_xprv".into(),
    details: err.to_string(),
})?;
```

#### Line 71: xpub parsing

**Current:**
```rust
let xpub = ExtendedPublicKey::<PublicKey>::from_str(xpub).map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
let xpub = ExtendedPublicKey::<PublicKey>::from_str(xpub).map_err(|err| ThresholdError::CryptoError {
    operation: "parse_xpub".into(),
    details: err.to_string(),
})?;
```

#### Line 112: Redeem script

**Current:**
```rust
multisig_redeem_script(xonly_keys.iter(), required_sigs).map_err(|err| ThresholdError::Message(err.to_string()))
```

**Fix:**
```rust
multisig_redeem_script(xonly_keys.iter(), required_sigs).map_err(|err| ThresholdError::CryptoError {
    operation: "build_redeem_script".into(),
    details: err.to_string(),
})
```

---

### 4. Transport Filtering (Security-Relevant)

**File:** `igra-core/src/infrastructure/transport/iroh/filtering.rs`

#### Line 43: Decode error

**Current:**
```rust
yield Err(ThresholdError::Message(format!(
    "failed to decode gossip message: {}",
    err
)));
```

**Fix:**
```rust
yield Err(ThresholdError::TransportError {
    operation: "decode_gossip".into(),
    details: err.to_string(),
});
```

#### Line 65: Payload hash mismatch

**Current:**
```rust
yield Err(ThresholdError::Message(format!(
    "payload hash mismatch: expected={} actual={}",
    hex::encode(envelope.payload_hash),
    hex::encode(computed_hash)
)));
```

**Fix:**
```rust
yield Err(ThresholdError::TransportError {
    operation: "verify_payload_hash".into(),
    details: format!(
        "mismatch expected={} actual={} sender={}",
        hex::encode(envelope.payload_hash),
        hex::encode(computed_hash),
        envelope.sender_peer_id
    ),
});
```

#### Line 79: Invalid signature

**Current:**
```rust
yield Err(ThresholdError::Message(format!(
    "invalid envelope signature from peer={}",
    envelope.sender_peer_id
)));
```

**Fix:**
```rust
yield Err(ThresholdError::SignatureVerificationFailed);
// Or with context:
yield Err(ThresholdError::TransportError {
    operation: "verify_envelope_signature".into(),
    details: format!("peer={}", envelope.sender_peer_id),
});
```

---

### 5. gRPC/Network Errors

**File:** `igra-core/src/infrastructure/rpc/grpc.rs`

#### Lines 43, 134, 149: Tonic errors

**Current:**
```rust
.map_err(|err| ThresholdError::Message(err.to_string()))?
```

**Fix:**
```rust
.map_err(|err| ThresholdError::NetworkError(format!("grpc: {}", err)))?
```

#### Line 84: Connection error

**Current:**
```rust
return Err(ThresholdError::Message(err.to_string()));
```

**Fix:**
```rust
return Err(ThresholdError::NetworkError(format!("grpc connect: {}", err)));
```

---

### 6. Retry Exhaustion

**File:** `igra-core/src/infrastructure/rpc/retry/mod.rs`

#### Line 36

**Current:**
```rust
ThresholdError::Message(format!("retry exhausted after {} attempts", initial_attempts))
```

**Fix:**
```rust
ThresholdError::NetworkError(format!(
    "retry exhausted after {} attempts, last_error={}",
    initial_attempts,
    last_error.as_ref().map(|e| e.to_string()).unwrap_or_default()
))
```

---

### 7. PSKT Builder/Fee Errors

**File:** `igra-core/src/domain/pskt/builder.rs`

#### Line 210: Script builder

**Current:**
```rust
let redeem_push = ScriptBuilder::new().add_data(redeem_script).map_err(|err| ThresholdError::Message(err.to_string()))?.drain();
```

**Fix:**
```rust
let redeem_push = ScriptBuilder::new()
    .add_data(redeem_script)
    .map_err(|err| ThresholdError::PsktError {
        operation: "build_redeem_push".into(),
        details: err.to_string(),
    })?
    .drain();
```

#### Lines 315, 319: Fee split validation

**Current:**
```rust
return Err(ThresholdError::Message("fee split parts must not both be zero".to_string()));
```

**Fix:**
```rust
return Err(ThresholdError::PsktError {
    operation: "calculate_fee_split".into(),
    details: format!("parts must not both be zero: bridge={} recipient={}", bridge_parts, recipient_parts),
});
```

**File:** `igra-core/src/domain/pskt/fee.rs`

#### Lines 13, 21, 34, 50

**Current:**
```rust
return Err(ThresholdError::Message(format!(
    "fee split parts must not both be zero: bridge={} recipient={}",
    self.bridge_parts, self.recipient_parts
)));
```

**Fix:**
```rust
return Err(ThresholdError::PsktError {
    operation: "fee_split_validate".into(),
    details: format!(
        "parts must not both be zero: bridge={} recipient={}",
        self.bridge_parts, self.recipient_parts
    ),
});
```

---

### 8. Transport Client/Subscription

**File:** `igra-core/src/infrastructure/transport/iroh/client.rs`

#### Line 220: Gossip publish failure

**Current:**
```rust
Err(ThresholdError::Message(last_err.unwrap_or_else(|| "failed to publish gossip message".to_string())))
```

**Fix:**
```rust
Err(ThresholdError::TransportError {
    operation: "publish_gossip".into(),
    details: last_err.unwrap_or_else(|| "unknown error".to_string()),
})
```

#### Line 300: Subscribe failure

**Current:**
```rust
self.gossip.subscribe(topic_id, self.bootstrap.clone()).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
self.gossip.subscribe(topic_id, self.bootstrap.clone()).await.map_err(|err| ThresholdError::TransportError {
    operation: "gossip_subscribe".into(),
    details: err.to_string(),
})?;
```

**File:** `igra-core/src/infrastructure/transport/iroh/subscription.rs`

#### Lines 36, 49, 70

**Fix:** Use `ThresholdError::TransportError` with operation context.

**File:** `igra-core/src/infrastructure/transport/iroh/encoding.rs`

#### Lines 14, 32, 39: Postcard serialization

**Current:**
```rust
.map_err(|err| ThresholdError::Message(err.to_string()))?;
```

**Fix:**
```rust
.map_err(|err| ThresholdError::SerializationError {
    format: "postcard".into(),
    details: err.to_string(),
})?;
```

---

## P3: Low Priority (Startup/Config Errors)

### 9. Metrics Registration

**File:** `igra-service/src/service/metrics.rs`

24 occurrences of Prometheus registry errors. These only happen at startup.

**Option A:** Leave as-is (acceptable for startup-only code).

**Option B:** Add `MetricsError` variant:
```rust
#[error("metrics error during {operation}: {details}")]
MetricsError { operation: String, details: String },
```

---

### 10. Config Persistence

**File:** `igra-core/src/infrastructure/config/persistence.rs`

5 occurrences of RocksDB config store errors.

**Fix:** Use `ThresholdError::StorageError` consistently:
```rust
.map_err(|err| ThresholdError::StorageError {
    operation: "config_db_open".into(),
    details: err.to_string(),
})?
```

---

### 11. Storage Engine Edge Cases

**File:** `igra-core/src/infrastructure/storage/rocks/engine.rs`

#### Line 90: Checkpoint not empty

**Current:**
```rust
return Err(ThresholdError::Message(format!("checkpoint directory is not empty: {}", path.display())));
```

**Fix:**
```rust
return Err(ThresholdError::StorageError {
    operation: "create_checkpoint".into(),
    details: format!("directory not empty: {}", path.display()),
});
```

#### Line 101: Missing column family

**Current:**
```rust
self.db.cf_handle(name).ok_or_else(|| ThresholdError::Message(format!("missing column family: {}", name)))
```

**Fix:**
```rust
self.db.cf_handle(name).ok_or_else(|| ThresholdError::StorageError {
    operation: "cf_handle".into(),
    details: format!("missing column family: {}", name),
})
```

#### Lines 123, 126, 209: Corrupt data

These are data corruption errors - could add a dedicated variant:
```rust
#[error("data corruption in {location}: {details}")]
DataCorruption { location: String, details: String },
```

---

## Skip: No Changes Needed

### CLI Binaries (34+ occurrences)

Files:
- `igra-service/src/bin/kaspa-threshold-service.rs`
- `igra-service/src/bin/kaspa-threshold-service/setup.rs`
- `igra-service/src/bin/kaspa-threshold-service/modes/finalize.rs`
- `igra-service/src/bin/kaspa-threshold-service/modes/audit.rs`
- `igra-core/src/bin/devnet-keygen.rs`

**Rationale:** CLI tools print errors and exit. Structured errors provide no benefit.

### Test Files (4 occurrences)

Files:
- `igra-service/tests/integration/crdt_e2e.rs`
- `igra-service/tests/integration/crdt_partition.rs`
- `igra-core/tests/unit/domain_event.rs`

**Rationale:** Test assertions don't need structured errors.

### Mock Transport (2 occurrences)

File: `igra-core/src/infrastructure/transport/iroh/mock.rs`

**Rationale:** Test-only mock implementation.

---

## Checklist

### P1 (This Sprint)
- [ ] `crdt_handler.rs:99,382` - Use `KeyNotFound` with context
- [ ] `crdt_handler.rs:446` - Add event_id to policy rejection
- [ ] `crdt_handler.rs:479` - Use `PsktError`
- [ ] `event_processor.rs:217,230,293` - Add context / use appropriate variant

### P2 (Next Sprint)
- [ ] `hd.rs` - Migrate 5 occurrences to `CryptoError`
- [ ] `filtering.rs` - Migrate 3 occurrences to `TransportError`
- [ ] `grpc.rs` - Migrate 4 occurrences to `NetworkError`
- [ ] `retry/mod.rs` - Add last_error context
- [ ] `pskt/builder.rs`, `fee.rs` - Migrate 6 occurrences to `PsktError`
- [ ] `client.rs`, `subscription.rs` - Migrate to `TransportError`
- [ ] `encoding.rs` - Migrate to `SerializationError { format: "postcard" }`

### P3 (Backlog)
- [ ] `metrics.rs` - Consider `MetricsError` variant (optional)
- [ ] `persistence.rs` - Use `StorageError` consistently
- [ ] `engine.rs` edge cases - Use `StorageError` or `DataCorruption`

---

*Generated: 2025-01-14*
*Based on: ThresholdError::Message scan excluding docs/legacy/*
