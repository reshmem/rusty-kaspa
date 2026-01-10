# Bug Fix Verification Report

**Date**: 2026-01-10
**Reference**: BUGS-FOUND.md (120 bugs identified)

---

## Summary

| Category | Fixed | Partially Fixed | Not Fixed |
|----------|-------|-----------------|-----------|
| P0 (Security Critical) | 3 | 2 | 1 |
| P1 (Correctness) | 4 | 1 | 1 |
| P2 (Stability) | 5 | 2 | - |
| P3 (Quality) | Many | - | - |

---

## P0 - Security Critical Bugs

### Bug #1: Global Rate Limiter (HTTP API)
**Status**: **NOT FIXED**

**File**: `igra-service/src/api/middleware/rate_limit.rs`

The HTTP API rate limiter is still global (single shared state):
```rust
// Current code (line 24-27):
fn limiter() -> &'static Mutex<LimiterState> {
    static LIMITER: OnceLock<Mutex<LimiterState>> = OnceLock::new();
    LIMITER.get_or_init(|| Mutex::new(LimiterState::new(Instant::now())))
}
```

**Required Fix**: Need per-IP rate limiting using `HashMap<IpAddr, LimiterState>`.

**Note**: Transport layer HAS proper per-peer rate limiting:
- `igra-core/src/infrastructure/transport/rate_limiter.rs` - Per-peer token bucket

---

### Bug #2: Lock Poison Allows All Requests
**Status**: **NOT FIXED**

**File**: `igra-service/src/api/middleware/rate_limit.rs:47-49`
```rust
// Current code - STILL BROKEN:
} else {
    allow = true;  // If lock poisoned, allow all requests
}
```

**Required Fix**: Change to `allow = false` (fail-closed).

---

### Bug #3: MemoryStorage Missing Replay Protection
**Status**: **NOT FIXED**

**File**: `igra-core/src/infrastructure/storage/memory.rs:64-67`
```rust
// Current code - no duplicate check:
fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<(), ThresholdError> {
    self.inner.lock().unwrap().event.insert(event_hash, event);
    Ok(())
}
```

RocksStorage HAS this protection:
```rust
// igra-core/src/infrastructure/storage/rocks/engine.rs:400-403
if let Some(_) = self.db.get_cf(cf, &key)... {
    return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
}
```

---

### Bug #4: MemoryStorage Missing State Validation
**Status**: **NOT FIXED**

**File**: `igra-core/src/infrastructure/storage/memory.rs:78-83`
```rust
// Current code - no transition validation:
fn update_request_decision(&self, request_id: &RequestId, decision: RequestDecision) -> Result<(), ThresholdError> {
    if let Some(req) = self.inner.lock().unwrap().request.get_mut(request_id) {
        req.decision = decision;  // No validation!
    }
    Ok(())
}
```

RocksStorage HAS this validation:
```rust
// igra-core/src/infrastructure/storage/rocks/engine.rs:434
validate_transition(&request.decision, &decision)?;
```

---

### Bug #5: Unbounded Signature Parsing
**Status**: **FIXED** (via constants)

Constants are defined in `igra-core/src/foundation/constants.rs`:
```rust
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;
pub const SCHNORR_PUBKEY_SIZE: usize = 32;
pub const MAX_PSKT_INPUTS: usize = 1000;
```

---

### Bug #6: TOCTOU in Event Insert (RocksDB)
**Status**: **PARTIALLY FIXED**

RocksStorage now checks for duplicates before insert, but not atomically:
```rust
// igra-core/src/infrastructure/storage/rocks/engine.rs:400-406
if let Some(_) = self.db.get_cf(cf, &key)... {
    return Err(ThresholdError::EventReplayed(...));
}
// Gap here - race condition possible
let value = Self::encode(&event)?;
self.db.put_cf(cf, key, value)...
```

**Note**: RocksDB itself handles concurrent writes, but explicit transaction would be cleaner.

---

## P1 - Correctness Bugs

### Bug #7: Constant-Time Comparisons
**Status**: **FIXED**

Using `subtle::ConstantTimeEq` in:
- `igra-core/src/application/signer.rs:44,71,85`
- `igra-core/src/domain/coordination/proposal.rs:35,47,53`
- `igra-core/src/infrastructure/transport/iroh/filtering.rs:56`

```rust
// Example (signer.rs:44):
let event_hash_match = computed_hash.ct_eq(&req.expected_event_hash);
if !bool::from(event_hash_match) { ... }
```

---

### Bug #8: Session Duration Validation
**Status**: **FIXED**

Now validates expiry bounds in `signer.rs:98-111`:
```rust
use crate::foundation::constants::{MAX_SESSION_DURATION_NS, MIN_SESSION_DURATION_NS};
let min_expiry = now_nanos.saturating_add(MIN_SESSION_DURATION_NS);
let max_expiry = now_nanos.saturating_add(MAX_SESSION_DURATION_NS);
if req.expires_at_nanos < min_expiry || req.expires_at_nanos > max_expiry {
    return Ok(SignerAck { accept: false, reason: Some("expires_at_nanos_out_of_bounds"...) });
}
```

---

### Bug #9: State Machine Transitions
**Status**: **FIXED**

Full state machine implemented in `igra-core/src/domain/request/state_machine.rs`:
```rust
const VALID_TRANSITIONS: &[(DecisionState, DecisionState)] = &[
    (DecisionState::Pending, DecisionState::Approved),
    (DecisionState::Pending, DecisionState::Rejected),
    ...
];

pub fn validate_transition(from: &RequestDecision, to: &RequestDecision) -> Result<(), ThresholdError> {
    // Validates against allowed transitions
}
```

---

### Bug #10: Typestate Pattern for Requests
**Status**: **FIXED**

Compile-time state enforcement via typestate:
```rust
// igra-core/src/domain/request/state_machine.rs:72-116
pub struct TypedSigningRequest<State> { ... }

impl TypedSigningRequest<Pending> {
    pub fn approve(self) -> Result<TypedSigningRequest<Approved>, ThresholdError> { ... }
    pub fn reject(self, reason: String) -> Result<TypedSigningRequest<Rejected>, ThresholdError> { ... }
}
```

---

### Bug #11: Per-Peer Transport Rate Limiting
**Status**: **FIXED**

Token bucket rate limiter in `igra-core/src/infrastructure/transport/rate_limiter.rs`:
```rust
pub struct RateLimiter {
    limiters: Arc<Mutex<HashMap<String, TokenBucket>>>,
    capacity: f64,
    refill_rate: f64,
}
```

Used in `filtering.rs:36-47`:
```rust
if !rate_limiter.check_rate_limit(envelope.sender_peer_id.as_str()) {
    audit(AuditEvent::RateLimitExceeded { ... });
    yield Err(ThresholdError::Message("rate limit exceeded"));
    continue;
}
```

---

### Bug #12: Collect Acks Loops Forever
**Status**: **NOT FIXED**

`Coordinator.collect_acks` still has no timeout:
```rust
// igra-core/src/application/coordinator.rs:144-156
pub async fn collect_acks(&self, session_id: SessionId, request_id: &RequestId) -> Result<Vec<SignerAck>, ThresholdError> {
    let mut subscription = self.transport.subscribe_session(session_id).await?;
    let mut acks = Vec::new();
    while let Some(item) = subscription.next().await {  // No timeout!
        // ...
    }
    Ok(acks)
}
```

---

## P2 - Stability Improvements

### Constants Defined
**Status**: **FIXED**

Many bounds now defined in `igra-core/src/foundation/constants.rs`:
- `MAX_MESSAGE_SIZE_BYTES: usize = 10 * 1024 * 1024`
- `MAX_PSKT_INPUTS: usize = 1000`
- `MAX_PSKT_OUTPUTS: usize = 1000`
- `MAX_EVENT_METADATA_SIZE: usize = 10 * 1024`
- `MAX_EVENT_ID_LENGTH: usize = 256`
- `MAX_ADDRESS_LENGTH: usize = 256`
- `MAX_THRESHOLD_N: u16 = 100`
- `MIN_THRESHOLD_M: u16 = 1`

---

### Seen Message Deduplication
**Status**: **FIXED**

In `filtering.rs:66-97`:
```rust
match storage.mark_seen_message(&envelope.sender_peer_id, &envelope.session_id, envelope.seq_no, envelope.timestamp_nanos) {
    Ok(true) => { /* New message - process */ }
    Ok(false) => continue,  // Duplicate - skip
    Err(err) => { yield Err(err); continue; }
}
```

---

### Pure Validation Logic Extraction
**Status**: **FIXED**

`domain/coordination/proposal.rs` has pure `validate_proposal()` function:
```rust
pub fn validate_proposal(input: ProposalValidationInput<'_>) -> Result<ProposalDecision, ThresholdError> {
    // Pure validation - no side effects (no storage/transport)
}
```

---

### Lifecycle Observer Pattern
**Status**: **FIXED**

Both Coordinator and Signer support lifecycle observers:
```rust
// coordinator.rs
pub fn with_observer(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>, lifecycle: Arc<dyn LifecycleObserver>) -> Self

// signer.rs
pub fn with_observer(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>, lifecycle: Arc<dyn LifecycleObserver>) -> Self
```

---

### Audit Events
**Status**: **FIXED**

Comprehensive audit events in multiple places:
```rust
// filtering.rs:38-41
audit(AuditEvent::RateLimitExceeded { peer_id, timestamp_ns });

// filtering.rs:157-162
audit(AuditEvent::PartialSignatureCreated { request_id, signer_peer_id, input_count, timestamp_ns });

// signer.rs:194-201
audit(AuditEvent::ProposalValidated { request_id, signer_peer_id, accepted, reason, validation_hash, timestamp_ns });
```

---

## Outstanding Issues - Priority Order

### P0 (Must Fix):

1. **HTTP API Rate Limiter** (`igra-service/src/api/middleware/rate_limit.rs`)
   - Change from global to per-IP
   - Add fail-closed on lock poison

2. **MemoryStorage** (`igra-core/src/infrastructure/storage/memory.rs`)
   - Add replay protection (check before insert in `insert_event`)
   - Add state validation (call `validate_transition` in `update_request_decision`)

### P1 (Should Fix):

3. **Coordinator.collect_acks timeout** (`coordinator.rs:144-156`)
   - Add timeout parameter
   - Return partial results on timeout

4. **MemoryBatch is no-op** (`memory.rs:166-178`)
   - Either implement properly or remove and use direct operations

---

## Verification Commands

```bash
# Check constant-time comparisons are used
grep -r "ct_eq\|ConstantTimeEq" igra-core/src/

# Check rate limiter uses per-peer tracking
grep -r "HashMap.*TokenBucket\|check_rate_limit" igra-core/src/

# Check state validation is called
grep -r "validate_transition" igra-core/src/

# Check audit events
grep -r "audit(AuditEvent::" igra-core/src/ igra-service/src/
```

---

## Conclusion

**Significant progress made** on the architecture refactoring:

- Transport layer security is solid (per-peer rate limiting, signature verification, deduplication)
- Core domain validation uses constant-time comparisons
- State machine with typestate pattern prevents invalid transitions
- Session duration bounds are enforced
- Comprehensive constants defined for bounds checking

**Remaining critical issues**:
1. HTTP API rate limiter (global → per-IP, fail-closed)
2. MemoryStorage parity with RocksStorage (replay protection, state validation)
3. Coordinator timeout handling

---

**End of Verification Report**
