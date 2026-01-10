# Dead Code Analysis Report

**Date**: 2026-01-10
**Scope**: igra-core and igra-service

---

## Summary

| Category | Count | Recommendation |
|----------|-------|----------------|
| Unused Constants | 7 | Remove |
| Unused Public Functions | 9 | Remove or Add Tests |
| Unused Stub Structs | 3 | Remove or Implement |
| Unused Modules | 1 | Remove |
| Intentionally Dead (marked) | 4 | Keep |

---

## 1. UNUSED CONSTANTS (Remove)

**File**: `igra-core/src/foundation/constants.rs`

| Constant | Line | Value | Recommendation |
|----------|------|-------|----------------|
| `MAX_PSKT_INPUTS` | 29 | 1000 | Remove - not validated anywhere |
| `MAX_PSKT_OUTPUTS` | 32 | 1000 | Remove - not validated anywhere |
| `MAX_BOOTSTRAP_PEERS` | 65 | 10 | Remove - gossip feature not implemented |
| `GOSSIP_PUBLISH_RETRIES` | 68 | 3 | Remove - gossip retry not implemented |
| `GOSSIP_RETRY_DELAY_MS` | 71 | 200 | Remove - gossip retry not implemented |
| `MAX_GOSSIP_TOPIC_LENGTH` | 74 | 256 | Remove - not validated anywhere |
| `RATE_LIMIT_CLEANUP_INTERVAL_SECS` | 83 | 300 | Remove - cleanup uses different mechanism |

**Action**: Delete these constants. If PSKT limits are needed, implement validation first.

---

## 2. UNUSED PUBLIC FUNCTIONS

### 2.1 Remove Completely (Not Useful)

| Function | File | Line | Reason |
|----------|------|------|--------|
| `decode_hex_array()` | `foundation/util/encoding.rs` | 16 | Duplicate of `decode_hex()` |
| `u8_to_usize()` | `foundation/util/conversion.rs` | 11 | Trivial - use `usize::from()` directly |

### 2.2 Remove or Implement Validation

| Function | File | Line | Recommendation |
|----------|------|------|----------------|
| `validate_inputs()` | `domain/pskt/validation.rs` | 5 | **Option A**: Add call in `build_pskt_from_utxos()` |
| `validate_outputs()` | `domain/pskt/validation.rs` | 12 | **Option A**: Add call in `build_pskt_from_utxos()` |
| `validate_params()` | `domain/pskt/validation.rs` | 19 | **Option A**: Add call in `build_pskt_from_utxos()` |
| `decode_hex_exact()` | `foundation/util/encoding.rs` | 7 | **Option B**: Remove if not needed |
| `u64_to_u32()` | `foundation/util/conversion.rs` | 3 | **Option B**: Remove if not needed |
| `usize_to_u32()` | `foundation/util/conversion.rs` | 7 | **Option B**: Remove if not needed |
| `verify_group_id()` | `domain/group_id.rs` | 33 | **Option A**: Add test coverage |

**Recommended Action**:
- Integrate validation functions into PSKT builder, OR remove the entire `validation.rs` file
- Remove conversion utilities (use inline conversions)
- Keep `verify_group_id()` - useful for testing group ID computation

---

## 3. UNUSED STUB IMPLEMENTATIONS

### 3.1 Signing Backends (Stubs)

| Struct | File | Line | Status |
|--------|------|------|--------|
| `MpcSigner` | `domain/signing/mpc.rs` | 6 | Returns "not implemented" error |
| `MuSig2Signer` | `domain/signing/musig2.rs` | 6 | Returns "not implemented" error |

**Recommendation**:
- **Option A**: Keep as placeholders if MPC/MuSig2 will be implemented
- **Option B**: Remove files entirely and add back when implementing

### 3.2 Infrastructure Stubs

| Struct | File | Line | Status |
|--------|------|------|--------|
| `CircuitBreaker` | `infrastructure/rpc/circuit_breaker.rs` | 4 | Fully implemented but never instantiated |

**Recommendation**:
- **Option A**: Integrate into `GrpcNodeRpc` for RPC resilience
- **Option B**: Remove and add back when implementing retry logic

---

## 4. ENTIRE MODULES TO CONSIDER REMOVING

### 4.1 `domain/pskt/validation.rs`
- Contains 3 functions, none used
- Either integrate into PSKT builder or remove

### 4.2 `foundation/util/conversion.rs`
- Contains 3 functions, none used
- Trivial utilities, remove entirely

### 4.3 `domain/signing/mpc.rs` and `musig2.rs`
- Stub implementations that always error
- Remove until actual implementation planned

---

## 5. INTENTIONALLY DEAD CODE (Keep)

These are marked with `#[allow(dead_code)]`:

| Item | File | Line | Purpose |
|------|------|------|---------|
| `key_partial_sig_input_prefix()` | `storage/rocks/engine.rs` | 188 | Reserved for future query pattern |
| `key_partial_sig_input()` | `storage/rocks/engine.rs` | 199 | Reserved for future query pattern |
| Test helpers in `fixtures/factories.rs` | - | - | Module-level allow for test utilities |

---

## 6. UNUSED TEST HELPERS

**File**: `igra-core/tests/fixtures/factories.rs`

| Function | Line | Status |
|----------|------|--------|
| `coordinator_peer_id()` | 47 | Not called in any test |
| `group_policy_allow_all()` | 21 | Used in some tests - **KEEP** |

**Recommendation**: Review and remove unused helpers, or add tests that use them.

---

## 7. ACTION PLAN

### Phase 1: Safe Removals (No Impact)

```bash
# Files to delete entirely:
igra-core/src/foundation/util/conversion.rs
igra-core/src/domain/signing/mpc.rs
igra-core/src/domain/signing/musig2.rs
```

Update `mod.rs` files to remove module declarations.

### Phase 2: Function Removals

```rust
// In igra-core/src/foundation/constants.rs - remove lines:
// 29: pub const MAX_PSKT_INPUTS
// 32: pub const MAX_PSKT_OUTPUTS
// 65: pub const MAX_BOOTSTRAP_PEERS
// 68: pub const GOSSIP_PUBLISH_RETRIES
// 71: pub const GOSSIP_RETRY_DELAY_MS
// 74: pub const MAX_GOSSIP_TOPIC_LENGTH
// 83: pub const RATE_LIMIT_CLEANUP_INTERVAL_SECS

// In igra-core/src/foundation/util/encoding.rs - remove:
// decode_hex_array() (line 16-18)
// decode_hex_exact() (line 7-14)

// In igra-core/src/domain/group_id.rs - KEEP verify_group_id()
```

### Phase 3: Decide on Validation

**Option A - Integrate Validation**:
```rust
// In domain/pskt/builder.rs, add at start of build_pskt_from_utxos():
validate_params(params)?;
```

**Option B - Remove Validation Module**:
```bash
rm igra-core/src/domain/pskt/validation.rs
# Update domain/pskt/mod.rs to remove "pub mod validation;"
```

### Phase 4: Circuit Breaker Decision

**Option A - Integrate**:
```rust
// In infrastructure/rpc/grpc.rs, wrap RPC calls:
pub struct GrpcNodeRpc {
    // ...
    circuit_breaker: CircuitBreaker,
}
```

**Option B - Remove**:
```bash
rm igra-core/src/infrastructure/rpc/circuit_breaker.rs
# Update infrastructure/rpc/mod.rs
```

---

## 8. VERIFICATION COMMANDS

After cleanup, verify no regressions:

```bash
# Check compilation
cargo build -p igra-core -p igra-service

# Run tests
cargo test -p igra-core -p igra-service

# Check for new dead code warnings
RUSTFLAGS="-Wdead_code" cargo check -p igra-core -p igra-service
```

---

## 9. ITEMS NOT TO REMOVE

These appear unused but are actually used:

| Item | Reason |
|------|--------|
| `NoopVerifier` | Used in 18 test files |
| `NoopSignatureVerifier` | Used in transport tests |
| `KeyBuilder` methods | Used in storage engine |
| `decode_hex()` | Used via re-export |

---

**End of Report**
