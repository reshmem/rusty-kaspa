# REFACTOR_FOR_FOOLS.md

Codebase hygiene issues found during scan. Fix these.

---

## 1. DUPLICATE TIME FUNCTIONS

`now_nanos()` is copy-pasted in **6 places**:

| File | Line |
|------|------|
| `infrastructure/audit/mod.rs` | 86 |
| `infrastructure/storage/rocks/engine.rs` | 188 |
| `infrastructure/storage/memory.rs` | 413 |
| `infrastructure/transport/iroh/client.rs` | 109 |
| `infrastructure/transport/iroh/mock.rs` | 65 |
| `infrastructure/transport/iroh/filtering.rs` | 94 (inline) |

`day_start_nanos()` is duplicated in **3 places**:

| File | Line |
|------|------|
| `foundation/util/time.rs` | 14 |
| `infrastructure/storage/rocks/engine.rs` | 210 |
| `infrastructure/storage/memory.rs` | 420 |

**Fix:** Use `crate::foundation::util::time::*` everywhere. Delete duplicates.

---

## 2. DUPLICATE CONSTANTS

`NANOS_PER_DAY` defined **3 times**:

```
foundation/constants.rs:9       - pub const NANOS_PER_DAY
foundation/util/time.rs:15      - const NANOS_PER_DAY (local)
infrastructure/storage/memory.rs:421 - const NANOS_PER_DAY (local)
```

**Fix:** Use `crate::foundation::constants::NANOS_PER_DAY` everywhere.

---

## 3. TIME UTILITIES NOT EXPORTED FROM FOUNDATION

`foundation/mod.rs` does NOT re-export `util::time`:

```rust
// Current:
pub mod util;

// Missing:
pub use util::time::*;
```

**Fix:** Add `pub use util::time::{current_timestamp_nanos_env, day_start_nanos};` to `foundation/mod.rs`.

Or create a simple `now_nanos()` wrapper in foundation that calls `current_timestamp_nanos_env(None)`.

---

## 4. MAGIC NUMBERS IN CODE

### grpc.rs:30
```rust
Some(500_000)  // What is this? Max message size? Timeout?
```

### circuit_breaker.rs:157
```rust
Duration::from_secs(1)  // Magic base duration
```

### rate_limiter.rs:153
```rust
Duration::from_secs(15 * 60)  // Magic 15 minute max age
```

### rate_limiter.rs:204 (test)
```rust
thread::sleep(Duration::from_millis(150));  // Magic sleep
```

### filtering.rs:12-13
```rust
const SEEN_MESSAGE_TTL_NANOS: u64 = 24 * 60 * 60 * 1_000_000_000;  // Should use NANOS_PER_DAY
const SEEN_MESSAGE_CLEANUP_INTERVAL: u64 = 500;  // 500 what? Messages? Seconds?
```

### client.rs:30
```rust
const PUBLISH_INFO_REPORT_INTERVAL_NANOS: u64 = 30 * 1_000_000_000;  // Should use NANOS_PER_SECOND
```

**Fix:** Move all to `foundation/constants.rs` with proper names and documentation.

---

## 5. SCATTERED CONFIG DEFAULTS

Defaults defined in `infrastructure/config/loader.rs` instead of `foundation/constants.rs`:

```rust
const DEFAULT_NODE_RPC_URL: &str = "grpc://127.0.0.1:16110";
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8088";
const DEFAULT_POLL_SECS: u64 = 5;
const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 60;
const DEFAULT_SESSION_EXPIRY_SECS: u64 = 600;
const DEFAULT_CRDT_GC_INTERVAL_SECS: u64 = 600;
const DEFAULT_CRDT_GC_TTL_SECS: u64 = 24 * 60 * 60;
```

**Fix:** Move network/timing defaults to `foundation/constants.rs`. Keep URLs in config loader if they're truly config-specific.

---

## 6. QUESTIONABLE FIELDS IN DATA STRUCTURES

### StoredCompletionRecord / CompletionRecord

```rust
pub struct StoredCompletionRecord {
    pub tx_id: TransactionId,
    pub submitter_peer_id: PeerId,  // <-- Why needed?
    pub timestamp_nanos: u64,       // <-- LWW tiebreaker for what?
    pub blue_score: Option<u64>,
}
```

- `submitter_peer_id`: Pure audit data, not needed for correctness
- `timestamp_nanos`: LWW tiebreaker is meaningless when `tx_id` is identical

**Decision needed:** Keep for audit or remove for simplicity?

---

## 7. INCONSISTENT RECORD TYPES

Three different "signature record" types:

```rust
// domain/model.rs:93
pub struct PartialSigRecord { ... }

// domain/model.rs:136
pub struct CrdtSignatureRecord { ... }

// domain/crdt/types.rs:23
pub struct SignatureRecord { ... }
```

**Fix:** Consolidate or clearly document why each exists.

---

## 8. CompletionRecord DUPLICATED

```rust
// domain/model.rs:145
pub struct StoredCompletionRecord { ... }

// infrastructure/transport/iroh/messages.rs:72
pub struct CompletionRecord { ... }
```

Nearly identical. One uses `TransactionId`, other uses `Hash32`.

**Fix:** Use one type or create clear conversion.

---

## 9. UNWRAP IN PRODUCTION CODE

Non-test `unwrap()` calls that should be handled:

| File | Line | Issue |
|------|------|-------|
| `infrastructure/logging/mod.rs` | 71, 78, 89, 96, 130 | Logger setup |
| `infrastructure/config/encryption.rs` | 55 | `decrypted.unwrap()` |
| `infrastructure/audit/mod.rs` | 14, 35 | JSON serialization |

**Fix:** Use `expect()` with message or proper error handling.

---

## 10. MISSING FOUNDATION EXPORTS

`foundation/mod.rs` exports:
- `constants::*`
- `error::*`
- `hd::*`
- `types::*`

Missing:
- `util::time::*`
- `util::encoding::*`

---

## REFACTOR CHECKLIST

### Phase 1: Time Functions
- [ ] Add `now_nanos()` to `foundation/util/time.rs`
- [ ] Export time functions from `foundation/mod.rs`
- [ ] Delete all duplicate `now_nanos()` functions (6 files)
- [ ] Delete all duplicate `day_start_nanos()` functions (2 files)
- [ ] Delete local `NANOS_PER_DAY` constants (2 files)

### Phase 2: Constants
- [ ] Move magic numbers to `foundation/constants.rs`
- [ ] Use `NANOS_PER_SECOND` / `NANOS_PER_DAY` instead of inline math
- [ ] Document all constants with units and purpose

### Phase 3: Type Consolidation
- [ ] Decide on signature record types
- [ ] Decide on completion record types
- [ ] Decide on `submitter_peer_id` / `timestamp_nanos` in completion

### Phase 4: Error Handling
- [ ] Replace `unwrap()` with `expect()` or proper handling
- [ ] Add context to all `expect()` calls

---

*Generated: 2025-01-13*
