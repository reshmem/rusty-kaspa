# Refactor Plan: Remove `hex::encode(...)` from Logs

We currently call `hex::encode(...)` in many places (≈256 matches across `igra-core/src` + `igra-service/src`). This creates noisy log code and allocates new `String`s for every log line.

Goal: make log formatting clean and consistent by using Rust formatting traits (`{:x}`, `{:#x}`, `{}`) instead of explicit `hex::encode(...)` calls.

---

## 1. Constraints (why `{:#x}` doesn’t work today for `Hash32`)

In `igra-core/src/foundation/types.rs`, `Hash32` is a type alias:

```rust
pub type Hash32 = [u8; 32];
```

Because it is an alias to a foreign type (`[u8; 32]`), we cannot implement `LowerHex`/`Display` for it directly (Rust orphan rules).

So we have two approaches:

1) **Low-risk (recommended)**: add formatting wrappers and use them in logs (no storage/wire changes).
2) **High-churn**: change `Hash32` into a newtype `struct Hash32([u8; 32]);` (large refactor, potential serialization/storage impact).

This plan implements (1) first; (2) can remain optional later.

---

## 2. Target log style (standard)

This refactor keeps the existing log style by default:

- `Display` prints **lowercase hex without `0x`** (drop-in replacement for `hex::encode(...)` in logs).
- `{:#x}` is still supported via `LowerHex` if/when we want to migrate logs to `0x`-prefixed identifiers.

Example target log line:

```
proposal committed event_id=0x… round=2 canonical_hash=0x…
```

---

## 3. What we add (new formatting utilities)

### 3.1 New module: zero-allocation hex formatting wrappers

Add a new module in `igra-core`:

- `igra-core/src/foundation/util/hex_fmt.rs`

Provide wrapper types that implement formatting traits:

- `HexBytes<'a>(&'a [u8])`
- `Hex32<'a>(&'a [u8; 32])`

Trait behavior:

- `impl LowerHex`:
  - `{:x}` → hex without prefix
  - `{:#x}` → hex with `0x` prefix
- `impl Display`:
  - prints lowercase hex **without** `0x` (matches existing logs)

### 3.2 Re-exports for ergonomic use

Expose helper constructors in `igra-core`:

 - `pub fn hx(bytes: &[u8]) -> HexBytes<'_>`
 - `pub fn hx32(bytes: &Hash32) -> Hex32<'_>`

and re-export them at the foundation level:

- `igra-core/src/foundation/mod.rs`:
  - re-exports `hx`, `hx32`, `HexBytes`, `Hex32`

### 3.3 Usage examples (how logs will look)

Before:

```rust
info!("received CRDT broadcast event_id={}", hex::encode(event_id));
```

After (wrappers, no allocations; same log output as `hex::encode`):

```rust
info!("received CRDT broadcast event_id={}", hx32(event_id));
```

If you want `0x`-prefixed hex:

```rust
info!("received CRDT broadcast event_id={:#x}", hx32(event_id));
```

For variable-length bytes:

```rust
debug!("message body={:#x}", hx(&body_bytes));
```

---

## 4. What we change (mechanical refactor)

### 4.1 Scope (v1)

Only refactor:

- `info!`, `warn!`, `debug!`, `error!`, `trace!` calls
- structured audit summaries (human logs) where they call `short_id()` or embed hex ids

Do **not** refactor in v1:

- serialization formats (JSON fields that intentionally use `hex::encode`)
- storage key encoding
- RPC responses that are explicitly `"0x..."` strings
- error variants that store `String` ids (unless we explicitly redesign them)

### 4.2 High-impact files (largest `hex::encode` counts)

These are the first refactor targets because they dominate log noise:

**igra-service**

- `igra-service/src/service/coordination/crdt_handler.rs` (≈43)
- `igra-service/src/service/coordination/two_phase_handler.rs` (≈28)
- `igra-service/src/service/coordination/two_phase_timeout.rs` (≈9)
- `igra-service/src/api/handlers/hyperlane.rs` (≈9)
- `igra-service/src/api/handlers/chain.rs` (≈8)

**igra-core**

- `igra-core/src/application/event_processor.rs` (≈22)
- `igra-core/src/infrastructure/storage/rocks/engine.rs` (≈20)
- `igra-core/src/application/lifecycle.rs` (≈15)
- `igra-core/src/infrastructure/transport/iroh/client.rs` (≈11)
- `igra-core/src/infrastructure/transport/iroh/filtering.rs` (≈9)
- `igra-core/src/infrastructure/storage/memory.rs` (≈8)

### 4.3 Mechanical replacement rules

Replace patterns like:

- `hex::encode(event_id)` where `event_id: &Hash32` or `Hash32`
  - → `hx32(event_id)` (use `{:#x}` in format string)

Replace patterns like:

- `format!("0x{}", hex::encode(bytes))`
  - → format with `{:#x}` using wrappers:
    - `format!("{:#x}", hx(bytes))`

Replace “list of hashes” joins (if currently `map(hex::encode)`):

- `iter.map(hex::encode).join(",")`
  - → `iter.map(|h| format!("{:#x}", hx32(h))).join(",")`

Note: this one still allocates because it builds a joined string; we accept this in rare error/debug paths.

---

## 5. Optional improvement: make log identifiers *typed* (semantic IDs)

Even with wrappers, we still write `hx32(event_id)` everywhere. If we want `info!("event_id={:#x}", event_id);` directly, introduce semantic newtypes:

- `EventId([u8; 32])`
- `TxTemplateHash([u8; 32])`
- `GroupId([u8; 32])`
- `MessageId([u8; 32])`

and implement `LowerHex`/`Display` for them.

This is lower churn than changing `Hash32` globally and allows direct formatting in logs while keeping storage/wire representations stable via `#[serde(transparent)]`.

This step is optional and can be done incrementally: start with the IDs we log most frequently (`event_id`, `tx_template_hash`, `message_id`).

---

## 6. Verification / guardrails

### 6.1 Tests

Add unit tests for the formatter wrappers in:

- `igra-core/src/foundation/util/hex_fmt.rs` (or a sibling `tests` module)

Minimum cases:

- `{:#x}` produces `0x` prefix
- output length is correct for 32-byte inputs (`2 + 64`)
- formatting matches `hex::encode` for known inputs

### 6.2 Grep guardrail

After refactor, we should be able to reduce `hex::encode` in log contexts significantly.

Suggested checks:

- `rg "hex::encode\\(" igra-core/src igra-service/src`
- `rg "info!\\(|warn!\\(|debug!\\(|error!\\(" -n igra-core/src igra-service/src | rg "hex::encode\\("`

---

## 7. Rollout plan (step-by-step)

1) Add wrapper module `igra-core/src/foundation/util/hex_fmt.rs` + re-exports (`hx`, `hx32`).
2) Convert the top 5 files by count (see §4.2).
3) Convert remaining log sites opportunistically.
4) (Optional) Introduce semantic ID newtypes (`EventId`, `TxTemplateHash`, `MessageId`) if we want `event_id={:#x}` without wrappers.
