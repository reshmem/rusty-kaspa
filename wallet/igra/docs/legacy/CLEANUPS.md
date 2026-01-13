# IGRA Codebase Cleanup Plan

This document identifies code to remove, normalize, and implement.

**Related Document:** `docs/DEAD-CODE.md` - Detailed dead code analysis (NOTE: may be outdated - verify before deleting)

---

## 0. Glossary (Use These Terms Consistently)

This project currently mixes terms like `event_id`, `event_hash`, and `request_id`. For determinism and CRDT convergence we must be precise:

| Term | Meaning | Deterministic? | Notes |
|------|---------|----------------|-------|
| `external_id` | Source-provided identifier (Hyperlane `message_id`, etc.) | Yes | Canonical bytes (`Hash32`), never “whatever string arrived”. |
| `event` | Canonical external request payload | Yes | Only externally-derived fields. No local timestamps. No signer policy fields. |
| `event_id` | `H("igra:event:v1:" || encode_v1(event))` | Yes | Domain separated and versioned. |
| `stored_event` | Canonical `event` + local receipt metadata | No | Allowed to include local timestamps and raw strings for audit. |
| `tx_template` | Deterministically constructed unsigned tx (inputs/outputs/fee policy) for one event | Yes | Must converge across signers (no leader). |
| `tx_template_hash` | Hash of the `tx_template` canonical encoding | Yes | Used to detect divergence. |
| `crdt_key` | Storage key for the signing CRDT state | Yes | If it includes `tx_template_hash`, we need an index to query by `event_id`. |

**Invariant:** One external event must map to exactly one tx template (one event → one tx), otherwise signers diverge.

---

## 1. Refactor Event Model

### Problem: Current Model Mixes Concerns

Current `SigningEvent` mixes:
- **Canonical data** (deterministic - all signers must agree)
- **Local data** (non-deterministic - differs per signer)
- **Internal policy** (derivation - signer config, not external)

```rust
// CURRENT (problematic)
pub struct SigningEvent {
    pub event_id: String,              // External
    pub event_source: EventSource,     // External
    pub derivation_path: String,       // INTERNAL (signer policy)
    pub derivation_index: Option<u32>, // INTERNAL (signer policy)
    pub destination_address: String,   // External
    pub amount_sompi: u64,             // External
    pub metadata: BTreeMap<...>,       // For audit
    pub timestamp_nanos: u64,          // LOCAL (non-deterministic!)
    pub signature: Option<Vec<u8>>,    // For validation
}
```

### Solution: Separate Canonical from Local

```
External Message (Hyperlane/API)
         │
         ▼
┌─────────────────────┐
│   Normalization     │  Pure, deterministic extraction
└─────────────────────┘
         │
         ▼
    Event (canonical - all signers identical)
         │
         ├──► event_id = H("igra:event:v1:" || encode(Event))
         │
         ▼
┌─────────────────────┐
│  Application Layer  │  Adds timestamp, stores
└─────────────────────┘
         │
         ▼
    StoredEvent (canonical + local metadata)
```

### New Model

```rust
// igra_core::domain::Event

use kaspa_consensus_core::tx::ScriptPublicKey;

/// Canonical event - ONLY external request data
/// Deterministic: all signers produce identical `Event`
///
/// CRITICAL: This struct is FROZEN for `event_id` stability.
/// - DO NOT reorder fields
/// - DO NOT add/remove fields without version bump
/// - Use `EventV2` for breaking changes
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Event {
    /// External identifier - MUST be canonical bytes, not string.
    /// For Hyperlane: 32-byte `message_id` (parsed, validated).
    /// For API: hash of request body.
    pub external_id: Hash32,

    /// Source type (frozen enum - append-only for new variants).
    pub source: SourceType,

    /// Kaspa destination script.
    ///
    /// IMPORTANT: `event_id` must not depend on serde/bincode serialization of `ScriptPublicKey`.
    /// Instead, `compute_event_id` uses an explicit encoding that includes only
    /// `destination.version()` + `destination.script()` bytes.
    pub destination: ScriptPublicKey,

    /// Amount in sompi.
    pub amount: u64,
}

/// Source type enum - APPEND ONLY, never reorder variants
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum SourceType {
    Hyperlane { origin_domain: u32 },
    LayerZero { src_eid: u32 },
    Api,
    Manual,
    // Future variants MUST be appended here, never inserted
}

/// Stored event with local metadata (CF_EVENT)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredEvent {
    /// Canonical event (deterministic)
    pub event: Event,

    /// When this node received it (nanos) - set by application layer
    pub received_at_nanos: u64,

    /// Original string representations for audit/debugging
    /// (e.g., original address string, message_id hex)
    pub audit: EventAuditData,
}

/// Audit data - original forms before canonicalization
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventAuditData {
    /// Original external_id as received (hex string with 0x prefix, etc.)
    pub external_id_raw: String,

    /// Original destination address string
    pub destination_raw: String,

    /// Source-specific raw data (Hyperlane signatures, etc.)
    pub source_data: BTreeMap<String, String>,
}
```

**Key changes from naive approach:**
- `external_id: Hash32` not `id: String` (avoids 0x/case/padding non-determinism)
- `destination: ScriptPublicKey` not `String` (canonical bytes; `event_id` encoding uses `version()+script()` bytes, not serde)
- `audit` preserves original strings for debugging
- Struct marked as FROZEN with version guidance

### What Goes Where

| Data | Location | Type | Deterministic? |
|------|----------|------|----------------|
| external_id | Event | `Hash32` | Yes (canonical bytes) |
| source | Event | `SourceType` enum | Yes (frozen enum) |
| destination | Event | `ScriptPublicKey` | Yes (canonical script bytes; never hashed via serde/bincode) |
| amount | Event | `u64` | Yes |
| derivation | **SignerConfig** | config | N/A (internal policy) |
| received_at_nanos | StoredEvent | `u64` | No (local timestamp) |
| audit | StoredEvent | `EventAuditData` | No (original strings for debug) |

### Canonicalization Rules (CRITICAL)

For a custody system, canonicalization MUST be explicit and documented:

| Field | Canonicalization Rule |
|-------|----------------------|
| `external_id` | Parse hex string → 32 bytes. Accept `0x` prefix or bare. Lowercase. Reject if not exactly 64 hex chars (32 bytes). |
| `destination` | Parse Kaspa address → validate network/prefix → build `ScriptPublicKey` using `pay_to_address_script` (do not store/compare strings). |
| `origin_domain` | u32, no transformation needed |
| `amount` | u64, no transformation needed |

**Validation during normalization:**
```rust
fn parse_external_id(raw: &str) -> Result<Hash32, ThresholdError> {
    let s = raw.trim().to_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);
    if s.len() != 64 {
        return Err(ThresholdError::InvalidExternalId(format!(
            "expected 64 hex chars, got {}", s.len()
        )));
    }
    let bytes = hex::decode(s)?;
    Ok(bytes.try_into().expect("64 hex chars = 32 bytes"))
}
```

### Event-ID Encoding (VERSIONED, EXPLICIT)

**Goal:** `event_id` must be stable across:
- machines/architectures
- refactors that don't bump version

**Rule:** Never compute `event_id` by serializing `Event` (or `ScriptPublicKey`) via serde/bincode.
`event_id` must be computed from an explicit encoding that we control. For `destination`, only use
`ScriptPublicKey::version()` and `ScriptPublicKey::script()` bytes.

**Rule:** Define an explicit byte encoding for `event_id`:

Conceptually:
```
event_id_v1 = BLAKE3( "igra:event:v1:" || encode_event_v1(event) )
encode_event_v1(event) =
    external_id(32)
  || source_tag(u8) || source_params(...)
  || destination.version(u16 LE)
  || destination.script_len(u32 LE) || destination.script_bytes
  || amount(u64 LE)
```

If the canonical event schema ever changes incompatibly:
- introduce `EventV2`
- introduce `compute_event_id_v2` with `b"igra:event:v2:"`
- keep v1 forever for backwards compatibility

### Deterministic Tx Construction (No Leader)

We do not have a deterministic leader. That means multiple signers can attempt to propose/build the tx template concurrently. To avoid divergence:

**Hard invariants:**
- One `event_id` MUST map to exactly one tx template (one event → one tx).
- Given the same UTXO set and same config, all signers MUST produce the same tx template and `tx_template_hash`.
- Any attempt to create a second tx template for the same `event_id` MUST be rejected (surface `TxTemplateMismatch` / `PsktMismatch`).

**Deterministic UTXO selection (must be total-order):**
- Candidate set: spendable, confirmed UTXOs for the multisig address (exclude immature/locked/unconfirmed).
- Sort candidates by a total ordering (matches `builder.rs`):
  1. amount (u64 **descending**) - prefer larger UTXOs to minimize input count
  2. outpoint txid bytes (lexicographic ascending)
  3. outpoint index (u32 ascending)
- Select the minimal prefix of this sorted list that covers `amount + fee + dust/change policy`.
- If multiple solutions exist because of equal-value UTXOs, the deterministic ordering resolves ties (no randomness).

**Deterministic outputs:**
- Always place the primary recipient output first.
- Change output (if any) is second.
- Output script bytes must be canonical (bytes, not address strings).

### CRDT Signing Material Availability (Leaderless)

In a leaderless design, it is not enough to gossip only “signatures” and “completion”. Every signer must have access to the exact same signing material for a given `event_id`:
- the canonical `signing_event` (or derived `Event` + source metadata necessary for verification)
- the unsigned transaction template / PSKT blob (`kpsbt_blob` / `pskt_blob`) that signatures are produced over

If a signer receives CRDT signatures for a template it never saw, it cannot contribute signatures (and the system can stall at `local_sig_count=1` forever).

**Recommendation (devnet + current multisig-only mode):**
- Include `signing_event` and `kpsbt_blob` in CRDT state broadcasts and state-sync responses (bounded by size limits).
- On merge, persist the first-seen template as the “active template” for that `event_id` (and reject any later mismatched template for the same `event_id`).
- Before accepting/persisting remote `kpsbt_blob`, verify it matches the claimed `tx_template_hash` and that the template commits to the same `event_id` (domain-separated).

This section is intentionally prescriptive because nondeterminism here directly becomes “multiple tx templates for one event” which breaks CRDT convergence.

### Limits & DoS Hardening (Event Ingestion)

Even pre-prod, the system should enforce size limits on untrusted inputs to prevent log/DB amplification:
- `external_id_raw`: max 128 bytes
- `destination_raw`: max 256 bytes
- `source_data`: max 64 keys, each key max 64 bytes, each value max 2048 bytes, total serialized size max 16 KiB

When limits are exceeded:
- reject during validation/normalization
- log a structured warning without dumping the full payload

### Derivation Policy (Signer Config)

Derivation is internal signer policy, NOT part of external event:

```rust
// In config, not in event
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DerivationConfig {
    /// Base path for multisig address (default: no derivation)
    pub base_path: String,  // e.g., "m/44'/111111'/0'"

    /// Index policy
    pub index_policy: IndexPolicy,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub enum IndexPolicy {
    #[default]
    None,           // No index derivation (default)
    Fixed(u32),     // Always use this index
}
```

---

## 1.1 Step-by-Step Implementation

### Step 1: Create New Types

**File:** `igra-core/src/domain/model.rs`

```rust
// ADD these new types (delete old SigningEvent, EventSource)

use kaspa_consensus_core::tx::ScriptPublicKey;

/// Canonical event - deterministic across all signers
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Event {
    pub external_id: Hash32,
    pub source: SourceType,
    pub destination: ScriptPublicKey, // Canonical script bytes (event_id encoding uses version()+script()).
    pub amount: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum SourceType {
    Hyperlane { origin_domain: u32 },
    LayerZero { src_eid: u32 },
    Api,
    Manual,
}

/// Stored event with local metadata
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredEvent {
    pub event: Event,
    pub received_at_nanos: u64,
    pub audit: EventAuditData,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EventAuditData {
    pub external_id_raw: String,
    pub destination_raw: String,
    pub source_data: BTreeMap<String, String>,
}
```

### Step 2: Add event_id Computation (VERSIONED, OWNED ENCODING)

**File:** `igra-core/src/domain/hashes.rs`

```rust
// REPLACE event_hash() and event_hash_without_signature() with:

use crate::domain::Event;
use crate::foundation::Hash32;

/// Domain separator for event_id computation.
/// CRITICAL: Never change this without bumping version.
const EVENT_ID_DOMAIN_V1: &[u8] = b"igra:event:v1:";

/// Compute deterministic event_id from canonical event.
///
/// # Stability
/// This function produces stable hashes across versions by:
/// 1. Using explicit domain separator with version
/// 2. Using an explicit byte encoding owned by IGRA (NOT serde/bincode)
/// 3. Operating on Event which is FROZEN (see Event docs)
///
/// # Breaking Changes
/// If Event struct changes incompatibly:
/// 1. Create EventV2 struct
/// 2. Create compute_event_id_v2() with "igra:event:v2:" domain
/// 3. Keep this function for backwards compatibility
pub fn compute_event_id(event: &Event) -> Hash32 {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(EVENT_ID_DOMAIN_V1);
    encode_event_v1(event, &mut buf);
    *blake3::hash(&buf).as_bytes()
}

fn encode_event_v1(event: &Event, out: &mut Vec<u8>) {
    // external_id: fixed 32 bytes
    out.extend_from_slice(&event.external_id);

    // source: stable tag + params
    encode_source_v1(&event.source, out);

    // destination: ScriptPublicKey (encode only version()+script() bytes; never serde/bincode)
    out.extend_from_slice(&event.destination.version().to_le_bytes());
    let script = event.destination.script();
    out.extend_from_slice(&(script.len() as u32).to_le_bytes());
    out.extend_from_slice(script);

    // amount: u64 LE
    out.extend_from_slice(&event.amount.to_le_bytes());
}

fn encode_source_v1(source: &SourceType, out: &mut Vec<u8>) {
    match source {
        SourceType::Hyperlane { origin_domain } => {
            out.push(1);
            out.extend_from_slice(&origin_domain.to_le_bytes());
        }
        SourceType::LayerZero { src_eid } => {
            out.push(2);
            out.extend_from_slice(&src_eid.to_le_bytes());
        }
        SourceType::Api => out.push(3),
        SourceType::Manual => out.push(4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::ScriptPublicKey;

    #[test]
    fn test_event_id_stability() {
        // This test ensures event_id doesn't change across versions.
        // If this test fails, you've broken backwards compatibility!
        let event = Event {
            external_id: [0x42; 32],
            source: SourceType::Hyperlane { origin_domain: 1 },
            destination: ScriptPublicKey::new(0, smallvec::smallvec![0x51]),
            amount: 1000000,
        };

        let id = compute_event_id(&event);

        // FROZEN: This hash must never change
        assert_eq!(
            hex::encode(id),
            "expected_hash_here",  // Fill in after first run
            "event_id computation changed - this breaks backwards compatibility!"
        );
    }
}
```

**Why versioned domain separator?**
- Any refactor (reordering fields, adding variants) can silently change event_id
- Domain separator lets us detect/migrate incompatible changes
- For custody systems, this stability is critical

### Step 3: Delete Old Types

**File:** `igra-core/src/domain/model.rs`

```rust
// DELETE entire SigningEvent struct
// DELETE EventSource enum (replaced by SourceType)
```

### Step 4: Create Normalizers (PURE - No Side Effects)

**File:** `igra-core/src/domain/normalization/mod.rs` (NEW)

```rust
//! Event normalization - converts external messages to canonical form.
//!
//! DESIGN PRINCIPLE: Normalization is PURE.
//! - No timestamps (caller adds those)
//! - No I/O
//! - Deterministic output for same input
//! - Easy to test and replay

mod hyperlane;
pub use hyperlane::normalize_hyperlane;

use crate::domain::{Event, EventAuditData};
use crate::foundation::{Hash32, ThresholdError};

/// Result of pure normalization - no timestamps, no side effects
pub struct NormalizationResult {
    /// Computed event_id (hash of canonical event)
    pub event_id: Hash32,

    /// Canonical event (deterministic)
    pub event: Event,

    /// Audit data (original strings for debugging)
    pub audit: EventAuditData,
}
```

**File:** `igra-core/src/domain/normalization/hyperlane.rs` (NEW)

```rust
use super::NormalizationResult;
use crate::domain::{Event, EventAuditData, SourceType};
use crate::domain::hashes::compute_event_id;
use crate::foundation::ThresholdError;
use kaspa_consensus_core::network::NetworkId;
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_address_script;
use std::collections::BTreeMap;

/// Normalize Hyperlane message to canonical event.
///
/// PURE FUNCTION: No timestamps, no I/O, deterministic.
/// Caller is responsible for adding timestamp when storing.
pub fn normalize_hyperlane(
    message_id_raw: &str,
    origin_domain: u32,
    expected_network: NetworkId,
    destination_raw: &str,
    amount: u64,
    source_data: BTreeMap<String, String>,
) -> Result<NormalizationResult, ThresholdError> {
    // Canonicalize external_id (parse hex, validate length)
    let external_id = parse_external_id(message_id_raw)?;

    // Canonicalize destination (parse address to ScriptPublicKey)
    let destination = parse_destination(expected_network, destination_raw)?;

    // Build canonical event
    let event = Event {
        external_id,
        source: SourceType::Hyperlane { origin_domain },
        destination,
        amount,
    };

    // Compute deterministic event_id
    let event_id = compute_event_id(&event);

    // Preserve original strings for audit
    let audit = EventAuditData {
        external_id_raw: message_id_raw.to_string(),
        destination_raw: destination_raw.to_string(),
        source_data,
    };

    Ok(NormalizationResult { event_id, event, audit })
}

fn parse_external_id(raw: &str) -> Result<Hash32, ThresholdError> {
    let s = raw.trim().to_lowercase();
    let s = s.strip_prefix("0x").unwrap_or(&s);
    if s.len() != 64 {
        return Err(ThresholdError::InvalidExternalId(format!(
            "expected 64 hex chars, got {}", s.len()
        )));
    }
    let bytes = hex::decode(s)
        .map_err(|e| ThresholdError::InvalidExternalId(e.to_string()))?;
    Ok(bytes.try_into().expect("64 hex chars = 32 bytes"))
}

fn parse_destination(expected_network: NetworkId, raw: &str) -> Result<ScriptPublicKey, ThresholdError> {
    // Parse address; validate it belongs to the expected network; then derive ScriptPublicKey.
    //
    // NOTE: Exact APIs vary; keep the invariant:
    // - reject if prefix/network mismatches config
    // - compute ScriptPublicKey from the address, not from raw strings
    let address = kaspa_addresses::Address::try_from(raw.trim())
        .map_err(|e| ThresholdError::InvalidDestination(e.to_string()))?;
    if address.network_id() != expected_network {
        return Err(ThresholdError::InvalidDestination(format!(
            "address network mismatch: expected {:?}, got {:?}",
            expected_network,
            address.network_id()
        )));
    }
    Ok(pay_to_address_script(&address))
}
```

**File:** `igra-core/src/application/event_processor.rs` (Application layer adds timestamp)

```rust
use crate::domain::normalization::normalize_hyperlane;
use crate::domain::StoredEvent;

pub async fn process_hyperlane_event(
    message_id: &str,
    origin_domain: u32,
    expected_kaspa_network: NetworkId,
    destination: &str,
    amount: u64,
    source_data: BTreeMap<String, String>,
    storage: &dyn Storage,
) -> Result<Hash32, ThresholdError> {
    // Pure normalization (no side effects)
    let result = normalize_hyperlane(
        message_id,
        origin_domain,
        expected_kaspa_network,
        destination,
        amount,
        source_data,
    )?;

    // Application layer adds timestamp (side effect isolated here)
    let stored = StoredEvent {
        event: result.event,
        received_at_nanos: now_nanos(),  // Timestamp added HERE, not in normalization
        audit: result.audit,
    };

    // Replay / idempotency semantics (NO LEADER)
    //
    // In async multi-signer CRDT environments, "already known" is often OK:
    // - If event is already completed: return success.
    // - If event is already in-progress: return success (or "accepted/in-progress").
    //
    // IMPORTANT: if the CRDT key is (event_id, tx_template_hash) then "check CRDT state"
    // cannot depend on knowing tx_template_hash yet. We therefore REQUIRE an index by event_id:
    // - CF_EVENT_ACTIVE_TEMPLATE: event_id -> tx_template_hash (optional until template built)
    // - CF_EVENT_COMPLETION: event_id -> completion record
    //
    // Any attempt to create a second tx template for the same event_id MUST be rejected.

    // Store (or update if already exists)
    storage.insert_event(result.event_id, stored)?;

    Ok(result.event_id)
}

// NOTE: For strict replay rejection (e.g., API that shouldn't accept duplicates),
// use a separate function:
pub async fn process_hyperlane_event_strict(
    // ... same params
) -> Result<Hash32, ThresholdError> {
    let result = normalize_hyperlane(...)?;

    // Strict: any existing event is an error
    if storage.get_event(&result.event_id)?.is_some() {
        return Err(ThresholdError::EventReplayed(hex::encode(result.event_id)));
    }

    // ... rest of processing
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
```

### Step 5: Update Storage Trait

**File:** `igra-core/src/infrastructure/storage/traits.rs`

```rust
// CHANGE signature from:
fn insert_event(&self, event_hash: Hash32, event: SigningEvent) -> Result<()>;
fn get_event(&self, event_hash: &Hash32) -> Result<Option<SigningEvent>>;

// TO:
fn insert_event(&self, event_id: Hash32, event: StoredEvent) -> Result<()>;
fn get_event(&self, event_id: &Hash32) -> Result<Option<StoredEvent>>;
```

### Step 6: Update RocksDB Storage

**File:** `igra-core/src/infrastructure/storage/rocks/engine.rs`

```rust
// UPDATE insert_event and get_event to use StoredEvent
// Key format stays the same: "evt:{event_id}"
```

### Step 7: Update CRDT Storage

**File:** `igra-core/src/domain/crdt/event_state.rs`

```rust
// RENAME field:
pub event_hash: Hash32,  // OLD
pub event_id: Hash32,    // NEW

// Update all references throughout file
```

**File:** `igra-core/src/infrastructure/storage/rocks/engine.rs`

```rust
// CRDT key - rename variable:
fn key_event_crdt(event_id: &Hash32, tx_template_hash: &Hash32) -> Vec<u8>
```

### Step 8: Update Event Processing

See Step 4 for the full `event_processor.rs` implementation with CRDT-aware idempotency handling.

Key points:
- Use `normalize_hyperlane()` for pure normalization
- Add timestamp in application layer (not in normalization)
- Handle idempotency: "already known" is OK in multi-signer CRDT environments
- For strict replay rejection (API), use separate `process_hyperlane_event_strict()`

### Step 9: Update Validation

**File:** `igra-core/src/domain/validation/hyperlane.rs`

```rust
// Validation happens BEFORE normalization (on raw message data)
// After validation passes, call normalize_hyperlane()
// Update to work with Event instead of SigningEvent
```

### Step 10: Move Derivation to Config

**File:** `igra-core/src/infrastructure/config/mod.rs`

```rust
// ADD to ServiceConfig or create new section:

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DerivationConfig {
    /// Base derivation path (default: "m/44'/111111'/0'")
    #[serde(default = "default_base_path")]
    pub base_path: String,

    /// Index policy (default: None)
    #[serde(default)]
    pub index_policy: IndexPolicy,
}

fn default_base_path() -> String {
    "m/44'/111111'/0'".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub enum IndexPolicy {
    #[default]
    None,
    Fixed(u32),
}
```

### Step 11: Update CRDT Handler

**File:** `igra-service/src/service/coordination/crdt_handler.rs`

```rust
// UPDATE to use Event and event_id
// Derivation path comes from config, not event
```

### Step 12: Delete Old Code

```bash
# Delete from igra-core/src/domain/model.rs:
# - SigningEvent struct
# - EventSource enum

# Delete from igra-core/src/domain/hashes.rs:
# - event_hash()
# - event_hash_without_signature()

# Search and remove all references to:
# - derivation_path
# - derivation_index
# - SigningEvent
# - EventSource (the old enum)
```

### Step 13: Update Tests

```bash
# Update all test files:
# - Replace SigningEvent with Event + StoredEvent
# - Update test fixtures/builders
# - Update assertions to use new field names (id, source, destination, amount)
```

### Step 14: Update Exports

**File:** `igra-core/src/domain/mod.rs`

```rust
pub mod normalization;  // ADD

pub use model::{
    Event,
    SourceType,
    StoredEvent,
    // DELETE: SigningEvent, EventSource
};
```

---

## 2. LayerZero: Future Work (v2)

LayerZero support is planned for v2. Current validation is placeholder.

**No action needed now.** When implementing v2:
- Add `normalize_layerzero()` function
- Validate GUID similar to Hyperlane message_id
- Store full LayerZero message data in raw_metadata

---

## 3. Simplify Request-ID

`RequestId` as internal primary key is redundant - use `event_id: Hash32`.

**However:** Keep `external_request_id` as optional client correlation ID for API tracing.

### New Model

```rust
pub struct SigningEventParams {
    /// Client-provided correlation ID (optional, for tracing)
    /// NOT used for internal keying - purely for client convenience
    pub external_request_id: Option<String>,

    // ... other fields
}
```

### Files to Modify

- `foundation/types.rs` - Delete internal `RequestId` type
- `domain/signing/mod.rs` - Update SignerBackend trait to use `event_id: &Hash32`
- `domain/signing/results.rs` - Update SigningResult to use `event_id: Hash32`
- `domain/signing/threshold.rs` - Update sign() method signature
- `domain/event/types.rs` - Rename `request_id` to `external_request_id: Option<String>`
- `domain/audit/types.rs` - Use `event_id: String` (hex-encoded Hash32) as primary key
- `api/handlers/signing_event.rs` - Update logging to use `event_id`, include `external_request_id` if present

### Why Keep External Request ID?

Operationally, clients often need a correlation ID that:
- They generate (not computed from hash)
- Appears in logs for support tickets
- Links to their internal systems

`event_id` is internal (hash of canonical event) and clients don't control it.
`external_request_id` is client-controlled and optional.

---

## 4. Keep In-Memory Storage for Tests

**DO NOT DELETE** `igra-core/src/infrastructure/storage/memory.rs`

### Rationale

Removing in-memory storage is a productivity regression:
- Unit tests become slower (RocksDB startup overhead)
- Tests become less hermetic (temp dir cleanup issues)
- Property-based tests become impractical (need fast iterations)

### Solution: Feature-Gate for Tests

```rust
// In igra-core/src/infrastructure/storage/mod.rs

#[cfg(any(test, feature = "test-utils"))]
pub mod memory;

#[cfg(any(test, feature = "test-utils"))]
pub use memory::MemoryStorage;
```

### Usage Guidelines

| Test Type | Storage | Rationale |
|-----------|---------|-----------|
| Unit tests | `MemoryStorage` | Fast, hermetic |
| Property tests | `MemoryStorage` | Fast iterations |
| Integration tests | `RocksStorage` + tempdir | Tests real storage |
| E2E tests | `RocksStorage` + tempdir | Production-like |

### Integration Test Example

```rust
use tempfile::tempdir;

#[tokio::test]
async fn test_crdt_persistence() {
    let temp_dir = tempdir().unwrap();
    let storage = Arc::new(RocksStorage::open(temp_dir.path()).unwrap());
    // ... test that exercises persistence
}
```

---

## 5. Keep MPC/MuSig2 as Proper Stubs (with Safe Feature Gates)

**DO NOT DELETE** - Keep as placeholders but improve error handling and feature gating.

### Current (Poor)

```rust
fn sign(&self, ...) -> Result<..., ThresholdError> {
    Err(ThresholdError::Message("not implemented".into()))
}
```

### Improved Error Handling

```rust
fn sign(&self, ...) -> Result<..., ThresholdError> {
    Err(ThresholdError::Unimplemented(
        "MuSig2 signing backend not yet implemented. Use 'threshold' backend.".into()
    ))
}
```

### Feature Gating (with Config Validation)

**Problem:** If config says `backend=musig2` but feature not compiled, you get silent failures or confusing errors.

**Solution:** Explicit config-time validation.

```rust
// In Cargo.toml
[features]
default = []
musig2 = []
mpc = []

// In igra-core/src/domain/signing/mod.rs
#[cfg(feature = "musig2")]
pub mod musig2;

#[cfg(feature = "mpc")]
pub mod mpc;

// In config validation (igra-core/src/infrastructure/config/validation.rs)
pub fn validate_signing_backend(config: &ServiceConfig) -> Result<(), ThresholdError> {
    match config.signing_backend.as_str() {
        "threshold" => Ok(()),

        #[cfg(feature = "musig2")]
        "musig2" => Ok(()),

        #[cfg(not(feature = "musig2"))]
        "musig2" => Err(ThresholdError::ConfigError(
            "signing_backend='musig2' requires the 'musig2' feature. \
             Rebuild with: cargo build --features musig2".to_string()
        )),

        #[cfg(feature = "mpc")]
        "mpc" => Ok(()),

        #[cfg(not(feature = "mpc"))]
        "mpc" => Err(ThresholdError::ConfigError(
            "signing_backend='mpc' requires the 'mpc' feature. \
             Rebuild with: cargo build --features mpc".to_string()
        )),

        other => Err(ThresholdError::ConfigError(format!(
            "unknown signing_backend '{}'. Valid options: threshold, musig2, mpc", other
        ))),
    }
}
```

**Call during startup:**
```rust
// In main.rs or setup.rs
let config = load_config()?;
validate_signing_backend(&config)?;  // Fail early with clear message
```

---

## 6. Keep fake_hyperlane_ism_api

**DO NOT DELETE** - Used for staging environment.

Move to appropriate location later:
```
igra-service/src/bin/fake_hyperlane_ism_api.rs → staging/tools/ (future)
```

The `#[allow(dead_code)]` annotations are intentional for unused JSON fields.

---

## 6.5 RocksDB Schema Migration Strategy

### Problem

When CF_EVENT format changes (e.g., Event model refactoring):
- Old data becomes unreadable (bincode decode panic)
- Devnet iterations break repeatedly
- No graceful upgrade path

### Solution: Schema Versioning

**Store schema version in CF_METADATA:**

```rust
// In rocks/schema.rs
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
const SCHEMA_VERSION_KEY: &[u8] = b"__schema_version__";

impl RocksStorage {
    pub fn open(path: &Path) -> Result<Self, ThresholdError> {
        let db = DB::open(...)?;

        // Check schema version (CF_METADATA, not default CF)
        let stored_version = db.get_cf(cf_metadata, SCHEMA_VERSION_KEY)?
            .map(|v| u32::from_le_bytes(v.try_into().unwrap_or([0; 4])))
            .unwrap_or(0);

        if stored_version == 0 {
            // Fresh DB, set version
            db.put_cf(cf_metadata, SCHEMA_VERSION_KEY, CURRENT_SCHEMA_VERSION.to_le_bytes())?;
        } else if stored_version != CURRENT_SCHEMA_VERSION {
            return Err(ThresholdError::SchemaMismatch {
                stored: stored_version,
                current: CURRENT_SCHEMA_VERSION,
            });
        }

        Ok(Self { db })
    }
}
```

### Migration Strategies

| Environment | Strategy |
|-------------|----------|
| **Devnet** | Wipe DB on version mismatch (fast iteration) |
| **Testnet** | Manual migration or coordinated wipe |
| **Production** | Versioned migration functions |

**Devnet auto-wipe (opt-in via config):**
```rust
if stored_version != CURRENT_SCHEMA_VERSION {
    if config.allow_schema_wipe {
        warn!("Schema mismatch (stored={}, current={}), wiping DB",
              stored_version, CURRENT_SCHEMA_VERSION);
        drop(db);
        std::fs::remove_dir_all(path)?;
        return Self::open(path);  // Retry with fresh DB
    } else {
        return Err(ThresholdError::SchemaMismatch { ... });
    }
}
```

**Production migration (when needed):**
```rust
fn migrate_v1_to_v2(db: &DB) -> Result<(), ThresholdError> {
    // Read all CF_EVENT entries
    // Decode with V1 schema
    // Re-encode with V2 schema
    // Write back
    // Update schema version
}
```

### When to Bump Schema Version

| Change | Bump Version? |
|--------|---------------|
| Add optional field with default | No |
| Add required field | Yes |
| Remove field | Yes |
| Rename field | Yes |
| Change field type | Yes |
| Reorder struct fields | Yes (bincode-dependent) |
| Add enum variant (append) | Depends (old binaries cannot decode new variants) |
| Reorder enum variants | Yes |

---

## 6.6 Transport / Gossip Wire-Versioning Strategy

### Problem

We currently use `bincode` for gossip payloads. `bincode` is compact and fast, but it is **not** a stable on-the-wire format:
- adding/removing/reordering fields can break decoding
- new binaries can become incompatible with old binaries (and vice-versa)

This is acceptable for devnet (restart everything), but must be explicit in the design so we don’t get “mystery split-brain” in staging/prod.

### Recommendation

- Add an explicit `protocol_version: u16` (or `u32`) to the top-level wire envelope.
- Treat any version mismatch as a hard error: reject message + log once per peer.
- For future upgrades, use `enum WireMessage { V1(WireMessageV1), V2(WireMessageV2) }` and decode based on the explicit version.

**Important:** `event_id` / `tx_template_hash` determinism is not a substitute for wire compatibility. Mismatched binaries must fail fast.

---

## 7. Implement or Remove Dead Code

Reference: `docs/DEAD-CODE.md`

### 7.1 IMPLEMENT: Validation Functions

**File:** `igra-core/src/domain/pskt/validation.rs`

These functions exist but are never called. **Integrate them:**

```rust
// In build_pskt_from_utxos(), add at start:
validate_inputs(&inputs)?;
validate_outputs(&outputs)?;
validate_params(&params)?;
```

### 7.2 IMPLEMENT: Circuit Breaker

**File:** `igra-core/src/infrastructure/rpc/circuit_breaker.rs`

Fully implemented but never used. **Integrate into GrpcNodeRpc:**

```rust
pub struct GrpcNodeRpc {
    client: KaspaRpcClient,
    circuit_breaker: CircuitBreaker,  // Add this
}

impl GrpcNodeRpc {
    pub async fn get_utxos(&self, ...) -> Result<...> {
        self.circuit_breaker.call(|| {
            self.client.get_utxos_by_addresses(...)
        }).await
    }
}
```

### Circuit Breaker Specification

**Per-method breaker state:**
- Each RPC method gets its own circuit breaker instance
- Allows `get_utxos` to fail without breaking `submit_transaction`

**Configuration:**
```rust
pub struct CircuitBreakerConfig {
    /// Failures before opening circuit
    pub failure_threshold: u32,  // default: 5

    /// Time circuit stays open before half-open probe
    pub open_duration_secs: u64,  // default: 30

    /// Successes in half-open before closing
    pub success_threshold: u32,  // default: 2
}
```

**Failure definitions:**
| Error Type | Counts as Failure? |
|------------|-------------------|
| Connection timeout | Yes |
| Connection refused | Yes |
| HTTP 5xx | Yes |
| RPC error (node-side) | Yes |
| HTTP 4xx | No (client error) |
| Validation error | No (client error) |

**Backoff strategy:**
- Exponential: 1s, 2s, 4s, 8s, ... up to `open_duration_secs`
- Jitter: ±20% to prevent thundering herd

**Metrics/Logging:**
```rust
// Metrics
rpc_circuit_breaker_state{method="get_utxos", state="open|closed|half_open"}
rpc_circuit_breaker_failures_total{method="get_utxos"}
rpc_circuit_breaker_successes_total{method="get_utxos"}

// Log on state change
info!("circuit breaker state change method={} old={} new={}", method, old, new);
```

### 7.3 IMPLEMENT: Use Existing Constants

**File:** `igra-core/src/foundation/constants.rs`

These constants are correctly defined but not yet used. Integrate them:

| Constant | Where to Use |
|----------|--------------|
| `MAX_PSKT_INPUTS` | ✅ Already used in `builder.rs` |
| `MAX_PSKT_OUTPUTS` | Add check in `validation.rs` |
| `MAX_BOOTSTRAP_PEERS` | Use in gossip config validation |
| `GOSSIP_PUBLISH_RETRIES` | Use in gossip publish retry loop |
| `GOSSIP_RETRY_DELAY_MS` | Use in gossip publish retry loop |
| `MAX_GOSSIP_TOPIC_LENGTH` | Use in topic validation |
| `RATE_LIMIT_CLEANUP_INTERVAL_SECS` | Use in rate limiter cleanup task |

**Example - Add MAX_PSKT_OUTPUTS check:**

```rust
// In validation.rs
use crate::foundation::constants::{MAX_PSKT_INPUTS, MAX_PSKT_OUTPUTS};

pub fn validate_params(params: &PsktParams) -> PsktValidationResult {
    // ... existing checks ...

    if params.outputs.len() > MAX_PSKT_OUTPUTS {
        errors.push(PsktValidationError::TooManyOutputs);
    }
}
```

### 7.4 REMOVE: Unused Utilities

**File:** `igra-core/src/foundation/util/conversion.rs` - Delete entire file

These are trivial - use `usize::from()`, `u32::try_from()` directly.

**File:** `igra-core/src/foundation/util/encoding.rs`

Remove:
- `decode_hex_array()` - Duplicate of `decode_hex()`
- `decode_hex_exact()` - Not used anywhere

---

## 8. Unify Wrapper Types with Macro

**File:** `igra-core/src/foundation/types.rs`

Create macro for `PeerId`, `SessionId`, `TransactionId`:

```rust
macro_rules! define_id_type {
    (string $name:ident) => {
        #[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self { Self(value.into()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::ops::Deref for $name {
            type Target = str;
            fn deref(&self) -> &Self::Target { &self.0 }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self { Self(s) }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self { Self(s.to_string()) }
        }
    };

    (hash $name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
        pub struct $name(Hash32);

        impl $name {
            pub fn new(hash: Hash32) -> Self { Self(hash) }
            pub fn as_hash(&self) -> &Hash32 { &self.0 }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        impl From<Hash32> for $name {
            fn from(h: Hash32) -> Self { Self(h) }
        }
    };
}

// Usage
define_id_type!(string PeerId);
define_id_type!(hash SessionId);
define_id_type!(hash TransactionId);
```

---

## 9. Use thiserror for Error Handling

**File:** `igra-core/src/foundation/error.rs`

Replace manual `From` implementations with derive macros:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThresholdError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("RocksDB error: {0}")]
    Storage(#[from] rocksdb::Error),

    #[error("Feature not implemented: {0}")]
    Unimplemented(String),

    // ... etc
}
```

---

## 10. Normalize Naming

### 10.1 Timestamp Fields

Standardize on `timestamp_nanos` everywhere:
- `timestamp_ns` → `timestamp_nanos`

### 10.2 Document New Model

Add doc comments for the new types:

```rust
/// Canonical event - deterministic across all signers.
/// Contains ONLY data from external source, nothing local.
/// event_id = BLAKE3("igra:event:v1:" || encode_event_v1(Event))
pub struct Event { ... }

/// Stored event with local metadata for audit trail.
/// Contains canonical event + local receipt info + raw data for re-verification.
pub struct StoredEvent { ... }
```

---

## 11. Implementation Checklist

### Phase 1: Refactor Event Model (Section 1.1)
- [ ] **Step 1:** Create `Event`, `SourceType`, `StoredEvent`, `EventAuditData` in `model.rs` (use upstream `ScriptPublicKey`)
- [ ] **Step 2:** Add `compute_event_id(event: &Event) -> Hash32` in `hashes.rs` using explicit `encode_event_v1`
- [ ] **Step 3:** Delete old `SigningEvent`, `EventSource` from `model.rs`
- [ ] **Step 4:** Create `domain/normalization/` module with `normalize_hyperlane()`
- [ ] **Step 5:** Update `Storage` trait: `insert_event(Hash32, StoredEvent)`
- [ ] **Step 6:** Update RocksDB `engine.rs` to use `StoredEvent`
- [ ] **Step 7:** Update CRDT: rename `event_hash` → `event_id`
- [ ] **Step 7.1:** Add event_id indexes required for idempotency and divergence checks (`event_id -> active tx_template_hash`, `event_id -> completion`)
- [ ] **Step 8:** Update `event_processor.rs` to use normalization
- [ ] **Step 9:** Update `validation/hyperlane.rs` to work with new types
- [ ] **Step 10:** Add `DerivationConfig` to config (move from event)
- [ ] **Step 11:** Update CRDT handler to get derivation from config
- [ ] **Step 12:** Delete old code: `event_hash()`, `derivation_path` references
- [ ] **Step 13:** Update all tests
- [ ] **Step 14:** Update exports in `domain/mod.rs`

### Phase 2: Simplify RequestId
- [ ] Delete internal `RequestId` type from `foundation/types.rs`
- [ ] Keep `external_request_id: Option<String>` in SigningEventParams
- [ ] Update `SignerBackend` trait to use `event_id: &Hash32`
- [ ] Update all audit events to use `event_id` as primary key
- [ ] Update all logging (include `external_request_id` when present)

### Phase 3: Implement Dead Code
- [ ] Integrate PSKT validation functions into builder
- [ ] Integrate CircuitBreaker into GrpcNodeRpc (with spec from 7.2)
- [ ] Add feature gates for MPC/MuSig2 stubs (with config validation)

### Phase 4: Cleanup Unused Code
- [ ] Feature-gate `memory.rs` with `#[cfg(any(test, feature = "test-utils"))]`
- [ ] Integrate unused constants (7 items) - see Section 7.3
- [ ] Delete `conversion.rs`
- [ ] Delete unused encoding functions

### Phase 5: Schema & Migration
- [ ] Add schema version to CF_METADATA
- [ ] Add schema version check on DB open
- [ ] Add `allow_schema_wipe` config for devnet
- [ ] Document migration strategy for production

### Phase 6: Modernize
- [ ] Add wrapper type macro for PeerId, SessionId, TransactionId
- [ ] Add thiserror dependency
- [ ] Refactor ThresholdError with derive macros
- [ ] Add new error variants: `InvalidExternalId`, `InvalidDestination`, `SchemaMismatch`
- [ ] Normalize timestamp naming (`received_at_nanos` everywhere)

### Phase 7: Verify
- [ ] `cargo build --all-targets`
- [ ] `cargo test --all`
- [ ] `cargo clippy --all-targets`
- [ ] `RUSTFLAGS="-Wdead_code" cargo check`
- [ ] Verify event_id stability test passes

### Future (v2): LayerZero Support
- [ ] Add `normalize_layerzero()` function
- [ ] Implement GUID computation and validation
- [ ] Add LayerZero-specific metadata extraction

---

## Summary

| Action | Priority | Effort | Impact |
|--------|----------|--------|--------|
| Refactor Event Model (typed fields) | **CRITICAL** | High | Architecture, determinism |
| Versioned event_id encoding | **CRITICAL** | Low | Schema stability |
| Add canonicalization rules | **HIGH** | Medium | Determinism |
| Pure normalization (no side effects) | **HIGH** | Low | Testability |
| Schema migration strategy | **HIGH** | Medium | Production safety |
| Move derivation to config | **HIGH** | Low | Separation of concerns |
| Simplify RequestId (keep external) | Medium | Medium | Simplification |
| Integrate PSKT validation | Medium | Low | Correctness |
| Integrate CircuitBreaker | Medium | Low | Reliability |
| Feature-gate memory.rs (keep!) | Low | Low | Test performance |
| Integrate unused constants | Low | Low | Correctness |
| Wrapper type macro | Low | Low | DRY |
| thiserror refactor | Low | Medium | Readability |
| LayerZero support | Future (v2) | High | Feature |

**Key insights:**
1. **Typed canonical fields** (`Hash32`, `ScriptPublicKey`) prevent string non-determinism
2. **Versioned encoding** with domain separator ensures event_id stability across versions
3. **Explicit event_id encoding** avoids reliance on serde/bincode of upstream types (use `version()+script()` bytes)
4. **Pure normalization** isolates side effects to application layer
5. **Schema versioning** prevents bincode decode panics during devnet iteration
6. **Keep memory storage** for fast, hermetic unit tests

---

## Appendix: Expert Review Integration

This document was updated based on expert review feedback addressing:

1. **Event-ID stability** - Added versioned domain separator (`igra:event:v1:`) and explicit byte encoding
2. **String canonicalization** - Changed to typed canonical fields (`Hash32`, `ScriptPublicKey`)
3. **Avoid serde reliance** - `event_id` uses explicit encoding; `ScriptPublicKey` contributes via `version()+script()` bytes only
4. **Pure normalization** - Removed `now_nanos()` from normalization module
5. **Naming clarity** - Renamed `Event.id` → `Event.external_id`
6. **Memory storage** - Changed from "delete" to "feature-gate for tests"
7. **Feature gate safety** - Added config-time validation for MPC/MuSig2
8. **Schema migration** - Added new section 6.5
9. **Replay semantics** - Added CRDT-aware idempotent handling
10. **Circuit breaker spec** - Added detailed configuration and metrics
11. **RequestId** - Keep `external_request_id` for client correlation
12. **UTXO selection** - Documented deterministic ordering (amount desc → txid → index)

---

*Document Version: 5.1*
*Created: 2026-01-13*
*Updated: Clarified `event_id` encoding invariants and fixed UTXO sort order to match code*
