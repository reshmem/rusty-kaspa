# Database Schema Specification

**Version:** 1.0
**Last Updated:** 2025-12-31
**Status:** Production
**Location:** `igra-core/src/storage/rocks.rs`

---

## Table of Contents

1. [Overview](#overview)
2. [Database Architecture](#database-architecture)
3. [Column Families](#column-families)
4. [Schema Diagram](#schema-diagram)
5. [Data Models](#data-models)
6. [Key Formats](#key-formats)
7. [Relationships and Interconnections](#relationships-and-interconnections)
8. [Database Operations](#database-operations)
9. [Performance Characteristics](#performance-characteristics)
10. [Durability and Reliability](#durability-and-reliability)
11. [Migrations](#migrations)
12. [Maintenance Operations](#maintenance-operations)
13. [Operational Procedures](#operational-procedures)
14. [Troubleshooting](#troubleshooting)

---

## Overview

The IGRA threshold signing service uses **RocksDB** as its primary embedded database for persistent storage. RocksDB is a high-performance key-value store optimized for fast, low-latency storage on SSD and flash devices.

### Key Features

- **Embedded Database**: No separate database server required
- **ACID Transactions**: Atomic batch writes with WriteBatch
- **Column Families**: Logical separation of data types for performance
- **Durability**: fsync enabled, WAL (Write-Ahead Log) for crash recovery
- **Custom Merge Operators**: Lock-free atomic volume accumulation
- **Crash Recovery**: Paranoid checks enabled for corruption detection

### Database Locations

The database is stored at:

```
<data_dir>/threshold-signing/
```

**Lookup Priority:**
1. `KASPA_DATA_DIR` environment variable
2. `./.igra/` in current working directory (fallback)

### Implementation

- **Storage Trait**: `igra-core/src/storage/mod.rs` - Abstract interface
- **RocksDB Implementation**: `igra-core/src/storage/rocks.rs` - Concrete implementation
- **Serialization**: `bincode` with fixed-int encoding for deterministic sizes

---

## Database Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    RocksDB Database                         │
│                <data_dir>/threshold-signing                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   default    │  │    group     │  │    event     │     │
│  │  (legacy)    │  │  (configs)   │  │ (signing evt)│     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   request    │  │   proposal   │  │request_input │     │
│  │(signing req) │  │   (KPSBT)    │  │   (UTXOs)    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ signer_ack   │  │ partial_sig  │  │   volume     │     │
│  │ (approvals)  │  │ (signatures) │  │  (tracking)  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  ┌──────────────┐                                           │
│  │     seen     │  (replay prevention)                      │
│  └──────────────┘                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Durability Configuration

```rust
// From rocks.rs:62-73
let mut options = RocksOptions::default();
options.create_if_missing(true);
options.create_missing_column_families(true);

// Enable fsync for durability
options.set_use_fsync(true);          // ✅ Force sync to disk

// Enable WAL for crash recovery
options.set_manual_wal_flush(false);  // ✅ Auto-flush WAL

// Detect corruption early
options.set_paranoid_checks(true);    // ✅ Validate all data
```

---

## Column Families

Column families provide logical separation of data types, enabling:
- **Independent compaction strategies**
- **Targeted performance tuning**
- **Efficient range queries within categories**

### 1. **default** (Legacy + Config)

- **Purpose**: Legacy column family for backward compatibility + App configuration
- **Status**: Migrated to specialized CFs when `KASPA_IGRA_ENABLE_MIGRATIONS=true`
- **Current Use**: Stores `cfg:app` key for `AppConfig` (including encrypted mnemonics)
- **Historical Use**: All data was in default CF before migration

**Current Keys:**
```
cfg:app    → JSON-serialized AppConfig (with encrypted mnemonics)
```

**Historical Key Prefixes (migrated):**
```
grp:*          → Migrated to CF_GROUP
evt:*          → Migrated to CF_EVENT
req:*          → Migrated to CF_REQUEST
proposal:*     → Migrated to CF_PROPOSAL
req_input:*    → Migrated to CF_REQUEST_INPUT
req_ack:*      → Migrated to CF_SIGNER_ACK
req_sig:*      → Migrated to CF_PARTIAL_SIG
vol:*          → Migrated to CF_VOLUME
seen:*         → Migrated to CF_SEEN
```

### 2. **group** (GroupConfig)

**Reference:** rocks.rs:50

- **Purpose**: Store threshold group configurations
- **Primary Key**: `group_id` (Hash32 - 32 bytes)
- **Value**: Bincode-serialized `GroupConfig`
- **Cardinality**: Low (typically 1-10 groups)
- **Access Pattern**: Read-heavy (loaded at startup, cached in memory)

**Data Stored:**
- Network parameters (mainnet/testnet)
- Threshold parameters (M-of-N)
- Member public keys
- Fee configuration
- Finality parameters
- Group policies (rate limits, allowed destinations)

**Key Format:**
```
grp:<group_id_32_bytes>
```

**Example:**
```
grp:a1b2c3d4...  →  GroupConfig { threshold_m: 2, threshold_n: 3, ... }
```

### 3. **event** (SigningEvent)

**Reference:** rocks.rs:51

- **Purpose**: Store signing events received from external sources (bridges, APIs)
- **Primary Key**: `event_hash` (Hash32 - 32 bytes)
- **Value**: Bincode-serialized `SigningEvent`
- **Cardinality**: High (grows with transaction volume)
- **Access Pattern**: Write-once, read-many (immutable after insertion)
- **Deduplication**: Enforced - duplicate inserts return `EventReplayed` error

**Data Stored:**
- Event metadata (ID, source, timestamp)
- Destination address and amount
- HD derivation path
- External signature (if provided)

**Key Format:**
```
evt:<event_hash_32_bytes>
```

**Replay Prevention:**
```rust
// rocks.rs:476-482
if let Some(_) = self.db.get_cf(cf, &key)? {
    return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
}
```

### 4. **request** (SigningRequest)

**Reference:** rocks.rs:52

- **Purpose**: Store signing request state and lifecycle
- **Primary Key**: `request_id` (String - UUID format)
- **Value**: Bincode-serialized `SigningRequest`
- **Cardinality**: High (1 request per event)
- **Access Pattern**: Read-write (status updates through state machine)
- **Special Keys**: Archived requests prefixed with `archive:req:`

**Data Stored:**
- Request/session IDs
- Event hash (FK to event CF)
- Coordinator peer ID
- Transaction template hash
- Decision state (Pending → Approved/Rejected → Finalized)
- Expiration timestamp
- Final transaction ID (when finalized)
- Blue score (consensus confirmation)

**Key Formats:**
```
req:<request_id>           →  Active request
archive:req:<request_id>   →  Archived request
```

**State Machine Transitions:**
```
Pending → Approved → Finalized
Pending → Rejected
Pending → Expired
Pending → Aborted
```

### 5. **proposal** (StoredProposal)

**Reference:** rocks.rs:53

- **Purpose**: Store coordinator's transaction proposal (KPSBT)
- **Primary Key**: `request_id` (FK to request)
- **Value**: Bincode-serialized `StoredProposal`
- **Cardinality**: High (1 proposal per approved request)
- **Access Pattern**: Write-once during coordination, read by signers

**Data Stored:**
- Request/session IDs
- Event hash (FK)
- Validation hash
- Complete signing event
- KPSBT blob (Kaspa Partially Signed Bitcoin Transaction)

**Key Format:**
```
proposal:<request_id>
```

### 6. **request_input** (RequestInput)

**Reference:** rocks.rs:54

- **Purpose**: Store UTXO inputs for each signing request
- **Primary Key**: Composite - `(request_id, input_index)`
- **Value**: Bincode-serialized `RequestInput`
- **Cardinality**: Very High (multiple inputs per request)
- **Access Pattern**: Bulk insert during proposal, bulk read during signing

**Data Stored:**
- Input index (ordinal within transaction)
- UTXO reference (tx_id, output_index, value)
- Signing hash (hash to be signed)
- My signature (local signer's signature)

**Key Format:**
```
req_input:<request_id>:<input_index_u32_be>
```

**Example:**
```
req_input:550e8400-e29b-41d4-a716-446655440000:00000000  →  RequestInput { input_index: 0, ... }
req_input:550e8400-e29b-41d4-a716-446655440000:00000001  →  RequestInput { input_index: 1, ... }
```

### 7. **signer_ack** (SignerAckRecord)

**Reference:** rocks.rs:55

- **Purpose**: Store signer acknowledgments (approve/reject votes)
- **Primary Key**: Composite - `(request_id, signer_peer_id)`
- **Value**: Bincode-serialized `SignerAckRecord`
- **Cardinality**: High (M acks per request, where M is quorum)
- **Access Pattern**: Individual insert per signer, bulk read for quorum check

**Data Stored:**
- Signer peer ID
- Approval decision (accept: bool)
- Rejection reason (if rejected)
- Timestamp

**Key Format:**
```
req_ack:<request_id>:<signer_peer_id>
```

### 8. **partial_sig** (PartialSigRecord)

**Reference:** rocks.rs:56

- **Purpose**: Store partial Schnorr signatures from each signer
- **Primary Key**: Composite - `(request_id, signer_peer_id, input_index)`
- **Value**: Bincode-serialized `PartialSigRecord`
- **Cardinality**: Very High (M signers × N inputs per request)
- **Access Pattern**: Individual insert per signature, bulk read for aggregation

**Data Stored:**
- Signer peer ID
- Input index
- Public key (schnorr pubkey)
- Signature bytes (schnorr signature)
- Timestamp

**Key Format:**
```
req_sig:<request_id>:<signer_peer_id>:<input_index_u32_be>
```

### 9. **volume** (Daily Volume Tracking)

**Reference:** rocks.rs:57

- **Purpose**: Track daily transaction volume for rate limiting
- **Primary Key**: `day_start_nanos` (u64 - Unix nanoseconds at day start)
- **Value**: `u64` (cumulative volume in sompi)
- **Cardinality**: Low (365 keys per year, pruned regularly)
- **Access Pattern**: Merge-writes (concurrent updates), range scans for totals
- **Special**: **Custom merge operator for lock-free atomic accumulation**

**Merge Operator:**
```rust
// rocks.rs:20-43
fn volume_merge_operator(
    _key: &[u8],
    existing_val: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let mut total = /* existing value or 0 */;
    for op in operands {
        total = total.saturating_add(/* delta */);
    }
    Some(total.to_be_bytes().to_vec())
}
```

**Key Format:**
```
vol:<day_start_nanos_u64_be>
```

**Atomic Increment:**
```rust
// rocks.rs:304-315
fn add_to_daily_volume(&self, amount_sompi: u64, timestamp_nanos: u64) {
    let day_start = Self::day_start_nanos(timestamp_nanos);
    let key = Self::key_volume(day_start);
    let value = amount_sompi.to_be_bytes();
    self.db.merge_cf(cf, key, value)?;  // ✅ Lock-free atomic add
}
```

### 10. **seen** (Replay Prevention)

**Reference:** rocks.rs:58

- **Purpose**: Prevent replay attacks on gossip messages
- **Primary Key**: Composite - `(sender_peer_id, session_id, seq_no)`
- **Value**: `u64` (timestamp_nanos when first seen)
- **Cardinality**: Very High (grows with message volume)
- **Access Pattern**: Check-and-set on message receipt, periodic cleanup
- **Cleanup**: Messages older than TTL are deleted

**Key Format:**
```
seen:<sender_peer_id>:<session_id_32_bytes>:<seq_no_u64_be>
```

**Deduplication Check:**
```rust
// rocks.rs:685-702
fn mark_seen_message(&self, sender: &PeerId, session: &SessionId, seq_no: u64, ts: u64) -> Result<bool> {
    let key = Self::key_seen(sender, session, seq_no);
    let existing = self.db.get_cf(cf, &key)?;
    if existing.is_some() {
        return Ok(false);  // ❌ Duplicate - reject
    }
    self.db.put_cf(cf, key, ts.to_be_bytes())?;
    Ok(true)  // ✅ First time seen - accept
}
```

---

## Schema Diagram

### Entity-Relationship Diagram

```
┌──────────────────┐
│   GroupConfig    │
│  (CF: group)     │
│                  │
│ PK: group_id     │
│ • threshold_m/n  │
│ • member_pubkeys │
│ • policy         │
└──────────────────┘
         │
         │ referenced by
         ▼
┌──────────────────┐          ┌──────────────────┐
│  SigningEvent    │          │  SigningRequest  │
│  (CF: event)     │◀────────│  (CF: request)   │
│                  │  FK      │                  │
│ PK: event_hash   │          │ PK: request_id   │
│ • destination    │          │ FK: event_hash   │
│ • amount         │          │ • coordinator    │
│ • timestamp      │          │ • decision       │
│ • derivation     │          │ • final_tx_id    │
└──────────────────┘          └──────────────────┘
                                       │
                     ┌─────────────────┼─────────────────┐
                     │                 │                 │
                     ▼                 ▼                 ▼
            ┌────────────────┐ ┌──────────────┐ ┌──────────────┐
            │ StoredProposal │ │ RequestInput │ │ SignerAck    │
            │ (CF: proposal) │ │(CF: req_inp) │ │(CF: sig_ack) │
            │                │ │              │ │              │
            │PK: request_id  │ │PK: (req, ix) │ │PK: (req,sig) │
            │• kpsbt_blob    │ │• utxo_ref    │ │• accept:bool │
            │• validation    │ │• signing_hash│ │• reason      │
            └────────────────┘ └──────────────┘ └──────────────┘
                                       │
                                       │ referenced by
                                       ▼
                               ┌──────────────┐
                               │ PartialSig   │
                               │(CF: part_sig)│
                               │              │
                               │PK:(req,sig,ix│
                               │• signature   │
                               │• pubkey      │
                               └──────────────┘

┌──────────────────┐          ┌──────────────────┐
│  DailyVolume     │          │    SeenMessage   │
│  (CF: volume)    │          │   (CF: seen)     │
│                  │          │                  │
│ PK: day_start    │          │PK:(peer,sess,seq)│
│ • total_sompi    │          │• timestamp_nanos │
│ (merge operator) │          │ (replay prevent) │
└──────────────────┘          └──────────────────┘
```

### Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                    SIGNING REQUEST FLOW                       │
└──────────────────────────────────────────────────────────────┘

1. EVENT CREATION
   ┌──────────────┐
   │ Bridge/API   │
   └──────┬───────┘
          │
          ▼
   [insert_event]
          │
          ▼
   ┌──────────────┐
   │ CF: event    │ ← Immutable, replay-protected
   └──────────────┘

2. REQUEST INITIATION
   ┌──────────────┐
   │ Coordinator  │
   └──────┬───────┘
          │
          ▼
   [insert_request]
          │
          ▼
   ┌──────────────┐
   │ CF: request  │ ← Status: Pending
   └──────────────┘

3. PROPOSAL BROADCAST
          │
          ▼
   [insert_proposal]
          │
          ├─────────────────┐
          ▼                 ▼
   ┌──────────────┐  ┌──────────────┐
   │ CF: proposal │  │ CF: req_inp  │ ← N inputs
   └──────────────┘  └──────────────┘

4. SIGNER ACKNOWLEDGMENT
   ┌──────────────┐
   │ Signer Nodes │
   └──────┬───────┘
          │
          ▼
   [insert_signer_ack] × M signers
          │
          ▼
   ┌──────────────┐
   │ CF: sig_ack  │ ← M acks (approve/reject)
   └──────────────┘
          │
          ▼
   [update_request_decision] → Approved/Rejected

5. SIGNATURE COLLECTION
   ┌──────────────┐
   │ Signer Nodes │
   └──────┬───────┘
          │
          ▼
   [insert_partial_sig] × (M signers × N inputs)
          │
          ▼
   ┌──────────────┐
   │ CF: part_sig │ ← M × N partial signatures
   └──────────────┘

6. FINALIZATION
          │
          ▼
   [update_request_final_tx]
          │
          ├─────────────────┐
          ▼                 ▼
   ┌──────────────┐  ┌──────────────┐
   │ CF: request  │  │ CF: volume   │ ← Daily volume += amount
   │ (Finalized)  │  │ (merge add)  │
   └──────────────┘  └──────────────┘

7. ARCHIVAL (optional)
          │
          ▼
   [archive_old_requests] → req: → archive:req:
          │
          ▼
   [delete_old_archives] → delete archive:req:
```

---

## Data Models

**Reference:** All models defined in `igra-core/src/model.rs`

All models are serialized using **bincode** with fixed-int encoding for deterministic sizes and efficient storage.

### GroupConfig (model.rs:8-20)

**Purpose:** Multi-signature threshold group configuration

```rust
pub struct GroupConfig {
    pub network_id: u8,                      // 0=mainnet, 1=testnet, etc.
    pub threshold_m: u16,                    // Required signatures (M-of-N)
    pub threshold_n: u16,                    // Total signers (M-of-N)
    pub member_pubkeys: Vec<Vec<u8>>,        // N public keys (schnorr)
    pub fee_rate_sompi_per_gram: u64,        // Transaction fee rate
    pub finality_blue_score_threshold: u64,  // Consensus finality depth
    pub dust_threshold_sompi: u64,           // Minimum output value
    pub min_recipient_amount_sompi: u64,     // Minimum transfer amount
    pub session_timeout_seconds: u64,        // Signing session timeout
    pub group_metadata: GroupMetadata,       // Metadata (name, version)
    pub policy: GroupPolicy,                 // Rate limits, allowlists
}
```

### GroupPolicy (model.rs:30-37)

**Purpose:** Security policy enforcement

```rust
pub struct GroupPolicy {
    pub allowed_destinations: Vec<String>,    // Address allowlist (empty = all)
    pub min_amount_sompi: Option<u64>,        // Minimum transfer amount
    pub max_amount_sompi: Option<u64>,        // Maximum transfer amount
    pub max_daily_volume_sompi: Option<u64>,  // Daily volume limit
    pub require_reason: bool,                 // Require reason for signing
}
```

### SigningEvent (model.rs:39-50)

**Purpose:** External signing request from bridges/APIs

```rust
pub struct SigningEvent {
    pub event_id: String,                    // External event ID
    pub event_source: EventSource,           // Origin (Hyperlane, LayerZero, API, etc.)
    pub derivation_path: String,             // HD wallet path (m/45'/111111'/0'/0/{index})
    pub derivation_index: Option<u32>,       // HD index
    pub destination_address: String,         // Kaspa address
    pub amount_sompi: u64,                   // Transfer amount (1 KAS = 10^8 sompi)
    pub metadata: BTreeMap<String, String>,  // Additional context
    pub timestamp_nanos: u64,                // Event timestamp
    pub signature: Option<Vec<u8>>,          // External signature (for verification)
}
```

### SigningRequest (model.rs:61-73)

**Purpose:** Internal signing request lifecycle tracking

```rust
pub struct SigningRequest {
    pub request_id: RequestId,               // UUID
    pub session_id: SessionId,               // Session hash (32 bytes)
    pub event_hash: Hash32,                  // FK to SigningEvent
    pub coordinator_peer_id: PeerId,         // Coordinator node ID
    pub tx_template_hash: Hash32,            // Transaction template hash
    pub validation_hash: Hash32,             // Validation data hash
    pub decision: RequestDecision,           // State machine status
    pub expires_at_nanos: u64,               // Expiration timestamp
    pub final_tx_id: Option<TransactionId>,  // Finalized tx ID (when complete)
    pub final_tx_accepted_blue_score: Option<u64>, // Consensus confirmation depth
}
```

### RequestDecision (model.rs:75-83)

**Purpose:** Request state machine

```rust
pub enum RequestDecision {
    Pending,                    // Initial state
    Approved,                   // Quorum reached, ready to sign
    Rejected { reason: String }, // Quorum rejected
    Expired,                    // Timeout reached
    Finalized,                  // Transaction broadcast and finalized
    Aborted { reason: String }, // Coordinator aborted
}
```

### StoredProposal (model.rs:125-133)

**Purpose:** Coordinator's transaction proposal (KPSBT)

```rust
pub struct StoredProposal {
    pub request_id: RequestId,            // FK to SigningRequest
    pub session_id: SessionId,            // Session identifier
    pub event_hash: Hash32,               // FK to SigningEvent
    pub validation_hash: Hash32,          // Consistency check
    pub signing_event: SigningEvent,      // Embedded event copy
    pub kpsbt_blob: Vec<u8>,              // Kaspa PSBT binary
}
```

### RequestInput (model.rs:85-93)

**Purpose:** UTXO input to be signed

```rust
pub struct RequestInput {
    pub input_index: u32,              // Input ordinal (0, 1, 2, ...)
    pub utxo_tx_id: Hash32,            // Previous transaction ID
    pub utxo_output_index: u32,        // Previous output index
    pub utxo_value: u64,               // UTXO value (sompi)
    pub signing_hash: [u8; 32],        // Hash to be signed (sighash)
    pub my_signature: Option<Vec<u8>>, // Local signer's signature
}
```

### SignerAckRecord (model.rs:95-101)

**Purpose:** Signer approval/rejection vote

```rust
pub struct SignerAckRecord {
    pub signer_peer_id: PeerId,       // Signer identifier
    pub accept: bool,                 // true=approve, false=reject
    pub reason: Option<String>,       // Rejection reason (if accept=false)
    pub timestamp_nanos: u64,         // Vote timestamp
}
```

### PartialSigRecord (model.rs:103-110)

**Purpose:** Individual signer's partial Schnorr signature

```rust
pub struct PartialSigRecord {
    pub signer_peer_id: PeerId,       // Signer identifier
    pub input_index: u32,             // Input being signed
    pub pubkey: Vec<u8>,              // Schnorr public key
    pub signature: Vec<u8>,           // Schnorr signature
    pub timestamp_nanos: u64,         // Signature timestamp
}
```

---

## Key Formats

**Reference:** Key construction in rocks.rs:209-297

All keys use **big-endian encoding** for numeric fields to enable lexicographic sorting and efficient range queries.

### Type Aliases (types.rs)

```rust
pub type Hash32 = [u8; 32];              // 32-byte hash
pub struct RequestId(String);            // UUID string
pub struct PeerId(String);               // Peer identifier string
pub struct SessionId(Hash32);            // 32-byte session hash
pub struct TransactionId(Hash32);        // 32-byte transaction ID
```

### Key Construction Table

| Column Family  | Key Format | Key Length | Code Reference |
|----------------|------------|------------|----------------|
| `default`      | `cfg:app` | 7 bytes | persistence.rs:8 |
| `group`        | `grp:<group_id>` | 4 + 32 = 36 bytes | rocks.rs:209 |
| `event`        | `evt:<event_hash>` | 4 + 32 = 36 bytes | rocks.rs:216 |
| `request`      | `req:<request_id>` | 4 + UUID length | rocks.rs:223 |
| `request` (archived) | `archive:req:<request_id>` | 12 + UUID length | rocks.rs:400 |
| `proposal`     | `proposal:<request_id>` | 9 + UUID length | rocks.rs:230 |
| `request_input` | `req_input:<request_id>:<input_index_be>` | 10 + UUID + 1 + 4 | rocks.rs:245 |
| `signer_ack`   | `req_ack:<request_id>:<peer_id>` | 8 + UUID + 1 + peer length | rocks.rs:259 |
| `partial_sig`  | `req_sig:<request_id>:<peer_id>:<input_index_be>` | 8 + UUID + 1 + peer + 1 + 4 | rocks.rs:273 |
| `volume`       | `vol:<day_start_nanos_be>` | 4 + 8 = 12 bytes | rocks.rs:292 |
| `seen`         | `seen:<peer_id>:<session_id>:<seq_no_be>` | 5 + peer + 1 + 32 + 1 + 8 | rocks.rs:281 |

### Key Construction Examples

**Group:**
```rust
// rocks.rs:209-214
fn key_group(group_id: &Hash32) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + 32);
    key.extend_from_slice(b"grp:");
    key.extend_from_slice(group_id);
    key
}
```

**Request Input:**
```rust
// rocks.rs:245-249
fn key_request_input(request_id: &RequestId, input_index: u32) -> Vec<u8> {
    let mut key = Self::key_request_input_prefix(request_id);
    key.extend_from_slice(&input_index.to_be_bytes());  // ✅ Big-endian
    key
}
```

**Volume:**
```rust
// rocks.rs:292-297
fn key_volume(day_start_nanos: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + 8);
    key.extend_from_slice(b"vol:");
    key.extend_from_slice(&day_start_nanos.to_be_bytes());  // ✅ Big-endian
    key
}

// Day boundary calculation (UTC-aligned)
fn day_start_nanos(now_nanos: u64) -> u64 {
    let nanos_per_day = 24 * 60 * 60 * 1_000_000_000u64;
    (now_nanos / nanos_per_day) * nanos_per_day
}
```

---

## Relationships and Interconnections

### Primary Relationships

```
GroupConfig (group_id)
  │
  └─→ (implicit) SigningRequest (group selection during validation)
                       │
                       ├─→ SigningEvent (event_hash) [1:1]
                       │
                       ├─→ StoredProposal (request_id) [1:1]
                       │
                       ├─→ RequestInput (request_id) [1:N]
                       │         │
                       │         └─→ PartialSigRecord (request_id, input_index) [1:M]
                       │
                       └─→ SignerAckRecord (request_id) [1:M]

DailyVolume (day_start)  ← Updated on finalization
  ↑
  └─ Incremented by SigningRequest.finalize() → event.amount_sompi

SeenMessage (peer, session, seq) ← Independent (gossip layer)
```

### Foreign Key Enforcement

**Application-Level Foreign Keys:**

1. **SigningRequest → SigningEvent** (rocks.rs:500)
   - `SigningRequest.event_hash` must reference existing `SigningEvent`

2. **StoredProposal → SigningRequest** (rocks.rs:535)
   - `StoredProposal.request_id` must reference existing `SigningRequest`

3. **RequestInput → SigningRequest** (rocks.rs:554)
   - Parent-child relationship via `request_id`

4. **SignerAckRecord → SigningRequest** (rocks.rs:578)
   - Many-to-one relationship via `request_id`

5. **PartialSigRecord → RequestInput** (rocks.rs:602)
   - Composite FK: `(request_id, input_index)`

### Lifecycle Dependencies

**Complete Request Lifecycle:**

```
1. insert_event(event)                      [CF: event]
   ↓
2. insert_request(request)                  [CF: request]
   ↓
3. insert_proposal(proposal)                [CF: proposal]
   ↓
4. insert_request_input(input) × N          [CF: request_input]
   ↓
5. insert_signer_ack(ack) × M               [CF: signer_ack]
   → update_request_decision(Approved)      [CF: request]
   ↓
6. insert_partial_sig(sig) × (M × N)        [CF: partial_sig]
   ↓
7. update_request_final_tx(tx_id)           [CF: request, volume]
   → decision = Finalized
   → add_to_daily_volume(amount)            [Auto-triggered]
```

---

## Database Operations

**Reference:** Storage trait in mod.rs:10-47, implementation in rocks.rs:451-762

### Core CRUD Operations

**Group Configuration:**
```rust
storage.upsert_group_config(group_id, config)?;  // rocks.rs:452
let config = storage.get_group_config(&group_id)?;  // rocks.rs:461
```

**Signing Event (with replay protection):**
```rust
storage.insert_event(event_hash, event)?;  // rocks.rs:471 (errors if duplicate)
let event = storage.get_event(&event_hash)?;  // rocks.rs:490
```

**Signing Request:**
```rust
storage.insert_request(request)?;  // rocks.rs:500
let request = storage.get_request(&request_id)?;  // rocks.rs:525
storage.update_request_decision(&request_id, decision)?;  // rocks.rs:509
storage.update_request_final_tx(&request_id, tx_id)?;  // rocks.rs:626
storage.update_request_final_tx_score(&request_id, score)?;  // rocks.rs:655
```

**Proposal:**
```rust
storage.insert_proposal(&request_id, proposal)?;  // rocks.rs:535
let proposal = storage.get_proposal(&request_id)?;  // rocks.rs:544
```

**Request Inputs (with range queries):**
```rust
storage.insert_request_input(&request_id, input)?;  // rocks.rs:554
let inputs = storage.list_request_inputs(&request_id)?;  // rocks.rs:563
```

**Signer Acknowledgments:**
```rust
storage.insert_signer_ack(&request_id, ack)?;  // rocks.rs:578
let acks = storage.list_signer_acks(&request_id)?;  // rocks.rs:587
```

**Partial Signatures:**
```rust
storage.insert_partial_sig(&request_id, sig)?;  // rocks.rs:602
let sigs = storage.list_partial_sigs(&request_id)?;  // rocks.rs:611
```

**Volume Tracking:**
```rust
let volume = storage.get_volume_since(timestamp_nanos)?;  // rocks.rs:670
// Automatic: add_to_daily_volume() called on finalization  // rocks.rs:650
```

**Replay Prevention:**
```rust
let is_new = storage.mark_seen_message(&peer, &session, seq, ts)?;  // rocks.rs:685
let deleted = storage.cleanup_seen_messages(older_than)?;  // rocks.rs:704
```

### Batch Operations

```rust
let mut batch = storage.begin_batch()?;  // rocks.rs:731
batch.insert(key, value)?;
batch.delete(key)?;
batch.commit()?;  // Atomic
// Or: batch.rollback();
```

### Maintenance Operations

```rust
let archived = storage.archive_old_requests(before_nanos)?;  // rocks.rs:378
let deleted = storage.delete_old_archives(before_nanos)?;  // rocks.rs:415
storage.compact()?;  // rocks.rs:445
storage.health_check()?;  // rocks.rs:678
storage.create_checkpoint(path)?;  // rocks.rs:125
```

---

## Performance Characteristics

### Read Performance

| Operation | Complexity | Typical Latency | Implementation |
|-----------|------------|-----------------|----------------|
| `get_group_config` | O(1) | <1ms | Point lookup, cached |
| `get_event` | O(1) | <1ms | Point lookup |
| `get_request` | O(1) | <1ms | Point lookup |
| `list_request_inputs` | O(N) | 1-10ms | N = input count (typically 1-10) |
| `list_signer_acks` | O(M) | 1-5ms | M = signer count (typically 3-10) |
| `list_partial_sigs` | O(M×N) | 5-50ms | M×N = total sigs (typically 15) |
| `get_volume_since` | O(D) | 1-10ms | D = day count (typically 1-7) |

### Write Performance

| Operation | Complexity | Typical Latency | Notes |
|-----------|------------|-----------------|-------|
| `insert_event` | O(1) | 1-5ms | With fsync |
| `insert_request` | O(1) | 1-5ms | With fsync |
| `update_request_decision` | O(1) | 1-5ms | Read-modify-write |
| `insert_proposal` | O(1) | 5-20ms | Large KPSBT blob |
| `add_to_daily_volume` | O(1) | <1ms | **Merge operator (lock-free)** |
| `WriteBatch::commit` | O(B) | 5-50ms | B = batch size |

### Space Complexity

**Estimated Storage (per request):**
```
SigningEvent:      ~500 bytes   ×1
SigningRequest:    ~200 bytes   ×1
StoredProposal:    ~10KB        ×1
RequestInput:      ~150 bytes   ×5  = 750 bytes
SignerAckRecord:   ~100 bytes   ×3  = 300 bytes
PartialSigRecord:  ~150 bytes   ×15 = 2.25KB
─────────────────────────────────────────────
Total per request: ~14KB
```

**Annual Storage:**
```
14 KB/request × 100 requests/day × 365 days = ~511 MB/year
```

---

## Durability and Reliability

### Durability Configuration (rocks.rs:62-73)

```rust
options.set_use_fsync(true);          // ✅ Force disk sync
options.set_manual_wal_flush(false);  // ✅ Auto-flush WAL
options.set_paranoid_checks(true);    // ✅ Detect corruption
```

### Write-Ahead Log (WAL)

- All writes go to WAL before memtable
- WAL flushed to disk before write confirmation
- On crash: RocksDB replays WAL to recover

### Backup and Restore

**Checkpoint Creation (rocks.rs:125-130):**
```rust
storage.create_checkpoint("/path/to/backup")?;
```

**Characteristics:**
- Consistent snapshot (no partial writes)
- Online backup (no downtime)
- Hardlinks used (fast, space-efficient on same filesystem)

---

## Migrations

**Reference:** rocks.rs:138-193

**Status:** Optional, disabled by default

**Enabling:**
```bash
export KASPA_IGRA_ENABLE_MIGRATIONS=true
```

### Migration: Default CF → Specialized CFs

**Process (rocks.rs:150-193):**
1. Scan all keys in `default` CF
2. Determine target CF by key prefix
3. Copy key-value to target CF
4. Delete from `default` CF
5. Atomic commit via WriteBatch

**Safety:**
- Atomic (all-or-nothing)
- Idempotent (can re-run)
- Non-destructive (only recognized prefixes)

---

## Maintenance Operations

### Archival (rocks.rs:378-413)

**Archive Old Requests:**
```rust
let archived = storage.archive_old_requests(cutoff_nanos)?;
```

**Process:**
1. Scan `req:*` keys
2. Check `request.decision == Finalized`
3. If older than cutoff: Copy to `archive:req:*`, delete original

### Archive Deletion (rocks.rs:415-443)

**Delete Old Archives:**
```rust
let deleted = storage.delete_old_archives(cutoff_nanos)?;
```

**Note:** Related records (inputs, sigs) NOT automatically deleted

### Compaction (rocks.rs:445-448)

```rust
storage.compact()?;  // Manual full compaction
```

**When to Use:**
- After bulk deletions
- Before backups
- When read performance degrades

### Seen Message Cleanup (rocks.rs:704-729)

```rust
let deleted = storage.cleanup_seen_messages(cutoff_nanos)?;
```

**Recommended:** Run daily via background task

---

## Operational Procedures

### Health Monitoring (rocks.rs:678-683)

```rust
storage.health_check()?;  // Verify DB accessible
```

**Additional Metrics:**
```rust
db.property_value("rocksdb.stats")?;
db.property_value("rocksdb.estimate-num-keys")?;
db.property_value("rocksdb.block-cache-usage")?;
```

### Backup Schedule

**Recommended:**
- Daily: Incremental checkpoint
- Weekly: Full checkpoint with archival
- Monthly: Off-site backup

### Disaster Recovery

**Corruption Scenario:**
```bash
# 1. Stop service
systemctl stop kaspa-threshold-service

# 2. Backup corrupted database
mv <data_dir>/threshold-signing <data_dir>/threshold-signing.corrupted

# 3. Restore from checkpoint
cp -r /backups/latest <data_dir>/threshold-signing

# 4. Start service
systemctl start kaspa-threshold-service
```

---

## Troubleshooting

### Common Issues

**Issue: "Missing column family: event"**
- **Cause:** Database created before CF migration
- **Solution:** Enable migrations, restart service

**Issue: "EventReplayed" Error**
- **Cause:** Duplicate event insertion
- **Solution:** This is **expected behavior** - replay prevention working correctly

**Issue: Slow Query Performance**
- **Diagnosis:** Check SST file count
- **Solution:** Run manual compaction

**Issue: Database Size Growing**
- **Solution:**
  1. Archive old requests
  2. Delete old archives
  3. Cleanup seen messages
  4. Compact database

---

## Summary

The IGRA database uses RocksDB with **10 column families** to organize threshold signing data with optimal performance and durability. Key features include ACID transactions, lock-free volume tracking, replay prevention, and comprehensive lifecycle management.

**Key Metrics:**
- Point lookups: <1ms
- Writes: 1-5ms (with fsync)
- Space: ~14KB per request
- Durability: fsync + WAL enabled
- Crash recovery: Automatic via WAL replay

**References:**
- Implementation: `igra-core/src/storage/rocks.rs`
- Models: `igra-core/src/model.rs`
- Types: `igra-core/src/types.rs`
- Tests: `igra-service/tests/integration/storage/*.rs`
