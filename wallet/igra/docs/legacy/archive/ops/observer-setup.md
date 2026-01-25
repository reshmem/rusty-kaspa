# Igra-Observer (Read-Only Monitoring Service)

This document specifies a new component, **igra-observer**, whose job is to provide a single, trust-minimized operational view of:

- EVM Hyperlane message production (`Mailbox.dispatch`)
- delivery attempts into Igra (`mailbox_process` effects, delivered state, indexing)
- Kaspa transaction submission/confirmation
- “who signed what” attribution, using **public artifacts** (and optionally signer audit telemetry)

It is designed to be **read-only** (no signing keys, no chain writes).

---

## 1. Goals

- Provide a **dashboard backend** for operators:
  - what messages exist, their status, and end-to-end latency
  - what Kaspa tx corresponds to each Hyperlane message
  - which validator/signer identities contributed (best-effort)
- Support **multi-signer deployments** (N Igra signers) and tolerate temporary divergence.
- Derive a canonical timeline from **public sources**:
  - EVM logs + Hyperlane checkpoint artifacts + Kaspa transaction state
- Export **Prometheus metrics** and a small **query API** for Grafana/UI.

---

## 2. Non-goals (v1)

- Not a relayer, not a validator, and does not submit transactions.
- Not a replacement for centralized log aggregation (though it can optionally ingest audit JSONL).
- No “automatic remediation” (restarts, replays) in v1—observe and alert only.

---

## 3. Inputs and data sources

### 3.1 EVM origin (Hyperlane)

Sources:

- EVM JSON-RPC (WebSocket optional):
  - `eth_getLogs` for Mailbox events
  - `eth_getBlockByNumber` for block timestamps

Primary events:

- `Mailbox.dispatch(...)` (creates a message; provides `message_id`, nonce, origin/destination)
- (optional) `Mailbox.process(...)` (delivery occurred on-chain; depends on deployment topology)

### 3.2 Hyperlane checkpoint artifacts

Sources (depending on deployment):

- local filesystem (`file://...`) in devnet
- S3/GCS/HTTP in prod (as configured for validators)

Used for:

- checkpoint index progression per validator
- extracting validator signatures per checkpoint (attribution)
- verifying that a given `message_id` was part of a committed checkpoint root (optional, but valuable)

### 3.3 Igra (destination API surface)

Sources:

- Igra Hyperlane-compatible endpoints (read-only calls):
  - `GET /rpc/mailbox/delivered/:message_id`
  - `GET /rpc/indexer/messages?from=&to=`
  - `GET /rpc/indexer/deliveries?from=&to=`
  - `GET /rpc/indexer/sequence_tip`
  - `GET /rpc/indexer/finalized_block`

Observer should support polling **multiple** `igra-service` instances and merging results (see §5.4).

### 3.4 Kaspa chain (finality + attribution)

Sources:

- Kaspa node RPC (existing read calls used by Igra are sufficient):
  - `get_transaction` (by tx id) to confirm existence / acceptance
  - `get_server_info` or virtual DAA score for “finalized” heuristics
  - `get_balance` (optional KPI)

Used for:

- mempool inclusion vs confirmation metrics
- (optional) extracting the signature/public-key material from the transaction to attribute signers (depends on script type)

---

## 4. Outputs

### 4.1 Prometheus metrics

At minimum:

- `igra_observer_up{component=...}` gauges for each poller
- message lifecycle counters:
  - `igra_observer_messages_seen_total`
  - `igra_observer_messages_delivered_total`
  - `igra_observer_messages_submitted_total`
  - `igra_observer_messages_confirmed_total`
- error counters by subsystem:
  - `igra_observer_evm_errors_total{kind}`
  - `igra_observer_igra_errors_total{kind,signer}`
  - `igra_observer_kaspa_errors_total{kind}`
- latency histograms (recommended):
  - `igra_observer_dispatch_to_delivered_seconds`
  - `igra_observer_delivered_to_broadcast_seconds`
  - `igra_observer_broadcast_to_confirmed_seconds`

### 4.2 Query API (for UI/Grafana)

Minimal REST (JSON), read-only:

- `GET /health`, `GET /ready`, `GET /metrics`
- `GET /v1/messages?status=&from_ts=&to_ts=&limit=&cursor=`
- `GET /v1/messages/:message_id`
- `GET /v1/events/:event_id` (if we can map message_id → event_id)
- `GET /v1/signers` (configured Igra signers and their last-seen status)
- `GET /v1/validators` (configured Hyperlane validators + checkpoint progress)

The API should be designed so it can be backed by either:

- embedded DB (SQLite/RocksDB) in v1, or
- Postgres in a later stage.

---

## 5. Internal model

### 5.1 Core entity: ObservedMessage

The observer’s central record is an **ObservedMessage** keyed by `message_id` (32 bytes).

Suggested fields (conceptual):

- **Identity**
  - `message_id`
  - `origin_domain`, `destination_domain`
  - `nonce`
  - `sender` (bytes32)
  - `recipient` (bytes32)
- **Payload**
  - `body` (hex/base64) + parsed `(kaspa_address, amount)` when applicable
- **Timeline**
  - `evm_dispatch_block`, `evm_dispatch_tx_hash`, `evm_dispatch_ts`
  - `checkpoint_index` (if known), `checkpoint_root` (if known)
  - `igra_delivered_first_seen_ts` (+ per-signer first-seen if tracking)
  - `kaspa_tx_id` (if known), `kaspa_broadcast_first_seen_ts`
  - `kaspa_confirmed_ts` and chosen confirmation metric (e.g., DAA score)
- **Attribution (best-effort)**
  - `validator_signers`: list of validator addresses (or pubkeys) that signed the checkpoint (if parsed)
  - `kaspa_signers`: list of pubkeys that appear in the final transaction (if derivable)
- **Status**
  - `Observed` → `Checkpointed` → `DeliveredToIgra` → `BroadcastOnKaspa` → `Confirmed`
  - plus failure annotations (see §5.3)

### 5.2 Mapping message_id → event_id

In Igra’s current Hyperlane integration, `message_id` is stored as the event’s external identifier; therefore, the mapping can be derived from:

- Igra indexer `messages` records (contains `message_id`, tx_id/daa/log_index, etc.), or
- observer-side recomputation of `event_id` (only if the derivation is stable and exposed).

For v1, prefer using Igra’s indexer output as the source of truth.

### 5.3 Failure classification

To support actionable alerts, normalize failures into a small set of classes:

- `OriginRpcUnavailable` (EVM RPC down)
- `CheckpointUnavailable` (cannot fetch artifacts)
- `ValidatorThresholdNotMet` (checkpoint has insufficient signatures)
- `DestinationRpcUnavailable` (Igra API down)
- `DeliveryStuck` (dispatch exists, but delivered never becomes true within SLA)
- `KaspaBroadcastFailed` / `KaspaRpcUnavailable`
- `KaspaConfirmationStuck`

These are observer-side diagnoses; they do not change protocol behavior.

### 5.4 Multi-signer merge semantics (Igra polling)

Observer polls multiple `igra-service` instances and merges by `message_id`:

- **Delivered**: treat as delivered if *any* signer reports delivered, but retain per-signer results for debugging.
- **Tx association**: if multiple signers report different `tx_id` for the same `message_id`, treat as anomaly and raise an alert (should not happen if the protocol is safe and convergent).
- **First-seen timestamps**: keep both global first-seen and per-signer first-seen.

---

## 6. Where to put the code (crate layout)

Add a new binary crate next to existing crates:

```
igra/
  igra-core/
  igra-service/
  igra-observer/          # NEW
    Cargo.toml
    src/
      api/
        router.rs
        handlers/
          health.rs
          messages.rs
          signers.rs
          validators.rs
      service/
        mod.rs
        metrics.rs
        store.rs
        pollers/
          evm.rs
          hyperlane_checkpoints.rs
          igra_indexer.rs
          kaspa.rs
      bin/
        igra-observer.rs
```

Workspace wiring (in the parent workspace `Cargo.toml`):

- add `igra-observer` as a member and build target.

`igra-observer` dependencies should follow `CODE-GUIDELINE.md`:

- structured errors (add new `ThresholdError` variants if reusing `igra-core`, or define an observer-local error enum)
- no `unwrap()`/`expect()` in non-test code
- log identifiers in hex / stable formats

---

## 7. How to build it (implementation sketch)

### 7.1 Runtime

- Tokio async runtime.
- HTTP server (Axum) exposing `/health`, `/ready`, `/metrics`, `/v1/*`.
- Background pollers with bounded concurrency and explicit timeouts.

### 7.2 Storage

Two viable v1 options:

**Option A (simplest): SQLite**

- Good for local development and easy queries for UI/dashboards.
- Schema keyed by `message_id` with secondary indices on timestamps/status.

**Option B (consistent with Igra storage): RocksDB**

- Reuse patterns familiar from Igra, very fast key-value.
- Queries for dashboards require extra indexing tables (more work).

Recommendation: start with SQLite for the observer.

### 7.3 Pollers

Implement pollers as independent modules:

- `evm` poller:
  - maintains last processed block
  - ingests Mailbox `Dispatch` logs into `ObservedMessage`
- `hyperlane_checkpoints` poller:
  - tracks validators and their announced checkpoint syncer locations (if configured)
  - downloads newest checkpoint metadata and extracts signer identities
- `igra_indexer` poller:
  - polls each signer’s `/rpc/indexer/*` endpoints
  - merges deliveries/messages into the store
- `kaspa` poller:
  - for messages with known `tx_id`, queries Kaspa RPC for status and confirmation

Each poller should update metrics:

- last successful sync timestamp
- errors_total by kind

---

## 8. Configuration

Suggested config file: `config/observer.toml` (or YAML), containing:

- `evm`:
  - `rpc_url`
  - `mailbox_address`
  - `from_block` (optional), `poll_interval_seconds`
- `hyperlane`:
  - `origin_domain`
  - `validator_announce_address`
  - `checkpoint_syncers` (optional explicit list; in prod you might also read from chain)
- `igra`:
  - `signer_urls = [ "http://127.0.0.1:8088", ... ]`
  - `rpc_token` (if required by the indexer endpoints)
- `kaspa`:
  - `rpc_url` (or node endpoints)
  - finality heuristic parameters
- `storage`:
  - `sqlite_path` (or rocks path)
- `api`:
  - `listen_addr`

Devnet should keep everything under the existing `--root` tree (same approach as `run_local_devnet.sh`).

---

## 9. “Who signed what” attribution strategy

### 9.1 Hyperlane validators

Goal: show which validators signed the checkpoint that attested the message.

Approach:

- fetch checkpoint artifact containing signatures (as produced by validators)
- map signature → validator address (or pubkey) and compare to configured validator set
- store `validator_signers` on the message record

This is fully public and does not require access to relayer internal state.

### 9.2 Igra/Kaspa signers

Goal: show which Igra signers’ pubkeys appear in the finalized Kaspa transaction.

Approach options:

- **Chain-derived (preferred, trust-minimized):**
  - fetch the Kaspa transaction by `tx_id`
  - parse the script/witness and verify signatures against the known group pubkeys
  - record the matching pubkeys as `kaspa_signers`
- **Signer-telemetry (optional):**
  - ingest signer audit JSONL (centralized logs) and map `PartialSignatureCreated` / `TransactionFinalized` into per-signer contributions

Note: chain-derived extraction depends on the exact Kaspa transaction format and script type; it should be implemented carefully and tested against real transactions.

---

## 10. Rollout plan (incremental)

1) **v0 (no DB):** in-memory store + `/metrics` + `/v1/messages` for last N messages.
2) **v1:** SQLite-backed store + EVM dispatch poller + Igra indexer poller + Kaspa tx status poller.
3) **v1.1:** Hyperlane checkpoint poller + validator attribution.
4) **v1.2:** optional signer-audit ingestion (log tailing or push API).

---

## 11. Open questions (before coding)

- Should observer trust Igra’s indexer `tx_id` association as canonical, or attempt to independently compute/verify it from chain?
- What finality metric do we want for Kaspa in prod dashboards (DAA score delta, blue score, time)?
- Do we want to require auth tokens to query Igra indexer endpoints from observer in prod?
- Which persistence backend do we prefer for v1: SQLite (simpler queries) vs RocksDB (consistent with Igra)?

