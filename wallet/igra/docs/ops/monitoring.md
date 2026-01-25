# Observability (Igra + Hyperlane Integration)

This document describes what can be observed **today** in the current Igra + Hyperlane integration, and what a **production-grade** observability stack should look like to support:

- a dashboard for “what got signed / by whom / when”
- end-to-end delivery monitoring (EVM `Mailbox.dispatch` → Igra verification → Kaspa transaction submission/confirmation)
- incident debugging (stuck deliveries, equivocation, node divergence, relayer failures)

The focus is **operational visibility**; it does not change protocol correctness assumptions.

---

## 1. Scope and components

### 1.1 Runtime components

- **Igra signers**: `igra-service` instances (HTTP API, coordination loop, Kaspa RPC usage, RocksDB storage).
- **Hyperlane agents**:
  - **Validators**: sign origin checkpoints and announce checkpoint storage locations on-chain via `ValidatorAnnounce`.
  - **Relayers**: read checkpoints, build metadata, and deliver messages to the destination chain client (`hyperlane-kaspa` → Igra HTTP).
- **Origin chain**: EVM (Anvil in devnet; any EVM L1/L2 in prod), hosting Hyperlane contracts (Mailbox, hooks, ISM, ValidatorAnnounce).
- **Destination chain**: Kaspa (devnet now), where Igra submits the finalized transaction.
- **Storage/backends**:
  - Igra RocksDB (event CRDT state, completion records, indexing).
  - Hyperlane checkpoint syncer storage (local filesystem in devnet; S3/GCS/etc in prod).

### 1.2 Objects to correlate

To produce useful dashboards, everything should be correlated around stable identifiers:

- `message_id` (Hyperlane): unique ID derived from message content.
- `event_id` (Igra): identifier for the Igra signing session/event (often derived from message fields + policy version).
- `tx_template_hash` (Igra): deterministic hash of the unsigned transaction skeleton for the given round.
- `tx_id` (Kaspa): final broadcast transaction id.
- `checkpoint_index` (Hyperlane): origin chain checkpoint sequence number.

---

## 2. Observability surfaces available today

### 2.1 Health and readiness (service liveness)

Each `igra-service` exposes:

- `GET /health`: process is up.
- `GET /ready`: service is ready to accept work (e.g., storage open, config loaded, loops started).

These are the minimum primitives for process supervision and alerting.

### 2.2 Prometheus metrics (`/metrics`)

Each `igra-service` exposes:

- `GET /metrics`: Prometheus text format.

Existing metrics are oriented around signing flow + storage health (examples):

- `rpc_requests_total{method,status}`
- `signing_sessions_total{stage}` (`proposal_received`, `finalized`, `timed_out`, …)
- `signer_acks_total{accepted}`
- `partial_sigs_total`
- `crdt_event_states_total|pending|completed`
- `crdt_cf_estimated_*` (RocksDB estimates)
- `tx_template_hash_mismatches_total{kind}`

This is already enough to build a basic operational dashboard:

- “Are signers alive and progressing?”
- “Is the system producing sessions and finalizing?”
- “Is storage growing or stuck?”
- “Are template mismatches happening?”

### 2.3 Structured audit events (who signed what)

Igra has an explicit audit stream (`AuditEvent`) that captures key lifecycle points, including identity fields:

- `EventReceived { event_id, source, recipient, amount_sompi, ... }`
- `EventSignatureValidated { event_id, validator_count, valid, ... }`
- `ProposalValidated { event_id, signer_peer_id, accepted, validation_hash, ... }`
- `PartialSignatureCreated { event_id, signer_peer_id, input_count, ... }`
- `TransactionFinalized { event_id, tx_id, signature_count, threshold_required, ... }`
- `TransactionSubmitted { event_id, tx_id, blue_score, ... }`
- `SessionTimedOut { event_id, signature_count, threshold_required, ... }`

These events are emitted as:

- JSON lines (log target `igra::audit::json`) suitable for ingestion into Loki/ELK,
- a human summary (log target `igra::audit::human`) suitable for live tailing,
- optionally a file-backed audit logger (append-only JSONL).

This is the foundation for the “dashboard of what honest signers signed”, because:

- it includes `signer_peer_id` at signature creation time,
- it includes stable identifiers (`event_id`, `tx_id`, timestamps),
- it is produced by each signer independently (useful for cross-checking).

### 2.4 Forensic state inspection (offline)

The `igra-service` binary has an audit/report mode that can dump CRDT state for a given `event_id` directly from RocksDB:

- signatures include `signer_peer_id`, `pubkey`, `signature`, and `input_index`,
- completion record includes `tx_id`, submitter, and timestamps.

This is useful for incident post-mortems and verifying signer claims.

### 2.5 Hyperlane-facing RPC and indexer endpoints

Igra exposes the destination-side API the relayer uses (e.g., `validators_and_threshold`, `mailbox_process`) plus indexer-like endpoints for delivery state. These can also be polled by monitoring to measure:

- message delivery attempts and outcomes,
- delivered/not delivered status per `message_id`,
- message backlog (if any).

### 2.6 “Public” attribution from chains (no signer cooperation required)

Even without cooperation from signers, an external observer can attribute work using public chain data:

- **EVM**: Mailbox emits `Dispatch` (message creation) and `Process` (delivery) events.
- **Hyperlane**: validator signatures are public in checkpoint artifacts (and the validator set is public via `ValidatorAnnounce` + config).
- **Kaspa**: once Igra submits a transaction, the transaction and its signatures are public.

This supports “trust-minimized monitoring”: an observer can infer outcomes without trusting signer telemetry, and use signer telemetry only as a debugging aid.

---

## 3. Production observability architecture (recommended)

### 3.1 Goals

- **Fast diagnosis**: identify whether a stuck delivery is due to origin chain, relayer, Igra verification, Kaspa node, or signer coordination.
- **Attribution**: produce a per-event and per-epoch view of which signer produced which partial signatures and which peer finalized/submitted.
- **SLOs**: measure and alert on end-to-end latency and failure rate.
- **Forensics**: retain evidence (audit logs + CRDT snapshots + chain references) for post-incident analysis.

### 3.2 Metrics stack

- **Prometheus** scrapes:
  - each `igra-service` `/metrics`
  - Hyperlane validator and relayer metrics endpoints (if enabled in their configs)
  - Kaspa node metrics (if exposed)
  - EVM node metrics (optional)
- **Grafana** dashboards:
  - system overview
  - per-signer health
  - delivery latency and failure rate
  - backlog and retry rates

Recommended additions (future) to Igra metrics for Hyperlane flows:

- `hyperlane_mailbox_process_total{status}` (`ok`, `pending`, `error`)
- `hyperlane_verify_total{result}` (`valid`, `invalid`, `threshold_not_met`, ...)
- `hyperlane_messages_delivered_total`
- `hyperlane_messages_duplicate_total`
- `tx_submit_total{result}` (`ok`, `rpc_error`, `rejected`)
- `tx_confirmed_total`
- histograms for:
  - dispatch→delivered latency,
  - delivered→kaspa_broadcast latency,
  - kaspa_broadcast→confirmation latency.

### 3.3 Logs and audit ingestion

- Route `igra::audit::json` to a centralized log pipeline (Loki or ELK).
- Treat the audit JSON stream as a “poor man’s event bus”:
  - parse JSON into fields (`event_id`, `signer_peer_id`, `tx_id`, timestamps),
  - build Grafana dashboards off log queries,
  - alert on error patterns (validation failures, timeouts).

Recommended production log conventions (aligned with `CODE-GUIDELINE.md` intent):

- Always log with identifiers (`event_id`, `message_id`, `tx_template_hash`, `peer_id`).
- Never log binary IDs with `{:?}`; use hex for stable correlation.
- Keep audit logs append-only and immutable (forensics).

### 3.4 Tracing (distributed correlation)

For faster cross-component debugging, add optional distributed tracing:

- propagate an `external_request_id` / correlation ID from:
  - origin ingestion → coordination → signature creation → finalization → submission,
  - HTTP request context in `igra-service` handlers.
- export spans via OpenTelemetry to Tempo/Jaeger.

This is optional but very high leverage once multiple relayers and signers run across machines.

### 3.5 A dedicated observer (optional but recommended): `igra-observer`

To answer “what happened?” without requiring access to signer DBs/logs, introduce a read-only observer service:

**Responsibilities**

- Ingest:
  - EVM Mailbox events (`Dispatch`, `Process`) from an RPC endpoint.
  - Hyperlane checkpoint artifacts from the configured checkpoint syncers.
  - Igra indexer endpoints (delivered status, message list, delivery list).
  - Kaspa transaction status (mempool + confirmation) via Kaspa RPC.
- Correlate into a single model:
  - `message_id` ↔ `event_id` ↔ `tx_template_hash` ↔ `tx_id`
- Expose:
  - Prometheus metrics (derived KPIs/SLOs),
  - a small HTTP UI (or Grafana-friendly endpoints) for drill-down.

**Why this helps**

- avoids coupling monitoring to signer internal state,
- can run independently (no keys, no signing),
- provides a canonical “truth” view derived from chains + minimal APIs.

---

## 4. Dashboards (what we should see)

### 4.1 End-to-end delivery dashboard

- `Dispatch` rate (EVM) vs delivered rate (Igra) vs submitted rate (Kaspa)
- median / p95 latency:
  - dispatch→delivered
  - delivered→kaspa_broadcast
  - kaspa_broadcast→confirmed
- failure counts and top error reasons

### 4.2 Signer dashboard (per `igra-service`)

- health/ready status and uptime
- coordination loop throughput (sessions staged)
- signature production rate
- RPC error rates (Kaspa RPC, peer transport)
- storage growth and GC activity

### 4.3 Ceremony integrity dashboard (coordination + CRDT)

- `tx_template_hash_mismatches_total{kind}` rate (divergence indicator)
- pending CRDT states and their age (stuck sessions)
- timeouts per window
- “fast-forward commit” counts (if used)

### 4.4 Hyperlane validator/relayer dashboard

- checkpoint index progression (validators)
- relayer queue depth and retry rates
- delivered-but-not-confirmed vs confirmed
- validator signature availability (threshold met?)

---

## 5. Attribution: “who signed what”

There are two complementary attribution sources:

### 5.1 Signer-reported attribution (audit + CRDT metadata)

From Igra audit logs and CRDT signature records we can report:

- which `signer_peer_id` created partial signatures for a given `event_id`
- which peer submitted the final transaction (`submitter_peer_id`)
- timestamps for each step

This is the best source for “who contributed” at the Igra protocol layer.

### 5.2 Public attribution (chain-derived)

Even if a signer is malicious or silent, the final artifacts are public:

- **Hyperlane checkpoint signatures**: identify which validator addresses signed a checkpoint (and whether threshold was met).
- **Kaspa transaction**: identify which public keys’ signatures appear in the transaction witness/script.

For classic multisig scripts, attribution can be computed by verifying each signature against the known pubkeys in the redeem/witness script until it matches (careful: signature ordering may not correspond to pubkey ordering; verification is the safe method).

---

## 6. Alerting recommendations

Minimum alert set for production:

- **Signer down**: `/ready` failing or missing Prometheus scrape.
- **Stuck deliveries**: high `pending` rate or backlog age > threshold.
- **High validation failures**: spike in `EventSignatureValidated.valid=false` or mailbox verification failures.
- **Kaspa submission failures**: increased submit RPC errors/rejections.
- **Coordination divergence**: sustained `tx_template_hash_mismatches_total` above baseline.
- **No checkpoint progress**: validator checkpoint index not advancing.
- **Relayer unhealthy**: relayer process down or high retry/error rates.

---

## 7. Practical rollout strategy

1) Start with **Prometheus + Grafana** scraping:
   - `igra-service` `/metrics`
   - Hyperlane agent metrics (if enabled)
2) Add centralized logs with **Loki** and parse `igra::audit::json`.
3) Introduce `igra-observer` once you need:
   - a trust-minimized view,
   - a single place to correlate EVM↔Igra↔Kaspa,
   - long-term analytics and incident timelines.

---

## 8. Open questions (for design review)

- Do we want an HTTP audit API (push or pull), or keep audit as “logs only” for v1?
- How long should audit evidence be retained, and where (S3, database, cold storage)?
- Do we want to expose per-event CRDT summaries over HTTP (read-only), or keep that as an operator-only “audit mode” feature?
- What are the initial SLO targets (p95 end-to-end latency, success rate) for prod?

