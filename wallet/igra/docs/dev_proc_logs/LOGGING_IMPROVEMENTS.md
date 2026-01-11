# Logging Improvements

This document provides specific recommendations for improving log readability and operator experience.

---

## Table of Contents

1. [Current Problems](#current-problems)
2. [Logging Philosophy](#logging-philosophy)
3. [Flow-Based Logging Strategy](#flow-based-logging-strategy)
4. [Specific Recommendations](#specific-recommendations)
5. [Implementation Checklist](#implementation-checklist)

---

## Current Problems

### What's Wrong with Current Logs

Looking at a real production log (`igra-signer-1.log`), we see:

```
2026-01-11T18:20:02.723385Z INFO igra_core::infrastructure::audit: audit audit_event=...
2026-01-11T18:20:02.744114Z INFO igra_service::api::router: starting HTTP server addr="127.0.0.1:18088"
2026-01-11T18:20:02.745226Z INFO kaspa_threshold_service::setup: service ready
2026-01-11T18:20:03.761285Z INFO igra_service::api::router: request addr=127.0.0.1:50339 method=GET path=/rpc status=405 latency_ms=0
2026-01-11T18:20:04.768052Z INFO igra_service::api::router: request addr=127.0.0.1:50340 method=GET path=/rpc status=405 latency_ms=0
... (repeats every second)
2026-01-11T18:20:32.729987Z WARN igra_service::service::coordination::loop: iroh gossip receive timeout elapsed=30.001166s
2026-01-11T18:21:02.732146Z WARN igra_service::service::coordination::loop: iroh gossip receive timeout elapsed=30.002143s
```

**Issues Identified:**

| Problem | Impact |
|---------|--------|
| **Health check spam** | HTTP `GET /rpc` every second drowns important logs |
| **No flow context** | Can't tell what signing session we're in |
| **Cryptic timeouts** | "iroh gossip receive timeout" - is this normal? |
| **Missing business context** | No amounts, recipients, transaction details |
| **No state transitions** | Can't see `Pending → Approved → Finalized` |
| **Audit logs not human-readable** | JSON blobs instead of clear messages |
| **Repeated warnings** | "rpc auth disabled" every startup |
| **No progress indicators** | "Waiting for X more signatures" not shown |

---

## Logging Philosophy

### The Story Logs Should Tell

An operator should be able to read logs and understand:

```
"At 18:20:02, signer-1 received a proposal (session abc123) to sign
10,000 KAS to kaspa:qz... from Hyperlane message 0xdef456.

Signer validated: group_id ✓, event_hash ✓, policy ✓.
Accepted the proposal and submitted partial signature for input 0.

At 18:20:05, coordinator collected 2/3 signatures (threshold met).
Transaction finalized: tx_id=xyz789, blue_score=12345678.

Session completed successfully in 3.2 seconds."
```

### Log Levels

| Level | Use Case |
|-------|----------|
| **ERROR** | Operation failed, intervention required |
| **WARN** | Unexpected but recoverable (policy rejection, timeout) |
| **INFO** | Major flow milestones, state transitions, business events |
| **DEBUG** | Detailed operation progress, per-input processing |
| **TRACE** | Wire-level data, full message dumps |

### Required Context Fields

Every log message should include (via tracing spans):

```rust
#[tracing::instrument(
    skip(storage, transport),
    fields(
        session_id = %session_id,
        request_id = %request_id,
        peer_id = %peer_id,
    )
)]
```

---

## Flow-Based Logging Strategy

### Flow 1: Proposal Reception

**Location:** `igra-service/src/service/coordination/loop.rs`

**Current State:**
```rust
// Line 62 - No log for envelope reception
let Some(event) = result? else { continue };
```

**Recommended:**
```rust
// Flow 1.1: Message received from gossip
info!(
    sender_peer = %envelope.sender,
    message_type = %message_type_name(&msg),
    "received coordination message"
);

// Flow 1.2: Proposal details extracted
info!(
    session_id = %session_id,
    request_id = %request_id,
    recipient = %signing_event.recipient,
    amount_sompi = signing_event.amount_sompi,
    event_source = %signing_event.event_source,
    "processing signing proposal"
);
```

---

### Flow 2: Proposal Validation

**Location:** `igra-core/src/application/signer.rs`

**Current State:**
```rust
// Line 75 - Only logs rejections
warn!("rejecting proposal: group_id_mismatch");
```

**Recommended:**
```rust
// Flow 2.1: Validation started
info!(
    session_id = %session_id,
    checks_to_run = "group_id, event_hash, tx_template, validation_hash, clock_skew, message_sig, policy",
    "starting proposal validation"
);

// Flow 2.2: Each check result (at DEBUG level)
debug!(check = "group_id", result = "pass", "validation check");
debug!(check = "event_hash", result = "pass", "validation check");

// Flow 2.3: Final validation result
if accepted {
    info!(
        session_id = %session_id,
        decision = "ACCEPT",
        checks_passed = checks_passed,
        "proposal validation complete"
    );
} else {
    warn!(
        session_id = %session_id,
        decision = "REJECT",
        reason = %reason,
        failed_check = %failed_check,
        "proposal validation failed"
    );
}
```

---

### Flow 3: Signature Collection

**Location:** `igra-service/src/service/coordination/finalization.rs`

**Current State:**
```rust
// Line 136 - Silent collection
if count_changed {
    // No log
}
```

**Recommended:**
```rust
// Flow 3.1: Collection started
info!(
    session_id = %session_id,
    required_signatures = threshold_m,
    input_count = input_count,
    timeout_seconds = session_timeout,
    "starting signature collection"
);

// Flow 3.2: Progress updates (rate-limited)
info!(
    session_id = %session_id,
    collected = current_count,
    required = threshold_m,
    from_peer = %signer_peer_id,
    remaining = threshold_m - current_count,
    "signature received"
);

// Flow 3.3: Threshold reached
info!(
    session_id = %session_id,
    collected = current_count,
    required = threshold_m,
    collection_time_ms = elapsed.as_millis(),
    "signature threshold reached"
);

// Flow 3.4: Timeout
warn!(
    session_id = %session_id,
    collected = current_count,
    required = threshold_m,
    missing_signers = ?missing_peers,
    "signature collection timed out"
);
```

---

### Flow 4: Transaction Finalization

**Location:** `igra-service/src/service/coordination/finalization.rs`

**Current State:**
```rust
// Line 227 - Minimal logging
info!("transaction submitted");
```

**Recommended:**
```rust
// Flow 4.1: Finalization started
info!(
    session_id = %session_id,
    signatures_collected = sig_count,
    "starting transaction finalization"
);

// Flow 4.2: PSKT finalized
info!(
    session_id = %session_id,
    input_count = input_count,
    output_count = output_count,
    total_sompi = total_output_sompi,
    "PSKT finalized"
);

// Flow 4.3: Transaction submission
info!(
    session_id = %session_id,
    tx_id = %tx_id,
    blue_score = blue_score,
    attempt = attempt_num,
    "transaction submitted to network"
);

// Flow 4.4: Session complete
info!(
    session_id = %session_id,
    tx_id = %tx_id,
    recipient = %recipient,
    amount_sompi = amount_sompi,
    total_time_ms = session_duration.as_millis(),
    outcome = "FINALIZED",
    "signing session complete"
);
```

---

### Flow 5: State Transitions

**Location:** `igra-core/src/domain/request/state_machine.rs`

**Current State:**
```rust
// No transition logging
```

**Recommended:**
```rust
// Flow 5.1: Every state transition
info!(
    session_id = %session_id,
    from_state = %from_state,
    to_state = %to_state,
    reason = %reason,
    "request state transition"
);
```

---

## Specific Recommendations

### 1. Suppress Health Check Spam

**File:** `igra-service/src/api/router.rs`

**Current:**
```rust
// Logs every request including health checks
info!(
    addr = %addr,
    method = %method,
    path = %path,
    status = %status,
    latency_ms = latency_ms,
    "request"
);
```

**Recommended:**
```rust
// Skip health check endpoints at INFO level
let should_log = match path.as_str() {
    "/health" | "/ready" | "/rpc" if method == "GET" && status == 200 => false,
    _ => true,
};

if should_log {
    info!(
        addr = %addr,
        method = %method,
        path = %path,
        status = %status,
        latency_ms = latency_ms,
        "request"
    );
} else {
    trace!(
        addr = %addr,
        method = %method,
        path = %path,
        status = %status,
        latency_ms = latency_ms,
        "health check"
    );
}
```

### 2. Add Idle Status Indicator

**File:** `igra-service/src/service/coordination/loop.rs`

**Current:**
```rust
// Line 63 - Silent wait, then cryptic timeout warning
warn!("iroh gossip receive timeout");
```

**Recommended:**
```rust
// Replace timeout warning with idle status
if elapsed > Duration::from_secs(30) {
    info!(
        idle_seconds = elapsed.as_secs(),
        group_id = %hex::encode(&group_id[..8]),
        "waiting for signing proposals (service idle)"
    );
}
```

### 3. Add Session Summary Log

**File:** `igra-service/src/service/coordination/finalization.rs`

At end of `collect_and_finalize()`:

```rust
// Always log session outcome
match outcome {
    SessionOutcome::Finalized { tx_id, blue_score, duration } => {
        info!(
            session_id = %session_id,
            tx_id = %tx_id,
            recipient = %recipient,
            amount_kas = amount_sompi as f64 / 100_000_000.0,
            signers_participated = signer_count,
            blue_score = blue_score,
            duration_ms = duration.as_millis(),
            outcome = "SUCCESS",
            "=== SESSION COMPLETE ==="
        );
    }
    SessionOutcome::Timeout { collected, required } => {
        warn!(
            session_id = %session_id,
            signatures_collected = collected,
            signatures_required = required,
            missing_count = required - collected,
            outcome = "TIMEOUT",
            "=== SESSION FAILED ==="
        );
    }
    SessionOutcome::Rejected { reason } => {
        warn!(
            session_id = %session_id,
            reason = %reason,
            outcome = "REJECTED",
            "=== SESSION FAILED ==="
        );
    }
}
```

### 4. Make Audit Logs Human-Readable

**File:** `igra-core/src/infrastructure/audit/mod.rs`

Add a human-readable summary alongside structured data:

```rust
impl AuditLogger for StructuredAuditLogger {
    fn log(&self, event: &AuditEvent) {
        // Structured JSON for parsing (current behavior)
        info!(target: "igra::audit::json", audit_event = ?event);

        // Human-readable summary at INFO level
        let summary = match &event.event_type {
            AuditEventType::SigningEventReceived { event_hash, amount_sompi, recipient, .. } => {
                format!(
                    "AUDIT: Signing event received - {} KAS to {} (hash: {})",
                    *amount_sompi as f64 / 100_000_000.0,
                    recipient,
                    &hex::encode(event_hash)[..16]
                )
            }
            AuditEventType::ProposalAccepted { session_id, .. } => {
                format!("AUDIT: Proposal accepted (session: {})", &hex::encode(session_id)[..16])
            }
            AuditEventType::ProposalRejected { session_id, reason, .. } => {
                format!("AUDIT: Proposal rejected - {} (session: {})", reason, &hex::encode(session_id)[..16])
            }
            AuditEventType::TransactionFinalized { tx_id, blue_score, .. } => {
                format!("AUDIT: Transaction finalized - tx:{} at blue_score:{}", tx_id, blue_score)
            }
            _ => format!("AUDIT: {:?}", event.event_type),
        };
        info!(target: "igra::audit::human", "{}", summary);
    }
}
```

### 5. Add Startup Banner

**File:** `igra-service/src/bin/kaspa-threshold-service/setup.rs`

After config loaded:

```rust
pub fn log_startup_banner(config: &AppConfig, peer_id: &PeerId) {
    info!("╔════════════════════════════════════════════════════════════╗");
    info!("║              IGRA Threshold Signing Service                ║");
    info!("╠════════════════════════════════════════════════════════════╣");
    info!("║ Peer ID:     {} ║", peer_id);
    info!("║ Group ID:    {} ║", config.iroh.group_id.as_deref().unwrap_or("not set"));
    info!("║ Threshold:   {}/{} signers                                  ║",
          config.group.as_ref().map(|g| g.threshold_m).unwrap_or(0),
          config.group.as_ref().map(|g| g.threshold_n).unwrap_or(0));
    info!("║ Network:     {} ║",
          if config.service.node_rpc_url.contains("16110") { "mainnet" }
          else if config.service.node_rpc_url.contains("16210") { "testnet" }
          else { "devnet" });
    info!("║ RPC:         {} ║", config.rpc.addr);
    info!("╚════════════════════════════════════════════════════════════╝");
}
```

### 6. Periodic Status Log

Add a background task that logs service status every 5 minutes:

```rust
async fn status_reporter(state: Arc<ServiceState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;

        let stats = state.get_stats().await;
        info!(
            uptime_minutes = stats.uptime.as_secs() / 60,
            sessions_total = stats.sessions_total,
            sessions_finalized = stats.sessions_finalized,
            sessions_failed = stats.sessions_failed,
            signatures_produced = stats.signatures_produced,
            pending_sessions = stats.pending_sessions,
            "periodic status report"
        );
    }
}
```

---

## Implementation Checklist

### Phase 1: Quick Wins (Low Risk)

- [ ] Suppress health check spam in `api/router.rs`
- [ ] Replace timeout warnings with idle status in `coordination/loop.rs`
- [ ] Add startup banner in `setup.rs`
- [ ] Add session outcome summary in `finalization.rs`

### Phase 2: Flow Instrumentation

- [ ] Add `#[tracing::instrument]` to all major functions with session_id/request_id
- [ ] Add proposal reception logs in `coordination/loop.rs`
- [ ] Add validation check progress in `signer.rs`
- [ ] Add signature collection progress in `finalization.rs`

### Phase 3: State Machine

- [ ] Add state transition logging in `state_machine.rs`
- [ ] Track and log transition reasons
- [ ] Add duration tracking for each state

### Phase 4: Audit Improvements

- [ ] Add human-readable audit summaries
- [ ] Ensure all audit events include session_id
- [ ] Add audit log rotation configuration

### Phase 5: Operational

- [ ] Add periodic status reporter task
- [ ] Add graceful shutdown logging
- [ ] Document log format for operators

---

## Example: Before and After

### Before (Current)
```
2026-01-11T18:20:02.723Z INFO  audit audit_event={...long json...}
2026-01-11T18:20:02.744Z INFO  starting HTTP server addr="127.0.0.1:18088"
2026-01-11T18:20:02.745Z INFO  service ready
2026-01-11T18:20:03.761Z INFO  request method=GET path=/rpc status=405
2026-01-11T18:20:04.768Z INFO  request method=GET path=/rpc status=405
2026-01-11T18:20:32.729Z WARN  iroh gossip receive timeout elapsed=30s
```

### After (Improved)
```
2026-01-11T18:20:02.700Z INFO  ╔════════════════════════════════════════════════════════════╗
2026-01-11T18:20:02.700Z INFO  ║              IGRA Threshold Signing Service                ║
2026-01-11T18:20:02.700Z INFO  ╠════════════════════════════════════════════════════════════╣
2026-01-11T18:20:02.700Z INFO  ║ Peer ID:     peer-signer-1                                 ║
2026-01-11T18:20:02.700Z INFO  ║ Group ID:    abc123...                                     ║
2026-01-11T18:20:02.700Z INFO  ║ Threshold:   2/3 signers                                   ║
2026-01-11T18:20:02.700Z INFO  ║ Network:     devnet                                        ║
2026-01-11T18:20:02.700Z INFO  ║ RPC:         127.0.0.1:18088                               ║
2026-01-11T18:20:02.700Z INFO  ╚════════════════════════════════════════════════════════════╝
2026-01-11T18:20:02.723Z INFO  AUDIT: Service started (peer: peer-signer-1)
2026-01-11T18:20:02.744Z INFO  HTTP server listening addr="127.0.0.1:18088"
2026-01-11T18:20:02.745Z INFO  coordination loop started group_id=abc123
2026-01-11T18:20:32.729Z INFO  waiting for signing proposals (service idle) idle_seconds=30

--- SIGNING SESSION STARTS ---

2026-01-11T18:25:01.100Z INFO  received coordination message sender_peer=coordinator message_type=SigningEventPropose
2026-01-11T18:25:01.101Z INFO  processing signing proposal session_id=def456 recipient=kaspa:qz... amount_sompi=1000000000 event_source=hyperlane
2026-01-11T18:25:01.102Z INFO  starting proposal validation session_id=def456
2026-01-11T18:25:01.105Z INFO  proposal validation complete session_id=def456 decision=ACCEPT checks_passed=7
2026-01-11T18:25:01.106Z INFO  AUDIT: Proposal accepted (session: def456)
2026-01-11T18:25:01.108Z INFO  submitting partial signature session_id=def456 input_index=0
2026-01-11T18:25:01.150Z INFO  signature received session_id=def456 collected=1 required=2 from_peer=signer-1
2026-01-11T18:25:01.250Z INFO  signature received session_id=def456 collected=2 required=2 from_peer=signer-2
2026-01-11T18:25:01.251Z INFO  signature threshold reached session_id=def456 collected=2 required=2 collection_time_ms=143
2026-01-11T18:25:01.300Z INFO  PSKT finalized session_id=def456 input_count=1 output_count=2
2026-01-11T18:25:01.500Z INFO  transaction submitted session_id=def456 tx_id=xyz789 blue_score=12345678
2026-01-11T18:25:01.501Z INFO  AUDIT: Transaction finalized - tx:xyz789 at blue_score:12345678
2026-01-11T18:25:01.502Z INFO  === SESSION COMPLETE === session_id=def456 tx_id=xyz789 recipient=kaspa:qz... amount_kas=10.0 duration_ms=402 outcome=SUCCESS
```

---

## Summary

| Change | Files | Lines Changed | Impact |
|--------|-------|---------------|--------|
| Suppress health checks | router.rs | ~10 | High (noise reduction) |
| Idle status indicator | loop.rs | ~5 | High (operator clarity) |
| Session summary | finalization.rs | ~30 | High (outcome visibility) |
| Startup banner | setup.rs | ~15 | Medium (initial context) |
| Validation progress | signer.rs | ~20 | Medium (debug clarity) |
| Signature progress | finalization.rs | ~15 | High (progress visibility) |
| Human audit logs | audit/mod.rs | ~40 | Medium (readability) |
| Periodic status | new task | ~30 | Medium (operational) |

**Total estimated changes:** ~165 lines
**Impact:** Transform logs from cryptic noise to operational story
