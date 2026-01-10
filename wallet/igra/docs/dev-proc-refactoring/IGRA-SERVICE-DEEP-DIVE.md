# Igra-Service Deep Dive: Custody Infrastructure Analysis

**Document ID**: CUSTODY-ARCH-001
**Classification**: Internal Security Review
**Status**: Actionable Findings
**Created**: 2026-01-10
**Perspective**: Senior Custody Infrastructure Architect

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Threat Model Assessment](#threat-model-assessment)
3. [Component Analysis](#component-analysis)
   - [JSON-RPC API (json_rpc.rs)](#json-rpc-api-json_rpcrs)
   - [Coordination Loop](#coordination-loop)
   - [Service Flow & Orchestration](#service-flow--orchestration)
   - [Configuration & Identity Management](#configuration--identity-management)
4. [Security Analysis](#security-analysis)
5. [Policy Enforcement Review](#policy-enforcement-review)
6. [Audit Trail Assessment](#audit-trail-assessment)
7. [Cross-Chain Bridge Integration (Hyperlane)](#cross-chain-bridge-integration-hyperlane)
8. [Critical Findings](#critical-findings)
9. [Recommendations](#recommendations)
10. [Architecture Restructuring Proposal](#architecture-restructuring-proposal)

---

## Executive Summary

### Current State

`igra-service` is a **deployment layer** for the Igra threshold signing service. It provides:

- JSON-RPC API for signing event submission
- Hyperlane bridge integration (cross-chain message verification)
- Iroh gossip-based signer coordination
- Prometheus metrics and health endpoints
- Configuration management and identity initialization

### Assessment Summary

| Category | Rating | Notes |
|----------|--------|-------|
| **Key Management** | **NEEDS WORK** | See `KEY-MANAGEMENT.md` |
| **API Security** | **ADEQUATE** | Token auth present, constant-time comparison |
| **Policy Enforcement** | **GOOD** | Destination allowlist, velocity limits, amount bounds |
| **Audit Trail** | **ADEQUATE** | Structured JSON logging, but no tamper-evidence |
| **Replay Protection** | **GOOD** | Event hash deduplication in storage |
| **Cross-Chain Security** | **GOOD** | Merkle proof verification, validator quorum |
| **Transport Security** | **ADEQUATE** | Ed25519 message signing, but no encryption at rest |
| **Code Organization** | **NEEDS WORK** | Monolithic json_rpc.rs (737 lines), mixed concerns |

### Top 3 Risks

1. **No rate limiting on RPC endpoint** - DoS vector on signing event submission
2. **Monolithic API handler** - Security-critical code mixed with protocol parsing
3. **No TLS enforcement** - Credentials visible on network

---

## Threat Model Assessment

### Assets Under Protection

| Asset | Value | Location |
|-------|-------|----------|
| Signing key shares | **CRITICAL** | See `KEY-MANAGEMENT.md` |
| Group policies | HIGH | RocksDB storage |
| Audit logs | HIGH | tracing output, storage |
| Session state | MEDIUM | In-memory + RocksDB |

### Threat Actors

| Actor | Capability | Primary Attack Vector |
|-------|-----------|----------------------|
| External Attacker | Network access | RPC exploitation, DoS |
| Malicious Coordinator | Protocol-level | Tampered PSKT proposals |
| Compromised Signer | Key access | Unauthorized signing |
| Insider (Operator) | Config access | Key exfiltration |
| Bridge Attacker | Cross-chain | Forged Hyperlane messages |

### Attack Surfaces

```
                                    ┌─────────────────────┐
                                    │   External APIs     │
                                    │  (Hyperlane, LZ)    │
                                    └──────────┬──────────┘
                                               │
┌──────────────┐    ┌──────────────┐    ┌──────▼──────────┐
│   Operator   │───▶│  Config/INI  │───▶│   JSON-RPC API  │◀──── Internet
│   (Insider)  │    │  Key Seeds   │    │    :8080/rpc    │
└──────────────┘    └──────────────┘    └──────┬──────────┘
                                               │
                           ┌───────────────────┼───────────────────┐
                           │                   │                   │
                    ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
                    │   Storage   │     │    Iroh     │     │   Kaspa    │
                    │  (RocksDB)  │     │   Gossip    │     │    Node    │
                    └─────────────┘     └─────────────┘     └─────────────┘
```

---

## Component Analysis

### JSON-RPC API (json_rpc.rs)

**Location**: `igra-service/src/api/json_rpc.rs`
**Lines**: 737
**Complexity**: HIGH - Multiple concerns mixed

#### Current Structure

```rust
// Current API endpoints
POST /rpc           - JSON-RPC dispatch (signing_event.submit, hyperlane.*)
GET  /health        - Basic health check
GET  /ready         - Readiness check (storage + node connectivity)
GET  /metrics       - Prometheus metrics
```

#### Security-Relevant Code

**Authentication** (lines 678-701):
```rust
fn authorize_rpc(headers: &HeaderMap, expected: Option<&str>) -> Result<(), String> {
    // ✅ GOOD: Constant-time comparison
    if constant_time_eq(token, expected) { return Ok(()); }
    // ...
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()  // ✅ Using subtle crate
}
```

**Hyperlane Proof Verification** (lines 612-664):
```rust
match ism.verify_proof(&message, &metadata, mode.clone()) {
    Ok(report) => {
        // ✅ GOOD: Derives session_id deterministically from group_id + message_id
        let session_id = derive_session_id_hex(state.group_id_hex.as_deref(), report.message_id);
        // ...
    }
}
```

#### Issues Identified

| Issue | Severity | Line | Description |
|-------|----------|------|-------------|
| **No rate limiting** | HIGH | 442-676 | RPC handler has no request rate limiting |
| **Monolithic handler** | MEDIUM | 442-676 | 234-line switch statement for method dispatch |
| **Hyperlane watcher reads files** | MEDIUM | 408-440 | File-based event ingestion (race conditions) |
| **Hard-coded expiry** | LOW | 386 | `10 * 60 * 1_000_000_000` ns hardcoded |
| **No request ID validation** | LOW | 449-484 | `signing_event.submit` accepts arbitrary request_id |

#### Recommended Refactoring

```
igra-service/src/api/
├── mod.rs                      # Module exports
├── router.rs                   # Axum router setup
├── auth/
│   ├── mod.rs
│   ├── token.rs               # Token validation
│   └── rate_limit.rs          # Rate limiting middleware
├── handlers/
│   ├── mod.rs
│   ├── signing_event.rs       # signing_event.submit
│   ├── hyperlane.rs           # hyperlane.* methods
│   ├── health.rs              # Health/ready/metrics
│   └── middleware.rs          # Logging, metrics
├── types/
│   ├── mod.rs
│   ├── requests.rs            # Request DTOs
│   └── responses.rs           # Response DTOs
└── hyperlane/
    ├── mod.rs
    ├── watcher.rs             # File watcher (move from json_rpc.rs)
    └── message_parser.rs      # Message extraction
```

---

### Coordination Loop

**Location**: `igra-service/src/service/coordination.rs`
**Lines**: 474
**Role**: Main event loop for signer coordination

#### Security-Critical Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    COORDINATION LOOP FLOW                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Subscribe to group topic (Iroh gossip)                          │
│                          │                                          │
│                          ▼                                          │
│  2. Receive proposal (TransportMessage::SigningEventPropose)        │
│                          │                                          │
│                          ▼                                          │
│  3. Build validation request (ProposalValidationRequestBuilder)     │
│                          │                                          │
│                          ▼                                          │
│  4. Validate proposal (signer.validate_proposal)                    │
│      ├─ Event hash verification (constant-time)    ✅               │
│      ├─ TX template hash verification              ✅               │
│      ├─ Validation hash verification               ✅               │
│      ├─ Expiry window check                        ✅               │
│      ├─ Policy enforcement                         ✅               │
│      └─ Message verifier (Hyperlane/LayerZero)     ✅               │
│                          │                                          │
│                          ▼                                          │
│  5. Submit acknowledgment (transport.publish_ack)                   │
│                          │                                          │
│                          ▼                                          │
│  6. If coordinator: spawn collect_and_finalize()                    │
│      ├─ Wait for threshold signatures                               │
│      ├─ Apply partial sigs to PSKT                                  │
│      ├─ Finalize and submit to Kaspa node                          │
│      └─ Publish finalize notice                                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

#### Security Controls Present

| Control | Implementation | Assessment |
|---------|----------------|------------|
| **Hash verification** | `ct_eq` (constant-time) | ✅ Correct |
| **Expiry bounds** | MIN/MAX_SESSION_DURATION_NS | ✅ Prevents unbounded sessions |
| **Policy enforcement** | `DefaultPolicyEnforcer` | ✅ Destination allowlist, velocity limits |
| **Message authentication** | Ed25519 signatures on transport | ✅ Peer identity verified |
| **Tampered PSKT detection** | tx_template_hash comparison | ✅ Tests confirm rejection |
| **Replay prevention** | Event hash stored before processing | ✅ Tests confirm rejection |

#### Issues Identified

| Issue | Severity | Line | Description |
|-------|----------|------|-------------|
| **Session dedup in-memory only** | MEDIUM | 210-222 | `active_sessions` HashSet lost on restart |
| **No coordinator election** | MEDIUM | 168-204 | First to receive is coordinator (race) |
| **Signature threshold hardcoded** | LOW | 240-244 | From config, but no runtime validation |

---

### Service Flow & Orchestration

**Location**: `igra-service/src/service/flow.rs`
**Lines**: 169
**Role**: Wires together Coordinator, Storage, Transport, RPC

#### Architecture

```rust
pub struct ServiceFlow {
    coordinator: Coordinator,      // From igra_core::application
    storage: Arc<dyn Storage>,     // RocksDB via trait
    transport: Arc<dyn Transport>, // Iroh via trait
    rpc: Arc<dyn NodeRpc>,         // Kaspa gRPC via trait
    metrics: Arc<Metrics>,         // Prometheus
    lifecycle: Arc<dyn LifecycleObserver>,
}
```

#### Assessment

**GOOD**:
- Clean separation via traits (`Storage`, `Transport`, `NodeRpc`)
- Lifecycle hooks for extensibility
- Metrics integration

**NEEDS WORK**:
- `resolve_pskt_config` duplicates logic from core
- No circuit breaker for Kaspa RPC failures
- No backpressure on proposal processing

---

### Configuration & Identity Management

**Location**: `igra-service/src/bin/kaspa-threshold-service/setup.rs`

> **Key Management**: All identity and key material security concerns are documented in `KEY-MANAGEMENT.md`.

The setup module handles:
- Configuration loading (INI files, environment variables, profiles)
- Iroh gossip network initialization
- Storage initialization (RocksDB)
- Logging and audit trail setup

---

## Security Analysis

### Authentication & Authorization

| Endpoint | Auth | Notes |
|----------|------|-------|
| `POST /rpc` | Bearer token OR x-api-key | ✅ Constant-time comparison |
| `GET /health` | None | ✅ Appropriate (public) |
| `GET /ready` | None | ⚠️ Exposes internal state |
| `GET /metrics` | None | ⚠️ Exposes operational data |

**Missing Controls**:
- No request rate limiting
- No IP allowlisting
- No mTLS option
- No request logging with correlation IDs

### Cryptographic Assessment

| Operation | Algorithm | Implementation | Assessment |
|-----------|-----------|----------------|------------|
| Event hashing | Blake3 | `domain::hashes::event_hash` | ✅ Correct |
| Validation hash | Blake3 | `domain::hashes::validation_hash` | ✅ Correct |
| Transport auth | Ed25519 | `Ed25519Signer` | ✅ Correct |
| Hash comparison | Constant-time | `subtle::ct_eq` | ✅ Correct |
| Token comparison | Constant-time | `subtle::ct_eq` | ✅ Correct |
| Signature aggregation | Schnorr/ECDSA | `domain::signing::aggregation` | ✅ Correct |
| Hyperlane verification | ECDSA (secp256k1) | `hyperlane_core` | ✅ Correct |

### Transport Security

| Layer | Protection | Notes |
|-------|------------|-------|
| Iroh gossip | Ed25519 message signatures | ✅ Per-message authentication |
| Iroh gossip | No encryption | ⚠️ Messages visible to network observers |
| Kaspa RPC | gRPC (HTTP/2) | ⚠️ No TLS by default |
| JSON-RPC | HTTP | ⚠️ No TLS enforcement |

---

## Policy Enforcement Review

**Location**: `igra-core/src/domain/policy/enforcement.rs`

### Available Policy Rules

| Rule | Field | Enforcement |
|------|-------|-------------|
| **Destination allowlist** | `allowed_destinations: Vec<String>` | ✅ Exact match |
| **Minimum amount** | `min_amount_sompi: Option<u64>` | ✅ Lower bound |
| **Maximum amount** | `max_amount_sompi: Option<u64>` | ✅ Upper bound |
| **Daily velocity limit** | `max_daily_volume_sompi: Option<u64>` | ✅ Rolling sum |
| **Require reason** | `require_reason: bool` | ✅ Metadata check |

### Policy Enforcement Code

```rust
// domain/policy/enforcement.rs
impl PolicyEnforcer for DefaultPolicyEnforcer {
    fn enforce_policy(&self, event: &SigningEvent, policy: &GroupPolicy, daily_volume: u64) -> Result<()> {
        // 1. Destination allowlist
        if !policy.allowed_destinations.is_empty()
            && !policy.allowed_destinations.contains(&event.destination_address) {
            return Err(ThresholdError::DestinationNotAllowed(...));
        }

        // 2. Amount bounds
        if let Some(min) = policy.min_amount_sompi {
            if event.amount_sompi < min { return Err(...); }
        }
        if let Some(max) = policy.max_amount_sompi {
            if event.amount_sompi > max { return Err(...); }
        }

        // 3. Daily velocity limit
        if let Some(limit) = policy.max_daily_volume_sompi {
            if daily_volume.saturating_add(event.amount_sompi) > limit {
                return Err(ThresholdError::VelocityLimitExceeded { current, limit });
            }
        }

        // 4. Require reason
        if policy.require_reason && !event.metadata.contains_key("reason") {
            return Err(ThresholdError::MemoRequired);
        }

        Ok(())
    }
}
```

### Missing Policy Rules (Custody Best Practice)

| Rule | Priority | Description |
|------|----------|-------------|
| **Time-of-day restrictions** | HIGH | Signing only during business hours |
| **Approval quorum** | HIGH | M-of-N operator approval before signing |
| **Time-delay execution** | HIGH | Mandatory delay for large transactions |
| **Source address validation** | MEDIUM | Verify UTXOs from expected addresses |
| **Per-destination limits** | MEDIUM | Different limits per destination |
| **Cumulative per-request limits** | MEDIUM | Limit total value across batch requests |
| **Blocklist** | MEDIUM | Reject known malicious destinations |
| **Geographic restrictions** | LOW | IP-based policy adjustment |

---

## Audit Trail Assessment

**Location**: `igra-core/src/infrastructure/audit/mod.rs`

### Audit Event Types

```rust
pub enum AuditEvent {
    EventReceived { event_hash, source, recipient, amount_sompi, timestamp_ns },
    PolicyEnforced { request_id, event_hash, policy_type, decision, reason, timestamp_ns },
    ProposalValidated { request_id, signer_peer_id, accepted, reason, validation_hash, timestamp_ns },
    SessionTimedOut { request_id, event_hash, signature_count, threshold_required, duration_seconds, timestamp_ns },
    TransactionFinalized { request_id, event_hash, tx_id, signature_count, threshold_required, timestamp_ns },
    TransactionSubmitted { request_id, tx_id, blue_score, timestamp_ns },
}
```

### Audit Implementation

```rust
// Global singleton logger
static AUDIT_LOGGER: OnceLock<Box<dyn AuditLogger>> = OnceLock::new();

pub fn audit(event: AuditEvent) {
    if let Some(logger) = AUDIT_LOGGER.get() {
        logger.log(event);
    }
}

// StructuredAuditLogger outputs JSON to tracing
impl AuditLogger for StructuredAuditLogger {
    fn log(&self, event: AuditEvent) {
        let json = serde_json::to_string(&event).unwrap_or(...);
        info!(target: "audit", "{}", json);
    }
}
```

### Assessment

| Criterion | Status | Notes |
|-----------|--------|-------|
| **Structured format** | ✅ | JSON output |
| **Timestamps** | ✅ | Nanosecond precision |
| **Request correlation** | ✅ | `request_id` in events |
| **Tamper evidence** | ❌ | No hash chaining |
| **Retention policy** | ❌ | No rotation/archival |
| **Integrity verification** | ❌ | No signatures on log entries |
| **Remote shipping** | ❌ | Local only (tracing) |

### Missing Audit Events

| Event | Priority | Description |
|-------|----------|-------------|
| **ConfigurationChanged** | HIGH | Policy or config updates |
| **IdentityCreated** | HIGH | New signer identity generated |
| **AuthenticationFailed** | HIGH | Invalid RPC token attempts |
| **RateLimitTriggered** | HIGH | DoS protection activations |
| **KeyShareAccessed** | MEDIUM | When signing key is used |
| **PeerConnected/Disconnected** | MEDIUM | Transport topology changes |

---

## Cross-Chain Bridge Integration (Hyperlane)

### Message Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────┐
│   Source    │    │  Hyperlane  │    │       Igra Service          │
│   Chain     │───▶│  Validators │───▶│  hyperlane.mailbox_process  │
│  (EVM etc)  │    │  (quorum)   │    │                             │
└─────────────┘    └─────────────┘    └──────────────┬──────────────┘
                                                     │
                                                     ▼
                                      ┌──────────────────────────────┐
                                      │      Proof Verification      │
                                      ├──────────────────────────────┤
                                      │ 1. Parse HyperlaneMessage    │
                                      │ 2. Verify checkpoint sigs    │
                                      │ 3. Verify Merkle proof       │
                                      │ 4. Check validator quorum    │
                                      │ 5. Extract recipient/amount  │
                                      │ 6. Submit signing event      │
                                      └──────────────────────────────┘
```

### Security Model

| Check | Implementation | Code Location |
|-------|----------------|---------------|
| **Validator set** | Per-domain config | `HyperlaneDomainConfig.validators` |
| **Threshold quorum** | Per-domain config | `HyperlaneDomainConfig.threshold` |
| **Merkle proof** | `merkle_root_multisig` mode | `ism.verify_proof()` |
| **Message ID derivation** | `blake3(group_id || message_id)` | `derive_session_id_hex()` |
| **Signature format** | 65-byte ECDSA (r || s || v) | `parse_signature_hex()` |

### Security Concerns

| Issue | Severity | Description |
|-------|----------|-------------|
| **Validator rotation** | MEDIUM | No mechanism to update validators without restart |
| **Domain spoofing** | LOW | `destination_domain` must match config |
| **Message replay** | MITIGATED | Event hash deduplication prevents replay |

---

## Critical Findings

> **Key Management Issues**: All key material security findings are in `KEY-MANAGEMENT.md`.

### HIGH: No API Rate Limiting

**Location**: `json_rpc.rs:442-676`

**Description**: The JSON-RPC endpoint has no rate limiting. An attacker can flood the service with signing requests, causing:
- Storage exhaustion (RocksDB growth)
- CPU exhaustion (hash computations)
- Memory exhaustion (in-flight sessions)

**Recommendation**:
```rust
// Add tower-governor or similar
let app = Router::new()
    .route("/rpc", post(handle_rpc))
    .layer(GovernorLayer {
        config: Arc::new(GovernorConfig::default()),
    });
```

### HIGH: Monolithic API Handler

**Location**: `json_rpc.rs` (737 lines)

**Description**: Security-critical code (auth, Hyperlane verification, signing event submission) mixed with HTTP parsing and response formatting. Makes security review difficult and increases risk of bugs.

**Recommendation**: Restructure per [Component Analysis](#recommended-refactoring).

### MEDIUM: Session State Lost on Restart

**Location**: `coordination.rs:210-222`

**Description**: `active_sessions` HashSet is in-memory only. If service restarts mid-session:
- Duplicate finalization attempts possible
- Session timeout tracking lost

**Recommendation**: Persist session state to RocksDB with TTL.

### MEDIUM: No TLS Enforcement

**Location**: `json_rpc.rs:392-396`

**Description**: JSON-RPC server binds to plain TCP. No TLS enforcement.

**Recommendation**:
1. Add `axum-server` with rustls
2. Require TLS in production configuration
3. Support mTLS for operator authentication

---

## Recommendations

> **Key Management Recommendations**: See `KEY-MANAGEMENT.md` for all key-related action items.

### Immediate (P0 - Security Critical)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 1 | Add API rate limiting | 2-4 hours | Prevents DoS |
| 2 | Add TLS support to RPC server | 4-8 hours | Prevents credential sniffing |
| 3 | Audit authentication on /ready and /metrics | 1 hour | Prevents information leakage |

### Short-Term (P1 - Security Hardening)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 4 | Refactor json_rpc.rs into modules | 1-2 days | Improves auditability |
| 5 | Add request correlation IDs | 4 hours | Improves incident response |
| 6 | Persist session state | 4-8 hours | Prevents duplicate finalization |
| 7 | Add tamper-evident audit logging | 1-2 days | Compliance requirement |
| 8 | Add missing audit events (auth failures, config changes) | 4-8 hours | Complete audit trail |

### Medium-Term (P2 - Custody Best Practice)

| # | Action | Effort | Impact |
|---|--------|--------|--------|
| 9 | Operator approval workflow | 1 week | Multi-party authorization |
| 10 | Time-delay execution for large tx | 2-3 days | Fraud prevention window |
| 11 | Geographic/IP-based policy | 2-3 days | Operational security |

---

## Architecture Restructuring Proposal

### Current vs Proposed Structure

```
CURRENT:                              PROPOSED:
igra-service/src/                     igra-service/src/
├── api/                              ├── api/
│   ├── mod.rs                        │   ├── mod.rs
│   └── json_rpc.rs (737 lines!)      │   ├── router.rs
│                                     │   ├── middleware/
│                                     │   │   ├── mod.rs
│                                     │   │   ├── auth.rs
│                                     │   │   ├── rate_limit.rs
│                                     │   │   └── logging.rs
│                                     │   ├── handlers/
│                                     │   │   ├── mod.rs
│                                     │   │   ├── signing_event.rs
│                                     │   │   ├── hyperlane.rs
│                                     │   │   └── health.rs
│                                     │   └── types/
│                                     │       ├── mod.rs
│                                     │       ├── requests.rs
│                                     │       └── responses.rs
├── service/                          ├── service/
│   ├── mod.rs                        │   ├── mod.rs
│   ├── coordination.rs (474 lines)   │   ├── coordinator/
│   ├── flow.rs                       │   │   ├── mod.rs
│   └── metrics.rs                    │   │   ├── loop.rs
│                                     │   │   ├── session.rs
│                                     │   │   └── finalization.rs
│                                     │   ├── flow.rs
│                                     │   └── metrics.rs
├── transport/                        ├── transport/
│   ├── mod.rs                        │   └── mod.rs
│   └── iroh.rs                       │
└── bin/                              └── bin/
    └── ...                               └── ...
```

> **Note**: Key management modules (`security/key_store.rs`, `security/hsm.rs`) are planned separately - see `KEY-MANAGEMENT.md`.

### New Module Responsibilities

| Module | Responsibility | Security Relevance |
|--------|----------------|-------------------|
| `api/middleware/auth.rs` | Token validation, mTLS | **HIGH** - Auth boundary |
| `api/middleware/rate_limit.rs` | Request throttling | **HIGH** - DoS protection |
| `api/handlers/signing_event.rs` | Signing event processing | **HIGH** - Business logic |
| `api/handlers/hyperlane.rs` | Bridge verification | **HIGH** - Cross-chain security |
| `service/coordinator/session.rs` | Session state management | **MEDIUM** - State integrity |

---

## Appendix: Security Test Coverage

### Existing Tests

| Test | File | Coverage |
|------|------|----------|
| Malicious coordinator PSKT tampering | `integration/security/malicious_coordinator.rs` | ✅ |
| Replay attack prevention | `integration/security/replay_attack.rs` | ✅ |
| DoS resistance | `integration/security/dos_resistance.rs` | Partial |
| Timing attacks | `integration/security/timing_attacks.rs` | Partial |

### Missing Test Coverage

| Scenario | Priority |
|----------|----------|
| Invalid RPC token rejected | HIGH |
| Rate limiting triggers correctly | HIGH |
| Policy violations audited | HIGH |
| Session timeout handling | MEDIUM |
| Hyperlane signature forgery rejected | MEDIUM |
| Coordinator failover | MEDIUM |

---

## Conclusion

The Igra service has a **solid foundation** for threshold signing custody with:
- Good cryptographic hygiene (constant-time comparisons, proper hash algorithms)
- Effective policy enforcement (destination allowlist, velocity limits)
- Working replay protection

**Improvements needed** before production deployment:
1. **Add API rate limiting**
2. **Enable TLS on all endpoints**
3. **Refactor monolithic handlers for auditability**
4. **Key management hardening** - see `KEY-MANAGEMENT.md`

The migration path from current multisig → FROST MPC → MuSig2 is architecturally supported, as the `SignerBackend` trait abstracts the signing mechanism. The `SigningBackendKind` enum already includes `MuSig2` and `Mpc` variants.

---

**End of Document**

**Next Steps**:
1. Review with security team
2. Prioritize P0 items for immediate implementation
3. Create tracking issues for P1/P2 items
4. Schedule penetration testing after P0 completion
