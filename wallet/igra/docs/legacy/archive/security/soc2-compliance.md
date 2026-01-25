# SOC2 Compliance Assessment

This document provides a comprehensive SOC2 Type II compliance assessment of the Igra threshold signing service.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Compliance Matrix](#compliance-matrix)
3. [Detailed Findings](#detailed-findings)
   - [Logging & Monitoring](#1-logging--monitoring-cc71-cc72)
   - [Access Control](#2-access-control-cc61-cc63)
   - [Encryption & Key Management](#3-encryption--key-management-cc66-cc67)
   - [Input Validation & Data Protection](#4-input-validation--data-protection-cc61-pi12)
   - [Error Handling & Recovery](#5-error-handling--recovery-cc73-cc74)
   - [Configuration Security](#6-configuration-security-cc61)
4. [Remediation Plan](#remediation-plan)
5. [Implementation Guide](#implementation-guide)
6. [Required Documentation](#required-documentation)
7. [Checklist](#checklist)

---

## Executive Summary

### Overall Compliance Score: 70%

| Area | Status | Score |
|------|--------|-------|
| Logging & Monitoring | Mostly Compliant | 75% |
| Access Control | Partially Compliant | 60% |
| Encryption & Key Management | Partially Compliant | 65% |
| Input Validation | Compliant | 85% |
| Error Handling & Recovery | Compliant | 80% |
| Configuration Security | Partially Compliant | 60% |

### What's Working Well

- Structured audit logging with 11 event types and nanosecond timestamps
- XChaCha20Poly1305 encryption for mnemonics at rest
- Constant-time authentication comparison (timing attack prevention)
- Per-IP rate limiting with configurable thresholds
- Configuration validation before startup
- Sensitive header redaction in logs
- Circuit breaker for RPC resilience

### Critical Gaps

1. No Role-Based Access Control (RBAC)
2. No log retention/rotation policy
3. No API key rotation mechanism
4. Config file permissions not enforced
5. No configuration tamper detection

---

## Compliance Matrix

### Trust Services Criteria Coverage

| Criteria | Description | Status | Evidence |
|----------|-------------|--------|----------|
| **CC1.1** | COSO Principle 1: Integrity and Ethics | N/A | Organizational control |
| **CC2.1** | Board oversight | N/A | Organizational control |
| **CC3.1** | Risk assessment | Partial | Config validation exists |
| **CC4.1** | Monitoring activities | Partial | Audit logging exists |
| **CC5.1** | Control activities | Partial | Auth + rate limiting |
| **CC6.1** | Logical access security | Partial | Auth exists, no RBAC |
| **CC6.2** | Access provisioning | Gap | No user management |
| **CC6.3** | Access removal | Gap | No revocation mechanism |
| **CC6.6** | System boundaries | Compliant | Network isolation configurable |
| **CC6.7** | Encryption | Partial | At-rest yes, key rotation no |
| **CC7.1** | System monitoring | Partial | Audit events logged |
| **CC7.2** | Anomaly detection | Gap | No alerting system |
| **CC7.3** | Incident response | Partial | Circuit breaker exists |
| **CC7.4** | Recovery | Gap | Limited recovery procedures |
| **PI1.2** | Data quality | Compliant | Input validation |

---

## Detailed Findings

### 1. Logging & Monitoring (CC7.1, CC7.2)

#### Compliant

**Centralized Audit Logging**
- Location: `igra-core/src/infrastructure/audit/mod.rs`
- Implementations: `StructuredAuditLogger`, `FileAuditLogger`, `MultiAuditLogger`

**Security Events Logged**
| Event Type | Logged | Location |
|------------|--------|----------|
| Authentication failures | Yes | `api/middleware/auth.rs` |
| Policy enforcement | Yes | `audit_policy_enforced!` macro |
| Rate limit exceeded | Yes | `AuditEvent::RateLimitExceeded` |
| Transaction finalization | Yes | `AuditEvent::TransactionFinalized` |
| Configuration changes | Yes | `AuditEvent::ConfigurationChanged` |
| Storage mutations | Yes | `AuditEvent::StorageMutated` |

**Audit Event Schema** (`domain/audit/types.rs`):
```rust
pub enum AuditEvent {
    EventReceived { event_hash, source, recipient, amount_sompi, timestamp_ns },
    EventSignatureValidated { event_hash, validator_count, valid, reason, timestamp_ns },
    PolicyEnforced { request_id, event_hash, policy_type, decision, reason, timestamp_ns },
    ProposalValidated { request_id, signer_peer_id, accepted, reason, validation_hash, timestamp_ns },
    PartialSignatureCreated { request_id, signer_peer_id, input_count, timestamp_ns },
    TransactionFinalized { request_id, event_hash, tx_id, signature_count, threshold_required, timestamp_ns },
    TransactionSubmitted { request_id, tx_id, blue_score, timestamp_ns },
    SessionTimedOut { request_id, event_hash, signature_count, threshold_required, duration_seconds, timestamp_ns },
    ConfigurationChanged { change_type, old_value, new_value, changed_by, timestamp_ns },
    StorageMutated { operation, key_prefix, record_count, timestamp_ns },
    RateLimitExceeded { peer_id, timestamp_ns },
}
```

#### Gaps

| Gap | Risk | Priority |
|-----|------|----------|
| No log retention policy | Logs grow unbounded or lost | High |
| No log integrity protection | Tampering undetected | Medium |
| No alerting on critical events | Delayed incident response | Medium |
| Health/metrics endpoints not audited | Incomplete audit trail | Low |

#### Recommendations

```rust
// 1. Add log retention configuration
pub struct LogRetentionPolicy {
    pub max_size_mb: u64,
    pub max_age_days: u32,
    pub rotation_count: u8,
    pub archive_path: Option<PathBuf>,
    pub compression: bool,
}

// 2. Add log integrity (HMAC signature per line)
pub struct SignedAuditLogger {
    inner: Box<dyn AuditLogger>,
    signing_key: [u8; 32],
}

impl AuditLogger for SignedAuditLogger {
    fn log(&self, event: AuditEvent) {
        let json = serde_json::to_string(&event).unwrap();
        let signature = hmac_sha256(&self.signing_key, json.as_bytes());
        let signed = format!("{}|{}", json, hex::encode(signature));
        self.inner.log_raw(&signed);
    }
}

// 3. Add alerting hooks
pub trait AlertSink: Send + Sync {
    fn alert(&self, severity: AlertSeverity, message: &str);
}

pub enum AlertSeverity {
    Critical,  // Auth failures, policy rejections
    Warning,   // Rate limits, circuit breaker
    Info,      // Normal operations
}
```

---

### 2. Access Control (CC6.1, CC6.3)

#### Compliant

**Authentication Implemented**
- Location: `igra-service/src/api/middleware/auth.rs`
- Methods: `x-api-key` header, `Bearer` token
- Security: Constant-time comparison via `subtle::ConstantTimeEq`

```rust
// Current implementation
pub fn authorize_rpc(config: &RpcConfig, headers: &HeaderMap) -> bool {
    let Some(expected) = config.token.as_ref() else {
        return true; // Auth disabled
    };
    // Checks x-api-key or Authorization: Bearer
    // Uses constant-time comparison
}
```

**Rate Limiting**
- Location: `igra-service/src/api/middleware/rate_limit.rs`
- Type: Per-IP token bucket
- Features: Configurable RPS, burst, automatic cleanup

**Request Correlation**
- Location: `igra-service/src/api/middleware/correlation.rs`
- Adds `x-request-id` header (UUID) for audit trails

#### Gaps

| Gap | Risk | Priority |
|-----|------|----------|
| No RBAC | All users have same permissions | Critical |
| No API key rotation | Long-lived credentials | High |
| No session management | No expiration/revocation | High |
| No access review logging | Compliance gap | Medium |
| No IP whitelist/blacklist | Limited network control | Low |

#### Recommendations

```rust
// 1. Implement RBAC
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RbacConfig {
    pub tokens: HashMap<String, TokenConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenConfig {
    pub roles: Vec<Role>,
    pub expires_at: Option<u64>,  // Unix timestamp
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Role {
    Admin,      // All operations
    Signer,     // Sign events only
    Monitor,    // Read-only (status, health)
    Auditor,    // Read audit logs
}

// Method-level authorization
pub fn authorize_method(roles: &[Role], method: &str) -> bool {
    match method {
        "signing_event.submit" => roles.contains(&Role::Signer) || roles.contains(&Role::Admin),
        "signing_event.finalize" => roles.contains(&Role::Admin),
        "status" | "health" => true,  // Public
        _ => roles.contains(&Role::Admin),
    }
}

// 2. API Key Rotation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    pub rotation_days: u32,
    pub grace_period_days: u32,  // Old key still valid
    pub max_active_keys: u8,
}

// 3. Session Management
#[derive(Clone, Debug)]
pub struct SessionManager {
    sessions: DashMap<String, Session>,
    revoked: DashSet<String>,
}

pub struct Session {
    pub token_hash: String,
    pub roles: Vec<Role>,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_activity: AtomicU64,
}
```

---

### 3. Encryption & Key Management (CC6.6, CC6.7)

#### Compliant

**Encryption at Rest**
- Algorithm: XChaCha20Poly1305 (AEAD)
- Location: `igra-core/src/infrastructure/config/encryption.rs`
- Library: `kaspa_wallet_core::encryption::Encryptable`

```rust
// Current: Mnemonics encrypted before storage
let encrypted = encrypt_mnemonics(
    mnemonics,
    payment_secret.as_ref(),
    &wallet_secret
)?;
// Uses: EncryptionKind::XChaCha20Poly1305
```

**Secure Crypto Libraries**
| Purpose | Library | Version |
|---------|---------|---------|
| Hashing | blake3 | 1.5.1 |
| ECDSA | secp256k1 | workspace |
| EdDSA | ed25519-dalek | latest |
| AEAD | chacha20poly1305 | via kaspa_wallet_core |

**Secret Handling**
- Wallet secret from environment: `KASPA_IGRA_WALLET_SECRET`
- Memory zeroization: `phrase.zeroize()` after use

#### Gaps

| Gap | Risk | Priority |
|-----|------|----------|
| No key rotation | Long-lived secrets | High |
| Secrets in env vars | Process environment exposure | Medium |
| No HSM support | Keys only in memory | Medium |
| Single wallet secret | No per-group isolation | Low |

#### Recommendations

```rust
// 1. Key Rotation Policy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    pub rotation_interval_days: u32,
    pub key_version: u32,
    pub previous_keys: Vec<VersionedKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionedKey {
    pub version: u32,
    pub encrypted_key: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
}

// 2. Secure Secret Loading
pub fn load_wallet_secret() -> Result<Secret, ThresholdError> {
    // Priority: 1. Locked file, 2. Env var, 3. Error
    if let Some(secret) = load_from_locked_file()? {
        return Ok(secret);
    }
    if let Ok(value) = std::env::var(HD_WALLET_SECRET_ENV) {
        // Log warning about env var usage
        tracing::warn!("wallet secret loaded from environment variable");
        return Ok(Secret::from(value));
    }
    Err(ThresholdError::ConfigError("no wallet secret configured".into()))
}

fn load_from_locked_file() -> Result<Option<Secret>, ThresholdError> {
    let path = resolve_data_dir()?.join(".wallet_secret");
    if !path.exists() {
        return Ok(None);
    }

    // Check permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ThresholdError::ConfigError(
                "wallet secret file must have 0600 permissions".into()
            ));
        }
    }

    let content = std::fs::read_to_string(&path)?;
    Ok(Some(Secret::from(content.trim())))
}

// 3. HSM Abstraction (future)
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, ThresholdError>;
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, ThresholdError>;
    async fn rotate(&self, key_id: &str) -> Result<(), ThresholdError>;
}

pub struct SoftwareKeyProvider { /* current implementation */ }
pub struct Pkcs11KeyProvider { /* HSM via PKCS#11 */ }
```

---

### 4. Input Validation & Data Protection (CC6.1, PI1.2)

#### Compliant

**Configuration Validation** (`infrastructure/config/validation.rs`):
```rust
impl AppConfig {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        // Address format validation
        // Threshold constraints (m <= n, both > 0)
        // Amount ranges (min <= max)
        // Session timeout bounds (0 < timeout <= 600s)
        // Secp256k1 pubkey format (33 or 65 bytes)
    }
}
```

**Sensitive Data Redaction** (`api/middleware/logging.rs`):
```rust
const REDACT: &[&str] = &["authorization", "x-api-key", "cookie"];
// Values replaced with "[REDACTED]"
// Long values (>128 chars) truncated
```

**Policy Validation** (`domain/policy/enforcement.rs`):
- Amount non-zero
- Destination address format
- Allowed destination whitelist
- Daily velocity limits

#### Gaps

| Gap | Risk | Priority |
|-----|------|----------|
| Error messages leak details | Information disclosure | Medium |
| No input length limits at API | DoS potential | Low |
| No auth-specific rate limiting | Brute force possible | Medium |

#### Recommendations

```rust
// 1. Sanitize error messages to clients
pub fn sanitize_error(err: &ThresholdError, request_id: &str) -> JsonRpcError {
    // Log full error internally
    tracing::warn!(
        request_id = %request_id,
        error = ?err,
        "request failed"
    );

    // Return generic message to client
    match err {
        ThresholdError::PolicyViolation(_) => JsonRpcError {
            code: -32007,
            message: "policy check failed".into(),
            data: Some(json!({ "request_id": request_id })),
        },
        ThresholdError::ConfigError(_) => JsonRpcError {
            code: -32001,
            message: "configuration error".into(),
            data: Some(json!({ "request_id": request_id })),
        },
        _ => JsonRpcError {
            code: -32000,
            message: "internal error".into(),
            data: Some(json!({ "request_id": request_id })),
        },
    }
}

// 2. Auth-specific rate limiting
pub struct AuthRateLimiter {
    failed_attempts: DashMap<IpAddr, FailedAttempts>,
}

struct FailedAttempts {
    count: u32,
    first_failure: Instant,
    locked_until: Option<Instant>,
}

impl AuthRateLimiter {
    pub fn check(&self, ip: &IpAddr) -> Result<(), AuthRateLimitError> {
        if let Some(attempts) = self.failed_attempts.get(ip) {
            if let Some(locked_until) = attempts.locked_until {
                if Instant::now() < locked_until {
                    return Err(AuthRateLimitError::Locked);
                }
            }
        }
        Ok(())
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut entry = self.failed_attempts.entry(ip).or_insert(FailedAttempts::default());
        entry.count += 1;
        if entry.count >= 5 {
            entry.locked_until = Some(Instant::now() + Duration::from_secs(900)); // 15 min
        }
    }
}
```

---

### 5. Error Handling & Recovery (CC7.3, CC7.4)

#### Compliant

**Error Mapping** (`api/handlers/types.rs`):
- Domain errors mapped to JSON-RPC codes
- No stack traces in responses
- Internal errors return generic message

**Retry Logic** (`infrastructure/rpc/retry/mod.rs`):
```rust
pub async fn retry<F, Fut, T>(attempts: usize, delay: Duration, op: F) -> Result<T, ThresholdError>
// Logs each attempt with remaining count
```

**Circuit Breaker** (`infrastructure/rpc/circuit_breaker.rs`):
```rust
pub struct CircuitBreaker {
    threshold: usize,    // Failures before opening
    cooldown: Duration,  // Time before retry
}
// States: Closed -> Open -> Closed (on cooldown expiry + success)
```

#### Gaps

| Gap | Risk | Priority |
|-----|------|----------|
| No half-open state | Delayed recovery | Medium |
| No state persistence | Lost on restart | Medium |
| Error context lost | Debugging difficulty | Low |

#### Recommendations

See [IMPROVEMENTS.md](docs/IMPROVEMENTS.md.md) for `failsafe` and `backoff` crate integration.

---

### 6. Configuration Security (CC6.1)

#### Compliant

**Secrets Not Hardcoded**:
- Wallet secret: `KASPA_IGRA_WALLET_SECRET` env var
- RPC token: Config file (can be env override)
- Mnemonics: Encrypted before storage

**Secure Defaults**:
```rust
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8088";  // Loopback only
const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 60;
const DEFAULT_SESSION_EXPIRY_SECS: u64 = 600;
```

**Config Validation**: `load_app_config()` calls `validate()` before startup

#### Gaps

| Gap | Risk | Priority |
|-----|------|----------|
| File permissions not enforced | Unauthorized access | High |
| No tamper detection | Config manipulation | High |
| Plain-text token in TOML | Credential exposure | Medium |
| No config change audit | Compliance gap | Medium |

#### Recommendations

```rust
// 1. Enforce file permissions
pub fn check_config_permissions(path: &Path) -> Result<(), ThresholdError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode();

        // Check owner-only read/write (0600)
        if mode & 0o077 != 0 {
            return Err(ThresholdError::ConfigError(format!(
                "config file {} has insecure permissions {:o}, expected 0600",
                path.display(),
                mode & 0o777
            )));
        }
    }
    Ok(())
}

// 2. Config integrity verification
use sha2::{Sha256, Digest};

pub struct ConfigIntegrity {
    pub path: PathBuf,
    pub hash: String,
    pub verified_at: u64,
}

impl ConfigIntegrity {
    pub fn compute(path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read(path)?;
        let hash = hex::encode(Sha256::digest(&content));
        Ok(Self {
            path: path.to_path_buf(),
            hash,
            verified_at: current_timestamp_nanos(),
        })
    }

    pub fn verify(&self) -> Result<bool, std::io::Error> {
        let current = Self::compute(&self.path)?;
        Ok(current.hash == self.hash)
    }
}

// 3. Audit config loads
pub fn load_config_with_audit(path: &Path) -> Result<AppConfig, ThresholdError> {
    check_config_permissions(path)?;

    let integrity = ConfigIntegrity::compute(path)?;
    let config = load_config_from_file(path, &resolve_data_dir()?)?;

    audit(AuditEvent::ConfigurationChanged {
        change_type: "load".into(),
        old_value: None,
        new_value: integrity.hash.clone(),
        changed_by: "system".into(),
        timestamp_ns: current_timestamp_nanos(),
    });

    Ok(config)
}
```

---

## Remediation Plan

### Phase 1: Critical (Week 1-2)

| Task | Owner | Effort |
|------|-------|--------|
| Implement RBAC | Backend | 8h |
| Add config permission checks | Backend | 2h |
| Add config integrity verification | Backend | 4h |
| Add log rotation policy | Backend | 4h |
| Sanitize error messages | Backend | 4h |

### Phase 2: High Priority (Week 3-4)

| Task | Owner | Effort |
|------|-------|--------|
| API key rotation mechanism | Backend | 8h |
| Session management with expiry | Backend | 8h |
| Auth-specific rate limiting | Backend | 4h |
| Key rotation policy | Backend | 8h |

### Phase 3: Medium Priority (Week 5-6)

| Task | Owner | Effort |
|------|-------|--------|
| Log integrity (HMAC signing) | Backend | 4h |
| Alerting integration | DevOps | 8h |
| Enhance circuit breaker | Backend | 4h |
| Config change audit trail | Backend | 4h |

### Phase 4: Documentation (Week 7)

| Document | Owner | Effort |
|----------|-------|--------|
| Security Policy | Security | 8h |
| Access Control Policy | Security | 4h |
| Incident Response Plan | Security | 8h |
| Key Management Policy | Security | 4h |
| Data Retention Policy | Compliance | 4h |

---

## Implementation Guide

### Adding RBAC

**Step 1: Update Config Types**

```toml
# igra-config.toml
[rpc]
addr = "127.0.0.1:8088"
enabled = true

[rpc.tokens]
# Admin token with all permissions
"sk_admin_abc123" = { roles = ["admin"], expires_at = 1735689600 }
# Signer token for signing operations only
"sk_signer_def456" = { roles = ["signer"], expires_at = 1735689600 }
# Monitor token for read-only access
"sk_monitor_ghi789" = { roles = ["monitor"] }
```

**Step 2: Update RpcConfig**

```rust
// infrastructure/config/types.rs
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RpcConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub tokens: HashMap<String, TokenConfig>,
    // Deprecated: single token
    #[serde(default, skip_serializing)]
    pub token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenConfig {
    pub roles: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
}
```

**Step 3: Update Authorization**

```rust
// api/middleware/auth.rs
pub struct AuthResult {
    pub token_id: String,
    pub roles: Vec<Role>,
}

pub fn authorize_rpc(config: &RpcConfig, headers: &HeaderMap) -> Result<AuthResult, AuthError> {
    // Extract token from headers
    let token = extract_token(headers)?;

    // Check in tokens map
    if let Some(token_config) = config.tokens.get(&token) {
        // Check expiry
        if let Some(expires_at) = token_config.expires_at {
            if current_timestamp_secs() > expires_at {
                return Err(AuthError::TokenExpired);
            }
        }

        let roles = token_config.roles.iter()
            .filter_map(|r| Role::from_str(r).ok())
            .collect();

        return Ok(AuthResult { token_id: hash_token(&token), roles });
    }

    // Fallback to legacy single token
    if let Some(expected) = &config.token {
        if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            return Ok(AuthResult {
                token_id: "legacy".into(),
                roles: vec![Role::Admin],
            });
        }
    }

    Err(AuthError::InvalidToken)
}

pub fn authorize_method(auth: &AuthResult, method: &str) -> bool {
    let required_roles = match method {
        "signing_event.submit" => &[Role::Signer, Role::Admin][..],
        "signing_event.finalize" => &[Role::Admin][..],
        "session.list" | "session.get" => &[Role::Monitor, Role::Admin][..],
        "audit.query" => &[Role::Auditor, Role::Admin][..],
        _ => &[Role::Admin][..],
    };

    auth.roles.iter().any(|r| required_roles.contains(r))
}
```

---

## Required Documentation

For SOC2 Type II attestation, prepare these documents:

| Document | Purpose | Template |
|----------|---------|----------|
| **Security Policy** | Overall security commitments | [AICPA template](https://www.aicpa.org) |
| **Access Control Policy** | Who can access what | Based on RBAC implementation |
| **Incident Response Plan** | How to handle security incidents | NIST SP 800-61 |
| **Change Management Policy** | How changes are approved/deployed | Git workflow + PR reviews |
| **Data Retention Policy** | How long data is kept | Based on log rotation config |
| **Key Management Policy** | How keys are created/rotated/destroyed | Based on implementation |
| **Vendor Management Policy** | Third-party risk management | For dependencies |
| **Business Continuity Plan** | Disaster recovery procedures | Based on backup strategy |

---

## Checklist

### Pre-Audit

- [ ] All critical gaps remediated
- [ ] Documentation complete
- [ ] Evidence collection automated
- [ ] Internal audit completed
- [ ] Readiness assessment passed

### Technical Controls

#### Logging & Monitoring
- [ ] Audit logging enabled
- [ ] Log retention configured (90 days minimum)
- [ ] Log rotation implemented
- [ ] Log integrity protection (optional)
- [ ] Alerting configured for critical events

#### Access Control
- [ ] RBAC implemented
- [ ] Unique tokens per user/service
- [ ] Token expiration enforced
- [ ] Token rotation policy defined
- [ ] Access reviews scheduled (quarterly)
- [ ] Auth failures logged and rate-limited

#### Encryption
- [ ] Data encrypted at rest (XChaCha20Poly1305)
- [ ] Secrets not in code/config files
- [ ] Key rotation policy defined
- [ ] Secure secret loading (file with 0600)
- [ ] Memory zeroization for sensitive data

#### Configuration
- [ ] Config file permissions enforced (0600)
- [ ] Config integrity verification
- [ ] Secure defaults (loopback binding)
- [ ] Config changes audited
- [ ] No plain-text secrets in config

#### Input Validation
- [ ] All inputs validated
- [ ] Error messages sanitized
- [ ] Rate limiting on all endpoints
- [ ] Auth-specific rate limiting

#### Recovery
- [ ] Circuit breaker implemented
- [ ] Retry with backoff
- [ ] Graceful degradation
- [ ] State recovery after restart

### Documentation
- [ ] Security Policy
- [ ] Access Control Policy
- [ ] Incident Response Plan
- [ ] Change Management Policy
- [ ] Data Retention Policy
- [ ] Key Management Policy

### Evidence Collection
- [ ] Audit logs exported
- [ ] Access reviews documented
- [ ] Change records (git history)
- [ ] Incident reports (if any)
- [ ] Vulnerability scan results
- [ ] Penetration test results (optional)

---

## References

- [SOC 2 Controls List (2025)](https://www.complyjet.com/blog/soc-2-controls)
- [AICPA Trust Services Criteria](https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services)
- [SOC 2 Compliance Requirements](https://www.brightdefense.com/resources/soc-2-compliance-requirements-your-essential-2024-overview/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
