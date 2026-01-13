# Domain Logging Refactor Guide

This document provides a file-by-file analysis of the domain layer, suggesting rich result types to replace direct logging, and showing how to log from application/infrastructure/service layers.

## Principles

1. **Domain layer should be pure** - No `tracing`, `log`, or any logging crate
2. **Rich result types** - Return detailed enums/structs that carry all context
3. **Application layer logs** - Based on domain results
4. **Audit events are separate** - Distinct from operational logging

---

## Current State Analysis

### Files with Logging (to remove) - 7 FILES

| File | Current Logging | Log Calls |
|------|-----------------|-----------|
| `validation/hyperlane.rs` | `debug!`, `error!`, `info!`, `trace!`, `warn!` | 10 calls |
| `validation/layerzero.rs` | `debug!`, `error!`, `trace!`, `warn!` | 5 calls |
| `policy/enforcement.rs` | `debug!`, `info!`, `warn!` | 9 calls |
| `signing/threshold.rs` | `debug!`, `error!`, `info!` | 8 calls |
| `pskt/multisig.rs` | `debug!`, `info!`, `trace!`, `warn!` | 22 calls |
| `coordination/finalization.rs` | `debug!`, `trace!` | 3 calls |
| `request/state_machine.rs` | `debug!`, `info!`, `warn!` | 7 calls |

**Total: 64 logging calls to remove/refactor**

### Files Already Pure (no changes needed)

- `model.rs` - Pure data structures
- `hashes.rs` - Pure hash computation
- `group_id.rs` - Pure group ID computation
- `coordination/timeout.rs` - Pure time calculations
- `coordination/threshold.rs` - Pure threshold checks
- `coordination/acknowledgment.rs` - Pure ack summarization
- `coordination/signature_collection.rs` - Pure signature counting
- `coordination/proposal.rs` - Pure proposal validation
- `pskt/params.rs` - Pure data structures
- `pskt/fee.rs` - Pure fee calculations
- `pskt/builder.rs` - Pure PSKT building
- `pskt/validation.rs` - Pure PSKT validation
- `signing/types.rs` - Pure data structures
- `signing/aggregation.rs` - Pure PSKT aggregation
- `signing/musig2.rs` - Stub (unimplemented)
- `signing/mpc.rs` - Stub (unimplemented)
- `event/types.rs` - Pure data structures
- `event/validation.rs` - Pure event parsing
- `event/hashing.rs` - Pure hash computation
- `request/types.rs` - Type aliases only
- `audit/types.rs` - Pure audit event definitions
- `audit/builder.rs` - Pure audit builders

---

## File-by-File Refactor Guide

### 1. `domain/validation/hyperlane.rs`

**Current State:** Has `debug!` and `warn!` logging

**Remove:**
```rust
use tracing::{debug, warn};
```

**Add Rich Result Type:**
```rust
/// Result of Hyperlane signature verification with full context
#[derive(Debug, Clone)]
pub struct HyperlaneVerificationResult {
    pub valid: bool,
    pub event_hash: [u8; 32],
    pub validator_count: usize,
    pub signatures_checked: usize,
    pub valid_signatures: usize,
    pub threshold_required: usize,
    pub failure_reason: Option<HyperlaneVerificationFailure>,
}

#[derive(Debug, Clone)]
pub enum HyperlaneVerificationFailure {
    NoValidatorsConfigured,
    NoSignatureProvided,
    TooManySignatureChunks { chunks: usize, max: usize },
    InsufficientValidSignatures { valid: usize, required: usize },
    InvalidSignatureFormat { chunk_index: usize },
}
```

**Refactored Function:**
```rust
pub fn verify_event(
    event: &SigningEvent,
    validators: &[PublicKey],
    threshold: usize,
) -> Result<HyperlaneVerificationResult, ThresholdError> {
    let event_hash = event_hash_without_signature(event)?;

    if validators.is_empty() {
        return Ok(HyperlaneVerificationResult {
            valid: false,
            event_hash,
            validator_count: 0,
            signatures_checked: 0,
            valid_signatures: 0,
            threshold_required: threshold,
            failure_reason: Some(HyperlaneVerificationFailure::NoValidatorsConfigured),
        });
    }

    let signature = match &event.signature {
        Some(sig) => sig,
        None => return Ok(HyperlaneVerificationResult {
            valid: false,
            event_hash,
            validator_count: validators.len(),
            signatures_checked: 0,
            valid_signatures: 0,
            threshold_required: threshold,
            failure_reason: Some(HyperlaneVerificationFailure::NoSignatureProvided),
        }),
    };

    // ... verification logic ...

    Ok(HyperlaneVerificationResult {
        valid: valid_count >= threshold,
        event_hash,
        validator_count: validators.len(),
        signatures_checked: chunks.len(),
        valid_signatures: valid_count,
        threshold_required: threshold,
        failure_reason: if valid_count >= threshold {
            None
        } else {
            Some(HyperlaneVerificationFailure::InsufficientValidSignatures {
                valid: valid_count,
                required: threshold,
            })
        },
    })
}
```

**Application Layer Logging:**
```rust
// In application/event_processor.rs or application/signer.rs
use tracing::{debug, warn, info};

let result = hyperlane::verify_event(&event, &validators, threshold)?;

if result.valid {
    info!(
        event_hash = %hex::encode(result.event_hash),
        validator_count = result.validator_count,
        valid_signatures = result.valid_signatures,
        threshold = result.threshold_required,
        "hyperlane verification succeeded"
    );
} else {
    warn!(
        event_hash = %hex::encode(result.event_hash),
        validator_count = result.validator_count,
        valid_signatures = result.valid_signatures,
        threshold = result.threshold_required,
        failure = ?result.failure_reason,
        "hyperlane verification failed"
    );
}
```

---

### 2. `domain/validation/layerzero.rs`

**Current State:** Has `debug!` logging

**Remove:**
```rust
use tracing::debug;
```

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct LayerZeroVerificationResult {
    pub valid: bool,
    pub event_hash: [u8; 32],
    pub validator_count: usize,
    pub matching_validator_index: Option<usize>,
    pub failure_reason: Option<LayerZeroVerificationFailure>,
}

#[derive(Debug, Clone)]
pub enum LayerZeroVerificationFailure {
    NoValidatorsConfigured,
    NoSignatureProvided,
    NoMatchingValidator,
    InvalidSignatureFormat,
}
```

**Application Layer Logging:**
```rust
let result = layerzero::verify_event(&event, &validators)?;

if result.valid {
    debug!(
        event_hash = %hex::encode(result.event_hash),
        validator_index = result.matching_validator_index,
        "layerzero verification succeeded"
    );
} else {
    warn!(
        event_hash = %hex::encode(result.event_hash),
        validator_count = result.validator_count,
        failure = ?result.failure_reason,
        "layerzero verification failed"
    );
}
```

---

### 3. `domain/validation/verifier.rs`

**Current State:** Pure (no logging)

**Enhance `VerificationReport`:**
```rust
#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub source: ValidationSource,
    pub validator_count: usize,
    pub valid: bool,
    pub valid_signatures: usize,
    pub threshold_required: usize,
    pub failure_reason: Option<String>,
    pub event_hash: Option<[u8; 32]>,
}
```

**Application Layer Logging:**
```rust
let report = verifier.verify(&event)?;

match report.valid {
    true => info!(
        source = ?report.source,
        validator_count = report.validator_count,
        valid_signatures = report.valid_signatures,
        "message verification passed"
    ),
    false => warn!(
        source = ?report.source,
        validator_count = report.validator_count,
        failure = ?report.failure_reason,
        "message verification failed"
    ),
}
```

---

### 4. `domain/policy/enforcement.rs`

**Current State:** Has `debug!`, `info!`, `warn!` logging (9 calls)

**Remove:**
```rust
use tracing::{debug, info, warn};
```

**Current Result:** Returns `Result<(), ThresholdError>`

**Enhance with `PolicyEvaluationResult`:**
```rust
#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult {
    pub allowed: bool,
    pub checks_performed: Vec<PolicyCheck>,
    pub failed_check: Option<PolicyCheckFailure>,
}

#[derive(Debug, Clone)]
pub struct PolicyCheck {
    pub check_type: PolicyCheckType,
    pub passed: bool,
    pub details: String,
}

#[derive(Debug, Clone, Copy)]
pub enum PolicyCheckType {
    AmountNonZero,
    DestinationValid,
    DestinationWhitelisted,
    AmountAboveMinimum,
    AmountBelowMaximum,
    ReasonProvided,
    VelocityLimit,
}

#[derive(Debug, Clone)]
pub struct PolicyCheckFailure {
    pub check_type: PolicyCheckType,
    pub reason: String,
    pub context: PolicyFailureContext,
}

#[derive(Debug, Clone)]
pub enum PolicyFailureContext {
    AmountTooLow { amount: u64, min: u64 },
    AmountTooHigh { amount: u64, max: u64 },
    VelocityExceeded { current_volume: u64, amount: u64, limit: u64 },
    DestinationNotAllowed { destination: String, whitelist_size: usize },
    MissingReason,
    InvalidDestination { destination: String },
}
```

**Refactored Function:**
```rust
pub fn evaluate_policy(
    event: &SigningEvent,
    policy: &GroupPolicy,
    current_volume: u64,
) -> PolicyEvaluationResult {
    let mut checks = Vec::new();

    // Check 1: Amount non-zero
    let amount_check = PolicyCheck {
        check_type: PolicyCheckType::AmountNonZero,
        passed: event.amount_sompi > 0,
        details: format!("amount={}", event.amount_sompi),
    };
    checks.push(amount_check.clone());
    if !amount_check.passed {
        return PolicyEvaluationResult {
            allowed: false,
            checks_performed: checks,
            failed_check: Some(PolicyCheckFailure {
                check_type: PolicyCheckType::AmountNonZero,
                reason: "amount must be greater than zero".to_string(),
                context: PolicyFailureContext::AmountTooLow { amount: 0, min: 1 },
            }),
        };
    }

    // ... additional checks ...

    PolicyEvaluationResult {
        allowed: true,
        checks_performed: checks,
        failed_check: None,
    }
}
```

**Application Layer Logging:**
```rust
let policy_result = policy_enforcer.evaluate_policy(&event, &policy, current_volume);

for check in &policy_result.checks_performed {
    trace!(
        check_type = ?check.check_type,
        passed = check.passed,
        details = %check.details,
        "policy check"
    );
}

if policy_result.allowed {
    debug!(
        event_id = %event.event_id,
        checks_passed = policy_result.checks_performed.len(),
        "policy evaluation passed"
    );
} else if let Some(failure) = &policy_result.failed_check {
    warn!(
        event_id = %event.event_id,
        check_type = ?failure.check_type,
        reason = %failure.reason,
        context = ?failure.context,
        "policy evaluation failed"
    );

    // Emit audit event
    audit_policy_enforced!(
        &request_id,
        &event_hash,
        format!("{:?}", failure.check_type),
        PolicyDecision::Rejected,
        &failure.reason
    );
}
```

---

### 5. `domain/signing/threshold.rs`

**Current State:** Has `debug!`, `error!`, `info!` logging (8 calls)

**Remove:**
```rust
use tracing::{debug, error, info};
```

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct SigningResult {
    pub request_id: RequestId,
    pub input_count: usize,
    pub signatures_produced: Vec<SignatureOutput>,
    pub signer_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignatureOutput {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum SigningFailure {
    KeypairConversionFailed { reason: String },
    PsktDeserializationFailed { reason: String },
    SigningOperationFailed { reason: String },
    NoSignaturesProduced,
}
```

**Refactored Function:**
```rust
impl SignerBackend for ThresholdSigner {
    fn sign(&self, kpsbt_blob: &[u8], request_id: &RequestId) -> Result<SigningResult, ThresholdError> {
        let keypair = self.keypair.to_secp256k1()
            .map_err(|e| ThresholdError::SigningFailed(format!("keypair conversion: {}", e)))?;

        let pskt = deserialize_pskt_signer(kpsbt_blob)
            .map_err(|e| ThresholdError::SigningFailed(format!("pskt deserialize: {}", e)))?;

        let input_count = pskt.inputs.len();
        let signed = sign_pskt(pskt, &keypair)?;
        let partials = partial_sigs_for_pubkey(&signed, &keypair.public_key())?;

        if partials.is_empty() {
            return Err(ThresholdError::SigningFailed("no signatures produced".to_string()));
        }

        Ok(SigningResult {
            request_id: request_id.clone(),
            input_count,
            signatures_produced: partials.into_iter().map(|p| SignatureOutput {
                input_index: p.input_index,
                pubkey: p.pubkey,
                signature: p.signature,
            }).collect(),
            signer_pubkey: keypair.public_key().serialize().to_vec(),
        })
    }
}
```

**Application Layer Logging:**
```rust
match signer.sign(&kpsbt_blob, &request_id) {
    Ok(result) => {
        info!(
            request_id = %result.request_id,
            input_count = result.input_count,
            signatures_produced = result.signatures_produced.len(),
            signer_pubkey = %hex::encode(&result.signer_pubkey),
            "signing operation completed"
        );

        // Audit
        audit(AuditEvent::PartialSignatureCreated {
            request_id: result.request_id.to_string(),
            signer_peer_id: local_peer_id.to_string(),
            input_count: result.signatures_produced.len(),
            timestamp_ns: now_nanos(),
        });
    }
    Err(err) => {
        error!(
            request_id = %request_id,
            error = %err,
            "signing operation failed"
        );
    }
}
```

---

### 6. `domain/pskt/multisig.rs`

**Current State:** Has `debug!`, `info!`, `trace!`, `warn!` logging (22 calls - most in domain)

**Remove:**
```rust
use tracing::{debug, info, trace, warn};
```

**Add Rich Result Types:**
```rust
#[derive(Debug, Clone)]
pub struct PsktBuildResult {
    pub input_count: usize,
    pub output_count: usize,
    pub total_input_amount: u64,
    pub total_output_amount: u64,
    pub pskt: PSKT<Updater>,
}

#[derive(Debug, Clone)]
pub struct PsktSignResult {
    pub input_count: usize,
    pub signatures_added: usize,
    pub pskt: PSKT<Signer>,
}

#[derive(Debug, Clone)]
pub struct PsktFinalizeResult {
    pub input_count: usize,
    pub signatures_per_input: Vec<usize>,
    pub required_signatures: usize,
    pub pskt: PSKT<Finalizer>,
}

#[derive(Debug, Clone)]
pub struct TransactionExtractionResult {
    pub tx_id: [u8; 32],
    pub input_count: usize,
    pub output_count: usize,
    pub mass: u64,
}
```

**Application Layer Logging:**
```rust
// After build_pskt
let build_result = pskt_multisig::build_pskt(&inputs, &outputs)?;
debug!(
    input_count = build_result.input_count,
    output_count = build_result.output_count,
    total_input = build_result.total_input_amount,
    total_output = build_result.total_output_amount,
    "pskt built"
);

// After finalize
let finalize_result = pskt_multisig::finalize_multisig(pskt, required, &pubkeys)?;
info!(
    input_count = finalize_result.input_count,
    required = finalize_result.required_signatures,
    "pskt finalized"
);

// After extract_tx
let tx_result = pskt_multisig::extract_tx(pskt, params)?;
info!(
    tx_id = %hex::encode(tx_result.tx_id),
    input_count = tx_result.input_count,
    output_count = tx_result.output_count,
    mass = tx_result.mass,
    "transaction extracted"
);
```

---

### 7. `domain/pskt/builder.rs`

**Current State:** Pure (no logging) - No changes needed

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct UtxoSelectionResult {
    pub selected_utxos: usize,
    pub total_input_amount: u64,
    pub total_output_amount: u64,
    pub fee_amount: u64,
    pub change_amount: u64,
    pub has_change_output: bool,
}
```

**Application Layer Logging:**
```rust
let selection = build_pskt_from_utxos(&params, utxos)?;
debug!(
    selected_utxos = selection.selected_utxos,
    total_input = selection.total_input_amount,
    total_output = selection.total_output_amount,
    fee = selection.fee_amount,
    change = selection.change_amount,
    has_change = selection.has_change_output,
    "utxo selection completed"
);
```

---

### 8. `domain/pskt/validation.rs`

**Current State:** Pure (no logging) - No changes needed

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct PsktValidationResult {
    pub valid: bool,
    pub input_count: usize,
    pub output_count: usize,
    pub sig_op_count: u8,
    pub validation_errors: Vec<PsktValidationError>,
}

#[derive(Debug, Clone)]
pub enum PsktValidationError {
    NoInputs,
    NoOutputs,
    ZeroSigOpCount,
    NoSourceAddresses,
    NoOutputParams,
}
```

**Application Layer Logging:**
```rust
let validation = pskt_validation::validate_params(&params);
if !validation.valid {
    warn!(
        errors = ?validation.validation_errors,
        "pskt validation failed"
    );
}
```

---

### 9. `domain/coordination/proposal.rs`

**Current State:** Pure (no logging) - No changes needed

**Current `ProposalDecision` is already good. Enhance it:**
```rust
#[derive(Debug, Clone)]
pub struct ProposalDecision {
    pub accept: bool,
    pub reason: Option<String>,
    pub per_input_hashes: Vec<Hash32>,
    pub validation_steps: Vec<ValidationStep>,
}

#[derive(Debug, Clone)]
pub struct ValidationStep {
    pub step_name: &'static str,
    pub passed: bool,
    pub details: Option<String>,
}
```

**Application Layer Logging:**
```rust
let decision = coordination::validate_proposal(input)?;

for step in &decision.validation_steps {
    trace!(
        step = step.step_name,
        passed = step.passed,
        details = ?step.details,
        "validation step"
    );
}

if decision.accept {
    info!(
        request_id = %request_id,
        input_count = decision.per_input_hashes.len(),
        "proposal validated and accepted"
    );
} else {
    warn!(
        request_id = %request_id,
        reason = ?decision.reason,
        "proposal rejected"
    );
}

// Audit
audit(AuditEvent::ProposalValidated {
    request_id: request_id.to_string(),
    signer_peer_id: local_peer_id.to_string(),
    accepted: decision.accept,
    reason: decision.reason.clone(),
    validation_hash: hex::encode(validation_hash),
    timestamp_ns: now_nanos(),
});
```

---

### 10. `domain/coordination/finalization.rs`

**Current State:** Has `debug!`, `trace!` logging (3 calls)

**Remove:**
```rust
use tracing::{debug, trace};
```

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct ThresholdStatus {
    pub ready: bool,
    pub input_count: usize,
    pub required_signatures: usize,
    pub per_input_signature_counts: Vec<usize>,
    pub missing_inputs: Vec<u32>,
}

impl ThresholdStatus {
    pub fn missing_signatures(&self) -> Vec<(u32, usize)> {
        self.per_input_signature_counts
            .iter()
            .enumerate()
            .filter(|(_, &count)| count < self.required_signatures)
            .map(|(idx, &count)| (idx as u32, self.required_signatures - count))
            .collect()
    }
}
```

**Application Layer Logging:**
```rust
let status = finalization::threshold_status(&partials, input_count, required);

if status.ready {
    info!(
        input_count = status.input_count,
        required = status.required_signatures,
        "threshold met, ready to finalize"
    );
} else {
    debug!(
        input_count = status.input_count,
        required = status.required_signatures,
        missing = ?status.missing_signatures(),
        "threshold not yet met"
    );
}
```

---

### 11. `domain/request/state_machine.rs`

**Current State:** Has `debug!`, `info!`, `warn!` logging (7 calls)

**Remove:**
```rust
use tracing::{debug, info, warn};
```

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct StateTransitionResult {
    pub valid: bool,
    pub from_state: String,
    pub to_state: String,
    pub transition_reason: Option<String>,
}
```

**Application Layer Logging:**
```rust
let transition = state_machine::validate_transition(&from, &to);

if transition.valid {
    info!(
        from = %transition.from_state,
        to = %transition.to_state,
        reason = ?transition.transition_reason,
        "request state transition"
    );
} else {
    error!(
        from = %transition.from_state,
        to = %transition.to_state,
        "invalid state transition attempted"
    );
}
```

---

### 12. `domain/event/validation.rs`

**Current State:** Pure (no logging) - No changes needed

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct EventParsingResult {
    pub event: SigningEvent,
    pub derivation_path_source: DerivationPathSource,
    pub signature_source: SignatureSource,
}

#[derive(Debug, Clone, Copy)]
pub enum DerivationPathSource {
    ExplicitPath,
    DerivedFromIndex { index: u32 },
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureSource {
    HexField,
    BinaryField,
    None,
}
```

**Application Layer Logging:**
```rust
let parsed = event_validation::into_signing_event(wire)?;
debug!(
    event_id = %parsed.event.event_id,
    derivation_source = ?parsed.derivation_path_source,
    signature_source = ?parsed.signature_source,
    "signing event parsed"
);
```

---

### 13. `domain/group_id.rs`

**Current State:** Pure (no logging) - No changes needed

**Add Rich Result Type:**
```rust
#[derive(Debug, Clone)]
pub struct GroupIdComputationResult {
    pub group_id: Hash32,
    pub member_count: usize,
    pub threshold_m: u16,
    pub threshold_n: u16,
    pub network_id: u8,
}

#[derive(Debug, Clone)]
pub struct GroupIdVerificationResult {
    pub matches: bool,
    pub computed: Hash32,
    pub expected: Hash32,
}
```

**Application Layer Logging:**
```rust
let computed = group_id::compute_group_id(&config)?;
debug!(
    group_id = %hex::encode(computed.group_id),
    member_count = computed.member_count,
    threshold = format!("{}/{}", computed.threshold_m, computed.threshold_n),
    network_id = computed.network_id,
    "group id computed"
);

let verification = group_id::verify_group_id(&config, &expected)?;
if !verification.matches {
    error!(
        computed = %hex::encode(verification.computed),
        expected = %hex::encode(verification.expected),
        "group id mismatch"
    );
}
```

---

## Summary: New Types to Add

### `domain/validation/types.rs` (new file)

```rust
//! Rich result types for validation operations

pub mod hyperlane {
    #[derive(Debug, Clone)]
    pub struct VerificationResult { /* ... */ }

    #[derive(Debug, Clone)]
    pub enum VerificationFailure { /* ... */ }
}

pub mod layerzero {
    #[derive(Debug, Clone)]
    pub struct VerificationResult { /* ... */ }

    #[derive(Debug, Clone)]
    pub enum VerificationFailure { /* ... */ }
}
```

### `domain/policy/types.rs` (new file)

```rust
//! Rich result types for policy evaluation

#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult { /* ... */ }

#[derive(Debug, Clone)]
pub struct PolicyCheck { /* ... */ }

#[derive(Debug, Clone, Copy)]
pub enum PolicyCheckType { /* ... */ }

#[derive(Debug, Clone)]
pub struct PolicyCheckFailure { /* ... */ }

#[derive(Debug, Clone)]
pub enum PolicyFailureContext { /* ... */ }
```

### `domain/signing/results.rs` (new file)

```rust
//! Rich result types for signing operations

#[derive(Debug, Clone)]
pub struct SigningResult { /* ... */ }

#[derive(Debug, Clone)]
pub struct SignatureOutput { /* ... */ }
```

### `domain/pskt/results.rs` (new file)

```rust
//! Rich result types for PSKT operations

#[derive(Debug, Clone)]
pub struct PsktBuildResult { /* ... */ }

#[derive(Debug, Clone)]
pub struct PsktSignResult { /* ... */ }

#[derive(Debug, Clone)]
pub struct PsktFinalizeResult { /* ... */ }

#[derive(Debug, Clone)]
pub struct TransactionExtractionResult { /* ... */ }

#[derive(Debug, Clone)]
pub struct UtxoSelectionResult { /* ... */ }
```

### `domain/coordination/results.rs` (new file)

```rust
//! Rich result types for coordination operations

#[derive(Debug, Clone)]
pub struct ThresholdStatus { /* ... */ }

#[derive(Debug, Clone)]
pub struct ValidationStep { /* ... */ }
```

---

## Application Layer Logging Patterns

### Pattern 1: Match on Result

```rust
match domain_operation() {
    Ok(result) => {
        info!(field1 = %result.field1, field2 = result.field2, "operation succeeded");
    }
    Err(err) => {
        warn!(error = %err, "operation failed");
    }
}
```

### Pattern 2: Inspect and Continue

```rust
let result = domain_operation()?;

// Log based on result content
if result.has_warnings() {
    warn!(warnings = ?result.warnings, "operation completed with warnings");
} else {
    debug!(details = ?result, "operation completed");
}

// Continue with result
process(result)
```

### Pattern 3: Audit + Operational Logging

```rust
let result = domain_operation()?;

// Operational log (for debugging/monitoring)
info!(
    request_id = %request_id,
    outcome = ?result.outcome,
    "operation completed"
);

// Audit log (for compliance/security)
audit(AuditEvent::OperationCompleted {
    request_id: request_id.to_string(),
    outcome: result.outcome.to_string(),
    timestamp_ns: now_nanos(),
});
```

---

## Migration Checklist

### Phase 1: Create Rich Result Types
- [ ] Create `domain/validation/types.rs` with rich result types
- [ ] Create `domain/policy/types.rs` with rich result types
- [ ] Create `domain/signing/results.rs` with rich result types
- [ ] Create `domain/pskt/results.rs` with rich result types
- [ ] Create `domain/coordination/results.rs` with rich result types
- [ ] Create `domain/request/results.rs` with rich result types

### Phase 2: Refactor Domain Files (7 files, ~64 log calls)
- [ ] Refactor `validation/hyperlane.rs` - remove tracing (10 calls)
- [ ] Refactor `validation/layerzero.rs` - remove tracing (5 calls)
- [ ] Refactor `policy/enforcement.rs` - remove tracing (9 calls)
- [ ] Refactor `signing/threshold.rs` - remove tracing (8 calls)
- [ ] Refactor `pskt/multisig.rs` - remove tracing (22 calls)
- [ ] Refactor `coordination/finalization.rs` - remove tracing (3 calls)
- [ ] Refactor `request/state_machine.rs` - remove tracing (7 calls)

### Phase 3: Update Application/Service Layer Logging
- [ ] Update `application/signer.rs` to log based on domain results
- [ ] Update `application/coordinator.rs` to log based on domain results
- [ ] Update `application/event_processor.rs` to log based on domain results
- [ ] Update `service/coordination/loop.rs` to log based on domain results
- [ ] Update `service/coordination/finalization.rs` to log based on domain results
- [ ] Update `service/flow.rs` to log based on domain results

### Phase 4: Verification
- [ ] Run: `grep -r "use tracing" igra-core/src/domain/` (should return empty)
- [ ] Run: `grep -r "tracing::" igra-core/src/domain/` (should return empty)
- [ ] Run full test suite: `cargo test -p igra-core`
- [ ] Run integration tests: `cargo test -p igra-service`

### Estimated Effort
| Phase | Files | Effort |
|-------|-------|--------|
| Phase 1 | 6 new files | 4-6 hours |
| Phase 2 | 7 files, 64 calls | 6-8 hours |
| Phase 3 | 6 files | 4-6 hours |
| Phase 4 | - | 1-2 hours |
| **Total** | | **15-22 hours**
