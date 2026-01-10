use crate::domain::coordination::results::ValidationStep;
use crate::domain::hashes::{event_hash, validation_hash};
use crate::domain::policy::PolicyEnforcer;
use crate::domain::pskt::multisig;
use crate::domain::validation::MessageVerifier;
use crate::domain::{GroupPolicy, SigningEvent};
use crate::foundation::constants::{MAX_SESSION_DURATION_NS, MIN_SESSION_DURATION_NS};
use crate::foundation::Hash32;
use crate::foundation::ThresholdError;
use subtle::ConstantTimeEq;

/// Result of proposal validation without any side effects (no storage/transport).
pub struct ProposalDecision {
    pub accept: bool,
    pub reason: Option<String>,
    pub per_input_hashes: Vec<Hash32>,
    pub validation_steps: Vec<ValidationStep>,
}

pub struct ProposalValidationInput<'a> {
    pub signing_event: &'a SigningEvent,
    pub expected_event_hash: &'a Hash32,
    pub kpsbt_blob: &'a [u8],
    pub tx_template_hash: &'a Hash32,
    pub expected_validation_hash: &'a Hash32,
    pub expires_at_nanos: u64,
    pub now_nanos: u64,
    pub policy: Option<&'a GroupPolicy>,
    pub current_volume: u64,
    pub policy_enforcer: &'a dyn PolicyEnforcer,
    pub message_verifier: Option<&'a dyn MessageVerifier>,
}

/// Pure validation of an incoming proposal.
pub fn validate_proposal(input: ProposalValidationInput<'_>) -> Result<ProposalDecision, ThresholdError> {
    let mut steps = Vec::new();
    let computed_hash = event_hash(input.signing_event)?;
    if !bool::from(computed_hash.ct_eq(input.expected_event_hash)) {
        steps.push(ValidationStep {
            step_name: "event_hash_match",
            passed: false,
            details: Some(format!("computed={}, expected={}", hex::encode(computed_hash), hex::encode(input.expected_event_hash))),
        });
        return Ok(ProposalDecision {
            accept: false,
            reason: Some("event_hash_mismatch".to_string()),
            per_input_hashes: vec![],
            validation_steps: steps,
        });
    }
    steps.push(ValidationStep { step_name: "event_hash_match", passed: true, details: None });

    if let Some(verifier) = input.message_verifier {
        let report = verifier.verify(input.signing_event)?;
        if !report.valid {
            steps.push(ValidationStep { step_name: "message_verification", passed: false, details: report.failure_reason.clone() });
            return Ok(ProposalDecision {
                accept: false,
                reason: Some(report.failure_reason.unwrap_or_else(|| "message_verification_failed".to_string())),
                per_input_hashes: vec![],
                validation_steps: steps,
            });
        }
        steps.push(ValidationStep { step_name: "message_verification", passed: true, details: None });
    }

    let signer_pskt = multisig::deserialize_pskt_signer(input.kpsbt_blob)?;
    let computed_tx_hash = multisig::tx_template_hash(&signer_pskt)?;
    if !bool::from(computed_tx_hash.ct_eq(input.tx_template_hash)) {
        steps.push(ValidationStep {
            step_name: "tx_template_hash_match",
            passed: false,
            details: Some(format!("computed={}, expected={}", hex::encode(computed_tx_hash), hex::encode(input.tx_template_hash))),
        });
        return Ok(ProposalDecision {
            accept: false,
            reason: Some("tx_template_hash_mismatch".to_string()),
            per_input_hashes: vec![],
            validation_steps: steps,
        });
    }
    steps.push(ValidationStep { step_name: "tx_template_hash_match", passed: true, details: None });

    let per_input_hashes = multisig::input_hashes(&signer_pskt)?;
    let computed_validation = validation_hash(input.expected_event_hash, input.tx_template_hash, &per_input_hashes);
    if !bool::from(computed_validation.ct_eq(input.expected_validation_hash)) {
        steps.push(ValidationStep {
            step_name: "validation_hash_match",
            passed: false,
            details: Some(format!(
                "computed={}, expected={}",
                hex::encode(computed_validation),
                hex::encode(input.expected_validation_hash)
            )),
        });
        return Ok(ProposalDecision {
            accept: false,
            reason: Some("validation_hash_mismatch".to_string()),
            per_input_hashes: vec![],
            validation_steps: steps,
        });
    }
    steps.push(ValidationStep { step_name: "validation_hash_match", passed: true, details: None });

    const CLOCK_SKEW_TOLERANCE_NS: u64 = 30 * 1_000_000_000;
    let min_expiry = input.now_nanos.saturating_add(MIN_SESSION_DURATION_NS).saturating_sub(CLOCK_SKEW_TOLERANCE_NS);
    let max_expiry = input.now_nanos.saturating_add(MAX_SESSION_DURATION_NS).saturating_add(CLOCK_SKEW_TOLERANCE_NS);
    if input.expires_at_nanos < min_expiry || input.expires_at_nanos > max_expiry {
        steps.push(ValidationStep {
            step_name: "expires_at_bounds",
            passed: false,
            details: Some(format!("expires_at={}, min={}, max={}", input.expires_at_nanos, min_expiry, max_expiry)),
        });
        return Ok(ProposalDecision {
            accept: false,
            reason: Some("expires_at_nanos_out_of_bounds".to_string()),
            per_input_hashes: vec![],
            validation_steps: steps,
        });
    }
    steps.push(ValidationStep { step_name: "expires_at_bounds", passed: true, details: None });

    if let Some(policy) = input.policy {
        let result = input.policy_enforcer.evaluate_policy(input.signing_event, policy, input.current_volume);
        if !result.allowed {
            steps.push(ValidationStep {
                step_name: "policy_evaluation",
                passed: false,
                details: result.failed_check.as_ref().map(|failure| failure.reason.clone()),
            });
            return Ok(ProposalDecision {
                accept: false,
                reason: result.failed_check.map(|failure| failure.reason).or(Some("policy_rejected".to_string())),
                per_input_hashes: vec![],
                validation_steps: steps,
            });
        }
        steps.push(ValidationStep { step_name: "policy_evaluation", passed: true, details: None });
    }

    Ok(ProposalDecision { accept: true, reason: None, per_input_hashes, validation_steps: steps })
}
