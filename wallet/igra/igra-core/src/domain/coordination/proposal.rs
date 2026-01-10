use crate::foundation::constants::{MAX_SESSION_DURATION_NS, MIN_SESSION_DURATION_NS};
use crate::domain::hashes::{event_hash, validation_hash};
use crate::domain::policy::PolicyEnforcer;
use crate::foundation::ThresholdError;
use crate::foundation::Hash32;
use crate::domain::{GroupPolicy, SigningEvent};
use crate::domain::pskt::multisig;
use crate::domain::validation::MessageVerifier;
use subtle::ConstantTimeEq;

/// Result of proposal validation without any side effects (no storage/transport).
pub struct ProposalDecision {
    pub accept: bool,
    pub reason: Option<String>,
    pub per_input_hashes: Vec<Hash32>,
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
    let computed_hash = event_hash(input.signing_event)?;
    if !bool::from(computed_hash.ct_eq(input.expected_event_hash)) {
        return Ok(ProposalDecision { accept: false, reason: Some("event_hash_mismatch".to_string()), per_input_hashes: vec![] });
    }

    if let Some(verifier) = input.message_verifier {
        if let Err(err) = verifier.verify(input.signing_event) {
            return Ok(ProposalDecision { accept: false, reason: Some(err.to_string()), per_input_hashes: vec![] });
        }
    }

    let signer_pskt = multisig::deserialize_pskt_signer(input.kpsbt_blob)?;
    let computed_tx_hash = multisig::tx_template_hash(&signer_pskt)?;
    if !bool::from(computed_tx_hash.ct_eq(input.tx_template_hash)) {
        return Ok(ProposalDecision { accept: false, reason: Some("tx_template_hash_mismatch".to_string()), per_input_hashes: vec![] });
    }

    let per_input_hashes = multisig::input_hashes(&signer_pskt)?;
    let computed_validation = validation_hash(input.expected_event_hash, input.tx_template_hash, &per_input_hashes);
    if !bool::from(computed_validation.ct_eq(input.expected_validation_hash)) {
        return Ok(ProposalDecision { accept: false, reason: Some("validation_hash_mismatch".to_string()), per_input_hashes: vec![] });
    }

    let min_expiry = input.now_nanos.saturating_add(MIN_SESSION_DURATION_NS);
    let max_expiry = input.now_nanos.saturating_add(MAX_SESSION_DURATION_NS);
    if input.expires_at_nanos < min_expiry || input.expires_at_nanos > max_expiry {
        return Ok(ProposalDecision { accept: false, reason: Some("expires_at_nanos_out_of_bounds".to_string()), per_input_hashes: vec![] });
    }

    if let Some(policy) = input.policy {
        if let Err(err) = input.policy_enforcer.enforce_policy(input.signing_event, policy, input.current_volume) {
            return Ok(ProposalDecision { accept: false, reason: Some(err.to_string()), per_input_hashes: vec![] });
        }
    }

    Ok(ProposalDecision { accept: true, reason: None, per_input_hashes })
}
