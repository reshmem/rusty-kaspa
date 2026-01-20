use crate::domain::hashes::compute_event_id;
use crate::domain::validation::types::{LayerZeroVerificationFailure, LayerZeroVerificationResult};
use crate::domain::{SourceType, StoredEvent};
use crate::foundation::ThresholdError;
use secp256k1::ecdsa::Signature as SecpSignature;
use secp256k1::{Message, PublicKey, Secp256k1};

pub fn verify_event(event: &StoredEvent, validators: &[PublicKey]) -> Result<LayerZeroVerificationResult, ThresholdError> {
    let event_id = compute_event_id(&event.event);
    if !matches!(event.event.source, SourceType::LayerZero { .. }) {
        return Ok(LayerZeroVerificationResult {
            valid: true,
            event_id,
            validator_count: 0,
            matching_validator_index: None,
            failure_reason: None,
        });
    }
    if validators.is_empty() {
        return Ok(LayerZeroVerificationResult {
            valid: false,
            event_id,
            validator_count: 0,
            matching_validator_index: None,
            failure_reason: Some(LayerZeroVerificationFailure::NoValidatorsConfigured),
        });
    }
    let Some(signature) = event.proof.as_ref() else {
        return Ok(LayerZeroVerificationResult {
            valid: false,
            event_id,
            validator_count: validators.len(),
            matching_validator_index: None,
            failure_reason: Some(LayerZeroVerificationFailure::NoSignatureProvided),
        });
    };
    let message = Message::from_digest_slice(event_id.as_ref())?;
    let sig = match signature.len() {
        64 => match SecpSignature::from_compact(signature) {
            Ok(sig) => sig,
            Err(_) => {
                return Ok(LayerZeroVerificationResult {
                    valid: false,
                    event_id,
                    validator_count: validators.len(),
                    matching_validator_index: None,
                    failure_reason: Some(LayerZeroVerificationFailure::InvalidSignatureFormat),
                });
            }
        },
        _ => match SecpSignature::from_der(signature) {
            Ok(sig) => sig,
            Err(_) => {
                return Ok(LayerZeroVerificationResult {
                    valid: false,
                    event_id,
                    validator_count: validators.len(),
                    matching_validator_index: None,
                    failure_reason: Some(LayerZeroVerificationFailure::InvalidSignatureFormat),
                });
            }
        },
    };
    let secp = Secp256k1::verification_only();
    for (idx, validator) in validators.iter().enumerate() {
        if secp.verify_ecdsa(&message, &sig, validator).is_ok() {
            return Ok(LayerZeroVerificationResult {
                valid: true,
                event_id,
                validator_count: validators.len(),
                matching_validator_index: Some(idx),
                failure_reason: None,
            });
        }
    }
    Ok(LayerZeroVerificationResult {
        valid: false,
        event_id,
        validator_count: validators.len(),
        matching_validator_index: None,
        failure_reason: Some(LayerZeroVerificationFailure::NoMatchingValidator),
    })
}
