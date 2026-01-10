use crate::domain::hashes::event_hash_without_signature;
use crate::domain::validation::types::{LayerZeroVerificationFailure, LayerZeroVerificationResult};
use crate::domain::{EventSource, SigningEvent};
use crate::foundation::ThresholdError;
use secp256k1::ecdsa::Signature as SecpSignature;
use secp256k1::{Message, PublicKey, Secp256k1};

pub fn verify_event(event: &SigningEvent, validators: &[PublicKey]) -> Result<LayerZeroVerificationResult, ThresholdError> {
    if !matches!(event.event_source, EventSource::LayerZero { .. }) {
        return Ok(LayerZeroVerificationResult {
            valid: true,
            event_hash: [0u8; 32],
            validator_count: 0,
            matching_validator_index: None,
            failure_reason: None,
        });
    }
    if validators.is_empty() {
        let event_hash = event_hash_without_signature(event)?;
        return Ok(LayerZeroVerificationResult {
            valid: false,
            event_hash,
            validator_count: 0,
            matching_validator_index: None,
            failure_reason: Some(LayerZeroVerificationFailure::NoValidatorsConfigured),
        });
    }
    let Some(signature) = event.signature.as_ref() else {
        let event_hash = event_hash_without_signature(event)?;
        return Ok(LayerZeroVerificationResult {
            valid: false,
            event_hash,
            validator_count: validators.len(),
            matching_validator_index: None,
            failure_reason: Some(LayerZeroVerificationFailure::NoSignatureProvided),
        });
    };
    let hash = event_hash_without_signature(event)?;
    let message = Message::from_digest_slice(&hash)?;
    let sig = match signature.len() {
        64 => match SecpSignature::from_compact(signature) {
            Ok(sig) => sig,
            Err(_) => {
                return Ok(LayerZeroVerificationResult {
                    valid: false,
                    event_hash: hash,
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
                    event_hash: hash,
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
                event_hash: hash,
                validator_count: validators.len(),
                matching_validator_index: Some(idx),
                failure_reason: None,
            });
        }
    }
    Ok(LayerZeroVerificationResult {
        valid: false,
        event_hash: hash,
        validator_count: validators.len(),
        matching_validator_index: None,
        failure_reason: Some(LayerZeroVerificationFailure::NoMatchingValidator),
    })
}
