use crate::domain::hashes::event_hash_without_signature;
use crate::domain::validation::types::{HyperlaneVerificationFailure, HyperlaneVerificationResult};
use crate::domain::{EventSource, SigningEvent};
use crate::foundation::ThresholdError;
use secp256k1::ecdsa::Signature as SecpSignature;
use secp256k1::{Message, PublicKey, Secp256k1};

pub fn verify_event(
    event: &SigningEvent,
    validators: &[PublicKey],
    threshold: usize,
) -> Result<HyperlaneVerificationResult, ThresholdError> {
    if !matches!(event.event_source, EventSource::Hyperlane { .. }) {
        return Ok(HyperlaneVerificationResult {
            valid: true,
            event_hash: [0u8; 32],
            validator_count: 0,
            signatures_checked: 0,
            valid_signatures: 0,
            threshold_required: 0,
            failure_reason: None,
        });
    }
    if validators.is_empty() {
        let event_hash = event_hash_without_signature(event)?;
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
    let Some(signature) = event.signature.as_ref() else {
        let event_hash = event_hash_without_signature(event)?;
        return Ok(HyperlaneVerificationResult {
            valid: false,
            event_hash,
            validator_count: validators.len(),
            signatures_checked: 0,
            valid_signatures: 0,
            threshold_required: threshold,
            failure_reason: Some(HyperlaneVerificationFailure::NoSignatureProvided),
        });
    };
    let hash = event_hash_without_signature(event)?;
    let message = Message::from_digest_slice(&hash)?;
    let signatures = match signature.len() {
        64 => match SecpSignature::from_compact(signature) {
            Ok(sig) => vec![sig],
            Err(_) => {
                return Ok(HyperlaneVerificationResult {
                    valid: false,
                    event_hash: hash,
                    validator_count: validators.len(),
                    signatures_checked: 1,
                    valid_signatures: 0,
                    threshold_required: threshold,
                    failure_reason: Some(HyperlaneVerificationFailure::InvalidSignatureFormat { chunk_index: 0 }),
                });
            }
        },
        len if len > 64 && len % 64 == 0 => {
            const MAX_SIGNATURE_CHUNKS: usize = 256;
            let chunk_count = len / 64;
            if chunk_count > MAX_SIGNATURE_CHUNKS {
                return Ok(HyperlaneVerificationResult {
                    valid: false,
                    event_hash: hash,
                    validator_count: validators.len(),
                    signatures_checked: 0,
                    valid_signatures: 0,
                    threshold_required: threshold,
                    failure_reason: Some(HyperlaneVerificationFailure::TooManySignatureChunks {
                        chunks: chunk_count,
                        max: MAX_SIGNATURE_CHUNKS,
                    }),
                });
            }
            let mut signatures = Vec::with_capacity(chunk_count);
            for (chunk_index, chunk) in signature.chunks(64).enumerate() {
                match SecpSignature::from_compact(chunk) {
                    Ok(sig) => signatures.push(sig),
                    Err(_) => {
                        return Ok(HyperlaneVerificationResult {
                            valid: false,
                            event_hash: hash,
                            validator_count: validators.len(),
                            signatures_checked: chunk_index.saturating_add(1),
                            valid_signatures: 0,
                            threshold_required: threshold,
                            failure_reason: Some(HyperlaneVerificationFailure::InvalidSignatureFormat { chunk_index }),
                        });
                    }
                }
            }
            signatures
        }
        _ => match SecpSignature::from_der(signature) {
            Ok(sig) => vec![sig],
            Err(_) => {
                return Ok(HyperlaneVerificationResult {
                    valid: false,
                    event_hash: hash,
                    validator_count: validators.len(),
                    signatures_checked: 1,
                    valid_signatures: 0,
                    threshold_required: threshold,
                    failure_reason: Some(HyperlaneVerificationFailure::InvalidSignatureFormat { chunk_index: 0 }),
                });
            }
        },
    };

    let secp = Secp256k1::verification_only();
    let mut used = vec![false; validators.len()];
    let mut matched = 0usize;

    let signature_chunks = signatures.len();
    for (_sig_index, sig) in signatures.iter().enumerate() {
        for (idx, validator) in validators.iter().enumerate() {
            if used[idx] {
                continue;
            }
            if secp.verify_ecdsa(&message, sig, validator).is_ok() {
                used[idx] = true;
                matched += 1;
                break;
            }
        }
        if matched >= threshold {
            return Ok(HyperlaneVerificationResult {
                valid: true,
                event_hash: hash,
                validator_count: validators.len(),
                signatures_checked: signature_chunks,
                valid_signatures: matched,
                threshold_required: threshold,
                failure_reason: None,
            });
        }
    }

    Ok(HyperlaneVerificationResult {
        valid: false,
        event_hash: hash,
        validator_count: validators.len(),
        signatures_checked: signature_chunks,
        valid_signatures: matched,
        threshold_required: threshold,
        failure_reason: Some(HyperlaneVerificationFailure::InsufficientValidSignatures { valid: matched, required: threshold }),
    })
}
