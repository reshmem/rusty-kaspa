use crate::coordination::hashes::event_hash_without_signature;
use crate::error::ThresholdError;
use crate::model::{EventSource, SigningEvent};
use secp256k1::ecdsa::Signature as SecpSignature;
use secp256k1::{Message, PublicKey, Secp256k1};
use tracing::debug;

pub fn verify_event(event: &SigningEvent, validators: &[PublicKey]) -> Result<(), ThresholdError> {
    if !matches!(event.event_source, EventSource::Hyperlane { .. }) {
        return Ok(());
    }
    debug!(
        event_id = %event.event_id,
        validator_count = validators.len(),
        "verifying hyperlane signature"
    );
    if validators.is_empty() {
        return Err(ThresholdError::ConfigError("no hyperlane validators configured".to_string()));
    }
    let signature = event.signature.as_ref().ok_or(ThresholdError::EventSignatureInvalid)?;
    let hash = event_hash_without_signature(event)?;
    let message = Message::from_digest_slice(&hash).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let signatures = match signature.len() {
        64 => vec![SecpSignature::from_compact(signature).map_err(|err| ThresholdError::Message(err.to_string()))?],
        len if len > 64 && len % 64 == 0 => {
            let mut signatures = Vec::new();
            for chunk in signature.chunks(64) {
                signatures.push(SecpSignature::from_compact(chunk).map_err(|err| ThresholdError::Message(err.to_string()))?);
            }
            signatures
        }
        _ => vec![SecpSignature::from_der(signature).map_err(|err| ThresholdError::Message(err.to_string()))?],
    };

    let min_required = if signatures.len() > 1 { 2 } else { 1 };
    let secp = Secp256k1::verification_only();
    let mut used = vec![false; validators.len()];
    let mut matched = 0usize;

    for sig in signatures {
        for (idx, validator) in validators.iter().enumerate() {
            if used[idx] {
                continue;
            }
            if secp.verify_ecdsa(&message, &sig, validator).is_ok() {
                used[idx] = true;
                matched += 1;
                break;
            }
        }
        if matched >= min_required {
            return Ok(());
        }
    }

    Err(ThresholdError::EventSignatureInvalid)
}
