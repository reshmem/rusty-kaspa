use crate::coordination::hashes::event_hash_without_signature;
use crate::error::ThresholdError;
use crate::model::{EventSource, SigningEvent};
use secp256k1::ecdsa::Signature as SecpSignature;
use secp256k1::{Message, PublicKey, Secp256k1};
use tracing::debug;

pub fn verify_event(event: &SigningEvent, validators: &[PublicKey]) -> Result<(), ThresholdError> {
    if !matches!(event.event_source, EventSource::LayerZero { .. }) {
        return Ok(());
    }
    debug!(
        event_id = %event.event_id,
        validator_count = validators.len(),
        "verifying layerzero signature"
    );
    if validators.is_empty() {
        return Err(ThresholdError::ConfigError("no layerzero endpoint pubkeys configured".to_string()));
    }
    let signature = event.signature.as_ref().ok_or(ThresholdError::EventSignatureInvalid)?;
    let hash = event_hash_without_signature(event)?;
    let message = Message::from_digest_slice(&hash).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let sig = match signature.len() {
        64 => SecpSignature::from_compact(signature).map_err(|err| ThresholdError::Message(err.to_string()))?,
        _ => SecpSignature::from_der(signature).map_err(|err| ThresholdError::Message(err.to_string()))?,
    };
    let secp = Secp256k1::verification_only();
    for validator in validators {
        if secp.verify_ecdsa(&message, &sig, validator).is_ok() {
            return Ok(());
        }
    }
    Err(ThresholdError::EventSignatureInvalid)
}
