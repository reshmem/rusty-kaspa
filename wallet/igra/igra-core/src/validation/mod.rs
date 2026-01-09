#[cfg(feature = "hyperlane")]
pub mod hyperlane;
#[cfg(not(feature = "hyperlane"))]
pub mod hyperlane {
    use crate::error::ThresholdError;
    use crate::model::SigningEvent;
    use secp256k1::PublicKey;

    pub fn verify_event(_event: &SigningEvent, _validators: &[PublicKey]) -> Result<(), ThresholdError> {
        Err(ThresholdError::Message("hyperlane verification disabled".to_string()))
    }
}

#[cfg(feature = "layerzero")]
pub mod layerzero;
#[cfg(not(feature = "layerzero"))]
pub mod layerzero {
    use crate::error::ThresholdError;
    use crate::model::SigningEvent;
    use secp256k1::PublicKey;

    pub fn verify_event(_event: &SigningEvent, _validators: &[PublicKey]) -> Result<(), ThresholdError> {
        Err(ThresholdError::Message("layerzero verification disabled".to_string()))
    }
}
pub mod verifier;

use crate::error::ThresholdError;
use secp256k1::PublicKey;

pub use verifier::{CompositeVerifier, MessageVerifier, NoopVerifier, ValidationSource, VerificationReport};

pub fn parse_validator_pubkeys(label: &str, values: &[String]) -> Result<Vec<PublicKey>, ThresholdError> {
    let mut validators = Vec::new();
    for entry in values.iter().filter(|s| !s.trim().is_empty()) {
        let stripped = entry.trim().trim_start_matches("0x");
        let bytes = hex::decode(stripped)?;
        if bytes.len() != 33 && bytes.len() != 65 {
            return Err(ThresholdError::Message(format!("{} validator key must be 33 or 65 bytes (secp256k1)", label)));
        }
        let key = PublicKey::from_slice(&bytes).map_err(|err| ThresholdError::Message(err.to_string()))?;
        validators.push(key);
    }
    Ok(validators)
}
