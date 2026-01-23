pub mod hyperlane;
pub mod layerzero;
pub mod types;
pub mod verifier;

use crate::foundation::decode_hex_prefixed;
use crate::foundation::ThresholdError;
use secp256k1::PublicKey;

pub use verifier::{CompositeVerifier, MessageVerifier, NoopVerifier, ValidationSource, VerificationReport};

/// Parse secp256k1 validator pubkeys from hex strings (33-byte or 65-byte).
pub fn parse_validator_pubkeys(label: &str, values: &[String]) -> Result<Vec<PublicKey>, ThresholdError> {
    let mut validators = Vec::new();
    for entry in values.iter().filter(|s| !s.trim().is_empty()) {
        let bytes = decode_hex_prefixed(entry)?;
        if bytes.len() != 33 && bytes.len() != 65 {
            return Err(ThresholdError::ConfigError(format!(
                "{label} validator key must be 33 or 65 bytes (secp256k1), got {}",
                bytes.len()
            )));
        }
        let key = PublicKey::from_slice(&bytes).map_err(|err| ThresholdError::CryptoError {
            operation: "parse_validator_pubkey".to_string(),
            details: err.to_string(),
        })?;
        validators.push(key);
    }
    Ok(validators)
}
