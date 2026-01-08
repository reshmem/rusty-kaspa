//! Encoding utilities for hex and helpers used across the codebase.

use crate::error::ThresholdError;

/// Encodes bytes to lowercase hex string.
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decodes hex to a byte vector.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, ThresholdError> {
    hex::decode(s).map_err(|e| e.into())
}

/// Decodes hex to a fixed-size array.
pub fn decode_hex_array<const N: usize>(s: &str) -> Result<[u8; N], ThresholdError> {
    let bytes = decode_hex(s)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| ThresholdError::Message(format!("hex length mismatch: expected {} bytes, got {}", N, len)))
}

/// Short hex for logs (first 8 chars).
pub fn encode_hex_short(bytes: &[u8]) -> String {
    let full = hex::encode(bytes);
    if full.len() > 8 {
        format!("{}...", &full[..8])
    } else {
        full
    }
}
