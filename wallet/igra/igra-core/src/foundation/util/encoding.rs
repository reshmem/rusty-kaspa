use crate::foundation::ThresholdError;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ThresholdError> {
    hex::decode(s).map_err(|e| e.into())
}

pub fn decode_hex_exact<const N: usize>(s: &str) -> Result<[u8; N], ThresholdError> {
    let bytes = decode_hex(s)?;
    let len = bytes.len();
    let array: [u8; N] = bytes.try_into().map_err(|_| ThresholdError::Message(format!("expected {N} bytes hex, got {}", len)))?;
    Ok(array)
}

pub fn decode_hex_array(s: &str) -> Result<Vec<u8>, ThresholdError> {
    decode_hex(s)
}
