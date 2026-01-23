use crate::foundation::ThresholdError;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ThresholdError> {
    hex::decode(s).map_err(|e| e.into())
}

pub fn decode_hex_prefixed(value: &str) -> Result<Vec<u8>, ThresholdError> {
    let stripped = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    hex::decode(stripped).map_err(|err| ThresholdError::ParseError(format!("invalid hex: {err}")))
}

pub fn parse_hex_fixed<const N: usize>(value: &str) -> Result<[u8; N], ThresholdError> {
    let bytes = decode_hex_prefixed(value)?;
    if bytes.len() != N {
        return Err(ThresholdError::ParseError(format!("expected {N} bytes, got {}", bytes.len())));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn parse_hex_32bytes(value: &str) -> Result<[u8; 32], ThresholdError> {
    parse_hex_fixed::<32>(value)
}

pub fn parse_hex_32bytes_allow_64bytes(value: &str) -> Result<[u8; 32], ThresholdError> {
    let stripped = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped).map_err(|err| ThresholdError::ParseError(format!("invalid hex: {err}")))?;
    let bytes = match bytes.len() {
        32 => bytes,
        64 => bytes[0..32].to_vec(),
        other => return Err(ThresholdError::ParseError(format!("expected 32 or 64 bytes, got {}", other))),
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
