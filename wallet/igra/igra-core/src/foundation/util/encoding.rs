use crate::foundation::ThresholdError;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ThresholdError> {
    hex::decode(s).map_err(|e| e.into())
}
