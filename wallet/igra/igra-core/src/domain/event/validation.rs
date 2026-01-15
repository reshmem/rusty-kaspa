use super::types::SigningEventParams;
use crate::foundation::error::ThresholdError;
use crate::foundation::{PeerId, SessionId};

pub fn decode_session_and_coordinator_ids(params: &SigningEventParams) -> Result<(SessionId, PeerId), ThresholdError> {
    let session_id = SessionId::from(decode_hash32(&params.session_id_hex)?);
    let coordinator_peer_id = validate_peer_id("coordinator_peer_id", params.coordinator_peer_id.as_str())?;
    Ok((session_id, coordinator_peer_id))
}

fn decode_hash32(value: &str) -> Result<[u8; 32], ThresholdError> {
    let trimmed = value.trim();
    let stripped = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    let bytes = hex::decode(stripped).map_err(|e| ThresholdError::EncodingError(format!("invalid hex '{trimmed}': {e}")))?;
    let array: [u8; 32] =
        bytes.as_slice().try_into().map_err(|_| ThresholdError::EncodingError(format!("expected 32 bytes, got {}", bytes.len())))?;
    Ok(array)
}

fn validate_peer_id(label: &str, value: &str) -> Result<PeerId, ThresholdError> {
    const MAX_LEN: usize = 256;
    if value.len() > MAX_LEN {
        return Err(ThresholdError::EncodingError(format!("{label} too long: {} > {}", value.len(), MAX_LEN)));
    }
    Ok(PeerId::from(value))
}
