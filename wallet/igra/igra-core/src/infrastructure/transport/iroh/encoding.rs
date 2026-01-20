use super::traits::{MessageEnvelope, TransportMessage};
use crate::foundation::{PayloadHash, ThresholdError};
use bincode::Options;

const WIRE_PROTOCOL_VERSION_V1: u16 = 1;

pub fn encode_envelope(envelope: &MessageEnvelope) -> Result<Vec<u8>, ThresholdError> {
    let mut out = Vec::new();
    out.extend_from_slice(&WIRE_PROTOCOL_VERSION_V1.to_le_bytes());
    let bytes =
        bincode::DefaultOptions::new().with_fixint_encoding().serialize(envelope).map_err(|err| crate::serde_err!("bincode", err))?;
    out.extend_from_slice(&bytes);
    Ok(out)
}

pub fn decode_envelope(bytes: &[u8]) -> Result<MessageEnvelope, ThresholdError> {
    if bytes.len() < 2 {
        return Err(ThresholdError::NetworkError("gossip message too short".to_string()));
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    if version != WIRE_PROTOCOL_VERSION_V1 {
        return Err(ThresholdError::NetworkError(format!(
            "wire protocol version mismatch: expected {WIRE_PROTOCOL_VERSION_V1}, got {version}"
        )));
    }
    bincode::DefaultOptions::new().with_fixint_encoding().deserialize(&bytes[2..]).map_err(|err| crate::serde_err!("bincode", err))
}

pub fn payload_hash(payload: &TransportMessage) -> Result<PayloadHash, ThresholdError> {
    let bytes =
        bincode::DefaultOptions::new().with_fixint_encoding().serialize(payload).map_err(|err| crate::serde_err!("bincode", err))?;
    Ok(PayloadHash::from(*blake3::hash(&bytes).as_bytes()))
}
