use crate::foundation::ThresholdError;
use crate::foundation::Hash32;
use super::traits::{MessageEnvelope, TransportMessage};
use bincode::Options;

pub fn encode_envelope(envelope: &MessageEnvelope) -> Result<Vec<u8>, ThresholdError> {
    bincode::DefaultOptions::new().with_fixint_encoding().serialize(envelope).map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn decode_envelope(bytes: &[u8]) -> Result<MessageEnvelope, ThresholdError> {
    bincode::DefaultOptions::new().with_fixint_encoding().deserialize(bytes).map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn payload_hash(payload: &TransportMessage) -> Result<Hash32, ThresholdError> {
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(payload)
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
