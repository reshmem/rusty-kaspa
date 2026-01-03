use crate::error::ThresholdError;
use crate::model::{Hash32, SigningEvent};
use bincode::Options;
use blake3::Hasher;

pub fn event_hash(event: &SigningEvent) -> Result<Hash32, ThresholdError> {
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(event)
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub fn event_hash_without_signature(event: &SigningEvent) -> Result<Hash32, ThresholdError> {
    let mut sanitized = event.clone();
    sanitized.signature = None;
    event_hash(&sanitized)
}

pub fn validation_hash(event_hash: &Hash32, tx_template_hash: &Hash32, per_input_hashes: &[Hash32]) -> Hash32 {
    let mut hasher = Hasher::new();
    hasher.update(event_hash);
    hasher.update(tx_template_hash);
    for hash in per_input_hashes {
        hasher.update(hash);
    }
    *hasher.finalize().as_bytes()
}
