use crate::domain::SigningEvent;
use crate::foundation::error::ThresholdError;
use crate::foundation::Hash32;
use bincode::Options;
use blake3::Hasher;

pub fn event_hash(event: &SigningEvent) -> Result<Hash32, ThresholdError> {
    // Event hashes must be deterministic across signers.
    // Any locally-derived fields (e.g. wall-clock timestamps) MUST NOT affect the hash.
    let mut canonical = event.clone();
    canonical.signature = None;
    canonical.timestamp_nanos = 0;

    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&canonical)
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub fn event_hash_without_signature(event: &SigningEvent) -> Result<Hash32, ThresholdError> {
    event_hash(event)
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
