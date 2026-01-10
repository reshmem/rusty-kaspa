use crate::domain::{EventSource, SigningEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SigningEventParams {
    pub session_id_hex: String,
    pub request_id: String,
    pub coordinator_peer_id: String,
    pub expires_at_nanos: u64,
    pub signing_event: SigningEventWire,
}

#[derive(Debug, Serialize)]
pub struct SigningEventResult {
    pub session_id_hex: String,
    pub event_hash_hex: String,
    pub validation_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct SigningEventWire {
    pub event_id: String,
    pub event_source: EventSource,
    pub derivation_path: String,
    pub derivation_index: Option<u32>,
    pub destination_address: String,
    pub amount_sompi: u64,
    pub metadata: std::collections::BTreeMap<String, String>,
    pub timestamp_nanos: u64,
    pub signature_hex: Option<String>,
    pub signature: Option<Vec<u8>>,
}

impl SigningEventWire {
    pub fn into_signing_event(self) -> Result<SigningEvent, crate::foundation::error::ThresholdError> {
        super::validation::into_signing_event(self)
    }
}
