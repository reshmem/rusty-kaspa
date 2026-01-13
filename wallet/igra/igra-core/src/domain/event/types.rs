use crate::domain::SourceType;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
pub struct SigningEventParams {
    pub session_id_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_request_id: Option<String>,
    pub coordinator_peer_id: String,
    pub expires_at_nanos: u64,
    pub event: SigningEventWire,
}

#[derive(Debug, Serialize)]
pub struct SigningEventResult {
    pub session_id_hex: String,
    pub event_id_hex: String,
    pub tx_template_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct SigningEventWire {
    /// Source-provided identifier (e.g. Hyperlane message_id) as received.
    pub external_id: String,
    pub source: SourceType,
    pub destination_address: String,
    pub amount_sompi: u64,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Optional proof/signature bytes (source-specific).
    #[serde(default)]
    pub proof_hex: Option<String>,
    #[serde(default)]
    pub proof: Option<Vec<u8>>,
}
