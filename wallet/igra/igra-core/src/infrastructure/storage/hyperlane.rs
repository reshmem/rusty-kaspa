use crate::foundation::{ExternalId, Hash32, TransactionId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HyperlaneDeliveryRecord {
    pub message_id: ExternalId,
    pub tx_id: TransactionId,
    pub daa_score: u64,
    pub timestamp_nanos: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HyperlaneMessageRecord {
    pub message_id: ExternalId,
    pub sender: Hash32,
    pub recipient: Hash32,
    pub origin: u32,
    pub destination: u32,
    pub body_hex: String,
    pub nonce: u32,
    pub tx_id: TransactionId,
    pub daa_score: u64,
    pub log_index: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HyperlaneDeliveredMessage {
    pub delivery: HyperlaneDeliveryRecord,
    pub message: HyperlaneMessageRecord,
}
