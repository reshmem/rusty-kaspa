//! Rich result types for signing operations (no logging in domain).

use crate::foundation::EventId;

#[derive(Debug, Clone)]
pub struct SigningResult {
    pub event_id: EventId,
    pub input_count: usize,
    pub signatures_produced: Vec<SignatureOutput>,
    pub signer_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignatureOutput {
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}
