//! Rich result types for signing operations (no logging in domain).

use crate::foundation::RequestId;

#[derive(Debug, Clone)]
pub struct SigningResult {
    pub request_id: RequestId,
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
