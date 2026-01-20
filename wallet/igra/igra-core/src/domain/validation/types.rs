//! Rich result types for message verification (no logging in domain).

use crate::foundation::EventId;

#[derive(Debug, Clone)]
pub struct HyperlaneVerificationResult {
    pub valid: bool,
    pub event_id: EventId,
    pub validator_count: usize,
    pub signatures_checked: usize,
    pub valid_signatures: usize,
    pub threshold_required: usize,
    pub failure_reason: Option<HyperlaneVerificationFailure>,
}

#[derive(Debug, Clone)]
pub enum HyperlaneVerificationFailure {
    NoValidatorsConfigured,
    NoSignatureProvided,
    MissingMetadataField { field: &'static str },
    MessageIdMismatch,
    TooManySignatureChunks { chunks: usize, max: usize },
    InsufficientValidSignatures { valid: usize, required: usize },
    InvalidSignatureFormat { chunk_index: usize },
}

#[derive(Debug, Clone)]
pub struct LayerZeroVerificationResult {
    pub valid: bool,
    pub event_id: EventId,
    pub validator_count: usize,
    pub matching_validator_index: Option<usize>,
    pub failure_reason: Option<LayerZeroVerificationFailure>,
}

#[derive(Debug, Clone)]
pub enum LayerZeroVerificationFailure {
    NoValidatorsConfigured,
    NoSignatureProvided,
    NoMatchingValidator,
    InvalidSignatureFormat,
}
