use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    EventReplayed,
    EventSignatureInvalid,
    EventExpired,
    DestinationNotAllowed,
    AmountTooLow,
    AmountTooHigh,
    VelocityLimitExceeded,
    MemoRequired,
    PsktValidationFailed,
    PsktMismatch,
    InsufficientUTXOs,
    TransactionMismatch,
    SigningFailed,
    ThresholdNotMet,
    InvalidSignature,
    MessageReplayed,
    SignatureVerificationFailed,
    InvalidPeerIdentity,
    StorageError,
    KeyNotFound,
    ConfigError,
    InvalidStateTransition,
    InvalidDerivationPath,
    NodeRpcError,
    NodeNotSynced,
    Unimplemented,
    Message,
}

#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum ThresholdError {
    #[error("event already processed: {0}")]
    EventReplayed(String),

    #[error("event signature verification failed")]
    EventSignatureInvalid,

    #[error("event expired at {expired_at}, current time {current_time}")]
    EventExpired { expired_at: u64, current_time: u64 },

    #[error("destination not allowed: {0}")]
    DestinationNotAllowed(String),

    #[error("amount {amount} below minimum {min}")]
    AmountTooLow { amount: u64, min: u64 },

    #[error("amount {amount} exceeds maximum {max}")]
    AmountTooHigh { amount: u64, max: u64 },

    #[error("daily volume exceeded: current={current}, limit={limit}")]
    VelocityLimitExceeded { current: u64, limit: u64 },

    #[error("reason metadata required")]
    MemoRequired,

    #[error("pskt validation failed: {0}")]
    PsktValidationFailed(String),

    #[error("pskt mismatch: expected {expected}, got {actual}")]
    PsktMismatch { expected: String, actual: String },

    #[error("insufficient UTXOs to cover amount + fee")]
    InsufficientUTXOs,

    #[error("transaction hash mismatch")]
    TransactionMismatch,

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("threshold not met: required {required}, received {received}")]
    ThresholdNotMet { required: u16, received: u16 },

    #[error("invalid signature for input {input_index}")]
    InvalidSignature { input_index: usize },

    #[error("message replayed")]
    MessageReplayed,

    #[error("envelope signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid peer identity")]
    InvalidPeerIdentity,

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("node RPC error: {0}")]
    NodeRpcError(String),

    #[error("node not synced")]
    NodeNotSynced,

    #[error("feature not implemented: {0}")]
    Unimplemented(String),

    #[error("{0}")]
    Message(String),
}

impl ThresholdError {
    pub fn code(&self) -> ErrorCode {
        match self {
            ThresholdError::EventReplayed(_) => ErrorCode::EventReplayed,
            ThresholdError::EventSignatureInvalid => ErrorCode::EventSignatureInvalid,
            ThresholdError::EventExpired { .. } => ErrorCode::EventExpired,
            ThresholdError::DestinationNotAllowed(_) => ErrorCode::DestinationNotAllowed,
            ThresholdError::AmountTooLow { .. } => ErrorCode::AmountTooLow,
            ThresholdError::AmountTooHigh { .. } => ErrorCode::AmountTooHigh,
            ThresholdError::VelocityLimitExceeded { .. } => ErrorCode::VelocityLimitExceeded,
            ThresholdError::MemoRequired => ErrorCode::MemoRequired,
            ThresholdError::PsktValidationFailed(_) => ErrorCode::PsktValidationFailed,
            ThresholdError::PsktMismatch { .. } => ErrorCode::PsktMismatch,
            ThresholdError::InsufficientUTXOs => ErrorCode::InsufficientUTXOs,
            ThresholdError::TransactionMismatch => ErrorCode::TransactionMismatch,
            ThresholdError::SigningFailed(_) => ErrorCode::SigningFailed,
            ThresholdError::ThresholdNotMet { .. } => ErrorCode::ThresholdNotMet,
            ThresholdError::InvalidSignature { .. } => ErrorCode::InvalidSignature,
            ThresholdError::MessageReplayed => ErrorCode::MessageReplayed,
            ThresholdError::SignatureVerificationFailed => ErrorCode::SignatureVerificationFailed,
            ThresholdError::InvalidPeerIdentity => ErrorCode::InvalidPeerIdentity,
            ThresholdError::StorageError(_) => ErrorCode::StorageError,
            ThresholdError::KeyNotFound(_) => ErrorCode::KeyNotFound,
            ThresholdError::ConfigError(_) => ErrorCode::ConfigError,
            ThresholdError::InvalidStateTransition { .. } => ErrorCode::InvalidStateTransition,
            ThresholdError::InvalidDerivationPath(_) => ErrorCode::InvalidDerivationPath,
            ThresholdError::NodeRpcError(_) => ErrorCode::NodeRpcError,
            ThresholdError::NodeNotSynced => ErrorCode::NodeNotSynced,
            ThresholdError::Unimplemented(_) => ErrorCode::Unimplemented,
            ThresholdError::Message(_) => ErrorCode::Message,
        }
    }

    pub fn context(&self) -> ErrorContext {
        ErrorContext {
            code: self.code(),
            message: self.to_string(),
        }
    }
}
