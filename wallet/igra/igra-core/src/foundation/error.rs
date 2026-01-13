use secp256k1::Error as SecpError;
use std::fmt;
use std::io;
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
    SerializationError,
    CryptoError,
    PsktError,
    TransportError,
    KeyNotFound,
    ConfigError,
    InvalidStateTransition,
    InvalidDerivationPath,
    InvalidExternalId,
    InvalidDestination,
    SchemaMismatch,
    NodeRpcError,
    NodeNotSynced,
    Unimplemented,
    InvalidInputIndex,
    MessageTooLarge,
    EncodingError,
    NetworkError,
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

    #[error("storage error during {operation}: {details}")]
    StorageError { operation: String, details: String },

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("invalid external id: {0}")]
    InvalidExternalId(String),

    #[error("invalid destination: {0}")]
    InvalidDestination(String),

    #[error("schema mismatch: stored={stored} current={current}")]
    SchemaMismatch { stored: u32, current: u32 },

    #[error("node RPC error: {0}")]
    NodeRpcError(String),

    #[error("node not synced")]
    NodeNotSynced,

    #[error("feature not implemented: {0}")]
    Unimplemented(String),

    #[error("invalid input index: {index} (max {max})")]
    InvalidInputIndex { index: u32, max: u32 },

    #[error("message too large: {size} exceeds max {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("encoding error: {0}")]
    EncodingError(String),

    #[error("network error: {0}")]
    NetworkError(String),

    #[error("{format} serialization error: {details}")]
    SerializationError { format: String, details: String },

    #[error("crypto error during {operation}: {details}")]
    CryptoError { operation: String, details: String },

    #[error("PSKT error during {operation}: {details}")]
    PsktError { operation: String, details: String },

    #[error("transport error during {operation}: {details}")]
    TransportError { operation: String, details: String },

    #[error("{0}")]
    Message(String),
}

pub type Result<T> = std::result::Result<T, ThresholdError>;

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
            ThresholdError::StorageError { .. } => ErrorCode::StorageError,
            ThresholdError::KeyNotFound(_) => ErrorCode::KeyNotFound,
            ThresholdError::ConfigError(_) => ErrorCode::ConfigError,
            ThresholdError::InvalidStateTransition { .. } => ErrorCode::InvalidStateTransition,
            ThresholdError::InvalidDerivationPath(_) => ErrorCode::InvalidDerivationPath,
            ThresholdError::InvalidExternalId(_) => ErrorCode::InvalidExternalId,
            ThresholdError::InvalidDestination(_) => ErrorCode::InvalidDestination,
            ThresholdError::SchemaMismatch { .. } => ErrorCode::SchemaMismatch,
            ThresholdError::NodeRpcError(_) => ErrorCode::NodeRpcError,
            ThresholdError::NodeNotSynced => ErrorCode::NodeNotSynced,
            ThresholdError::Unimplemented(_) => ErrorCode::Unimplemented,
            ThresholdError::InvalidInputIndex { .. } => ErrorCode::InvalidInputIndex,
            ThresholdError::MessageTooLarge { .. } => ErrorCode::MessageTooLarge,
            ThresholdError::EncodingError(_) => ErrorCode::EncodingError,
            ThresholdError::NetworkError(_) => ErrorCode::NetworkError,
            ThresholdError::SerializationError { .. } => ErrorCode::SerializationError,
            ThresholdError::CryptoError { .. } => ErrorCode::CryptoError,
            ThresholdError::PsktError { .. } => ErrorCode::PsktError,
            ThresholdError::TransportError { .. } => ErrorCode::TransportError,
            ThresholdError::Message(_) => ErrorCode::Message,
        }
    }

    pub fn context(&self) -> ErrorContext {
        ErrorContext { code: self.code(), message: self.to_string() }
    }
}

impl From<hex::FromHexError> for ThresholdError {
    fn from(err: hex::FromHexError) -> Self {
        ThresholdError::Message(format!("hex decode error: {}", err))
    }
}

impl From<toml::de::Error> for ThresholdError {
    fn from(err: toml::de::Error) -> Self {
        ThresholdError::ConfigError(format!("TOML parsing error: {}", err))
    }
}

impl From<rocksdb::Error> for ThresholdError {
    fn from(err: rocksdb::Error) -> Self {
        ThresholdError::StorageError {
            operation: "rocksdb".to_string(),
            details: err.to_string(),
        }
    }
}

impl From<bincode::Error> for ThresholdError {
    fn from(err: bincode::Error) -> Self {
        ThresholdError::SerializationError {
            format: "bincode".to_string(),
            details: err.to_string(),
        }
    }
}

#[macro_export]
macro_rules! storage_err {
    ($op:expr, $err:expr) => {
        crate::foundation::ThresholdError::StorageError {
            operation: $op.into(),
            details: $err.to_string(),
        }
    };
}

#[macro_export]
macro_rules! serde_err {
    ($fmt:expr, $err:expr) => {
        crate::foundation::ThresholdError::SerializationError {
            format: $fmt.into(),
            details: $err.to_string(),
        }
    };
}

impl From<io::Error> for ThresholdError {
    fn from(err: io::Error) -> Self {
        ThresholdError::Message(format!("IO error: {}", err))
    }
}

impl From<serde_json::Error> for ThresholdError {
    fn from(err: serde_json::Error) -> Self {
        ThresholdError::Message(format!("JSON error: {}", err))
    }
}

impl From<kaspa_addresses::AddressError> for ThresholdError {
    fn from(err: kaspa_addresses::AddressError) -> Self {
        ThresholdError::Message(format!("address error: {}", err))
    }
}

impl From<SecpError> for ThresholdError {
    fn from(err: SecpError) -> Self {
        ThresholdError::Message(format!("secp256k1 error: {}", err))
    }
}

pub trait IntoThresholdError {
    fn into_threshold_error(self) -> ThresholdError;
}

impl<E: fmt::Display> IntoThresholdError for E {
    fn into_threshold_error(self) -> ThresholdError {
        ThresholdError::Message(self.to_string())
    }
}
