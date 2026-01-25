use secp256k1::Error as SecpError;
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
    InvalidPublicKey,
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
    PkarrInitFailed,
    InvalidRelayConfig,
    MalformedRelayUrl,
    InvalidDnsDomain,
    SignedHashConflict,
    MetricsError,
    MissingCrdtState,
    MissingKpsbtBlob,
    ProposalValidationFailed,
    ProposalEventIdMismatch,
    UtxoBelowMinDepth,
    UtxoMissing,
    PolicyEvaluationFailed,
    ParseError,
    SecretNotFound,
    SecretDecodeFailed,
    SecretStoreUnavailable,
    SecretDecryptFailed,
    UnsupportedSecretFileFormat,
    UnsupportedSignatureScheme,
    KeyOperationFailed,
    InsecureFilePermissions,
    AuditLogError,
    RocksDBOpenError,
    StorageLockTimeout,
    MissingSigningPayload,
    HyperlaneBodyTooLarge,
    HyperlaneInvalidUtf8,
    HyperlaneMetadataParseError,
    NoValidatorsConfigured,
    PsktInputMismatch,
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

    #[error("invalid public key: input={input} reason={reason}")]
    InvalidPublicKey { input: String, reason: String },

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

    // === Iroh Discovery / Relay Errors ===
    /// Pkarr DHT discovery initialization failed.
    #[error("pkarr discovery init failed: {details}")]
    PkarrInitFailed { details: String },

    /// Relay configuration is invalid.
    #[error("invalid relay config: {reason}")]
    InvalidRelayConfig { reason: String },

    /// Custom relay URL is malformed.
    #[error("malformed relay url: {url}")]
    MalformedRelayUrl { url: String },

    /// DNS discovery domain is invalid.
    #[error("invalid DNS domain: {domain}")]
    InvalidDnsDomain { domain: String },

    #[error("signed hash conflict: event_id={event_id} existing={existing} attempted={attempted}")]
    SignedHashConflict { event_id: String, existing: String, attempted: String },

    #[error("metrics error during {operation}: {details}")]
    MetricsError { operation: String, details: String },

    #[error("{format} serialization error: {details}")]
    SerializationError { format: String, details: String },

    #[error("crypto error during {operation}: {details}")]
    CryptoError { operation: String, details: String },

    #[error("PSKT error during {operation}: {details}")]
    PsktError { operation: String, details: String },

    #[error("transport error during {operation}: {details}")]
    TransportError { operation: String, details: String },

    #[error("missing CRDT state event_id={event_id} tx_template_hash={tx_template_hash} context={context}")]
    MissingCrdtState { event_id: String, tx_template_hash: String, context: String },

    #[error("missing kpsbt_blob event_id={event_id} tx_template_hash={tx_template_hash} context={context}")]
    MissingKpsbtBlob { event_id: String, tx_template_hash: String, context: String },

    #[error("proposal validation failed: {details}")]
    ProposalValidationFailed { details: String },

    #[error("proposal event_id mismatch: claimed={claimed} computed={computed}")]
    ProposalEventIdMismatch { claimed: String, computed: String },

    #[error("UTXO below min depth outpoint={outpoint} depth={depth} min_required={min_required}")]
    UtxoBelowMinDepth { outpoint: String, depth: u64, min_required: u64 },

    #[error("UTXO missing at commit time outpoint={outpoint}")]
    UtxoMissing { outpoint: String },

    #[error("policy evaluation failed: {details}")]
    PolicyEvaluationFailed { details: String },

    #[error("parse error: {0}")]
    ParseError(String),

    // === Key Management Errors ===
    #[error("secret not found: {name} (backend: {backend})")]
    SecretNotFound {
        name: String,
        backend: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("secret decode failed: {name} (encoding: {encoding}, details: {details})")]
    SecretDecodeFailed {
        name: String,
        encoding: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("secret store unavailable: {backend} - {details}")]
    SecretStoreUnavailable {
        backend: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("secret decryption failed: {backend} - {details}")]
    SecretDecryptFailed {
        backend: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("unsupported secret file format: {details}")]
    UnsupportedSecretFileFormat { details: String },

    #[error("unsupported signature scheme: {scheme} (backend: {backend})")]
    UnsupportedSignatureScheme { scheme: String, backend: String },

    #[error("key operation failed: {operation} on {key_ref} - {details}")]
    KeyOperationFailed {
        operation: String,
        key_ref: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("invalid secret file permissions: {path} has mode {mode:o}, expected 0600")]
    InsecureFilePermissions { path: String, mode: u32 },

    #[error("audit log error: {details}")]
    AuditLogError {
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    // === Storage Errors ===
    #[error("RocksDB open error: {details}")]
    RocksDBOpenError {
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("storage lock timeout: {operation} (waited {timeout_secs}s)")]
    StorageLockTimeout { operation: String, timeout_secs: u64 },

    // === Hyperlane Errors ===
    #[error("missing signing payload for message_id={message_id}")]
    MissingSigningPayload { message_id: String },

    #[error("hyperlane body too large: {size} bytes (max: {max} bytes)")]
    HyperlaneBodyTooLarge { size: usize, max: usize },

    #[error("hyperlane invalid UTF-8 at position {position}")]
    HyperlaneInvalidUtf8 {
        position: usize,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("hyperlane metadata parse error: {details}")]
    HyperlaneMetadataParseError {
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    // === Configuration Errors ===
    #[error("no {validator_type} validators configured")]
    NoValidatorsConfigured { validator_type: String },

    // === PSKT Errors ===
    #[error("PSKT input mismatch: expected {expected}, got {actual} - {details}")]
    PsktInputMismatch { expected: usize, actual: usize, details: String },

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
            ThresholdError::InvalidPublicKey { .. } => ErrorCode::InvalidPublicKey,
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
            ThresholdError::PkarrInitFailed { .. } => ErrorCode::PkarrInitFailed,
            ThresholdError::InvalidRelayConfig { .. } => ErrorCode::InvalidRelayConfig,
            ThresholdError::MalformedRelayUrl { .. } => ErrorCode::MalformedRelayUrl,
            ThresholdError::InvalidDnsDomain { .. } => ErrorCode::InvalidDnsDomain,
            ThresholdError::SignedHashConflict { .. } => ErrorCode::SignedHashConflict,
            ThresholdError::MetricsError { .. } => ErrorCode::MetricsError,
            ThresholdError::SerializationError { .. } => ErrorCode::SerializationError,
            ThresholdError::CryptoError { .. } => ErrorCode::CryptoError,
            ThresholdError::PsktError { .. } => ErrorCode::PsktError,
            ThresholdError::TransportError { .. } => ErrorCode::TransportError,
            ThresholdError::MissingCrdtState { .. } => ErrorCode::MissingCrdtState,
            ThresholdError::MissingKpsbtBlob { .. } => ErrorCode::MissingKpsbtBlob,
            ThresholdError::ProposalValidationFailed { .. } => ErrorCode::ProposalValidationFailed,
            ThresholdError::ProposalEventIdMismatch { .. } => ErrorCode::ProposalEventIdMismatch,
            ThresholdError::UtxoBelowMinDepth { .. } => ErrorCode::UtxoBelowMinDepth,
            ThresholdError::UtxoMissing { .. } => ErrorCode::UtxoMissing,
            ThresholdError::PolicyEvaluationFailed { .. } => ErrorCode::PolicyEvaluationFailed,
            ThresholdError::ParseError(_) => ErrorCode::ParseError,
            ThresholdError::SecretNotFound { .. } => ErrorCode::SecretNotFound,
            ThresholdError::SecretDecodeFailed { .. } => ErrorCode::SecretDecodeFailed,
            ThresholdError::SecretStoreUnavailable { .. } => ErrorCode::SecretStoreUnavailable,
            ThresholdError::SecretDecryptFailed { .. } => ErrorCode::SecretDecryptFailed,
            ThresholdError::UnsupportedSecretFileFormat { .. } => ErrorCode::UnsupportedSecretFileFormat,
            ThresholdError::UnsupportedSignatureScheme { .. } => ErrorCode::UnsupportedSignatureScheme,
            ThresholdError::KeyOperationFailed { .. } => ErrorCode::KeyOperationFailed,
            ThresholdError::InsecureFilePermissions { .. } => ErrorCode::InsecureFilePermissions,
            ThresholdError::AuditLogError { .. } => ErrorCode::AuditLogError,
            ThresholdError::RocksDBOpenError { .. } => ErrorCode::RocksDBOpenError,
            ThresholdError::StorageLockTimeout { .. } => ErrorCode::StorageLockTimeout,
            ThresholdError::MissingSigningPayload { .. } => ErrorCode::MissingSigningPayload,
            ThresholdError::HyperlaneBodyTooLarge { .. } => ErrorCode::HyperlaneBodyTooLarge,
            ThresholdError::HyperlaneInvalidUtf8 { .. } => ErrorCode::HyperlaneInvalidUtf8,
            ThresholdError::HyperlaneMetadataParseError { .. } => ErrorCode::HyperlaneMetadataParseError,
            ThresholdError::NoValidatorsConfigured { .. } => ErrorCode::NoValidatorsConfigured,
            ThresholdError::PsktInputMismatch { .. } => ErrorCode::PsktInputMismatch,
            ThresholdError::Message(_) => ErrorCode::Message,
        }
    }

    pub fn context(&self) -> ErrorContext {
        ErrorContext { code: self.code(), message: self.to_string() }
    }

    pub fn secret_not_found(name: impl Into<String>, backend: impl Into<String>) -> Self {
        ThresholdError::SecretNotFound { name: name.into(), backend: backend.into(), source: None }
    }

    pub fn secret_decode_failed(name: impl Into<String>, encoding: impl Into<String>, details: impl Into<String>) -> Self {
        ThresholdError::SecretDecodeFailed { name: name.into(), encoding: encoding.into(), details: details.into(), source: None }
    }

    pub fn secret_store_unavailable(backend: impl Into<String>, details: impl Into<String>) -> Self {
        ThresholdError::SecretStoreUnavailable { backend: backend.into(), details: details.into(), source: None }
    }

    pub fn secret_decrypt_failed(backend: impl Into<String>, details: impl Into<String>) -> Self {
        ThresholdError::SecretDecryptFailed { backend: backend.into(), details: details.into(), source: None }
    }

    pub fn unsupported_secret_file_format(details: impl Into<String>) -> Self {
        ThresholdError::UnsupportedSecretFileFormat { details: details.into() }
    }

    pub fn unsupported_signature_scheme(scheme: impl Into<String>, backend: impl Into<String>) -> Self {
        ThresholdError::UnsupportedSignatureScheme { scheme: scheme.into(), backend: backend.into() }
    }

    pub fn key_not_found(key_ref: impl Into<String>) -> Self {
        ThresholdError::KeyNotFound(key_ref.into())
    }

    pub fn key_operation_failed(operation: impl Into<String>, key_ref: impl Into<String>, details: impl Into<String>) -> Self {
        ThresholdError::KeyOperationFailed {
            operation: operation.into(),
            key_ref: key_ref.into(),
            details: details.into(),
            source: None,
        }
    }
}

impl From<hex::FromHexError> for ThresholdError {
    fn from(err: hex::FromHexError) -> Self {
        ThresholdError::EncodingError(format!("hex decode error: {}", err))
    }
}

impl From<toml::de::Error> for ThresholdError {
    fn from(err: toml::de::Error) -> Self {
        ThresholdError::ConfigError(format!("TOML parsing error: {}", err))
    }
}

impl From<rocksdb::Error> for ThresholdError {
    fn from(err: rocksdb::Error) -> Self {
        ThresholdError::StorageError { operation: "rocksdb".to_string(), details: err.to_string() }
    }
}

impl From<bincode::Error> for ThresholdError {
    fn from(err: bincode::Error) -> Self {
        ThresholdError::SerializationError { format: "bincode".to_string(), details: err.to_string() }
    }
}

#[macro_export]
macro_rules! storage_err {
    ($op:expr, $err:expr) => {
        $crate::foundation::ThresholdError::StorageError { operation: $op.into(), details: $err.to_string() }
    };
}

#[macro_export]
macro_rules! serde_err {
    ($fmt:expr, $err:expr) => {
        $crate::foundation::ThresholdError::SerializationError { format: $fmt.into(), details: $err.to_string() }
    };
}

impl From<io::Error> for ThresholdError {
    fn from(err: io::Error) -> Self {
        ThresholdError::StorageError { operation: "io".to_string(), details: err.to_string() }
    }
}

impl From<serde_json::Error> for ThresholdError {
    fn from(err: serde_json::Error) -> Self {
        ThresholdError::SerializationError { format: "json".to_string(), details: err.to_string() }
    }
}

impl From<kaspa_addresses::AddressError> for ThresholdError {
    fn from(err: kaspa_addresses::AddressError) -> Self {
        ThresholdError::InvalidDestination(err.to_string())
    }
}

impl From<SecpError> for ThresholdError {
    fn from(err: SecpError) -> Self {
        ThresholdError::CryptoError { operation: "secp256k1".to_string(), details: err.to_string() }
    }
}

// NOTE: Avoid adding generic "stringly" error conversions here.
// Use structured `ThresholdError` variants at the call site to preserve context.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_error_variants_render() {
        let err = ThresholdError::RocksDBOpenError { details: "test".to_string(), source: None };
        assert!(err.to_string().contains("RocksDB"));

        let err = ThresholdError::StorageLockTimeout { operation: "test".to_string(), timeout_secs: 1 };
        assert!(err.to_string().contains("timeout"));

        let err = ThresholdError::MissingSigningPayload { message_id: "0xabc".to_string() };
        assert!(err.to_string().contains("message_id"));

        let err = ThresholdError::HyperlaneBodyTooLarge { size: 2, max: 1 };
        assert!(err.to_string().contains("too large"));

        let err = ThresholdError::NoValidatorsConfigured { validator_type: "hyperlane".to_string() };
        assert!(err.to_string().contains("validators"));

        let err = ThresholdError::PsktInputMismatch { expected: 1, actual: 2, details: "mismatch".to_string() };
        assert!(err.to_string().contains("mismatch"));
    }
}
