//! Audit logging for key management operations.

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::types::{RequestId, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type Timestamp = u64;

pub fn now_nanos() -> Timestamp {
    crate::foundation::now_nanos()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result")]
pub enum OperationResult {
    Success,
    Failure { error: String },
}

impl OperationResult {
    pub fn from_result<T, E: std::fmt::Display>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Success,
            Err(e) => Self::Failure { error: e.to_string() },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecretOperation {
    Get,
    List,
    Exists,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccessEvent {
    pub timestamp: Timestamp,
    pub request_id: RequestId,
    pub secret_name: String,
    pub backend: String,
    pub operation: SecretOperation,
    pub result: OperationResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningEvent {
    pub timestamp: Timestamp,
    pub request_id: RequestId,
    pub key_ref: String,
    pub scheme: SignatureScheme,
    pub payload_hash: String,
    pub result: OperationResult,
    pub duration_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyEvent {
    pub timestamp: Timestamp,
    pub request_id: RequestId,
    pub key_ref: String,
    pub scheme: SignatureScheme,
    pub result: OperationResult,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KeyLifecycleOperation {
    Created,
    Rotated,
    Revoked,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLifecycleEvent {
    pub timestamp: Timestamp,
    pub key_ref: String,
    pub operation: KeyLifecycleOperation,
    pub operator: String,
}

pub trait KeyAuditLogger: Send + Sync {
    fn log_secret_access<'a>(
        &'a self,
        event: SecretAccessEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;

    fn log_signing_operation<'a>(
        &'a self,
        event: SigningEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;

    fn log_public_key_retrieval<'a>(
        &'a self,
        event: PublicKeyEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;

    fn log_key_lifecycle<'a>(
        &'a self,
        event: KeyLifecycleEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>>;
}

pub struct NoopAuditLogger;

impl KeyAuditLogger for NoopAuditLogger {
    fn log_secret_access<'a>(
        &'a self,
        _event: SecretAccessEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn log_signing_operation<'a>(
        &'a self,
        _event: SigningEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn log_public_key_retrieval<'a>(
        &'a self,
        _event: PublicKeyEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn log_key_lifecycle<'a>(
        &'a self,
        _event: KeyLifecycleEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

pub struct FileAuditLogger {
    file: Arc<tokio::sync::Mutex<std::fs::File>>,
}

impl FileAuditLogger {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self, ThresholdError> {
        use std::fs::OpenOptions;

        let file = OpenOptions::new().create(true).append(true).open(path.as_ref()).map_err(|e| ThresholdError::AuditLogError {
            details: format!("Failed to open audit log: {}", e),
            source: Some(Box::new(e)),
        })?;

        Ok(Self { file: Arc::new(tokio::sync::Mutex::new(file)) })
    }

    async fn write_event(&self, event: impl Serialize) -> Result<(), ThresholdError> {
        use std::io::Write;

        let json = serde_json::to_string(&event).map_err(|e| ThresholdError::AuditLogError {
            details: format!("Failed to serialize audit event: {}", e),
            source: Some(Box::new(e)),
        })?;

        let mut file = self.file.lock().await;
        writeln!(file, "{}", json).map_err(|e| ThresholdError::AuditLogError {
            details: format!("Failed to write audit event: {}", e),
            source: Some(Box::new(e)),
        })?;
        file.flush().map_err(|e| ThresholdError::AuditLogError {
            details: format!("Failed to flush audit log: {}", e),
            source: Some(Box::new(e)),
        })?;
        Ok(())
    }
}

impl KeyAuditLogger for FileAuditLogger {
    fn log_secret_access<'a>(
        &'a self,
        event: SecretAccessEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({ "event_type": "secret_access", "event": event })))
    }

    fn log_signing_operation<'a>(
        &'a self,
        event: SigningEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({ "event_type": "signing", "event": event })))
    }

    fn log_public_key_retrieval<'a>(
        &'a self,
        event: PublicKeyEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({ "event_type": "public_key", "event": event })))
    }

    fn log_key_lifecycle<'a>(
        &'a self,
        event: KeyLifecycleEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(self.write_event(serde_json::json!({ "event_type": "lifecycle", "event": event })))
    }
}
