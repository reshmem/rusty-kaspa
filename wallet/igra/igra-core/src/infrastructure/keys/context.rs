//! KeyManagerContext - KeyManager with audit logging integration.

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::audit::{
    now_nanos, OperationResult, PublicKeyEvent, SecretAccessEvent, SecretOperation, SigningEvent,
};
use crate::infrastructure::keys::key_manager::KeyManager;
use crate::infrastructure::keys::types::{KeyRef, RequestId, SecretName, SignatureScheme, SigningPayload};
use std::sync::Arc;
use std::time::Instant;

use super::audit::KeyAuditLogger;

pub struct KeyManagerContext {
    key_manager: Arc<dyn KeyManager>,
    audit_log: Arc<dyn KeyAuditLogger>,
    request_id: RequestId,
}

impl KeyManagerContext {
    pub fn new(key_manager: Arc<dyn KeyManager>, audit_log: Arc<dyn KeyAuditLogger>, request_id: RequestId) -> Self {
        Self { key_manager, audit_log, request_id }
    }

    pub fn with_new_request_id(key_manager: Arc<dyn KeyManager>, audit_log: Arc<dyn KeyAuditLogger>) -> Self {
        Self::new(key_manager, audit_log, RequestId::new())
    }

    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    pub fn key_manager(&self) -> &Arc<dyn KeyManager> {
        &self.key_manager
    }

    pub fn audit_log(&self) -> &Arc<dyn KeyAuditLogger> {
        &self.audit_log
    }

    pub async fn sign_with_audit(
        &self,
        key: &KeyRef,
        scheme: SignatureScheme,
        payload: SigningPayload<'_>,
    ) -> Result<Vec<u8>, ThresholdError> {
        let start = Instant::now();

        let payload_hash = blake3::hash(payload.as_bytes()).to_hex().to_string();
        let result = self.key_manager.sign(key, scheme, payload).await;
        let duration_micros = start.elapsed().as_micros() as u64;

        let event = SigningEvent {
            timestamp: now_nanos(),
            request_id: self.request_id,
            key_ref: key.to_string(),
            scheme,
            payload_hash,
            result: OperationResult::from_result(&result),
            duration_micros,
        };
        self.audit_log.log_signing_operation(event).await?;

        result
    }

    pub async fn public_key_with_audit(&self, key: &KeyRef, scheme: SignatureScheme) -> Result<Vec<u8>, ThresholdError> {
        let result = self.key_manager.public_key(key, scheme).await;
        let event = PublicKeyEvent {
            timestamp: now_nanos(),
            request_id: self.request_id,
            key_ref: key.to_string(),
            scheme,
            result: OperationResult::from_result(&result),
        };
        self.audit_log.log_public_key_retrieval(event).await?;
        result
    }

    pub async fn get_secret_with_audit(&self, name: &SecretName) -> Result<super::secret_store::SecretBytes, ThresholdError> {
        let Some(store) = self.key_manager.secret_store() else {
            return Err(ThresholdError::secret_store_unavailable("none", "KeyManager has no SecretStore"));
        };
        let result = store.get(name).await;
        let event = SecretAccessEvent {
            timestamp: now_nanos(),
            request_id: self.request_id,
            secret_name: name.to_string(),
            backend: store.backend().to_string(),
            operation: SecretOperation::Get,
            result: OperationResult::from_result(&result),
            caller_module: None,
        };
        self.audit_log.log_secret_access(event).await?;
        result
    }

    pub async fn exists_secret_with_audit(&self, name: &SecretName) -> Result<bool, ThresholdError> {
        let Some(store) = self.key_manager.secret_store() else {
            return Err(ThresholdError::secret_store_unavailable("none", "KeyManager has no SecretStore"));
        };
        let result = store.exists(name).await;
        let event = SecretAccessEvent {
            timestamp: now_nanos(),
            request_id: self.request_id,
            secret_name: name.to_string(),
            backend: store.backend().to_string(),
            operation: SecretOperation::Exists,
            result: OperationResult::from_result(&result),
            caller_module: None,
        };
        self.audit_log.log_secret_access(event).await?;
        result
    }

    pub async fn list_secrets_with_audit(&self) -> Result<Vec<SecretName>, ThresholdError> {
        let Some(store) = self.key_manager.secret_store() else {
            return Err(ThresholdError::secret_store_unavailable("none", "KeyManager has no SecretStore"));
        };
        let result = store.list_secrets().await;
        let event = SecretAccessEvent {
            timestamp: now_nanos(),
            request_id: self.request_id,
            secret_name: "*".to_string(),
            backend: store.backend().to_string(),
            operation: SecretOperation::List,
            result: OperationResult::from_result(&result),
            caller_module: None,
        };
        self.audit_log.log_secret_access(event).await?;
        result
    }
}
