//! Local in-process KeyManager implementation.

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::audit::{now_nanos, OperationResult, SecretAccessEvent, SecretOperation};
use crate::infrastructure::keys::key_manager::KeyManager;
use crate::infrastructure::keys::panic_guard::SecretPanicGuard;
use crate::infrastructure::keys::secret_store::{SecretBytes, SecretStore};
use crate::infrastructure::keys::types::{KeyManagerCapabilities, KeyRef, SecretName, SignatureScheme, SigningPayload};
use ed25519_dalek::Signer;
use secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use zeroize::Zeroize;

use super::super::audit::KeyAuditLogger;

pub struct LocalKeyManager {
    secret_store: Arc<dyn SecretStore>,
    audit_log: Arc<dyn KeyAuditLogger>,
}

impl LocalKeyManager {
    pub fn new(secret_store: Arc<dyn SecretStore>, audit_log: Arc<dyn KeyAuditLogger>) -> Self {
        Self { secret_store, audit_log }
    }

    async fn get_secret_with_audit(&self, key_ref: &KeyRef) -> Result<SecretBytes, ThresholdError> {
        let name: SecretName = key_ref.into();
        let result = self.secret_store.get(&name).await;
        let event = SecretAccessEvent {
            timestamp: now_nanos(),
            request_id: crate::infrastructure::keys::types::RequestId::new(),
            secret_name: name.to_string(),
            backend: self.secret_store.backend().to_string(),
            operation: SecretOperation::Get,
            result: OperationResult::from_result(&result),
            caller_module: Some("LocalKeyManager".to_string()),
        };
        self.audit_log.log_secret_access(event).await?;
        result
    }

    async fn sign_schnorr(&self, key_ref: &KeyRef, payload: SigningPayload<'_>) -> Result<Vec<u8>, ThresholdError> {
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;
        let mut guard = SecretPanicGuard::new(secret_bytes.expose_owned());

        let secret = SecretKey::from_slice(guard.get())
            .map_err(|err| ThresholdError::key_operation_failed("parse_secp256k1_secret", key_ref.to_string(), err.to_string()))?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);

        let digest: [u8; 32] = match payload {
            SigningPayload::Message(msg) => *blake3::hash(msg).as_bytes(),
            SigningPayload::Digest(digest) => digest.try_into().map_err(|_| {
                ThresholdError::key_operation_failed("message_from_digest", key_ref.to_string(), "digest must be 32 bytes")
            })?,
        };
        let msg = Message::from_digest_slice(&digest)
            .map_err(|err| ThresholdError::key_operation_failed("message_from_digest", key_ref.to_string(), err.to_string()))?;
        let sig = secp.sign_schnorr(&msg, &keypair);

        let mut owned = guard.take();
        owned.zeroize();
        Ok(sig.as_ref().to_vec())
    }

    async fn sign_ecdsa(&self, key_ref: &KeyRef, payload: SigningPayload<'_>) -> Result<Vec<u8>, ThresholdError> {
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;
        let mut guard = SecretPanicGuard::new(secret_bytes.expose_owned());
        let secret = SecretKey::from_slice(guard.get())
            .map_err(|err| ThresholdError::key_operation_failed("parse_secp256k1_secret", key_ref.to_string(), err.to_string()))?;
        let secp = Secp256k1::new();
        let digest: [u8; 32] = match payload {
            SigningPayload::Message(msg) => *blake3::hash(msg).as_bytes(),
            SigningPayload::Digest(digest) => digest.try_into().map_err(|_| {
                ThresholdError::key_operation_failed("message_from_digest", key_ref.to_string(), "digest must be 32 bytes")
            })?,
        };
        let msg = Message::from_digest_slice(&digest)
            .map_err(|err| ThresholdError::key_operation_failed("message_from_digest", key_ref.to_string(), err.to_string()))?;
        let sig = secp.sign_ecdsa(&msg, &secret);
        let sig64 = sig.serialize_compact().to_vec();
        let mut owned = guard.take();
        owned.zeroize();
        Ok(sig64)
    }

    async fn sign_ed25519(&self, key_ref: &KeyRef, payload: SigningPayload<'_>) -> Result<Vec<u8>, ThresholdError> {
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;
        let mut guard = SecretPanicGuard::new(secret_bytes.expose_owned());
        let seed: [u8; 32] = guard.get().as_slice().try_into().map_err(|_| {
            ThresholdError::key_operation_failed("parse_ed25519_seed", key_ref.to_string(), "Ed25519 seed must be exactly 32 bytes")
        })?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(payload.as_bytes());
        let mut owned = guard.take();
        owned.zeroize();
        Ok(sig.to_bytes().to_vec())
    }

    async fn get_public_key_secp256k1(&self, key_ref: &KeyRef, scheme: SignatureScheme) -> Result<Vec<u8>, ThresholdError> {
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;
        let mut guard = SecretPanicGuard::new(secret_bytes.expose_owned());
        let secret = SecretKey::from_slice(guard.get())
            .map_err(|err| ThresholdError::key_operation_failed("parse_secp256k1_secret", key_ref.to_string(), err.to_string()))?;
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret);
        let mut owned = guard.take();
        owned.zeroize();
        match scheme {
            SignatureScheme::Secp256k1Schnorr => {
                let (xonly, _) = public_key.x_only_public_key();
                Ok(xonly.serialize().to_vec())
            }
            SignatureScheme::Secp256k1Ecdsa => Ok(public_key.serialize().to_vec()),
            SignatureScheme::Ed25519 => Err(ThresholdError::unsupported_signature_scheme(scheme.to_string(), "local")),
        }
    }

    async fn get_public_key_ed25519(&self, key_ref: &KeyRef) -> Result<Vec<u8>, ThresholdError> {
        let secret_bytes = self.get_secret_with_audit(key_ref).await?;
        let mut guard = SecretPanicGuard::new(secret_bytes.expose_owned());
        let seed: [u8; 32] = guard.get().as_slice().try_into().map_err(|_| {
            ThresholdError::key_operation_failed("parse_ed25519_seed", key_ref.to_string(), "Ed25519 seed must be exactly 32 bytes")
        })?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let mut owned = guard.take();
        owned.zeroize();
        Ok(verifying_key.to_bytes().to_vec())
    }
}

impl KeyManager for LocalKeyManager {
    fn capabilities(&self) -> KeyManagerCapabilities {
        KeyManagerCapabilities {
            supports_secp256k1_schnorr: true,
            supports_secp256k1_ecdsa: true,
            supports_ed25519: true,
            supports_secret_export: true,
            supports_key_rotation: false,
        }
    }

    fn secret_store(&self) -> Option<&dyn SecretStore> {
        Some(self.secret_store.as_ref())
    }

    fn public_key<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            match scheme {
                SignatureScheme::Secp256k1Schnorr | SignatureScheme::Secp256k1Ecdsa => {
                    self.get_public_key_secp256k1(key, scheme).await
                }
                SignatureScheme::Ed25519 => self.get_public_key_ed25519(key).await,
            }
        })
    }

    fn sign<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
        payload: SigningPayload<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            match scheme {
                SignatureScheme::Secp256k1Schnorr => self.sign_schnorr(key, payload).await,
                SignatureScheme::Secp256k1Ecdsa => self.sign_ecdsa(key, payload).await,
                SignatureScheme::Ed25519 => self.sign_ed25519(key, payload).await,
            }
        })
    }
}
