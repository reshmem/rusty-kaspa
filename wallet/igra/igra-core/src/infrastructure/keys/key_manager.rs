//! KeyManager trait - high-level key operations.

use crate::foundation::ThresholdError;
use crate::infrastructure::keys::secret_store::SecretStore;
use crate::infrastructure::keys::types::{KeyManagerCapabilities, KeyRef, SignatureScheme, SigningPayload};
use std::future::Future;
use std::pin::Pin;

pub trait KeyManager: Send + Sync {
    fn capabilities(&self) -> KeyManagerCapabilities;

    fn secret_store(&self) -> Option<&dyn SecretStore>;

    fn public_key<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>>;

    fn sign<'a>(
        &'a self,
        key: &'a KeyRef,
        scheme: SignatureScheme,
        payload: SigningPayload<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, ThresholdError>> + Send + 'a>>;

    fn validate_required_keys<'a>(
        &'a self,
        keys: &'a [&'a KeyRef],
        scheme: SignatureScheme,
    ) -> Pin<Box<dyn Future<Output = Result<(), ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            for key in keys {
                self.public_key(key, scheme).await.map_err(|_| ThresholdError::key_not_found(key.to_string()))?;
            }
            Ok(())
        })
    }
}
