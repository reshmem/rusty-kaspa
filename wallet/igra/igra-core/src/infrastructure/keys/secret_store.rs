//! SecretStore trait and secret byte wrappers.

use crate::foundation::ThresholdError;
use secrecy::{ExposeSecret, SecretVec};
use std::future::Future;
use std::pin::Pin;

use super::types::SecretName;

/// Wrapper around secret bytes that prevents accidental logging.
pub struct SecretBytes {
    inner: SecretVec<u8>,
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_vec())
    }
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: SecretVec::new(bytes) }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self::new(slice.to_vec())
    }

    /// Expose secret bytes for use (explicit, auditable in code review).
    pub fn expose_secret(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Convert to owned Vec (caller responsible for zeroizing).
    pub fn expose_owned(&self) -> Vec<u8> {
        self.inner.expose_secret().to_vec()
    }

    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED {} bytes])", self.len())
    }
}

/// Trait for retrieving secrets from various backends.
pub trait SecretStore: Send + Sync {
    /// A short backend name (e.g. `"env"`, `"file"`).
    fn backend(&self) -> &'static str {
        "unknown"
    }

    /// Retrieve a secret by name.
    fn get<'a>(&'a self, name: &'a SecretName) -> Pin<Box<dyn Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>>;

    /// Check if a secret exists (without retrieving it).
    fn exists<'a>(&'a self, name: &'a SecretName) -> Pin<Box<dyn Future<Output = Result<bool, ThresholdError>> + Send + 'a>> {
        Box::pin(async move {
            match self.get(name).await {
                Ok(_) => Ok(true),
                Err(ThresholdError::SecretNotFound { .. }) => Ok(false),
                Err(e) => Err(e),
            }
        })
    }

    /// List all available secret names (for management tools).
    fn list_secrets<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes_no_leak() {
        let secret = SecretBytes::new(b"password123".to_vec());
        let debug_str = format!("{:?}", secret);
        assert!(!debug_str.contains("password"));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_secret_bytes_expose() {
        let secret = SecretBytes::new(b"test_secret".to_vec());
        assert_eq!(secret.expose_secret(), b"test_secret");
    }
}
