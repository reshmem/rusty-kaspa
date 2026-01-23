//! Memory-protected secret storage with optional mlock.

use secrecy::{ExposeSecret, SecretVec};
use std::fmt;
use zeroize::Zeroize;

use crate::foundation::ThresholdError;

pub struct ProtectedSecret {
    inner: SecretVec<u8>,
    #[cfg(target_family = "unix")]
    mlocked: bool,
}

impl ProtectedSecret {
    pub fn new(data: Vec<u8>) -> Result<Self, ThresholdError> {
        let inner = SecretVec::new(data);
        #[cfg(target_family = "unix")]
        let mlocked = Self::try_mlock(&inner);
        Ok(Self {
            inner,
            #[cfg(target_family = "unix")]
            mlocked,
        })
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    #[cfg(target_family = "unix")]
    pub fn is_mlocked(&self) -> bool {
        self.mlocked
    }

    #[cfg(not(target_family = "unix"))]
    pub fn is_mlocked(&self) -> bool {
        false
    }

    #[cfg(target_family = "unix")]
    fn try_mlock(secret: &SecretVec<u8>) -> bool {
        let slice = secret.expose_secret();
        let result = unsafe { libc::mlock(slice.as_ptr() as *const libc::c_void, slice.len()) };
        if result != 0 {
            log::warn!("Failed to mlock secret memory (may require elevated privileges)");
            false
        } else {
            log::debug!("Successfully mlocked {} bytes", slice.len());
            true
        }
    }
}

impl Drop for ProtectedSecret {
    fn drop(&mut self) {
        #[cfg(target_family = "unix")]
        if self.mlocked {
            let slice = self.inner.expose_secret();
            unsafe {
                libc::munlock(slice.as_ptr() as *const libc::c_void, slice.len());
            }
        }
        let mut bytes = self.inner.expose_secret().to_vec();
        bytes.zeroize();
    }
}

impl fmt::Debug for ProtectedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedSecret").field("len", &self.len()).field("mlocked", &self.is_mlocked()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_secret_creation() {
        let secret = ProtectedSecret::new(b"test_data".to_vec()).unwrap();
        assert_eq!(secret.expose_secret(), b"test_data");
    }

    #[test]
    fn test_protected_secret_no_leak() {
        let secret = ProtectedSecret::new(b"password123".to_vec()).unwrap();
        let debug_str = format!("{:?}", secret);
        assert!(!debug_str.contains("password"));
    }
}
