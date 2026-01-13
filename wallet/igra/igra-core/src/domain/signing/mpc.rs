use crate::domain::signing::results::SigningResult;
use crate::domain::signing::{SignerBackend, SigningBackendKind};
use crate::foundation::Hash32;
use crate::foundation::ThresholdError;

pub struct MpcSigner;

impl MpcSigner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MpcSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl SignerBackend for MpcSigner {
    fn kind(&self) -> SigningBackendKind {
        SigningBackendKind::Mpc
    }

    fn sign(&self, _kpsbt_blob: &[u8], _event_id: &Hash32) -> Result<SigningResult, ThresholdError> {
        Err(ThresholdError::Unimplemented("MPC signing backend not yet implemented. Use signing_backend='threshold'.".to_string()))
    }
}
