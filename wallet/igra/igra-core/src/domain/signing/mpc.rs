use crate::domain::signing::results::SigningResult;
use crate::domain::signing::{SignerBackend, SigningBackendKind};
use crate::foundation::RequestId;
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

    fn sign(&self, _kpsbt_blob: &[u8], _request_id: &RequestId) -> Result<SigningResult, ThresholdError> {
        Err(ThresholdError::Message("MPC backend not implemented".to_string()))
    }
}
