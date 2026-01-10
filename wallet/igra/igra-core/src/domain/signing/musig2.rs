use crate::domain::signing::results::SigningResult;
use crate::domain::signing::{SignerBackend, SigningBackendKind};
use crate::foundation::RequestId;
use crate::foundation::ThresholdError;

pub struct MuSig2Signer;

impl MuSig2Signer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MuSig2Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl SignerBackend for MuSig2Signer {
    fn kind(&self) -> SigningBackendKind {
        SigningBackendKind::MuSig2
    }

    fn sign(&self, _kpsbt_blob: &[u8], _request_id: &RequestId) -> Result<SigningResult, ThresholdError> {
        Err(ThresholdError::Message("MuSig2 backend not implemented".to_string()))
    }
}
