use crate::foundation::ThresholdError;
use crate::foundation::RequestId;
use crate::domain::signing::{SignerBackend, SigningBackendKind};
use crate::domain::signing::PartialSigSubmit;

pub struct MuSig2Signer;

impl MuSig2Signer {
    pub fn new() -> Self {
        Self
    }
}

impl SignerBackend for MuSig2Signer {
    fn kind(&self) -> SigningBackendKind {
        SigningBackendKind::MuSig2
    }

    fn sign(&self, _kpsbt_blob: &[u8], _request_id: &RequestId) -> Result<Vec<PartialSigSubmit>, ThresholdError> {
        Err(ThresholdError::Message("MuSig2 backend not implemented".to_string()))
    }
}
