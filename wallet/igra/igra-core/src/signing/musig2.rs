use crate::error::ThresholdError;
use crate::signing::{SignerBackend, SigningBackendKind};
use crate::transport::PartialSigSubmit;

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

    fn sign(&self, _kpsbt_blob: &[u8]) -> Result<Vec<PartialSigSubmit>, ThresholdError> {
        Err(ThresholdError::Message("MuSig2 backend not implemented".to_string()))
    }
}
