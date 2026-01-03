use crate::error::ThresholdError;
use crate::signing::{SignerBackend, SigningBackendKind};
use crate::transport::PartialSigSubmit;

pub struct MpcSigner;

impl MpcSigner {
    pub fn new() -> Self {
        Self
    }
}

impl SignerBackend for MpcSigner {
    fn kind(&self) -> SigningBackendKind {
        SigningBackendKind::Mpc
    }

    fn sign(&self, _kpsbt_blob: &[u8]) -> Result<Vec<PartialSigSubmit>, ThresholdError> {
        Err(ThresholdError::Message("MPC backend not implemented".to_string()))
    }
}
