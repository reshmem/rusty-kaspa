use crate::foundation::ThresholdError;
use crate::foundation::RequestId;
use crate::domain::signing::{SignerBackend, SigningBackendKind};
use crate::domain::signing::PartialSigSubmit;

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

    fn sign(&self, _kpsbt_blob: &[u8], _request_id: &RequestId) -> Result<Vec<PartialSigSubmit>, ThresholdError> {
        Err(ThresholdError::Message("MPC backend not implemented".to_string()))
    }
}
