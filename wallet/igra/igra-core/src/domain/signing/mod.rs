use crate::foundation::ThresholdError;
use crate::foundation::RequestId;

pub mod mpc;
pub mod musig2;
pub mod threshold;
pub mod aggregation;
pub mod types;

pub use types::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningBackendKind {
    Threshold,
    MuSig2,
    Mpc,
}

impl SigningBackendKind {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "threshold" | "multisig" => Some(Self::Threshold),
            "musig2" => Some(Self::MuSig2),
            "mpc" | "frost" => Some(Self::Mpc),
            _ => None,
        }
    }
}

pub trait SignerBackend: Send + Sync {
    fn kind(&self) -> SigningBackendKind;
    fn sign(&self, kpsbt_blob: &[u8], request_id: &RequestId) -> Result<Vec<PartialSigSubmit>, ThresholdError>;
}
