use crate::error::ThresholdError;
use crate::transport::PartialSigSubmit;

pub mod mpc;
pub mod musig2;
pub mod threshold;

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

pub fn backend_kind_from_config(config: &crate::config::SigningConfig) -> Result<SigningBackendKind, ThresholdError> {
    SigningBackendKind::from_str(&config.backend)
        .ok_or_else(|| ThresholdError::Message(format!("unknown signing.backend: {}", config.backend)))
}

pub trait SignerBackend: Send + Sync {
    fn kind(&self) -> SigningBackendKind;
    fn sign(&self, kpsbt_blob: &[u8]) -> Result<Vec<PartialSigSubmit>, ThresholdError>;
}
