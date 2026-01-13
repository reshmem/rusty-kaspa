use crate::foundation::RequestId;
use crate::foundation::ThresholdError;
use std::str::FromStr;

pub mod aggregation;
pub mod mpc;
pub mod musig2;
pub mod results;
pub mod threshold;

pub use results::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningBackendKind {
    Threshold,
    MuSig2,
    Mpc,
}

impl FromStr for SigningBackendKind {
    type Err = ThresholdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().as_str() {
            "threshold" | "multisig" => Ok(Self::Threshold),
            "musig2" => Ok(Self::MuSig2),
            "mpc" | "frost" => Ok(Self::Mpc),
            _ => Err(ThresholdError::ConfigError(format!("unknown signing backend: {value}"))),
        }
    }
}

pub trait SignerBackend: Send + Sync {
    fn kind(&self) -> SigningBackendKind;
    fn sign(&self, kpsbt_blob: &[u8], request_id: &RequestId) -> Result<SigningResult, ThresholdError>;
}
