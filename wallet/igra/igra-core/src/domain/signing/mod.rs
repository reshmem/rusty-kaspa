use crate::foundation::Hash32;
use crate::foundation::ThresholdError;
use std::str::FromStr;

pub mod aggregation;
pub mod results;
pub mod threshold;

#[cfg(feature = "mpc")]
pub mod mpc;

#[cfg(feature = "musig2")]
pub mod musig2;

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
            "musig2" => {
                #[cfg(feature = "musig2")]
                {
                    Ok(Self::MuSig2)
                }
                #[cfg(not(feature = "musig2"))]
                {
                    Err(ThresholdError::ConfigError("signing.backend='musig2' requires the 'musig2' feature".to_string()))
                }
            }
            "mpc" | "frost" => {
                #[cfg(feature = "mpc")]
                {
                    Ok(Self::Mpc)
                }
                #[cfg(not(feature = "mpc"))]
                {
                    Err(ThresholdError::ConfigError("signing.backend='mpc' requires the 'mpc' feature".to_string()))
                }
            }
            _ => Err(ThresholdError::ConfigError(format!("unknown signing backend: {value}"))),
        }
    }
}

pub trait SignerBackend: Send + Sync {
    fn kind(&self) -> SigningBackendKind;
    fn sign(&self, kpsbt_blob: &[u8], event_id: &Hash32) -> Result<SigningResult, ThresholdError>;
}
