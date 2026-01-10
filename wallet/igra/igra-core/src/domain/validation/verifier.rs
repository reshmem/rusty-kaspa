use crate::foundation::ThresholdError;
use crate::domain::SigningEvent;
use secp256k1::PublicKey;

use super::{hyperlane, layerzero};

#[derive(Clone, Copy, Debug)]
pub enum ValidationSource {
    Hyperlane,
    LayerZero,
    None,
}

#[derive(Clone, Copy, Debug)]
pub struct VerificationReport {
    pub source: ValidationSource,
    pub validator_count: usize,
}

pub trait MessageVerifier: Send + Sync {
    fn verify(&self, event: &SigningEvent) -> Result<VerificationReport, ThresholdError>;
    fn report_for(&self, event: &SigningEvent) -> VerificationReport;
}

pub struct CompositeVerifier {
    hyperlane_validators: Vec<PublicKey>,
    layerzero_validators: Vec<PublicKey>,
}

impl CompositeVerifier {
    pub fn new(hyperlane_validators: Vec<PublicKey>, layerzero_validators: Vec<PublicKey>) -> Self {
        Self { hyperlane_validators, layerzero_validators }
    }
}

impl MessageVerifier for CompositeVerifier {
    fn verify(&self, event: &SigningEvent) -> Result<VerificationReport, ThresholdError> {
        match event.event_source {
            crate::domain::EventSource::Hyperlane { .. } => {
                hyperlane::verify_event(event, &self.hyperlane_validators)?;
                Ok(VerificationReport { source: ValidationSource::Hyperlane, validator_count: self.hyperlane_validators.len() })
            }
            crate::domain::EventSource::LayerZero { .. } => {
                layerzero::verify_event(event, &self.layerzero_validators)?;
                Ok(VerificationReport { source: ValidationSource::LayerZero, validator_count: self.layerzero_validators.len() })
            }
            _ => Ok(VerificationReport { source: ValidationSource::None, validator_count: 0 }),
        }
    }

    fn report_for(&self, event: &SigningEvent) -> VerificationReport {
        match event.event_source {
            crate::domain::EventSource::Hyperlane { .. } => {
                VerificationReport { source: ValidationSource::Hyperlane, validator_count: self.hyperlane_validators.len() }
            }
            crate::domain::EventSource::LayerZero { .. } => {
                VerificationReport { source: ValidationSource::LayerZero, validator_count: self.layerzero_validators.len() }
            }
            _ => VerificationReport { source: ValidationSource::None, validator_count: 0 },
        }
    }
}

pub struct NoopVerifier;

impl Default for NoopVerifier {
    fn default() -> Self {
        Self
    }
}

impl MessageVerifier for NoopVerifier {
    fn verify(&self, _event: &SigningEvent) -> Result<VerificationReport, ThresholdError> {
        Ok(VerificationReport { source: ValidationSource::None, validator_count: 0 })
    }

    fn report_for(&self, _event: &SigningEvent) -> VerificationReport {
        VerificationReport { source: ValidationSource::None, validator_count: 0 }
    }
}
