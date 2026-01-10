use crate::domain::SigningEvent;
use crate::foundation::ThresholdError;
use secp256k1::PublicKey;

use super::{hyperlane, layerzero};

#[derive(Clone, Copy, Debug)]
pub enum ValidationSource {
    Hyperlane,
    LayerZero,
    None,
}

#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub source: ValidationSource,
    pub validator_count: usize,
    pub valid: bool,
    pub valid_signatures: usize,
    pub threshold_required: usize,
    pub failure_reason: Option<String>,
    pub event_hash: Option<[u8; 32]>,
}

pub trait MessageVerifier: Send + Sync {
    fn verify(&self, event: &SigningEvent) -> Result<VerificationReport, ThresholdError>;
    fn report_for(&self, event: &SigningEvent) -> VerificationReport;
}

pub struct CompositeVerifier {
    hyperlane_validators: Vec<PublicKey>,
    hyperlane_threshold: usize,
    layerzero_validators: Vec<PublicKey>,
}

impl CompositeVerifier {
    pub fn new(hyperlane_validators: Vec<PublicKey>, hyperlane_threshold: usize, layerzero_validators: Vec<PublicKey>) -> Self {
        Self { hyperlane_validators, hyperlane_threshold, layerzero_validators }
    }
}

impl MessageVerifier for CompositeVerifier {
    fn verify(&self, event: &SigningEvent) -> Result<VerificationReport, ThresholdError> {
        match event.event_source {
            crate::domain::EventSource::Hyperlane { .. } => {
                let result = hyperlane::verify_event(event, &self.hyperlane_validators, self.hyperlane_threshold)?;
                Ok(VerificationReport {
                    source: ValidationSource::Hyperlane,
                    validator_count: self.hyperlane_validators.len(),
                    valid: result.valid,
                    valid_signatures: result.valid_signatures,
                    threshold_required: result.threshold_required,
                    failure_reason: result.failure_reason.map(|f| format!("{:?}", f)),
                    event_hash: Some(result.event_hash),
                })
            }
            crate::domain::EventSource::LayerZero { .. } => {
                let result = layerzero::verify_event(event, &self.layerzero_validators)?;
                Ok(VerificationReport {
                    source: ValidationSource::LayerZero,
                    validator_count: self.layerzero_validators.len(),
                    valid: result.valid,
                    valid_signatures: if result.valid { 1 } else { 0 },
                    threshold_required: 1,
                    failure_reason: result.failure_reason.map(|f| format!("{:?}", f)),
                    event_hash: Some(result.event_hash),
                })
            }
            _ => Ok(VerificationReport {
                source: ValidationSource::None,
                validator_count: 0,
                valid: true,
                valid_signatures: 0,
                threshold_required: 0,
                failure_reason: None,
                event_hash: None,
            }),
        }
    }

    fn report_for(&self, event: &SigningEvent) -> VerificationReport {
        match event.event_source {
            crate::domain::EventSource::Hyperlane { .. } => VerificationReport {
                source: ValidationSource::Hyperlane,
                validator_count: self.hyperlane_validators.len(),
                valid: false,
                valid_signatures: 0,
                threshold_required: self.hyperlane_threshold,
                failure_reason: None,
                event_hash: None,
            },
            crate::domain::EventSource::LayerZero { .. } => VerificationReport {
                source: ValidationSource::LayerZero,
                validator_count: self.layerzero_validators.len(),
                valid: false,
                valid_signatures: 0,
                threshold_required: 1,
                failure_reason: None,
                event_hash: None,
            },
            _ => VerificationReport {
                source: ValidationSource::None,
                validator_count: 0,
                valid: true,
                valid_signatures: 0,
                threshold_required: 0,
                failure_reason: None,
                event_hash: None,
            },
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
        Ok(VerificationReport {
            source: ValidationSource::None,
            validator_count: 0,
            valid: true,
            valid_signatures: 0,
            threshold_required: 0,
            failure_reason: None,
            event_hash: None,
        })
    }

    fn report_for(&self, _event: &SigningEvent) -> VerificationReport {
        VerificationReport {
            source: ValidationSource::None,
            validator_count: 0,
            valid: true,
            valid_signatures: 0,
            threshold_required: 0,
            failure_reason: None,
            event_hash: None,
        }
    }
}
