use crate::domain::policy::enforcement::{DefaultPolicyEnforcer, PolicyEnforcer};
use crate::domain::validation::{MessageVerifier, VerificationReport};
use crate::domain::{GroupPolicy, StoredEvent};
use crate::foundation::ThresholdError;
use crate::infrastructure::storage::Storage;

pub struct SigningPipeline<'a> {
    verifier: &'a dyn MessageVerifier,
    policy: &'a GroupPolicy,
    storage: &'a dyn Storage,
    now_nanos: u64,
}

impl<'a> SigningPipeline<'a> {
    pub fn new(verifier: &'a dyn MessageVerifier, policy: &'a GroupPolicy, storage: &'a dyn Storage, now_nanos: u64) -> Self {
        Self { verifier, policy, storage, now_nanos }
    }

    pub fn verify_source(&self, event: &StoredEvent) -> Result<VerificationReport, ThresholdError> {
        self.verifier.verify(event)
    }

    pub fn enforce_policy(&self, event: &StoredEvent) -> Result<(), ThresholdError> {
        let current_daily_volume = self.storage.get_volume_since(self.now_nanos)?;
        DefaultPolicyEnforcer::new().enforce_policy(event, self.policy, current_daily_volume)
    }

    pub fn verify_and_enforce(&self, event: &StoredEvent) -> Result<VerificationReport, ThresholdError> {
        let report = self.verify_source(event)?;
        if !report.valid {
            return Err(ThresholdError::EventSignatureInvalid);
        }
        self.enforce_policy(event)?;
        Ok(report)
    }
}
