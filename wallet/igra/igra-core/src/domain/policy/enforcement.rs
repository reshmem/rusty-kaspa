use crate::foundation::error::ThresholdError;
use crate::domain::{GroupPolicy, SigningEvent};
use kaspa_addresses::Address;

pub trait PolicyEnforcer: Send + Sync {
    /// Enforce policy rules using the caller-provided current daily volume (sompi) since day start.
    fn enforce_policy(&self, signing_event: &SigningEvent, policy: &GroupPolicy, current_daily_volume_sompi: u64) -> Result<(), ThresholdError>;
}

pub struct DefaultPolicyEnforcer;

impl DefaultPolicyEnforcer {
    pub fn new() -> Self { Self }
}

impl PolicyEnforcer for DefaultPolicyEnforcer {
    fn enforce_policy(&self, signing_event: &SigningEvent, policy: &GroupPolicy, current_daily_volume_sompi: u64) -> Result<(), ThresholdError> {
        if signing_event.amount_sompi == 0 {
            return Err(ThresholdError::AmountTooLow { amount: 0, min: 1 });
        }

        if Address::try_from(signing_event.destination_address.as_str()).is_err() {
            return Err(ThresholdError::DestinationNotAllowed(signing_event.destination_address.clone()));
        }

        if !policy.allowed_destinations.is_empty() && !policy.allowed_destinations.contains(&signing_event.destination_address) {
            return Err(ThresholdError::DestinationNotAllowed(signing_event.destination_address.clone()));
        }

        if let Some(min_amount) = policy.min_amount_sompi {
            if signing_event.amount_sompi < min_amount {
                return Err(ThresholdError::AmountTooLow { amount: signing_event.amount_sompi, min: min_amount });
            }
        }

        if let Some(max_amount) = policy.max_amount_sompi {
            if signing_event.amount_sompi > max_amount {
                return Err(ThresholdError::AmountTooHigh { amount: signing_event.amount_sompi, max: max_amount });
            }
        }

        if policy.require_reason && !signing_event.metadata.contains_key("reason") {
            return Err(ThresholdError::MemoRequired);
        }

        if let Some(limit) = policy.max_daily_volume_sompi {
            let total = current_daily_volume_sompi;
            if total.saturating_add(signing_event.amount_sompi) > limit {
                return Err(ThresholdError::VelocityLimitExceeded { current: total, limit });
            }
        }

        Ok(())
    }
}
