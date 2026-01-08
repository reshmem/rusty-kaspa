use crate::error::ThresholdError;
use crate::model::{GroupPolicy, SigningEvent};
use crate::storage::Storage;
use crate::util::time::day_start_nanos;
use std::sync::Arc;

pub trait PolicyEnforcer: Send + Sync {
    fn enforce_policy(&self, signing_event: &SigningEvent, policy: &GroupPolicy) -> Result<(), ThresholdError>;
}

pub struct DefaultPolicyEnforcer {
    storage: Arc<dyn Storage>,
}

impl DefaultPolicyEnforcer {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

impl PolicyEnforcer for DefaultPolicyEnforcer {
    fn enforce_policy(&self, signing_event: &SigningEvent, policy: &GroupPolicy) -> Result<(), ThresholdError> {
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
            let day_start = day_start_nanos(signing_event.timestamp_nanos);
            let total = self.storage.get_volume_since(day_start)?;
            if total.saturating_add(signing_event.amount_sompi) > limit {
                return Err(ThresholdError::VelocityLimitExceeded { current: total, limit });
            }
        }

        Ok(())
    }
}
