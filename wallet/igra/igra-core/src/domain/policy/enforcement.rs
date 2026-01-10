use crate::domain::policy::types::{PolicyCheck, PolicyCheckFailure, PolicyCheckType, PolicyEvaluationResult, PolicyFailureContext};
use crate::domain::{GroupPolicy, SigningEvent};
use crate::foundation::error::ThresholdError;
use kaspa_addresses::Address;

pub trait PolicyEnforcer: Send + Sync {
    /// Evaluate policy rules using the caller-provided current daily volume (sompi) since day start.
    fn evaluate_policy(
        &self,
        signing_event: &SigningEvent,
        policy: &GroupPolicy,
        current_daily_volume_sompi: u64,
    ) -> PolicyEvaluationResult;

    /// Convenience wrapper for legacy call sites that still expect `ThresholdError` failures.
    fn enforce_policy(
        &self,
        signing_event: &SigningEvent,
        policy: &GroupPolicy,
        current_daily_volume_sompi: u64,
    ) -> Result<(), ThresholdError> {
        let result = self.evaluate_policy(signing_event, policy, current_daily_volume_sompi);
        if result.allowed {
            return Ok(());
        }
        let Some(failure) = result.failed_check else {
            return Err(ThresholdError::Message("policy evaluation failed without a failed_check".to_string()));
        };
        Err(map_policy_failure_to_error(&failure.context))
    }
}

pub struct DefaultPolicyEnforcer;

impl DefaultPolicyEnforcer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DefaultPolicyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEnforcer for DefaultPolicyEnforcer {
    fn evaluate_policy(
        &self,
        signing_event: &SigningEvent,
        policy: &GroupPolicy,
        current_daily_volume_sompi: u64,
    ) -> PolicyEvaluationResult {
        let mut checks = Vec::new();

        if signing_event.amount_sompi == 0 {
            let check = PolicyCheck { check_type: PolicyCheckType::AmountNonZero, passed: false, details: "amount=0".to_string() };
            checks.push(check);
            return PolicyEvaluationResult {
                allowed: false,
                checks_performed: checks,
                failed_check: Some(PolicyCheckFailure {
                    check_type: PolicyCheckType::AmountNonZero,
                    reason: "amount must be greater than zero".to_string(),
                    context: PolicyFailureContext::AmountTooLow { amount: 0, min: 1 },
                }),
            };
        }
        checks.push(PolicyCheck {
            check_type: PolicyCheckType::AmountNonZero,
            passed: true,
            details: format!("amount={}", signing_event.amount_sompi),
        });

        if Address::try_from(signing_event.destination_address.as_str()).is_err() {
            let destination = signing_event.destination_address.clone();
            let check = PolicyCheck {
                check_type: PolicyCheckType::DestinationValid,
                passed: false,
                details: format!("destination={}", destination),
            };
            checks.push(check);
            return PolicyEvaluationResult {
                allowed: false,
                checks_performed: checks,
                failed_check: Some(PolicyCheckFailure {
                    check_type: PolicyCheckType::DestinationValid,
                    reason: "invalid destination address".to_string(),
                    context: PolicyFailureContext::InvalidDestination { destination },
                }),
            };
        }
        checks.push(PolicyCheck {
            check_type: PolicyCheckType::DestinationValid,
            passed: true,
            details: format!("destination={}", signing_event.destination_address),
        });

        if !policy.allowed_destinations.is_empty() && !policy.allowed_destinations.contains(&signing_event.destination_address) {
            let destination = signing_event.destination_address.clone();
            let whitelist_size = policy.allowed_destinations.len();
            let check = PolicyCheck {
                check_type: PolicyCheckType::DestinationWhitelisted,
                passed: false,
                details: format!("destination={}, whitelist_size={}", destination, whitelist_size),
            };
            checks.push(check);
            return PolicyEvaluationResult {
                allowed: false,
                checks_performed: checks,
                failed_check: Some(PolicyCheckFailure {
                    check_type: PolicyCheckType::DestinationWhitelisted,
                    reason: "destination not in whitelist".to_string(),
                    context: PolicyFailureContext::DestinationNotAllowed { destination, whitelist_size },
                }),
            };
        }
        checks.push(PolicyCheck {
            check_type: PolicyCheckType::DestinationWhitelisted,
            passed: true,
            details: format!("whitelist_size={}", policy.allowed_destinations.len()),
        });

        if let Some(min_amount) = policy.min_amount_sompi {
            if signing_event.amount_sompi < min_amount {
                let amount = signing_event.amount_sompi;
                let check = PolicyCheck {
                    check_type: PolicyCheckType::AmountAboveMinimum,
                    passed: false,
                    details: format!("amount={}, min={}", amount, min_amount),
                };
                checks.push(check);
                return PolicyEvaluationResult {
                    allowed: false,
                    checks_performed: checks,
                    failed_check: Some(PolicyCheckFailure {
                        check_type: PolicyCheckType::AmountAboveMinimum,
                        reason: format!("amount below minimum {min_amount}"),
                        context: PolicyFailureContext::AmountTooLow { amount, min: min_amount },
                    }),
                };
            }
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::AmountAboveMinimum,
                passed: true,
                details: format!("amount={}, min={}", signing_event.amount_sompi, min_amount),
            });
        } else {
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::AmountAboveMinimum,
                passed: true,
                details: "min_amount=none".to_string(),
            });
        }

        if let Some(max_amount) = policy.max_amount_sompi {
            if signing_event.amount_sompi > max_amount {
                let amount = signing_event.amount_sompi;
                let check = PolicyCheck {
                    check_type: PolicyCheckType::AmountBelowMaximum,
                    passed: false,
                    details: format!("amount={}, max={}", amount, max_amount),
                };
                checks.push(check);
                return PolicyEvaluationResult {
                    allowed: false,
                    checks_performed: checks,
                    failed_check: Some(PolicyCheckFailure {
                        check_type: PolicyCheckType::AmountBelowMaximum,
                        reason: format!("amount exceeds maximum {max_amount}"),
                        context: PolicyFailureContext::AmountTooHigh { amount, max: max_amount },
                    }),
                };
            }
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::AmountBelowMaximum,
                passed: true,
                details: format!("amount={}, max={}", signing_event.amount_sompi, max_amount),
            });
        } else {
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::AmountBelowMaximum,
                passed: true,
                details: "max_amount=none".to_string(),
            });
        }

        if policy.require_reason && !signing_event.metadata.contains_key("reason") {
            let check =
                PolicyCheck { check_type: PolicyCheckType::ReasonProvided, passed: false, details: "reason=missing".to_string() };
            checks.push(check);
            return PolicyEvaluationResult {
                allowed: false,
                checks_performed: checks,
                failed_check: Some(PolicyCheckFailure {
                    check_type: PolicyCheckType::ReasonProvided,
                    reason: "missing required reason".to_string(),
                    context: PolicyFailureContext::MissingReason,
                }),
            };
        }
        checks.push(PolicyCheck {
            check_type: PolicyCheckType::ReasonProvided,
            passed: true,
            details: format!("require_reason={}", policy.require_reason),
        });

        if let Some(limit) = policy.max_daily_volume_sompi {
            let total = current_daily_volume_sompi;
            if total.saturating_add(signing_event.amount_sompi) > limit {
                let amount = signing_event.amount_sompi;
                let check = PolicyCheck {
                    check_type: PolicyCheckType::VelocityLimit,
                    passed: false,
                    details: format!("current_volume={}, amount={}, limit={}", total, amount, limit),
                };
                checks.push(check);
                return PolicyEvaluationResult {
                    allowed: false,
                    checks_performed: checks,
                    failed_check: Some(PolicyCheckFailure {
                        check_type: PolicyCheckType::VelocityLimit,
                        reason: "daily volume exceeded".to_string(),
                        context: PolicyFailureContext::VelocityExceeded { current_volume: total, amount, limit },
                    }),
                };
            }
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::VelocityLimit,
                passed: true,
                details: format!("current_volume={}, amount={}, limit={}", total, signing_event.amount_sompi, limit),
            });
        } else {
            checks.push(PolicyCheck {
                check_type: PolicyCheckType::VelocityLimit,
                passed: true,
                details: "daily_limit=none".to_string(),
            });
        }

        PolicyEvaluationResult { allowed: true, checks_performed: checks, failed_check: None }
    }
}

fn map_policy_failure_to_error(context: &PolicyFailureContext) -> ThresholdError {
    match context {
        PolicyFailureContext::AmountTooLow { amount, min } => ThresholdError::AmountTooLow { amount: *amount, min: *min },
        PolicyFailureContext::AmountTooHigh { amount, max } => ThresholdError::AmountTooHigh { amount: *amount, max: *max },
        PolicyFailureContext::VelocityExceeded { current_volume, limit, .. } => {
            ThresholdError::VelocityLimitExceeded { current: *current_volume, limit: *limit }
        }
        PolicyFailureContext::DestinationNotAllowed { destination, .. } => ThresholdError::DestinationNotAllowed(destination.clone()),
        PolicyFailureContext::MissingReason => ThresholdError::MemoRequired,
        PolicyFailureContext::InvalidDestination { destination } => ThresholdError::DestinationNotAllowed(destination.clone()),
    }
}
