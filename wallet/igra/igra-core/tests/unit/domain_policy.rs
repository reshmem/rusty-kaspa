#[path = "../fixtures/mod.rs"]
mod fixtures;

use fixtures::builders::SigningEventBuilder;
use igra_core::domain::policy::enforcement::{DefaultPolicyEnforcer, PolicyEnforcer};
use igra_core::domain::GroupPolicy;
use igra_core::foundation::ThresholdError;

#[test]
fn test_policy_enforcement_when_destination_not_allowed_then_rejects() {
    let enforcer = DefaultPolicyEnforcer::new();
    let event = SigningEventBuilder::default().destination_address("kaspatest:disallowed").build();
    let policy = GroupPolicy { allowed_destinations: vec!["kaspatest:allowed".to_string()], ..Default::default() };
    let err = enforcer.enforce_policy(&event, &policy, 0).unwrap_err();
    assert!(matches!(err, ThresholdError::DestinationNotAllowed(_)));
}

#[test]
fn test_policy_enforcement_when_amount_below_min_then_rejects() {
    let enforcer = DefaultPolicyEnforcer::new();
    let event = SigningEventBuilder::default().amount_sompi(1).build();
    let policy = GroupPolicy { min_amount_sompi: Some(10), ..Default::default() };
    let err = enforcer.enforce_policy(&event, &policy, 0).unwrap_err();
    assert!(matches!(err, ThresholdError::AmountTooLow { .. }));
}

#[test]
fn test_policy_enforcement_when_daily_volume_exceeded_then_rejects() {
    let enforcer = DefaultPolicyEnforcer::new();
    let event = SigningEventBuilder::default().amount_sompi(50).build();
    let policy = GroupPolicy { max_daily_volume_sompi: Some(100), ..Default::default() };
    let err = enforcer.enforce_policy(&event, &policy, 60).unwrap_err();
    assert!(matches!(err, ThresholdError::VelocityLimitExceeded { .. }));
}
