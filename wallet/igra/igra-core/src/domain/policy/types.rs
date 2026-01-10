//! Rich result types for policy evaluation (no logging in domain).

#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult {
    pub allowed: bool,
    pub checks_performed: Vec<PolicyCheck>,
    pub failed_check: Option<PolicyCheckFailure>,
}

#[derive(Debug, Clone)]
pub struct PolicyCheck {
    pub check_type: PolicyCheckType,
    pub passed: bool,
    pub details: String,
}

#[derive(Debug, Clone, Copy)]
pub enum PolicyCheckType {
    AmountNonZero,
    DestinationValid,
    DestinationWhitelisted,
    AmountAboveMinimum,
    AmountBelowMaximum,
    ReasonProvided,
    VelocityLimit,
}

#[derive(Debug, Clone)]
pub struct PolicyCheckFailure {
    pub check_type: PolicyCheckType,
    pub reason: String,
    pub context: PolicyFailureContext,
}

#[derive(Debug, Clone)]
pub enum PolicyFailureContext {
    AmountTooLow { amount: u64, min: u64 },
    AmountTooHigh { amount: u64, max: u64 },
    VelocityExceeded { current_volume: u64, amount: u64, limit: u64 },
    DestinationNotAllowed { destination: String, whitelist_size: usize },
    MissingReason,
    InvalidDestination { destination: String },
}
