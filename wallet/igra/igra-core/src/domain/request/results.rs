//! Rich result types for request lifecycle operations (no logging in domain).

#[derive(Debug, Clone)]
pub struct StateTransitionResult {
    pub valid: bool,
    pub from_state: String,
    pub to_state: String,
    pub transition_reason: Option<String>,
}
