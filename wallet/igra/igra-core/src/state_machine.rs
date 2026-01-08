use crate::error::ThresholdError;
use crate::model::RequestDecision;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum DecisionState {
    Pending,
    Approved,
    Rejected,
    Expired,
    Finalized,
    Aborted,
}

const VALID_TRANSITIONS: &[(DecisionState, DecisionState)] = &[
    (DecisionState::Pending, DecisionState::Approved),
    (DecisionState::Pending, DecisionState::Rejected),
    (DecisionState::Pending, DecisionState::Expired),
    (DecisionState::Pending, DecisionState::Finalized),
    (DecisionState::Approved, DecisionState::Finalized),
    (DecisionState::Approved, DecisionState::Expired),
    (DecisionState::Approved, DecisionState::Aborted),
];

fn decision_state(decision: &RequestDecision) -> DecisionState {
    match decision {
        RequestDecision::Pending => DecisionState::Pending,
        RequestDecision::Approved => DecisionState::Approved,
        RequestDecision::Rejected { .. } => DecisionState::Rejected,
        RequestDecision::Expired => DecisionState::Expired,
        RequestDecision::Finalized => DecisionState::Finalized,
        RequestDecision::Aborted { .. } => DecisionState::Aborted,
    }
}

pub fn validate_transition(from: &RequestDecision, to: &RequestDecision) -> Result<(), ThresholdError> {
    let from_state = decision_state(from);
    let to_state = decision_state(to);
    if from_state == to_state {
        return Ok(());
    }
    if VALID_TRANSITIONS.contains(&(from_state, to_state)) {
        Ok(())
    } else {
        Err(ThresholdError::InvalidStateTransition { from: format!("{:?}", from), to: format!("{:?}", to) })
    }
}

pub fn is_terminal(decision: &RequestDecision) -> bool {
    matches!(
        decision,
        RequestDecision::Finalized | RequestDecision::Rejected { .. } | RequestDecision::Expired | RequestDecision::Aborted { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(validate_transition(&RequestDecision::Pending, &RequestDecision::Approved).is_ok());
        assert!(validate_transition(&RequestDecision::Approved, &RequestDecision::Finalized).is_ok());
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(validate_transition(&RequestDecision::Finalized, &RequestDecision::Pending).is_err());
        assert!(validate_transition(&RequestDecision::Rejected { reason: "policy".to_string() }, &RequestDecision::Approved).is_err());
    }

    #[test]
    fn test_terminal_states() {
        assert!(is_terminal(&RequestDecision::Finalized));
        assert!(is_terminal(&RequestDecision::Rejected { reason: "policy".to_string() }));
        assert!(is_terminal(&RequestDecision::Expired));
        assert!(is_terminal(&RequestDecision::Aborted { reason: "manual".to_string() }));
        assert!(!is_terminal(&RequestDecision::Pending));
    }
}
