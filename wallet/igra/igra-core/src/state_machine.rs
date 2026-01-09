use crate::error::ThresholdError;
use crate::model::{Hash32, RequestDecision, SigningRequest};
use crate::types::{PeerId, RequestId, SessionId, TransactionId};
use std::marker::PhantomData;

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

// Typestate wrappers for SigningRequest lifecycle
pub struct Pending;
pub struct Approved;
pub struct Finalized;
pub struct Rejected;
pub struct Expired;
pub struct Aborted;

#[derive(Clone, Debug)]
pub struct TypedSigningRequest<State> {
    inner: SigningRequest,
    _state: PhantomData<State>,
}

impl TypedSigningRequest<Pending> {
    pub fn new(
        request_id: RequestId,
        session_id: SessionId,
        event_hash: Hash32,
        coordinator_peer_id: PeerId,
        tx_template_hash: Hash32,
        validation_hash: Hash32,
        expires_at_nanos: u64,
    ) -> Self {
        let inner = SigningRequest {
            request_id,
            session_id,
            event_hash,
            coordinator_peer_id,
            tx_template_hash,
            validation_hash,
            decision: RequestDecision::Pending,
            expires_at_nanos,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        };
        Self { inner, _state: PhantomData }
    }

    pub fn approve(self) -> Result<TypedSigningRequest<Approved>, ThresholdError> {
        transition(self.inner, RequestDecision::Approved)
    }

    pub fn reject(self, reason: String) -> Result<TypedSigningRequest<Rejected>, ThresholdError> {
        transition(self.inner, RequestDecision::Rejected { reason })
    }

    pub fn expire(self) -> Result<TypedSigningRequest<Expired>, ThresholdError> {
        transition(self.inner, RequestDecision::Expired)
    }

    pub fn finalize(
        self,
        tx_id: TransactionId,
        accepted_blue_score: Option<u64>,
    ) -> Result<TypedSigningRequest<Finalized>, ThresholdError> {
        transition_with_tx(self.inner, RequestDecision::Finalized, Some(tx_id), accepted_blue_score)
    }
}

impl TypedSigningRequest<Approved> {
    pub fn finalize(
        self,
        tx_id: TransactionId,
        accepted_blue_score: Option<u64>,
    ) -> Result<TypedSigningRequest<Finalized>, ThresholdError> {
        transition_with_tx(self.inner, RequestDecision::Finalized, Some(tx_id), accepted_blue_score)
    }

    pub fn abort(self, reason: String) -> Result<TypedSigningRequest<Aborted>, ThresholdError> {
        transition(self.inner, RequestDecision::Aborted { reason })
    }
}

impl<State> TypedSigningRequest<State> {
    pub fn into_inner(self) -> SigningRequest {
        self.inner
    }

    pub fn as_inner(&self) -> &SigningRequest {
        &self.inner
    }
}

fn transition<TargetState>(
    mut inner: SigningRequest,
    next: RequestDecision,
) -> Result<TypedSigningRequest<TargetState>, ThresholdError> {
    validate_transition(&inner.decision, &next)?;
    inner.decision = next;
    Ok(TypedSigningRequest { inner, _state: PhantomData })
}

fn transition_with_tx<TargetState>(
    mut inner: SigningRequest,
    next: RequestDecision,
    tx_id: Option<TransactionId>,
    accepted_blue_score: Option<u64>,
) -> Result<TypedSigningRequest<TargetState>, ThresholdError> {
    validate_transition(&inner.decision, &next)?;
    inner.decision = next;
    inner.final_tx_id = tx_id;
    inner.final_tx_accepted_blue_score = accepted_blue_score;
    Ok(TypedSigningRequest { inner, _state: PhantomData })
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
