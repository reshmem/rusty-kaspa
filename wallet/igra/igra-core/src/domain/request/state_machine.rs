use crate::domain::request::results::StateTransitionResult;
use crate::domain::{RequestDecision, SigningRequest};
use crate::foundation::Hash32;
use crate::foundation::ThresholdError;
use crate::foundation::{PeerId, RequestId, SessionId, TransactionId};
use std::marker::PhantomData;
use log::{info, warn};

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

pub fn validate_transition(from: &RequestDecision, to: &RequestDecision) -> StateTransitionResult {
    let from_state = decision_state(from);
    let to_state = decision_state(to);
    if from_state == to_state {
        return StateTransitionResult {
            valid: true,
            from_state: format!("{:?}", from),
            to_state: format!("{:?}", to),
            transition_reason: Some("no_op".to_string()),
        };
    }
    if VALID_TRANSITIONS.contains(&(from_state, to_state)) {
        return StateTransitionResult {
            valid: true,
            from_state: format!("{:?}", from),
            to_state: format!("{:?}", to),
            transition_reason: None,
        };
    }
    StateTransitionResult {
        valid: false,
        from_state: format!("{:?}", from),
        to_state: format!("{:?}", to),
        transition_reason: Some("not_allowed".to_string()),
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
    let from = inner.decision.clone();
    if let Err(err) = ensure_valid_transition(&from, &next) {
        warn!(
            "invalid request state transition request_id={} session_id={} from_state={:?} to_state={:?} error={}",
            inner.request_id,
            hex::encode(inner.session_id.as_hash()),
            from,
            next,
            err
        );
        return Err(err);
    }
    inner.decision = next;
    info!(
        "request state transition request_id={} session_id={} from_state={:?} to_state={:?}",
        inner.request_id,
        hex::encode(inner.session_id.as_hash()),
        from,
        inner.decision
    );
    Ok(TypedSigningRequest { inner, _state: PhantomData })
}

fn transition_with_tx<TargetState>(
    mut inner: SigningRequest,
    next: RequestDecision,
    tx_id: Option<TransactionId>,
    accepted_blue_score: Option<u64>,
) -> Result<TypedSigningRequest<TargetState>, ThresholdError> {
    let from = inner.decision.clone();
    if let Err(err) = ensure_valid_transition(&from, &next) {
        warn!(
            "invalid request state transition request_id={} session_id={} from_state={:?} to_state={:?} error={}",
            inner.request_id,
            hex::encode(inner.session_id.as_hash()),
            from,
            next,
            err
        );
        return Err(err);
    }
    inner.decision = next;
    inner.final_tx_id = tx_id;
    inner.final_tx_accepted_blue_score = accepted_blue_score;
    info!(
        "request state transition request_id={} session_id={} from_state={:?} to_state={:?} tx_id={:?} accepted_blue_score={:?}",
        inner.request_id,
        hex::encode(inner.session_id.as_hash()),
        from,
        inner.decision,
        inner.final_tx_id,
        inner.final_tx_accepted_blue_score
    );
    Ok(TypedSigningRequest { inner, _state: PhantomData })
}

pub fn ensure_valid_transition(from: &RequestDecision, to: &RequestDecision) -> Result<(), ThresholdError> {
    let transition = validate_transition(from, to);
    if transition.valid {
        Ok(())
    } else {
        Err(ThresholdError::InvalidStateTransition { from: transition.from_state, to: transition.to_state })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(validate_transition(&RequestDecision::Pending, &RequestDecision::Approved).valid);
        assert!(validate_transition(&RequestDecision::Approved, &RequestDecision::Finalized).valid);
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(!validate_transition(&RequestDecision::Finalized, &RequestDecision::Pending).valid);
        assert!(!validate_transition(&RequestDecision::Rejected { reason: "policy".to_string() }, &RequestDecision::Approved).valid);
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
