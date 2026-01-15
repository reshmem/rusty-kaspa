use crate::domain::coordination::{EventPhase, EventPhaseState, Proposal};
use crate::foundation::{Hash32, PeerId, ThresholdError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreProposalResult {
    Stored,
    DuplicateFromPeer,
    Equivocation { existing_hash: Hash32, new_hash: Hash32 },
    PhaseTooLate,
    RoundMismatch { expected: u32, got: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordSignedHashResult {
    Set,
    AlreadySame,
    Conflict { existing: Hash32, attempted: Hash32 },
}

pub trait PhaseStorage: Send + Sync {
    fn try_enter_proposing(&self, event_id: &Hash32, now_ns: u64) -> Result<bool, ThresholdError>;

    fn get_phase(&self, event_id: &Hash32) -> Result<Option<EventPhaseState>, ThresholdError>;

    fn get_signed_hash(&self, event_id: &Hash32) -> Result<Option<Hash32>, ThresholdError>;

    fn record_signed_hash(
        &self,
        event_id: &Hash32,
        tx_template_hash: Hash32,
        now_ns: u64,
    ) -> Result<RecordSignedHashResult, ThresholdError>;

    /// If the event is not committed/terminal and our local round is behind `new_round`,
    /// move the event into `Proposing` at `new_round` and reset per-round fields.
    ///
    /// Returns `Ok(true)` if we adopted the new round.
    fn adopt_round_if_behind(&self, event_id: &Hash32, new_round: u32, now_ns: u64) -> Result<bool, ThresholdError>;

    fn set_own_proposal_hash(&self, event_id: &Hash32, tx_template_hash: Hash32) -> Result<(), ThresholdError>;

    fn store_proposal(&self, proposal: &Proposal) -> Result<StoreProposalResult, ThresholdError>;

    fn get_proposals(&self, event_id: &Hash32, round: u32) -> Result<Vec<Proposal>, ThresholdError>;

    fn proposal_count(&self, event_id: &Hash32, round: u32) -> Result<usize, ThresholdError>;

    fn get_events_in_phase(&self, phase: EventPhase) -> Result<Vec<Hash32>, ThresholdError>;

    fn mark_committed(&self, event_id: &Hash32, round: u32, canonical_hash: Hash32, now_ns: u64) -> Result<bool, ThresholdError>;

    fn mark_completed(&self, event_id: &Hash32, now_ns: u64) -> Result<(), ThresholdError>;

    fn fail_and_bump_round(&self, event_id: &Hash32, expected_round: u32, now_ns: u64) -> Result<bool, ThresholdError>;

    fn mark_abandoned(&self, event_id: &Hash32, now_ns: u64) -> Result<(), ThresholdError>;

    fn clear_stale_proposals(&self, event_id: &Hash32, before_round: u32) -> Result<usize, ThresholdError>;

    fn gc_events_older_than(&self, cutoff_timestamp_ns: u64) -> Result<usize, ThresholdError>;

    fn has_proposal_from(&self, event_id: &Hash32, round: u32, peer_id: &PeerId) -> Result<bool, ThresholdError>;
}
