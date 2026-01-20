use crate::foundation::TxTemplateHash;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventPhase {
    #[default]
    Unknown = 0,
    Proposing = 1,
    Committed = 2,
    Completed = 3,
    Failed = 4,
    Abandoned = 5,
}

impl EventPhase {
    pub fn can_transition_to(self, target: EventPhase) -> bool {
        use EventPhase::*;
        matches!(
            (self, target),
            (Unknown, Proposing)
                | (Unknown, Committed)
                | (Proposing, Committed)
                | (Proposing, Failed)
                | (Committed, Completed)
                | (Failed, Committed)
                | (Failed, Proposing)
                | (Failed, Abandoned)
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, EventPhase::Completed | EventPhase::Abandoned)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KaspaAnchorRef {
    pub tip_blue_score: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseContext {
    pub round: u32,
    pub phase: EventPhase,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventPhaseState {
    pub phase: EventPhase,
    pub phase_started_at_ns: u64,
    pub round: u32,
    pub canonical_hash: Option<TxTemplateHash>,
    pub own_proposal_hash: Option<TxTemplateHash>,
    pub retry_count: u32,
}

impl EventPhaseState {
    pub fn new(phase: EventPhase, now_ns: u64) -> Self {
        Self { phase, phase_started_at_ns: now_ns, round: 0, canonical_hash: None, own_proposal_hash: None, retry_count: 0 }
    }

    pub fn is_timeout_expired(&self, now_ns: u64, timeout_ms: u64) -> bool {
        let elapsed_ns = now_ns.saturating_sub(self.phase_started_at_ns);
        elapsed_ns >= timeout_ms.saturating_mul(1_000_000)
    }
}
