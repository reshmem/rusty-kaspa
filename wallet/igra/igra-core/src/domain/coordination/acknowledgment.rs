use crate::domain::SignerAckRecord;

#[derive(Debug, Default, Clone, Copy)]
pub struct AckSummary {
    pub accept: usize,
    pub reject: usize,
}

pub fn summarize_acks(acks: &[SignerAckRecord]) -> AckSummary {
    let mut summary = AckSummary::default();
    for ack in acks {
        if ack.accept {
            summary.accept += 1;
        } else {
            summary.reject += 1;
        }
    }
    summary
}

pub fn has_quorum(acks: &[SignerAckRecord], required_accepts: usize) -> bool {
    summarize_acks(acks).accept >= required_accepts
}
