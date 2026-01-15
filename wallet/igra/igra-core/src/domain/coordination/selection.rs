use crate::domain::coordination::Proposal;
use crate::foundation::{Hash32, PeerId};
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct HashVoteStats {
    hash: Hash32,
    vote_count: usize,
    lowest_proposer: PeerId,
}

impl HashVoteStats {
    fn selection_key(&self) -> (std::cmp::Reverse<usize>, Hash32, &str) {
        (std::cmp::Reverse(self.vote_count), self.hash, self.lowest_proposer.as_str())
    }
}

/// Returns `Some(hash)` if at least one hash has `>= commit_quorum` votes.
///
/// Deterministic tie-breaks:
/// - Higher vote count wins
/// - On ties, numerically-lower `tx_template_hash` wins
/// - On ties, lowest `proposer_peer_id` wins
pub fn quorum_hash(proposals: &[Proposal], commit_quorum: usize) -> Option<Hash32> {
    if proposals.is_empty() || commit_quorum == 0 {
        return None;
    }

    let mut stats_by_hash: HashMap<Hash32, HashVoteStats> = HashMap::new();
    for proposal in proposals {
        let stats = stats_by_hash.entry(proposal.tx_template_hash).or_insert_with(|| HashVoteStats {
            hash: proposal.tx_template_hash,
            vote_count: 0,
            lowest_proposer: proposal.proposer_peer_id.clone(),
        });
        stats.vote_count += 1;
        if proposal.proposer_peer_id.as_str() < stats.lowest_proposer.as_str() {
            stats.lowest_proposer = proposal.proposer_peer_id.clone();
        }
    }

    stats_by_hash.values().filter(|s| s.vote_count >= commit_quorum).min_by_key(|s| s.selection_key()).map(|s| s.hash)
}

pub fn select_canonical_proposal_for_commit<'a>(proposals: &'a [Proposal], commit_quorum: usize) -> Option<&'a Proposal> {
    let winning_hash = quorum_hash(proposals, commit_quorum)?;
    let event_id = proposals.first().map(|p| p.event_id)?;

    proposals
        .iter()
        .filter(|p| p.tx_template_hash == winning_hash)
        .min_by_key(|p| canonical_proposal_score(&event_id, p.round, &p.proposer_peer_id))
}

fn canonical_proposal_score(event_id: &Hash32, round: u32, proposer_peer_id: &PeerId) -> [u8; 32] {
    const DOMAIN: &[u8] = b"igra:two_phase:canonical_proposal:v1:";
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(event_id);
    hasher.update(&round.to_le_bytes());
    hasher.update(proposer_peer_id.as_str().as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::{CrdtSigningMaterial, Event, EventAuditData, SourceType};
    use kaspa_consensus_core::tx::ScriptPublicKey;
    use std::collections::BTreeMap;

    fn proposal(hash: Hash32, peer: &str) -> Proposal {
        Proposal {
            event_id: [1u8; 32],
            round: 0,
            tx_template_hash: hash,
            kpsbt_blob: vec![],
            utxos_used: vec![],
            outputs: vec![],
            signing_material: CrdtSigningMaterial {
                event: Event {
                    external_id: [2u8; 32],
                    source: SourceType::Api,
                    destination: ScriptPublicKey::from_vec(0, vec![1]),
                    amount_sompi: 1,
                },
                audit: EventAuditData {
                    external_id_raw: "x".to_string(),
                    destination_raw: "y".to_string(),
                    source_data: BTreeMap::new(),
                },
                proof: None,
            },
            proposer_peer_id: PeerId::from(peer),
            timestamp_ns: 0,
        }
    }

    #[test]
    fn select_canonical_proposal_requires_single_hash_quorum() {
        let proposals = vec![proposal([1u8; 32], "peer-1"), proposal([2u8; 32], "peer-2"), proposal([3u8; 32], "peer-3")];

        let out = select_canonical_proposal_for_commit(&proposals, 3);
        assert!(out.is_none());
    }

    #[test]
    fn select_canonical_proposal_is_deterministic_for_quorum_hash() {
        let h = [9u8; 32];
        let proposals = vec![proposal(h, "peer-b"), proposal(h, "peer-a"), proposal([8u8; 32], "peer-c")];

        let out = select_canonical_proposal_for_commit(&proposals, 2).expect("winner");
        assert_eq!(out.tx_template_hash, h);

        let expected = proposals
            .iter()
            .filter(|p| p.tx_template_hash == h)
            .min_by_key(|p| canonical_proposal_score(&p.event_id, p.round, &p.proposer_peer_id))
            .expect("expected winner");
        assert_eq!(out.proposer_peer_id.as_str(), expected.proposer_peer_id.as_str());
    }
}
