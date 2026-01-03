use crate::model::PartialSigRecord;
use std::collections::HashSet;

pub fn has_threshold(partials: &[PartialSigRecord], input_count: usize, required: usize) -> bool {
    if input_count == 0 || required == 0 {
        return false;
    }
    if partials.len() < input_count.saturating_mul(required) {
        return false;
    }
    let mut per_input: Vec<HashSet<Vec<u8>>> = (0..input_count).map(|_| HashSet::new()).collect();
    for sig in partials {
        let idx = sig.input_index as usize;
        if idx >= input_count {
            continue;
        }
        per_input[idx].insert(sig.pubkey.clone());
    }
    per_input.into_iter().all(|set| set.len() >= required)
}
