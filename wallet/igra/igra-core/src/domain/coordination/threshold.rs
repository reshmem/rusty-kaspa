use crate::domain::PartialSigRecord;
use std::collections::{HashMap, HashSet};

/// Returns true if at least `required` unique pubkeys are present per input.
pub fn has_threshold(partials: &[PartialSigRecord], input_count: usize, required: usize) -> bool {
    if input_count == 0 || required == 0 {
        return false;
    }
    if partials.len() < required {
        return false;
    }

    let mut per_input: HashMap<u32, HashSet<&[u8]>> = HashMap::new();
    for sig in partials {
        let idx = sig.input_index;
        if idx as usize >= input_count {
            continue;
        }
        per_input.entry(idx).or_default().insert(sig.pubkey.as_slice());
    }

    (0..input_count as u32).all(|idx| per_input.get(&idx).map_or(false, |set| set.len() >= required))
}
