use crate::domain::coordination::threshold::has_threshold;
use crate::domain::PartialSigRecord;

pub fn unique_signers_per_input(partials: &[PartialSigRecord], input_count: usize) -> Vec<usize> {
    let mut counts = vec![0usize; input_count];
    let mut seen: Vec<Vec<Vec<u8>>> = (0..input_count).map(|_| Vec::new()).collect();
    for sig in partials {
        if let Ok(idx) = usize::try_from(sig.input_index) {
            if idx < input_count && !seen[idx].iter().any(|p| p == &sig.pubkey) {
                seen[idx].push(sig.pubkey.clone());
                counts[idx] += 1;
            }
        }
    }
    counts
}

pub fn meets_threshold(partials: &[PartialSigRecord], input_count: usize, required: usize) -> bool {
    has_threshold(partials, input_count, required)
}
