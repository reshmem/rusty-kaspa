use crate::domain::coordination::threshold::has_threshold;
use crate::domain::PartialSigRecord;

pub fn ready_to_finalize(partials: &[PartialSigRecord], input_count: usize, required: usize) -> bool {
    has_threshold(partials, input_count, required)
}

pub fn missing_signatures(partials: &[PartialSigRecord], input_count: usize, required: usize) -> usize {
    if input_count == 0 {
        return required;
    }
    let mut counts = vec![0usize; input_count];
    for sig in partials {
        if let Ok(idx) = usize::try_from(sig.input_index) {
            if idx < input_count {
                counts[idx] = counts[idx].saturating_add(1);
            }
        }
    }
    counts
        .into_iter()
        .map(|count| required.saturating_sub(count))
        .sum()
}
