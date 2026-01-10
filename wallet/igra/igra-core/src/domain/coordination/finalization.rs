use crate::domain::coordination::results::ThresholdStatus;
use crate::domain::PartialSigRecord;

pub fn threshold_status(partials: &[PartialSigRecord], input_count: usize, required: usize) -> ThresholdStatus {
    let mut per_input_signature_counts = vec![0usize; input_count];
    for sig in partials {
        if let Ok(idx) = usize::try_from(sig.input_index) {
            if idx < input_count {
                per_input_signature_counts[idx] = per_input_signature_counts[idx].saturating_add(1);
            }
        }
    }

    let missing_inputs = per_input_signature_counts
        .iter()
        .enumerate()
        .filter(|(_, &count)| count < required)
        .map(|(idx, _)| idx as u32)
        .collect::<Vec<_>>();

    ThresholdStatus {
        ready: missing_inputs.is_empty() && input_count > 0,
        input_count,
        required_signatures: required,
        per_input_signature_counts,
        missing_inputs,
    }
}
