//! Rich result types for coordination operations (no logging in domain).

#[derive(Debug, Clone)]
pub struct ThresholdStatus {
    pub ready: bool,
    pub input_count: usize,
    pub required_signatures: usize,
    pub per_input_signature_counts: Vec<usize>,
    pub missing_inputs: Vec<u32>,
}

impl ThresholdStatus {
    pub fn missing_signatures(&self) -> Vec<(u32, usize)> {
        self.per_input_signature_counts
            .iter()
            .enumerate()
            .filter(|(_, &count)| count < self.required_signatures)
            .map(|(idx, &count)| (idx as u32, self.required_signatures - count))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ValidationStep {
    pub step_name: &'static str,
    pub passed: bool,
    pub details: Option<String>,
}
