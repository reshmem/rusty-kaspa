use crate::domain::pskt::params::PsktParams;

#[derive(Debug, Clone)]
pub struct PsktValidationResult {
    pub valid: bool,
    pub input_count: usize,
    pub output_count: usize,
    pub sig_op_count: u8,
    pub validation_errors: Vec<PsktValidationError>,
}

#[derive(Debug, Clone)]
pub enum PsktValidationError {
    NoInputs,
    NoOutputs,
    ZeroSigOpCount,
    NoSourceAddresses,
    NoOutputParams,
}

pub fn validate_params(params: &PsktParams) -> PsktValidationResult {
    let mut errors = Vec::new();

    if params.sig_op_count == 0 {
        errors.push(PsktValidationError::ZeroSigOpCount);
    }
    if params.source_addresses.is_empty() {
        errors.push(PsktValidationError::NoSourceAddresses);
    }
    if params.outputs.is_empty() {
        errors.push(PsktValidationError::NoOutputParams);
    }

    PsktValidationResult {
        valid: errors.is_empty(),
        input_count: 0,
        output_count: params.outputs.len(),
        sig_op_count: params.sig_op_count,
        validation_errors: errors,
    }
}
