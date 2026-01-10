use crate::domain::pskt::multisig::{MultisigInput, MultisigOutput};
use crate::domain::pskt::params::PsktParams;
use crate::foundation::ThresholdError;

pub fn validate_inputs(inputs: &[MultisigInput]) -> Result<(), ThresholdError> {
    if inputs.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("pskt requires at least one input".to_string()));
    }
    Ok(())
}

pub fn validate_outputs(outputs: &[MultisigOutput]) -> Result<(), ThresholdError> {
    if outputs.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("pskt requires at least one output".to_string()));
    }
    Ok(())
}

pub fn validate_params(params: &PsktParams) -> Result<(), ThresholdError> {
    if params.sig_op_count == 0 {
        return Err(ThresholdError::PsktValidationFailed("pskt.sig_op_count must be > 0".to_string()));
    }
    if params.source_addresses.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("pskt.source_addresses must not be empty".to_string()));
    }
    if params.outputs.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("pskt.outputs must not be empty".to_string()));
    }
    Ok(())
}
