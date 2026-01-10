use crate::foundation::ThresholdError;
use crate::domain::FeePaymentMode;
use crate::domain::pskt::multisig::MultisigOutput;

/// Split fee into recipient/signer parts according to policy.
pub fn split_fee(fee: u64, mode: &FeePaymentMode) -> Result<(u64, u64), ThresholdError> {
    match mode {
        FeePaymentMode::RecipientPays => Ok((fee, 0)),
        FeePaymentMode::SignersPay => Ok((0, fee)),
        FeePaymentMode::Split { recipient_parts, signer_parts } => {
            let total_parts = recipient_parts.saturating_add(*signer_parts);
            if total_parts == 0 {
                return Err(ThresholdError::Message("fee split parts must not both be zero".to_string()));
            }
            let recipient_fee = fee
                .checked_mul(*recipient_parts as u64)
                .and_then(|v| v.checked_div(total_parts as u64))
                .ok_or_else(|| ThresholdError::Message("fee split overflow".to_string()))?;
            Ok((recipient_fee, fee.saturating_sub(recipient_fee)))
        }
    }
}

/// Apply a fee split to outputs (mutates outputs in place). Change handling is left to the caller.
pub fn apply_recipient_fee(outputs: &mut [MultisigOutput], recipient_fee: u64) -> Result<(), ThresholdError> {
    if recipient_fee == 0 {
        return Ok(());
    }
    let first = outputs.first_mut().ok_or_else(|| ThresholdError::Message("missing recipient output".to_string()))?;
    if first.amount < recipient_fee {
        return Err(ThresholdError::InsufficientUTXOs);
    }
    first.amount -= recipient_fee;
    Ok(())
}

/// Basic PSKT fee sanity checks before building.
pub fn validate_fee_mode(mode: &FeePaymentMode) -> Result<(), ThresholdError> {
    if let FeePaymentMode::Split { recipient_parts, signer_parts } = mode {
        if *recipient_parts == 0 && *signer_parts == 0 {
            return Err(ThresholdError::Message("fee split parts must not both be zero".to_string()));
        }
    }
    Ok(())
}
