use crate::domain::pskt::multisig::{build_pskt, MultisigInput, MultisigOutput};
use crate::domain::pskt::params::{PsktParams, UtxoInput};
use crate::domain::pskt::results::{PsktBuildResult, UtxoSelectionResult};
use crate::domain::FeePaymentMode;
use crate::foundation::ThresholdError;
use crate::foundation::constants::MAX_PSKT_INPUTS;
use kaspa_addresses::Address;
use kaspa_txscript::pay_to_address_script;

pub fn build_pskt_from_utxos(
    params: &PsktParams,
    mut utxos: Vec<UtxoInput>,
) -> Result<(UtxoSelectionResult, PsktBuildResult), ThresholdError> {
    let base_outputs = params
        .outputs
        .iter()
        .map(|out| {
            let addr = Address::constructor(&out.address);
            MultisigOutput { amount: out.amount_sompi, script_public_key: pay_to_address_script(&addr) }
        })
        .collect::<Vec<_>>();

    // Prefer fewer inputs: sort by amount (desc), then outpoint (asc) for determinism.
    utxos.sort_by(|a, b| {
        b.entry
            .amount
            .cmp(&a.entry.amount)
            .then(a.outpoint.transaction_id.as_bytes().cmp(&b.outpoint.transaction_id.as_bytes()))
            .then(a.outpoint.index.cmp(&b.outpoint.index))
    });

    // Deterministically select the smallest set of UTXOs that satisfies the configured outputs+fee policy.
    let mut selected = Vec::new();
    let mut total_input = 0u64;
    let mut outputs: Option<Vec<MultisigOutput>> = None;

    for utxo in utxos.into_iter() {
        if selected.len() >= MAX_PSKT_INPUTS {
            return Err(ThresholdError::PsktValidationFailed(format!(
                "too many inputs selected for PSKT: {} (max {})",
                selected.len(),
                MAX_PSKT_INPUTS
            )));
        }

        total_input = total_input.saturating_add(utxo.entry.amount);
        selected.push(utxo);

        let mut candidate_outputs = base_outputs.clone();
        match apply_fee_policy(params, total_input, &mut candidate_outputs) {
            Ok(()) => {
                outputs = Some(candidate_outputs);
                break;
            }
            Err(ThresholdError::InsufficientUTXOs) => continue,
            Err(err) => return Err(err),
        }
    }

    let outputs = match outputs {
        Some(outputs) => outputs,
        None => return Err(ThresholdError::InsufficientUTXOs),
    };

    let selected_utxos = selected.len();

    let inputs = selected
        .into_iter()
        .map(|utxo| MultisigInput {
            utxo_entry: utxo.entry,
            previous_outpoint: utxo.outpoint,
            redeem_script: params.redeem_script.clone(),
            sig_op_count: params.sig_op_count,
        })
        .collect::<Vec<_>>();

    let total_output_amount = outputs.iter().map(|out| out.amount).sum::<u64>();
    let has_change_output = outputs.len() > params.outputs.len();
    let change_amount = if has_change_output { outputs.last().map(|out| out.amount).unwrap_or(0) } else { 0 };
    let fee_amount = total_input.saturating_sub(total_output_amount);

    let selection = UtxoSelectionResult {
        selected_utxos,
        total_input_amount: total_input,
        total_output_amount,
        fee_amount,
        change_amount,
        has_change_output,
    };

    let build = build_pskt(&inputs, &outputs)?;
    Ok((selection, build))
}

struct FeeConfig {
    recipient_fee: u64,
    signer_fee: u64,
}

impl FeeConfig {
    fn from_mode(fee: u64, mode: &FeePaymentMode) -> Result<Self, ThresholdError> {
        let (recipient_fee, signer_fee) = match mode {
            FeePaymentMode::RecipientPays => (fee, 0),
            FeePaymentMode::SignersPay => (0, fee),
            FeePaymentMode::Split { recipient_parts, signer_parts } => {
                let total_parts = recipient_parts.saturating_add(*signer_parts);
                if total_parts == 0 {
                    return Err(ThresholdError::Message("fee split parts must not both be zero".to_string()));
                }
                let recipient_fee = fee
                    .checked_mul(*recipient_parts as u64)
                    .and_then(|v| v.checked_div(total_parts as u64))
                    .ok_or_else(|| ThresholdError::Message("fee split overflow".to_string()))?;
                (recipient_fee, fee.saturating_sub(recipient_fee))
            }
        };

        Ok(FeeConfig { recipient_fee, signer_fee })
    }
}

fn apply_fee_policy(params: &PsktParams, total_input: u64, outputs: &mut Vec<MultisigOutput>) -> Result<(), ThresholdError> {
    let fee = params.fee_sompi.unwrap_or(0);
    if outputs.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("missing outputs for fee calculation".to_string()));
    }

    let fee_cfg = FeeConfig::from_mode(fee, &params.fee_payment_mode)?;

    if fee_cfg.recipient_fee > 0 {
        let first = outputs.first_mut().ok_or_else(|| ThresholdError::PsktValidationFailed("missing recipient output".to_string()))?;
        if first.amount < fee_cfg.recipient_fee {
            return Err(ThresholdError::InsufficientUTXOs);
        }
        first.amount -= fee_cfg.recipient_fee;
    }

    let total_output = outputs.iter().map(|out| out.amount).sum::<u64>();
    let required = total_output.saturating_add(fee_cfg.signer_fee);
    if total_input < required {
        return Err(ThresholdError::InsufficientUTXOs);
    }

    let change = total_input - required;
    if change > 0 {
        if let Some(address) = params.change_address.as_ref() {
            let addr = Address::constructor(address);
            outputs.push(MultisigOutput { amount: change, script_public_key: pay_to_address_script(&addr) });
        } else if fee > 0 {
            // If the caller specified a fee, require a change address so we can avoid implicitly overpaying.
            return Err(ThresholdError::PsktValidationFailed("missing change_address".to_string()));
        }
    }
    Ok(())
}
