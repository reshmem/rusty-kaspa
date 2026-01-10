use crate::domain::pskt::multisig::{build_pskt, MultisigInput, MultisigOutput};
use crate::domain::pskt::params::{PsktParams, UtxoInput};
use crate::domain::FeePaymentMode;
use crate::foundation::ThresholdError;
use kaspa_addresses::Address;
use kaspa_txscript::pay_to_address_script;

pub fn build_pskt_from_utxos(
    params: &PsktParams,
    mut utxos: Vec<UtxoInput>,
) -> Result<kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Updater>, ThresholdError> {
    let mut outputs = params
        .outputs
        .iter()
        .map(|out| {
            let addr = Address::constructor(&out.address);
            MultisigOutput { amount: out.amount_sompi, script_public_key: pay_to_address_script(&addr) }
        })
        .collect::<Vec<_>>();

    // Deterministic ordering across nodes.
    utxos.sort_by(|a, b| {
        a.outpoint
            .transaction_id
            .as_bytes()
            .cmp(&b.outpoint.transaction_id.as_bytes())
            .then(a.outpoint.index.cmp(&b.outpoint.index))
    });

    let total_input = utxos.iter().map(|utxo| utxo.entry.amount).sum::<u64>();
    apply_fee_policy(params, total_input, &mut outputs)?;

    let inputs = utxos
        .into_iter()
        .map(|utxo| MultisigInput {
            utxo_entry: utxo.entry,
            previous_outpoint: utxo.outpoint,
            redeem_script: params.redeem_script.clone(),
            sig_op_count: params.sig_op_count,
        })
        .collect::<Vec<_>>();

    build_pskt(&inputs, &outputs)
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
    if fee == 0 {
        return Ok(());
    }
    if outputs.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("missing outputs for fee calculation".to_string()));
    }

    let fee_cfg = FeeConfig::from_mode(fee, &params.fee_payment_mode)?;

    if fee_cfg.recipient_fee > 0 {
        let first =
            outputs.first_mut().ok_or_else(|| ThresholdError::PsktValidationFailed("missing recipient output".to_string()))?;
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
        let address = params
            .change_address
            .as_ref()
            .ok_or_else(|| ThresholdError::PsktValidationFailed("missing change_address".to_string()))?;
        let addr = Address::constructor(address);
        outputs.push(MultisigOutput { amount: change, script_public_key: pay_to_address_script(&addr) });
    }
    Ok(())
}
