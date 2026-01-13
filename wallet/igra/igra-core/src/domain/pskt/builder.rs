use crate::domain::pskt::multisig::{build_pskt, MultisigInput, MultisigOutput};
use crate::domain::pskt::params::{PsktParams, UtxoInput};
use crate::domain::pskt::results::{PsktBuildResult, UtxoSelectionResult};
use crate::domain::FeePaymentMode;
use crate::foundation::ThresholdError;
use crate::foundation::constants::MAX_PSKT_INPUTS;
use kaspa_addresses::Address;
use kaspa_addresses::Prefix;
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, SIMNET_PARAMS, TESTNET_PARAMS};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::{calc_storage_mass, MassCalculator, UtxoCell};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput};
use kaspa_txscript::{opcodes::codes::OpData65, script_builder::ScriptBuilder};
use kaspa_txscript::pay_to_address_script;
use kaspa_wallet_core::tx::mass::MAXIMUM_STANDARD_TRANSACTION_MASS;

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

    let consensus_params = consensus_params_for_pskt(params)?;
    let mass_calc = MassCalculator::new_with_consensus_params(consensus_params);
    let required_signatures = required_signatures_from_redeem_script(&params.redeem_script)?;
    let signature_script_template = signature_script_template(&params.redeem_script, required_signatures)?;
    let storm_param = consensus_params.storage_mass_parameter;

    // Deterministic UTXO ordering.
    //
    // We sort by amount (asc) to avoid selecting a single very-large input for small withdrawals.
    // For KIP-0009 storage mass, extremely large inputs can make `C / mean(input)` become 0
    // due to integer division, which can push storage mass above the standardness limit.
    //
    // Tie-break by outpoint (txid, index) for determinism.
    utxos.sort_by(|a, b| {
        a.entry
            .amount
            .cmp(&b.entry.amount)
            .then(a.outpoint.transaction_id.as_bytes().cmp(&b.outpoint.transaction_id.as_bytes()))
            .then(a.outpoint.index.cmp(&b.outpoint.index))
    });

    let calc_storage_mass_for_candidate = |inputs: &[UtxoInput], outputs: &[MultisigOutput]| -> Option<u64> {
        let input_cells: Vec<UtxoCell> = inputs.iter().map(|input| UtxoCell::from(&input.entry)).collect();
        let output_cells: Vec<UtxoCell> = outputs
            .iter()
            .map(|output| {
                let consensus_output = TransactionOutput { value: output.amount, script_public_key: output.script_public_key.clone() };
                UtxoCell::from(&consensus_output)
            })
            .collect();

        // NOTE: storage mass depends on the network's `storage_mass_parameter` (KIP-0009).
        // For current Kaspa networks this is uniform, but we use the params-derived value to avoid drifting.
        calc_storage_mass(false, input_cells.iter().copied(), output_cells.into_iter(), storm_param)
    };

    // Deterministically select the smallest prefix of UTXOs that satisfies:
    // 1) outputs+fee policy, and
    // 2) standardness storage-mass bound (MAXIMUM_STANDARD_TRANSACTION_MASS).
    let mut selected = Vec::new();
    let mut total_input = 0u64;
    let mut outputs: Option<Vec<MultisigOutput>> = None;
    let mut last_storage_mass: Option<u64> = None;

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
        match apply_fee_policy_with_auto_fee(params, &mass_calc, &selected, total_input, &base_outputs, &signature_script_template, &mut candidate_outputs) {
            Ok(()) => {
                let storage_mass = calc_storage_mass_for_candidate(&selected, &candidate_outputs)
                    .ok_or_else(|| ThresholdError::PsktValidationFailed("failed to compute transaction storage mass".to_string()))?;
                last_storage_mass = Some(storage_mass);

                if storage_mass > MAXIMUM_STANDARD_TRANSACTION_MASS {
                    continue;
                }

                outputs = Some(candidate_outputs);
                break;
            }
            Err(ThresholdError::InsufficientUTXOs) => continue,
            Err(err) => return Err(err),
        }
    }

    let outputs = match outputs {
        Some(outputs) => outputs,
        None => {
            if let Some(storage_mass) = last_storage_mass {
                return Err(ThresholdError::PsktValidationFailed(format!(
                    "transaction storage mass {storage_mass} exceeds standard limit {MAXIMUM_STANDARD_TRANSACTION_MASS} (KIP-0009); \
                     try increasing the withdrawal amount or funding the multisig with smaller UTXOs"
                )));
            }
            return Err(ThresholdError::InsufficientUTXOs);
        }
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

fn consensus_params_for_pskt(params: &PsktParams) -> Result<&'static kaspa_consensus_core::config::params::Params, ThresholdError> {
    let addr = params
        .source_addresses
        .first()
        .or_else(|| params.outputs.first().map(|o| &o.address))
        .ok_or_else(|| ThresholdError::PsktValidationFailed("missing source_addresses for PSKT".to_string()))?;

    let address = Address::constructor(addr);
    let out = match address.prefix {
        Prefix::Mainnet => &MAINNET_PARAMS,
        Prefix::Devnet => &DEVNET_PARAMS,
        Prefix::Simnet => &SIMNET_PARAMS,
        Prefix::Testnet => &TESTNET_PARAMS,
        #[cfg(test)]
        Prefix::A | Prefix::B => &DEVNET_PARAMS,
    };
    Ok(out)
}

fn required_signatures_from_redeem_script(redeem_script: &[u8]) -> Result<usize, ThresholdError> {
    fn decode_small_int(op: u8) -> Option<usize> {
        match op {
            0x00 => Some(0),
            0x51..=0x60 => Some((op - 0x50) as usize),
            _ => None,
        }
    }

    let m = redeem_script
        .first()
        .and_then(|b| decode_small_int(*b))
        .ok_or_else(|| ThresholdError::PsktValidationFailed("invalid redeem script: missing threshold opcode".to_string()))?;

    if m == 0 {
        return Err(ThresholdError::PsktValidationFailed("invalid redeem script: threshold m must be > 0".to_string()));
    }
    Ok(m)
}

fn signature_script_template(redeem_script: &[u8], required_signatures: usize) -> Result<Vec<u8>, ThresholdError> {
    // Mirror the layout in `pskt::multisig::finalize_multisig()`:
    //   [sig1][sig2]...[sigM] [push(redeem_script)]
    // Each signature push is 66 bytes: OP_DATA_65 + 64 sig bytes + 1 sighash byte.
    let mut signatures = Vec::with_capacity(required_signatures.saturating_mul(66));
    for _ in 0..required_signatures {
        signatures.push(OpData65);
        signatures.extend([0u8; 64]);
        signatures.push(SIG_HASH_ALL.to_u8());
    }

    let redeem_push = ScriptBuilder::new()
        .add_data(redeem_script)
        .map_err(|err| ThresholdError::Message(err.to_string()))?
        .drain();

    let mut out = signatures;
    out.extend(redeem_push);
    Ok(out)
}

fn minimum_relay_fee_sompi_for_compute_mass(compute_mass: u64) -> u64 {
    // Match kaspad default: DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE = 1000 sompi/kg.
    // See `mining/src/mempool/config.rs` and `mempool::check_transaction_standard`.
    const MIN_RELAY_FEE_SOMPI_PER_KG: u64 = 1000;
    let mut minimum_fee = (compute_mass.saturating_mul(MIN_RELAY_FEE_SOMPI_PER_KG)) / 1000;
    if minimum_fee == 0 {
        minimum_fee = MIN_RELAY_FEE_SOMPI_PER_KG;
    }
    minimum_fee
}

fn estimate_compute_mass_for_signed_tx(
    mass_calc: &MassCalculator,
    inputs: &[UtxoInput],
    outputs: &[MultisigOutput],
    sig_op_count: u8,
    signature_script_template: &[u8],
) -> u64 {
    let tx = Transaction::new(
        0,
        inputs
            .iter()
            .map(|utxo| TransactionInput {
                previous_outpoint: utxo.outpoint,
                signature_script: signature_script_template.to_vec(),
                sequence: u64::MAX,
                sig_op_count,
            })
            .collect(),
        outputs
            .iter()
            .map(|out| TransactionOutput { value: out.amount, script_public_key: out.script_public_key.clone() })
            .collect(),
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    mass_calc.calc_non_contextual_masses(&tx).compute_mass
}

fn apply_fee_policy_with_auto_fee(
    params: &PsktParams,
    mass_calc: &MassCalculator,
    selected_inputs: &[UtxoInput],
    total_input: u64,
    base_outputs: &[MultisigOutput],
    signature_script_template: &[u8],
    outputs: &mut Vec<MultisigOutput>,
) -> Result<(), ThresholdError> {
    // Treat `None` *and* `0` as "auto" during stabilization to avoid mempool rejects.
    // If a caller needs explicit 0-fee behavior, they should do so against a node configured to allow it.
    let mut fee = params.fee_sompi.unwrap_or(0);
    if fee == 0 {
        // Fixed-point iteration: fee affects change output which affects compute mass which affects fee.
        // A small bounded loop keeps this deterministic and robust.
        let mut last_fee = 0u64;
        for _ in 0..4 {
            outputs.clear();
            outputs.extend_from_slice(base_outputs);

            apply_fee_policy_for_fee(params, total_input, outputs, fee)?;

            let compute_mass = estimate_compute_mass_for_signed_tx(
                mass_calc,
                selected_inputs,
                outputs,
                params.sig_op_count,
                signature_script_template,
            );
            let min_fee = minimum_relay_fee_sompi_for_compute_mass(compute_mass);
            if min_fee == fee || min_fee == last_fee {
                fee = min_fee;
                break;
            }
            last_fee = fee;
            fee = min_fee;
        }

        outputs.clear();
        outputs.extend_from_slice(base_outputs);
        apply_fee_policy_for_fee(params, total_input, outputs, fee)?;
        return Ok(());
    }

    apply_fee_policy_for_fee(params, total_input, outputs, fee)
}

struct FeeConfig {
    recipient_fee: u64,
}

impl FeeConfig {
    fn from_mode(fee: u64, mode: &FeePaymentMode) -> Result<Self, ThresholdError> {
        let recipient_fee = match mode {
            FeePaymentMode::RecipientPays => fee,
            FeePaymentMode::SignersPay => 0,
            FeePaymentMode::Split { recipient_parts, signer_parts } => {
                let total_parts = recipient_parts.saturating_add(*signer_parts);
                if total_parts == 0 {
                    return Err(ThresholdError::Message("fee split parts must not both be zero".to_string()));
                }
                fee.checked_mul(*recipient_parts as u64)
                    .and_then(|v| v.checked_div(total_parts as u64))
                    .ok_or_else(|| ThresholdError::Message("fee split overflow".to_string()))?
            }
        };

        Ok(FeeConfig { recipient_fee })
    }
}

fn apply_fee_policy_for_fee(params: &PsktParams, total_input: u64, outputs: &mut Vec<MultisigOutput>, fee: u64) -> Result<(), ThresholdError> {
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
    // Network fee is always paid via input-output delta.
    let required = total_output.saturating_add(fee);
    if total_input < required {
        return Err(ThresholdError::InsufficientUTXOs);
    }

    let change = total_input - required;
    if change > 0 {
        if let Some(address) = params.change_address.as_ref() {
            let addr = Address::constructor(address);
            outputs.push(MultisigOutput { amount: change, script_public_key: pay_to_address_script(&addr) });
        } else {
            // Avoid implicitly overpaying large fees when change is expected.
            return Err(ThresholdError::PsktValidationFailed("missing change_address".to_string()));
        }
    }
    Ok(())
}
