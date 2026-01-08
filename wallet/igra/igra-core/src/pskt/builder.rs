use crate::config::{PsktBuildConfig, PsktOutput};
use crate::error::ThresholdError;
use crate::model::FeePaymentMode;
use crate::pskt::multisig::{build_pskt, MultisigInput, MultisigOutput};
use crate::rpc::grpc::GrpcNodeRpc;
use crate::rpc::NodeRpc;
use kaspa_addresses::Address;
use kaspa_txscript::pay_to_address_script;
use tracing::info;

pub async fn build_pskt_via_rpc(
    config: &PsktBuildConfig,
) -> Result<kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Updater>, ThresholdError> {
    let rpc = GrpcNodeRpc::connect(config.node_rpc_url.clone()).await?;
    build_pskt_with_client(&rpc, config).await
}

pub async fn build_pskt_with_client(
    rpc: &dyn NodeRpc,
    config: &PsktBuildConfig,
) -> Result<kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Updater>, ThresholdError> {
    let addresses = config.source_addresses.iter().map(|addr| Address::constructor(addr)).collect::<Vec<_>>();

    let mut outputs = config
        .outputs
        .iter()
        .map(|PsktOutput { address, amount_sompi }| {
            let addr = Address::constructor(address);
            MultisigOutput { amount: *amount_sompi, script_public_key: pay_to_address_script(&addr) }
        })
        .collect::<Vec<_>>();

    let redeem_script = hex::decode(&config.redeem_script_hex)?;

    let mut utxos = rpc.get_utxos_by_addresses(&addresses).await?;
    let total_input = utxos.iter().map(|utxo| utxo.entry.amount).sum::<u64>();
    info!("pskt builder: fetched {} utxos totaling {} sompi for {:?}", utxos.len(), total_input, addresses);

    // Sort UTXOs deterministically to ensure all nodes build identical transactions
    // Primary sort: by transaction_id (lexicographic)
    // Secondary sort: by output_index (numeric)
    utxos.sort_by(|a, b| {
        a.outpoint.transaction_id.as_bytes().cmp(&b.outpoint.transaction_id.as_bytes()).then(a.outpoint.index.cmp(&b.outpoint.index))
    });

    apply_fee_policy(config, total_input, &mut outputs)?;

    let inputs = utxos
        .into_iter()
        .map(|utxo| MultisigInput {
            utxo_entry: utxo.entry,
            previous_outpoint: utxo.outpoint,
            redeem_script: redeem_script.clone(),
            sig_op_count: config.sig_op_count,
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

        if recipient_fee + signer_fee != fee {
            return Err(ThresholdError::Message("fee split does not sum to total".to_string()));
        }

        Ok(FeeConfig { recipient_fee, signer_fee })
    }
}

fn apply_fee_policy(config: &PsktBuildConfig, total_input: u64, outputs: &mut Vec<MultisigOutput>) -> Result<(), ThresholdError> {
    let fee = config.fee_sompi.unwrap_or(0);
    if fee == 0 {
        return Ok(());
    }
    if outputs.is_empty() {
        return Err(ThresholdError::Message("missing outputs for fee calculation".to_string()));
    }

    let fee_cfg = FeeConfig::from_mode(fee, &config.fee_payment_mode)?;

    if fee_cfg.recipient_fee > 0 {
        let first = outputs.first_mut().ok_or_else(|| ThresholdError::Message("missing recipient output".to_string()))?;
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
        let address = config.change_address.as_ref().ok_or_else(|| ThresholdError::Message("missing change_address".to_string()))?;
        let addr = Address::constructor(address);
        outputs.push(MultisigOutput { amount: change, script_public_key: pay_to_address_script(&addr) });
    }
    Ok(())
}
