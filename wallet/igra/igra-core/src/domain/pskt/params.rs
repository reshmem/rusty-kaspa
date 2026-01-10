use crate::domain::FeePaymentMode;
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};

#[derive(Clone, Debug)]
pub struct PsktOutputParams {
    pub address: String,
    pub amount_sompi: u64,
}

#[derive(Clone, Debug)]
pub struct PsktParams {
    pub source_addresses: Vec<String>,
    pub outputs: Vec<PsktOutputParams>,
    pub redeem_script: Vec<u8>,
    pub sig_op_count: u8,
    pub fee_payment_mode: FeePaymentMode,
    pub fee_sompi: Option<u64>,
    pub change_address: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UtxoInput {
    pub outpoint: TransactionOutpoint,
    pub entry: UtxoEntry,
}
