use crate::domain::FeePaymentMode;
use crate::foundation::Hash32;
use kaspa_consensus_core::tx::{TransactionOutpoint, UtxoEntry};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Deterministic seed for UTXO selection ordering.
    ///
    /// This is used to avoid pathological UTXO reuse across different events with identical
    /// output parameters, while remaining deterministic across signers.
    pub selection_seed: Option<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoInput {
    pub outpoint: TransactionOutpoint,
    pub entry: UtxoEntry,
}
