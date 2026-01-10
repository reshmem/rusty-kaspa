//! Rich result types for PSKT operations (no logging in domain).

use kaspa_consensus_core::tx::Transaction;
use kaspa_wallet_pskt::prelude::{Finalizer, Signer, Updater, PSKT};

#[derive(Clone)]
pub struct PsktBuildResult {
    pub input_count: usize,
    pub output_count: usize,
    pub total_input_amount: u64,
    pub total_output_amount: u64,
    pub pskt: PSKT<Updater>,
}

#[derive(Clone)]
pub struct PsktSignResult {
    pub input_count: usize,
    pub signatures_added: usize,
    pub pskt: PSKT<Signer>,
}

#[derive(Clone)]
pub struct PsktFinalizeResult {
    pub input_count: usize,
    pub signatures_per_input: Vec<usize>,
    pub required_signatures: usize,
    pub pskt: PSKT<Finalizer>,
}

#[derive(Debug, Clone)]
pub struct TransactionExtractionResult {
    pub tx_id: [u8; 32],
    pub input_count: usize,
    pub output_count: usize,
    pub mass: u64,
    pub tx: Transaction,
}

#[derive(Debug, Clone)]
pub struct UtxoSelectionResult {
    pub selected_utxos: usize,
    pub total_input_amount: u64,
    pub total_output_amount: u64,
    pub fee_amount: u64,
    pub change_amount: u64,
    pub has_change_output: bool,
}

impl std::fmt::Debug for PsktBuildResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsktBuildResult")
            .field("input_count", &self.input_count)
            .field("output_count", &self.output_count)
            .field("total_input_amount", &self.total_input_amount)
            .field("total_output_amount", &self.total_output_amount)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PsktSignResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsktSignResult")
            .field("input_count", &self.input_count)
            .field("signatures_added", &self.signatures_added)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PsktFinalizeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsktFinalizeResult")
            .field("input_count", &self.input_count)
            .field("signatures_per_input", &self.signatures_per_input)
            .field("required_signatures", &self.required_signatures)
            .finish_non_exhaustive()
    }
}
