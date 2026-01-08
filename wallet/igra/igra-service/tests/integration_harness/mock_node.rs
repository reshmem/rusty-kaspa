use igra_core::error::ThresholdError;
use igra_core::rpc::{NodeRpc, UtxoWithOutpoint};
use kaspa_consensus_core::tx::{Transaction, TransactionId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub struct MockKaspaNode {
    utxos: Mutex<Vec<UtxoWithOutpoint>>,
    submitted: Mutex<Vec<Transaction>>,
    blue_score: AtomicU64,
}

#[allow(dead_code)]
impl MockKaspaNode {
    pub fn new() -> Self {
        Self { utxos: Mutex::new(Vec::new()), submitted: Mutex::new(Vec::new()), blue_score: AtomicU64::new(0) }
    }

    pub fn add_utxo(&self, utxo: UtxoWithOutpoint) {
        if let Ok(mut entries) = self.utxos.lock() {
            entries.push(utxo);
        }
    }

    pub fn set_blue_score(&self, score: u64) {
        self.blue_score.store(score, Ordering::Relaxed);
    }

    pub fn submitted_transactions(&self) -> Vec<Transaction> {
        self.submitted.lock().map(|txs| txs.clone()).unwrap_or_default()
    }

    pub fn assert_transaction_submitted(&self, tx_id: &TransactionId) {
        let submitted = self.submitted_transactions();
        let found = submitted.iter().any(|tx| &tx.id() == tx_id);
        assert!(found, "expected transaction {} to be submitted", hex::encode(tx_id));
    }
}

impl Default for MockKaspaNode {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NodeRpc for MockKaspaNode {
    async fn get_utxos_by_addresses(
        &self,
        addresses: &[kaspa_wallet_core::prelude::Address],
    ) -> Result<Vec<UtxoWithOutpoint>, ThresholdError> {
        let entries = self.utxos.lock().map_err(|_| ThresholdError::Message("utxo store lock poisoned".to_string()))?;
        if addresses.is_empty() {
            return Ok(entries.clone());
        }
        let filtered = entries
            .iter()
            .filter(|utxo| utxo.address.as_ref().map(|addr| addresses.contains(addr)).unwrap_or(true))
            .cloned()
            .collect::<Vec<_>>();
        Ok(filtered)
    }

    async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId, ThresholdError> {
        let mut tx = tx;
        tx.finalize();
        let tx_id = tx.id();
        if let Ok(mut submitted) = self.submitted.lock() {
            submitted.push(tx);
        }
        Ok(tx_id)
    }

    async fn get_virtual_selected_parent_blue_score(&self) -> Result<u64, ThresholdError> {
        Ok(self.blue_score.load(Ordering::Relaxed))
    }
}
