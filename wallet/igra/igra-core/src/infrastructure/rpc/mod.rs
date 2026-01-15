use crate::foundation::ThresholdError;
use async_trait::async_trait;
use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{Transaction, TransactionId, TransactionOutpoint, UtxoEntry};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct UtxoWithOutpoint {
    pub address: Option<Address>,
    pub outpoint: TransactionOutpoint,
    pub entry: UtxoEntry,
}

#[async_trait]
pub trait NodeRpc: Send + Sync {
    async fn get_utxos_by_addresses(&self, addresses: &[Address]) -> Result<Vec<UtxoWithOutpoint>, ThresholdError>;
    async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId, ThresholdError>;
    async fn get_virtual_selected_parent_blue_score(&self) -> Result<u64, ThresholdError>;
}

pub struct UnimplementedRpc {
    utxos: Mutex<Vec<UtxoWithOutpoint>>,
    submitted: Mutex<Vec<Transaction>>,
    blue_score: AtomicU64,
}

impl UnimplementedRpc {
    pub fn new() -> Self {
        Self { utxos: Mutex::new(Vec::new()), submitted: Mutex::new(Vec::new()), blue_score: AtomicU64::new(0) }
    }

    pub fn with_utxos(utxos: Vec<UtxoWithOutpoint>) -> Self {
        Self { utxos: Mutex::new(utxos), submitted: Mutex::new(Vec::new()), blue_score: AtomicU64::new(0) }
    }

    pub fn push_utxo(&self, utxo: UtxoWithOutpoint) {
        if let Ok(mut entries) = self.utxos.lock() {
            entries.push(utxo);
        }
    }

    pub fn submitted_transactions(&self) -> Vec<Transaction> {
        self.submitted.lock().map(|txs| txs.clone()).unwrap_or_default()
    }

    pub fn set_blue_score(&self, score: u64) {
        self.blue_score.store(score, Ordering::Relaxed);
    }
}

impl Default for UnimplementedRpc {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NodeRpc for UnimplementedRpc {
    async fn get_utxos_by_addresses(&self, _addresses: &[Address]) -> Result<Vec<UtxoWithOutpoint>, ThresholdError> {
        let addresses = _addresses;
        let entries = self.utxos.lock().map_err(|_| ThresholdError::StorageError {
            operation: "unimplemented_rpc utxo store lock".to_string(),
            details: "poisoned".to_string(),
        })?;
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

    async fn submit_transaction(&self, _tx: Transaction) -> Result<TransactionId, ThresholdError> {
        let mut tx = _tx;
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

pub mod circuit_breaker;
pub mod grpc;
pub mod kaspa_integration;
pub mod retry;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
pub use grpc::GrpcNodeRpc;
pub use kaspa_integration::*;
pub use retry::retry;
