use igra_core::domain::hashes::event_hash_without_signature;
use igra_core::domain::SigningEvent;
use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::rpc::{NodeRpc, UtxoWithOutpoint};
use kaspa_consensus_core::tx::{Transaction, TransactionId};
use secp256k1::{ecdsa::Signature as SecpSignature, Message, PublicKey, Secp256k1, SecretKey};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub struct MockKaspaNode {
    utxos: Mutex<Vec<UtxoWithOutpoint>>,
    submitted: Mutex<Vec<Transaction>>,
    blue_score: AtomicU64,
}

impl MockKaspaNode {
    pub fn new() -> Self {
        Self { utxos: Mutex::new(Vec::new()), submitted: Mutex::new(Vec::new()), blue_score: AtomicU64::new(0) }
    }

    pub fn add_utxo(&self, utxo: UtxoWithOutpoint) {
        if let Ok(mut entries) = self.utxos.lock() {
            entries.push(utxo);
        }
    }

    #[allow(dead_code)]
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
    async fn get_utxos_by_addresses(&self, addresses: &[kaspa_wallet_core::prelude::Address]) -> Result<Vec<UtxoWithOutpoint>, ThresholdError> {
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

#[derive(Clone)]
pub struct HyperlaneValidator {
    #[allow(dead_code)]
    pub address: String,
    pub private_key: SecretKey,
}

pub struct MockHyperlaneValidator {
    validators: Vec<HyperlaneValidator>,
    threshold: usize,
}

impl MockHyperlaneValidator {
    pub fn new(num_validators: usize, threshold: usize) -> Self {
        let mut validators = Vec::new();
        for idx in 0..num_validators {
            let key = SecretKey::from_slice(&[idx as u8 + 1; 32]).expect("validator key");
            validators.push(HyperlaneValidator { address: format!("validator-{}", idx + 1), private_key: key });
        }
        Self { validators, threshold }
    }

    pub fn get_validator_pubkeys(&self) -> Vec<PublicKey> {
        let secp = Secp256k1::new();
        self.validators.iter().map(|validator| PublicKey::from_secret_key(&secp, &validator.private_key)).collect()
    }

    pub fn sign_event_bytes(&self, event: &SigningEvent, signers: &[usize]) -> Result<Vec<u8>, ThresholdError> {
        let hash = event_hash_without_signature(event)?;
        let message = Message::from_digest_slice(&hash).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let secp = Secp256k1::new();
        let mut out = Vec::new();
        for index in signers {
            let validator =
                self.validators.get(*index).ok_or_else(|| ThresholdError::Message("validator index out of range".to_string()))?;
            let sig: SecpSignature = secp.sign_ecdsa(&message, &validator.private_key);
            out.extend_from_slice(&sig.serialize_compact());
        }
        Ok(out)
    }

    pub fn sign_with_quorum(&self, event: &SigningEvent) -> Result<Vec<u8>, ThresholdError> {
        let signers = (0..self.threshold).collect::<Vec<_>>();
        self.sign_event_bytes(event, &signers)
    }
}
