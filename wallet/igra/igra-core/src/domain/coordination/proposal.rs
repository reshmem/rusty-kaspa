use crate::domain::coordination::config::{MAX_KPSBT_SIZE, MAX_OUTPUTS_PER_PROPOSAL, MAX_UTXOS_PER_PROPOSAL};
use crate::domain::pskt::params::{PsktOutputParams, UtxoInput};
use crate::domain::CrdtSigningMaterial;
use crate::foundation::{EventId, PeerId, ThresholdError, TxTemplateHash};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub event_id: EventId,
    pub round: u32,
    pub tx_template_hash: TxTemplateHash,
    pub kpsbt_blob: Vec<u8>,
    pub utxos_used: Vec<UtxoInput>,
    pub outputs: Vec<PsktOutputParams>,
    pub signing_material: CrdtSigningMaterial,
    pub proposer_peer_id: PeerId,
    pub timestamp_ns: u64,
}

pub type ProposalBroadcast = Proposal;

#[derive(Debug, thiserror::Error)]
pub enum ProposalValidationError {
    #[error("KPSBT too large: {size} > {max}")]
    KpsbtTooLarge { size: usize, max: usize },
    #[error("too many UTXOs: {count} > {max}")]
    TooManyUtxos { count: usize, max: usize },
    #[error("too many outputs: {count} > {max}")]
    TooManyOutputs { count: usize, max: usize },
    #[error("missing UTXOs")]
    NoUtxos,
    #[error("missing outputs")]
    NoOutputs,
    #[error("tx_template_hash mismatch")]
    HashMismatch,
}

impl Proposal {
    pub fn validate_structure(&self) -> Result<(), ProposalValidationError> {
        if self.kpsbt_blob.len() > MAX_KPSBT_SIZE {
            return Err(ProposalValidationError::KpsbtTooLarge { size: self.kpsbt_blob.len(), max: MAX_KPSBT_SIZE });
        }
        if self.utxos_used.len() > MAX_UTXOS_PER_PROPOSAL {
            return Err(ProposalValidationError::TooManyUtxos { count: self.utxos_used.len(), max: MAX_UTXOS_PER_PROPOSAL });
        }
        if self.outputs.len() > MAX_OUTPUTS_PER_PROPOSAL {
            return Err(ProposalValidationError::TooManyOutputs { count: self.outputs.len(), max: MAX_OUTPUTS_PER_PROPOSAL });
        }
        if self.utxos_used.is_empty() {
            return Err(ProposalValidationError::NoUtxos);
        }
        if self.outputs.is_empty() {
            return Err(ProposalValidationError::NoOutputs);
        }
        Ok(())
    }

    pub fn computed_template_hash(&self) -> Result<TxTemplateHash, ThresholdError> {
        let pskt = crate::domain::pskt::multisig::deserialize_pskt_signer(&self.kpsbt_blob)?;
        crate::domain::pskt::multisig::tx_template_hash(&pskt)
    }

    pub fn verify_hash_consistency(&self) -> Result<(), ProposalValidationError> {
        let computed = self.computed_template_hash().map_err(|_| ProposalValidationError::HashMismatch)?;
        if computed != self.tx_template_hash {
            return Err(ProposalValidationError::HashMismatch);
        }
        Ok(())
    }
}
