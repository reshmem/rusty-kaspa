use blake3::Hasher;
use hyperlane_core::accumulator::merkle::Proof as HyperlaneMerkleProof;
use hyperlane_core::Signable;
use hyperlane_core::{CheckpointWithMessageId, HyperlaneMessage, Signature, H256};
use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::{HyperlaneConfig, HyperlaneDomainConfig, HyperlaneIsmMode};
use crate::error::ThresholdError;

/// ISM verification mode.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsmMode {
    MessageIdMultisig,
    MerkleRootMultisig,
}

impl Default for IsmMode {
    fn default() -> Self {
        IsmMode::MessageIdMultisig
    }
}

/// Per-domain validator set and quorum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub domain: u32,
    pub validators: Vec<secp256k1::PublicKey>,
    pub threshold: u8,
    pub mode: IsmMode,
}

impl ValidatorSet {
    pub fn config_hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.domain.to_be_bytes());
        hasher.update(&[self.threshold]);
        hasher.update(match self.mode {
            IsmMode::MessageIdMultisig => &[0u8],
            IsmMode::MerkleRootMultisig => &[1u8],
        });
        for pk in &self.validators {
            hasher.update(&pk.serialize());
        }
        *hasher.finalize().as_bytes()
    }
}

/// Proof metadata passed alongside a message for verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    pub checkpoint: CheckpointWithMessageId,
    pub merkle_proof: Option<HyperlaneMerkleProof>,
    pub signatures: Vec<Signature>, // validators’ recoverable signatures (65-byte form)
}

/// Result of verifying a proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofReport {
    pub message_id: H256,
    pub root: H256,
    pub quorum: usize,
    pub validators_used: Vec<secp256k1::PublicKey>,
}

/// Trait for an ISM-like verifier implementation.
pub trait IsmVerifier {
    fn validators_and_threshold(&self, domain: u32, message_id: H256) -> Option<ValidatorSet>;
    fn verify_proof(&self, message: &HyperlaneMessage, metadata: &ProofMetadata, mode: IsmMode) -> Result<ProofReport, String>;
}

/// Static, config-backed ISM verifier.
#[derive(Clone)]
pub struct ConfiguredIsm {
    domains: HashMap<u32, ValidatorSet>,
}

impl ConfiguredIsm {
    pub fn from_config(config: &HyperlaneConfig) -> Result<Self, ThresholdError> {
        if config.domains.is_empty() {
            return Err(ThresholdError::ConfigError("hyperlane.domains is required for ISM verification".to_string()));
        }
        let mut domains = HashMap::new();
        for domain_cfg in &config.domains {
            let set = Self::build_set(domain_cfg)?;
            domains.insert(set.domain, set);
        }
        Ok(Self { domains })
    }

    fn build_set(cfg: &HyperlaneDomainConfig) -> Result<ValidatorSet, ThresholdError> {
        let mut validators = Vec::new();
        for val in &cfg.validators {
            validators.push(parse_pubkey(val)?);
        }
        if validators.is_empty() {
            return Err(ThresholdError::ConfigError(format!("hyperlane domain {} has no validators", cfg.domain)));
        }
        let threshold = if cfg.threshold == 0 { validators.len() as u8 } else { cfg.threshold };
        if threshold as usize > validators.len() {
            return Err(ThresholdError::ConfigError(format!(
                "hyperlane domain {} threshold {} exceeds validator count {}",
                cfg.domain,
                threshold,
                validators.len()
            )));
        }
        let mode = match cfg.mode {
            HyperlaneIsmMode::MessageIdMultisig => IsmMode::MessageIdMultisig,
            HyperlaneIsmMode::MerkleRootMultisig => IsmMode::MerkleRootMultisig,
        };
        Ok(ValidatorSet { domain: cfg.domain, validators, threshold, mode })
    }
}

impl IsmVerifier for ConfiguredIsm {
    fn validators_and_threshold(&self, domain: u32, _message_id: H256) -> Option<ValidatorSet> {
        self.domains.get(&domain).cloned()
    }

    fn verify_proof(&self, message: &HyperlaneMessage, metadata: &ProofMetadata, mode: IsmMode) -> Result<ProofReport, String> {
        let set = self.domains.get(&message.destination).ok_or_else(|| "unknown destination domain".to_string())?;

        if set.mode != mode {
            return Err("mode mismatch with configured ISM".to_string());
        }

        // Basic domain sanity check
        if metadata.checkpoint.mailbox_domain != message.origin {
            return Err("checkpoint mailbox_domain mismatch origin".to_string());
        }

        let message_id = message.id();
        if metadata.checkpoint.message_id != message_id {
            return Err("message_id mismatch".to_string());
        }

        // Merkle proof (if required)
        if matches!(mode, IsmMode::MerkleRootMultisig) {
            let proof = metadata.merkle_proof.as_ref().ok_or_else(|| "merkle_proof required for merkle_root_multisig".to_string())?;
            if proof.leaf != message_id {
                return Err("merkle proof leaf != message_id".to_string());
            }
            let depth = proof.path.len();
            if proof.index != metadata.checkpoint.index as usize {
                return Err("merkle proof index mismatch checkpoint index".to_string());
            }
            if !hyperlane_core::accumulator::merkle::verify_merkle_proof(
                proof.leaf,
                &proof.path,
                depth,
                proof.index,
                metadata.checkpoint.root,
            ) {
                return Err("merkle proof invalid".to_string());
            }
        }

        // Signature verification over checkpoint signing_hash
        let signing_hash = metadata.checkpoint.signing_hash();
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest_slice(signing_hash.as_ref()).map_err(|e| format!("invalid signing hash: {e}"))?;

        let configured: Vec<PublicKey> = set.validators.clone();
        let mut matched = Vec::new();

        for sig in &metadata.signatures {
            if let Ok(pk) = recover_validator(&secp, sig, &msg) {
                if configured.iter().any(|v| v == &pk) && !matched.contains(&pk) {
                    matched.push(pk);
                    if matched.len() >= set.threshold as usize {
                        break;
                    }
                }
            }
        }

        if matched.len() < set.threshold as usize {
            return Err("insufficient quorum".to_string());
        }

        Ok(ProofReport { message_id, root: metadata.checkpoint.root, quorum: matched.len(), validators_used: matched })
    }
}

fn parse_pubkey(hex_str: &str) -> Result<PublicKey, ThresholdError> {
    let stripped = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(stripped).map_err(|_| ThresholdError::ConfigError("invalid hyperlane validator hex".to_string()))?;
    PublicKey::from_slice(&bytes).map_err(|_| ThresholdError::ConfigError("invalid hyperlane validator key".to_string()))
}

fn recover_validator(secp: &Secp256k1<secp256k1::VerifyOnly>, sig: &Signature, msg: &Message) -> Result<PublicKey, String> {
    let sig_bytes: [u8; 65] = sig.into();
    let rec_id_raw = sig_bytes[64];
    let rec_id = match rec_id_raw {
        27 | 28 => rec_id_raw - 27,
        0 | 1 => rec_id_raw,
        _ => return Err("invalid recovery id".to_string()),
    };
    let rid = secp256k1::ecdsa::RecoveryId::from_i32(rec_id as i32).map_err(|e| format!("recovery id: {e}"))?;
    let rec_sig = RecoverableSignature::from_compact(&sig_bytes[0..64], rid).map_err(|e| format!("signature parse: {e}"))?;
    secp.recover_ecdsa(msg, &rec_sig).map_err(|e| format!("recover: {e}"))
}
