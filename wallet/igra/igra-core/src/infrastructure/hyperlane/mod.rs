//! Hyperlane integration primitives.
//!
//! This module provides the types and helpers needed to:
//! - Parse and validate Hyperlane metadata accompanying a message (`ProofMetadata`).
//! - Verify ISM signatures for supported modes (currently `message_id_multisig` and
//!   `merkle_root_multisig`).
//! - Provide stable configuration and hashing (`ValidatorSet::config_hash`) for relayer queries.

use blake3::Hasher;
use hyperlane_core::accumulator::merkle::Proof as HyperlaneMerkleProof;
use hyperlane_core::Signable;
use hyperlane_core::{CheckpointWithMessageId, HyperlaneMessage, Signature, H256};
use once_cell::sync::Lazy;
use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::foundation::parse_hex_fixed;
use crate::foundation::ThresholdError;
use crate::infrastructure::config::{HyperlaneConfig, HyperlaneDomainConfig, HyperlaneIsmMode};

pub mod ism_client;
pub mod metadata_bytes;
pub mod types;

pub use metadata_bytes::{decode_proof_metadata_bytes, decode_proof_metadata_hex};

/// ISM verification mode.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsmMode {
    #[default]
    MessageIdMultisig,
    MerkleRootMultisig,
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

    pub fn default_mode(&self) -> Option<IsmMode> {
        self.domains.values().next().map(|set| set.mode.clone())
    }

    fn build_set(cfg: &HyperlaneDomainConfig) -> Result<ValidatorSet, ThresholdError> {
        let mut validators = Vec::new();
        for val in &cfg.validators {
            validators.push(parse_pubkey(val)?);
        }
        if validators.is_empty() {
            return Err(ThresholdError::ConfigError(format!("hyperlane domain {} has no validators", cfg.domain)));
        }
        if cfg.threshold == 0 {
            return Err(ThresholdError::ConfigError(format!("hyperlane domain {} requires non-zero threshold", cfg.domain)));
        }
        let threshold = cfg.threshold;
        if usize::from(threshold) > validators.len() {
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
        let set = self.domains.get(&message.origin).ok_or_else(|| "unknown origin domain".to_string())?;

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
            let checkpoint_index: usize =
                metadata.checkpoint.index.try_into().map_err(|_| "checkpoint index too large".to_string())?;
            if proof.index > checkpoint_index {
                return Err("merkle proof index beyond checkpoint index".to_string());
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

        // Signature verification over the EIP-191 compliant hash.
        // Hyperlane validators sign `eth_signed_message_hash()` (not the raw `signing_hash()`).
        let signing_hash = metadata.checkpoint.eth_signed_message_hash();
        static SECP: Lazy<Secp256k1<secp256k1::VerifyOnly>> = Lazy::new(Secp256k1::verification_only);
        let msg = Message::from_digest_slice(signing_hash.as_ref()).map_err(|e| format!("invalid signing hash: {e}"))?;

        let configured: Vec<PublicKey> = set.validators.clone();
        let mut matched = Vec::new();

        for sig in &metadata.signatures {
            if let Ok(pk) = recover_validator(&SECP, sig, &msg) {
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
    let bytes = parse_hex_fixed::<33>(hex_str)
        .map_err(|err| ThresholdError::InvalidPublicKey { input: hex_str.to_string(), reason: err.to_string() })?;
    PublicKey::from_slice(&bytes)
        .map_err(|err| ThresholdError::InvalidPublicKey { input: hex_str.to_string(), reason: format!("secp256k1 error: {err}") })
}

fn recover_validator(secp: &Secp256k1<secp256k1::VerifyOnly>, sig: &Signature, msg: &Message) -> Result<PublicKey, String> {
    let sig_bytes: [u8; 65] = sig.into();
    let rec_id_raw = sig_bytes[64];
    let rec_id = match rec_id_raw {
        27 | 28 => rec_id_raw - 27,
        0 | 1 => rec_id_raw,
        v => return Err(format!("invalid recovery id: {} (expected 0, 1, 27, or 28)", v)),
    };
    let rid_i32: i32 = rec_id.into();
    let rid = secp256k1::ecdsa::RecoveryId::from_i32(rid_i32).map_err(|e| format!("recovery id: {e}"))?;
    let rec_sig = RecoverableSignature::from_compact(&sig_bytes[0..64], rid).map_err(|e| format!("signature parse: {e}"))?;
    secp.recover_ecdsa(msg, &rec_sig).map_err(|e| format!("recover: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperlane_core::accumulator::merkle::MerkleTree;
    use hyperlane_core::{Checkpoint, U256};
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn merkle_root_multisig_allows_proof_index_below_checkpoint_index() {
        let origin_domain = 123u32;
        let message = HyperlaneMessage {
            version: 1,
            nonce: 0,
            origin: origin_domain,
            sender: H256::from([0x01; 32]),
            destination: 456,
            recipient: H256::from([0x02; 32]),
            body: vec![0xAA, 0xBB],
        };
        let message_id = message.id();

        let tree = MerkleTree::create(&[message_id, H256::from([0x11; 32])], hyperlane_core::accumulator::TREE_DEPTH);
        let (leaf, branch) = tree.generate_proof(0, hyperlane_core::accumulator::TREE_DEPTH);
        let mut path = [H256::zero(); hyperlane_core::accumulator::TREE_DEPTH];
        for (idx, item) in branch.iter().enumerate() {
            path[idx] = *item;
        }
        let proof = HyperlaneMerkleProof { leaf, index: 0, path };

        let checkpoint = CheckpointWithMessageId {
            checkpoint: Checkpoint {
                merkle_tree_hook_address: H256::zero(),
                mailbox_domain: origin_domain,
                root: tree.hash(),
                index: 1, // checkpoint for 2 leaves, proof for the first leaf
            },
            message_id,
        };

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x03; 32]).expect("secret key");
        let validator_pk = PublicKey::from_secret_key(&secp, &secret);

        let signing_hash = checkpoint.eth_signed_message_hash();
        let msg = Message::from_digest_slice(signing_hash.as_ref()).expect("signing hash");
        let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
        let (rid, sig64) = sig.serialize_compact();

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig64[0..32]);
        s.copy_from_slice(&sig64[32..64]);
        let signature = Signature { r: U256::from_big_endian(&r), s: U256::from_big_endian(&s), v: rid.to_i32() as u64 };

        let metadata = ProofMetadata { checkpoint, merkle_proof: Some(proof), signatures: vec![signature] };

        let config = HyperlaneConfig {
            domains: vec![HyperlaneDomainConfig {
                domain: origin_domain,
                validators: vec![format!("0x{}", hex::encode(validator_pk.serialize()))],
                threshold: 1,
                mode: HyperlaneIsmMode::MerkleRootMultisig,
            }],
            ..Default::default()
        };
        let ism = ConfiguredIsm::from_config(&config).expect("configured ism");

        let report = ism.verify_proof(&message, &metadata, IsmMode::MerkleRootMultisig).expect("proof should verify");
        assert_eq!(report.message_id, message_id);
    }

    #[test]
    fn message_id_multisig_verifies_eip191_checkpoint_signature() {
        let origin_domain = 31337u32;
        let message = HyperlaneMessage {
            version: 1,
            nonce: 1664,
            origin: origin_domain,
            sender: H256::from([0x01; 32]),
            destination: 7,
            recipient: H256::from([0x02; 32]),
            body: vec![0xAA, 0xBB],
        };
        let message_id = message.id();

        let checkpoint = CheckpointWithMessageId {
            checkpoint: Checkpoint {
                merkle_tree_hook_address: H256::zero(),
                mailbox_domain: origin_domain,
                root: H256::from([0x11; 32]),
                index: 1664,
            },
            message_id,
        };

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x07; 32]).expect("secret key");
        let validator_pk = PublicKey::from_secret_key(&secp, &secret);

        let signing_hash = checkpoint.eth_signed_message_hash();
        let msg = Message::from_digest_slice(signing_hash.as_ref()).expect("signing hash");
        let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
        let (rid, sig64) = sig.serialize_compact();

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig64[0..32]);
        s.copy_from_slice(&sig64[32..64]);
        let signature = Signature { r: U256::from_big_endian(&r), s: U256::from_big_endian(&s), v: rid.to_i32() as u64 };

        let metadata = ProofMetadata { checkpoint, merkle_proof: None, signatures: vec![signature] };

        let config = HyperlaneConfig {
            domains: vec![HyperlaneDomainConfig {
                domain: origin_domain,
                validators: vec![format!("0x{}", hex::encode(validator_pk.serialize()))],
                threshold: 1,
                mode: HyperlaneIsmMode::MessageIdMultisig,
            }],
            ..Default::default()
        };
        let ism = ConfiguredIsm::from_config(&config).expect("configured ism");

        let report = ism.verify_proof(&message, &metadata, IsmMode::MessageIdMultisig).expect("proof should verify");
        assert_eq!(report.message_id, message_id);
    }
}
