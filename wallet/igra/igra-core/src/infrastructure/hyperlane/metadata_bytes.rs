use super::{IsmMode, ProofMetadata};
use crate::foundation::ThresholdError;
use hyperlane_core::accumulator::merkle::{merkle_root_from_branch, Proof as HyperlaneMerkleProof};
use hyperlane_core::accumulator::TREE_DEPTH;
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signature, H256, U256};

pub fn decode_proof_metadata_hex(
    mode: IsmMode,
    message: &HyperlaneMessage,
    metadata_hex: &str,
) -> Result<ProofMetadata, ThresholdError> {
    let stripped = metadata_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped).map_err(|err| {
        ThresholdError::EncodingError(format!(
            "invalid hyperlane metadata hex message_id={} mode={:?} error={}",
            hex::encode(message.id().as_bytes()),
            mode,
            err
        ))
    })?;
    decode_proof_metadata_bytes(mode, message, &bytes)
}

pub fn decode_proof_metadata_bytes(mode: IsmMode, message: &HyperlaneMessage, bytes: &[u8]) -> Result<ProofMetadata, ThresholdError> {
    match mode {
        IsmMode::MessageIdMultisig => decode_message_id_multisig(message, bytes),
        IsmMode::MerkleRootMultisig => decode_merkle_root_multisig(message, bytes),
    }
}

fn decode_message_id_multisig(message: &HyperlaneMessage, bytes: &[u8]) -> Result<ProofMetadata, ThresholdError> {
    const HEADER_LEN: usize = 32 + 32 + 4;
    if bytes.len() < HEADER_LEN {
        return Err(ThresholdError::EncodingError(format!(
            "hyperlane metadata too short for message_id_multisig message_id={} bytes_len={}",
            hex::encode(message.id().as_bytes()),
            bytes.len()
        )));
    }
    let merkle_tree_hook_address = h256_from_slice(&bytes[0..32])?;
    let root = h256_from_slice(&bytes[32..64])?;
    let index = u32::from_be_bytes(copy4(&bytes[64..68])?);

    let signatures = parse_signatures(&bytes[HEADER_LEN..], message.id(), "message_id_multisig")?;

    let checkpoint = CheckpointWithMessageId {
        checkpoint: Checkpoint { merkle_tree_hook_address, mailbox_domain: message.origin, root, index },
        message_id: message.id(),
    };

    Ok(ProofMetadata { checkpoint, merkle_proof: None, signatures })
}

fn decode_merkle_root_multisig(message: &HyperlaneMessage, bytes: &[u8]) -> Result<ProofMetadata, ThresholdError> {
    const PROOF_BYTES: usize = TREE_DEPTH * 32;
    const HEADER_LEN: usize = 32 + 4 + 32 + PROOF_BYTES + 4;
    if bytes.len() < HEADER_LEN {
        return Err(ThresholdError::EncodingError(format!(
            "hyperlane metadata too short for merkle_root_multisig message_id={} bytes_len={}",
            hex::encode(message.id().as_bytes()),
            bytes.len()
        )));
    }

    let merkle_tree_hook_address = h256_from_slice(&bytes[0..32])?;
    let leaf_index = u32::from_be_bytes(copy4(&bytes[32..36])?) as usize;
    let message_id = h256_from_slice(&bytes[36..68])?;
    let message_id_expected = message.id();
    if message_id != message_id_expected {
        return Err(ThresholdError::EncodingError(format!(
            "hyperlane metadata message_id mismatch mode=merkle_root_multisig expected={} got={}",
            hex::encode(message_id_expected.as_bytes()),
            hex::encode(message_id.as_bytes())
        )));
    }

    let proof_start = 68;
    let proof_end = proof_start + PROOF_BYTES;
    let mut path = [H256::zero(); TREE_DEPTH];
    for (idx, chunk) in bytes[proof_start..proof_end].chunks_exact(32).enumerate() {
        if idx >= TREE_DEPTH {
            break;
        }
        path[idx] = h256_from_slice(chunk)?;
    }

    let checkpoint_index_offset = proof_end;
    let checkpoint_index = u32::from_be_bytes(copy4(&bytes[checkpoint_index_offset..checkpoint_index_offset + 4])?);

    let merkle_root = merkle_root_from_branch(message_id, &path, TREE_DEPTH, leaf_index);
    let merkle_proof = HyperlaneMerkleProof { leaf: message_id, index: leaf_index, path };

    let signatures = parse_signatures(&bytes[checkpoint_index_offset + 4..], message.id(), "merkle_root_multisig")?;

    let checkpoint = CheckpointWithMessageId {
        checkpoint: Checkpoint {
            merkle_tree_hook_address,
            mailbox_domain: message.origin,
            root: merkle_root,
            index: checkpoint_index,
        },
        message_id,
    };

    Ok(ProofMetadata { checkpoint, merkle_proof: Some(merkle_proof), signatures })
}

fn parse_signatures(bytes: &[u8], message_id: H256, mode: &'static str) -> Result<Vec<Signature>, ThresholdError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 65 != 0 {
        return Err(ThresholdError::EncodingError(format!(
            "hyperlane metadata signatures invalid length message_id={} mode={} bytes_len={}",
            hex::encode(message_id.as_bytes()),
            mode,
            bytes.len()
        )));
    }
    let count = bytes.len() / 65;
    const MAX_SIGNATURES: usize = 256;
    if count > MAX_SIGNATURES {
        return Err(ThresholdError::EncodingError(format!(
            "hyperlane metadata has too many signatures message_id={} mode={} count={} max={}",
            hex::encode(message_id.as_bytes()),
            mode,
            count,
            MAX_SIGNATURES
        )));
    }

    let mut out = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(65) {
        out.push(signature_from_bytes(chunk)?);
    }
    Ok(out)
}

fn signature_from_bytes(bytes: &[u8]) -> Result<Signature, ThresholdError> {
    if bytes.len() != 65 {
        return Err(ThresholdError::EncodingError(format!("hyperlane signature must be 65 bytes (r||s||v), got {}", bytes.len())));
    }
    let r = U256::from_big_endian(&bytes[0..32]);
    let s = U256::from_big_endian(&bytes[32..64]);
    let v = u64::from(bytes[64]);
    Ok(Signature { r, s, v })
}

fn copy4(bytes: &[u8]) -> Result<[u8; 4], ThresholdError> {
    bytes.try_into().map_err(|_| ThresholdError::EncodingError("invalid u32 slice".to_string()))
}

fn h256_from_slice(bytes: &[u8]) -> Result<H256, ThresholdError> {
    let array: [u8; 32] =
        bytes.try_into().map_err(|_| ThresholdError::EncodingError(format!("invalid H256 slice length {}", bytes.len())))?;
    Ok(H256::from(array))
}
