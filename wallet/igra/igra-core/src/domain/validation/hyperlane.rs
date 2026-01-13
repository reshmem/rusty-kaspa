use crate::domain::hashes::compute_event_id;
use crate::domain::validation::types::{HyperlaneVerificationFailure, HyperlaneVerificationResult};
use crate::domain::{SourceType, StoredEvent};
use crate::foundation::ThresholdError;
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signable, H256};
use secp256k1::ecdsa::Signature as SecpSignature;
use secp256k1::{Message, PublicKey, Secp256k1};

pub fn verify_event(
    event: &StoredEvent,
    validators: &[PublicKey],
    threshold: usize,
) -> Result<HyperlaneVerificationResult, ThresholdError> {
    let event_id = compute_event_id(&event.event);
    if !matches!(event.event.source, SourceType::Hyperlane { .. }) {
        return Ok(HyperlaneVerificationResult {
            valid: true,
            event_id,
            validator_count: 0,
            signatures_checked: 0,
            valid_signatures: 0,
            threshold_required: 0,
            failure_reason: None,
        });
    }
    if validators.is_empty() {
        return Ok(HyperlaneVerificationResult {
            valid: false,
            event_id,
            validator_count: 0,
            signatures_checked: 0,
            valid_signatures: 0,
            threshold_required: threshold,
            failure_reason: Some(HyperlaneVerificationFailure::NoValidatorsConfigured),
        });
    }
    let Some(signature) = event.proof.as_ref() else {
        return Ok(HyperlaneVerificationResult {
            valid: false,
            event_id,
            validator_count: validators.len(),
            signatures_checked: 0,
            valid_signatures: 0,
            threshold_required: threshold,
            failure_reason: Some(HyperlaneVerificationFailure::NoSignatureProvided),
        });
    };
    let signing_hash = match hyperlane_signing_hash(event) {
        Ok(hash) => hash,
        Err(failure_reason) => {
            return Ok(HyperlaneVerificationResult {
                valid: false,
                event_id,
                validator_count: validators.len(),
                signatures_checked: 0,
                valid_signatures: 0,
                threshold_required: threshold,
                failure_reason: Some(failure_reason),
            });
        }
    };
    let message = Message::from_digest_slice(signing_hash.as_ref())?;
    let signatures = match signature.len() {
        64 => match SecpSignature::from_compact(signature) {
            Ok(sig) => vec![sig],
            Err(_) => {
                return Ok(HyperlaneVerificationResult {
                    valid: false,
                    event_id,
                    validator_count: validators.len(),
                    signatures_checked: 1,
                    valid_signatures: 0,
                    threshold_required: threshold,
                    failure_reason: Some(HyperlaneVerificationFailure::InvalidSignatureFormat { chunk_index: 0 }),
                });
            }
        },
        len if len > 64 && len % 64 == 0 => {
            const MAX_SIGNATURE_CHUNKS: usize = 256;
            let chunk_count = len / 64;
            if chunk_count > MAX_SIGNATURE_CHUNKS {
                return Ok(HyperlaneVerificationResult {
                    valid: false,
                    event_id,
                    validator_count: validators.len(),
                    signatures_checked: 0,
                    valid_signatures: 0,
                    threshold_required: threshold,
                    failure_reason: Some(HyperlaneVerificationFailure::TooManySignatureChunks {
                        chunks: chunk_count,
                        max: MAX_SIGNATURE_CHUNKS,
                    }),
                });
            }
            let mut signatures = Vec::with_capacity(chunk_count);
            for (chunk_index, chunk) in signature.chunks(64).enumerate() {
                match SecpSignature::from_compact(chunk) {
                    Ok(sig) => signatures.push(sig),
                    Err(_) => {
                        return Ok(HyperlaneVerificationResult {
                            valid: false,
                            event_id,
                            validator_count: validators.len(),
                            signatures_checked: chunk_index.saturating_add(1),
                            valid_signatures: 0,
                            threshold_required: threshold,
                            failure_reason: Some(HyperlaneVerificationFailure::InvalidSignatureFormat { chunk_index }),
                        });
                    }
                }
            }
            signatures
        }
        _ => match SecpSignature::from_der(signature) {
            Ok(sig) => vec![sig],
            Err(_) => {
                return Ok(HyperlaneVerificationResult {
                    valid: false,
                    event_id,
                    validator_count: validators.len(),
                    signatures_checked: 1,
                    valid_signatures: 0,
                    threshold_required: threshold,
                    failure_reason: Some(HyperlaneVerificationFailure::InvalidSignatureFormat { chunk_index: 0 }),
                });
            }
        },
    };

    let secp = Secp256k1::verification_only();
    let mut used = vec![false; validators.len()];
    let mut matched = 0usize;

    let signature_chunks = signatures.len();
    for (_sig_index, sig) in signatures.iter().enumerate() {
        for (idx, validator) in validators.iter().enumerate() {
            if used[idx] {
                continue;
            }
            if secp.verify_ecdsa(&message, sig, validator).is_ok() {
                used[idx] = true;
                matched += 1;
                break;
            }
        }
        if matched >= threshold {
            return Ok(HyperlaneVerificationResult {
                valid: true,
                event_id,
                validator_count: validators.len(),
                signatures_checked: signature_chunks,
                valid_signatures: matched,
                threshold_required: threshold,
                failure_reason: None,
            });
        }
    }

    Ok(HyperlaneVerificationResult {
        valid: false,
        event_id,
        validator_count: validators.len(),
        signatures_checked: signature_chunks,
        valid_signatures: matched,
        threshold_required: threshold,
        failure_reason: Some(HyperlaneVerificationFailure::InsufficientValidSignatures { valid: matched, required: threshold }),
    })
}

fn require_meta<'a>(event: &'a StoredEvent, key: &'static str) -> Result<&'a str, HyperlaneVerificationFailure> {
    event.audit.source_data.get(key).map(String::as_str).ok_or(HyperlaneVerificationFailure::MissingMetadataField { field: key })
}

fn parse_u8(value: &str, field: &'static str) -> Result<u8, HyperlaneVerificationFailure> {
    value.trim().parse::<u8>().map_err(|_| HyperlaneVerificationFailure::MissingMetadataField { field })
}

fn parse_u32(value: &str, field: &'static str) -> Result<u32, HyperlaneVerificationFailure> {
    value.trim().parse::<u32>().map_err(|_| HyperlaneVerificationFailure::MissingMetadataField { field })
}

fn parse_h256(value: &str, field: &'static str) -> Result<H256, HyperlaneVerificationFailure> {
    let stripped = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped).map_err(|_| HyperlaneVerificationFailure::MissingMetadataField { field })?;
    if bytes.len() != 32 {
        return Err(HyperlaneVerificationFailure::MissingMetadataField { field });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(H256::from(arr))
}

fn matches_external_id(event: &StoredEvent, message_id: H256) -> bool {
    event.event.external_id.as_slice() == message_id.as_bytes()
}

fn recompute_message_id(event: &StoredEvent) -> Result<H256, HyperlaneVerificationFailure> {
    let version = parse_u8(require_meta(event, "hyperlane.msg.version")?, "hyperlane.msg.version")?;
    let nonce = parse_u32(require_meta(event, "hyperlane.msg.nonce")?, "hyperlane.msg.nonce")?;
    let origin = parse_u32(require_meta(event, "hyperlane.msg.origin")?, "hyperlane.msg.origin")?;
    let sender = parse_h256(require_meta(event, "hyperlane.msg.sender")?, "hyperlane.msg.sender")?;
    let destination = parse_u32(require_meta(event, "hyperlane.msg.destination")?, "hyperlane.msg.destination")?;
    let recipient = parse_h256(require_meta(event, "hyperlane.msg.recipient")?, "hyperlane.msg.recipient")?;
    let body_hex = require_meta(event, "hyperlane.msg.body_hex")?;
    let body = hex::decode(body_hex.trim())
        .map_err(|_| HyperlaneVerificationFailure::MissingMetadataField { field: "hyperlane.msg.body_hex" })?;

    let message = HyperlaneMessage { version, nonce, origin, sender, destination, recipient, body };
    Ok(message.id())
}

fn hyperlane_signing_hash(event: &StoredEvent) -> Result<H256, HyperlaneVerificationFailure> {
    let message_id = recompute_message_id(event)?;

    if !matches_external_id(event, message_id) {
        return Err(HyperlaneVerificationFailure::MessageIdMismatch);
    }

    let checkpoint_message_id = parse_h256(require_meta(event, "hyperlane.message_id")?, "hyperlane.message_id")?;
    if checkpoint_message_id != message_id {
        return Err(HyperlaneVerificationFailure::MessageIdMismatch);
    }

    let mailbox_domain = parse_u32(require_meta(event, "hyperlane.mailbox_domain")?, "hyperlane.mailbox_domain")?;
    let origin = parse_u32(require_meta(event, "hyperlane.msg.origin")?, "hyperlane.msg.origin")?;
    if mailbox_domain != origin {
        return Err(HyperlaneVerificationFailure::MessageIdMismatch);
    }

    let merkle_tree_hook_address =
        parse_h256(require_meta(event, "hyperlane.merkle_tree_hook_address")?, "hyperlane.merkle_tree_hook_address")?;
    let root = parse_h256(require_meta(event, "hyperlane.root")?, "hyperlane.root")?;
    let index = parse_u32(require_meta(event, "hyperlane.index")?, "hyperlane.index")?;

    let checkpoint =
        CheckpointWithMessageId { checkpoint: Checkpoint { merkle_tree_hook_address, mailbox_domain, root, index }, message_id };
    Ok(checkpoint.signing_hash())
}
