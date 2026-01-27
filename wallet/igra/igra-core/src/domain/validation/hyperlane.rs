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
	    let signature_digest = match hyperlane_validator_signature_digest(event) {
	        Ok(digest) => digest,
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
	    let message = Message::from_digest_slice(signature_digest.as_ref())?;
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
    for sig in signatures.iter() {
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
    let arr = crate::foundation::parse_hex_32bytes(value).map_err(|_| HyperlaneVerificationFailure::MissingMetadataField { field })?;
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

fn hyperlane_validator_signature_digest(event: &StoredEvent) -> Result<H256, HyperlaneVerificationFailure> {
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
    Ok(checkpoint.eth_signed_message_hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ExternalId;
    use kaspa_consensus_core::tx::ScriptPublicKey;
    use secp256k1::{Secp256k1, SecretKey};
    use std::collections::BTreeMap;

    fn h256_hex(v: &H256) -> String {
        format!("0x{}", hex::encode(v.as_bytes()))
    }

    #[test]
    fn verify_event_requires_eip191_digest() {
        let secp = Secp256k1::new();

        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);

        let origin_domain = 31337u32;
        let destination_domain = 7u32;

        let sender = H256::from([0x11u8; 32]);
        let recipient = H256::from([0x22u8; 32]);
        let body = vec![0xde, 0xad, 0xbe, 0xef];

        let message = HyperlaneMessage {
            version: 0,
            nonce: 42,
            origin: origin_domain,
            sender,
            destination: destination_domain,
            recipient,
            body: body.clone(),
        };
        let message_id = message.id();

        let checkpoint = CheckpointWithMessageId {
            checkpoint: Checkpoint {
                merkle_tree_hook_address: H256::from([0x33u8; 32]),
                mailbox_domain: origin_domain,
                root: H256::from([0x44u8; 32]),
                index: 1664,
            },
            message_id,
        };

        let mut meta = BTreeMap::new();
        meta.insert("hyperlane.msg.version".to_string(), message.version.to_string());
        meta.insert("hyperlane.msg.nonce".to_string(), message.nonce.to_string());
        meta.insert("hyperlane.msg.origin".to_string(), message.origin.to_string());
        meta.insert("hyperlane.msg.sender".to_string(), h256_hex(&message.sender));
        meta.insert("hyperlane.msg.destination".to_string(), message.destination.to_string());
        meta.insert("hyperlane.msg.recipient".to_string(), h256_hex(&message.recipient));
        meta.insert("hyperlane.msg.body_hex".to_string(), hex::encode(&body));

        meta.insert("hyperlane.message_id".to_string(), h256_hex(&message_id));
        meta.insert("hyperlane.mailbox_domain".to_string(), origin_domain.to_string());
        meta.insert(
            "hyperlane.merkle_tree_hook_address".to_string(),
            h256_hex(&checkpoint.checkpoint.merkle_tree_hook_address),
        );
        meta.insert("hyperlane.root".to_string(), h256_hex(&checkpoint.checkpoint.root));
        meta.insert("hyperlane.index".to_string(), checkpoint.checkpoint.index.to_string());

        let event = crate::domain::Event {
            external_id: {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(message_id.as_bytes());
                ExternalId::from(bytes)
            },
            source: SourceType::Hyperlane { origin_domain },
            destination: ScriptPublicKey::from_vec(0, vec![0x51]),
            amount_sompi: 1,
        };

        let digest = checkpoint.eth_signed_message_hash();
        let msg = Message::from_digest_slice(digest.as_ref()).unwrap();
        let sig1 = secp.sign_ecdsa(&msg, &sk1).serialize_compact();
        let sig2 = secp.sign_ecdsa(&msg, &sk2).serialize_compact();
        let proof = [sig1.as_slice(), sig2.as_slice()].concat();

        let stored = StoredEvent {
            event,
            received_at_nanos: 0,
            audit: crate::domain::EventAuditData {
                external_id_raw: h256_hex(&message_id),
                destination_raw: "kaspadev:qq...".to_string(),
                source_data: meta,
            },
            proof: Some(proof),
        };

        let ok = verify_event(&stored, &[pk1, pk2], 2).unwrap();
        assert!(ok.valid);
        assert_eq!(ok.valid_signatures, 2);

        // A signature over the raw `signing_hash()` should NOT verify.
        let raw = checkpoint.signing_hash();
        let raw_msg = Message::from_digest_slice(raw.as_ref()).unwrap();
        let raw_sig1 = secp.sign_ecdsa(&raw_msg, &sk1).serialize_compact();
        let raw_sig2 = secp.sign_ecdsa(&raw_msg, &sk2).serialize_compact();
        let raw_proof = [raw_sig1.as_slice(), raw_sig2.as_slice()].concat();
        let mut stored_raw = stored.clone();
        stored_raw.proof = Some(raw_proof);
        let bad = verify_event(&stored_raw, &[pk1, pk2], 2).unwrap();
        assert!(!bad.valid);
        assert_eq!(bad.valid_signatures, 0);
    }
}
