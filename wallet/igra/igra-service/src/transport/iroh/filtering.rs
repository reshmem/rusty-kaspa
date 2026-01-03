use crate::transport::{FinalizeNotice, MessageEnvelope, PartialSigSubmit, SigningEventPropose, TransportMessage, TransportSubscription};
use crate::transport::SignatureVerifier;
use igra_core::audit::{audit, AuditEvent};
use igra_core::error::ThresholdError;
use igra_core::rate_limit::RateLimiter;
use igra_core::storage::Storage;
use igra_core::types::{PeerId, SessionId, TransactionId};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use super::encoding;

const SEEN_MESSAGE_TTL_NANOS: u64 = 24 * 60 * 60 * 1_000_000_000;
const SEEN_MESSAGE_CLEANUP_INTERVAL: u64 = 500;

pub fn filter_stream(
    verifier: Arc<dyn SignatureVerifier>,
    storage: Arc<dyn Storage>,
    rate_limiter: Arc<RateLimiter>,
    mut stream: futures_util::stream::BoxStream<'static, Result<MessageEnvelope, ThresholdError>>,
    keepalive: Option<Box<dyn std::any::Any + Send>>,
) -> TransportSubscription {
    let cleanup_counter = std::sync::atomic::AtomicU64::new(0);
    let mapped = async_stream::stream! {
        while let Some(item) = futures_util::StreamExt::next(&mut stream).await {
            let envelope = match item {
                Ok(envelope) => envelope,
                Err(err) => {
                    yield Err(err);
                    continue;
                }
            };

            // Rate limit check - prevent DoS attacks
            if !rate_limiter.check_rate_limit(envelope.sender_peer_id.as_str()) {
                audit(AuditEvent::RateLimitExceeded {
                    peer_id: envelope.sender_peer_id.to_string(),
                    timestamp_ns: envelope.timestamp_nanos,
                });
                yield Err(ThresholdError::Message(format!(
                    "rate limit exceeded for peer {}",
                    envelope.sender_peer_id
                )));
                continue;
            }

            let expected = match encoding::payload_hash(&envelope.payload) {
                Ok(expected) => expected,
                Err(err) => {
                    yield Err(err);
                    continue;
                }
            };
            let payload_hash_match = expected.ct_eq(&envelope.payload_hash);
            if !bool::from(payload_hash_match) {
                yield Err(ThresholdError::Message("payload hash mismatch".to_string()));
                continue;
            }
            if !verifier.verify(&envelope.sender_peer_id, &envelope.payload_hash, envelope.signature.as_slice()) {
                yield Err(ThresholdError::Message("invalid signature".to_string()));
                continue;
            }

            match storage.mark_seen_message(
                &envelope.sender_peer_id,
                &envelope.session_id,
                envelope.seq_no,
                envelope.timestamp_nanos,
            ) {
                Ok(true) => {
                    if cleanup_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % SEEN_MESSAGE_CLEANUP_INTERVAL == 0 {
                        let cutoff = envelope.timestamp_nanos.saturating_sub(SEEN_MESSAGE_TTL_NANOS);
                        if let Err(err) = storage.cleanup_seen_messages(cutoff) {
                            yield Err(err);
                            continue;
                        }
                    }
                    if let Err(err) = record_payload(
                        &storage,
                        &envelope.sender_peer_id,
                        envelope.session_id,
                        envelope.timestamp_nanos,
                        &envelope.payload,
                    ) {
                        yield Err(err);
                        continue;
                    }
                    yield Ok(envelope)
                }
                Ok(false) => continue,
                Err(err) => {
                    yield Err(err);
                    continue;
                }
            }
        }
    };
    match keepalive {
        Some(keepalive) => TransportSubscription::new_with_keepalive(Box::pin(mapped), keepalive),
        None => TransportSubscription::new(Box::pin(mapped)),
    }
}

pub fn record_payload(
    storage: &Arc<dyn Storage>,
    sender_peer_id: &PeerId,
    session_id: SessionId,
    timestamp_nanos: u64,
    payload: &TransportMessage,
) -> Result<(), ThresholdError> {
    match payload {
        TransportMessage::SigningEventPropose(SigningEventPropose {
            request_id,
            event_hash,
            validation_hash,
            signing_event,
            kpsbt_blob,
            ..
        }) => {
            storage.insert_event(*event_hash, signing_event.clone())?;
            storage.insert_proposal(
                request_id,
                igra_core::model::StoredProposal {
                    request_id: request_id.clone(),
                    session_id,
                    event_hash: *event_hash,
                    validation_hash: *validation_hash,
                    signing_event: signing_event.clone(),
                    kpsbt_blob: kpsbt_blob.clone(),
                },
            )?;
        }
        TransportMessage::SignerAck(ack) => {
            storage.insert_signer_ack(
                &ack.request_id,
                igra_core::model::SignerAckRecord {
                    signer_peer_id: sender_peer_id.clone(),
                    accept: ack.accept,
                    reason: ack.reason.clone(),
                    timestamp_nanos,
                },
            )?;
        }
        TransportMessage::PartialSigSubmit(PartialSigSubmit {
            request_id,
            input_index,
            pubkey,
            signature,
        }) => {
            storage.insert_partial_sig(
                request_id,
                igra_core::model::PartialSigRecord {
                    signer_peer_id: sender_peer_id.clone(),
                    input_index: *input_index,
                    pubkey: pubkey.clone(),
                    signature: signature.clone(),
                    timestamp_nanos,
                },
            )?;
            audit(AuditEvent::PartialSignatureCreated {
                request_id: request_id.to_string(),
                signer_peer_id: sender_peer_id.to_string(),
                input_count: 1,
                timestamp_ns: timestamp_nanos,
            });
        }
        TransportMessage::FinalizeNotice(FinalizeNotice { request_id, final_tx_id }) => {
            storage.update_request_final_tx(request_id, TransactionId::from(*final_tx_id))?;
        }
        _ => {}
    }
    Ok(())
}
