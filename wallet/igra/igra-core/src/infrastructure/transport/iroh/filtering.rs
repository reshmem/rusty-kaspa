use super::traits::{
    FinalizeNotice, MessageEnvelope, PartialSigSubmit, SignatureVerifier, SigningEventPropose, TransportMessage, TransportSubscription,
};
use crate::domain::{PartialSigRecord, SignerAckRecord, StoredProposal};
use crate::foundation::ThresholdError;
use crate::foundation::{PeerId, SessionId, TransactionId};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::RateLimiter;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tracing::{debug, trace, warn};

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
                debug!(
                    peer_id = %envelope.sender_peer_id,
                    session_id = %hex::encode(envelope.session_id.as_hash()),
                    seq_no = envelope.seq_no,
                    "rate limit blocked message"
                );
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
                warn!(
                    peer_id = %envelope.sender_peer_id,
                    expected_hash = %hex::encode(expected),
                    actual_hash = %hex::encode(envelope.payload_hash),
                    "payload hash mismatch"
                );
                yield Err(ThresholdError::Message("payload hash mismatch".to_string()));
                continue;
            }
            if !verifier.verify(&envelope.sender_peer_id, &envelope.payload_hash, envelope.signature.as_slice()) {
                warn!(
                    peer_id = %envelope.sender_peer_id,
                    payload_hash = %hex::encode(envelope.payload_hash),
                    "invalid signature"
                );
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
                    debug!(
                        peer_id = %envelope.sender_peer_id,
                        session_id = %hex::encode(envelope.session_id.as_hash()),
                        seq_no = envelope.seq_no,
                        "accepted new message"
                    );
                    if cleanup_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % SEEN_MESSAGE_CLEANUP_INTERVAL == 0 {
                        let local_now_nanos: u64 = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_err(|_| ThresholdError::Message("system time before unix epoch".to_string()))?
                            .as_nanos()
                            .try_into()
                            .unwrap_or(u64::MAX);
                        let cutoff = local_now_nanos.saturating_sub(SEEN_MESSAGE_TTL_NANOS);
                        trace!(cutoff, "cleanup_seen_messages tick");
                        match storage.cleanup_seen_messages(cutoff) {
                            Ok(deleted) => trace!(deleted, "cleanup_seen_messages complete"),
                            Err(err) => {
                                yield Err(err);
                                continue;
                            }
                        };
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
                Ok(false) => {
                    debug!(
                        peer_id = %envelope.sender_peer_id,
                        session_id = %hex::encode(envelope.session_id.as_hash()),
                        seq_no = envelope.seq_no,
                        "duplicate message ignored"
                    );
                    continue;
                }
                Err(err) => {
                    warn!(peer_id = %envelope.sender_peer_id, error = %err, "mark_seen_message failed");
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
    trace!(
        sender_peer_id = %sender_peer_id,
        session_id = %hex::encode(session_id.as_hash()),
        timestamp_nanos,
        "record_payload"
    );
    match payload {
        TransportMessage::SigningEventPropose(SigningEventPropose {
            request_id,
            event_hash,
            validation_hash,
            signing_event,
            kpsbt_blob,
            ..
        }) => {
            trace!(
                request_id = %request_id,
                event_hash = %hex::encode(event_hash),
                validation_hash = %hex::encode(validation_hash),
                event_id = %signing_event.event_id,
                kpsbt_len = kpsbt_blob.len(),
                "record proposal payload"
            );
            match storage.insert_event(*event_hash, signing_event.clone()) {
                Ok(()) => {}
                Err(ThresholdError::EventReplayed(_)) => {}
                Err(err) => return Err(err),
            }
            storage.insert_proposal(
                request_id,
                StoredProposal {
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
            trace!(
                request_id = %ack.request_id,
                accept = ack.accept,
                reason = ?ack.reason,
                "record signer ack payload"
            );
            storage.insert_signer_ack(
                &ack.request_id,
                SignerAckRecord {
                    signer_peer_id: sender_peer_id.clone(),
                    accept: ack.accept,
                    reason: ack.reason.clone(),
                    timestamp_nanos,
                },
            )?;
        }
        TransportMessage::PartialSigSubmit(PartialSigSubmit { request_id, input_index, pubkey, signature }) => {
            trace!(
                request_id = %request_id,
                input_index = *input_index,
                pubkey_len = pubkey.len(),
                signature_len = signature.len(),
                "record partial sig payload"
            );
            storage.insert_partial_sig(
                request_id,
                PartialSigRecord {
                    signer_peer_id: sender_peer_id.clone(),
                    input_index: *input_index,
                    pubkey: pubkey.clone(),
                    signature: signature.clone(),
                    timestamp_nanos,
                },
            )?;
        }
        TransportMessage::FinalizeNotice(FinalizeNotice { request_id, final_tx_id }) => {
            trace!(
                request_id = %request_id,
                final_tx_id = %hex::encode(final_tx_id),
                "record finalize payload"
            );
            storage.update_request_final_tx(request_id, TransactionId::from(*final_tx_id))?;
        }
        _ => {}
    }
    Ok(())
}
