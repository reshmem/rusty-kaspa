use super::traits::{MessageEnvelope, SignatureVerifier, TransportSubscription};
use crate::foundation::ThresholdError;
use crate::foundation::{hx32, now_nanos, SEEN_MESSAGE_CLEANUP_INTERVAL_MESSAGES, SEEN_MESSAGE_TTL_NANOS};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::RateLimiter;
use log::{debug, trace, warn};
use std::sync::Arc;
use subtle::ConstantTimeEq;

use super::encoding;

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
                    "rate limit blocked message peer_id={} session_id={} seq_no={}",
                    envelope.sender_peer_id,
                    envelope.session_id,
                    envelope.seq_no
                );
                audit(AuditEvent::RateLimitExceeded {
                    peer_id: envelope.sender_peer_id.to_string(),
                    timestamp_nanos: envelope.timestamp_nanos,
                });
                yield Err(ThresholdError::TransportError {
                    operation: "rate_limit".to_string(),
                    details: format!("rate limit exceeded for peer {}", envelope.sender_peer_id),
                });
                continue;
            }

            let expected = match encoding::payload_hash(&envelope.payload) {
                Ok(expected) => expected,
                Err(err) => {
                    yield Err(err);
                    continue;
                }
            };
            let payload_hash_match = expected.as_hash().ct_eq(envelope.payload_hash.as_hash());
            if !bool::from(payload_hash_match) {
                warn!(
                    "payload hash mismatch peer_id={} expected_hash={:#x} actual_hash={:#x}",
                    envelope.sender_peer_id,
                    hx32(expected.as_hash()),
                    hx32(envelope.payload_hash.as_hash())
                );
                yield Err(ThresholdError::TransportError {
                    operation: "payload_hash_mismatch".to_string(),
                    details: format!(
                        "peer_id={} expected_hash={:#x} actual_hash={:#x}",
                        envelope.sender_peer_id,
                        hx32(expected.as_hash()),
                        hx32(envelope.payload_hash.as_hash())
                    ),
                });
                continue;
            }
            if !verifier.verify(&envelope.sender_peer_id, &envelope.payload_hash, envelope.signature.as_slice()) {
                warn!(
                    "invalid signature peer_id={} payload_hash={:#x}",
                    envelope.sender_peer_id,
                    hx32(envelope.payload_hash.as_hash())
                );
                yield Err(ThresholdError::TransportError {
                    operation: "signature_verification".to_string(),
                    details: format!("peer_id={} payload_hash={:#x}", envelope.sender_peer_id, hx32(envelope.payload_hash.as_hash())),
                });
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
                        "accepted new message peer_id={} session_id={} seq_no={}",
                        envelope.sender_peer_id,
                        envelope.session_id,
                        envelope.seq_no
                    );
                    if cleanup_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % SEEN_MESSAGE_CLEANUP_INTERVAL_MESSAGES == 0 {
                        let local_now_nanos = now_nanos();
                        let cutoff = local_now_nanos.saturating_sub(SEEN_MESSAGE_TTL_NANOS);
                        trace!("cleanup_seen_messages tick cutoff={}", cutoff);
                        match storage.cleanup_seen_messages(cutoff) {
                            Ok(deleted) => trace!("cleanup_seen_messages complete deleted={}", deleted),
                            Err(err) => {
                                yield Err(err);
                                continue;
                            }
                        };
                    }
                    yield Ok(envelope)
                }
                Ok(false) => {
                    debug!(
                        "duplicate message ignored peer_id={} session_id={} seq_no={}",
                        envelope.sender_peer_id,
                        envelope.session_id,
                        envelope.seq_no
                    );
                    continue;
                }
                Err(err) => {
                    warn!(
                        "mark_seen_message failed peer_id={} error={}",
                        envelope.sender_peer_id,
                        err
                    );
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
