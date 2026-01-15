use super::traits::{SignatureVerifier, TransportSubscription};
use super::{encoding, filtering};
use crate::foundation::ThresholdError;
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::RateLimiter;
use futures_util::StreamExt;
use iroh_gossip::api::Event as GossipEvent;
use log::warn;
use std::sync::Arc;

// Maximum message size: 10 MB (must match limit in mod.rs)
use crate::foundation::constants::MAX_MESSAGE_SIZE_BYTES;

const MAX_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE_BYTES;

pub fn subscribe_stream<E>(
    verifier: Arc<dyn SignatureVerifier>,
    storage: Arc<dyn Storage>,
    rate_limiter: Arc<RateLimiter>,
    mut stream: impl futures_util::Stream<Item = Result<GossipEvent, E>> + Unpin + Send + 'static,
    keepalive: Box<dyn std::any::Any + Send>,
) -> TransportSubscription
where
    E: std::fmt::Display + Send + 'static,
{
    let mapped = async_stream::stream! {
        loop {
            let item: Option<Result<GossipEvent, E>> = stream.next().await;
            let Some(item) = item else {
                break;
            };
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    warn!("iroh gossip stream error error={}", err);
                    yield Err(ThresholdError::TransportError { operation: "gossip_stream".to_string(), details: err.to_string() });
                    continue;
                }
            };
            match item {
                GossipEvent::Received(message) => {
                    // Reject oversized messages to prevent memory exhaustion
                    if message.content.len() > MAX_MESSAGE_SIZE {
                        warn!(
                            "iroh gossip oversized message size={} max={}",
                            message.content.len(),
                            MAX_MESSAGE_SIZE
                        );
                        yield Err(ThresholdError::MessageTooLarge { size: message.content.len(), max: MAX_MESSAGE_SIZE });
                        continue;
                    }

                    let envelope = match encoding::decode_envelope(message.content.as_ref()) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            let msg_hash = blake3::hash(message.content.as_ref());
                            warn!(
                                "iroh gossip decode error error={} message_hash={} size={}",
                                err,
                                hex::encode(msg_hash.as_bytes()),
                                message.content.len()
                            );
                            yield Err(err);
                            continue;
                        }
                    };
                    yield Ok(envelope);
                }
                GossipEvent::Lagged => {
                    // Group id not available in this layer; surface lag with placeholder.
                    warn!("iroh gossip stream lagged group_id=unknown");
                    yield Err(ThresholdError::TransportError {
                        operation: "gossip_stream_lagged".to_string(),
                        details: "iroh gossip stream lagged group_id=unknown".to_string(),
                    });
                }
                _ => {}
            }
        }
    };
    filtering::filter_stream(verifier, storage, rate_limiter, Box::pin(mapped), Some(keepalive))
}
