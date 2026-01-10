use crate::foundation::ThresholdError;
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::RateLimiter;
use super::{encoding, filtering};
use super::traits::{SignatureVerifier, TransportSubscription};
use futures_util::StreamExt;
use iroh_gossip::api::Event as GossipEvent;
use std::sync::Arc;
use std::time::Duration;

// Maximum message size: 10 MB (must match limit in mod.rs)
use crate::foundation::constants::MAX_MESSAGE_SIZE_BYTES;

const MAX_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE_BYTES;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);

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
            let item: Option<Result<GossipEvent, E>> = match tokio::time::timeout(RECEIVE_TIMEOUT, stream.next()).await {
                Ok(item) => item,
                Err(_) => {
                    yield Err(ThresholdError::Message("iroh gossip receive timeout".to_string()));
                    continue;
                }
            };
            let Some(item) = item else {
                break;
            };
            let item = match item {
                Ok(item) => item,
                Err(err) => {
                    yield Err(ThresholdError::Message(err.to_string()));
                    continue;
                }
            };
            match item {
                GossipEvent::Received(message) => {
                    // Reject oversized messages to prevent memory exhaustion
                    if message.content.len() > MAX_MESSAGE_SIZE {
                        yield Err(ThresholdError::Message(format!(
                            "received message size {} exceeds maximum {}",
                            message.content.len(),
                            MAX_MESSAGE_SIZE
                        )));
                        continue;
                    }

                    let envelope = match encoding::decode_envelope(message.content.as_ref()) {
                        Ok(envelope) => envelope,
                        Err(err) => {
                            yield Err(err);
                            continue;
                        }
                    };
                    yield Ok(envelope);
                }
                GossipEvent::Lagged => {
                    yield Err(ThresholdError::Message("iroh gossip stream lagged".to_string()));
                }
                _ => {}
            }
        }
    };
    filtering::filter_stream(verifier, storage, rate_limiter, Box::pin(mapped), Some(keepalive))
}
