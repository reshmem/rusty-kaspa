use super::traits::{
    EventStateBroadcast, MessageEnvelope, SignatureSigner, SignatureVerifier, StateSyncRequest, StateSyncResponse, Transport,
    TransportMessage, TransportSubscription,
};
use crate::foundation::Hash32;
use crate::foundation::SessionId;
use crate::foundation::ThresholdError;
use crate::foundation::GOSSIP_PUBLISH_INFO_REPORT_INTERVAL_NANOS;
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::iroh::{config::IrohConfig, encoding, subscription};
use crate::infrastructure::transport::RateLimiter;
use async_trait::async_trait;
use iroh::EndpointId;
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;
use log::{debug, info, trace, warn};
use std::str::FromStr;
use std::sync::Arc;

// Maximum message size: 10 MB (allows for PSKT with many inputs)
// PSKT blob size: ~1KB base + ~200 bytes per input × 100 inputs = ~21KB
// 10 MB provides comfortable headroom while preventing DoS
use crate::foundation::constants::{
    GOSSIP_PUBLISH_RETRIES, GOSSIP_RETRY_DELAY_MS, MAX_BOOTSTRAP_PEERS, MAX_GOSSIP_TOPIC_LENGTH, MAX_MESSAGE_SIZE_BYTES,
    RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_RATE,
};
const MAX_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE_BYTES;
const PUBLISH_RETRY_ATTEMPTS: usize = GOSSIP_PUBLISH_RETRIES;
const PUBLISH_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(GOSSIP_RETRY_DELAY_MS);

pub struct IrohTransport {
    gossip: Gossip,
    signer: Arc<dyn SignatureSigner>,
    verifier: Arc<dyn SignatureVerifier>,
    storage: Arc<dyn Storage>,
    rate_limiter: Arc<RateLimiter>,
    config: IrohConfig,
    bootstrap: Vec<EndpointId>,
    seq: std::sync::atomic::AtomicU64,
    publish_ok_count: std::sync::atomic::AtomicU64,
    publish_ok_bytes: std::sync::atomic::AtomicU64,
    publish_last_report_nanos: std::sync::atomic::AtomicU64,
}

impl IrohTransport {
    pub fn new(
        gossip: Gossip,
        signer: Arc<dyn SignatureSigner>,
        verifier: Arc<dyn SignatureVerifier>,
        storage: Arc<dyn Storage>,
        config: IrohConfig,
    ) -> Result<Self, ThresholdError> {
        if config.bootstrap_nodes.len() > MAX_BOOTSTRAP_PEERS {
            return Err(ThresholdError::ConfigError(format!(
                "iroh.bootstrap has too many peers ({} > max {})",
                config.bootstrap_nodes.len(),
                MAX_BOOTSTRAP_PEERS
            )));
        }
        info!(
            "creating iroh transport network_id={} group_id={} bootstrap_nodes={}",
            config.network_id,
            hex::encode(config.group_id),
            config.bootstrap_nodes.len()
        );
        let bootstrap = config
            .bootstrap_nodes
            .iter()
            .filter_map(|node_id| match EndpointId::from_str(node_id) {
                Ok(id) => Some(id),
                Err(err) => {
                    warn!("invalid bootstrap node, skipping node_id={} error={}", node_id.as_str(), err);
                    None
                }
            })
            .collect::<Vec<_>>();

        if !config.bootstrap_nodes.is_empty() && bootstrap.is_empty() {
            return Err(ThresholdError::ConfigError("no valid iroh.bootstrap nodes".to_string()));
        }

        // Create rate limiter: 100 messages burst, 10 messages/sec sustained per peer
        let rate_limiter = Arc::new(RateLimiter::new(RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_RATE));

        Ok(Self {
            gossip,
            signer,
            verifier,
            storage,
            rate_limiter,
            config,
            bootstrap,
            seq: std::sync::atomic::AtomicU64::new(1),
            publish_ok_count: std::sync::atomic::AtomicU64::new(0),
            publish_ok_bytes: std::sync::atomic::AtomicU64::new(0),
            publish_last_report_nanos: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn group_topic_id(group_id: &Hash32, network_id: u8) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kaspa-sign/v1");
        hasher.update(&[network_id]);
        hasher.update(group_id);
        *hasher.finalize().as_bytes()
    }

    fn maybe_report_publish_stats(&self, now_nanos: u64) {
        let last = self.publish_last_report_nanos.load(std::sync::atomic::Ordering::Relaxed);
        if last != 0 && now_nanos.saturating_sub(last) < GOSSIP_PUBLISH_INFO_REPORT_INTERVAL_NANOS {
            return;
        }

        if self
            .publish_last_report_nanos
            .compare_exchange(last, now_nanos, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let ok_msgs = self.publish_ok_count.swap(0, std::sync::atomic::Ordering::AcqRel);
        let ok_bytes = self.publish_ok_bytes.swap(0, std::sync::atomic::Ordering::AcqRel);
        if ok_msgs == 0 {
            return;
        }

        info!(
            "gossip publish stats ok_msgs={} ok_bytes={} interval_secs={} network_id={} group_id={}",
            ok_msgs,
            ok_bytes,
            GOSSIP_PUBLISH_INFO_REPORT_INTERVAL_NANOS / crate::foundation::NANOS_PER_SECOND,
            self.config.network_id,
            hex::encode(self.config.group_id)
        );
    }

    async fn publish_bytes(&self, topic: Hash32, bytes: Vec<u8>, kind: &'static str) -> Result<(), ThresholdError> {
        // Enforce message size limit to prevent memory exhaustion attacks
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(ThresholdError::MessageTooLarge { size: bytes.len(), max: MAX_MESSAGE_SIZE });
        }

        let topic_id = TopicId::from(topic);
        if topic_id.as_bytes().len() > MAX_GOSSIP_TOPIC_LENGTH {
            return Err(ThresholdError::ConfigError(format!(
                "gossip topic too long ({} > max {})",
                topic_id.as_bytes().len(),
                MAX_GOSSIP_TOPIC_LENGTH
            )));
        }
        let mut last_err: Option<String> = None;
        debug!(
            "publishing gossip message topic={} byte_len={} bootstrap_peers={}",
            hex::encode(topic_id.as_bytes()),
            bytes.len(),
            self.bootstrap.len()
        );
        for attempt in 0..PUBLISH_RETRY_ATTEMPTS {
            trace!("publish attempt attempt={} topic={} byte_len={}", attempt + 1, hex::encode(topic_id.as_bytes()), bytes.len());
            let mut topic = match self.gossip.subscribe(topic_id, self.bootstrap.clone()).await {
                Ok(topic) => topic,
                Err(err) => {
                    let err_str = err.to_string();
                    last_err = Some(err_str.clone());
                    warn!(
                        "failed to subscribe for publish attempt={} topic={} error={}",
                        attempt + 1,
                        hex::encode(topic_id.as_bytes()),
                        err_str
                    );
                    if attempt + 1 < PUBLISH_RETRY_ATTEMPTS {
                        trace!("publish retry sleep sleep_ms={}", PUBLISH_RETRY_DELAY.as_millis());
                        tokio::time::sleep(PUBLISH_RETRY_DELAY).await;
                    }
                    continue;
                }
            };
            match topic.broadcast(bytes.clone().into()).await {
                Ok(()) => {
                    // Don't spam INFO for normal operation; emit INFO only when we had to retry.
                    if attempt > 0 {
                        info!(
                            "published gossip message after retry kind={} attempt={} topic={} byte_len={}",
                            kind,
                            attempt + 1,
                            hex::encode(topic_id.as_bytes()),
                            bytes.len()
                        );
                    } else {
                        debug!(
                            "published gossip message kind={} topic={} byte_len={}",
                            kind,
                            hex::encode(topic_id.as_bytes()),
                            bytes.len()
                        );
                    }

                    self.publish_ok_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.publish_ok_bytes.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    self.maybe_report_publish_stats(crate::foundation::now_nanos());
                    return Ok(());
                }
                Err(err) => {
                    let err_str = err.to_string();
                    last_err = Some(err_str.clone());
                    warn!(
                        "failed to broadcast gossip message attempt={} topic={} error={}",
                        attempt + 1,
                        hex::encode(topic_id.as_bytes()),
                        err_str
                    );
                    if attempt + 1 < PUBLISH_RETRY_ATTEMPTS {
                        trace!("publish retry sleep sleep_ms={}", PUBLISH_RETRY_DELAY.as_millis());
                        tokio::time::sleep(PUBLISH_RETRY_DELAY).await;
                    }
                }
            }
        }
        Err(ThresholdError::Message(last_err.unwrap_or_else(|| "failed to publish gossip message".to_string())))
    }
}

#[async_trait]
impl Transport for IrohTransport {
    async fn publish_event_state(&self, broadcast: EventStateBroadcast) -> Result<(), ThresholdError> {
        let topic = Self::group_topic_id(&self.config.group_id, self.config.network_id);
        let stream_id = SessionId::from(topic);
        debug!(
            "publishing CRDT state event_id={} tx_template_hash={} sig_count={} completed={}",
            hex::encode(broadcast.event_id),
            hex::encode(broadcast.tx_template_hash),
            broadcast.state.signatures.len(),
            broadcast.state.completion.is_some()
        );
        let payload = TransportMessage::EventStateBroadcast(broadcast);
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = crate::foundation::now_nanos();
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id: stream_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };
        let bytes = encoding::encode_envelope(&envelope)?;
        self.publish_bytes(topic, bytes, "event_state").await
    }

    async fn publish_state_sync_request(&self, request: StateSyncRequest) -> Result<(), ThresholdError> {
        let topic = Self::group_topic_id(&self.config.group_id, self.config.network_id);
        let stream_id = SessionId::from(topic);
        debug!("publishing CRDT sync request event_count={} requester_peer_id={}", request.event_ids.len(), request.requester_peer_id);
        let payload = TransportMessage::StateSyncRequest(request);
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = crate::foundation::now_nanos();
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id: stream_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };
        let bytes = encoding::encode_envelope(&envelope)?;
        self.publish_bytes(topic, bytes, "state_sync_request").await
    }

    async fn publish_state_sync_response(&self, response: StateSyncResponse) -> Result<(), ThresholdError> {
        let topic = Self::group_topic_id(&self.config.group_id, self.config.network_id);
        let stream_id = SessionId::from(topic);
        debug!("publishing CRDT sync response state_count={}", response.states.len());
        let payload = TransportMessage::StateSyncResponse(response);
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = crate::foundation::now_nanos();
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id: stream_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };
        let bytes = encoding::encode_envelope(&envelope)?;
        self.publish_bytes(topic, bytes, "state_sync_response").await
    }

    async fn subscribe_group(&self, group_id: Hash32) -> Result<TransportSubscription, ThresholdError> {
        let topic = Self::group_topic_id(&group_id, self.config.network_id);
        let topic_id = TopicId::from(topic);
        info!("subscribing to group gossip topic={} bootstrap_peers={}", hex::encode(topic), self.bootstrap.len());
        let topic =
            self.gossip.subscribe(topic_id, self.bootstrap.clone()).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        let (sender, receiver) = topic.split();
        let keepalive: Box<dyn std::any::Any + Send> = Box::new(sender);
        Ok(subscription::subscribe_stream(self.verifier.clone(), self.storage.clone(), self.rate_limiter.clone(), receiver, keepalive))
    }
}
