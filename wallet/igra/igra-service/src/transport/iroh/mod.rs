mod encoding;
mod filtering;
mod subscription;

use crate::transport::{ProposedSigningSession, SignerAck, Transport, TransportMessage, TransportSubscription};
use async_trait::async_trait;
use igra_core::error::ThresholdError;
use igra_core::model::Hash32;
use igra_core::rate_limit::RateLimiter;
use igra_core::storage::Storage;
use igra_core::types::{RequestId, SessionId};
use iroh::EndpointId;
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;
use std::str::FromStr;
use std::sync::Arc;

// Maximum message size: 10 MB (allows for PSKT with many inputs)
// PSKT blob size: ~1KB base + ~200 bytes per input × 100 inputs = ~21KB
// 10 MB provides comfortable headroom while preventing DoS
const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
const PUBLISH_RETRY_ATTEMPTS: usize = 3;
const PUBLISH_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

pub struct IrohConfig {
    pub network_id: u8,
    pub group_id: Hash32,
    pub bootstrap_nodes: Vec<String>,
}

pub struct IrohTransport {
    gossip: Gossip,
    signer: Arc<dyn crate::transport::SignatureSigner>,
    verifier: Arc<dyn crate::transport::SignatureVerifier>,
    storage: Arc<dyn Storage>,
    rate_limiter: Arc<RateLimiter>,
    config: IrohConfig,
    bootstrap: Vec<EndpointId>,
    seq: std::sync::atomic::AtomicU64,
}

impl IrohTransport {
    pub fn new(
        gossip: Gossip,
        signer: Arc<dyn crate::transport::SignatureSigner>,
        verifier: Arc<dyn crate::transport::SignatureVerifier>,
        storage: Arc<dyn Storage>,
        config: IrohConfig,
    ) -> Result<Self, ThresholdError> {
        let bootstrap = config
            .bootstrap_nodes
            .iter()
            .map(|node_id| EndpointId::from_str(node_id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ThresholdError::Message(err.to_string()))?;

        // Create rate limiter: 100 messages burst, 10 messages/sec sustained per peer
        let rate_limiter = Arc::new(RateLimiter::new(100.0, 10.0));

        Ok(Self { gossip, signer, verifier, storage, rate_limiter, config, bootstrap, seq: std::sync::atomic::AtomicU64::new(1) })
    }

    fn group_topic_id(group_id: &Hash32, network_id: u8) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kaspa-sign/v1");
        hasher.update(&[network_id]);
        hasher.update(group_id);
        *hasher.finalize().as_bytes()
    }

    fn session_topic_id(session_id: &SessionId) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kaspa-sign/session/v1");
        hasher.update(session_id.as_hash());
        *hasher.finalize().as_bytes()
    }

    fn now_nanos() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
    }

    async fn publish_bytes(&self, topic: Hash32, bytes: Vec<u8>) -> Result<(), ThresholdError> {
        // Enforce message size limit to prevent memory exhaustion attacks
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(ThresholdError::Message(format!(
                "message size {} exceeds maximum allowed size {}",
                bytes.len(),
                MAX_MESSAGE_SIZE
            )));
        }

        let topic_id = TopicId::from(topic);
        let mut last_err = None;
        for attempt in 0..PUBLISH_RETRY_ATTEMPTS {
            let mut topic = match self.gossip.subscribe(topic_id, self.bootstrap.clone()).await {
                Ok(topic) => topic,
                Err(err) => {
                    last_err = Some(err);
                    if attempt + 1 < PUBLISH_RETRY_ATTEMPTS {
                        tokio::time::sleep(PUBLISH_RETRY_DELAY).await;
                    }
                    continue;
                }
            };
            match topic.broadcast(bytes.clone().into()).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    last_err = Some(err);
                    if attempt + 1 < PUBLISH_RETRY_ATTEMPTS {
                        tokio::time::sleep(PUBLISH_RETRY_DELAY).await;
                    }
                }
            }
        }
        Err(ThresholdError::Message(
            last_err.map(|err| err.to_string()).unwrap_or_else(|| "failed to publish gossip message".to_string()),
        ))
    }
}

#[async_trait]
impl Transport for IrohTransport {
    async fn publish_proposal(&self, proposal: ProposedSigningSession) -> Result<(), ThresholdError> {
        tracing::debug!(
            session_id = %hex::encode(proposal.session_id.as_hash()),
            request_id = %proposal.request_id,
            "publishing proposal"
        );
        let payload = TransportMessage::SigningEventPropose(crate::transport::SigningEventPropose {
            request_id: proposal.request_id,
            event_hash: proposal.event_hash,
            validation_hash: proposal.validation_hash,
            coordinator_peer_id: proposal.coordinator_peer_id,
            expires_at_nanos: proposal.expires_at_nanos,
            signing_event: proposal.signing_event,
            kpsbt_blob: proposal.kpsbt_blob,
        });

        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = Self::now_nanos();
        filtering::record_payload(&self.storage, self.signer.sender_peer_id(), proposal.session_id, timestamp_nanos, &payload)?;
        let envelope = crate::transport::MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id: proposal.session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };

        let bytes = encoding::encode_envelope(&envelope)?;
        let topic = Self::group_topic_id(&self.config.group_id, self.config.network_id);
        self.publish_bytes(topic, bytes).await
    }

    async fn publish_ack(&self, session_id: SessionId, ack: SignerAck) -> Result<(), ThresholdError> {
        tracing::debug!(
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %ack.request_id,
            accepted = ack.accept,
            "publishing signer ack"
        );
        let payload = TransportMessage::SignerAck(ack);
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = Self::now_nanos();
        filtering::record_payload(&self.storage, self.signer.sender_peer_id(), session_id, timestamp_nanos, &payload)?;
        let envelope = crate::transport::MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };
        let bytes = encoding::encode_envelope(&envelope)?;
        let topic = Self::session_topic_id(&session_id);
        self.publish_bytes(topic, bytes).await
    }

    async fn publish_partial_sig(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        input_index: u32,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), ThresholdError> {
        tracing::debug!(
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %request_id,
            input_index,
            "publishing partial signature"
        );
        let payload = TransportMessage::PartialSigSubmit(crate::transport::PartialSigSubmit {
            request_id: request_id.clone(),
            input_index,
            pubkey,
            signature,
        });
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = Self::now_nanos();
        filtering::record_payload(&self.storage, self.signer.sender_peer_id(), session_id, timestamp_nanos, &payload)?;
        let envelope = crate::transport::MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };
        let bytes = encoding::encode_envelope(&envelope)?;
        let topic = Self::session_topic_id(&session_id);
        self.publish_bytes(topic, bytes).await
    }

    async fn publish_finalize(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        final_tx_id: Hash32,
    ) -> Result<(), ThresholdError> {
        tracing::debug!(
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %request_id,
            final_tx_id = %hex::encode(final_tx_id),
            "publishing finalize notice"
        );
        let payload =
            TransportMessage::FinalizeNotice(crate::transport::FinalizeNotice { request_id: request_id.clone(), final_tx_id });
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = Self::now_nanos();
        filtering::record_payload(&self.storage, self.signer.sender_peer_id(), session_id, timestamp_nanos, &payload)?;
        let envelope = crate::transport::MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            timestamp_nanos,
            payload,
            payload_hash,
            signature: self.signer.sign(&payload_hash),
        };
        let bytes = encoding::encode_envelope(&envelope)?;
        let topic = Self::session_topic_id(&session_id);
        self.publish_bytes(topic, bytes).await
    }

    async fn subscribe_group(&self, group_id: Hash32) -> Result<TransportSubscription, ThresholdError> {
        let topic = Self::group_topic_id(&group_id, self.config.network_id);
        let topic_id = TopicId::from(topic);
        let topic =
            self.gossip.subscribe(topic_id, self.bootstrap.clone()).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        let (sender, receiver) = topic.split();
        let keepalive: Box<dyn std::any::Any + Send> = Box::new(sender);
        Ok(subscription::subscribe_stream(self.verifier.clone(), self.storage.clone(), self.rate_limiter.clone(), receiver, keepalive))
    }

    async fn subscribe_session(&self, session_id: SessionId) -> Result<TransportSubscription, ThresholdError> {
        let topic = Self::session_topic_id(&session_id);
        let topic_id = TopicId::from(topic);
        let topic =
            self.gossip.subscribe(topic_id, self.bootstrap.clone()).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        let (sender, receiver) = topic.split();
        let keepalive: Box<dyn std::any::Any + Send> = Box::new(sender);
        Ok(subscription::subscribe_stream(self.verifier.clone(), self.storage.clone(), self.rate_limiter.clone(), receiver, keepalive))
    }
}
