use crate::foundation::ThresholdError;
use crate::foundation::util::time;
use crate::infrastructure::transport::iroh::{config::IrohConfig, encoding, subscription};
use crate::foundation::Hash32;
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::RateLimiter;
use super::traits::{
    FinalizeNotice, MessageEnvelope, PartialSigSubmit, ProposedSigningSession, SignatureSigner, SignatureVerifier, SignerAck,
    SigningEventPropose, Transport, TransportMessage, TransportSubscription,
};
use crate::foundation::{RequestId, SessionId};
use async_trait::async_trait;
use iroh::EndpointId;
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

// Maximum message size: 10 MB (allows for PSKT with many inputs)
// PSKT blob size: ~1KB base + ~200 bytes per input × 100 inputs = ~21KB
// 10 MB provides comfortable headroom while preventing DoS
use crate::foundation::constants::MAX_MESSAGE_SIZE_BYTES;
const MAX_MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE_BYTES;
const PUBLISH_RETRY_ATTEMPTS: usize = 3;
const PUBLISH_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

pub struct IrohTransport {
    gossip: Gossip,
    signer: Arc<dyn SignatureSigner>,
    verifier: Arc<dyn SignatureVerifier>,
    storage: Arc<dyn Storage>,
    rate_limiter: Arc<RateLimiter>,
    config: IrohConfig,
    bootstrap: Vec<EndpointId>,
    seq: std::sync::atomic::AtomicU64,
}

impl IrohTransport {
    pub fn new(
        gossip: Gossip,
        signer: Arc<dyn SignatureSigner>,
        verifier: Arc<dyn SignatureVerifier>,
        storage: Arc<dyn Storage>,
        config: IrohConfig,
    ) -> Result<Self, ThresholdError> {
        let bootstrap = config
            .bootstrap_nodes
            .iter()
            .filter_map(|node_id| match EndpointId::from_str(node_id) {
                Ok(id) => Some(id),
                Err(err) => {
                    tracing::warn!(node_id = node_id.as_str(), error = %err, "invalid bootstrap node, skipping");
                    None
                }
            })
            .collect::<Vec<_>>();

        if !config.bootstrap_nodes.is_empty() && bootstrap.is_empty() {
            return Err(ThresholdError::ConfigError("no valid iroh.bootstrap nodes".to_string()));
        }

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

    fn now_nanos() -> u64 { time::current_timestamp_nanos_env(Some("KASPA_IGRA_TEST_NOW_NANOS")).unwrap_or(0) }

    async fn publish_bytes(&self, topic: Hash32, bytes: Vec<u8>) -> Result<(), ThresholdError> {
        // Enforce message size limit to prevent memory exhaustion attacks
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(ThresholdError::MessageTooLarge { size: bytes.len(), max: MAX_MESSAGE_SIZE });
        }

        let topic_id = TopicId::from(topic);
        let mut last_err: Option<String> = None;
        debug!(
            topic = %hex::encode(topic_id.as_bytes()),
            byte_len = bytes.len(),
            bootstrap_peers = self.bootstrap.len(),
            "publishing gossip message"
        );
        for attempt in 0..PUBLISH_RETRY_ATTEMPTS {
            let mut topic = match self.gossip.subscribe(topic_id, self.bootstrap.clone()).await {
                Ok(topic) => topic,
                Err(err) => {
                    last_err = Some(err.to_string());
                    warn!(
                        attempt = attempt + 1,
                        topic = %hex::encode(topic_id.as_bytes()),
                        error = %last_err.as_ref().unwrap(),
                        "failed to subscribe for publish"
                    );
                    if attempt + 1 < PUBLISH_RETRY_ATTEMPTS {
                        tokio::time::sleep(PUBLISH_RETRY_DELAY).await;
                    }
                    continue;
                }
            };
            match topic.broadcast(bytes.clone().into()).await {
                Ok(()) => {
                    info!(
                        attempt = attempt + 1,
                        topic = %hex::encode(topic_id.as_bytes()),
                        byte_len = bytes.len(),
                        "published gossip message"
                    );
                    return Ok(());
                }
                Err(err) => {
                    last_err = Some(err.to_string());
                    warn!(
                        attempt = attempt + 1,
                        topic = %hex::encode(topic_id.as_bytes()),
                        error = %last_err.as_ref().unwrap(),
                        "failed to broadcast gossip message"
                    );
                    if attempt + 1 < PUBLISH_RETRY_ATTEMPTS {
                        tokio::time::sleep(PUBLISH_RETRY_DELAY).await;
                    }
                }
            }
        }
        Err(ThresholdError::Message(
            last_err.unwrap_or_else(|| "failed to publish gossip message".to_string()),
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
        let payload = TransportMessage::SigningEventPropose(SigningEventPropose {
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
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id: proposal.session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
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
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
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
        let payload = TransportMessage::PartialSigSubmit(PartialSigSubmit {
            request_id: request_id.clone(),
            input_index,
            pubkey,
            signature,
        });
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = Self::now_nanos();
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
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
        let payload = TransportMessage::FinalizeNotice(FinalizeNotice { request_id: request_id.clone(), final_tx_id });
        let payload_hash = encoding::payload_hash(&payload)?;
        let timestamp_nanos = Self::now_nanos();
        let envelope = MessageEnvelope {
            sender_peer_id: self.signer.sender_peer_id().clone(),
            group_id: self.config.group_id,
            session_id,
            seq_no: self.seq.fetch_add(1, std::sync::atomic::Ordering::AcqRel),
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
        info!(
            topic = %hex::encode(topic),
            bootstrap_peers = self.bootstrap.len(),
            "subscribing to group gossip"
        );
        let topic =
            self.gossip.subscribe(topic_id, self.bootstrap.clone()).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        let (sender, receiver) = topic.split();
        let keepalive: Box<dyn std::any::Any + Send> = Box::new(sender);
        Ok(subscription::subscribe_stream(self.verifier.clone(), self.storage.clone(), self.rate_limiter.clone(), receiver, keepalive))
    }

    async fn subscribe_session(&self, session_id: SessionId) -> Result<TransportSubscription, ThresholdError> {
        let topic = Self::session_topic_id(&session_id);
        let topic_id = TopicId::from(topic);
        info!(
            topic = %hex::encode(topic),
            bootstrap_peers = self.bootstrap.len(),
            session_id = %hex::encode(session_id.as_hash()),
            "subscribing to session gossip"
        );
        let topic =
            self.gossip.subscribe(topic_id, self.bootstrap.clone()).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        let (sender, receiver) = topic.split();
        let keepalive: Box<dyn std::any::Any + Send> = Box::new(sender);
        Ok(subscription::subscribe_stream(self.verifier.clone(), self.storage.clone(), self.rate_limiter.clone(), receiver, keepalive))
    }
}
