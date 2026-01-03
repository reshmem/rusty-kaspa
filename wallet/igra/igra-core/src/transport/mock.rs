use crate::error::ThresholdError;
use crate::model::Hash32;
use crate::transport::{
    FinalizeNotice, MessageEnvelope, PartialSigSubmit, ProposedSigningSession, SignerAck, SigningEventPropose,
    Transport, TransportMessage, TransportSubscription,
};
use crate::types::{PeerId, RequestId, SessionId};
use async_trait::async_trait;
use bincode::Options;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

pub struct MockHub {
    topics: Mutex<HashMap<Hash32, broadcast::Sender<MessageEnvelope>>>,
}

impl MockHub {
    pub fn new() -> Self {
        Self { topics: Mutex::new(HashMap::new()) }
    }

    async fn topic(&self, topic: Hash32) -> broadcast::Sender<MessageEnvelope> {
        let mut guard = self.topics.lock().await;
        guard
            .entry(topic)
            .or_insert_with(|| broadcast::channel(256).0)
            .clone()
    }
}

pub struct MockTransport {
    hub: Arc<MockHub>,
    sender_peer_id: PeerId,
    group_id: Hash32,
    network_id: u8,
    seq: AtomicU64,
}

impl MockTransport {
    pub fn new(hub: Arc<MockHub>, sender_peer_id: PeerId, group_id: Hash32, network_id: u8) -> Self {
        Self {
            hub,
            sender_peer_id,
            group_id,
            network_id,
            seq: AtomicU64::new(1),
        }
    }

    fn group_topic_id(&self) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kaspa-sign/v1");
        hasher.update(&[self.network_id]);
        hasher.update(&self.group_id);
        *hasher.finalize().as_bytes()
    }

    fn session_topic_id(session_id: &SessionId) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kaspa-sign/session/v1");
        hasher.update(session_id.as_hash());
        *hasher.finalize().as_bytes()
    }

    fn payload_hash(payload: &TransportMessage) -> Result<Hash32, ThresholdError> {
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(payload)
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    fn now_nanos() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    async fn publish(&self, topic: Hash32, session_id: SessionId, payload: TransportMessage) -> Result<(), ThresholdError> {
        let payload_hash = Self::payload_hash(&payload)?;
        let envelope = MessageEnvelope {
            sender_peer_id: self.sender_peer_id.clone(),
            group_id: self.group_id,
            session_id,
            seq_no: self.seq.fetch_add(1, Ordering::Relaxed),
            timestamp_nanos: Self::now_nanos(),
            payload,
            payload_hash,
            signature: Vec::new(),
        };
        let sender = self.hub.topic(topic).await;
        sender
            .send(envelope)
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        Ok(())
    }

    async fn subscribe(&self, topic: Hash32) -> Result<TransportSubscription, ThresholdError> {
        let sender = self.hub.topic(topic).await;
        let mut receiver = sender.subscribe();
        let stream = async_stream::stream! {
            loop {
                match receiver.recv().await {
                    Ok(envelope) => yield Ok(envelope),
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        yield Err(ThresholdError::Message("mock transport lagged".to_string()));
                    }
                }
            }
        };
        Ok(TransportSubscription::new(Box::pin(stream)))
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn publish_proposal(&self, proposal: ProposedSigningSession) -> Result<(), ThresholdError> {
        let payload = TransportMessage::SigningEventPropose(SigningEventPropose {
            request_id: proposal.request_id,
            event_hash: proposal.event_hash,
            validation_hash: proposal.validation_hash,
            coordinator_peer_id: proposal.coordinator_peer_id,
            expires_at_nanos: proposal.expires_at_nanos,
            signing_event: proposal.signing_event,
            kpsbt_blob: proposal.kpsbt_blob,
        });
        let topic = self.group_topic_id();
        self.publish(topic, proposal.session_id, payload).await
    }

    async fn publish_ack(&self, session_id: SessionId, ack: SignerAck) -> Result<(), ThresholdError> {
        let payload = TransportMessage::SignerAck(ack);
        let topic = Self::session_topic_id(&session_id);
        self.publish(topic, session_id, payload).await
    }

    async fn publish_partial_sig(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        input_index: u32,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), ThresholdError> {
        let payload = TransportMessage::PartialSigSubmit(PartialSigSubmit {
            request_id: request_id.clone(),
            input_index,
            pubkey,
            signature,
        });
        let topic = Self::session_topic_id(&session_id);
        self.publish(topic, session_id, payload).await
    }

    async fn publish_finalize(&self, session_id: SessionId, request_id: &RequestId, final_tx_id: Hash32) -> Result<(), ThresholdError> {
        let payload = TransportMessage::FinalizeNotice(FinalizeNotice { request_id: request_id.clone(), final_tx_id });
        let topic = Self::session_topic_id(&session_id);
        self.publish(topic, session_id, payload).await
    }

    async fn subscribe_group(&self, _group_id: Hash32) -> Result<TransportSubscription, ThresholdError> {
        let topic = self.group_topic_id();
        self.subscribe(topic).await
    }

    async fn subscribe_session(&self, session_id: SessionId) -> Result<TransportSubscription, ThresholdError> {
        let topic = Self::session_topic_id(&session_id);
        self.subscribe(topic).await
    }
}
