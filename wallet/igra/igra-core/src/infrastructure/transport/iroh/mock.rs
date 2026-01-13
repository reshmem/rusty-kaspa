use super::traits::{
    EventStateBroadcast, MessageEnvelope, StateSyncRequest, StateSyncResponse, Transport, TransportMessage, TransportSubscription,
};
use crate::foundation::Hash32;
use crate::foundation::ThresholdError;
use crate::foundation::{PeerId, SessionId};
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
        guard.entry(topic).or_insert_with(|| broadcast::channel(256).0).clone()
    }
}

impl Default for MockHub {
    fn default() -> Self {
        Self::new()
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
        Self { hub, sender_peer_id, group_id, network_id, seq: AtomicU64::new(1) }
    }

    fn group_topic_id(&self) -> Hash32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kaspa-sign/v1");
        hasher.update(&[self.network_id]);
        hasher.update(&self.group_id);
        *hasher.finalize().as_bytes()
    }

    fn payload_hash(payload: &TransportMessage) -> Result<Hash32, ThresholdError> {
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(payload)
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    async fn publish(&self, topic: Hash32, payload: TransportMessage) -> Result<(), ThresholdError> {
        let payload_hash = Self::payload_hash(&payload)?;
        let envelope = MessageEnvelope {
            sender_peer_id: self.sender_peer_id.clone(),
            group_id: self.group_id,
            session_id: SessionId::from(topic),
            seq_no: self.seq.fetch_add(1, Ordering::Relaxed),
            timestamp_nanos: crate::foundation::now_nanos(),
            payload,
            payload_hash,
            signature: Vec::new(),
        };
        let sender = self.hub.topic(topic).await;
        // `tokio::sync::broadcast::Sender::send` returns an error when there are no active receivers.
        // In real transports, publishing to a topic with no peers is not an error, so treat it as success.
        let _ = sender.send(envelope);
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
    async fn publish_event_state(&self, broadcast: EventStateBroadcast) -> Result<(), ThresholdError> {
        let payload = TransportMessage::EventStateBroadcast(broadcast);
        let topic = self.group_topic_id();
        self.publish(topic, payload).await
    }

    async fn publish_state_sync_request(&self, request: StateSyncRequest) -> Result<(), ThresholdError> {
        let payload = TransportMessage::StateSyncRequest(request);
        let topic = self.group_topic_id();
        self.publish(topic, payload).await
    }

    async fn publish_state_sync_response(&self, response: StateSyncResponse) -> Result<(), ThresholdError> {
        let payload = TransportMessage::StateSyncResponse(response);
        let topic = self.group_topic_id();
        self.publish(topic, payload).await
    }

    async fn subscribe_group(&self, _group_id: Hash32) -> Result<TransportSubscription, ThresholdError> {
        let topic = self.group_topic_id();
        self.subscribe(topic).await
    }
}
