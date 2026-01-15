use crate::foundation::ThresholdError;
use crate::foundation::{Hash32, PeerId};
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;

pub use crate::infrastructure::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
pub use crate::infrastructure::transport::messages::{
    CompletionRecord, CrdtSignature, EventCrdtState, EventStateBroadcast, MessageEnvelope, ProposalBroadcast, StateSyncRequest,
    StateSyncResponse, TransportMessage,
};

pub type Result<T> = std::result::Result<T, ThresholdError>;

pub struct TransportSubscription {
    inner: BoxStream<'static, Result<MessageEnvelope>>,
    _keepalive: Option<Box<dyn std::any::Any + Send>>,
}

impl TransportSubscription {
    pub fn new(inner: BoxStream<'static, Result<MessageEnvelope>>) -> Self {
        Self { inner, _keepalive: None }
    }

    pub fn new_with_keepalive(inner: BoxStream<'static, Result<MessageEnvelope>>, keepalive: Box<dyn std::any::Any + Send>) -> Self {
        Self { inner, _keepalive: Some(keepalive) }
    }

    pub async fn next(&mut self) -> Option<Result<MessageEnvelope>> {
        self.inner.next().await
    }
}

pub trait SignatureSigner: Send + Sync {
    fn sender_peer_id(&self) -> &PeerId;
    fn sign(&self, payload_hash: &Hash32) -> Vec<u8>;
}

pub trait SignatureVerifier: Send + Sync {
    fn verify(&self, sender_peer_id: &PeerId, payload_hash: &Hash32, signature: &[u8]) -> bool;
}

#[derive(Clone, Debug)]
pub struct NoopSignatureVerifier;

impl SignatureVerifier for NoopSignatureVerifier {
    fn verify(&self, _sender_peer_id: &PeerId, _payload_hash: &Hash32, _signature: &[u8]) -> bool {
        true
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn publish_event_state(&self, broadcast: EventStateBroadcast) -> Result<()>;
    async fn publish_proposal(&self, proposal: ProposalBroadcast) -> Result<()>;
    async fn publish_state_sync_request(&self, request: StateSyncRequest) -> Result<()>;
    async fn publish_state_sync_response(&self, response: StateSyncResponse) -> Result<()>;
    async fn subscribe_group(&self, group_id: Hash32) -> Result<TransportSubscription>;
}
