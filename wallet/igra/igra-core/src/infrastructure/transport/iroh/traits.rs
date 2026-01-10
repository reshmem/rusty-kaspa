use crate::foundation::ThresholdError;
use crate::domain::SigningEvent;
use crate::foundation::{Hash32, PeerId, RequestId, SessionId};
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;

pub use crate::infrastructure::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
pub use crate::infrastructure::transport::messages::{
    FinalizeAck, FinalizeNotice, MessageEnvelope, PartialSigSubmit, SignerAck, SigningEventPropose, TransportMessage,
};

pub type Result<T> = std::result::Result<T, ThresholdError>;

#[derive(Clone, Debug)]
pub struct ProposedSigningSession {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub signing_event: SigningEvent,
    pub event_hash: Hash32,
    pub validation_hash: Hash32,
    pub coordinator_peer_id: PeerId,
    pub expires_at_nanos: u64,
    pub kpsbt_blob: Vec<u8>,
}

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
    async fn publish_proposal(&self, proposal: ProposedSigningSession) -> Result<()>;
    async fn publish_ack(&self, session_id: SessionId, ack: SignerAck) -> Result<()>;
    async fn publish_partial_sig(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        input_index: u32,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()>;
    async fn publish_finalize(&self, session_id: SessionId, request_id: &RequestId, final_tx_id: Hash32) -> Result<()>;
    async fn subscribe_group(&self, group_id: Hash32) -> Result<TransportSubscription>;
    async fn subscribe_session(&self, session_id: SessionId) -> Result<TransportSubscription>;
}
