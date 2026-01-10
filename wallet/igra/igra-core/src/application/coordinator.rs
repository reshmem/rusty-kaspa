use crate::application::lifecycle::{LifecycleObserver, NoopObserver};
use crate::domain::hashes::{event_hash, validation_hash};
use crate::domain::pskt::multisig as pskt_multisig;
use crate::domain::signing::aggregation;
use crate::domain::{RequestDecision, SigningEvent, SigningRequest, StoredProposal};
use crate::foundation::{Hash32, PeerId, RequestId, SessionId, ThresholdError, TransactionId};
use crate::infrastructure::config::PsktBuildConfig;
use crate::infrastructure::rpc::kaspa_integration::build_pskt_from_rpc;
use crate::infrastructure::rpc::NodeRpc;
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::iroh::traits::{ProposedSigningSession, SignerAck, Transport};
use kaspa_wallet_pskt::prelude::Combiner;
use secp256k1::PublicKey;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

pub struct Coordinator {
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl Coordinator {
    pub fn new(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>) -> Self {
        Self { transport, storage, lifecycle: Arc::new(NoopObserver) }
    }

    pub fn with_observer(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>, lifecycle: Arc<dyn LifecycleObserver>) -> Self {
        Self { transport, storage, lifecycle }
    }

    pub fn set_lifecycle_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.lifecycle = observer;
    }

    pub async fn propose_session(
        &self,
        session_id: SessionId,
        request_id: RequestId,
        signing_event: SigningEvent,
        kpsbt_blob: Vec<u8>,
        tx_template_hash: Hash32,
        per_input_hashes: &[Hash32],
        expires_at_nanos: u64,
        coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        validate_signing_event(&signing_event)?;
        let ev_hash = event_hash(&signing_event)?;
        let val_hash = validation_hash(&ev_hash, &tx_template_hash, per_input_hashes);

        self.lifecycle.on_event_received(&signing_event, &ev_hash);
        self.storage.insert_event(ev_hash, signing_event.clone())?;
        let request = SigningRequest {
            request_id: request_id.clone(),
            session_id,
            event_hash: ev_hash,
            coordinator_peer_id: coordinator_peer_id.clone(),
            tx_template_hash,
            validation_hash: val_hash,
            decision: RequestDecision::Pending,
            expires_at_nanos,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        };
        self.storage.insert_request(request.clone())?;
        self.lifecycle.on_request_created(&request);
        self.storage.insert_proposal(
            &request_id,
            StoredProposal {
                request_id: request_id.clone(),
                session_id,
                event_hash: ev_hash,
                validation_hash: val_hash,
                signing_event: signing_event.clone(),
                kpsbt_blob: kpsbt_blob.clone(),
            },
        )?;

        let proposal = ProposedSigningSession {
            request_id,
            session_id,
            signing_event,
            event_hash: ev_hash,
            validation_hash: val_hash,
            coordinator_peer_id,
            expires_at_nanos,
            kpsbt_blob,
        };
        self.transport.publish_proposal(proposal).await?;
        Ok(val_hash)
    }

    pub async fn propose_session_from_rpc(
        &self,
        rpc: &dyn NodeRpc,
        config: &PsktBuildConfig,
        session_id: SessionId,
        request_id: RequestId,
        signing_event: SigningEvent,
        expires_at_nanos: u64,
        coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        let pskt = build_pskt_from_rpc(rpc, config).await?;
        let pskt = pskt_multisig::to_signer(pskt);
        let per_input_hashes = pskt_multisig::input_hashes(&pskt)?;
        let tx_template_hash = pskt_multisig::tx_template_hash(&pskt)?;
        let kpsbt_blob = pskt_multisig::serialize_pskt(&pskt)?;
        self.propose_session(
            session_id,
            request_id,
            signing_event,
            kpsbt_blob,
            tx_template_hash,
            &per_input_hashes,
            expires_at_nanos,
            coordinator_peer_id,
        )
        .await
    }

    pub async fn finalize_and_submit_multisig(
        &self,
        rpc: &dyn NodeRpc,
        request_id: &RequestId,
        pskt: kaspa_wallet_pskt::prelude::PSKT<Combiner>,
        required_signatures: usize,
        ordered_pubkeys: &[PublicKey],
        params: &kaspa_consensus_core::config::params::Params,
    ) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
        let finalized = aggregation::finalize_pskt(pskt, required_signatures, ordered_pubkeys)?;
        let final_tx = pskt_multisig::extract_tx(finalized, params)?;

        let request = self
            .storage
            .get_request(request_id)?
            .ok_or_else(|| ThresholdError::KeyNotFound(format!("request {} missing before finalize", request_id)))?;

        let mut attempt = 0u32;
        let tx_id = loop {
            attempt += 1;
            match rpc.submit_transaction(final_tx.clone()).await {
                Ok(id) => break id,
                Err(err) if attempt < 4 => {
                    let backoff_ms = 100u64.saturating_mul(2u64.saturating_pow(attempt - 1));
                    tracing::warn!(request_id = %request_id, attempt, backoff_ms, error = %err, "submit_transaction failed; retrying");
                    sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }
                Err(err) => return Err(err),
            }
        };
        let tx_id = TransactionId::from(tx_id);
        self.storage.update_request_final_tx(request_id, tx_id)?;
        self.lifecycle.on_finalized(request_id, &tx_id);
        self.transport.publish_finalize(request.session_id, request_id, *tx_id.as_hash()).await?;
        Ok(kaspa_consensus_core::tx::TransactionId::from_bytes(*tx_id.as_hash()))
    }

    pub async fn collect_acks(
        &self,
        session_id: SessionId,
        request_id: &RequestId,
        timeout: Duration,
        threshold: usize,
    ) -> Result<Vec<SignerAck>, ThresholdError> {
        let mut subscription = self.transport.subscribe_session(session_id).await?;
        let mut acks = Vec::new();
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, subscription.next()).await {
                Ok(Some(Ok(envelope))) => {
                    if let crate::infrastructure::transport::messages::TransportMessage::SignerAck(ack) = envelope.payload {
                        if &ack.request_id == request_id {
                            acks.push(ack);
                            if threshold > 0 && acks.len() >= threshold {
                                break;
                            }
                        }
                    }
                }
                Ok(Some(Err(err))) => return Err(err),
                Ok(None) | Err(_) => break,
            }
        }
        Ok(acks)
    }
}

fn validate_signing_event(event: &SigningEvent) -> Result<(), ThresholdError> {
    if event.destination_address.trim().is_empty() {
        return Err(ThresholdError::Message("destination_address required".to_string()));
    }
    if event.amount_sompi == 0 {
        return Err(ThresholdError::Message("amount_sompi must be > 0".to_string()));
    }
    if event.derivation_path.trim().is_empty() {
        return Err(ThresholdError::InvalidDerivationPath("missing derivation_path".to_string()));
    }
    Ok(())
}
