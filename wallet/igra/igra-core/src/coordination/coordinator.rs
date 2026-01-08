use crate::config::PsktBuildConfig;
use crate::coordination::hashes::{event_hash, validation_hash};
use crate::error::ThresholdError;
use crate::kaspa_integration::build_pskt_from_rpc;
use crate::lifecycle::{LifecycleObserver, NoopObserver};
use crate::model::{Hash32, RequestDecision, SigningEvent, SigningRequest};
use crate::pskt::multisig as pskt_multisig;
use crate::rpc::NodeRpc;
use crate::storage::Storage;
use crate::transport::{ProposedSigningSession, SignerAck, Transport};
use crate::types::{PeerId, RequestId, SessionId, TransactionId};
use kaspa_wallet_pskt::prelude::Updater;
use secp256k1::PublicKey;
use std::sync::Arc;

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
            crate::model::StoredProposal {
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

    pub async fn propose_session_from_pskt(
        &self,
        session_id: SessionId,
        request_id: RequestId,
        signing_event: SigningEvent,
        pskt: kaspa_wallet_pskt::prelude::PSKT<Updater>,
        expires_at_nanos: u64,
        coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        let pskt_blob = pskt_multisig::serialize_pskt(&pskt)?;
        let signer_pskt = pskt_multisig::to_signer(pskt);
        let tx_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;
        let per_input_hashes = pskt_multisig::input_hashes(&signer_pskt)?;

        self.propose_session(
            session_id,
            request_id,
            signing_event,
            pskt_blob,
            tx_hash,
            &per_input_hashes,
            expires_at_nanos,
            coordinator_peer_id,
        )
        .await
    }

    pub async fn propose_session_from_rpc(
        &self,
        rpc: &dyn NodeRpc,
        pskt_config: &PsktBuildConfig,
        session_id: SessionId,
        request_id: RequestId,
        signing_event: SigningEvent,
        expires_at_nanos: u64,
        coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        let pskt = build_pskt_from_rpc(rpc, pskt_config).await?;
        self.propose_session_from_pskt(session_id, request_id, signing_event, pskt, expires_at_nanos, coordinator_peer_id).await
    }

    pub async fn finalize_and_submit_multisig(
        &self,
        rpc: &dyn NodeRpc,
        request_id: &RequestId,
        pskt: kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Combiner>,
        required_signatures: usize,
        ordered_pubkeys: &[PublicKey],
        params: &kaspa_consensus_core::config::params::Params,
    ) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
        let finalizer = pskt_multisig::finalize_multisig(pskt, required_signatures, ordered_pubkeys)?;
        let tx = pskt_multisig::extract_tx(finalizer, params)?;
        let tx_id = rpc.submit_transaction(tx).await?;
        let final_tx_id = TransactionId::from(tx_id);
        self.storage.update_request_final_tx(request_id, final_tx_id)?;
        Ok(tx_id)
    }

    pub async fn publish_ack(&self, session_id: SessionId, ack: SignerAck) -> Result<(), ThresholdError> {
        self.transport.publish_ack(session_id, ack).await
    }
}
