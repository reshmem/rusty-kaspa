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
use tracing::{debug, error, info, trace, warn};

pub struct Coordinator {
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    lifecycle: Arc<dyn LifecycleObserver>,
}

impl Coordinator {
    pub fn new(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>) -> Self {
        debug!("coordinator created");
        Self { transport, storage, lifecycle: Arc::new(NoopObserver) }
    }

    pub fn with_observer(transport: Arc<dyn Transport>, storage: Arc<dyn Storage>, lifecycle: Arc<dyn LifecycleObserver>) -> Self {
        info!("coordinator created with lifecycle observer");
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
        let session_id_hex = hex::encode(session_id.as_hash());
        let request_id_str = request_id.to_string();
        let coordinator_peer_id_str = coordinator_peer_id.to_string();
        let event_id = signing_event.event_id.clone();
        let span = tracing::info_span!(
            "propose_session",
            session_id = %session_id_hex,
            request_id = %request_id_str,
            event_id = %event_id,
            expires_at_nanos,
            coordinator_peer_id = %coordinator_peer_id_str,
        );
        let _entered = span.enter();

        if let Err(err) = validate_signing_event(&signing_event) {
            warn!(
                event_id = %signing_event.event_id,
                destination_address = %signing_event.destination_address,
                amount_sompi = signing_event.amount_sompi,
                derivation_path = %signing_event.derivation_path,
                error = %err,
                "invalid signing event"
            );
            return Err(err);
        }
        let ev_hash = event_hash(&signing_event)?;
        let val_hash = validation_hash(&ev_hash, &tx_template_hash, per_input_hashes);
        info!(
            event_hash = %hex::encode(ev_hash),
            validation_hash = %hex::encode(val_hash),
            kpsbt_len = kpsbt_blob.len(),
            input_count = per_input_hashes.len(),
            "storing proposal"
        );

        self.lifecycle.on_event_received(&signing_event, &ev_hash);
        self.storage.insert_event(ev_hash, signing_event.clone())?;
        debug!(event_hash = %hex::encode(ev_hash), "event stored");
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
        debug!(request_id = %request.request_id, "request stored");
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
        trace!(
            session_id = %hex::encode(proposal.session_id.as_hash()),
            request_id = %proposal.request_id,
            event_hash = %hex::encode(proposal.event_hash),
            validation_hash = %hex::encode(proposal.validation_hash),
            kpsbt_len = proposal.kpsbt_blob.len(),
            "publishing proposal"
        );
        if let Err(err) = self.transport.publish_proposal(proposal).await {
            error!(error = %err, "failed to publish proposal");
            return Err(err);
        }
        debug!("proposal published");
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
        let session_id_hex = hex::encode(session_id.as_hash());
        let request_id_str = request_id.to_string();
        let event_id = signing_event.event_id.clone();
        info!(
            session_id = %session_id_hex,
            request_id = %request_id_str,
            event_id = %event_id,
            "building PSKT via rpc for proposal"
        );
        let (selection, build) = build_pskt_from_rpc(rpc, config).await?;
        debug!(
            selected_utxos = selection.selected_utxos,
            total_input = selection.total_input_amount,
            total_output = selection.total_output_amount,
            fee = selection.fee_amount,
            change = selection.change_amount,
            has_change = selection.has_change_output,
            "utxo selection completed"
        );
        let output_count = build.output_count;
        let pskt = pskt_multisig::to_signer(build.pskt);
        let per_input_hashes = pskt_multisig::input_hashes(&pskt)?;
        let tx_template_hash = pskt_multisig::tx_template_hash(&pskt)?;
        debug!(
            session_id = %session_id_hex,
            request_id = %request_id_str,
            input_count = per_input_hashes.len(),
            output_count,
            tx_template_hash = %hex::encode(tx_template_hash),
            sig_op_count = config.sig_op_count,
            outputs = config.outputs.len(),
            source_addresses = config.source_addresses.len(),
            "PSKT built"
        );
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
        info!(
            request_id = %request_id,
            required_signatures,
            pubkey_count = ordered_pubkeys.len(),
            "finalizing PSKT and submitting transaction"
        );
        let finalize_result = aggregation::finalize_pskt(pskt, required_signatures, ordered_pubkeys)?;
        debug!(
            input_count = finalize_result.input_count,
            required = finalize_result.required_signatures,
            signatures_per_input = ?finalize_result.signatures_per_input,
            "PSKT finalized"
        );
        let tx_result = pskt_multisig::extract_tx(finalize_result.pskt, params)?;
        info!(
            tx_id = %hex::encode(tx_result.tx_id),
            input_count = tx_result.input_count,
            output_count = tx_result.output_count,
            mass = tx_result.mass,
            "transaction extracted"
        );
        let final_tx = tx_result.tx.clone();

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
                Err(err) => {
                    error!(request_id = %request_id, attempt, error = %err, "submit_transaction failed after retries");
                    return Err(err);
                }
            }
        };
        let tx_id = TransactionId::from(tx_id);
        info!(
            request_id = %request_id,
            tx_id = %hex::encode(tx_id.as_hash()),
            attempts = attempt,
            "transaction submitted"
        );
        self.storage.update_request_final_tx(request_id, tx_id)?;
        info!(request_id = %request_id, tx_id = %hex::encode(tx_id.as_hash()), "stored finalized tx_id");
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
        let session_id_hex = hex::encode(session_id.as_hash());
        debug!(
            session_id = %session_id_hex,
            request_id = %request_id,
            threshold,
            timeout_ms = timeout.as_millis(),
            "collecting signer acks"
        );
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
                            debug!(session_id = %session_id_hex, ack_count = acks.len(), "ack collected");
                            if threshold > 0 && acks.len() >= threshold {
                                debug!(session_id = %session_id_hex, ack_count = acks.len(), "ack threshold reached");
                                break;
                            }
                        }
                    }
                }
                Ok(Some(Err(err))) => return Err(err),
                Ok(None) | Err(_) => break,
            }
        }
        info!(session_id = %session_id_hex, request_id = %request_id, ack_count = acks.len(), "ack collection complete");
        Ok(acks)
    }
}

fn validate_signing_event(event: &SigningEvent) -> Result<(), ThresholdError> {
    if event.destination_address.trim().is_empty() {
        warn!(event_id = %event.event_id, "validation failed: destination_address required");
        return Err(ThresholdError::Message("destination_address required".to_string()));
    }
    if event.amount_sompi == 0 {
        warn!(event_id = %event.event_id, "validation failed: amount_sompi must be > 0");
        return Err(ThresholdError::Message("amount_sompi must be > 0".to_string()));
    }
    if event.derivation_path.trim().is_empty() {
        warn!(event_id = %event.event_id, "validation failed: missing derivation_path");
        return Err(ThresholdError::InvalidDerivationPath("missing derivation_path".to_string()));
    }
    Ok(())
}
