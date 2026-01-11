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
use log::{debug, error, info, trace, warn};
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
        info!(
            "propose_session session_id={} request_id={} event_id={} expires_at_nanos={} coordinator_peer_id={}",
            session_id_hex, request_id_str, event_id, expires_at_nanos, coordinator_peer_id_str
        );

        if let Err(err) = validate_signing_event(&signing_event) {
            warn!(
                "invalid signing event event_id={} destination_address={} amount_sompi={} derivation_path={} error={}",
                signing_event.event_id, signing_event.destination_address, signing_event.amount_sompi, signing_event.derivation_path, err
            );
            return Err(err);
        }
        let ev_hash = event_hash(&signing_event)?;
        let val_hash = validation_hash(&ev_hash, &tx_template_hash, per_input_hashes);
        info!(
            "storing proposal event_hash={} validation_hash={} kpsbt_len={} input_count={}",
            hex::encode(ev_hash),
            hex::encode(val_hash),
            kpsbt_blob.len(),
            per_input_hashes.len()
        );

        self.lifecycle.on_event_received(&signing_event, &ev_hash);
        match self.storage.insert_event(ev_hash, signing_event.clone()) {
            Ok(()) => debug!("event stored event_hash={}", hex::encode(ev_hash)),
            Err(ThresholdError::EventReplayed(_)) => {
                debug!("event already stored event_hash={}", hex::encode(ev_hash));
            }
            Err(err) => return Err(err),
        }
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
        debug!("request stored request_id={}", request.request_id);
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
            "publishing proposal session_id={} request_id={} event_hash={} validation_hash={} kpsbt_len={}",
            hex::encode(proposal.session_id.as_hash()),
            proposal.request_id,
            hex::encode(proposal.event_hash),
            hex::encode(proposal.validation_hash),
            proposal.kpsbt_blob.len()
        );
        if let Err(err) = self.transport.publish_proposal(proposal).await {
            error!("failed to publish proposal error={}", err);
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
            "building PSKT via rpc for proposal session_id={} request_id={} event_id={}",
            session_id_hex, request_id_str, event_id
        );
        let (selection, build) = build_pskt_from_rpc(rpc, config).await?;
        debug!(
            "utxo selection completed selected_utxos={:?} total_input={:?} total_output={:?} fee={:?} change={:?} has_change={:?}",
            selection.selected_utxos,
            selection.total_input_amount,
            selection.total_output_amount,
            selection.fee_amount,
            selection.change_amount,
            selection.has_change_output
        );
        let output_count = build.output_count;
        let pskt = pskt_multisig::to_signer(build.pskt);
        let per_input_hashes = pskt_multisig::input_hashes(&pskt)?;
        let tx_template_hash = pskt_multisig::tx_template_hash(&pskt)?;
        debug!(
            "PSKT built session_id={} request_id={} input_count={} output_count={} tx_template_hash={} sig_op_count={} outputs={} source_addresses={}",
            session_id_hex,
            request_id_str,
            per_input_hashes.len(),
            output_count,
            hex::encode(tx_template_hash),
            config.sig_op_count,
            config.outputs.len(),
            config.source_addresses.len()
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
            "finalizing PSKT and submitting transaction request_id={} required_signatures={} pubkey_count={}",
            request_id,
            required_signatures,
            ordered_pubkeys.len()
        );
        let finalize_result = aggregation::finalize_pskt(pskt, required_signatures, ordered_pubkeys)?;
        debug!(
            "PSKT finalized input_count={} required={} signatures_per_input={:?}",
            finalize_result.input_count, finalize_result.required_signatures, finalize_result.signatures_per_input
        );
        let tx_result = pskt_multisig::extract_tx(finalize_result.pskt, params)?;
        info!(
            "transaction extracted tx_id={} input_count={} output_count={} mass={}",
            hex::encode(tx_result.tx_id),
            tx_result.input_count,
            tx_result.output_count,
            tx_result.mass
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
                    warn!(
                        "submit_transaction failed; retrying request_id={} attempt={} backoff_ms={} error={}",
                        request_id, attempt, backoff_ms, err
                    );
                    sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }
                Err(err) => {
                    error!(
                        "submit_transaction failed after retries request_id={} attempt={} error={}",
                        request_id, attempt, err
                    );
                    return Err(err);
                }
            }
        };
        let tx_id = TransactionId::from(tx_id);
        info!(
            "transaction submitted request_id={} tx_id={} attempts={}",
            request_id,
            hex::encode(tx_id.as_hash()),
            attempt
        );
        self.storage.update_request_final_tx(request_id, tx_id)?;
        info!("stored finalized tx_id request_id={} tx_id={}", request_id, hex::encode(tx_id.as_hash()));
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
            "collecting signer acks session_id={} request_id={} threshold={} timeout_ms={}",
            session_id_hex,
            request_id,
            threshold,
            timeout.as_millis()
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
                            debug!("ack collected session_id={} ack_count={}", session_id_hex, acks.len());
                            if threshold > 0 && acks.len() >= threshold {
                                debug!("ack threshold reached session_id={} ack_count={}", session_id_hex, acks.len());
                                break;
                            }
                        }
                    }
                }
                Ok(Some(Err(err))) => return Err(err),
                Ok(None) | Err(_) => break,
            }
        }
        info!(
            "ack collection complete session_id={} request_id={} ack_count={}",
            session_id_hex,
            request_id,
            acks.len()
        );
        Ok(acks)
    }
}

fn validate_signing_event(event: &SigningEvent) -> Result<(), ThresholdError> {
    if event.destination_address.trim().is_empty() {
        warn!("validation failed: destination_address required event_id={}", event.event_id);
        return Err(ThresholdError::Message("destination_address required".to_string()));
    }
    if event.amount_sompi == 0 {
        warn!("validation failed: amount_sompi must be > 0 event_id={}", event.event_id);
        return Err(ThresholdError::Message("amount_sompi must be > 0".to_string()));
    }
    if event.derivation_path.trim().is_empty() {
        warn!("validation failed: missing derivation_path event_id={}", event.event_id);
        return Err(ThresholdError::InvalidDerivationPath("missing derivation_path".to_string()));
    }
    Ok(())
}
