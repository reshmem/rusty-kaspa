use crate::service::flow::ServiceFlow;
use igra_core::audit::{audit, AuditEvent};
use igra_core::coordination::hashes::event_hash;
use igra_core::coordination::monitoring::TransactionMonitor;
use igra_core::coordination::signer::Signer;
use igra_core::coordination::threshold::has_threshold;
use igra_core::error::ThresholdError;
use igra_core::hd::{derive_keypair_from_key_data, derive_pubkeys, HdInputs};
use igra_core::model::{Hash32, RequestDecision, SigningEvent};
use igra_core::pskt::multisig as pskt_multisig;
use igra_core::rpc::grpc::GrpcNodeRpc;
use igra_core::signing::threshold::ThresholdSigner;
use igra_core::signing::{backend_kind_from_config, SignerBackend, SigningBackendKind};
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::transport::{Transport, TransportMessage};
use igra_core::types::{PeerId, RequestId, SessionId, TransactionId};
use igra_core::validation::{parse_validator_pubkeys, CompositeVerifier};
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, SIMNET_PARAMS, TESTNET_PARAMS};
use kaspa_wallet_core::prelude::Secret;
use secp256k1::PublicKey;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn run_coordination_loop(
    app_config: Arc<igra_core::config::AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<RocksStorage>,
    local_peer_id: PeerId,
    group_id: Hash32,
) -> Result<(), ThresholdError> {
    let signer = Signer::new(transport.clone(), storage.clone());
    let metrics = flow.metrics();
    let active_sessions = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    let mut subscription = transport.subscribe_group(group_id).await?;
    let hyperlane_validators = parse_validator_pubkeys("hyperlane.validators", &app_config.hyperlane.validators)?;
    let layerzero_validators = parse_validator_pubkeys("layerzero.endpoint_pubkeys", &app_config.layerzero.endpoint_pubkeys)?;
    let message_verifier = Arc::new(CompositeVerifier::new(hyperlane_validators, layerzero_validators));

    while let Some(item) = subscription.next().await {
        let envelope = match item {
            Ok(envelope) => envelope,
            Err(err) => {
                tracing::warn!(error = %err, "proposal stream error");
                continue;
            }
        };

        let TransportMessage::SigningEventPropose(proposal) = envelope.payload else {
            continue;
        };

        let session_id = envelope.session_id;
        metrics.inc_session_stage("proposal_received");
        let signer_pskt = pskt_multisig::deserialize_pskt_signer(&proposal.kpsbt_blob)?;
        let tx_template_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;

        let ack = match signer.validate_proposal(
            &proposal.request_id,
            session_id,
            proposal.signing_event.clone(),
            proposal.event_hash,
            &proposal.kpsbt_blob,
            tx_template_hash,
            proposal.validation_hash,
            proposal.coordinator_peer_id.clone(),
            proposal.expires_at_nanos,
            Some(&app_config.policy),
            Some(message_verifier.as_ref()),
        ) {
            Ok(ack) => ack,
            Err(err) => {
                tracing::warn!(error = %err, "proposal validation error");
                continue;
            }
        };

        if let Err(err) = signer.submit_ack(session_id, ack.clone(), local_peer_id.clone()).await {
            tracing::warn!(error = %err, "failed to submit ack");
        }
        metrics.inc_signer_ack(ack.accept);

        if ack.accept {
            match build_signer_backend(&app_config.signing, &app_config.service, &proposal.signing_event) {
                Ok(backend) => {
                    if let Err(err) =
                        signer.sign_and_submit_backend(session_id, &proposal.request_id, &proposal.kpsbt_blob, backend.as_ref()).await
                    {
                        tracing::warn!(error = %err, "failed to submit partial sigs");
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "signing backend unavailable");
                }
            }
        }

        if envelope.sender_peer_id == local_peer_id {
            let active = active_sessions.clone();
            let app_config = app_config.clone();
            let flow = flow.clone();
            let transport = transport.clone();
            let storage = storage.clone();
            let request_id = proposal.request_id.clone();
            let signing_event = proposal.signing_event.clone();
            tokio::spawn(async move {
                if !mark_session_active(&active, session_id).await {
                    return;
                }
                if let Err(err) =
                    collect_and_finalize(app_config, flow, transport, storage, session_id, request_id, signing_event).await
                {
                    tracing::warn!(error = %err, "collect/finalize error");
                }
                clear_session_active(&active, session_id).await;
            });
        }
    }

    Ok(())
}

async fn mark_session_active(active: &tokio::sync::Mutex<HashSet<SessionId>>, session_id: SessionId) -> bool {
    let mut guard = active.lock().await;
    if guard.contains(&session_id) {
        return false;
    }
    guard.insert(session_id);
    true
}

async fn clear_session_active(active: &tokio::sync::Mutex<HashSet<SessionId>>, session_id: SessionId) {
    let mut guard = active.lock().await;
    guard.remove(&session_id);
}

pub async fn collect_and_finalize(
    app_config: Arc<igra_core::config::AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<RocksStorage>,
    session_id: SessionId,
    request_id: RequestId,
    signing_event: SigningEvent,
) -> Result<(), ThresholdError> {
    if let Some(request) = storage.get_request(&request_id)? {
        if matches!(request.decision, RequestDecision::Finalized) {
            return Ok(());
        }
    }

    let required = app_config.service.pskt.sig_op_count as usize;
    if required == 0 {
        return Err(ThresholdError::ConfigError("sig_op_count must be > 0".to_string()));
    }

    let proposal = storage.get_proposal(&request_id)?.ok_or_else(|| ThresholdError::Message("missing stored proposal".to_string()))?;
    let pskt = pskt_multisig::deserialize_pskt_signer(&proposal.kpsbt_blob)?;
    let input_count = pskt.inputs.len();

    let mut last_partial_len = 0usize;
    if has_threshold(&storage.list_partial_sigs(&request_id)?, input_count, required) {
        return finalize_with_partials(
            &app_config,
            &flow,
            &transport,
            storage.clone(),
            session_id,
            &request_id,
            &signing_event,
            required,
        )
        .await;
    }

    let timeout = Duration::from_secs(app_config.runtime.session_timeout_seconds);
    let deadline = Instant::now() + timeout;
    let mut subscription = transport.subscribe_session(session_id).await?;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let next = tokio::time::timeout(remaining, subscription.next()).await;
        match next {
            Ok(Some(Ok(envelope))) => {
                if let TransportMessage::PartialSigSubmit(sig) = envelope.payload {
                    flow.metrics().inc_partial_sig();
                    if sig.request_id != request_id {
                        continue;
                    }
                }
            }
            Ok(Some(Err(err))) => {
                tracing::warn!(error = %err, "session stream error");
            }
            Ok(None) => break,
            Err(_) => break,
        }

        let partials = storage.list_partial_sigs(&request_id)?;
        if partials.len() == last_partial_len {
            continue;
        }
        last_partial_len = partials.len();
        if has_threshold(&partials, input_count, required) {
            return finalize_with_partials(
                &app_config,
                &flow,
                &transport,
                storage.clone(),
                session_id,
                &request_id,
                &signing_event,
                required,
            )
            .await;
        }
    }
    flow.metrics().inc_session_stage("timed_out");
    let event_hash = event_hash(&signing_event)?;
    audit(AuditEvent::SessionTimedOut {
        request_id: request_id.to_string(),
        event_hash: hex::encode(event_hash),
        signature_count: last_partial_len,
        threshold_required: required,
        duration_seconds: app_config.runtime.session_timeout_seconds,
        timestamp_ns: igra_core::audit::now_nanos(),
    });
    flow.lifecycle().on_failed(&request_id, "session_timeout");

    Ok(())
}

async fn finalize_with_partials(
    app_config: &igra_core::config::AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: Arc<RocksStorage>,
    session_id: SessionId,
    request_id: &RequestId,
    signing_event: &SigningEvent,
    required: usize,
) -> Result<(), ThresholdError> {
    let proposal = storage.get_proposal(request_id)?.ok_or_else(|| ThresholdError::Message("missing stored proposal".to_string()))?;
    let partials = storage.list_partial_sigs(request_id)?;
    flow.lifecycle().on_threshold_met(request_id, partials.len(), required);
    let pskt = pskt_multisig::apply_partial_sigs(&proposal.kpsbt_blob, &partials)?;
    let ordered_pubkeys = derive_ordered_pubkeys(&app_config.service, signing_event)?;
    let params = params_for_network_id(app_config.iroh.network_id);
    let tx_id = flow.finalize_and_submit(request_id, pskt, required, &ordered_pubkeys, params).await?;
    let final_tx_id = TransactionId::from(tx_id);
    flow.lifecycle().on_finalized(request_id, &final_tx_id);
    flow.metrics().inc_session_stage("finalized");
    let event_hash = event_hash(signing_event)?;
    audit(AuditEvent::TransactionFinalized {
        request_id: request_id.to_string(),
        event_hash: hex::encode(event_hash),
        tx_id: tx_id.to_string(),
        signature_count: partials.len(),
        threshold_required: required,
        timestamp_ns: igra_core::audit::now_nanos(),
    });
    let accepted_blue_score = flow.rpc().get_virtual_selected_parent_blue_score().await?;
    audit(AuditEvent::TransactionSubmitted {
        request_id: request_id.to_string(),
        tx_id: tx_id.to_string(),
        blue_score: accepted_blue_score,
        timestamp_ns: igra_core::audit::now_nanos(),
    });
    storage.update_request_final_tx_score(request_id, accepted_blue_score)?;
    transport.publish_finalize(session_id, request_id, *final_tx_id.as_hash()).await?;

    if let Some(group) = app_config.group.as_ref() {
        let confirmations = group.finality_blue_score_threshold;
        if confirmations > 0 {
            let node_url = app_config.service.node_rpc_url.clone();
            let request_id = request_id.clone();
            let storage = storage.clone();
            tokio::spawn(async move {
                match GrpcNodeRpc::connect(node_url).await {
                    Ok(rpc) => {
                        let monitor = TransactionMonitor::new(Arc::new(rpc), confirmations, Duration::from_secs(5));
                        if let Ok(score) = monitor.monitor_until_confirmed(accepted_blue_score).await {
                            let _ = storage.update_request_final_tx_score(&request_id, score);
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "monitor rpc connect failed");
                    }
                }
            });
        }
    }
    Ok(())
}

fn build_signer_backend(
    signing: &igra_core::config::SigningConfig,
    config: &igra_core::config::ServiceConfig,
    signing_event: &SigningEvent,
) -> Result<Box<dyn SignerBackend>, ThresholdError> {
    let kind = backend_kind_from_config(signing)?;
    match kind {
        SigningBackendKind::Threshold => {
            let hd = config.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config for signer".to_string()))?;
            let key_data = hd.decrypt_mnemonics()?;
            let key_data = key_data.first().ok_or_else(|| ThresholdError::ConfigError("missing signer mnemonic".to_string()))?;
            let payment_secret = hd.passphrase.as_deref().map(Secret::from);
            let keypair = derive_keypair_from_key_data(key_data, &signing_event.derivation_path, payment_secret.as_ref())?;
            Ok(Box::new(ThresholdSigner::new(keypair)))
        }
        SigningBackendKind::MuSig2 | SigningBackendKind::Mpc => {
            Err(ThresholdError::Unimplemented("signing backend not supported in service loop".to_string()))
        }
    }
}

pub fn derive_ordered_pubkeys(
    config: &igra_core::config::ServiceConfig,
    signing_event: &SigningEvent,
) -> Result<Vec<PublicKey>, ThresholdError> {
    let hd = config.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config for pubkeys".to_string()))?;
    let key_data = hd.decrypt_mnemonics()?;
    let payment_secret = hd.passphrase.as_deref().map(Secret::from);
    let inputs = HdInputs {
        key_data: &key_data,
        xpubs: &hd.xpubs,
        derivation_path: &signing_event.derivation_path,
        payment_secret: payment_secret.as_ref(),
    };
    derive_pubkeys(inputs)
}

pub fn params_for_network_id(network_id: u8) -> &'static kaspa_consensus_core::config::params::Params {
    match network_id {
        0 => &MAINNET_PARAMS,
        2 => &DEVNET_PARAMS,
        3 => &SIMNET_PARAMS,
        _ => &TESTNET_PARAMS,
    }
}
