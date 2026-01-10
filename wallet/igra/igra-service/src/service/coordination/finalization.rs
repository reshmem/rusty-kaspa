use crate::service::flow::ServiceFlow;
use igra_core::application::TransactionMonitor;
use igra_core::domain::coordination::threshold::has_threshold;
use igra_core::domain::hashes::event_hash;
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::{PartialSigRecord, RequestDecision, SigningEvent};
use igra_core::foundation::hd::{derive_pubkeys, HdInputs};
use igra_core::foundation::{RequestId, SessionId, ThresholdError, TransactionId};
use igra_core::infrastructure::audit::{audit, now_nanos, AuditEvent};
use igra_core::infrastructure::rpc::GrpcNodeRpc;
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::{Transport, TransportMessage};
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, SIMNET_PARAMS, TESTNET_PARAMS};
use kaspa_wallet_core::prelude::Secret;
use secp256k1::PublicKey;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

pub async fn collect_and_finalize(
    app_config: Arc<igra_core::infrastructure::config::AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<RocksStorage>,
    session_id: SessionId,
    request_id: RequestId,
    signing_event: SigningEvent,
) -> Result<(), ThresholdError> {
    if let Some(request) = storage.get_request(&request_id)? {
        if matches!(request.decision, RequestDecision::Finalized) {
            debug!(request_id = %request_id, "ignoring finalize for already finalized request");
            return Ok(());
        }
    }

    let required = usize::from(app_config.service.pskt.sig_op_count);
    if required == 0 {
        return Err(ThresholdError::ConfigError("sig_op_count must be > 0".to_string()));
    }

    let proposal = storage.get_proposal(&request_id)?.ok_or_else(|| ThresholdError::Message("missing stored proposal".to_string()))?;
    debug!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        kpsbt_len = proposal.kpsbt_blob.len(),
        "loaded stored proposal"
    );
    let pskt = pskt_multisig::deserialize_pskt_signer(&proposal.kpsbt_blob)?;
    let input_count = pskt.inputs.len();
    info!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        required_signatures = required,
        input_count,
        "collecting partial signatures"
    );

    let mut last_partial_len = 0usize;
    if has_threshold(&storage.list_partial_sigs(&request_id)?, input_count, required) {
        info!(
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %request_id,
            "threshold already met from stored partial sigs"
        );
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
                    trace!(
                        session_id = %hex::encode(session_id.as_hash()),
                        request_id = %request_id,
                        signer_peer_id = %envelope.sender_peer_id,
                        input_index = sig.input_index,
                        pubkey = %hex::encode(&sig.pubkey),
                        sig_len = sig.signature.len(),
                        "partial signature received"
                    );
                    storage.insert_partial_sig(
                        &request_id,
                        PartialSigRecord {
                            signer_peer_id: envelope.sender_peer_id.clone(),
                            input_index: sig.input_index,
                            pubkey: sig.pubkey,
                            signature: sig.signature,
                            timestamp_nanos: envelope.timestamp_nanos,
                        },
                    )?;
                }
            }
            Ok(Some(Err(err))) => {
                warn!(
                    session_id = %hex::encode(session_id.as_hash()),
                    request_id = %request_id,
                    error = %err,
                    "session stream error"
                );
            }
            Ok(None) => break,
            Err(_) => {
                warn!(
                    session_id = %hex::encode(session_id.as_hash()),
                    request_id = %request_id,
                    remaining_ms = remaining.as_millis(),
                    "session receive timeout"
                );
                break;
            }
        }

        let partials = storage.list_partial_sigs(&request_id)?;
        if partials.len() != last_partial_len {
            info!(
                session_id = %hex::encode(session_id.as_hash()),
                request_id = %request_id,
                collected = partials.len(),
                required = required,
                "partial signatures updated"
            );
            last_partial_len = partials.len();
        } else {
            continue;
        }
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
    let event_hash_hex = match event_hash(&signing_event) {
        Ok(hash) => hex::encode(hash),
        Err(err) => {
            warn!(request_id = %request_id, error = %err, "failed to compute event hash for timeout audit");
            "unknown".to_string()
        }
    };
    audit(AuditEvent::SessionTimedOut {
        request_id: request_id.to_string(),
        event_hash: event_hash_hex,
        signature_count: last_partial_len,
        threshold_required: required,
        duration_seconds: app_config.runtime.session_timeout_seconds,
        timestamp_ns: now_nanos(),
    });
    warn!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        collected = last_partial_len,
        required = required,
        timeout_secs = app_config.runtime.session_timeout_seconds,
        "session timed out without threshold"
    );
    flow.lifecycle().on_failed(&request_id, "session_timeout");

    Ok(())
}

async fn finalize_with_partials(
    app_config: &igra_core::infrastructure::config::AppConfig,
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
    debug!(request_id = %request_id, partial_sig_count = partials.len(), "applying partial signatures");
    let pskt = pskt_multisig::apply_partial_sigs(&proposal.kpsbt_blob, &partials)?;
    let ordered_pubkeys = derive_ordered_pubkeys(&app_config.service, signing_event)?;
    debug!(request_id = %request_id, pubkey_count = ordered_pubkeys.len(), "derived ordered pubkeys");
    let params = params_for_network_id(app_config.iroh.network_id);
    info!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        signatures = partials.len(),
        required = required,
        "finalizing and submitting transaction"
    );
    let tx_id = flow.finalize_and_submit(request_id, pskt, required, &ordered_pubkeys, params).await?;
    let final_tx_id = TransactionId::from(tx_id);
    flow.lifecycle().on_finalized(request_id, &final_tx_id);
    flow.metrics().inc_session_stage("finalized");
    info!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        signatures = partials.len(),
        required = required,
        tx_id = %tx_id,
        "finalized transaction with threshold signatures"
    );
    let event_hash = event_hash(signing_event)?;
    audit(AuditEvent::TransactionFinalized {
        request_id: request_id.to_string(),
        event_hash: hex::encode(event_hash),
        tx_id: tx_id.to_string(),
        signature_count: partials.len(),
        threshold_required: required,
        timestamp_ns: now_nanos(),
    });
    let accepted_blue_score = flow.rpc().get_virtual_selected_parent_blue_score().await?;
    audit(AuditEvent::TransactionSubmitted {
        request_id: request_id.to_string(),
        tx_id: tx_id.to_string(),
        blue_score: accepted_blue_score,
        timestamp_ns: now_nanos(),
    });
    storage.update_request_final_tx_score(request_id, accepted_blue_score)?;
    transport.publish_finalize(session_id, request_id, *final_tx_id.as_hash()).await?;

    if let Some(group) = app_config.group.as_ref() {
        let confirmations = group.finality_blue_score_threshold;
        if confirmations > 0 {
            debug!(
                request_id = %request_id,
                confirmations = confirmations,
                accepted_blue_score = accepted_blue_score,
                "spawning transaction confirmation monitor"
            );
            let node_url = app_config.service.node_rpc_url.clone();
            let request_id = request_id.clone();
            let storage = storage.clone();
            tokio::spawn(async move {
                match GrpcNodeRpc::connect(node_url).await {
                    Ok(rpc) => {
                        let monitor = TransactionMonitor::new(Arc::new(rpc), confirmations, Duration::from_secs(5));
                        match monitor.monitor_until_confirmed(accepted_blue_score).await {
                            Ok(score) => {
                                if let Err(err) = storage.update_request_final_tx_score(&request_id, score) {
                                    warn!(request_id = %request_id, error = %err, "failed to update final tx score");
                                } else {
                                    info!(
                                        request_id = %request_id,
                                        confirmations = confirmations,
                                        blue_score = score,
                                        "transaction reached confirmation threshold"
                                    );
                                }
                            }
                            Err(err) => {
                                warn!(request_id = %request_id, error = %err, "transaction monitor failed");
                            }
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "monitor rpc connect failed");
                    }
                }
            });
        }
    }
    Ok(())
}

pub fn derive_ordered_pubkeys(
    config: &igra_core::infrastructure::config::ServiceConfig,
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
