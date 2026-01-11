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
use log::{debug, info, trace, warn};
use secp256k1::PublicKey;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn collect_and_finalize(
    app_config: Arc<igra_core::infrastructure::config::AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<RocksStorage>,
    session_id: SessionId,
    request_id: RequestId,
    signing_event: SigningEvent,
) -> Result<(), ThresholdError> {
    let started_at = Instant::now();
    if let Some(request) = storage.get_request(&request_id)? {
        if matches!(request.decision, RequestDecision::Finalized) {
            debug!("ignoring finalize for already finalized request request_id={}", request_id);
            return Ok(());
        }
    }

    let required = usize::from(app_config.service.pskt.sig_op_count);
    if required == 0 {
        return Err(ThresholdError::ConfigError("sig_op_count must be > 0".to_string()));
    }

    let proposal = storage.get_proposal(&request_id)?.ok_or_else(|| ThresholdError::Message("missing stored proposal".to_string()))?;
    debug!(
        "loaded stored proposal session_id={} request_id={} kpsbt_len={}",
        hex::encode(session_id.as_hash()),
        request_id,
        proposal.kpsbt_blob.len()
    );
    let pskt = pskt_multisig::deserialize_pskt_signer(&proposal.kpsbt_blob)?;
    let input_count = pskt.inputs.len();
    let timeout_seconds = app_config.runtime.session_timeout_seconds;
    info!(
        "starting signature collection session_id={} request_id={} required_signatures={} input_count={} timeout_seconds={} recipient={} amount_sompi={}",
        hex::encode(session_id.as_hash()),
        request_id,
        required,
        input_count,
        timeout_seconds,
        signing_event.destination_address,
        signing_event.amount_sompi
    );

    let mut last_partial_len = 0usize;
    let mut last_sender_peer_id: Option<igra_core::foundation::PeerId> = None;
    if has_threshold(&storage.list_partial_sigs(&request_id)?, input_count, required) {
        info!(
            "signature threshold already met from stored partial sigs session_id={} request_id={} elapsed_ms={}",
            hex::encode(session_id.as_hash()),
            request_id,
            started_at.elapsed().as_millis()
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
            started_at,
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
                        "partial signature received session_id={} request_id={} signer_peer_id={} input_index={} pubkey={} sig_len={}",
                        hex::encode(session_id.as_hash()),
                        request_id,
                        envelope.sender_peer_id,
                        sig.input_index,
                        hex::encode(&sig.pubkey),
                        sig.signature.len()
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
                    last_sender_peer_id = Some(envelope.sender_peer_id.clone());
                }
            }
            Ok(Some(Err(err))) => {
                warn!(
                    "session stream error session_id={} request_id={} error={}",
                    hex::encode(session_id.as_hash()),
                    request_id,
                    err
                );
            }
            Ok(None) => break,
            Err(_) => {
                warn!(
                    "signature collection timed out session_id={} request_id={} remaining_ms={}",
                    hex::encode(session_id.as_hash()),
                    request_id,
                    remaining.as_millis()
                );
                break;
            }
        }

        let partials = storage.list_partial_sigs(&request_id)?;
        if partials.len() != last_partial_len {
            if let Some(peer) = last_sender_peer_id.take() {
                let required_total = required.saturating_mul(input_count);
                let progress_pct = if required_total == 0 { 0 } else { (partials.len().saturating_mul(100)) / required_total };
                info!(
                    "signature received session_id={} request_id={} collected={} required={} progress_pct={} remaining={} from_peer={}",
                    hex::encode(session_id.as_hash()),
                    request_id,
                    partials.len(),
                    required.saturating_mul(input_count),
                    progress_pct,
                    required_total.saturating_sub(partials.len()),
                    peer
                );
            } else {
                let required_total = required.saturating_mul(input_count);
                let progress_pct = if required_total == 0 { 0 } else { (partials.len().saturating_mul(100)) / required_total };
                info!(
                    "signature progress session_id={} request_id={} collected={} required={} progress_pct={} remaining={}",
                    hex::encode(session_id.as_hash()),
                    request_id,
                    partials.len(),
                    required.saturating_mul(input_count),
                    progress_pct,
                    required_total.saturating_sub(partials.len())
                );
            }
            last_partial_len = partials.len();
        } else {
            continue;
        }
        if has_threshold(&partials, input_count, required) {
            info!(
                "signature threshold reached session_id={} request_id={} collected={} required={} collection_time_ms={}",
                hex::encode(session_id.as_hash()),
                request_id,
                partials.len(),
                required,
                started_at.elapsed().as_millis()
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
                started_at,
            )
            .await;
        }
    }
    flow.metrics().inc_session_stage("timed_out");
    let event_hash_hex = match event_hash(&signing_event) {
        Ok(hash) => hex::encode(hash),
        Err(err) => {
            warn!(
                "failed to compute event hash for timeout audit request_id={} error={}",
                request_id, err
            );
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
        "session timed out without threshold session_id={} request_id={} collected={} required={} timeout_secs={}",
        hex::encode(session_id.as_hash()),
        request_id,
        last_partial_len,
        required,
        app_config.runtime.session_timeout_seconds
    );
    warn!(
        "=== SESSION FAILED === session_id={} request_id={} recipient={} amount_sompi={} signatures_collected={} signatures_required={} duration_ms={} outcome=TIMEOUT",
        hex::encode(session_id.as_hash()),
        request_id,
        signing_event.destination_address,
        signing_event.amount_sompi,
        last_partial_len,
        required,
        started_at.elapsed().as_millis()
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
    started_at: Instant,
) -> Result<(), ThresholdError> {
    let proposal = storage.get_proposal(request_id)?.ok_or_else(|| ThresholdError::Message("missing stored proposal".to_string()))?;
    let partials = storage.list_partial_sigs(request_id)?;
    flow.lifecycle().on_threshold_met(request_id, partials.len(), required);
    debug!(
        "applying partial signatures request_id={} partial_sig_count={}",
        request_id,
        partials.len()
    );
    let pskt = pskt_multisig::apply_partial_sigs(&proposal.kpsbt_blob, &partials)?;
    info!(
        "starting transaction finalization session_id={} request_id={} signatures_collected={} required={} input_count={} output_count={}",
        hex::encode(session_id.as_hash()),
        request_id,
        partials.len(),
        required,
        pskt.inputs.len(),
        pskt.outputs.len()
    );
    let ordered_pubkeys = derive_ordered_pubkeys(&app_config.service, signing_event)?;
    debug!(
        "derived ordered pubkeys request_id={} pubkey_count={}",
        request_id,
        ordered_pubkeys.len()
    );
    let params = params_for_network_id(app_config.iroh.network_id);
    info!(
        "finalizing and submitting transaction session_id={} request_id={} signatures={} required={}",
        hex::encode(session_id.as_hash()),
        request_id,
        partials.len(),
        required
    );
    let tx_id = match flow.finalize_and_submit(request_id, pskt, required, &ordered_pubkeys, params).await {
        Ok(tx_id) => tx_id,
        Err(err) => {
            warn!(
                "=== SESSION FAILED === session_id={} request_id={} recipient={} amount_sompi={} duration_ms={} outcome=FINALIZE_ERROR error={}",
                hex::encode(session_id.as_hash()),
                request_id,
                signing_event.destination_address,
                signing_event.amount_sompi,
                started_at.elapsed().as_millis(),
                err
            );
            return Err(err);
        }
    };
    let final_tx_id = TransactionId::from(tx_id);
    flow.lifecycle().on_finalized(request_id, &final_tx_id);
    flow.metrics().inc_session_stage("finalized");
    info!(
        "finalized transaction with threshold signatures session_id={} request_id={} signatures={} required={} tx_id={}",
        hex::encode(session_id.as_hash()),
        request_id,
        partials.len(),
        required,
        tx_id
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
    info!(
        "=== SESSION COMPLETE === session_id={} request_id={} tx_id={} recipient={} amount_kas={} signers_participated={} blue_score={} duration_ms={} outcome=SUCCESS",
        hex::encode(session_id.as_hash()),
        request_id,
        tx_id,
        signing_event.destination_address,
        signing_event.amount_sompi as f64 / 100_000_000.0,
        partials.len(),
        accepted_blue_score,
        started_at.elapsed().as_millis()
    );
    storage.update_request_final_tx_score(request_id, accepted_blue_score)?;
    transport.publish_finalize(session_id, request_id, *final_tx_id.as_hash()).await?;

    if let Some(group) = app_config.group.as_ref() {
        let confirmations = group.finality_blue_score_threshold;
        if confirmations > 0 {
            debug!(
                "spawning transaction confirmation monitor request_id={} confirmations={} accepted_blue_score={}",
                request_id, confirmations, accepted_blue_score
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
                                    warn!("failed to update final tx score request_id={} error={}", request_id, err);
                                } else {
                                    info!(
                                        "transaction reached confirmation threshold request_id={} confirmations={} blue_score={}",
                                        request_id, confirmations, score
                                    );
                                }
                            }
                            Err(err) => {
                                warn!("transaction monitor failed request_id={} error={}", request_id, err);
                            }
                        }
                    }
                    Err(err) => {
                        warn!("monitor rpc connect failed error={}", err);
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
