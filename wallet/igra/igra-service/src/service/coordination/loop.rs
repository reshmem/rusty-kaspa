use crate::service::coordination::finalization::collect_and_finalize;
use crate::service::coordination::session::{clear_session_active, mark_session_active, ActiveSessions};
use crate::service::flow::ServiceFlow;
use futures_util::FutureExt;
use igra_core::application::signer::{ProposalValidationRequestBuilder, Signer};
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::signing::threshold::ThresholdSigner;
use igra_core::domain::signing::{SignerBackend, SigningBackendKind};
use igra_core::domain::validation::{parse_validator_pubkeys, CompositeVerifier};
use igra_core::domain::SigningEvent;
use igra_core::foundation::hd::derive_keypair_from_key_data;
use igra_core::foundation::{Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::transport::iroh::traits::{Transport, TransportMessage};
use kaspa_wallet_core::prelude::Secret;
use log::{debug, error, info, trace, warn};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn run_coordination_loop(
    app_config: Arc<igra_core::infrastructure::config::AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<igra_core::infrastructure::storage::rocks::RocksStorage>,
    local_peer_id: PeerId,
    group_id: Hash32,
) -> Result<(), ThresholdError> {
    let signer = Signer::new(transport.clone(), storage.clone());
    let metrics = flow.metrics();
    let active_sessions: Arc<ActiveSessions> = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    let mut subscription = transport.subscribe_group(group_id).await?;
    let hyperlane_validators = parse_validator_pubkeys("hyperlane.validators", &app_config.hyperlane.validators)?;
    let layerzero_validators = parse_validator_pubkeys("layerzero.endpoint_pubkeys", &app_config.layerzero.endpoint_pubkeys)?;
    let hyperlane_threshold = app_config.hyperlane.threshold.unwrap_or(1) as usize;
    let message_verifier = Arc::new(CompositeVerifier::new(hyperlane_validators, hyperlane_threshold, layerzero_validators));

    info!(
        "coordination loop started group_id={} peer_id={} network_id={} signing_backend={} session_timeout_secs={} session_expiry_secs={:?} sig_op_count={} node_rpc_url_set={} pskt_node_rpc_url_set={} data_dir_set={} hyperlane_validator_count={} layerzero_validator_count={} bootstrap_addr_count={}",
        hex::encode(group_id),
        local_peer_id,
        app_config.iroh.network_id,
        app_config.signing.backend,
        app_config.runtime.session_timeout_seconds,
        app_config.runtime.session_expiry_seconds,
        app_config.service.pskt.sig_op_count,
        !app_config.service.node_rpc_url.trim().is_empty(),
        !app_config.service.pskt.node_rpc_url.trim().is_empty(),
        !app_config.service.data_dir.trim().is_empty(),
        app_config.hyperlane.validators.len(),
        app_config.layerzero.endpoint_pubkeys.len(),
        app_config.iroh.bootstrap_addrs.len()
    );

    let mut last_activity = Instant::now();
    let mut idle_ticker = tokio::time::interval(Duration::from_secs(60));
    idle_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = idle_ticker.tick() => {
                    let idle = last_activity.elapsed();
                    if idle >= Duration::from_secs(60) {
                    info!(
                        "service idle, waiting for signing proposals idle_seconds={} group_id_prefix={} peer_id={}",
                        idle.as_secs(),
                        hex::encode(&group_id[..8]),
                        local_peer_id
                    );
                    }
                }
            item = subscription.next() => {
                let Some(item) = item else { break; };
                let envelope = match item {
                    Ok(envelope) => {
                        last_activity = Instant::now();
                        envelope
                    }
                    Err(err) => {
                        warn!("proposal stream error error={}", err);
                        continue;
                    }
                };

        let payload_kind = match &envelope.payload {
            TransportMessage::SigningEventPropose(_) => "signing_event_propose",
            TransportMessage::SignerAck(_) => "signer_ack",
            TransportMessage::PartialSigSubmit(_) => "partial_sig_submit",
            TransportMessage::FinalizeNotice(_) => "finalize_notice",
            TransportMessage::FinalizeAck(_) => "finalize_ack",
        };
        debug!(
            "group message received session_id={} sender_peer_id={} seq_no={} payload={}",
            hex::encode(envelope.session_id.as_hash()),
            envelope.sender_peer_id,
            envelope.seq_no,
            payload_kind
        );

        let TransportMessage::SigningEventPropose(proposal) = envelope.payload else {
            continue;
        };

        let session_id = envelope.session_id;
        metrics.inc_session_stage("proposal_received");
        trace!("deserializing proposal PSKT kpsbt_len={}", proposal.kpsbt_blob.len());
        let signer_pskt = pskt_multisig::deserialize_pskt_signer(&proposal.kpsbt_blob)?;
        let tx_template_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;
        info!(
            "received proposal session_id={} request_id={} event_id={} recipient={} amount_sompi={} source={:?} input_count={} expire_at_ns={}",
            hex::encode(session_id.as_hash()),
            proposal.request_id,
            proposal.signing_event.event_id,
            proposal.signing_event.destination_address,
            proposal.signing_event.amount_sompi,
            proposal.signing_event.event_source,
            signer_pskt.inputs.len(),
            proposal.expires_at_nanos
        );
        debug!(
            "proposal details session_id={} request_id={} validation_hash={} coordinator_peer_id={} tx_template_hash={}",
            hex::encode(session_id.as_hash()),
            proposal.request_id,
            hex::encode(proposal.validation_hash),
            proposal.coordinator_peer_id,
            hex::encode(tx_template_hash)
        );

        let validation_request =
            match ProposalValidationRequestBuilder::new(proposal.request_id.clone(), session_id, proposal.signing_event.clone())
                .expected_group_id(group_id)
                .proposal_group_id(envelope.group_id)
                .expected_event_hash(proposal.event_hash)
                .kpsbt_blob(&proposal.kpsbt_blob)
                .tx_template_hash(tx_template_hash)
                .expected_validation_hash(proposal.validation_hash)
                .coordinator_peer_id(proposal.coordinator_peer_id.clone())
                .expires_at_nanos(proposal.expires_at_nanos)
                .policy(Some(&app_config.policy))
                .message_verifier(Some(message_verifier.clone()))
                .build()
            {
                Ok(req) => req,
                Err(err) => {
                    warn!(
                        "failed to build validation request session_id={} request_id={} error={}",
                        hex::encode(session_id.as_hash()),
                        proposal.request_id,
                        err
                    );
                    continue;
                }
            };

        let ack = match signer.validate_proposal(validation_request, &local_peer_id) {
            Ok(ack) => ack,
            Err(err) => {
                warn!(
                    "proposal validation error session_id={} request_id={} error={}",
                    hex::encode(session_id.as_hash()),
                    proposal.request_id,
                    err
                );
                continue;
            }
        };

        info!(
            "sending signer ack session_id={} request_id={} accept={} reason={:?}",
            hex::encode(session_id.as_hash()),
            ack.request_id,
            ack.accept,
            ack.reason
        );
        let mut submitted = false;
        for attempt in 1..=3u32 {
            match signer.submit_ack(session_id, ack.clone(), local_peer_id.clone()).await {
                Ok(()) => {
                    submitted = true;
                    break;
                }
                Err(err) => {
                    warn!("failed to submit ack attempt={} error={}", attempt, err);
                    tokio::time::sleep(std::time::Duration::from_millis(50u64.saturating_mul(attempt as u64))).await;
                }
            }
        }
        if !submitted {
            warn!(
                "failed to submit ack after retries session_id={} request_id={}",
                hex::encode(session_id.as_hash()),
                ack.request_id
            );
        }
        metrics.inc_signer_ack(ack.accept);

        if ack.accept {
            match build_signer_backend(&app_config.signing, &app_config.service, &proposal.signing_event) {
                Ok(backend) => {
                    info!(
                        "signing backend selected session_id={} request_id={} backend={}",
                        hex::encode(session_id.as_hash()),
                        proposal.request_id,
                        app_config.signing.backend
                    );
                    if let Err(err) = signer
                        .sign_and_submit_backend(
                            session_id,
                            &proposal.request_id,
                            &proposal.kpsbt_blob,
                            backend.as_ref(),
                            &local_peer_id,
                        )
                        .await
                    {
                        warn!(
                            "failed to submit partial sigs session_id={} request_id={} error={}",
                            hex::encode(session_id.as_hash()),
                            proposal.request_id,
                            err
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        "signing backend unavailable session_id={} request_id={} error={}",
                        hex::encode(session_id.as_hash()),
                        proposal.request_id,
                        err
                    );
                }
            }
        } else {
            debug!(
                "proposal rejected by local policy session_id={} request_id={}",
                hex::encode(session_id.as_hash()),
                proposal.request_id
            );
        }

        if envelope.sender_peer_id == local_peer_id {
            if !mark_session_active(&active_sessions, session_id).await {
                debug!(
                    "session already active, skipping finalize task session_id={}",
                    hex::encode(session_id.as_hash())
                );
                continue;
            }

            let active = active_sessions.clone();
            let app_config = app_config.clone();
            let flow = flow.clone();
            let transport = transport.clone();
            let storage = storage.clone();
            let request_id = proposal.request_id.clone();
            let signing_event = proposal.signing_event.clone();
            let session_id_hex = hex::encode(session_id.as_hash());
            info!("spawning finalization task session_id={} request_id={}", session_id_hex, request_id);
            tokio::spawn(async move {
                let session_start = Instant::now();
                let result = std::panic::AssertUnwindSafe(collect_and_finalize(
                    app_config,
                    flow,
                    transport,
                    storage,
                    session_id,
                    request_id.clone(),
                    signing_event,
                ))
                .catch_unwind()
                .await;

                clear_session_active(&active, session_id).await;

                match result {
                    Ok(Ok(())) => {
                        info!(
                            "=== SESSION COMPLETE === session_id={} request_id={} duration_ms={} outcome=SUCCESS",
                            session_id_hex,
                            request_id,
                            session_start.elapsed().as_millis()
                        );
                    }
                    Ok(Err(err)) => {
                        warn!("collect/finalize error session_id={} request_id={} error={}", session_id_hex, request_id, err);
                        warn!(
                            "=== SESSION COMPLETE === session_id={} request_id={} duration_ms={} outcome=FAILED",
                            session_id_hex,
                            request_id,
                            session_start.elapsed().as_millis()
                        );
                    }
                    Err(panic) => {
                        error!(
                            "=== SESSION COMPLETE === session_id={} request_id={} duration_ms={} outcome=PANIC panic={:?}",
                            session_id_hex,
                            request_id,
                            session_start.elapsed().as_millis(),
                            panic
                        );
                    }
                }
            });
        }
            }
        }
    }

    Ok(())
}

fn build_signer_backend(
    signing: &igra_core::infrastructure::config::SigningConfig,
    config: &igra_core::infrastructure::config::ServiceConfig,
    signing_event: &SigningEvent,
) -> Result<Box<dyn SignerBackend>, ThresholdError> {
    let kind: SigningBackendKind = signing.backend.parse()?;
    debug!(
        "building signing backend kind={:?} backend={} derivation_path={}",
        kind, signing.backend, signing_event.derivation_path
    );
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
