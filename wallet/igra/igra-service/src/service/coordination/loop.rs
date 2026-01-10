use crate::service::coordination::finalization::collect_and_finalize;
use crate::service::coordination::session::{clear_session_active, mark_session_active, ActiveSessions};
use crate::service::flow::ServiceFlow;
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
use std::collections::HashSet;
use std::sync::Arc;
use futures_util::FutureExt;
use tracing::{debug, info, warn};

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
    let message_verifier = Arc::new(CompositeVerifier::new(hyperlane_validators, layerzero_validators));

    info!(
        group_id = %hex::encode(group_id),
        peer_id = %local_peer_id,
        network_id = app_config.iroh.network_id,
        "coordination loop started"
    );

    while let Some(item) = subscription.next().await {
        let envelope = match item {
            Ok(envelope) => envelope,
            Err(err) => {
                warn!(error = %err, "proposal stream error");
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
        info!(
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %proposal.request_id,
            event_id = %proposal.signing_event.event_id,
            input_count = signer_pskt.inputs.len(),
            expire_at_ns = proposal.expires_at_nanos,
            "received proposal"
        );
        debug!(
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %proposal.request_id,
            validation_hash = %hex::encode(proposal.validation_hash),
            coordinator_peer_id = %proposal.coordinator_peer_id,
            tx_template_hash = %hex::encode(tx_template_hash),
            "proposal details"
        );

        let validation_request = match ProposalValidationRequestBuilder::new(
            proposal.request_id.clone(),
            session_id,
            proposal.signing_event.clone(),
        )
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
                    session_id = %hex::encode(session_id.as_hash()),
                    request_id = %proposal.request_id,
                    error = %err,
                    "failed to build validation request"
                );
                continue;
            }
        };

        let ack = match signer.validate_proposal(validation_request, &local_peer_id) {
            Ok(ack) => ack,
            Err(err) => {
                warn!(
                    session_id = %hex::encode(session_id.as_hash()),
                    request_id = %proposal.request_id,
                    error = %err,
                    "proposal validation error"
                );
                continue;
            }
        };

        info!(
            session_id = %hex::encode(session_id.as_hash()),
            request_id = %ack.request_id,
            accept = ack.accept,
            reason = ?ack.reason,
            "sending signer ack"
        );
        let mut submitted = false;
        for attempt in 1..=3u32 {
            match signer.submit_ack(session_id, ack.clone(), local_peer_id.clone()).await {
                Ok(()) => {
                    submitted = true;
                    break;
                }
                Err(err) => {
                    warn!(attempt, error = %err, "failed to submit ack");
                    tokio::time::sleep(std::time::Duration::from_millis(50u64.saturating_mul(attempt as u64))).await;
                }
            }
        }
        if !submitted {
            warn!(session_id = %hex::encode(session_id.as_hash()), request_id = %ack.request_id, "failed to submit ack after retries");
        }
        metrics.inc_signer_ack(ack.accept);

        if ack.accept {
            match build_signer_backend(&app_config.signing, &app_config.service, &proposal.signing_event) {
                Ok(backend) => {
                    if let Err(err) =
                        signer
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
                            session_id = %hex::encode(session_id.as_hash()),
                            request_id = %proposal.request_id,
                            error = %err,
                            "failed to submit partial sigs"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        session_id = %hex::encode(session_id.as_hash()),
                        request_id = %proposal.request_id,
                        error = %err,
                        "signing backend unavailable"
                    );
                }
            }
        } else {
            debug!(
                session_id = %hex::encode(session_id.as_hash()),
                request_id = %proposal.request_id,
                "proposal rejected by local policy"
            );
        }

        if envelope.sender_peer_id == local_peer_id {
            if !mark_session_active(&active_sessions, session_id).await {
                debug!(
                    session_id = %hex::encode(session_id.as_hash()),
                    "session already active, skipping finalize task"
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
            tokio::spawn(async move {
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
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!(session_id = %session_id_hex, request_id = %request_id, error = %err, "collect/finalize error");
                    }
                    Err(panic) => {
                        warn!(session_id = %session_id_hex, request_id = %request_id, panic = ?panic, "finalization task panicked");
                    }
                }
            });
        }
    }

    Ok(())
}

fn build_signer_backend(
    signing: &igra_core::infrastructure::config::SigningConfig,
    config: &igra_core::infrastructure::config::ServiceConfig,
    signing_event: &SigningEvent,
) -> Result<Box<dyn SignerBackend>, ThresholdError> {
    let kind = SigningBackendKind::from_str(&signing.backend)
        .ok_or_else(|| ThresholdError::Message(format!("unknown signing.backend: {}", signing.backend)))?;
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
