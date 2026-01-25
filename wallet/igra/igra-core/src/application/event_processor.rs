// Shared ingestion pipeline for event providers (JSON-RPC, file watcher, etc.).
use crate::domain::event::decode_session_and_coordinator_ids;
use crate::domain::normalization::{hyperlane::normalize_hyperlane, normalize_generic, ExpectedNetwork};
use crate::domain::validation::{MessageVerifier, ValidationSource};
use crate::domain::{CrdtSigningMaterial, StoredEvent};
use crate::foundation::{EventId, TxTemplateHash};
use crate::foundation::{PeerId, SessionId, ThresholdError};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::config::{PsktBuildConfig, PsktOutput, ServiceConfig};
use crate::infrastructure::keys::{KeyAuditLogger, KeyManager, KeyManagerContext};
use crate::infrastructure::network_mode::NetworkMode;
use crate::infrastructure::rpc::NodeRpc;
use crate::infrastructure::storage::phase::PhaseStorage;
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::iroh::traits::{CrdtSignature, EventCrdtState, EventStateBroadcast, Transport};
use kaspa_addresses::Address;
use log::{debug, info, trace, warn};
use std::sync::Arc;

pub use crate::domain::event::{SigningEventParams, SigningEventResult, SigningEventWire};

#[derive(Clone)]
pub struct EventContext {
    pub config: ServiceConfig,
    pub policy: crate::domain::GroupPolicy,
    pub two_phase: crate::domain::coordination::TwoPhaseConfig,
    pub local_peer_id: PeerId,
    pub message_verifier: Arc<dyn MessageVerifier>,
    pub storage: Arc<dyn Storage>,
    pub phase_storage: Arc<dyn PhaseStorage>,
    pub transport: Arc<dyn Transport>,
    pub rpc: Arc<dyn NodeRpc>,
    pub key_manager: Arc<dyn KeyManager>,
    pub key_audit_log: Arc<dyn KeyAuditLogger>,
}

impl EventContext {
    pub fn key_context(&self) -> KeyManagerContext {
        KeyManagerContext::with_new_request_id(self.key_manager.clone(), self.key_audit_log.clone())
    }
}

pub async fn submit_signing_event(ctx: &EventContext, params: SigningEventParams) -> Result<SigningEventResult, ThresholdError> {
    let (session_id, coordinator_peer_id) = decode_session_and_coordinator_ids(&params)?;
    debug!("decoded signing event ids session_id={} coordinator_peer_id={}", session_id, coordinator_peer_id);
    let SigningEventParams { session_id_hex, external_request_id, expires_at_nanos, event: wire, .. } = params;
    trace!("signing event wire={:?}", wire);

    let expected_network = if let Some(network) = ctx.config.network.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let mode = network.parse::<NetworkMode>()?;
        ExpectedNetwork::Prefix(match mode {
            NetworkMode::Mainnet => kaspa_addresses::Prefix::Mainnet,
            NetworkMode::Testnet => kaspa_addresses::Prefix::Testnet,
            NetworkMode::Devnet => kaspa_addresses::Prefix::Devnet,
        })
    } else if let Some(addr) = ctx.config.pskt.source_addresses.iter().find(|s| !s.trim().is_empty()) {
        ExpectedNetwork::Prefix(Address::constructor(addr).prefix)
    } else {
        warn!("pskt.source_addresses is empty and service.network is not set; skipping network prefix validation");
        ExpectedNetwork::Any
    };

    let crate::domain::event::SigningEventWire { external_id, source, destination_address, amount_sompi, metadata, proof_hex, proof } =
        wire;

    let proof = if let Some(hex_value) = proof_hex.as_deref() { Some(hex::decode(hex_value.trim())?) } else { proof };
    let normalized = match source {
        crate::domain::SourceType::Hyperlane { origin_domain } => normalize_hyperlane(
            expected_network,
            &external_id,
            origin_domain,
            &destination_address,
            amount_sompi,
            metadata.clone(),
            proof,
        )?,
        source => {
            normalize_generic(expected_network, source, &external_id, &destination_address, amount_sompi, metadata.clone(), proof)?
        }
    };
    let event_id = normalized.event_id;
    let stored_event = normalized.into_stored(crate::foundation::now_nanos());
    let external_request_id_for_audit = external_request_id.clone();
    ctx.storage.insert_event(event_id, stored_event.clone())?;
    audit(AuditEvent::EventReceived {
        event_id: event_id.to_string(),
        external_request_id: external_request_id.clone(),
        source: format!("{:?}", stored_event.event.source),
        recipient: stored_event.audit.destination_raw.clone(),
        amount_sompi: stored_event.event.amount_sompi,
        timestamp_nanos: crate::foundation::now_nanos(),
    });

    let pipeline = crate::application::signing_pipeline::SigningPipeline::new(
        ctx.message_verifier.as_ref(),
        &ctx.policy,
        ctx.storage.as_ref(),
        crate::foundation::now_nanos(),
    );
    let report = pipeline.verify_source(&stored_event)?;
    if report.valid {
        info!(
            "message verification passed source={:?} validator_count={} valid_signatures={} threshold={}",
            report.source, report.validator_count, report.valid_signatures, report.threshold_required
        );
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
            audit(AuditEvent::EventSignatureValidated {
                event_id: event_id.to_string(),
                validator_count: report.validator_count,
                valid: true,
                reason: None,
                timestamp_nanos: crate::foundation::now_nanos(),
            });
        }
    } else {
        warn!(
            "message verification failed source={:?} validator_count={} valid_signatures={} threshold={} failure={:?}",
            report.source, report.validator_count, report.valid_signatures, report.threshold_required, report.failure_reason
        );
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
            audit(AuditEvent::EventSignatureValidated {
                event_id: event_id.to_string(),
                validator_count: report.validator_count,
                valid: false,
                reason: report.failure_reason.clone(),
                timestamp_nanos: crate::foundation::now_nanos(),
            });
        }
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) && report.validator_count == 0 {
            return Err(ThresholdError::NoValidatorsConfigured {
                validator_type: match report.source {
                    ValidationSource::Hyperlane => "hyperlane".to_string(),
                    ValidationSource::LayerZero => "layerzero".to_string(),
                    ValidationSource::None => "unknown".to_string(),
                },
            });
        }
        return Err(ThresholdError::EventSignatureInvalid);
    }

    let now_nanos = crate::foundation::now_nanos();
    let pipeline = crate::application::signing_pipeline::SigningPipeline::new(
        ctx.message_verifier.as_ref(),
        &ctx.policy,
        ctx.storage.as_ref(),
        now_nanos,
    );
    match pipeline.enforce_policy(&stored_event) {
        Ok(()) => {
            crate::audit_policy_enforced!(
                external_request_id_for_audit,
                event_id,
                "group_policy",
                crate::domain::audit::types::PolicyDecision::Allowed,
                "ok"
            );
        }
        Err(err) => {
            crate::audit_policy_enforced!(
                external_request_id_for_audit,
                event_id,
                "group_policy",
                crate::domain::audit::types::PolicyDecision::Rejected,
                err.to_string()
            );
            return Err(err);
        }
    }

    // Fast-path idempotency: if the event is already completed, reject early.
    if ctx.storage.get_event_completion(&event_id)?.is_some() {
        return Err(ThresholdError::EventReplayed(event_id.to_string()));
    }

    // If we already have an active tx template for this event, reuse it and avoid generating a new tx template.
    if let Some(active_hash) = ctx.storage.get_event_active_template_hash(&event_id)? {
        if let Some(stored) = ctx.storage.get_event_crdt(&event_id, &active_hash)? {
            if let (Some(stored_material), Some(stored_kpsbt)) = (stored.signing_material.as_ref(), stored.kpsbt_blob.as_deref()) {
                debug!("reusing active CRDT template for event_id={:#x} tx_template_hash={:#x}", event_id, active_hash);

                sign_and_broadcast(
                    ctx,
                    stored_material,
                    &event_id,
                    &active_hash,
                    stored_kpsbt,
                    session_id,
                    external_request_id_for_audit.clone().unwrap_or_else(|| event_id.to_string()),
                    coordinator_peer_id,
                    expires_at_nanos,
                )
                .await?;

                return Ok(SigningEventResult {
                    session_id_hex,
                    event_id_hex: event_id.to_string(),
                    tx_template_hash_hex: active_hash.to_string(),
                });
            }
        }
    }

    let now_ns = crate::foundation::now_nanos();

    // Enter proposing (idempotent). If we're already in progress, don't rebuild.
    let entered = ctx.phase_storage.try_enter_proposing(&event_id, now_ns)?;
    if entered {
        let (proposal, _anchor) = crate::application::two_phase::build_local_proposal_for_round(
            ctx.rpc.as_ref(),
            &ctx.config,
            &ctx.key_context(),
            &stored_event,
            &ctx.local_peer_id,
            0,
            now_ns,
        )
        .await?;

        let store_result = ctx.phase_storage.store_proposal(&proposal)?;
        debug!(
            "two-phase stored local proposal event_id={:#x} round={} tx_template_hash={:#x} store_result={:?}",
            event_id, 0, proposal.tx_template_hash, store_result
        );
        ctx.phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
        ctx.transport.publish_proposal(proposal.clone()).await?;
        info!(
            "two-phase published local proposal event_id={:#x} round={} tx_template_hash={:#x}",
            event_id, 0, proposal.tx_template_hash
        );

        return Ok(SigningEventResult {
            session_id_hex,
            event_id_hex: event_id.to_string(),
            tx_template_hash_hex: proposal.tx_template_hash.to_string(),
        });
    }

    // Already have phase state. Ensure we also contribute a proposal for the current round.
    let phase = ctx.phase_storage.get_phase(&event_id)?;
    if let Some(phase) = phase.as_ref() {
        if phase.phase == crate::domain::coordination::EventPhase::Proposing {
            let round = phase.round;
            if !ctx.phase_storage.has_proposal_from(&event_id, round, &ctx.local_peer_id)? {
                let (proposal, _anchor) = crate::application::two_phase::build_local_proposal_for_round(
                    ctx.rpc.as_ref(),
                    &ctx.config,
                    &ctx.key_context(),
                    &stored_event,
                    &ctx.local_peer_id,
                    round,
                    now_ns,
                )
                .await?;

                let store_result = ctx.phase_storage.store_proposal(&proposal)?;
                debug!(
                    "two-phase stored local proposal event_id={:#x} round={} tx_template_hash={:#x} store_result={:?}",
                    event_id, round, proposal.tx_template_hash, store_result
                );
                ctx.phase_storage.set_own_proposal_hash(&event_id, proposal.tx_template_hash)?;
                ctx.transport.publish_proposal(proposal.clone()).await?;
                info!(
                    "two-phase published local proposal event_id={:#x} round={} tx_template_hash={:#x}",
                    event_id, round, proposal.tx_template_hash
                );

                return Ok(SigningEventResult {
                    session_id_hex,
                    event_id_hex: event_id.to_string(),
                    tx_template_hash_hex: proposal.tx_template_hash.to_string(),
                });
            }
        }
    }

    // Best-effort: return our last known proposal hash if present.
    let tx_template_hash_hex =
        phase.and_then(|p| p.own_proposal_hash).map(|hash| hash.to_string()).unwrap_or_else(|| "pending".to_string());

    Ok(SigningEventResult { session_id_hex, event_id_hex: event_id.to_string(), tx_template_hash_hex })
}

pub async fn resolve_pskt_config(
    config: &ServiceConfig,
    key_context: &KeyManagerContext,
    event: &StoredEvent,
) -> Result<PsktBuildConfig, ThresholdError> {
    if event.audit.destination_raw.trim().is_empty() {
        return Err(ThresholdError::InvalidDestination(format!(
            "missing destination_address external_id={}",
            event.audit.external_id_raw
        )));
    }
    if event.event.amount_sompi == 0 {
        return Err(ThresholdError::AmountTooLow { amount: 0, min: 1 });
    }

    let mut pskt = config.pskt.clone();
    if pskt.node_rpc_url.trim().is_empty() {
        pskt.node_rpc_url = config.node_rpc_url.clone();
    }
    pskt.outputs = vec![PsktOutput { address: event.audit.destination_raw.clone(), amount_sompi: event.event.amount_sompi }];

    if pskt.redeem_script_hex.trim().is_empty() {
        let hd = config.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing redeem script or HD config".to_string()))?;
        match hd.key_type {
            crate::infrastructure::config::KeyType::HdMnemonic => {
                let profile = crate::application::pskt_signing::active_profile(config)?;
                let (key_data, payment_secret) =
                    crate::application::pskt_signing::load_mnemonic_key_data_and_payment_secret_for_profile(key_context, profile)
                        .await?;
                pskt.redeem_script_hex = crate::infrastructure::config::derive_redeem_script_hex(
                    hd,
                    std::slice::from_ref(&key_data),
                    hd.derivation_path.as_deref(),
                    payment_secret.as_ref(),
                )?;
            }
            crate::infrastructure::config::KeyType::RawPrivateKey => {
                return Err(ThresholdError::ConfigError(
                    "service.pskt.redeem_script_hex is required when service.hd.key_type=raw_private_key".to_string(),
                ));
            }
        }
    }

    let provided = pskt.source_addresses.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
    let configured_network = config.network.as_deref().map(str::trim).filter(|s| !s.is_empty());

    if provided.is_empty() {
        let mode = configured_network
            .ok_or_else(|| ThresholdError::ConfigError("service.network is required to derive pskt.source_addresses".to_string()))?
            .parse::<NetworkMode>()?;
        let expected_source =
            crate::infrastructure::config::pskt_source_address_from_redeem_script_hex(mode, &pskt.redeem_script_hex)?;
        pskt.source_addresses = vec![expected_source.clone()];
        if pskt.change_address.as_deref().map(str::trim).unwrap_or("").is_empty() {
            pskt.change_address = Some(expected_source);
        }
    } else if let Some(network) = configured_network {
        let mode = network.parse::<NetworkMode>()?;
        let expected_source =
            crate::infrastructure::config::pskt_source_address_from_redeem_script_hex(mode, &pskt.redeem_script_hex)?;
        for addr in &provided {
            if *addr != expected_source {
                return Err(ThresholdError::ConfigError(format!(
                    "service.pskt.source_addresses must match the address derived from service.pskt.redeem_script_hex; expected='{expected_source}' got='{addr}'"
                )));
            }
        }
        pskt.source_addresses = vec![expected_source.clone()];
        if pskt.change_address.as_deref().map(str::trim).unwrap_or("").is_empty() {
            pskt.change_address = Some(expected_source);
        }
    } else if pskt.change_address.as_deref().map(str::trim).unwrap_or("").is_empty() {
        // Keep backwards compatibility for configs that still provide explicit source addresses.
        pskt.change_address = Some(provided[0].to_string());
    }

    Ok(pskt)
}

async fn sign_and_broadcast(
    ctx: &EventContext,
    _signing_material: &CrdtSigningMaterial,
    event_id: &EventId,
    tx_template_hash: &TxTemplateHash,
    kpsbt_blob: &[u8],
    session_id: SessionId,
    request_id: String,
    coordinator_peer_id: PeerId,
    expires_at_nanos: u64,
) -> Result<(), ThresholdError> {
    // Basic trace context (still useful for debugging external sources).
    trace!(
        "sign_and_broadcast session_id={} request_id={} coordinator_peer_id={} expires_at_nanos={}",
        session_id,
        request_id,
        coordinator_peer_id,
        expires_at_nanos
    );

    let signer_pskt = crate::domain::pskt::multisig::deserialize_pskt_signer(kpsbt_blob)?;
    let (pubkey, partials) = crate::application::pskt_signing::sign_pskt_with_service_config(
        &ctx.config,
        &ctx.key_context(),
        signer_pskt,
        crate::application::pskt_signing::PsktSigningContext { event_id, tx_template_hash, purpose: "sign_and_broadcast" },
    )
    .await?;

    let now_nanos = crate::foundation::now_nanos();
    for (input_index, signature) in partials {
        ctx.storage.add_signature_to_crdt(
            event_id,
            tx_template_hash,
            input_index,
            &pubkey,
            &signature,
            &ctx.local_peer_id,
            now_nanos,
        )?;
    }

    // Broadcast updated CRDT state.
    let stored = ctx.storage.get_event_crdt(event_id, tx_template_hash)?.ok_or_else(|| ThresholdError::MissingCrdtState {
        event_id: event_id.to_string(),
        tx_template_hash: tx_template_hash.to_string(),
        context: "after signing".to_string(),
    })?;
    let state = to_transport_state(&stored);
    let broadcast = EventStateBroadcast {
        event_id: *event_id,
        tx_template_hash: *tx_template_hash,
        state,
        sender_peer_id: ctx.local_peer_id.clone(),
        phase_context: None,
    };
    ctx.transport.publish_event_state(broadcast).await?;
    Ok(())
}

fn to_transport_state(stored: &crate::domain::StoredEventCrdt) -> EventCrdtState {
    let signatures = stored.signatures.iter().map(CrdtSignature::from).collect::<Vec<_>>();
    let completion = stored.completion.as_ref().map(crate::infrastructure::transport::iroh::messages::CompletionRecord::from);

    EventCrdtState {
        signatures,
        completion,
        signing_material: stored.signing_material.clone(),
        kpsbt_blob: stored.kpsbt_blob.clone(),
        version: 0,
    }
}
