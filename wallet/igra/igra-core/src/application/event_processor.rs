// Shared ingestion pipeline for event providers (JSON-RPC, file watcher, etc.).
use crate::domain::event::decode_session_and_request_ids;
use crate::domain::hashes::event_hash;
use crate::domain::policy::enforcement::{DefaultPolicyEnforcer, PolicyEnforcer};
use crate::domain::validation::{MessageVerifier, ValidationSource};
use crate::domain::SigningEvent;
use crate::foundation::Hash32;
use crate::foundation::{PeerId, RequestId, SessionId, ThresholdError};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::config::{PsktBuildConfig, PsktOutput, ServiceConfig};
use crate::infrastructure::rpc::kaspa_integration::build_pskt_from_rpc;
use crate::infrastructure::rpc::NodeRpc;
use crate::infrastructure::storage::Storage;
use crate::infrastructure::transport::iroh::traits::{CrdtSignature, EventCrdtState, EventStateBroadcast, Transport};
use log::{debug, info, trace, warn};
use std::sync::Arc;

pub use crate::domain::event::{SigningEventParams, SigningEventResult, SigningEventWire};

#[derive(Clone)]
pub struct EventContext {
    pub config: ServiceConfig,
    pub policy: crate::domain::GroupPolicy,
    pub local_peer_id: PeerId,
    pub message_verifier: Arc<dyn MessageVerifier>,
    pub storage: Arc<dyn Storage>,
    pub transport: Arc<dyn Transport>,
    pub rpc: Arc<dyn NodeRpc>,
}

pub async fn submit_signing_event(ctx: &EventContext, params: SigningEventParams) -> Result<SigningEventResult, ThresholdError> {
    let (session_id, request_id, coordinator_peer_id) = decode_session_and_request_ids(&params)?;
    debug!(
        "decoded signing event ids session_id={} request_id={} coordinator_peer_id={}",
        hex::encode(session_id.as_hash()),
        request_id,
        coordinator_peer_id
    );
    let parsed = params.signing_event.into_signing_event()?;
    debug!(
        "signing event parsed event_id={} derivation_source={:?} signature_source={:?}",
        parsed.event.event_id, parsed.derivation_path_source, parsed.signature_source
    );
    let signing_event = parsed.event;
    trace!("signing event details signing_event={:?}", signing_event);
    let event_hash = event_hash(&signing_event)?;
    debug!("computed signing event hash event_hash={}", hex::encode(event_hash));
    crate::audit_event_received!(event_hash, signing_event);
    info!("signing event received request_id={} event_id={}", params.request_id, signing_event.event_id);

    let report = ctx.message_verifier.verify(&signing_event)?;
    if report.valid {
        info!(
            "message verification passed source={:?} validator_count={} valid_signatures={} threshold={}",
            report.source, report.validator_count, report.valid_signatures, report.threshold_required
        );
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
            audit(AuditEvent::EventSignatureValidated {
                event_hash: hex::encode(event_hash),
                validator_count: report.validator_count,
                valid: true,
                reason: None,
                timestamp_ns: crate::infrastructure::audit::now_nanos(),
            });
        }
    } else {
        warn!(
            "message verification failed source={:?} validator_count={} valid_signatures={} threshold={} failure={:?}",
            report.source, report.validator_count, report.valid_signatures, report.threshold_required, report.failure_reason
        );
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
            audit(AuditEvent::EventSignatureValidated {
                event_hash: hex::encode(event_hash),
                validator_count: report.validator_count,
                valid: false,
                reason: report.failure_reason.clone(),
                timestamp_ns: crate::infrastructure::audit::now_nanos(),
            });
        }
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) && report.validator_count == 0 {
            let message = match report.source {
                ValidationSource::Hyperlane => "no hyperlane validators configured",
                ValidationSource::LayerZero => "no layerzero endpoint pubkeys configured",
                ValidationSource::None => "no validators configured",
            };
            return Err(ThresholdError::ConfigError(message.to_string()));
        }
        return Err(ThresholdError::EventSignatureInvalid);
    }

    let now_nanos = crate::infrastructure::audit::now_nanos();
    let current_daily_volume = ctx.storage.get_volume_since(now_nanos)?;
    match DefaultPolicyEnforcer::new().enforce_policy(&signing_event, &ctx.policy, current_daily_volume) {
        Ok(()) => {
            crate::audit_policy_enforced!(
                request_id,
                event_hash,
                "group_policy",
                crate::domain::audit::types::PolicyDecision::Allowed,
                "ok"
            );
        }
        Err(err) => {
            crate::audit_policy_enforced!(
                request_id,
                event_hash,
                "group_policy",
                crate::domain::audit::types::PolicyDecision::Rejected,
                err.to_string()
            );
            return Err(err);
        }
    }

    // Idempotent: do not treat replays as fatal in CRDT mode.
    ctx.storage.insert_event(event_hash, signing_event.clone())?;
    debug!("signing event stored event_hash={}", hex::encode(event_hash));

    // If we already have a CRDT state for this event, reuse it and avoid generating a new tx template.
    let mut existing_crdts = ctx.storage.list_event_crdts_for_event(&event_hash)?;
    if !existing_crdts.is_empty() {
        if existing_crdts.iter().any(|s| s.completion.is_some()) {
            return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
        }
        existing_crdts.sort_by(|a, b| a.tx_template_hash.cmp(&b.tx_template_hash));
        let canonical = &existing_crdts[0];
        if let (Some(stored_event), Some(stored_kpsbt)) = (canonical.signing_event.as_ref(), canonical.kpsbt_blob.as_deref()) {
            debug!(
                "reusing existing CRDT template for event_hash={} tx_template_hash={}",
                hex::encode(event_hash),
                hex::encode(canonical.tx_template_hash)
            );

            sign_and_broadcast(
                ctx,
                stored_event,
                &event_hash,
                &canonical.tx_template_hash,
                stored_kpsbt,
                session_id,
                request_id,
                coordinator_peer_id,
                params.expires_at_nanos,
            )
            .await?;

            return Ok(SigningEventResult {
                session_id_hex: params.session_id_hex,
                event_hash_hex: hex::encode(event_hash),
                // Backwards compatible field: now carries tx_template_hash in CRDT mode.
                validation_hash_hex: hex::encode(canonical.tx_template_hash),
            });
        }
    }

    // Deterministically build the transaction template via RPC.
    let pskt_config = resolve_pskt_config(&ctx.config, &signing_event)?;
    let (_selection, build) = build_pskt_from_rpc(ctx.rpc.as_ref(), &pskt_config).await?;
    let signer_pskt = crate::domain::pskt::multisig::to_signer(build.pskt);
    let kpsbt_blob = crate::domain::pskt::multisig::serialize_pskt(&signer_pskt)?;
    let tx_template_hash = crate::domain::pskt::multisig::tx_template_hash(&signer_pskt)?;

    if !existing_crdts.is_empty() {
        let expected = existing_crdts[0].tx_template_hash;
        if tx_template_hash != expected {
            warn!(
                "tx_template_hash mismatch for existing event_hash={} expected={} computed={} (refusing to create a second template)",
                hex::encode(event_hash),
                hex::encode(expected),
                hex::encode(tx_template_hash)
            );
            return Err(ThresholdError::PsktMismatch { expected: hex::encode(expected), actual: hex::encode(tx_template_hash) });
        }
    }

    // Initialize CRDT state for (event_hash, tx_template_hash), storing the event and KPSBT locally.
    let empty_state = EventCrdtState { signatures: vec![], completion: None, signing_event: None, kpsbt_blob: None, version: 0 };
    ctx.storage.merge_event_crdt(&event_hash, &tx_template_hash, &empty_state, Some(&signing_event), Some(&kpsbt_blob))?;

    // Sign locally and broadcast.
    sign_and_broadcast(
        ctx,
        &signing_event,
        &event_hash,
        &tx_template_hash,
        &kpsbt_blob,
        session_id,
        request_id,
        coordinator_peer_id,
        params.expires_at_nanos,
    )
    .await?;

    Ok(SigningEventResult {
        session_id_hex: params.session_id_hex,
        event_hash_hex: hex::encode(event_hash),
        // Backwards compatible field: now carries tx_template_hash in CRDT mode.
        validation_hash_hex: hex::encode(tx_template_hash),
    })
}

fn resolve_pskt_config(config: &ServiceConfig, signing_event: &SigningEvent) -> Result<PsktBuildConfig, ThresholdError> {
    if signing_event.destination_address.trim().is_empty() || signing_event.amount_sompi == 0 {
        return Err(ThresholdError::Message("signing_event missing destination_address or amount".to_string()));
    }

    let mut pskt = config.pskt.clone();
    if pskt.node_rpc_url.trim().is_empty() {
        pskt.node_rpc_url = config.node_rpc_url.clone();
    }
    pskt.outputs = vec![PsktOutput { address: signing_event.destination_address.clone(), amount_sompi: signing_event.amount_sompi }];

    if pskt.redeem_script_hex.trim().is_empty() {
        let hd = config.hd.as_ref().ok_or_else(|| ThresholdError::Message("missing redeem script or HD config".to_string()))?;
        pskt.redeem_script_hex = crate::infrastructure::config::derive_redeem_script_hex(hd, &signing_event.derivation_path)?;
    }

    Ok(pskt)
}

async fn sign_and_broadcast(
    ctx: &EventContext,
    signing_event: &SigningEvent,
    event_hash: &Hash32,
    tx_template_hash: &Hash32,
    kpsbt_blob: &[u8],
    session_id: SessionId,
    request_id: RequestId,
    coordinator_peer_id: PeerId,
    expires_at_nanos: u64,
) -> Result<(), ThresholdError> {
    // Basic trace context (still useful for debugging external sources).
    trace!(
        "sign_and_broadcast session_id={} request_id={} coordinator_peer_id={} expires_at_nanos={}",
        hex::encode(session_id.as_hash()),
        request_id,
        coordinator_peer_id,
        expires_at_nanos
    );

    let hd = ctx
        .config
        .hd
        .as_ref()
        .ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;
    let key_data = hd.decrypt_mnemonics()?;
    let payment_secret = hd.passphrase.as_deref().map(kaspa_wallet_core::prelude::Secret::from);
    let signing_key_data = key_data.first().ok_or_else(|| ThresholdError::ConfigError("missing mnemonic".to_string()))?;

    let signing_keypair = crate::foundation::hd::derive_keypair_from_key_data(
        signing_key_data,
        &signing_event.derivation_path,
        payment_secret.as_ref(),
    )?;
    let keypair = signing_keypair.to_secp256k1()?;

    let signer_pskt = crate::domain::pskt::multisig::deserialize_pskt_signer(kpsbt_blob)?;
    let signed = crate::domain::pskt::multisig::sign_pskt(signer_pskt, &keypair)?.pskt;
    let canonical_pubkey = crate::domain::pskt::multisig::canonical_schnorr_pubkey_for_keypair(&keypair);
    let partials = crate::domain::pskt::multisig::partial_sigs_for_pubkey(&signed, &canonical_pubkey);

    if partials.is_empty() {
        return Err(ThresholdError::SigningFailed("no signatures produced".to_string()));
    }

    let now_nanos = crate::infrastructure::audit::now_nanos();
    let pubkey = canonical_pubkey.serialize().to_vec();
    for (input_index, signature) in partials {
        ctx.storage.add_signature_to_crdt(event_hash, tx_template_hash, input_index, &pubkey, &signature, &ctx.local_peer_id, now_nanos)?;
    }

    // Broadcast updated CRDT state.
    let stored = ctx
        .storage
        .get_event_crdt(event_hash, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state after signing".to_string()))?;
    let state = to_transport_state(&stored);
    let broadcast =
        EventStateBroadcast { event_hash: *event_hash, tx_template_hash: *tx_template_hash, state, sender_peer_id: ctx.local_peer_id.clone() };
    ctx.transport.publish_event_state(broadcast).await?;
    Ok(())
}

fn to_transport_state(stored: &crate::domain::StoredEventCrdt) -> EventCrdtState {
    let signatures = stored
        .signatures
        .iter()
        .map(|s| CrdtSignature {
            input_index: s.input_index,
            pubkey: s.pubkey.clone(),
            signature: s.signature.clone(),
            signer_peer_id: Some(s.signer_peer_id.clone()),
            timestamp_nanos: s.timestamp_nanos,
        })
        .collect::<Vec<_>>();
    let completion = stored.completion.as_ref().map(|c| crate::infrastructure::transport::iroh::messages::CompletionRecord {
        tx_id: *c.tx_id.as_hash(),
        submitter_peer_id: c.submitter_peer_id.clone(),
        timestamp_nanos: c.timestamp_nanos,
        blue_score: c.blue_score,
    });

    EventCrdtState { signatures, completion, signing_event: stored.signing_event.clone(), kpsbt_blob: stored.kpsbt_blob.clone(), version: 0 }
}
