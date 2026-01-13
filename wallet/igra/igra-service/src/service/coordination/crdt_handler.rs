use crate::service::coordination::{derive_ordered_pubkeys, params_for_network_id};
use crate::service::flow::ServiceFlow;
use igra_core::application::event_processor::resolve_pskt_config;
use igra_core::domain::policy::enforcement::{DefaultPolicyEnforcer, PolicyEnforcer};
use igra_core::domain::pskt::multisig as pskt_multisig;
use igra_core::domain::{PartialSigRecord, StoredEvent};
use igra_core::foundation::{Hash32, PeerId, ThresholdError, TransactionId};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::rpc::kaspa_integration::build_pskt_from_rpc;
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::Transport;
use igra_core::infrastructure::transport::messages::{
    EventCrdtState, EventStateBroadcast, StateSyncRequest, StateSyncResponse,
};
use kaspa_wallet_core::prelude::Secret;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::sync::Arc;

pub async fn handle_crdt_broadcast(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    local_peer_id: &PeerId,
    broadcast: EventStateBroadcast,
) -> Result<(), ThresholdError> {
    let event_id = broadcast.event_id;
    let tx_template_hash = broadcast.tx_template_hash;

    if let Ok(existing) = storage.list_event_crdts_for_event(&event_id) {
        let mut other_hashes =
            existing.iter().filter(|s| s.tx_template_hash != tx_template_hash).map(|s| s.tx_template_hash).collect::<Vec<_>>();
        other_hashes.sort();
        other_hashes.dedup();
        if !other_hashes.is_empty() {
            warn!(
                "received CRDT broadcast with tx_template_hash mismatch against local states event_id={} received_tx_template_hash={} local_other_tx_template_hashes={}",
                hex::encode(event_id),
                hex::encode(tx_template_hash),
                other_hashes
                    .iter()
                    .take(3)
                    .map(|h| hex::encode(h))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            flow.metrics().inc_tx_template_hash_mismatch("network");
        }
    }

    info!(
        "received CRDT broadcast event_id={} tx_template_hash={} from_peer={} sig_count={} completed={}",
        hex::encode(event_id),
        hex::encode(tx_template_hash),
        broadcast.sender_peer_id,
        broadcast.state.signatures.len(),
        broadcast.state.completion.is_some()
    );

    let (local_state, changed) = storage.merge_event_crdt(
        &event_id,
        &tx_template_hash,
        &broadcast.state,
        broadcast.state.signing_material.as_ref(),
        broadcast.state.kpsbt_blob.as_deref(),
    )?;
    if !changed {
        debug!("CRDT merge no-op event_id={} tx_template_hash={}", hex::encode(event_id), hex::encode(tx_template_hash));
        return Ok(());
    }

    info!(
        "CRDT merged event_id={} tx_template_hash={} local_sig_count={} completed={}",
        hex::encode(event_id),
        hex::encode(tx_template_hash),
        local_state.signatures.len(),
        local_state.completion.is_some()
    );

    if local_state.completion.is_some() {
        return Ok(());
    }

    maybe_sign_and_broadcast(app_config, flow, transport, storage, local_peer_id, &local_state).await?;
    maybe_submit_and_broadcast(app_config, flow, transport, storage, local_peer_id, &event_id, &tx_template_hash).await?;
    Ok(())
}

pub async fn broadcast_local_state(
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    local_peer_id: &PeerId,
    event_id: &Hash32,
    tx_template_hash: &Hash32,
) -> Result<(), ThresholdError> {
    let state = storage
        .get_event_crdt(event_id, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;

    let crdt_state = EventCrdtState::from(&state);

    transport
        .publish_event_state(EventStateBroadcast {
            event_id: *event_id,
            tx_template_hash: *tx_template_hash,
            state: crdt_state,
            sender_peer_id: local_peer_id.clone(),
        })
        .await
}

pub async fn handle_state_sync_request(
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    local_peer_id: &PeerId,
    request: StateSyncRequest,
) -> Result<(), ThresholdError> {
    if request.requester_peer_id == *local_peer_id {
        return Ok(());
    }

    if request.event_ids.is_empty() {
        return Ok(());
    }

    // Bound the work to avoid unbounded CPU/memory on malformed requests.
    const MAX_EVENTS_PER_REQUEST: usize = 256;
    let event_ids = request.event_ids.into_iter().take(MAX_EVENTS_PER_REQUEST).collect::<Vec<_>>();

    debug!("state sync request received requester_peer_id={} event_count={}", request.requester_peer_id, event_ids.len());

    let mut states_out = Vec::new();
    for event_id in event_ids {
        let crdts = storage.list_event_crdts_for_event(&event_id)?;
        for state in crdts {
            let crdt_state = EventCrdtState::from(&state);
            states_out.push((state.event_id, state.tx_template_hash, crdt_state));
        }
    }

    if states_out.is_empty() {
        debug!("state sync request has no matching local states requester_peer_id={}", request.requester_peer_id);
        return Ok(());
    }

    debug!(
        "sending state sync response requester_peer_id={} state_count={} event_ids={}",
        request.requester_peer_id,
        states_out.len(),
        states_out
            .iter()
            .take(3)
            .map(|(eid, _, _)| hex::encode(eid))
            .collect::<Vec<_>>()
            .join(",")
    );
    transport.publish_state_sync_response(StateSyncResponse { states: states_out }).await
}

pub async fn handle_state_sync_response(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    local_peer_id: &PeerId,
    response: StateSyncResponse,
) -> Result<(), ThresholdError> {
    if response.states.is_empty() {
        return Ok(());
    }

    debug!(
        "state sync response received state_count={} event_ids={}",
        response.states.len(),
        response
            .states
            .iter()
            .take(3)
            .map(|(eid, _, _)| hex::encode(eid))
            .collect::<Vec<_>>()
            .join(",")
    );

    for (event_id, tx_template_hash, incoming) in response.states {
        let (local_state, changed) = storage.merge_event_crdt(
            &event_id,
            &tx_template_hash,
            &incoming,
            incoming.signing_material.as_ref(),
            incoming.kpsbt_blob.as_deref(),
        )?;
        if !changed {
            continue;
        }

        debug!(
            "state sync merged event_id={} tx_template_hash={} local_sig_count={} completed={}",
            hex::encode(event_id),
            hex::encode(tx_template_hash),
            local_state.signatures.len(),
            local_state.completion.is_some()
        );

        if local_state.completion.is_some() {
            continue;
        }

        maybe_sign_and_broadcast(app_config, flow, transport, storage, local_peer_id, &local_state).await?;
        maybe_submit_and_broadcast(app_config, flow, transport, storage, local_peer_id, &event_id, &tx_template_hash).await?;
    }

    Ok(())
}

pub async fn run_anti_entropy_loop(
    storage: Arc<dyn Storage>,
    transport: Arc<dyn Transport>,
    local_peer_id: PeerId,
    interval_secs: u64,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;

        match storage.list_pending_event_crdts() {
            Ok(pending) => {
                if !pending.is_empty() {
                    let mut uniq = HashSet::new();
                    let mut event_ids = Vec::new();
                    for state in &pending {
                        if uniq.insert(state.event_id) {
                            event_ids.push(state.event_id);
                        }
                    }

                    if !event_ids.is_empty() {
                        if let Err(err) = transport
                            .publish_state_sync_request(StateSyncRequest { event_ids, requester_peer_id: local_peer_id.clone() })
                            .await
                        {
                            debug!(
                                "anti-entropy state sync request failed error={} pending_count={}",
                                err,
                                pending.len()
                            );
                        }
                    }
                }

                for state in pending {
                    if let Err(err) =
                        broadcast_local_state(&transport, &storage, &local_peer_id, &state.event_id, &state.tx_template_hash).await
                    {
                        debug!(
                            "anti-entropy broadcast failed event_id={} tx_template_hash={} error={}",
                            hex::encode(state.event_id),
                            hex::encode(state.tx_template_hash),
                            err
                        );
                    }
                }
            }
            Err(err) => warn!("failed to list pending CRDT events: {}", err),
        }
    }
}

async fn maybe_sign_and_broadcast(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    local_peer_id: &PeerId,
    state: &igra_core::domain::StoredEventCrdt,
) -> Result<(), ThresholdError> {
    if state.completion.is_some() {
        return Ok(());
    }

    if state.signatures.iter().any(|s| &s.signer_peer_id == local_peer_id) {
        return Ok(());
    }

    let Some(signing_material) = state.signing_material.as_ref() else {
        debug!(
            "missing signing_material locally; cannot sign event_id={} tx_template_hash={}",
            hex::encode(state.event_id),
            hex::encode(state.tx_template_hash)
        );
        return Ok(());
    };

    let now = now_nanos();

    // Fix #2: ensure we also have an event record for gossip-only ingests
    // (required for accurate daily volume tracking on completion).
    let policy_event = StoredEvent {
        event: signing_material.event.clone(),
        received_at_nanos: now,
        audit: signing_material.audit.clone(),
        proof: signing_material.proof.clone(),
    };
    storage.insert_event_if_not_exists(state.event_id, policy_event.clone())?;

    // Fix #1: verify source proof before signing any gossip-originated event.
    let report = flow.message_verifier().verify(&policy_event)?;
    if !report.valid {
        warn!(
            "gossip event failed source verification event_id={} tx_template_hash={} source={:?} validator_count={} valid_signatures={} threshold={} failure={:?}",
            hex::encode(state.event_id),
            hex::encode(state.tx_template_hash),
            report.source,
            report.validator_count,
            report.valid_signatures,
            report.threshold_required,
            report.failure_reason
        );
        return Err(ThresholdError::EventSignatureInvalid);
    }

    validate_before_signing(flow, &app_config.policy, &policy_event).await?;

    // Fix #3: rebuild the PSKT locally from the verified event data and ensure it matches the CRDT tx_template_hash.
    let pskt_config = resolve_pskt_config(&app_config.service, &policy_event)?;
    let (_selection, build) = build_pskt_from_rpc(flow.rpc().as_ref(), &pskt_config).await?;
    let signer_pskt = pskt_multisig::to_signer(build.pskt);
    let our_tx_template_hash = pskt_multisig::tx_template_hash(&signer_pskt)?;
    if our_tx_template_hash != state.tx_template_hash {
        flow.metrics().inc_tx_template_hash_mismatch("local_rebuild");
        warn!(
            "tx_template_hash mismatch (refusing to sign) event_id={} expected={} computed={} input_count={} output_count={} destination_address={} amount_sompi={}",
            hex::encode(state.event_id),
            hex::encode(state.tx_template_hash),
            hex::encode(our_tx_template_hash),
            signer_pskt.inputs.len(),
            signer_pskt.outputs.len(),
            signing_material.audit.destination_raw,
            signing_material.event.amount_sompi
        );
        return Err(ThresholdError::PsktMismatch {
            expected: hex::encode(state.tx_template_hash),
            actual: hex::encode(our_tx_template_hash),
        });
    }

    let (pubkey, sigs) = sign_pskt(app_config, &signer_pskt)?;
    for (input_index, signature) in sigs {
        storage.add_signature_to_crdt(
            &state.event_id,
            &state.tx_template_hash,
            input_index,
            &pubkey,
            &signature,
            local_peer_id,
            now,
        )?;
    }
    info!(
        "signed and stored CRDT signatures event_id={} tx_template_hash={} input_count={}",
        hex::encode(state.event_id),
        hex::encode(state.tx_template_hash),
        signer_pskt.inputs.len()
    );

    broadcast_local_state(transport, storage, local_peer_id, &state.event_id, &state.tx_template_hash).await?;
    Ok(())
}

async fn maybe_submit_and_broadcast(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    transport: &Arc<dyn Transport>,
    storage: &Arc<dyn Storage>,
    local_peer_id: &PeerId,
    event_id: &Hash32,
    tx_template_hash: &Hash32,
) -> Result<(), ThresholdError> {
    let state = storage
        .get_event_crdt(event_id, tx_template_hash)?
        .ok_or_else(|| ThresholdError::Message("missing CRDT state".to_string()))?;

    if state.completion.is_some() {
        return Ok(());
    }

    // IMPORTANT: `sig_op_count` is *not* the multisig threshold.
    // - `sig_op_count` must be an upper bound for the number of sigops executed by the redeem script (≈ N).
    // - required signatures is the multisig threshold (M) and controls how many signatures we push to the script.
    let required_signatures = app_config
        .group
        .as_ref()
        .map(|g| usize::from(g.threshold_m))
        .or_else(|| app_config.service.hd.as_ref().map(|hd| hd.required_sigs))
        .ok_or_else(|| ThresholdError::ConfigError("missing group.threshold_m or service.hd.required_sigs".to_string()))?;
    if required_signatures == 0 {
        return Err(ThresholdError::ConfigError("required signatures must be > 0".to_string()));
    }

    let Some(kpsbt_blob) = state.kpsbt_blob.as_deref() else {
        return Ok(());
    };
    let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;
    let input_count = signer_pskt.inputs.len();

    if !storage.crdt_has_threshold(event_id, tx_template_hash, input_count, required_signatures)? {
        return Ok(());
    }

    info!(
        "threshold reached, attempting submission event_id={} tx_template_hash={} sig_count={} required={}",
        hex::encode(event_id),
        hex::encode(tx_template_hash),
        state.signatures.len(),
        required_signatures
    );

    let tx_id = attempt_submission(app_config, flow, &state).await?;
    let tx_id = TransactionId::from(tx_id);

    let now = now_nanos();
    let blue_score = flow.rpc().get_virtual_selected_parent_blue_score().await.ok();
    let (_, changed) = storage.mark_crdt_completed(event_id, tx_template_hash, tx_id, local_peer_id, now, blue_score)?;
    if changed {
        info!(
            "CRDT completion recorded event_id={} tx_template_hash={} tx_id={}",
            hex::encode(event_id),
            hex::encode(tx_template_hash),
            hex::encode(tx_id.as_hash())
        );
        broadcast_local_state(transport, storage, local_peer_id, event_id, tx_template_hash).await?;
    }

    Ok(())
}

async fn validate_before_signing(
    flow: &ServiceFlow,
    policy: &igra_core::domain::GroupPolicy,
    event: &StoredEvent,
) -> Result<(), ThresholdError> {
    let volume = flow.storage().get_volume_since(now_nanos())?;
    let result = DefaultPolicyEnforcer::new().evaluate_policy(event, policy, volume);
    if !result.allowed {
        return Err(ThresholdError::Message("policy rejected signing event".to_string()));
    }
    Ok(())
}

fn sign_pskt(
    app_config: &AppConfig,
    pskt: &kaspa_wallet_pskt::prelude::PSKT<kaspa_wallet_pskt::prelude::Signer>,
) -> Result<(Vec<u8>, Vec<(u32, Vec<u8>)>), ThresholdError> {
    let hd = app_config.service.hd.as_ref().ok_or_else(|| ThresholdError::ConfigError("missing HD config".to_string()))?;
    let key_data = hd.decrypt_mnemonics()?;
    let payment_secret = hd.passphrase.as_deref().map(Secret::from);

    let keypair = igra_core::foundation::hd::derive_keypair_from_key_data(
        key_data.first().ok_or_else(|| ThresholdError::ConfigError("missing mnemonic".to_string()))?,
        hd.derivation_path.as_deref(),
        payment_secret.as_ref(),
    )?
    .to_secp256k1()?;

    let signed = pskt_multisig::sign_pskt(pskt.clone(), &keypair)?.pskt;
    let canonical_pubkey = pskt_multisig::canonical_schnorr_pubkey_for_keypair(&keypair);
    let pubkey = canonical_pubkey.serialize().to_vec();
    let sigs = pskt_multisig::partial_sigs_for_pubkey(&signed, &canonical_pubkey);
    Ok((pubkey, sigs))
}

async fn attempt_submission(
    app_config: &AppConfig,
    flow: &ServiceFlow,
    state: &igra_core::domain::StoredEventCrdt,
) -> Result<kaspa_consensus_core::tx::TransactionId, ThresholdError> {
    let Some(kpsbt_blob) = state.kpsbt_blob.as_deref() else {
        return Err(ThresholdError::Message("missing kpsbt_blob".to_string()));
    };

    let partials = state
        .signatures
        .iter()
        .map(|s| PartialSigRecord {
            signer_peer_id: s.signer_peer_id.clone(),
            input_index: s.input_index,
            pubkey: s.pubkey.clone(),
            signature: s.signature.clone(),
            timestamp_nanos: s.timestamp_nanos,
        })
        .collect::<Vec<_>>();

    let pskt = pskt_multisig::apply_partial_sigs(kpsbt_blob, &partials)?;

    let required = app_config
        .group
        .as_ref()
        .map(|g| usize::from(g.threshold_m))
        .or_else(|| app_config.service.hd.as_ref().map(|hd| hd.required_sigs))
        .ok_or_else(|| ThresholdError::ConfigError("missing group.threshold_m or service.hd.required_sigs".to_string()))?;
    let ordered_pubkeys = derive_ordered_pubkeys(&app_config.service)?;
    let params = params_for_network_id(app_config.iroh.network_id);

    if required == 0 || required > ordered_pubkeys.len() {
        return Err(ThresholdError::ConfigError(format!(
            "invalid required signatures: required={required} pubkey_count={}",
            ordered_pubkeys.len()
        )));
    }

    flow.finalize_and_submit(state.event_id, pskt, required, &ordered_pubkeys, params).await
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}
