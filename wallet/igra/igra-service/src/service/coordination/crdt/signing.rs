use super::broadcast::broadcast_local_state;
use super::types::{record_signed_hash_or_conflict, signed_hash_conflict_error, CrdtHandlerContext};
use igra_core::application::pskt_multisig;
use igra_core::application::{StoredEvent, StoredEventCrdt};
use igra_core::foundation::{now_nanos, ThresholdError};
use log::{debug, info};

pub(crate) async fn maybe_sign_and_broadcast(ctx: &CrdtHandlerContext<'_>, state: &StoredEventCrdt) -> Result<(), ThresholdError> {
    if state.completion.is_some() {
        return Ok(());
    }

    if let Some(existing) = ctx.phase_storage.get_signed_hash(&state.event_id)? {
        if existing != state.tx_template_hash {
            return Err(signed_hash_conflict_error(&state.event_id, existing, state.tx_template_hash));
        }
    }

    if state.signatures.iter().any(|s| &s.signer_peer_id == ctx.local_peer_id) {
        let now = now_nanos();
        record_signed_hash_or_conflict(ctx.phase_storage, &state.event_id, state.tx_template_hash, now)?;
        return Ok(());
    }

    let Some(signing_material) = state.signing_material.as_ref() else {
        debug!(
            "missing signing_material locally; cannot sign event_id={:#x} tx_template_hash={:#x}",
            state.event_id, state.tx_template_hash
        );
        return Ok(());
    };

    let now = now_nanos();

    let policy_event = StoredEvent {
        event: signing_material.event.clone(),
        received_at_nanos: now,
        audit: signing_material.audit.clone(),
        proof: signing_material.proof.clone(),
    };

    // Fix #1: verify source proof before signing any gossip-originated event.
    let pipeline = igra_core::application::signing_pipeline::SigningPipeline::new(
        ctx.flow.message_verifier_ref(),
        &ctx.app_config.policy,
        ctx.storage.as_ref(),
        now,
    );
    pipeline.verify_and_enforce(&policy_event)?;

    // Fix #2: ensure we also have an event record for gossip-only ingests
    // (required for accurate daily volume tracking on completion).
    let inserted = ctx.storage.insert_event_if_not_exists(state.event_id, policy_event)?;
    if inserted {
        debug!(
            "stored event from CRDT signing material event_id={:#x} tx_template_hash={:#x}",
            state.event_id, state.tx_template_hash
        );
    }

    // Fix #3: rebuild the PSKT locally from the verified event data and ensure it matches the CRDT tx_template_hash.
    let kpsbt_blob = state.kpsbt_blob.as_deref().ok_or_else(|| ThresholdError::MissingKpsbtBlob {
        event_id: state.event_id.to_string(),
        tx_template_hash: state.tx_template_hash.to_string(),
        context: "maybe_sign_and_broadcast".to_string(),
    })?;
    pskt_multisig::validate_kpsbt_blob_matches_tx_template_hash(kpsbt_blob, &state.tx_template_hash)?;
    let signer_pskt = pskt_multisig::deserialize_pskt_signer(kpsbt_blob)?;

    let input_count = signer_pskt.inputs.len();
    let (pubkey, sigs) = igra_core::application::pskt_signing::sign_pskt_with_app_config(
        ctx.app_config,
        &ctx.flow.key_context(),
        signer_pskt,
        igra_core::application::pskt_signing::PsktSigningContext {
            event_id: &state.event_id,
            tx_template_hash: &state.tx_template_hash,
            purpose: "maybe_sign_and_broadcast",
        },
    )
    .await?;
    for (input_index, signature) in sigs {
        ctx.storage.add_signature_to_crdt(
            &state.event_id,
            &state.tx_template_hash,
            input_index,
            &pubkey,
            &signature,
            ctx.local_peer_id,
            now,
        )?;
    }
    info!(
        "signed and stored CRDT signatures event_id={:#x} tx_template_hash={:#x} input_count={}",
        state.event_id, state.tx_template_hash, input_count
    );

    record_signed_hash_or_conflict(ctx.phase_storage, &state.event_id, state.tx_template_hash, now)?;

    broadcast_local_state(ctx.transport, ctx.storage, ctx.phase_storage, ctx.local_peer_id, &state.event_id, &state.tx_template_hash)
        .await?;
    Ok(())
}
