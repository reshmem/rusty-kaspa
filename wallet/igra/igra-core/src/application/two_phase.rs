//! Two-phase proposal construction helpers.
//!
//! The service uses a two-phase coordination protocol (propose/commit) to ensure that signers
//! converge on a single canonical transaction template for an event, before collecting
//! signatures via the CRDT layer.
//!
//! This module builds a local proposal for a given round, including deterministic UTXO
//! selection seeding to reduce repeated collisions across retries.

use crate::domain::coordination::{KaspaAnchorRef, ProposalBroadcast};
use crate::domain::pskt::params::{PsktOutputParams, UtxoInput};
use crate::domain::{CrdtSigningMaterial, StoredEvent};
use crate::foundation::{EventId, PeerId, ThresholdError};
use crate::infrastructure::config::ServiceConfig;
use crate::infrastructure::keys::KeyManagerContext;
use crate::infrastructure::rpc::kaspa_integration::build_pskt_from_rpc_seeded;
use crate::infrastructure::rpc::NodeRpc;
use log::warn;

pub async fn build_local_proposal_for_round(
    rpc: &dyn NodeRpc,
    service_config: &ServiceConfig,
    key_context: &KeyManagerContext,
    stored_event: &StoredEvent,
    local_peer_id: &PeerId,
    round: u32,
    now_ns: u64,
) -> Result<(ProposalBroadcast, KaspaAnchorRef), ThresholdError> {
    let event_id = crate::domain::hashes::compute_event_id(&stored_event.event);
    let pskt_config = crate::application::event_processor::resolve_pskt_config(service_config, key_context, stored_event).await?;

    // Seed UTXO selection by (event_id, round) so that events with identical output parameters
    // don't continuously pick the same inputs across concurrent execution and retries.
    let mut hasher = blake3::Hasher::new();
    hasher.update(event_id.as_ref());
    hasher.update(&round.to_le_bytes());
    let digest = hasher.finalize();
    let mut selection_seed = [0u8; 32];
    selection_seed.copy_from_slice(digest.as_bytes());

    let (_selection, build) = build_pskt_from_rpc_seeded(rpc, &pskt_config, selection_seed).await?;
    let signer_pskt = crate::domain::pskt::multisig::to_signer(build.pskt);
    let kpsbt_blob = crate::domain::pskt::multisig::serialize_pskt(&signer_pskt)?;
    let tx_template_hash = crate::domain::pskt::multisig::tx_template_hash(&signer_pskt)?;

    let inner: &kaspa_wallet_pskt::pskt::Inner = &signer_pskt;
    let utxos_used = inner
        .inputs
        .iter()
        .filter_map(|input| input.utxo_entry.clone().map(|entry| UtxoInput { outpoint: input.previous_outpoint, entry }))
        .collect::<Vec<_>>();
    if utxos_used.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("proposal build produced no utxos_used".to_string()));
    }
    let outputs = pskt_config
        .outputs
        .iter()
        .map(|o| PsktOutputParams { address: o.address.clone(), amount_sompi: o.amount_sompi })
        .collect::<Vec<_>>();
    if outputs.is_empty() {
        return Err(ThresholdError::PsktValidationFailed("proposal build produced no outputs".to_string()));
    }

    let signing_material = CrdtSigningMaterial {
        event: stored_event.event.clone(),
        audit: stored_event.audit.clone(),
        proof: stored_event.proof.clone(),
    };

    let tip_blue_score = match rpc.get_virtual_selected_parent_blue_score().await {
        Ok(score) => score,
        Err(err) => {
            warn!(
                "two_phase: get_virtual_selected_parent_blue_score failed, defaulting tip_blue_score=0 event_id={:#x} round={} error={}",
                event_id, round, err
            );
            0
        }
    };
    let anchor = KaspaAnchorRef { tip_blue_score };

    let proposal = ProposalBroadcast {
        event_id,
        round,
        tx_template_hash,
        kpsbt_blob,
        utxos_used,
        outputs,
        signing_material,
        proposer_peer_id: local_peer_id.clone(),
        timestamp_ns: now_ns,
    };

    Ok((proposal, anchor))
}

pub fn extract_event_id_from_signing_material(signing_material: &CrdtSigningMaterial) -> EventId {
    crate::domain::hashes::compute_event_id(&signing_material.event)
}

pub fn revalidate_utxos_for_proposal(
    rpc_tip_blue_score: u64,
    proposal: &ProposalBroadcast,
    min_input_score_depth: u64,
) -> Result<(), ThresholdError> {
    let min = min_input_score_depth;
    for utxo in &proposal.utxos_used {
        let depth = rpc_tip_blue_score.saturating_sub(utxo.entry.block_daa_score);
        if depth < min {
            return Err(ThresholdError::UtxoBelowMinDepth { outpoint: utxo.outpoint.to_string(), depth, min_required: min });
        }
    }
    Ok(())
}
