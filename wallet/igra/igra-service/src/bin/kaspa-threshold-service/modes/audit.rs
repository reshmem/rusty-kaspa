use igra_core::error::ThresholdError;
use igra_core::model::{PartialSigRecord, RequestInput, SignerAckRecord, SigningEvent, SigningRequest};
use igra_core::storage::Storage;
use igra_core::storage::rocks::RocksStorage;
use igra_core::types::RequestId;
use serde::Serialize;

#[derive(Serialize)]
struct AuditReport {
    request: AuditRequest,
    proposal: Option<AuditProposal>,
    event: Option<SigningEvent>,
    inputs: Vec<AuditRequestInput>,
    signer_acks: Vec<SignerAckRecord>,
    partial_sigs: Vec<AuditPartialSig>,
}

#[derive(Serialize)]
struct AuditRequest {
    request_id: String,
    session_id_hex: String,
    event_hash_hex: String,
    coordinator_peer_id: String,
    tx_template_hash_hex: String,
    validation_hash_hex: String,
    decision: String,
    expires_at_nanos: u64,
    final_tx_id_hex: Option<String>,
    final_tx_accepted_blue_score: Option<u64>,
}

#[derive(Serialize)]
struct AuditRequestInput {
    input_index: u32,
    utxo_tx_id_hex: String,
    utxo_output_index: u32,
    utxo_value: u64,
    signing_hash_hex: String,
    my_signature_hex: Option<String>,
}

#[derive(Serialize)]
struct AuditProposal {
    request_id: String,
    session_id_hex: String,
    event_hash_hex: String,
    validation_hash_hex: String,
    kpsbt_hex: String,
}

#[derive(Serialize)]
struct AuditPartialSig {
    signer_peer_id: String,
    input_index: u32,
    pubkey_hex: String,
    signature_hex: String,
    timestamp_nanos: u64,
}

pub fn dump_audit_trail(request_id: &str, storage: &RocksStorage) -> Result<(), ThresholdError> {
    tracing::info!("Audit mode: dumping trail for {}", request_id);
    let report = build_audit_report(storage, &RequestId::from(request_id))?;
    let json = serde_json::to_string_pretty(&report).map_err(|err| ThresholdError::Message(err.to_string()))?;
    println!("{}", json);
    Ok(())
}

fn build_audit_report(storage: &RocksStorage, request_id: &RequestId) -> Result<AuditReport, ThresholdError> {
    let request = storage
        .get_request(request_id)?
        .ok_or_else(|| ThresholdError::KeyNotFound(format!("request not found: {}", request_id)))?;
    let event = storage.get_event(&request.event_hash)?;
    let proposal = storage.get_proposal(request_id)?;
    let inputs = storage.list_request_inputs(request_id)?;
    let signer_acks = storage.list_signer_acks(request_id)?;
    let partial_sigs = storage.list_partial_sigs(request_id)?;

    Ok(AuditReport {
        request: audit_request(&request),
        proposal: proposal.map(audit_proposal),
        event,
        inputs: inputs.into_iter().map(audit_input).collect(),
        signer_acks,
        partial_sigs: partial_sigs.into_iter().map(audit_partial_sig).collect(),
    })
}

fn audit_request(request: &SigningRequest) -> AuditRequest {
    AuditRequest {
        request_id: request.request_id.to_string(),
        session_id_hex: hex::encode(request.session_id.as_hash()),
        event_hash_hex: hex::encode(request.event_hash),
        coordinator_peer_id: request.coordinator_peer_id.to_string(),
        tx_template_hash_hex: hex::encode(request.tx_template_hash),
        validation_hash_hex: hex::encode(request.validation_hash),
        decision: format!("{:?}", request.decision),
        expires_at_nanos: request.expires_at_nanos,
        final_tx_id_hex: request.final_tx_id.map(|value| hex::encode(value.as_hash())),
        final_tx_accepted_blue_score: request.final_tx_accepted_blue_score,
    }
}

fn audit_input(input: RequestInput) -> AuditRequestInput {
    AuditRequestInput {
        input_index: input.input_index,
        utxo_tx_id_hex: hex::encode(input.utxo_tx_id),
        utxo_output_index: input.utxo_output_index,
        utxo_value: input.utxo_value,
        signing_hash_hex: hex::encode(input.signing_hash),
        my_signature_hex: input.my_signature.map(hex::encode),
    }
}

fn audit_partial_sig(sig: PartialSigRecord) -> AuditPartialSig {
    AuditPartialSig {
        signer_peer_id: sig.signer_peer_id.to_string(),
        input_index: sig.input_index,
        pubkey_hex: hex::encode(sig.pubkey),
        signature_hex: hex::encode(sig.signature),
        timestamp_nanos: sig.timestamp_nanos,
    }
}

fn audit_proposal(proposal: igra_core::model::StoredProposal) -> AuditProposal {
    AuditProposal {
        request_id: proposal.request_id.to_string(),
        session_id_hex: hex::encode(proposal.session_id.as_hash()),
        event_hash_hex: hex::encode(proposal.event_hash),
        validation_hash_hex: hex::encode(proposal.validation_hash),
        kpsbt_hex: hex::encode(proposal.kpsbt_blob),
    }
}
