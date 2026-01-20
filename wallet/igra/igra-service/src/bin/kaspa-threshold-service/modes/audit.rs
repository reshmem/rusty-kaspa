use igra_core::domain::StoredEvent;
use igra_core::foundation::{EventId, Hash32, ThresholdError};
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::storage::Storage;
use log::info;
use serde::Serialize;

#[derive(Serialize)]
struct AuditReport {
    event_id_hex: String,
    event: Option<StoredEvent>,
    crdts: Vec<AuditCrdtEntry>,
}

#[derive(Serialize)]
struct AuditCrdtEntry {
    tx_template_hash_hex: String,
    has_signing_material: bool,
    has_kpsbt_blob: bool,
    signature_count: usize,
    signatures: Vec<AuditSignature>,
    completion: Option<AuditCompletion>,
    created_at_nanos: u64,
    updated_at_nanos: u64,
}

#[derive(Serialize)]
struct AuditSignature {
    signer_peer_id: String,
    input_index: u32,
    pubkey_hex: String,
    signature_hex: String,
    timestamp_nanos: u64,
}

#[derive(Serialize)]
struct AuditCompletion {
    tx_id_hex: String,
    submitter_peer_id: String,
    timestamp_nanos: u64,
    blue_score: Option<u64>,
}

pub fn dump_audit_trail(event_id_hex: &str, storage: &RocksStorage) -> Result<(), ThresholdError> {
    info!("Audit mode: dumping CRDT trail for {}", event_id_hex);
    let event_id = EventId::from(parse_hash32_hex(event_id_hex)?);
    let report = build_audit_report(storage, &event_id)?;
    let json = serde_json::to_string_pretty(&report)?;
    println!("{}", json);
    Ok(())
}

fn build_audit_report(storage: &RocksStorage, event_id: &EventId) -> Result<AuditReport, ThresholdError> {
    let event = storage.get_event(event_id)?;
    let mut crdts = storage.list_event_crdts_for_event(event_id)?;
    crdts.sort_by(|a, b| a.tx_template_hash.cmp(&b.tx_template_hash));

    let crdts = crdts
        .into_iter()
        .map(|state| AuditCrdtEntry {
            tx_template_hash_hex: hex::encode(state.tx_template_hash),
            has_signing_material: state.signing_material.is_some(),
            has_kpsbt_blob: state.kpsbt_blob.is_some(),
            signature_count: state.signatures.len(),
            signatures: state
                .signatures
                .into_iter()
                .map(|sig| AuditSignature {
                    signer_peer_id: sig.signer_peer_id.to_string(),
                    input_index: sig.input_index,
                    pubkey_hex: hex::encode(sig.pubkey),
                    signature_hex: hex::encode(sig.signature),
                    timestamp_nanos: sig.timestamp_nanos,
                })
                .collect(),
            completion: state.completion.map(|c| AuditCompletion {
                tx_id_hex: hex::encode(c.tx_id.as_hash()),
                submitter_peer_id: c.submitter_peer_id.to_string(),
                timestamp_nanos: c.timestamp_nanos,
                blue_score: c.blue_score,
            }),
            created_at_nanos: state.created_at_nanos,
            updated_at_nanos: state.updated_at_nanos,
        })
        .collect();

    Ok(AuditReport { event_id_hex: event_id.to_string(), event, crdts })
}

fn parse_hash32_hex(value: &str) -> Result<Hash32, ThresholdError> {
    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let hash: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ThresholdError::Message(format!("expected 32-byte hex value, got {} bytes", bytes.len())))?;
    Ok(hash)
}
