use igra_core::domain::{Event, EventAuditData, SourceType, StoredEvent};
use igra_core::foundation::{Hash32, PeerId, ThresholdError, TransactionId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use igra_core::infrastructure::transport::messages::{CrdtSignature, EventCrdtState};
use kaspa_txscript::standard::pay_to_script_hash_script;
use std::collections::BTreeMap;
use tempfile::TempDir;

#[test]
fn test_crdt_storage_roundtrip_and_checkpoint() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let event_id: Hash32 = [1u8; 32];
    let tx_hash: Hash32 = [2u8; 32];

    let incoming = EventCrdtState {
        signatures: vec![CrdtSignature {
            input_index: 0,
            pubkey: vec![1],
            signature: vec![10],
            signer_peer_id: Some(PeerId::from("peer-1")),
            timestamp_nanos: 1000,
        }],
        completion: None,
        signing_material: None,
        kpsbt_blob: None,
        version: 0,
    };

    let (_state, changed) = storage.merge_event_crdt(&event_id, &tx_hash, &incoming, None, None)?;
    assert!(changed);

    let loaded = storage.get_event_crdt(&event_id, &tx_hash)?;
    assert!(loaded.is_some());

    let checkpoint_dir = TempDir::new().expect("checkpoint dir");
    storage.create_checkpoint(checkpoint_dir.path())?;

    let restored = RocksStorage::open(checkpoint_dir.path())?;
    let loaded = restored.get_event_crdt(&event_id, &tx_hash)?;
    assert!(loaded.is_some());
    Ok(())
}

#[tokio::test]
async fn test_concurrent_crdt_updates() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = std::sync::Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb"));
    let event_id: Hash32 = [1u8; 32];
    let tx_hash: Hash32 = [2u8; 32];

    let mut handles = Vec::new();
    for i in 0..10u8 {
        let storage = storage.clone();
        handles.push(tokio::spawn(async move {
            let incoming = EventCrdtState {
                signatures: vec![CrdtSignature {
                    input_index: 0,
                    pubkey: vec![i],
                    signature: vec![i.wrapping_mul(10)],
                    signer_peer_id: Some(PeerId::from(format!("peer-{}", i))),
                    timestamp_nanos: 1000 + i as u64,
                }],
                completion: None,
                signing_material: None,
                kpsbt_blob: None,
                version: 0,
            };
            storage.merge_event_crdt(&event_id, &tx_hash, &incoming, None, None)
        }));
    }

    for handle in handles {
        handle.await.expect("join").expect("merge");
    }

    let final_state = storage.get_event_crdt(&event_id, &tx_hash)?.expect("state");
    assert_eq!(final_state.signatures.len(), 10);
    Ok(())
}

#[test]
fn test_mark_completed_is_idempotent() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let event_id: Hash32 = [7u8; 32];
    let tx_hash: Hash32 = [8u8; 32];

    let incoming = EventCrdtState { signatures: vec![], completion: None, signing_material: None, kpsbt_blob: None, version: 0 };
    storage.merge_event_crdt(&event_id, &tx_hash, &incoming, None, None)?;

    let submitter = PeerId::from("submitter");
    let tx_id = TransactionId::from([9u8; 32]);
    storage.mark_crdt_completed(&event_id, &tx_hash, tx_id, &submitter, 10, Some(123))?;
    storage.mark_crdt_completed(&event_id, &tx_hash, tx_id, &submitter, 10, Some(123))?;

    let state = storage.get_event_crdt(&event_id, &tx_hash)?.expect("state");
    assert!(state.completion.is_some());
    Ok(())
}

#[test]
fn test_daily_volume_requires_event_record() -> Result<(), ThresholdError> {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    // Case 1: completion is recorded, but the event record is missing => volume does not update.
    let event_id_1: Hash32 = [11u8; 32];
    let tx_hash_1: Hash32 = [12u8; 32];
    let submitter = PeerId::from("submitter");
    let tx_id = TransactionId::from([13u8; 32]);
    storage.mark_crdt_completed(&event_id_1, &tx_hash_1, tx_id, &submitter, 10, None)?;
    assert_eq!(storage.get_volume_since(0)?, 0);

    // Case 2: event exists before completion => volume updates on first completion.
    let event_id_2: Hash32 = [21u8; 32];
    let tx_hash_2: Hash32 = [22u8; 32];
    let redeem = vec![1u8, 2, 3];
    let destination = pay_to_script_hash_script(&redeem);
    let stored_event = StoredEvent {
        event: Event { external_id: [99u8; 32], source: SourceType::Api, destination, amount_sompi: 4242 },
        received_at_nanos: 0,
        audit: EventAuditData { external_id_raw: "x".to_string(), destination_raw: "y".to_string(), source_data: BTreeMap::new() },
        proof: None,
    };
    storage.insert_event_if_not_exists(event_id_2, stored_event)?;
    storage.mark_crdt_completed(&event_id_2, &tx_hash_2, tx_id, &submitter, 10, None)?;
    assert_eq!(storage.get_volume_since(0)?, 4242);

    Ok(())
}
