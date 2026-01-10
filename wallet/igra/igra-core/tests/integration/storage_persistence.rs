use igra_core::domain::{EventSource, RequestDecision, SigningEvent, SigningRequest};
use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId, TransactionId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use tempfile::TempDir;

fn sample_event() -> SigningEvent {
    SigningEvent {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0hz8jkn6ptfhq3v9fg3jhqw5jtsfgy62wan8dhe8fqkhdqsahswcpe2ch3m".to_string(),
        amount_sompi: 50,
        metadata: Default::default(),
        timestamp_nanos: 10,
        signature: None,
    }
}

fn sample_request(request_id: &str, event_hash: Hash32) -> SigningRequest {
    SigningRequest {
        request_id: RequestId::from(request_id),
        session_id: SessionId::from([7u8; 32]),
        event_hash,
        coordinator_peer_id: PeerId::from("peer-1"),
        tx_template_hash: [1u8; 32],
        validation_hash: [2u8; 32],
        decision: RequestDecision::Finalized,
        expires_at_nanos: 0,
        final_tx_id: Some(TransactionId::from([3u8; 32])),
        final_tx_accepted_blue_score: None,
    }
}

#[test]
fn test_storage_checkpoint_when_restored_then_request_is_present() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let event_hash = [4u8; 32];
    storage.insert_event(event_hash, sample_event()).expect("insert event");
    let request = sample_request("req-checkpoint", event_hash);
    storage.insert_request(request.clone()).expect("insert request");

    let checkpoint_dir = TempDir::new().expect("checkpoint dir");
    storage.create_checkpoint(checkpoint_dir.path()).expect("create checkpoint");

    let restored = RocksStorage::open(checkpoint_dir.path()).expect("open checkpoint");
    let loaded = restored.get_request(&RequestId::from("req-checkpoint")).expect("get request");
    assert!(loaded.is_some());
}
