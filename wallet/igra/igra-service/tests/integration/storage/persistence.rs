use igra_core::coordination::hashes::event_hash;
use igra_core::model::{EventSource, RequestDecision, SigningEvent, SigningRequest};
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::types::{PeerId, RequestId, SessionId, TransactionId};
use std::collections::BTreeMap;
use tempfile::TempDir;

fn sample_event() -> SigningEvent {
    SigningEvent {
        event_id: "event-persist".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: 2_000_000,
        metadata: BTreeMap::new(),
        timestamp_nanos: 2,
        signature: None,
    }
}

#[tokio::test]
async fn persistence_across_restarts() {
    let temp_dir = TempDir::new().expect("temp dir");
    let event = sample_event();
    let ev_hash = event_hash(&event).expect("event hash");

    {
        let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("storage");
        storage.insert_event(ev_hash, event.clone()).expect("event insert");
        storage
            .insert_request(SigningRequest {
                request_id: RequestId::from("req-persist"),
                session_id: SessionId::from([2u8; 32]),
                event_hash: ev_hash,
                coordinator_peer_id: PeerId::from("peer-1"),
                tx_template_hash: [3u8; 32],
                validation_hash: [4u8; 32],
                decision: RequestDecision::Pending,
                expires_at_nanos: 0,
                final_tx_id: None,
                final_tx_accepted_blue_score: None,
            })
            .expect("request insert");
        storage.update_request_final_tx(&RequestId::from("req-persist"), TransactionId::from([5u8; 32])).expect("final tx update");
    }

    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("storage reopen");
    let stored_event = storage.get_event(&ev_hash).expect("event read").expect("event");
    assert_eq!(stored_event.event_id, "event-persist");

    let request = storage.get_request(&RequestId::from("req-persist")).expect("request read").expect("request");
    assert!(matches!(request.decision, RequestDecision::Finalized));
    assert_eq!(request.final_tx_id, Some(TransactionId::from([5u8; 32])));
}
