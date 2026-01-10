use igra_core::domain::hashes::event_hash;
use igra_core::domain::{EventSource, RequestDecision, SigningEvent, SigningRequest};
use igra_core::foundation::{PeerId, RequestId, SessionId, TransactionId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use std::collections::BTreeMap;
use tempfile::TempDir;

fn make_event(id: &str, amount: u64, timestamp_nanos: u64) -> SigningEvent {
    SigningEvent {
        event_id: id.to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: amount,
        metadata: BTreeMap::new(),
        timestamp_nanos,
        signature: None,
    }
}

#[tokio::test]
async fn volume_tracking_sums_finalized_requests() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("storage");

    let nanos_per_day = 24u64 * 60 * 60 * 1_000_000_000;
    let base_ts = 1_700_000_000_000_000_000u64;
    let event_a = make_event("event-vol-a", 10, base_ts + 10);
    let event_b = make_event("event-vol-b", 20, base_ts + 20);
    let event_c = make_event("event-vol-c", 30, base_ts + nanos_per_day + 30);

    let hash_a = event_hash(&event_a).expect("hash a");
    let hash_b = event_hash(&event_b).expect("hash b");
    let hash_c = event_hash(&event_c).expect("hash c");

    storage.insert_event(hash_a, event_a.clone()).expect("event a insert");
    storage.insert_event(hash_b, event_b.clone()).expect("event b insert");
    storage.insert_event(hash_c, event_c.clone()).expect("event c insert");

    storage
        .insert_request(SigningRequest {
            request_id: RequestId::from("req-vol-a"),
            session_id: SessionId::from([1u8; 32]),
            event_hash: hash_a,
            coordinator_peer_id: PeerId::from("peer-1"),
            tx_template_hash: [2u8; 32],
            validation_hash: [3u8; 32],
            decision: RequestDecision::Pending,
            expires_at_nanos: 0,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        })
        .expect("request a insert");
    storage
        .insert_request(SigningRequest {
            request_id: RequestId::from("req-vol-b"),
            session_id: SessionId::from([2u8; 32]),
            event_hash: hash_b,
            coordinator_peer_id: PeerId::from("peer-1"),
            tx_template_hash: [2u8; 32],
            validation_hash: [3u8; 32],
            decision: RequestDecision::Pending,
            expires_at_nanos: 0,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        })
        .expect("request b insert");
    storage
        .insert_request(SigningRequest {
            request_id: RequestId::from("req-vol-c"),
            session_id: SessionId::from([3u8; 32]),
            event_hash: hash_c,
            coordinator_peer_id: PeerId::from("peer-1"),
            tx_template_hash: [2u8; 32],
            validation_hash: [3u8; 32],
            decision: RequestDecision::Pending,
            expires_at_nanos: 0,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        })
        .expect("request c insert");

    storage.update_request_final_tx(&RequestId::from("req-vol-a"), TransactionId::from([9u8; 32])).expect("finalize a");
    storage.update_request_final_tx(&RequestId::from("req-vol-c"), TransactionId::from([8u8; 32])).expect("finalize c");

    // `get_volume_since` is a per-day counter used for daily policy enforcement.
    // It returns the total finalized volume for the day that contains the provided timestamp.
    let volume_day_1 = storage.get_volume_since(base_ts).expect("volume since base");
    assert_eq!(volume_day_1, 10);

    let volume_day_2 = storage.get_volume_since(base_ts + nanos_per_day + 1).expect("volume since late");
    assert_eq!(volume_day_2, 30);
}
