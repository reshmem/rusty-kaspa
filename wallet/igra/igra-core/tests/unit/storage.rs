use igra_core::model::{
    EventSource, GroupConfig, GroupMetadata, GroupPolicy, Hash32, PartialSigRecord, RequestDecision, RequestInput,
    SignerAckRecord, SigningEvent, SigningRequest, StoredProposal,
};
use igra_core::storage::rocks::RocksStorage;
use igra_core::storage::Storage;
use igra_core::types::{PeerId, RequestId, SessionId, TransactionId};
use tempfile::TempDir;

fn sample_event(amount: u64, timestamp_nanos: u64) -> SigningEvent {
    SigningEvent {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: amount,
        metadata: Default::default(),
        timestamp_nanos,
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
fn rocksdb_roundtrip_and_volume_tracking() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let event = sample_event(100, 10);
    let event_hash = [9u8; 32];
    storage.insert_event(event_hash, event.clone()).expect("insert event");

    let request = sample_request("req-1", event_hash);
    storage.insert_request(request.clone()).expect("insert request");

    let proposal = StoredProposal {
        request_id: request.request_id.clone(),
        session_id: request.session_id,
        event_hash,
        validation_hash: request.validation_hash,
        signing_event: event.clone(),
        kpsbt_blob: vec![1, 2, 3],
    };
    storage.insert_proposal(&request.request_id, proposal).expect("insert proposal");

    let ack = SignerAckRecord {
        signer_peer_id: PeerId::from("peer-2"),
        accept: true,
        reason: None,
        timestamp_nanos: 11,
    };
    storage.insert_signer_ack(&request.request_id, ack).expect("insert ack");

    let sig = PartialSigRecord {
        signer_peer_id: PeerId::from("peer-2"),
        input_index: 0,
        pubkey: vec![1, 2, 3],
        signature: vec![4, 5, 6],
        timestamp_nanos: 12,
    };
    storage.insert_partial_sig(&request.request_id, sig).expect("insert sig");

    let input = RequestInput {
        input_index: 0,
        utxo_tx_id: [1u8; 32],
        utxo_output_index: 0,
        utxo_value: 100,
        signing_hash: [2u8; 32],
        my_signature: None,
    };
    storage.insert_request_input(&request.request_id, input).expect("insert input");

    let volume = storage.get_volume_since(5).expect("volume");
    assert_eq!(volume, 100);

    let volume_none = storage.get_volume_since(20).expect("volume none");
    assert_eq!(volume_none, 0);
}

#[test]
fn rocksdb_group_config_roundtrip() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");
    let config = GroupConfig {
        network_id: 0,
        threshold_m: 2,
        threshold_n: 3,
        member_pubkeys: vec![vec![1, 2, 3]],
        fee_rate_sompi_per_gram: 1,
        finality_blue_score_threshold: 5,
        dust_threshold_sompi: 1,
        min_recipient_amount_sompi: 1,
        session_timeout_seconds: 10,
        group_metadata: GroupMetadata { creation_timestamp_nanos: 0, group_name: None, policy_version: 1, extra: Default::default() },
        policy: GroupPolicy::default(),
    };
    storage.upsert_group_config([5u8; 32], config.clone()).expect("upsert");
    let loaded = storage.get_group_config(&[5u8; 32]).expect("get");
    assert!(loaded.is_some());
}

#[test]
fn rocksdb_checkpoint_roundtrip() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = RocksStorage::open_in_dir(temp_dir.path()).expect("open rocksdb");

    let event = sample_event(50, 10);
    let event_hash = [4u8; 32];
    storage.insert_event(event_hash, event.clone()).expect("insert event");

    let request = sample_request("req-checkpoint", event_hash);
    storage.insert_request(request.clone()).expect("insert request");

    let checkpoint_dir = TempDir::new().expect("checkpoint dir");
    storage
        .create_checkpoint(checkpoint_dir.path())
        .expect("create checkpoint");

    let restored = RocksStorage::open(checkpoint_dir.path()).expect("open checkpoint");
    let loaded = restored
        .get_request(&RequestId::from("req-checkpoint"))
        .expect("get request");
    assert!(loaded.is_some());
}
