use igra_core::domain::hashes::event_hash;
use igra_core::domain::{
    EventSource, PartialSigRecord, RequestDecision, RequestInput, SignerAckRecord, SigningEvent, SigningRequest, StoredProposal,
};
use igra_core::foundation::{PeerId, RequestId, SessionId, TransactionId};
use igra_core::infrastructure::storage::{RocksStorage, Storage};
use std::collections::BTreeMap;
use std::sync::Arc;
use tempfile::TempDir;

fn sample_event() -> SigningEvent {
    SigningEvent {
        event_id: "event-audit".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: 1_000_000,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    }
}

#[tokio::test]
async fn audit_trail_completeness() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let event = sample_event();
    let ev_hash = event_hash(&event).expect("event hash");
    let session_id = SessionId::from([7u8; 32]);
    let validation_hash = [9u8; 32];
    let request_id = RequestId::from("req-audit");

    storage.insert_event(ev_hash, event.clone()).expect("event insert");
    storage
        .insert_request(SigningRequest {
            request_id: request_id.clone(),
            session_id,
            event_hash: ev_hash,
            coordinator_peer_id: PeerId::from("peer-1"),
            tx_template_hash: [3u8; 32],
            validation_hash,
            decision: RequestDecision::Pending,
            expires_at_nanos: 0,
            final_tx_id: None,
            final_tx_accepted_blue_score: None,
        })
        .expect("request insert");
    storage
        .insert_proposal(
            &request_id,
            StoredProposal {
                request_id: request_id.clone(),
                session_id,
                event_hash: ev_hash,
                validation_hash,
                signing_event: event.clone(),
                kpsbt_blob: vec![1, 2, 3],
            },
        )
        .expect("proposal insert");

    storage
        .insert_request_input(
            &request_id,
            RequestInput {
                input_index: 0,
                utxo_tx_id: [4u8; 32],
                utxo_output_index: 1,
                utxo_value: 10,
                signing_hash: [5u8; 32],
                my_signature: Some(vec![6, 7, 8]),
            },
        )
        .expect("input insert");

    storage
        .insert_signer_ack(
            &request_id,
            SignerAckRecord { signer_peer_id: PeerId::from("peer-2"), accept: true, reason: None, timestamp_nanos: 10 },
        )
        .expect("ack insert");

    storage
        .insert_partial_sig(
            &request_id,
            PartialSigRecord {
                signer_peer_id: PeerId::from("peer-2"),
                input_index: 0,
                pubkey: vec![1, 2, 3],
                signature: vec![4, 5, 6],
                timestamp_nanos: 11,
            },
        )
        .expect("partial insert");

    storage.update_request_final_tx(&request_id, TransactionId::from([8u8; 32])).expect("final tx update");
    storage.update_request_final_tx_score(&request_id, 42).expect("final score update");

    let stored_event = storage.get_event(&ev_hash).expect("event read").expect("event");
    assert_eq!(stored_event.event_id, "event-audit");

    let request = storage.get_request(&request_id).expect("request read").expect("request");
    assert!(matches!(request.decision, RequestDecision::Finalized));
    assert_eq!(request.final_tx_id, Some(TransactionId::from([8u8; 32])));
    assert_eq!(request.final_tx_accepted_blue_score, Some(42));

    let proposal = storage.get_proposal(&request_id).expect("proposal read").expect("proposal");
    assert_eq!(proposal.kpsbt_blob, vec![1, 2, 3]);

    let inputs = storage.list_request_inputs(&request_id).expect("inputs list");
    assert_eq!(inputs.len(), 1);

    let acks = storage.list_signer_acks(&request_id).expect("acks list");
    assert_eq!(acks.len(), 1);

    let partials = storage.list_partial_sigs(&request_id).expect("partials list");
    assert_eq!(partials.len(), 1);
}
