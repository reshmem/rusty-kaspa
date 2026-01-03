use async_trait::async_trait;
use igra_core::config::ServiceConfig;
use igra_core::coordination::hashes::event_hash;
use igra_core::event::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, Hash32, SigningEvent};
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::storage::rocks::RocksStorage;
use igra_core::validation::NoopVerifier;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

struct RecordingProcessor {
    calls: Arc<Mutex<Vec<RequestId>>>,
}

#[async_trait]
impl EventProcessor for RecordingProcessor {
    async fn handle_signing_event(
        &self,
        _config: &ServiceConfig,
        _session_id: SessionId,
        request_id: RequestId,
        _signing_event: SigningEvent,
        _expires_at_nanos: u64,
        _coordinator_peer_id: PeerId,
    ) -> Result<Hash32, igra_core::error::ThresholdError> {
        self.calls.lock().expect("lock").push(request_id);
        Ok([0u8; 32])
    }
}

#[tokio::test]
async fn event_ingestion_stores_event_and_calls_processor() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let ctx = EventContext {
        processor: Arc::new(RecordingProcessor { calls: calls.clone() }),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier::default()),
        storage: storage.clone(),
    };

    let signing_event = SigningEventWire {
        event_id: "event-1".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 123,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature_hex: None,
        signature: None,
    };

    let params = SigningEventParams {
        session_id_hex: hex::encode([1u8; 32]),
        request_id: "req-1".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event,
    };

    let result = submit_signing_event(&ctx, params).await.expect("submit");
    let stored = storage
        .get_event(&hex::decode(&result.event_hash_hex).expect("hash hex").as_slice().try_into().expect("hash"))
        .expect("get event");
    assert!(stored.is_some());

    let call_list = calls.lock().expect("lock");
    assert_eq!(call_list.len(), 1);
    assert_eq!(call_list[0], RequestId::from("req-1"));

    let event = stored.expect("event");
    let computed = event_hash(&event).expect("event hash");
    assert_eq!(hex::encode(computed), result.event_hash_hex);
}
