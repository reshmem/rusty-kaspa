use async_trait::async_trait;
use igra_core::error::ThresholdError;
use igra_core::event::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, Hash32, SigningEvent};
use igra_core::storage::rocks::RocksStorage;
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::validation::NoopVerifier;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

struct DummyProcessor;

#[async_trait]
impl EventProcessor for DummyProcessor {
    async fn handle_signing_event(
        &self,
        _config: &igra_core::config::ServiceConfig,
        _session_id: SessionId,
        _request_id: RequestId,
        _signing_event: SigningEvent,
        _expires_at_nanos: u64,
        _coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError> {
        Ok([0u8; 32])
    }
}

fn build_params(request_id: &str, session_seed: u8, event: &SigningEvent) -> SigningEventParams {
    SigningEventParams {
        session_id_hex: hex::encode([session_seed; 32]),
        request_id: request_id.to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: SigningEventWire {
            event_id: event.event_id.clone(),
            event_source: event.event_source.clone(),
            derivation_path: event.derivation_path.clone(),
            derivation_index: event.derivation_index,
            destination_address: event.destination_address.clone(),
            amount_sompi: event.amount_sompi,
            metadata: event.metadata.clone(),
            timestamp_nanos: event.timestamp_nanos,
            signature_hex: None,
            signature: None,
        },
    }
}

#[tokio::test]
async fn signature_throughput_smoke() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: igra_core::config::ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier),
        storage,
    };

    let base_event = SigningEvent {
        event_id: "event-throughput".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: 1_000_000,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    };

    let start = Instant::now();
    for idx in 0..200u32 {
        let mut event = base_event.clone();
        event.event_id = format!("event-throughput-{idx}");
        let params = build_params(&format!("req-throughput-{idx}"), (idx % 255) as u8, &event);
        submit_signing_event(&ctx, params).await.expect("submit event");
    }
    let elapsed = start.elapsed();
    let throughput = 200.0 / elapsed.as_secs_f64();
    assert!(throughput > 100.0, "throughput too low: {throughput:.2} events/sec");
}
