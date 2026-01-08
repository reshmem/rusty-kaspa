use async_trait::async_trait;
use igra_core::error::ThresholdError;
use igra_core::event::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, Hash32, SigningEvent};
use igra_core::storage::rocks::RocksStorage;
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::validation::NoopVerifier;
use std::collections::BTreeMap;
use std::sync::Arc;
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
async fn concurrent_session_capacity_smoke() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let ctx = Arc::new(EventContext {
        processor: Arc::new(DummyProcessor),
        config: igra_core::config::ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier),
        storage,
    });

    let base_event = SigningEvent {
        event_id: "event-concurrent".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: 1_000_000,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    };

    let mut tasks = Vec::new();
    for idx in 0..50u32 {
        let ctx = ctx.clone();
        let mut event = base_event.clone();
        event.event_id = format!("event-concurrent-{idx}");
        let params = build_params(&format!("req-concurrent-{idx}"), (idx % 255) as u8, &event);
        tasks.push(tokio::spawn(async move { submit_signing_event(&ctx, params).await }));
    }

    let mut success = 0usize;
    for task in tasks {
        if let Ok(Ok(_)) = task.await {
            success += 1;
        }
    }
    assert_eq!(success, 50, "only {success} of 50 sessions succeeded");
}
