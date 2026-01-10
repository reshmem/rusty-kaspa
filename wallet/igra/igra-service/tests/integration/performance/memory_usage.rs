use async_trait::async_trait;
use igra_core::application::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
use igra_core::domain::validation::NoopVerifier;
use igra_core::domain::{EventSource, SigningEvent};
use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
use igra_core::infrastructure::config::ServiceConfig;
use igra_core::infrastructure::storage::RocksStorage;
use igra_core::ThresholdError;
use std::collections::BTreeMap;
use std::sync::Arc;
use sysinfo::System;
use tempfile::TempDir;

struct DummyProcessor;

#[async_trait]
impl EventProcessor for DummyProcessor {
    async fn handle_signing_event(
        &self,
        _config: &ServiceConfig,
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
async fn test_memory_usage_growth() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));

    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: igra_core::infrastructure::config::ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier),
        storage,
    };

    let base_event = SigningEvent {
        event_id: "event-memory".to_string(),
        event_source: EventSource::Api { issuer: "tests".to_string() },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string(),
        amount_sompi: 1_000_000,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    };

    let mut sys = System::new_all();
    sys.refresh_all();
    let pid = sysinfo::get_current_pid().expect("pid");
    let initial_rss = sys.process(pid).map(|proc| proc.memory()).unwrap_or_default();

    let total_events = 200u32;
    for idx in 0..total_events {
        let mut event = base_event.clone();
        event.event_id = format!("event-memory-{idx}");
        let params = build_params(&format!("req-memory-{idx}"), (idx % 255) as u8, &event);
        submit_signing_event(&ctx, params).await.expect("submit event");

        if idx % 50 == 0 {
            sys.refresh_all();
            if let Some(proc) = sys.process(pid) {
                let rss = proc.memory();
                println!("After {} events: {} MB", idx, rss / (1024 * 1024));
            }
        }
    }

    sys.refresh_all();
    let final_rss = sys.process(pid).map(|proc| proc.memory()).unwrap_or_default();
    let growth_bytes = final_rss.saturating_sub(initial_rss);
    println!("RSS growth: {} MB", growth_bytes / (1024 * 1024));
    let growth_mb = growth_bytes / (1024 * 1024);
    assert!(growth_mb < 400, "memory growth too high: {} MB", growth_mb);
}
