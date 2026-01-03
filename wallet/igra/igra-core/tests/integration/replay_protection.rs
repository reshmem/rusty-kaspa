use async_trait::async_trait;
use igra_core::config::{AppConfig, ServiceConfig};
use igra_core::event::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, Hash32, SigningEvent};
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::validation::NoopVerifier;
use igra_core::storage::rocks::RocksStorage;
use std::collections::BTreeMap;
use std::sync::Arc;
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
    ) -> Result<Hash32, igra_core::error::ThresholdError> {
        Ok([0u8; 32])
    }
}

#[tokio::test]
async fn duplicate_event_is_rejected() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let config = AppConfig::default();
    let event_ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: config.service.clone(),
        message_verifier: Arc::new(NoopVerifier::default()),
        storage: storage.clone(),
    };

    let params = SigningEventParams {
        session_id_hex: hex::encode([1u8; 32]),
        request_id: "req-1".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: SigningEventWire {
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
        },
    };

    submit_signing_event(&event_ctx, params.clone()).await.expect("first submit");
    let result = submit_signing_event(&event_ctx, params).await;
    assert!(result.is_err());
}
