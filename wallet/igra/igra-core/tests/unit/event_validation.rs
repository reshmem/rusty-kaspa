use async_trait::async_trait;
use igra_core::config::ServiceConfig;
use igra_core::coordination::hashes::event_hash_without_signature;
use igra_core::event::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, Hash32, SigningEvent};
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::storage::rocks::RocksStorage;
use igra_core::validation::{CompositeVerifier, NoopVerifier};
use secp256k1::{Message, Secp256k1, SecretKey};
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

fn base_wire_event(event_source: EventSource) -> SigningEventWire {
    SigningEventWire {
        event_id: "event-1".to_string(),
        event_source,
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 123,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature_hex: None,
        signature: None,
    }
}

#[tokio::test]
async fn hyperlane_requires_validators() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(CompositeVerifier::new(Vec::new(), Vec::new())),
        storage,
    };

    let params = SigningEventParams {
        session_id_hex: hex::encode([1u8; 32]),
        request_id: "req-1".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: base_wire_event(EventSource::Hyperlane {
            domain: "test".to_string(),
            sender: "sender".to_string(),
        }),
    };

    let err = submit_signing_event(&ctx, params).await.expect_err("should fail");
    assert!(err.to_string().contains("hyperlane validators"));
}

#[tokio::test]
async fn layerzero_requires_validators() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(CompositeVerifier::new(Vec::new(), Vec::new())),
        storage,
    };

    let params = SigningEventParams {
        session_id_hex: hex::encode([2u8; 32]),
        request_id: "req-2".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: base_wire_event(EventSource::LayerZero {
            endpoint: "endpoint".to_string(),
            sender: "sender".to_string(),
        }),
    };

    let err = submit_signing_event(&ctx, params).await.expect_err("should fail");
    assert!(err.to_string().contains("layerzero endpoint"));
}

#[tokio::test]
async fn layerzero_signature_verifies() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[7u8; 32]).expect("secret key");
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

    let mut signing_event = SigningEvent {
        event_id: "event-3".to_string(),
        event_source: EventSource::LayerZero {
            endpoint: "endpoint".to_string(),
            sender: "sender".to_string(),
        },
        derivation_path: "m/45'/111111'/0'/0/0".to_string(),
        derivation_index: Some(0),
        destination_address: "kaspatest:qz0000000000000000000000000000000000000000000000000000000000p5x4p".to_string(),
        amount_sompi: 123,
        metadata: BTreeMap::new(),
        timestamp_nanos: 1,
        signature: None,
    };

    let digest = event_hash_without_signature(&signing_event).expect("hash");
    let message = Message::from_digest_slice(&digest).expect("message");
    let sig = secp.sign_ecdsa(&message, &secret).serialize_compact().to_vec();
    signing_event.signature = Some(sig.clone());

    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(CompositeVerifier::new(Vec::new(), vec![pubkey])),
        storage,
    };

    let params = SigningEventParams {
        session_id_hex: hex::encode([3u8; 32]),
        request_id: "req-3".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: SigningEventWire {
            event_id: signing_event.event_id.clone(),
            event_source: signing_event.event_source.clone(),
            derivation_path: signing_event.derivation_path.clone(),
            derivation_index: signing_event.derivation_index,
            destination_address: signing_event.destination_address.clone(),
            amount_sompi: signing_event.amount_sompi,
            metadata: signing_event.metadata.clone(),
            timestamp_nanos: signing_event.timestamp_nanos,
            signature_hex: None,
            signature: Some(sig),
        },
    };

    let result = submit_signing_event(&ctx, params).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn derivation_index_mismatch_rejected() {
    let temp_dir = TempDir::new().expect("temp dir");
    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(NoopVerifier::default()),
        storage,
    };

    let mut wire = base_wire_event(EventSource::Api { issuer: "tests".to_string() });
    wire.derivation_path = "m/45'/111111'/0'/0/1".to_string();
    wire.derivation_index = Some(0);

    let params = SigningEventParams {
        session_id_hex: hex::encode([4u8; 32]),
        request_id: "req-4".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: wire,
    };

    let err = submit_signing_event(&ctx, params).await.expect_err("should fail");
    assert!(err.to_string().contains("derivation_path"));
}
