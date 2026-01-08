use async_trait::async_trait;
use igra_core::config::{load_app_config_from_path, ServiceConfig};
use igra_core::coordination::hashes::event_hash_without_signature;
use igra_core::event::{submit_signing_event, EventContext, EventProcessor, SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, Hash32, SigningEvent};
use igra_core::storage::rocks::RocksStorage;
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::validation::CompositeVerifier;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::collections::BTreeMap;
use std::fs;
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
        event_id: "event-ini-1".to_string(),
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
async fn hyperlane_signature_verifies_from_ini_validators() {
    let temp_dir = TempDir::new().expect("temp dir");
    std::env::set_var("KASPA_DATA_DIR", temp_dir.path());

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[9u8; 32]).expect("secret key");
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let pub_hex = hex::encode(pubkey.serialize());

    let ini_path = temp_dir.path().join("igra-test.ini");
    let ini_contents = format!("[hyperlane]\nvalidators = {}\nthreshold = 1\n", pub_hex);
    fs::write(&ini_path, ini_contents).expect("write ini");

    let app_config = load_app_config_from_path(&ini_path).expect("config");
    let validators =
        igra_core::validation::parse_validator_pubkeys("hyperlane.validators", &app_config.hyperlane.validators).expect("validators");

    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let ctx = EventContext {
        processor: Arc::new(DummyProcessor),
        config: ServiceConfig::default(),
        message_verifier: Arc::new(CompositeVerifier::new(validators, Vec::new())),
        storage,
    };

    let event_source = EventSource::Hyperlane { domain: "devnet".to_string(), sender: "hyperlane-bridge".to_string() };
    let mut signing_event = SigningEvent {
        event_id: "event-ini-1".to_string(),
        event_source: event_source.clone(),
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
    let signature = secp.sign_ecdsa(&message, &secret).serialize_compact().to_vec();
    signing_event.signature = Some(signature.clone());

    let mut wire = base_wire_event(event_source);
    wire.signature_hex = Some(hex::encode(signature));

    let params = SigningEventParams {
        session_id_hex: hex::encode([3u8; 32]),
        request_id: "req-hyperlane-ini".to_string(),
        coordinator_peer_id: "peer-1".to_string(),
        expires_at_nanos: 0,
        signing_event: wire,
    };

    let result = submit_signing_event(&ctx, params).await.expect("submit");
    assert_eq!(result.session_id_hex, hex::encode([3u8; 32]));

    std::env::remove_var("KASPA_DATA_DIR");
}
