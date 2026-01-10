#![cfg(feature = "hyperlane")]

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signable, H256};
use igra_core::config::{HyperlaneConfig, HyperlaneDomainConfig, HyperlaneIsmMode, ServiceConfig};
use igra_core::error::ThresholdError;
use igra_core::event::{EventContext, EventProcessor};
use igra_core::hyperlane::ism::ConfiguredIsm;
use igra_core::model::{Hash32, SigningEvent};
use igra_core::storage::rocks::RocksStorage;
use igra_core::types::{PeerId, RequestId, SessionId};
use igra_core::validation::NoopVerifier;
use igra_service::api::json_rpc::{build_router, RpcState};
use igra_service::service::metrics::Metrics;
use kaspa_addresses::Address;
use secp256k1::{ecdsa::RecoverableSignature, Message as SecpMessage, PublicKey, Secp256k1, SecretKey};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

struct DummyProcessor;

#[async_trait::async_trait]
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

fn pub_hex(pk: &PublicKey) -> String {
    format!("0x{}", hex::encode(pk.serialize()))
}

fn make_state(keys: &[SecretKey], temp_dir: &TempDir) -> Arc<RpcState> {
    let secp = Secp256k1::new();
    let validators: Vec<PublicKey> = keys.iter().map(|k| PublicKey::from_secret_key(&secp, k)).collect();
    let domain_cfg = HyperlaneDomainConfig {
        domain: 7,
        validators: validators.iter().map(pub_hex).collect(),
        threshold: 2,
        mode: HyperlaneIsmMode::MessageIdMultisig,
    };
    let hyperlane_config = HyperlaneConfig { domains: vec![domain_cfg], ..Default::default() };
    let ism = ConfiguredIsm::from_config(&hyperlane_config).expect("ism");

    let storage = Arc::new(RocksStorage::open_in_dir(temp_dir.path()).expect("storage"));
    let mut service_cfg = ServiceConfig::default();
    service_cfg.pskt.source_addresses = vec!["kaspadev:qzjwhmuwx4fmmxleyykgcekr2m2tamseskqvl859mss2jvz7tk46j2qyvpukx".to_string()];
    let event_ctx =
        EventContext { processor: Arc::new(DummyProcessor), config: service_cfg, message_verifier: Arc::new(NoopVerifier), storage };
    let metrics = Arc::new(Metrics::new().expect("metrics"));

    Arc::new(RpcState {
        event_ctx,
        rpc_token: None,
        node_rpc_url: "".to_string(),
        metrics,
        rate_limiter: Arc::new(igra_service::api::RateLimiter::new()),
        hyperlane_ism: Some(ism),
        group_id_hex: Some("746573742d67726f7570".to_string()), // "test-group" hex for deterministic session id
        coordinator_peer_id: "test-peer".to_string(),
        hyperlane_default_derivation_path: "m/45h/111111h/0h/0/0".to_string(),
        rate_limit_rps: 30,
        rate_limit_burst: 60,
        session_expiry_seconds: 600,
    })
}

fn make_sig_hex(hash: H256, sk: &SecretKey) -> String {
    let secp = Secp256k1::new();
    let msg = SecpMessage::from_digest_slice(hash.as_ref()).expect("message");
    let rec: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, sk);
    let (rec_id, bytes) = rec.serialize_compact();
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&bytes);
    out[64] = rec_id.to_i32() as u8;
    format!("0x{}", hex::encode(out))
}

fn h256_hex(value: H256) -> String {
    format!("0x{}", hex::encode(value.as_ref()))
}

fn derive_session_id(group_hex: &str, message_id: H256) -> String {
    let group_bytes = hex::decode(group_hex).expect("hex");
    let mut hasher = blake3::Hasher::new();
    hasher.update(&group_bytes);
    hasher.update(message_id.as_ref());
    let out = hasher.finalize();
    format!("0x{}", out.to_hex())
}

#[tokio::test]
async fn hyperlane_validators_and_threshold_rpc() {
    let keys = vec![SecretKey::from_slice(&[1u8; 32]).expect("sk1"), SecretKey::from_slice(&[2u8; 32]).expect("sk2")];
    let temp_dir = TempDir::new().expect("tempdir");
    let state = make_state(&keys, &temp_dir);
    let app = build_router(state);
    let message_id = H256::from_low_u64_be(5);

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "hyperlane.validators_and_threshold",
        "params": {
            "message_id": h256_hex(message_id),
            "destination_domain": 7,
            "origin_domain": 5
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rpc")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(value["result"]["threshold"], 2);
    assert_eq!(value["result"]["domain"], 7);
    assert_eq!(value["result"]["validators"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn hyperlane_mailbox_process_proves_message() {
    let keys = vec![
        SecretKey::from_slice(&[7u8; 32]).expect("sk1"),
        SecretKey::from_slice(&[8u8; 32]).expect("sk2"),
        SecretKey::from_slice(&[9u8; 32]).expect("sk3"),
    ];
    let temp_dir = TempDir::new().expect("tempdir");
    let state = make_state(&keys[..2], &temp_dir);
    let app = build_router(state);
    let kaspa_addr = Address::try_from("kaspadev:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpcg49u").unwrap();
    let mut recipient_bytes = [0u8; 32];
    recipient_bytes.copy_from_slice(&kaspa_addr.payload);
    let amount_bytes = 42u64.to_be_bytes();
    let message = HyperlaneMessage {
        version: 3,
        nonce: 9,
        origin: 5,
        sender: H256::from_low_u64_be(11),
        destination: 7,
        recipient: H256::from(recipient_bytes),
        body: amount_bytes.to_vec(),
    };
    let checkpoint = CheckpointWithMessageId {
        checkpoint: Checkpoint {
            merkle_tree_hook_address: H256::zero(),
            mailbox_domain: message.origin,
            root: H256::from_low_u64_be(123),
            index: 0,
        },
        message_id: message.id(),
    };
    let signing_hash = checkpoint.signing_hash();

    let signatures = vec![make_sig_hex(signing_hash, &keys[0]), make_sig_hex(signing_hash, &keys[1])];

    let payload = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "hyperlane.mailbox_process",
        "params": {
            "message": {
                "version": message.version,
                "nonce": message.nonce,
                "origin": message.origin,
                "sender": h256_hex(message.sender),
                "destination": message.destination,
                "recipient": h256_hex(message.recipient),
                "body": message.body,
            },
            "metadata": {
                "checkpoint": {
                    "merkle_tree_hook_address": h256_hex(checkpoint.checkpoint.merkle_tree_hook_address),
                    "mailbox_domain": checkpoint.mailbox_domain,
                    "root": h256_hex(checkpoint.root),
                    "index": checkpoint.index,
                    "message_id": h256_hex(checkpoint.message_id),
                },
                "signatures": signatures,
            },
            "mode": "message_id_multisig"
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rpc")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(value["result"]["status"], "proven");
    assert_eq!(value["result"]["quorum"], 2);
    assert_eq!(value["result"]["mode"], "message_id_multisig");
    let expected_session = derive_session_id("746573742d67726f7570", checkpoint.message_id);
    assert_eq!(value["result"]["session_id"], expected_session);
    assert_eq!(value["result"]["event_id"], h256_hex(checkpoint.message_id));
    assert_eq!(value["result"]["signing_submitted"], true);
}
