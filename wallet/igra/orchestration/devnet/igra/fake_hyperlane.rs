use blake3::Hash;
use igra_core::coordination::hashes::event_hash_without_signature;
use igra_core::event::{SigningEventParams, SigningEventWire};
use igra_core::model::{EventSource, SigningEvent};
use reqwest::Client;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[derive(Deserialize)]
struct HyperlaneKeysFile {
    validators: Vec<HyperlaneValidator>,
}

#[derive(Deserialize)]
struct HyperlaneValidator {
    name: String,
    private_key_hex: String,
    public_key_hex: String,
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos() as u64
}

fn hash_to_hex(hash: Hash) -> String {
    hex::encode(hash.as_bytes())
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn build_event(
    event_id: String,
    event_source: EventSource,
    destination_address: String,
    amount_sompi: u64,
    derivation_path: String,
    timestamp_nanos: u64,
) -> SigningEvent {
    SigningEvent {
        event_id,
        event_source,
        derivation_path,
        derivation_index: Some(0),
        destination_address,
        amount_sompi,
        metadata: BTreeMap::new(),
        timestamp_nanos,
        signature: None,
    }
}

fn sign_event(event: &SigningEvent, validators: &[HyperlaneValidator]) -> Result<Vec<u8>, String> {
    if validators.len() < 2 {
        return Err("need at least 2 hyperlane validators".to_string());
    }
    let hash = event_hash_without_signature(event).map_err(|err| err.to_string())?;
    let message = Message::from_digest_slice(&hash).map_err(|err| err.to_string())?;
    let secp = Secp256k1::new();

    let mut signatures = Vec::new();
    for validator in validators.iter().take(2) {
        let key_bytes = hex::decode(validator.private_key_hex.trim())
            .map_err(|err| format!("invalid private key hex for {}: {}", validator.name, err))?;
        let secret = SecretKey::from_slice(&key_bytes)
            .map_err(|err| format!("invalid private key for {}: {}", validator.name, err))?;
        let sig = secp.sign_ecdsa(&message, &secret).serialize_compact();
        signatures.extend_from_slice(&sig);
    }
    Ok(signatures)
}

async fn submit_event(client: &Client, rpc_url: &str, params: &SigningEventParams) -> Result<(), String> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "fake-hyperlane",
        "method": "signing_event.submit",
        "params": params,
    });

    let response = client
        .post(rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("rpc error {}: {}", response.status(), body));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let rpc_url = env::var("IGRA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8088/rpc".to_string());
    let keys_path = env::var("HYPERLANE_KEYS_PATH").unwrap_or_else(|_| "/data/igra/hyperlane-keys.json".to_string());
    let interval_secs = parse_env_u64("HYPERLANE_INTERVAL_SECS", 10);
    let start_epoch_secs = parse_env_u64("HYPERLANE_START_EPOCH_SECS", 0);
    let amount_sompi = parse_env_u64("HYPERLANE_AMOUNT_SOMPI", 5_000_000_000);
    let destination = env::var("HYPERLANE_DESTINATION")
        .unwrap_or_else(|_| "kaspadev:qr9ptqk4gcphla6whs5qep9yp4c33sy4ndugtw2whf56279jw00wcqlxl3lq3".to_string());
    let derivation_path = env::var("HYPERLANE_DERIVATION_PATH")
        .unwrap_or_else(|_| "m/45'/111111'/0'/0/0".to_string());
    let domain = env::var("HYPERLANE_DOMAIN").unwrap_or_else(|_| "devnet".to_string());
    let sender = env::var("HYPERLANE_SENDER").unwrap_or_else(|_| "hyperlane-bridge".to_string());
    let coordinator_peer_id =
        env::var("HYPERLANE_COORDINATOR_PEER_ID").unwrap_or_else(|_| "coordinator-1".to_string());

    let keys_raw = fs::read_to_string(&keys_path).map_err(|err| err.to_string())?;
    let keys: HyperlaneKeysFile = serde_json::from_str(&keys_raw).map_err(|err| err.to_string())?;

    let client = Client::new();
    loop {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        let slot = now_secs.saturating_sub(start_epoch_secs) / interval_secs.max(1);
        let event_id = format!("hyperlane-devnet-slot-{slot}");
        let timestamp_nanos = (start_epoch_secs + slot * interval_secs.max(1)) * 1_000_000_000;
        let event_source = EventSource::Hyperlane {
            domain: domain.clone(),
            sender: sender.clone(),
        };
        let signing_event = build_event(
            event_id.clone(),
            event_source.clone(),
            destination.clone(),
            amount_sompi,
            derivation_path.clone(),
            timestamp_nanos,
        );

        let signature_bytes = sign_event(&signing_event, &keys.validators)?;
        let signature_hex = hex::encode(&signature_bytes);

        let session_id_hex = hash_to_hex(blake3::hash(event_id.as_bytes()));
        let expires_at_nanos = now_nanos() + Duration::from_secs(60).as_nanos() as u64;

        let wire = SigningEventWire {
            event_id,
            event_source,
            derivation_path: derivation_path.clone(),
            derivation_index: Some(0),
            destination_address: destination.clone(),
            amount_sompi,
            metadata: BTreeMap::new(),
            timestamp_nanos,
            signature_hex: Some(signature_hex),
            signature: None,
        };

        let params = SigningEventParams {
            session_id_hex,
            request_id: format!("req-hyperlane-slot-{slot}"),
            coordinator_peer_id: coordinator_peer_id.clone(),
            expires_at_nanos,
            signing_event: wire,
        };

        if let Err(err) = submit_event(&client, &rpc_url, &params).await {
            eprintln!("fake-hyperlane submit failed: {err}");
        }

        sleep(Duration::from_secs(interval_secs)).await;
    }
}
