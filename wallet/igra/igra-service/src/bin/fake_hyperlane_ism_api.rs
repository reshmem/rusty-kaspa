use blake3::Hash;
use hyperlane_core::accumulator::merkle::Proof as HyperlaneProof;
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signable, H256};
use reqwest::Client;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Secp256k1, SecretKey};
use serde::Deserialize;
use std::env;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[derive(Deserialize)]
struct HyperlaneKeysFile {
    validators: Vec<HyperlaneValidator>,
}

#[derive(Deserialize, Clone)]
struct HyperlaneValidator {
    name: String,
    private_key_hex: String,
    public_key_hex: String,
}

const DEFAULT_ORIGIN_DOMAIN: u32 = 5;
const DEFAULT_DESTINATION_DOMAIN: u32 = 7;
const DEFAULT_RECIPIENT_PAYLOAD: &str = "000000000000000000000000000000000000000000000000000000000000dead"; // burn-like payload

#[allow(dead_code)]
fn now_nanos() -> u64 {
    igra_core::foundation::util::time::current_timestamp_nanos_env(Some("KASPA_IGRA_TEST_NOW_NANOS")).unwrap_or(0)
}

#[allow(dead_code)]
fn hash_to_hex(hash: Hash) -> String {
    hex::encode(hash.as_bytes())
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    env::var(name).ok().and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(default)
}

fn parse_h256(hex_str: &str) -> Result<H256, String> {
    let stripped = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(stripped).map_err(|e| format!("invalid hex {hex_str}: {e}"))?;
    if bytes.len() != 32 {
        return Err("expected 32-byte hex for H256".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(H256::from(arr))
}

fn build_hyperlane_message(
    version: u8,
    nonce: u32,
    origin: u32,
    sender: H256,
    destination: u32,
    recipient_payload: [u8; 32],
    amount_sompi: u64,
) -> HyperlaneMessage {
    HyperlaneMessage {
        version,
        nonce,
        origin,
        sender,
        destination,
        recipient: H256::from(recipient_payload),
        body: amount_sompi.to_be_bytes().to_vec(),
    }
}

fn signing_hash(checkpoint: &CheckpointWithMessageId) -> H256 {
    checkpoint.signing_hash()
}

fn make_signatures(
    checkpoint: &CheckpointWithMessageId,
    validators: &[HyperlaneValidator],
    threshold: usize,
) -> Result<Vec<String>, String> {
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_digest_slice(signing_hash(checkpoint).as_ref()).map_err(|e| format!("signing hash: {e}"))?;
    let mut sigs = Vec::new();
    for validator in validators.iter().take(threshold) {
        let key_bytes = hex::decode(validator.private_key_hex.trim())
            .map_err(|err| format!("invalid private key hex for {}: {}", validator.name, err))?;
        let secret =
            SecretKey::from_slice(&key_bytes).map_err(|err| format!("invalid private key for {}: {}", validator.name, err))?;
        let rec: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &secret);
        let (rec_id, bytes) = rec.serialize_compact();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&bytes);
        out[64] = u8::try_from(rec_id.to_i32()).unwrap_or(0);
        sigs.push(format!("0x{}", hex::encode(out)));
    }
    Ok(sigs)
}

async fn submit_mailbox_process(
    client: &Client,
    rpc_url: &str,
    message: &HyperlaneMessage,
    checkpoint: &CheckpointWithMessageId,
    proof: Option<HyperlaneProof>,
    signatures: &[String],
) -> Result<(), String> {
    let mode = if proof.is_some() { "merkle_root_multisig" } else { "message_id_multisig" };
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "fake-hyperlane-ism",
        "method": "hyperlane.mailbox_process",
        "params": {
            "message": {
                "version": message.version,
                "nonce": message.nonce,
                "origin": message.origin,
                "sender": format!("0x{}", hex::encode(message.sender.as_ref())),
                "destination": message.destination,
                "recipient": format!("0x{}", hex::encode(message.recipient.as_ref())),
                "body": format!("0x{}", hex::encode(&message.body)),
            },
            "metadata": {
                "checkpoint": {
                    "merkle_tree_hook_address": format!("0x{}", hex::encode(checkpoint.checkpoint.merkle_tree_hook_address.as_ref())),
                    "mailbox_domain": checkpoint.checkpoint.mailbox_domain,
                    "root": format!("0x{}", hex::encode(checkpoint.checkpoint.root.as_ref())),
                    "index": checkpoint.checkpoint.index,
                    "message_id": format!("0x{}", hex::encode(checkpoint.message_id.as_ref())),
                },
                "merkle_proof": proof.as_ref().map(|p| {
                    serde_json::json!({
                        "leaf": format!("0x{}", hex::encode(p.leaf.as_ref())),
                        "index": p.index,
                        "path": p.path.iter().map(|h| format!("0x{}", hex::encode(h.as_ref()))).collect::<Vec<_>>()
                    })
                }),
                "signatures": signatures,
            },
            "mode": mode
        }
    });

    let response = client.post(rpc_url).json(&payload).send().await.map_err(|err| err.to_string())?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("rpc error {}: {}", status, body));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let rpc_url = env::var("IGRA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8088/rpc".to_string());
    let keys_path = env::var("HYPERLANE_KEYS_PATH").unwrap_or_else(|_| "/data/igra/hyperlane-keys.json".to_string());
    let interval_secs = parse_env_u64("HYPERLANE_INTERVAL_SECS", 10);
    let start_epoch_secs = parse_env_u64("HYPERLANE_START_EPOCH_SECS", 0);
    let amount_sompi = parse_env_u64("HYPERLANE_AMOUNT_SOMPI", 10_000_000); // 0.1 KAS
    let recipient_payload = env::var("HYPERLANE_RECIPIENT_PAYLOAD").unwrap_or_else(|_| DEFAULT_RECIPIENT_PAYLOAD.to_string());
    let recipient_bytes: [u8; 32] = hex::decode(recipient_payload.trim_start_matches("0x"))
        .map_err(|e| format!("invalid recipient payload: {e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "recipient payload must be 32 bytes")?;
    let domain = env::var("HYPERLANE_DOMAIN").unwrap_or_else(|_| DEFAULT_ORIGIN_DOMAIN.to_string()); // origin domain
    let destination_domain =
        env::var("HYPERLANE_DESTINATION_DOMAIN").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(DEFAULT_DESTINATION_DOMAIN);
    let sender = env::var("HYPERLANE_SENDER").ok().and_then(|v| parse_h256(&v).ok()).unwrap_or(H256::zero());

    let keys_raw = fs::read_to_string(&keys_path).map_err(|err| err.to_string())?;
    let keys: HyperlaneKeysFile = serde_json::from_str(&keys_raw).map_err(|err| err.to_string())?;
    eprintln!(
        "[fake-hyperlane] start rpc_url={} keys={} interval={}s start_epoch={} amount_sompi={} origin_domain={} dest_domain={} sender={}",
        rpc_url,
        keys.validators.len(),
        interval_secs,
        start_epoch_secs,
        amount_sompi,
        domain,
        destination_domain,
        hex::encode(sender)
    );
    if keys.validators.is_empty() {
        eprintln!("[fake-hyperlane] WARNING: no validators loaded from {}", keys_path);
    } else {
        for (idx, v) in keys.validators.iter().enumerate() {
            eprintln!("[fake-hyperlane] validator#{} name={} pubkey={}", idx + 1, v.name, v.public_key_hex);
        }
    }

    let client = Client::new();
    loop {
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let slot = now_secs.saturating_sub(start_epoch_secs) / interval_secs.max(1);
        let nonce: u32 = slot.try_into().unwrap_or(u32::MAX);
        let version = 3u8;
        let origin = domain.parse::<u32>().unwrap_or(5);
        let destination = destination_domain;
        eprintln!(
            "[fake-hyperlane] tick slot={} nonce={} origin={} dest={} amount={} validators={}",
            slot,
            nonce,
            origin,
            destination,
            amount_sompi,
            keys.validators.len()
        );
        let msg = build_hyperlane_message(version, nonce, origin, sender, destination, recipient_bytes, amount_sompi);
        let checkpoint = CheckpointWithMessageId {
            checkpoint: Checkpoint {
                merkle_tree_hook_address: H256::zero(),
                mailbox_domain: origin,
                root: H256::from_low_u64_be(123),
                index: 0,
            },
            message_id: msg.id(),
        };
        let signatures = make_signatures(&checkpoint, &keys.validators, 2)?;

        let mode = "message_id_multisig";
        eprintln!(
            "[fake-hyperlane] submit nonce={} mode={} amt={} sender={} dest={} sigs={}/{}",
            nonce,
            mode,
            amount_sompi,
            hex::encode(sender),
            destination,
            signatures.len(),
            2
        );

        if let Err(err) = submit_mailbox_process(&client, &rpc_url, &msg, &checkpoint, None, &signatures).await {
            eprintln!("[fake-hyperlane] submit failed rpc={} nonce={} mode={} err={}", rpc_url, nonce, mode, err);
        } else {
            eprintln!("[fake-hyperlane] submit ok rpc={} nonce={} mode={}", rpc_url, nonce, mode);
        }

        sleep(Duration::from_secs(interval_secs)).await;
    }
}
