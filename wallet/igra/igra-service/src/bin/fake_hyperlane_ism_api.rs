use blake3::Hash;
use hyperlane_core::accumulator::merkle::Proof as HyperlaneProof;
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signable, H256};
use kaspa_addresses::Address;
use reqwest::Client;
use reqwest::StatusCode;
use rand::seq::SliceRandom;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Secp256k1, SecretKey};
use serde::Deserialize;
use std::env;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[derive(Deserialize)]
struct JsonRpcErrorBody {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct JsonRpcEnvelope {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcErrorBody>,
}

#[derive(Debug, Clone)]
enum RpcFailure {
    Transport(String),
    Http { status: StatusCode, body: String },
    InvalidJson { error: String, body: String },
    JsonRpc { code: i64, message: String },
}

impl RpcFailure {
    fn summary(&self) -> String {
        match self {
            RpcFailure::Transport(message) => format!("transport_error={message}"),
            RpcFailure::Http { status, body } => format!("http_status={status} body={body}"),
            RpcFailure::InvalidJson { error, body } => format!("invalid_json_error={error} body={body}"),
            RpcFailure::JsonRpc { code, message } => format!("json_rpc_error code={code} message={message}"),
        }
    }

    fn is_event_already_processed(&self) -> bool {
        match self {
            RpcFailure::JsonRpc { code, message } => {
                *code == -32006
                    || message.contains("event already processed")
                    || message.contains("event replayed")
                    || message.contains("EventReplayed")
            }
            RpcFailure::Http { body, .. } | RpcFailure::InvalidJson { body, .. } => {
                body.contains("event already processed") || body.contains("event replayed") || body.contains("EventReplayed")
            }
            RpcFailure::Transport(msg) => {
                msg.contains("event already processed") || msg.contains("event replayed") || msg.contains("EventReplayed")
            }
        }
    }
}

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
const DEFAULT_DESTINATION_ADDRESS: &str = "kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw";

const UNORDERED_EVENTS_MIN: u16 = 1;
const UNORDERED_EVENTS_MAX: u16 = 1024;

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

fn parse_cli_unordered_events() -> Result<Option<u16>, String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            eprintln!(
                "Usage: fake_hyperlane_ism_api [--unordered-events N]\n\n  --unordered-events N   Shuffle nonces within each batch of N events ({}..={})",
                UNORDERED_EVENTS_MIN,
                UNORDERED_EVENTS_MAX
            );
            return Ok(None);
        }

        if let Some(value) = arg.strip_prefix("--unordered-events=") {
            let parsed = value.trim().parse::<u16>().map_err(|_| "invalid --unordered-events value".to_string())?;
            validate_unordered_events(parsed)?;
            return Ok(Some(parsed));
        }

        if arg == "--unordered-events" {
            let Some(value) = args.next() else {
                return Err("--unordered-events requires a value".to_string());
            };
            let parsed = value.trim().parse::<u16>().map_err(|_| "invalid --unordered-events value".to_string())?;
            validate_unordered_events(parsed)?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
}

fn validate_unordered_events(value: u16) -> Result<(), String> {
    if !(UNORDERED_EVENTS_MIN..=UNORDERED_EVENTS_MAX).contains(&value) {
        return Err(format!(
            "--unordered-events must be between {} and {}",
            UNORDERED_EVENTS_MIN, UNORDERED_EVENTS_MAX
        ));
    }
    Ok(())
}

fn build_hyperlane_message(
    version: u8,
    nonce: u32,
    origin: u32,
    sender: H256,
    destination: u32,
    recipient_payload: [u8; 32],
    amount_sompi: u64,
    destination_address: &str,
) -> HyperlaneMessage {
    let mut body = Vec::with_capacity(8 + destination_address.len());
    body.extend_from_slice(&amount_sompi.to_le_bytes());
    body.extend_from_slice(destination_address.as_bytes());
    HyperlaneMessage { version, nonce, origin, sender, destination, recipient: H256::from(recipient_payload), body }
}

fn signing_hash(checkpoint: &CheckpointWithMessageId) -> H256 {
    checkpoint.signing_hash()
}

fn make_signatures(
    checkpoint: &CheckpointWithMessageId,
    validators: &[HyperlaneValidator],
    threshold: usize,
) -> Result<Vec<String>, String> {
    if validators.len() < threshold {
        return Err(format!("not enough validators to satisfy threshold (have {}, need {})", validators.len(), threshold));
    }
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
) -> Result<serde_json::Value, RpcFailure> {
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

    let response = client.post(rpc_url).json(&payload).send().await.map_err(|err| RpcFailure::Transport(err.to_string()))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(RpcFailure::Http { status, body });
    }

    let envelope: JsonRpcEnvelope =
        serde_json::from_str(&body).map_err(|err| RpcFailure::InvalidJson { error: err.to_string(), body })?;
    if let Some(err) = envelope.error {
        return Err(RpcFailure::JsonRpc { code: err.code, message: err.message });
    }
    Ok(envelope.result.unwrap_or(serde_json::Value::Null))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let unordered_events = parse_cli_unordered_events()?;

    let rpc_url = env::var("IGRA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8088/rpc".to_string());
    let keys_path = env::var("HYPERLANE_KEYS_PATH").unwrap_or_else(|_| "/data/igra/hyperlane-keys.json".to_string());
    let interval_secs = parse_env_u64("HYPERLANE_INTERVAL_SECS", 10);
    let retry_delay_secs = parse_env_u64("HYPERLANE_RETRY_DELAY_SECS", 1);
    let start_epoch_secs = parse_env_u64("HYPERLANE_START_EPOCH_SECS", 0);
    // 10_000_000 sompi (0.1 KAS) can hit the mempool's standardness mass limit (KIP-0009 storage mass),
    // causing transactions to be rejected as non-standard. Use a safer default for devnet.
    let amount_sompi = parse_env_u64("HYPERLANE_AMOUNT_SOMPI", 20_000_000); // 0.2 KAS
    let destination_address =
        env::var("HYPERLANE_DESTINATION").unwrap_or_else(|_| DEFAULT_DESTINATION_ADDRESS.to_string()).trim().to_string();
    if destination_address.is_empty() {
        return Err("HYPERLANE_DESTINATION must be set".to_string());
    }
    let _ = Address::try_from(destination_address.as_str()).map_err(|_| "invalid HYPERLANE_DESTINATION address".to_string())?;
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
        "[fake-hyperlane] start rpc_url={} keys={} interval={}s start_epoch={} amount_sompi={} destination_address={} origin_domain={} dest_domain={} sender={} unordered_events={:?}",
        rpc_url,
        keys.validators.len(),
        interval_secs,
        start_epoch_secs,
        amount_sompi,
        destination_address,
        domain,
        destination_domain,
        hex::encode(sender)
        ,
        unordered_events
    );
    if keys.validators.is_empty() {
        eprintln!("[fake-hyperlane] WARNING: no validators loaded from {}", keys_path);
    } else {
        for (idx, v) in keys.validators.iter().enumerate() {
            eprintln!("[fake-hyperlane] validator#{} name={} pubkey={}", idx + 1, v.name, v.public_key_hex);
        }
    }

    let client = Client::new();

    // IMPORTANT: Do not advance to the next event until the previous one is accepted by RPC.
    // Use a sequential nonce (seeded from the current slot for convenience), and only increment
    // after a successful JSON-RPC response.
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let initial_slot = now_secs.saturating_sub(start_epoch_secs) / interval_secs.max(1);

    // For unordered batching tests we want deterministic, predictable ranges (0..N-1, N..2N-1, ...).
    // Allow overriding via env for other workflows.
    let start_nonce_override = env::var("HYPERLANE_START_NONCE").ok().and_then(|v| v.parse::<u32>().ok());
    let start_nonce = if let Some(override_nonce) = start_nonce_override {
        override_nonce
    } else if unordered_events.is_some() {
        0
    } else {
        u32::try_from(initial_slot).unwrap_or(0)
    };
    let mut next_batch_start_nonce: u32 = start_nonce;

    let batch_size = unordered_events.unwrap_or(1) as u32;
    let mut batch = Vec::<u32>::new();
    let mut pending_nonce: Option<u32> = None;
    let mut rng = rand::thread_rng();

    let mut refill_batch = |batch: &mut Vec<u32>, next_start: &mut u32| {
        batch.clear();
        let start = *next_start;
        let end_exclusive = start.saturating_add(batch_size);
        for n in start..end_exclusive {
            batch.push(n);
        }
        if batch_size > 1 {
            eprintln!(
                "[fake-hyperlane] unordered batch prepared start_nonce={} end_nonce_inclusive={} size={}",
                start,
                end_exclusive.saturating_sub(1),
                batch_size
            );
        }
        if batch_size > 1 {
            batch.shuffle(&mut rng);
        }
        *next_start = start.saturating_add(batch_size);
    };

    loop {
        let version = 3u8;
        let origin = domain.parse::<u32>().unwrap_or(5);
        let destination = destination_domain;

        let nonce = match pending_nonce {
            Some(nonce) => nonce,
            None => {
                if batch.is_empty() {
                    refill_batch(&mut batch, &mut next_batch_start_nonce);
                }
                let Some(nonce) = batch.pop() else {
                    continue;
                };
                pending_nonce = Some(nonce);
                nonce
            }
        };

        eprintln!(
            "[fake-hyperlane] tick nonce={} origin={} dest_domain={} amount={} destination_address={} validators={}",
            nonce,
            origin,
            destination,
            amount_sompi,
            destination_address,
            keys.validators.len()
        );
        let msg =
            build_hyperlane_message(version, nonce, origin, sender, destination, recipient_bytes, amount_sompi, &destination_address);
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

        match submit_mailbox_process(&client, &rpc_url, &msg, &checkpoint, None, &signatures).await {
            Ok(result) => {
                let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("ok");
                let signing_submitted = result.get("signing_submitted").and_then(|v| v.as_bool());
                eprintln!(
                    "[fake-hyperlane] submit ok rpc={} nonce={} mode={} status={} signing_submitted={:?}",
                    rpc_url, nonce, mode, status, signing_submitted
                );
                pending_nonce = None;
                sleep(Duration::from_secs(interval_secs)).await;
            }
            Err(err) => {
                if err.is_event_already_processed() {
                    eprintln!(
                        "[fake-hyperlane] submit skipped (already processed) rpc={} nonce={} mode={} {}",
                        rpc_url,
                        nonce,
                        mode,
                        err.summary()
                    );
                    pending_nonce = None;
                    sleep(Duration::from_secs(interval_secs)).await;
                } else {
                    eprintln!("[fake-hyperlane] submit failed rpc={} nonce={} mode={} {}", rpc_url, nonce, mode, err.summary());
                    sleep(Duration::from_secs(retry_delay_secs.max(1))).await;
                }
            }
        }
    }
}
