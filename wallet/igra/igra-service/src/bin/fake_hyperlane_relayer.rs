use hyperlane_core::accumulator::merkle::MerkleTree;
use hyperlane_core::accumulator::TREE_DEPTH;
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signable, Signature, H256, U256};
use kaspa_addresses::Address;
use rand::seq::SliceRandom;
use reqwest::{header, Client, StatusCode};
use secp256k1::{Secp256k1, SecretKey};
use serde::Deserialize;
use std::env;
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
}

#[derive(Deserialize)]
struct HyperlaneKeysFile {
    validators: Vec<HyperlaneValidator>,
}

#[derive(Deserialize, Clone)]
struct HyperlaneValidator {
    name: String,
    private_key_hex: String,
    #[serde(default)]
    pub public_key_hex: Option<String>,
}

#[derive(Deserialize)]
struct ModuleTypeResponse {
    module_type: String,
}

#[derive(Deserialize)]
struct DefaultIsmResponse {
    ism: String,
}

#[derive(Deserialize)]
struct DeliveredResponse {
    delivered: bool,
}

#[derive(Deserialize)]
struct MailboxCountResponse {
    count: u32,
}

#[derive(Deserialize)]
struct ValidatorsAndThresholdResult {
    domain: u32,
    validators: Vec<String>,
    threshold: u8,
    mode: String,
}

#[derive(Debug, Clone, Copy)]
enum IsmMode {
    MessageIdMultisig,
    MerkleRootMultisig,
}

impl IsmMode {
    fn from_wire(value: &str) -> Result<Self, String> {
        match value.trim() {
            "message_id_multisig" => Ok(IsmMode::MessageIdMultisig),
            "merkle_root_multisig" => Ok(IsmMode::MerkleRootMultisig),
            other => Err(format!("unsupported ism module_type={}", other)),
        }
    }
}

const DEFAULT_ORIGIN_DOMAIN: u32 = 5;
const DEFAULT_DESTINATION_DOMAIN: u32 = 7;
const DEFAULT_DESTINATION_ADDRESS: &str = "kaspadev:qp5mxzzk5gush9k2zv0pjhj3cmpq9n8nemljasdzxsqjr4x2dc6wc0225vqpw";

const DEFAULT_MERKLE_TREE_HOOK: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DEFAULT_SENDER: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DEFAULT_RECIPIENT: &str = "000000000000000000000000000000000000000000000000000000000000dead";

const UNORDERED_EVENTS_MIN: u16 = 1;
const UNORDERED_EVENTS_MAX: u16 = 1024;

fn parse_env_u64(name: &str, default: u64) -> u64 {
    env::var(name).ok().and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(default)
}

fn parse_env_u32(name: &str, default: u32) -> u32 {
    env::var(name).ok().and_then(|value| value.trim().parse::<u32>().ok()).unwrap_or(default)
}

fn parse_env_string(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string()).trim().to_string()
}

fn parse_cli_unordered_events() -> Result<Option<u16>, String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            eprintln!(
                "Usage: fake_hyperlane_relayer [--unordered-events N]\n\n  --unordered-events N   Shuffle nonces within each batch of N events ({}..={})",
                UNORDERED_EVENTS_MIN,
                UNORDERED_EVENTS_MAX
            );
            std::process::exit(0);
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
        return Err(format!("--unordered-events must be between {} and {}", UNORDERED_EVENTS_MIN, UNORDERED_EVENTS_MAX));
    }
    Ok(())
}

fn parse_h256(hex_str: &str) -> Result<H256, String> {
    let stripped = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(stripped).map_err(|e| format!("invalid hex {hex_str}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32-byte hex for H256, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(H256::from(arr))
}

fn format_h256(value: H256) -> String {
    format!("0x{}", hex::encode(value.as_bytes()))
}

fn build_hyperlane_message(
    version: u8,
    nonce: u32,
    origin: u32,
    sender: H256,
    destination: u32,
    recipient: H256,
    amount_sompi: u64,
    destination_address: &str,
) -> HyperlaneMessage {
    let mut body = Vec::with_capacity(8 + destination_address.len());
    body.extend_from_slice(&amount_sompi.to_le_bytes());
    body.extend_from_slice(destination_address.as_bytes());
    HyperlaneMessage { version, nonce, origin, sender, destination, recipient, body }
}

fn signature_to_bytes(sig: &Signature) -> [u8; 65] {
    sig.into()
}

fn signature_from_recoverable(rec: secp256k1::ecdsa::RecoverableSignature) -> Signature {
    let (rec_id, bytes) = rec.serialize_compact();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[0..32]);
    s.copy_from_slice(&bytes[32..64]);
    let v = u64::try_from(rec_id.to_i32().saturating_add(27)).unwrap_or(27);
    Signature { r: U256::from_big_endian(&r), s: U256::from_big_endian(&s), v }
}

fn normalize_hex(value: &str) -> String {
    value.trim().trim_start_matches("0x").trim_start_matches("0X").to_ascii_lowercase()
}

fn derive_uncompressed_pubkey_hex(validator: &HyperlaneValidator) -> Result<String, String> {
    let key_bytes = hex::decode(normalize_hex(&validator.private_key_hex))
        .map_err(|err| format!("invalid private key hex for {}: {}", validator.name, err))?;
    let secret = SecretKey::from_slice(&key_bytes).map_err(|err| format!("invalid private key for {}: {}", validator.name, err))?;
    let secp = Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    Ok(format!("0x{}", hex::encode(pk.serialize_uncompressed())))
}

fn derive_evm_address_h256_hex(validator: &HyperlaneValidator) -> Result<String, String> {
    let key_bytes = hex::decode(normalize_hex(&validator.private_key_hex))
        .map_err(|err| format!("invalid private key hex for {}: {}", validator.name, err))?;
    let secret = SecretKey::from_slice(&key_bytes).map_err(|err| format!("invalid private key for {}: {}", validator.name, err))?;
    let secp = Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let uncompressed = pk.serialize_uncompressed();
    let digest = alloy::primitives::keccak256(&uncompressed[1..]);
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&digest.as_slice()[12..]);
    Ok(format!("0x{}", hex::encode(out)))
}

fn sign_checkpoint(checkpoint: &CheckpointWithMessageId, validator: &HyperlaneValidator) -> Result<Signature, String> {
    let key_bytes = hex::decode(normalize_hex(&validator.private_key_hex))
        .map_err(|err| format!("invalid private key hex for {}: {}", validator.name, err))?;
    let secret = SecretKey::from_slice(&key_bytes).map_err(|err| format!("invalid private key for {}: {}", validator.name, err))?;
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_digest_slice(checkpoint.signing_hash().as_ref()).map_err(|e| format!("signing hash: {e}"))?;
    Ok(signature_from_recoverable(secp.sign_ecdsa_recoverable(&msg, &secret)))
}

fn build_metadata_bytes_message_id_multisig(
    message: &HyperlaneMessage,
    merkle_tree_hook_address: H256,
    signatures: &[Signature],
) -> Vec<u8> {
    let message_id = message.id();
    let root = message_id;
    let index = message.nonce;
    let checkpoint = CheckpointWithMessageId {
        checkpoint: Checkpoint { merkle_tree_hook_address, mailbox_domain: message.origin, root, index },
        message_id,
    };
    let mut out = Vec::with_capacity(32 + 32 + 4 + signatures.len().saturating_mul(65));
    out.extend_from_slice(checkpoint.checkpoint.merkle_tree_hook_address.as_bytes());
    out.extend_from_slice(checkpoint.checkpoint.root.as_bytes());
    out.extend_from_slice(&checkpoint.checkpoint.index.to_be_bytes());
    for sig in signatures {
        out.extend_from_slice(&signature_to_bytes(sig));
    }
    out
}

fn build_metadata_bytes_merkle_root_multisig(
    message: &HyperlaneMessage,
    merkle_tree_hook_address: H256,
    leaf_index: u32,
    checkpoint_index: u32,
    signatures: &[Signature],
) -> Result<Vec<u8>, String> {
    let message_id = message.id();
    let leaves = vec![message_id];
    let tree = MerkleTree::create(&leaves, TREE_DEPTH);
    let leaf_index_usize = usize::try_from(leaf_index).map_err(|_| format!("leaf_index too large: {}", leaf_index))?;
    let (leaf, branch) = tree.generate_proof(leaf_index_usize, TREE_DEPTH);
    if leaf != message_id {
        return Err("merkle proof leaf mismatch".to_string());
    }
    if branch.len() != TREE_DEPTH {
        return Err(format!("merkle proof branch must have length {}, got {}", TREE_DEPTH, branch.len()));
    }

    let mut out = Vec::with_capacity(32 + 4 + 32 + (TREE_DEPTH * 32) + 4 + signatures.len().saturating_mul(65));
    out.extend_from_slice(merkle_tree_hook_address.as_bytes());
    out.extend_from_slice(&leaf_index.to_be_bytes());
    out.extend_from_slice(message_id.as_bytes());
    for h in &branch {
        out.extend_from_slice(h.as_bytes());
    }
    out.extend_from_slice(&checkpoint_index.to_be_bytes());
    for sig in signatures {
        out.extend_from_slice(&signature_to_bytes(sig));
    }
    Ok(out)
}

async fn http_get_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    base_url: &str,
    path: &str,
    token: Option<&str>,
) -> Result<T, RpcFailure> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let mut req = client.get(&url);
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }
    let resp = req.send().await.map_err(|err| RpcFailure::Transport(err.to_string()))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(RpcFailure::Http { status, body });
    }
    serde_json::from_str(&body).map_err(|err| RpcFailure::InvalidJson { error: err.to_string(), body })
}

async fn http_post_json<T: serde::Serialize, R: for<'de> Deserialize<'de>>(
    client: &Client,
    base_url: &str,
    path: &str,
    token: Option<&str>,
    payload: &T,
) -> Result<R, RpcFailure> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let mut req = client.post(&url).json(payload);
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }
    let resp = req.send().await.map_err(|err| RpcFailure::Transport(err.to_string()))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(RpcFailure::Http { status, body });
    }
    serde_json::from_str(&body).map_err(|err| RpcFailure::InvalidJson { error: err.to_string(), body })
}

async fn json_rpc<T: serde::Serialize>(
    client: &Client,
    base_url: &str,
    token: Option<&str>,
    method: &str,
    params: T,
) -> Result<serde_json::Value, RpcFailure> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "fake-hyperlane-relayer",
        "method": method,
        "params": params,
    });
    let envelope: JsonRpcEnvelope = http_post_json(client, base_url, "/rpc", token, &payload).await?;
    if let Some(err) = envelope.error {
        return Err(RpcFailure::JsonRpc { code: err.code, message: err.message });
    }
    Ok(envelope.result.unwrap_or(serde_json::Value::Null))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let unordered_events = parse_cli_unordered_events()?;

    let rpc_base = parse_env_string("IGRA_RPC_BASE_URL", "http://127.0.0.1:8088");
    let rpc_token = env::var("IGRA_RPC_TOKEN").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let keys_path = parse_env_string("HYPERLANE_KEYS_PATH", "/data/igra/hyperlane-keys.json");

    let origin_domain = parse_env_u32("HYPERLANE_ORIGIN_DOMAIN", DEFAULT_ORIGIN_DOMAIN);
    let destination_domain = parse_env_u32("HYPERLANE_DESTINATION_DOMAIN", DEFAULT_DESTINATION_DOMAIN);
    let amount_sompi = parse_env_u64("HYPERLANE_AMOUNT_SOMPI", 20_000_000);
    let destination_address = parse_env_string("HYPERLANE_DESTINATION", DEFAULT_DESTINATION_ADDRESS);
    let interval_secs = parse_env_u64("HYPERLANE_INTERVAL_SECS", 5).max(1);
    let retry_delay_secs = parse_env_u64("HYPERLANE_RETRY_DELAY_SECS", 1).max(1);
    let client_side_timeout_secs = parse_env_u64("HYPERLANE_CLIENT_TIMEOUT_SECS", 120).max(1);

    if destination_address.is_empty() {
        return Err("HYPERLANE_DESTINATION must be set".to_string());
    }
    Address::try_from(destination_address.as_str()).map_err(|_| "invalid HYPERLANE_DESTINATION address".to_string())?;

    let sender = parse_h256(&parse_env_string("HYPERLANE_SENDER", DEFAULT_SENDER))?;
    let recipient = parse_h256(&parse_env_string("HYPERLANE_RECIPIENT", DEFAULT_RECIPIENT))?;
    let merkle_tree_hook_address = parse_h256(&parse_env_string("HYPERLANE_MERKLE_TREE_HOOK", DEFAULT_MERKLE_TREE_HOOK))?;

    let keys_raw = fs::read_to_string(&keys_path).map_err(|err| format!("read keys file failed path={} error={}", keys_path, err))?;
    let keys: HyperlaneKeysFile = serde_json::from_str(&keys_raw).map_err(|err| format!("parse keys json failed: {}", err))?;
    if keys.validators.is_empty() {
        return Err(format!("no validators loaded from keys_path={}", keys_path));
    }

    let strict_keys = env::var("HYPERLANE_STRICT_KEYS").ok().map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    for validator in &keys.validators {
        let derived = derive_uncompressed_pubkey_hex(validator)?;
        if let Some(expected) = validator.public_key_hex.as_deref() {
            if normalize_hex(expected) != normalize_hex(&derived) {
                let msg =
                    format!("validator pubkey mismatch name={} expected={} derived={}", validator.name, expected.trim(), derived);
                if strict_keys {
                    return Err(msg);
                }
                eprintln!("[fake-hyperlane-relayer] WARNING: {}", msg);
            }
        }
    }

    eprintln!(
        "[fake-hyperlane-relayer] start rpc_base={} token={} validators={} origin_domain={} dest_domain={} amount_sompi={} destination_address={} interval_secs={} retry_delay_secs={} client_timeout_secs={}",
        rpc_base,
        if rpc_token.is_some() { "set" } else { "none" },
        keys.validators.len(),
        origin_domain,
        destination_domain,
        amount_sompi,
        destination_address,
        interval_secs,
        retry_delay_secs,
        client_side_timeout_secs
    );

    let client =
        Client::builder().timeout(Duration::from_secs(15)).build().map_err(|err| format!("http client build failed: {}", err))?;

    let module_type: ModuleTypeResponse =
        http_get_json(&client, &rpc_base, "/rpc/ism/module_type", rpc_token.as_deref()).await.map_err(|e| e.summary())?;
    let mode = IsmMode::from_wire(&module_type.module_type)?;

    let default_ism: DefaultIsmResponse =
        http_get_json(&client, &rpc_base, "/rpc/mailbox/default_ism", rpc_token.as_deref()).await.map_err(|e| e.summary())?;
    eprintln!("[fake-hyperlane-relayer] destination default_ism={}", default_ism.ism);

    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    let start_nonce_override = env::var("HYPERLANE_START_NONCE").ok().and_then(|v| v.trim().parse::<u32>().ok());
    let mut next_batch_start_nonce: u32 = if let Some(override_nonce) = start_nonce_override {
        override_nonce
    } else if unordered_events.is_some() {
        0
    } else {
        u32::try_from(now_secs % 1_000_000).unwrap_or(0)
    };

    let batch_size = unordered_events.unwrap_or(1) as u32;
    let mut batch = Vec::<u32>::new();
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
                "[fake-hyperlane-relayer] unordered batch prepared start_nonce={} end_nonce_inclusive={} size={}",
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
        let deadline = Instant::now() + Duration::from_secs(client_side_timeout_secs);
        if batch.is_empty() {
            refill_batch(&mut batch, &mut next_batch_start_nonce);
        }
        let Some(nonce) = batch.pop() else {
            continue;
        };

        let msg = build_hyperlane_message(
            3,
            nonce,
            origin_domain,
            sender,
            destination_domain,
            recipient,
            amount_sompi,
            &destination_address,
        );
        let message_id = msg.id();
        let message_id_hex = format_h256(message_id);
        eprintln!("[fake-hyperlane-relayer] tick nonce={} message_id={} mode={:?}", nonce, message_id_hex, mode);

        let count: MailboxCountResponse =
            http_get_json(&client, &rpc_base, "/rpc/mailbox/count", rpc_token.as_deref()).await.map_err(|e| e.summary())?;
        eprintln!("[fake-hyperlane-relayer] mailbox.count={}", count.count);

        let delivered_path = format!("/rpc/mailbox/delivered/{}", message_id_hex);
        let delivered: DeliveredResponse =
            http_get_json(&client, &rpc_base, &delivered_path, rpc_token.as_deref()).await.map_err(|e| e.summary())?;
        if delivered.delivered {
            eprintln!("[fake-hyperlane-relayer] already delivered message_id={}", message_id_hex);
            sleep(Duration::from_secs(interval_secs)).await;
            continue;
        }

        let vat = json_rpc(
            &client,
            &rpc_base,
            rpc_token.as_deref(),
            "hyperlane.validators_and_threshold",
            serde_json::json!({
                "message_id": message_id_hex,
                "destination_domain": destination_domain,
                "origin_domain": origin_domain,
            }),
        )
        .await
        .map_err(|e| e.summary())?;
        let vat: ValidatorsAndThresholdResult =
            serde_json::from_value(vat).map_err(|err| format!("parse validators_and_threshold result: {}", err))?;
        eprintln!(
            "[fake-hyperlane-relayer] validators_and_threshold domain={} threshold={} validators={} mode={}",
            vat.domain,
            vat.threshold,
            vat.validators.len(),
            vat.mode
        );

        let threshold = usize::from(vat.threshold);
        if threshold == 0 {
            return Err("destination returned threshold=0".to_string());
        }
        if keys.validators.len() < threshold {
            return Err(format!(
                "not enough local validator keys to satisfy threshold local_keys={} threshold={}",
                keys.validators.len(),
                threshold
            ));
        }
        if vat.validators.len() < threshold {
            return Err(format!(
                "destination returned insufficient validators validator_count={} threshold={}",
                vat.validators.len(),
                threshold
            ));
        }
        for (idx, validator) in keys.validators.iter().take(threshold).enumerate() {
            let derived = derive_evm_address_h256_hex(validator)?;
            let expected = vat.validators.get(idx).cloned().unwrap_or_default();
            if normalize_hex(&expected) != normalize_hex(&derived) {
                let msg = format!(
                    "destination validator mismatch index={} destination_validator={} local_derived_validator={}",
                    idx, expected, derived
                );
                if strict_keys {
                    return Err(msg);
                }
                eprintln!("[fake-hyperlane-relayer] WARNING: {}", msg);
            }
        }

        let mut signatures = Vec::with_capacity(threshold);
        let mut checkpoint: CheckpointWithMessageId = CheckpointWithMessageId {
            checkpoint: Checkpoint { merkle_tree_hook_address, mailbox_domain: origin_domain, root: H256::zero(), index: 0 },
            message_id,
        };
        let metadata_bytes = match mode {
            IsmMode::MessageIdMultisig => {
                checkpoint.checkpoint.root = message_id;
                checkpoint.checkpoint.index = nonce;
                for validator in keys.validators.iter().take(threshold) {
                    signatures.push(sign_checkpoint(&checkpoint, validator)?);
                }
                build_metadata_bytes_message_id_multisig(&msg, merkle_tree_hook_address, &signatures)
            }
            IsmMode::MerkleRootMultisig => {
                let leaf_index = 0u32;
                let checkpoint_index = leaf_index;
                let tree = MerkleTree::create(&[message_id], TREE_DEPTH);
                checkpoint.checkpoint.root = tree.hash();
                checkpoint.checkpoint.index = checkpoint_index;
                for validator in keys.validators.iter().take(threshold) {
                    signatures.push(sign_checkpoint(&checkpoint, validator)?);
                }
                build_metadata_bytes_merkle_root_multisig(&msg, merkle_tree_hook_address, leaf_index, checkpoint_index, &signatures)?
            }
        };

        let metadata_hex = format!("0x{}", hex::encode(&metadata_bytes));
        eprintln!(
            "[fake-hyperlane-relayer] built metadata bytes_len={} sigs={}/{}",
            metadata_bytes.len(),
            signatures.len(),
            threshold
        );

        http_post_json::<_, serde_json::Value>(
            &client,
            &rpc_base,
            "/rpc/ism/dry_run_verify",
            rpc_token.as_deref(),
            &serde_json::json!({
                "message": {
                    "version": msg.version,
                    "nonce": msg.nonce,
                    "origin": msg.origin,
                    "sender": format_h256(msg.sender),
                    "destination": msg.destination,
                    "recipient": format_h256(msg.recipient),
                    "body": format!("0x{}", hex::encode(&msg.body)),
                },
                "metadata": metadata_hex,
            }),
        )
        .await
        .map_err(|e| e.summary())?;

        http_post_json::<_, serde_json::Value>(
            &client,
            &rpc_base,
            "/rpc/mailbox/estimate_costs",
            rpc_token.as_deref(),
            &serde_json::json!({
                "message": {
                    "version": msg.version,
                    "nonce": msg.nonce,
                    "origin": msg.origin,
                    "sender": format_h256(msg.sender),
                    "destination": msg.destination,
                    "recipient": format_h256(msg.recipient),
                    "body": format!("0x{}", hex::encode(&msg.body)),
                },
                "metadata": metadata_hex,
            }),
        )
        .await
        .map_err(|e| e.summary())?;

        let mut attempts = 0u32;
        loop {
            attempts = attempts.saturating_add(1);
            let result = json_rpc(
                &client,
                &rpc_base,
                rpc_token.as_deref(),
                "hyperlane.mailbox_process",
                serde_json::json!({
                    "message": {
                        "version": msg.version,
                        "nonce": msg.nonce,
                        "origin": msg.origin,
                        "sender": format_h256(msg.sender),
                        "destination": msg.destination,
                        "recipient": format_h256(msg.recipient),
                        "body": format!("0x{}", hex::encode(&msg.body)),
                    },
                    "metadata": metadata_hex,
                }),
            )
            .await
            .map_err(|e| e.summary())?;

            let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
            let tx_id = result.get("transaction_id").and_then(|v| v.as_str()).unwrap_or("");
            let err = result.get("error").and_then(|v| v.as_str()).unwrap_or("");
            if success {
                eprintln!(
                    "[fake-hyperlane-relayer] mailbox_process success message_id={} tx_id={} attempts={}",
                    message_id_hex, tx_id, attempts
                );
                break;
            }

            eprintln!(
                "[fake-hyperlane-relayer] mailbox_process pending message_id={} attempts={} error={}",
                message_id_hex, attempts, err
            );

            if Instant::now() >= deadline {
                return Err(format!(
                    "client timeout waiting for delivery message_id={} attempts={} last_error={}",
                    message_id_hex, attempts, err
                ));
            }
            sleep(Duration::from_secs(retry_delay_secs)).await;
        }

        // Confirm via delivered() (idempotency signal).
        let delivered: DeliveredResponse =
            http_get_json(&client, &rpc_base, &delivered_path, rpc_token.as_deref()).await.map_err(|e| e.summary())?;
        eprintln!("[fake-hyperlane-relayer] delivered after process message_id={} delivered={}", message_id_hex, delivered.delivered);

        sleep(Duration::from_secs(interval_secs)).await;
    }
}
