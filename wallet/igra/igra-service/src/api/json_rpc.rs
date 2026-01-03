use igra_core::error::ThresholdError;
use crate::service::metrics::Metrics;
use hyperlane_core::accumulator::{merkle::Proof as HyperlaneProof, TREE_DEPTH};
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signature, H256, U256};
use igra_core::event::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::hyperlane::ism::{ConfiguredIsm, IsmMode, ProofMetadata, ValidatorSet, IsmVerifier};
use igra_core::model::EventSource;
use igra_core::audit;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use axum::http::header::AUTHORIZATION;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use serde::{Deserialize, Serialize};
use serde::de::{self, SeqAccess, Visitor};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::fmt;
use blake3::Hasher;
use kaspa_addresses::{Address, Prefix, Version};
use tokio::fs;
use tokio::net::TcpListener;
use subtle::ConstantTimeEq;
use secp256k1::PublicKey;

#[derive(Clone)]
pub struct RpcState {
    pub event_ctx: EventContext,
    pub rpc_token: Option<String>,
    pub node_rpc_url: String,
    pub metrics: Arc<Metrics>,
    pub hyperlane_ism: Option<ConfiguredIsm>,
    pub group_id_hex: Option<String>,
    pub coordinator_peer_id: String,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub id: serde_json::Value,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    pub result: T,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub jsonrpc: &'static str,
    pub id: serde_json::Value,
    pub error: JsonRpcErrorBody,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcErrorBody {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
struct ValidatorsAndThresholdParams {
    pub message_id: H256,
    pub destination_domain: u32,
    #[serde(default)]
    pub origin_domain: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ValidatorsAndThresholdResult {
    pub domain: u32,
    pub validators: Vec<String>,
    pub threshold: u8,
    pub mode: IsmMode,
    pub config_hash: String,
}

#[derive(Debug, Deserialize)]
struct RpcHyperlaneMessage {
    pub version: u8,
    pub nonce: u32,
    pub origin: u32,
    pub sender: H256,
    pub destination: u32,
    pub recipient: H256,
    #[serde(deserialize_with = "deserialize_body_bytes")]
    pub body: Vec<u8>,
}

impl From<RpcHyperlaneMessage> for HyperlaneMessage {
    fn from(value: RpcHyperlaneMessage) -> Self {
        HyperlaneMessage {
            version: value.version,
            nonce: value.nonce,
            origin: value.origin,
            sender: value.sender,
            destination: value.destination,
            recipient: value.recipient,
            body: value.body,
        }
    }
}

#[derive(Debug, Deserialize)]
struct MailboxProcessParams {
    pub message: RpcHyperlaneMessage,
    pub metadata: MailboxMetadataParams,
    #[serde(default)]
    pub mode: Option<IsmMode>,
}

#[derive(Debug, Deserialize)]
struct MailboxMetadataParams {
    pub checkpoint: RpcCheckpointWithMessageId,
    #[serde(default)]
    pub merkle_proof: Option<RpcMerkleProof>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RpcCheckpointWithMessageId {
    #[serde(alias = "merkle_tree_hook")]
    pub merkle_tree_hook_address: H256,
    pub mailbox_domain: u32,
    pub root: H256,
    pub index: u32,
    pub message_id: H256,
}

#[derive(Debug, Deserialize)]
struct RpcMerkleProof {
    #[serde(default)]
    pub leaf: Option<H256>,
    pub index: usize,
    pub path: Vec<H256>,
}

#[derive(Debug, Serialize)]
struct MailboxProcessResult {
    pub status: &'static str,
    pub message_id: String,
    pub event_id: String,
    pub root: String,
    pub quorum: usize,
    pub validators_used: Vec<String>,
    pub config_hash: String,
    pub mode: IsmMode,
    pub session_id: String,
    pub signing_submitted: bool,
}

impl RpcCheckpointWithMessageId {
    fn into_core(self) -> CheckpointWithMessageId {
        CheckpointWithMessageId {
            checkpoint: Checkpoint {
                merkle_tree_hook_address: self.merkle_tree_hook_address,
                mailbox_domain: self.mailbox_domain,
                root: self.root,
                index: self.index,
            },
            message_id: self.message_id,
        }
    }
}

impl RpcMerkleProof {
    fn into_core(self, message_id: H256) -> Result<HyperlaneProof, String> {
        if self.path.len() != TREE_DEPTH {
            return Err(format!(
                "merkle proof path must have length {} (got {})",
                TREE_DEPTH,
                self.path.len()
            ));
        }
        let leaf = self.leaf.unwrap_or(message_id);
        if leaf != message_id {
            return Err("merkle proof leaf must match message_id".to_string());
        }
        let mut path = [H256::zero(); TREE_DEPTH];
        for (idx, item) in self.path.iter().enumerate() {
            path[idx] = *item;
        }
        Ok(HyperlaneProof {
            leaf,
            index: self.index,
            path,
        })
    }
}

impl MailboxMetadataParams {
    fn into_core(self, message_id: H256, mode: IsmMode) -> Result<ProofMetadata, String> {
        let checkpoint = self.checkpoint.into_core();
        let merkle_proof = match (mode, self.merkle_proof) {
            (IsmMode::MerkleRootMultisig, None) => {
                return Err("merkle_proof required for merkle_root_multisig".to_string())
            }
            (_, proof) => proof.map(|p| p.into_core(message_id)).transpose()?,
        };
        let signatures = self
            .signatures
            .iter()
            .map(|sig| parse_signature_hex(sig))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProofMetadata {
            checkpoint,
            merkle_proof,
            signatures,
        })
    }
}

fn deserialize_body_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BodyVisitor;

    impl<'de> Visitor<'de> for BodyVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("byte array or 0x-prefixed hex string")
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_body_str(v).map_err(E::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&v)
        }
    }

    deserializer.deserialize_any(BodyVisitor)
}

fn parse_body_str(value: &str) -> Result<Vec<u8>, String> {
    let stripped = value.trim();
    let hex_str = stripped.trim_start_matches("0x");
    hex::decode(hex_str).map_err(|_| "invalid message body hex".to_string())
}

fn parse_signature_hex(value: &str) -> Result<Signature, String> {
    let stripped = value.trim_start_matches("0x");
    let bytes = hex::decode(stripped).map_err(|_| "invalid signature hex".to_string())?;
    if bytes.len() != 65 {
        return Err("signature must be 65 bytes (r||s||v)".to_string());
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[0..32]);
    s.copy_from_slice(&bytes[32..64]);
    Ok(Signature {
        r: U256::from_big_endian(&r),
        s: U256::from_big_endian(&s),
        v: bytes[64] as u64,
    })
}

fn format_pubkey(pk: &PublicKey) -> String {
    format!("0x{}", hex::encode(pk.serialize()))
}

fn format_h256(value: H256) -> String {
    format!("0x{}", hex::encode(value.as_ref()))
}

fn format_config_hash(set: &ValidatorSet) -> String {
    format!("0x{}", hex::encode(set.config_hash()))
}

fn derive_session_id_hex(group_id_hex: Option<&str>, message_id: H256) -> String {
    let group_hex = group_id_hex.unwrap_or_default().trim();
    if group_hex.is_empty() {
        return String::new();
    }
    let bytes = match hex::decode(group_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let mut hasher = Hasher::new();
    hasher.update(&bytes);
    hasher.update(message_id.as_ref());
    format!("0x{}", hasher.finalize().to_hex())
}

fn format_signature_hex(sig: &Signature) -> String {
    let mut r_bytes = [0u8; 32];
    sig.r.to_big_endian(&mut r_bytes);
    let mut s_bytes = [0u8; 32];
    sig.s.to_big_endian(&mut s_bytes);
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&r_bytes);
    out.extend_from_slice(&s_bytes);
    out.push(sig.v as u8);
    format!("0x{}", hex::encode(out))
}

fn metadata_to_map(metadata: &ProofMetadata, mode: &IsmMode) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("hyperlane.mode".to_string(), format!("{:?}", mode).to_lowercase());
    map.insert(
        "hyperlane.merkle_root".to_string(),
        format_h256(metadata.checkpoint.root),
    );
    map.insert(
        "hyperlane.mailbox_domain".to_string(),
        metadata.checkpoint.mailbox_domain.to_string(),
    );
    map.insert("hyperlane.index".to_string(), metadata.checkpoint.index.to_string());
    map.insert(
        "hyperlane.message_id".to_string(),
        format_h256(metadata.checkpoint.message_id),
    );
    if let Some(proof) = metadata.merkle_proof.as_ref() {
        map.insert("hyperlane.proof.index".to_string(), proof.index.to_string());
    }
    for (idx, sig) in metadata.signatures.iter().enumerate() {
        map.insert(format!("hyperlane.signature.{idx}"), format_signature_hex(sig));
    }
    map
}

fn detect_local_prefix(ctx: &EventContext) -> Result<Prefix, String> {
    if let Some(addr) = ctx.config.pskt.source_addresses.first() {
        return Address::try_from(addr.as_str())
            .map(|a| a.prefix)
            .map_err(|_| "invalid pskt.source_addresses entry while inferring network".to_string());
    }
    if let Some(addr) = ctx.config.pskt.change_address.as_ref() {
        return Address::try_from(addr.as_str())
            .map(|a| a.prefix)
            .map_err(|_| "invalid pskt.change_address entry while inferring network".to_string());
    }
    Err("cannot determine local network prefix; configure pskt.source_addresses or change_address".to_string())
}

struct SigningPayload {
    destination_address: String,
    amount_sompi: u64,
    derivation_path: String,
    derivation_index: Option<u32>,
}

fn extract_signing_payload(message: &HyperlaneMessage, expected_prefix: Prefix) -> Result<SigningPayload, String> {
    // recipient holds a 32-byte Kaspa payload; prefix is added from local network, version assumed PubKey (len 32).
    let recipient_bytes: [u8; 32] = message.recipient.as_bytes().try_into().map_err(|_| "recipient must be 32 bytes")?;
    let destination_address = Address::new(expected_prefix, Version::PubKey, &recipient_bytes).to_string();
    // body carries amount as big-endian u64
    if message.body.len() != 8 {
        return Err("message.body must be exactly 8 bytes (big-endian u64 amount)".to_string());
    }
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&message.body);
    let amount_sompi = u64::from_be_bytes(amount_bytes);
    let derivation_index = Some(0);
    let derivation_path = String::new();
    Ok(SigningPayload {
        destination_address,
        amount_sompi,
        derivation_path,
        derivation_index,
    })
}

async fn submit_signing_from_hyperlane(
    ctx: &EventContext,
    message: &HyperlaneMessage,
    metadata: &ProofMetadata,
    session_id_hex: &str,
    set: &ValidatorSet,
    coordinator_peer_id: &str,
) -> Result<bool, String> {
    let expected_prefix = detect_local_prefix(ctx)?;
    let payload = extract_signing_payload(message, expected_prefix)?;
    if payload.destination_address.trim().is_empty() || payload.amount_sompi == 0 {
        return Err("destination_address and amount_sompi are required to submit signing event".to_string());
    }
    let event_id = format_h256(message.id());
    let mut meta = metadata_to_map(metadata, &set.mode);
    meta.insert("hyperlane.quorum".to_string(), set.threshold.to_string());
    let signing_event = SigningEventWire {
        event_id: event_id.clone(),
        event_source: EventSource::Hyperlane {
            domain: message.destination.to_string(),
            sender: format_h256(message.sender),
        },
        derivation_path: payload.derivation_path,
        derivation_index: payload.derivation_index,
        destination_address: payload.destination_address,
        amount_sompi: payload.amount_sompi,
        metadata: meta,
        timestamp_nanos: audit::now_nanos(),
        signature_hex: None,
        signature: None,
    };
    let params = SigningEventParams {
        session_id_hex: session_id_hex.to_string(),
        request_id: event_id.clone(),
        coordinator_peer_id: coordinator_peer_id.to_string(),
        expires_at_nanos: audit::now_nanos().saturating_add(10 * 60 * 1_000_000_000),
        signing_event,
    };
    submit_signing_event(ctx, params)
        .await
        .map_err(|e| e.to_string())?;
    Ok(true)
}
pub async fn run_json_rpc_server(addr: SocketAddr, state: Arc<RpcState>) -> Result<(), ThresholdError> {
    let app = build_router(state);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    axum::serve(listener, app)
        .await
        .map_err(|err| ThresholdError::Message(err.to_string()))
}

pub fn build_router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/rpc", post(handle_rpc))
        .route("/health", get(handle_health))
        .route("/ready", get(handle_ready))
        .route("/metrics", get(handle_metrics))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}

pub async fn run_hyperlane_watcher(
    state: Arc<RpcState>,
    dir: std::path::PathBuf,
    poll_interval: Duration,
) -> Result<(), ThresholdError> {
    loop {
        let mut entries = fs::read_dir(&dir)
            .await
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|err| ThresholdError::Message(err.to_string()))?
        {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path)
                .await
                .map_err(|err| ThresholdError::Message(err.to_string()))?;
            let params: SigningEventParams = match serde_json::from_slice(&bytes) {
                Ok(params) => params,
                Err(err) => {
                    tracing::warn!(path = %path.display(), error = %err, "hyperlane watcher invalid event");
                    continue;
                }
            };
            if let Err(err) = submit_signing_event(&state.event_ctx, params).await {
                tracing::warn!(path = %path.display(), error = %err, "hyperlane watcher submit failed");
                continue;
            }
            let mut done_path = path.clone();
            done_path.set_extension("done");
            if let Err(err) = fs::rename(&path, &done_path).await {
                tracing::warn!(path = %path.display(), error = %err, "hyperlane watcher rename failed");
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}

async fn handle_rpc(State(state): State<Arc<RpcState>>, headers: HeaderMap, Json(req): Json<JsonRpcRequest>) -> Response {
    let id = req.id.clone();
    if let Err(err) = authorize_rpc(&headers, state.rpc_token.as_deref()) {
        state.metrics.inc_rpc_request(req.method.as_str(), "unauthorized");
        return Json(JsonRpcError {
            jsonrpc: "2.0",
            id,
            error: JsonRpcErrorBody { code: -32001, message: err },
        })
        .into_response();
    }
    match req.method.as_str() {
        "signing_event.submit" => {
            let params = match req.params {
                Some(params) => params,
                None => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32602, message: "missing params".to_string() },
                    })
                    .into_response();
                }
            };
            let params: SigningEventParams = match serde_json::from_value(params) {
                Ok(params) => params,
                Err(err) => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32602, message: err.to_string() },
                    })
                    .into_response();
                }
            };
            match submit_signing_event(&state.event_ctx, params).await {
                Ok(result) => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "ok");
                    Json(JsonRpcResponse { jsonrpc: "2.0", id, result }).into_response()
                }
                Err(err) => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32000, message: err.to_string() },
                    })
                    .into_response()
                }
            }
        }
        "hyperlane.validators_and_threshold" => {
            let params = match req.params {
                Some(params) => params,
                None => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32602, message: "missing params".to_string() },
                    })
                    .into_response();
                }
            };
            let params: ValidatorsAndThresholdParams = match serde_json::from_value(params) {
                Ok(params) => params,
                Err(err) => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32602, message: err.to_string() },
                    })
                    .into_response();
                }
            };
            let ism = match state.hyperlane_ism.as_ref() {
                Some(ism) => ism,
                None => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32004, message: "hyperlane ISM not configured".to_string() },
                    })
                    .into_response();
                }
            };
            let set = match ism.validators_and_threshold(params.destination_domain, params.message_id) {
                Some(set) => set,
                None => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32004, message: "unknown destination domain".to_string() },
                    })
                    .into_response();
                }
            };
            let result = ValidatorsAndThresholdResult {
                domain: set.domain,
                validators: set.validators.iter().map(format_pubkey).collect(),
                threshold: set.threshold,
                mode: set.mode.clone(),
                config_hash: format_config_hash(&set),
            };
            state.metrics.inc_rpc_request(req.method.as_str(), "ok");
            Json(JsonRpcResponse { jsonrpc: "2.0", id, result }).into_response()
        }
        "hyperlane.mailbox_process" => {
            let params = match req.params {
                Some(params) => params,
                None => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32602, message: "missing params".to_string() },
                    })
                    .into_response();
                }
            };
            let params: MailboxProcessParams = match serde_json::from_value(params) {
                Ok(params) => params,
                Err(err) => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32602, message: err.to_string() },
                    })
                    .into_response();
                }
            };
            let ism = match state.hyperlane_ism.as_ref() {
                Some(ism) => ism,
                None => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32004, message: "hyperlane ISM not configured".to_string() },
                    })
                    .into_response();
                }
            };
            let message: HyperlaneMessage = params.message.into();
            let set = match ism.validators_and_threshold(message.destination, message.id()) {
                Some(set) => set,
                None => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32004, message: "unknown destination domain".to_string() },
                    })
                    .into_response();
                }
            };
            let mode = params.mode.unwrap_or(set.mode.clone());
            let metadata = match params.metadata.into_core(message.id(), mode.clone()) {
                Ok(meta) => meta,
                Err(err) => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    return Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32602, message: err },
                    })
                    .into_response();
                }
            };
            match ism.verify_proof(&message, &metadata, mode.clone()) {
                Ok(report) => {
                    let session_id = derive_session_id_hex(state.group_id_hex.as_deref(), report.message_id);
                    if session_id.is_empty() {
                        state.metrics.inc_rpc_request(req.method.as_str(), "error");
                        return Json(JsonRpcError {
                            jsonrpc: "2.0",
                            id,
                            error: JsonRpcErrorBody {
                                code: -32002,
                                message: "missing or invalid group_id for session derivation".to_string(),
                            },
                        })
                        .into_response();
                    }
                    let signing_submitted = match submit_signing_from_hyperlane(
                        &state.event_ctx,
                        &message,
                        &metadata,
                        &session_id,
                        &set,
                        &state.coordinator_peer_id,
                    )
                    .await
                    {
                        Ok(flag) => flag,
                        Err(err) => {
                            state.metrics.inc_rpc_request(req.method.as_str(), "error");
                            return Json(JsonRpcError {
                                jsonrpc: "2.0",
                                id,
                                error: JsonRpcErrorBody { code: -32005, message: err },
                            })
                            .into_response();
                        }
                    };

                    let result = MailboxProcessResult {
                        status: "proven",
                        message_id: format_h256(report.message_id),
                        event_id: format_h256(report.message_id),
                        root: format_h256(report.root),
                        quorum: report.quorum,
                        validators_used: report.validators_used.iter().map(format_pubkey).collect(),
                        config_hash: format_config_hash(&set),
                        mode,
                        session_id,
                        signing_submitted,
                    };
                    state.metrics.inc_rpc_request(req.method.as_str(), "ok");
                    Json(JsonRpcResponse { jsonrpc: "2.0", id, result }).into_response()
                }
                Err(err) => {
                    state.metrics.inc_rpc_request(req.method.as_str(), "error");
                    Json(JsonRpcError {
                        jsonrpc: "2.0",
                        id,
                        error: JsonRpcErrorBody { code: -32000, message: err },
                    })
                    .into_response()
                }
            }
        }
        _ => {
            state.metrics.inc_rpc_request(req.method.as_str(), "not_found");
            Json(JsonRpcError {
                jsonrpc: "2.0",
                id,
                error: JsonRpcErrorBody { code: -32601, message: "method not found".to_string() },
            })
            .into_response()
        }
    }
}

fn authorize_rpc(headers: &HeaderMap, expected: Option<&str>) -> Result<(), String> {
    let expected = match expected {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => return Ok(()),
    };

    if let Some(value) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        if constant_time_eq(value, expected) {
            return Ok(());
        }
    }
    if let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = value.strip_prefix("Bearer ") {
            if constant_time_eq(token, expected) {
                return Ok(());
            }
        }
    }
    Err("unauthorized".to_string())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
    }))
}

async fn handle_ready(State(state): State<Arc<RpcState>>) -> impl IntoResponse {
    let storage_ok = state.event_ctx.storage.health_check().is_ok();
    let node_connected = match igra_core::rpc::grpc::GrpcNodeRpc::connect(state.node_rpc_url.clone()).await {
        Ok(_) => true,
        Err(_) => false,
    };
    let status = if storage_ok && node_connected { "ready" } else { "degraded" };
    Json(serde_json::json!({
        "status": status,
        "storage_ok": storage_ok,
        "node_connected": node_connected,
    }))
}

async fn handle_metrics(State(state): State<Arc<RpcState>>) -> impl IntoResponse {
    match state.metrics.encode() {
        Ok(body) => {
            let mut response = body.into_response();
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4"),
            );
            response
        }
        Err(err) => {
            let mut response = format!("metrics_error: {}", err).into_response();
            *response.status_mut() = axum::http::StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}
