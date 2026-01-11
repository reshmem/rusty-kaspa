use super::types::{json_err, json_ok, RpcErrorCode};
use crate::api::state::RpcState;
use blake3::Hasher;
use hyperlane_core::accumulator::{merkle::Proof as HyperlaneProof, TREE_DEPTH};
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signature, H256, U256};
use igra_core::application::{submit_signing_event, EventContext, SigningEventParams, SigningEventWire};
use igra_core::domain::EventSource;
use igra_core::infrastructure::audit;
use igra_core::infrastructure::hyperlane::{IsmMode, IsmVerifier, ProofMetadata, ValidatorSet};
use kaspa_addresses::Address;
use log::{debug, info, warn};
use secp256k1::PublicKey;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

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
            return Err(format!("merkle proof path must have length {} (got {})", TREE_DEPTH, self.path.len()));
        }
        let leaf = self.leaf.unwrap_or(message_id);
        if leaf != message_id {
            return Err("merkle proof leaf must match message_id".to_string());
        }
        let mut path = [H256::zero(); TREE_DEPTH];
        for (idx, item) in self.path.iter().enumerate() {
            path[idx] = *item;
        }
        Ok(HyperlaneProof { leaf, index: self.index, path })
    }
}

impl MailboxMetadataParams {
    fn into_core(self, message_id: H256, mode: IsmMode) -> Result<ProofMetadata, String> {
        let checkpoint = self.checkpoint.into_core();
        let merkle_proof = match (mode, self.merkle_proof) {
            (IsmMode::MerkleRootMultisig, None) => return Err("merkle_proof required for merkle_root_multisig".to_string()),
            (_, proof) => proof.map(|p| p.into_core(message_id)).transpose()?,
        };
        let signatures = self.signatures.iter().map(|sig| parse_signature_hex(sig)).collect::<Result<Vec<_>, _>>()?;
        Ok(ProofMetadata { checkpoint, merkle_proof, signatures })
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
    Ok(Signature { r: U256::from_big_endian(&r), s: U256::from_big_endian(&s), v: u64::from(bytes[64]) })
}

fn format_h256(value: H256) -> String {
    format!("0x{}", hex::encode(value.as_bytes()))
}

fn format_pubkey(key: &PublicKey) -> String {
    format!("0x{}", hex::encode(key.serialize_uncompressed()))
}

fn format_config_hash(set: &ValidatorSet) -> String {
    let mut hasher = Hasher::new();
    for pk in &set.validators {
        hasher.update(pk.serialize().as_slice());
    }
    hasher.update(&[set.threshold]);
    hasher.update(ism_mode_str(&set.mode).as_bytes());
    format!("0x{}", hex::encode(hasher.finalize().as_bytes()))
}

fn ism_mode_str(mode: &IsmMode) -> &'static str {
    match mode {
        IsmMode::MessageIdMultisig => "message_id_multisig",
        IsmMode::MerkleRootMultisig => "merkle_root_multisig",
    }
}

#[derive(Clone, Debug)]
struct SigningPayload {
    destination_address: String,
    amount_sompi: u64,
    derivation_path: String,
    derivation_index: Option<u32>,
}

fn extract_signing_payload(message: &HyperlaneMessage, default_derivation_path: &str) -> Result<SigningPayload, String> {
    let body = &message.body;
    if body.len() < 8 {
        return Err("hyperlane message body too short".to_string());
    }
    let amount_sompi = u64::from_le_bytes(body[0..8].try_into().map_err(|_| "invalid amount bytes".to_string())?);
    let rest = &body[8..];
    let recipient = String::from_utf8(rest.to_vec()).map_err(|_| "recipient must be utf8".to_string())?;

    let _ = Address::try_from(recipient.as_str()).map_err(|_| "invalid recipient address".to_string())?;

    Ok(SigningPayload {
        destination_address: recipient,
        amount_sompi,
        derivation_path: default_derivation_path.to_string(),
        derivation_index: None,
    })
}

fn metadata_to_map(meta: &ProofMetadata, mode: &IsmMode) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("hyperlane.mode".to_string(), ism_mode_str(mode).to_string());
    map.insert("hyperlane.mailbox_domain".to_string(), meta.checkpoint.checkpoint.mailbox_domain.to_string());
    map.insert(
        "hyperlane.merkle_tree_hook_address".to_string(),
        format_h256(meta.checkpoint.checkpoint.merkle_tree_hook_address),
    );
    map.insert("hyperlane.root".to_string(), format_h256(meta.checkpoint.checkpoint.root));
    map.insert("hyperlane.index".to_string(), meta.checkpoint.checkpoint.index.to_string());
    map.insert("hyperlane.message_id".to_string(), format_h256(meta.checkpoint.message_id));
    map
}

fn derive_session_id_hex(group_id_hex: Option<&str>, message_id: H256) -> String {
    let group_id_hex = match group_id_hex {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => return String::new(),
    };
    let group_bytes = match hex::decode(group_id_hex.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(_) => return String::new(),
    };
    if group_bytes.len() != 32 {
        return String::new();
    }
    let mut hasher = Hasher::new();
    hasher.update(&group_bytes);
    hasher.update(message_id.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize().as_bytes()))
}

async fn submit_signing_from_hyperlane(
    ctx: &EventContext,
    message: &HyperlaneMessage,
    metadata: &ProofMetadata,
    session_id_hex: &str,
    set: &ValidatorSet,
    coordinator_peer_id: &str,
    session_expiry_seconds: u64,
    default_derivation_path: &str,
) -> Result<bool, String> {
    let payload = extract_signing_payload(message, default_derivation_path)?;
    if payload.destination_address.trim().is_empty() || payload.amount_sompi == 0 {
        return Err("destination_address and amount_sompi are required to submit signing event".to_string());
    }
    let event_id = format_h256(message.id());
    let mut meta = metadata_to_map(metadata, &set.mode);
    meta.insert("hyperlane.quorum".to_string(), set.threshold.to_string());
    // Persist the canonical Hyperlane message fields so the core verifier can recompute `message_id`
    // (like a destination chain Mailbox would) and ensure it matches the signed checkpoint.
    meta.insert("hyperlane.msg.version".to_string(), message.version.to_string());
    meta.insert("hyperlane.msg.nonce".to_string(), message.nonce.to_string());
    meta.insert("hyperlane.msg.origin".to_string(), message.origin.to_string());
    meta.insert("hyperlane.msg.sender".to_string(), format_h256(message.sender));
    meta.insert("hyperlane.msg.destination".to_string(), message.destination.to_string());
    meta.insert("hyperlane.msg.recipient".to_string(), format_h256(message.recipient));
    meta.insert("hyperlane.msg.body_hex".to_string(), hex::encode(&message.body));

    // Forward Hyperlane ISM signatures to the core verifier. We strip the recovery id byte and
    // pass compact (r||s) signatures, concatenated, so the core verifier can validate them
    // against the checkpoint signing_hash.
    let signature = if metadata.signatures.is_empty() {
        None
    } else {
        let mut bytes = Vec::with_capacity(metadata.signatures.len().saturating_mul(64));
        for sig in &metadata.signatures {
            let sig_bytes: [u8; 65] = sig.clone().into();
            bytes.extend_from_slice(&sig_bytes[0..64]);
        }
        Some(bytes)
    };

    let signing_event = SigningEventWire {
        event_id: event_id.clone(),
        event_source: EventSource::Hyperlane { domain: message.destination.to_string(), sender: format_h256(message.sender) },
        derivation_path: payload.derivation_path,
        derivation_index: payload.derivation_index,
        destination_address: payload.destination_address,
        amount_sompi: payload.amount_sompi,
        metadata: meta,
        timestamp_nanos: audit::now_nanos(),
        signature_hex: None,
        signature,
    };
    let params = SigningEventParams {
        session_id_hex: session_id_hex.to_string(),
        request_id: event_id.clone(),
        coordinator_peer_id: coordinator_peer_id.to_string(),
        expires_at_nanos: audit::now_nanos().saturating_add(session_expiry_seconds.saturating_mul(1_000_000_000)),
        signing_event,
    };
    submit_signing_event(ctx, params).await.map_err(|e| e.to_string())?;
    Ok(true)
}

pub async fn handle_validators_and_threshold(
    state: &RpcState,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> serde_json::Value {
    debug!("rpc hyperlane.validators_and_threshold called");
    let Some(ism) = state.hyperlane_ism.as_ref() else {
        state.metrics.inc_rpc_request("hyperlane.validators_and_threshold", "error");
        debug!("hyperlane not configured");
        return json_err(id, RpcErrorCode::HyperlaneNotConfigured, "hyperlane not configured");
    };

    let params = match params {
        Some(params) => params,
        None => {
            state.metrics.inc_rpc_request("hyperlane.validators_and_threshold", "error");
            debug!("missing params");
            return json_err(id, RpcErrorCode::InvalidParams, "missing params");
        }
    };

    let params: ValidatorsAndThresholdParams = match serde_json::from_value(params) {
        Ok(params) => params,
        Err(err) => {
            state.metrics.inc_rpc_request("hyperlane.validators_and_threshold", "error");
            debug!("invalid params error={}", err);
            return json_err(id, RpcErrorCode::InvalidParams, err.to_string());
        }
    };

    let domain = params.origin_domain.unwrap_or(params.destination_domain);
    let set = match ism.validators_and_threshold(domain, params.message_id) {
        Some(set) => set,
        None => {
            state.metrics.inc_rpc_request("hyperlane.validators_and_threshold", "error");
            debug!("unknown destination domain domain={}", domain);
            return json_err(id, RpcErrorCode::UnknownDomain, "unknown destination domain");
        }
    };
    info!(
        "resolved validators and threshold domain={} threshold={} validator_count={} mode={:?}",
        domain,
        set.threshold,
        set.validators.len(),
        set.mode
    );

    let result = ValidatorsAndThresholdResult {
        domain,
        validators: set.validators.iter().map(format_pubkey).collect(),
        threshold: set.threshold,
        mode: set.mode.clone(),
        config_hash: format_config_hash(&set),
    };
    state.metrics.inc_rpc_request("hyperlane.validators_and_threshold", "ok");
    json_ok(id, result)
}

pub async fn handle_mailbox_process(state: &RpcState, id: serde_json::Value, params: Option<serde_json::Value>) -> serde_json::Value {
    debug!("rpc hyperlane.mailbox_process called");
    let Some(ism) = state.hyperlane_ism.as_ref() else {
        state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
        debug!("hyperlane not configured");
        return json_err(id, RpcErrorCode::HyperlaneNotConfigured, "hyperlane not configured");
    };

    let params = match params {
        Some(params) => params,
        None => {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            debug!("missing params");
            return json_err(id, RpcErrorCode::InvalidParams, "missing params");
        }
    };

    let params: MailboxProcessParams = match serde_json::from_value(params) {
        Ok(params) => params,
        Err(err) => {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            debug!("invalid params error={}", err);
            return json_err(id, RpcErrorCode::InvalidParams, err.to_string());
        }
    };

    let message: HyperlaneMessage = params.message.into();
    debug!(
        "parsed mailbox process message origin_domain={} destination_domain={} message_id={}",
        message.origin,
        message.destination,
        format_h256(message.id())
    );
    let Some(set) = ism.validators_and_threshold(message.origin, message.id()) else {
        state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
        debug!("unknown destination domain origin_domain={}", message.origin);
        return json_err(id, RpcErrorCode::UnknownDomain, "unknown destination domain");
    };
    let mode = params.mode.unwrap_or(set.mode.clone());
    debug!(
        "selected ism mode mode={:?} threshold={} validator_count={}",
        mode,
        set.threshold,
        set.validators.len()
    );
    let metadata = match params.metadata.into_core(message.id(), mode.clone()) {
        Ok(meta) => meta,
        Err(err) => {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            debug!("invalid mailbox metadata error={}", err);
            return json_err(id, RpcErrorCode::InvalidParams, err);
        }
    };

    match ism.verify_proof(&message, &metadata, mode.clone()) {
        Ok(report) => {
            debug!(
                "hyperlane proof verified message_id={} root={} quorum={} validators_used={}",
                format_h256(report.message_id),
                format_h256(report.root),
                report.quorum,
                report.validators_used.len()
            );
            let session_id = derive_session_id_hex(state.group_id_hex.as_deref(), report.message_id);
            if session_id.is_empty() {
                state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
                debug!("missing or invalid group_id for session derivation");
                return json_err(id, RpcErrorCode::MissingGroupId, "missing or invalid group_id for session derivation");
            }
            let signing_submitted = match submit_signing_from_hyperlane(
                &state.event_ctx,
                &message,
                &metadata,
                &session_id,
                &set,
                &state.coordinator_peer_id,
                state.session_expiry_seconds,
                &state.hyperlane_default_derivation_path,
            )
            .await
            {
                Ok(flag) => flag,
                Err(err) => {
                    state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
                    // Log validation errors at debug to avoid spam from repeated requests
                    // Real errors (RPC failures, storage errors) stay at warn
                    let is_validation_error = err.contains("invalid recipient")
                        || err.contains("destination_address")
                        || err.contains("amount_sompi")
                        || err.contains("body too short")
                        || err.contains("event already processed");
                    if is_validation_error {
                        debug!("hyperlane signing event rejected message_id={} error={}", format_h256(message.id()), err);
                    } else {
                        warn!(
                            "failed to submit signing event from hyperlane message_id={} session_id={} error={}",
                            format_h256(message.id()),
                            session_id,
                            err
                        );
                    }
                    return json_err(id, RpcErrorCode::SigningFailed, err);
                }
            };
            info!(
                "hyperlane signing event submitted session_id={} signing_submitted={}",
                session_id, signing_submitted
            );

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
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "ok");
            json_ok(id, result)
        }
        Err(err) => {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            warn!(
                "hyperlane proof verification failed message_id={} origin_domain={} destination_domain={} error={}",
                format_h256(message.id()),
                message.origin,
                message.destination,
                err
            );
            json_err(id, RpcErrorCode::InternalError, err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::metrics::Metrics;
    use async_trait::async_trait;
    use igra_core::application::{EventContext, EventProcessor};
    use igra_core::domain::validation::NoopVerifier;
    use igra_core::domain::SigningEvent;
    use igra_core::foundation::{Hash32, PeerId, RequestId, SessionId};
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::ThresholdError;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct NoopProcessor;

    #[async_trait]
    impl EventProcessor for NoopProcessor {
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

    fn dummy_state() -> RpcState {
        let temp_dir = TempDir::new().expect("temp dir");
        let dir_path = temp_dir.into_path();
        let storage = Arc::new(RocksStorage::open_in_dir(&dir_path).expect("storage"));
        let ctx = EventContext {
            processor: Arc::new(NoopProcessor),
            config: ServiceConfig::default(),
            message_verifier: Arc::new(NoopVerifier),
            storage,
        };
        RpcState {
            event_ctx: ctx,
            rpc_token: None,
            node_rpc_url: "grpc://127.0.0.1:16110".to_string(),
            metrics: Arc::new(Metrics::new().expect("metrics")),
            rate_limiter: Arc::new(crate::api::RateLimiter::new()),
            hyperlane_ism: None,
            group_id_hex: None,
            coordinator_peer_id: "test-peer".to_string(),
            hyperlane_default_derivation_path: "m/45h/111111h/0h/0/0".to_string(),
            rate_limit_rps: 30,
            rate_limit_burst: 60,
            session_expiry_seconds: 600,
        }
    }

    #[tokio::test]
    async fn hyperlane_methods_error_when_not_configured() {
        let state = dummy_state();
        let value = handle_validators_and_threshold(&state, serde_json::json!(1), Some(serde_json::json!({}))).await;
        assert_eq!(value["error"]["code"], RpcErrorCode::HyperlaneNotConfigured as i64);
    }
}
