//! Hyperlane destination integration endpoints (JSON-RPC).
//!
//! This handler implements the minimal Hyperlane Mailbox/ISM-facing API surface that the
//! relayer/validator components expect (e.g. `validators_and_threshold`, `mailbox_process`).
//!
//! Key responsibilities:
//! - Enforce request size/UTF-8 limits to avoid DoS.
//! - Convert Hyperlane metadata into `source_data` using `MetadataKey` (typed keys).
//! - Forward verified signing requests into the core signing pipeline.

use super::hyperlane_wire::RpcHyperlaneMessage;
use super::types::{json_err, json_ok, RpcErrorCode};
use crate::api::state::RpcState;
use alloy::primitives::keccak256;
use blake3::Hasher;
use hyperlane_core::accumulator::{merkle::Proof as HyperlaneProof, TREE_DEPTH};
use hyperlane_core::{Checkpoint, CheckpointWithMessageId, HyperlaneMessage, Signature, H256, U256};
use igra_core::application::SourceType;
use igra_core::application::{submit_signing_event, EventContext, SigningEventParams, SigningEventResult, SigningEventWire};
use igra_core::foundation::util::hex_fmt::hx;
use igra_core::foundation::{MetadataKey, ThresholdError, MAX_HYPERLANE_BODY_SIZE_BYTES};
use igra_core::infrastructure::hyperlane::{decode_proof_metadata_hex, IsmMode, IsmVerifier, ProofMetadata, ValidatorSet};
use kaspa_addresses::Address;
use log::{debug, info, warn};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const DEFAULT_PROCESS_GAS_USED: &str = "100000";
const HYPERLANE_RECIPIENT_TAG_V1: &str = "igra:v1:";

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
struct MailboxProcessParams {
    pub message: RpcHyperlaneMessage,
    pub metadata: MailboxMetadataParam,
    #[serde(default)]
    pub mode: Option<IsmMode>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MailboxMetadataParam {
    Hex(String),
    Structured(MailboxMetadataParams),
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
struct ProcessMessageResponse {
    pub transaction_id: String,
    pub transaction_hash: String,
    pub gas_used: Option<String>,
    pub success: bool,
    pub error: Option<String>,
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
        let signatures = self
            .signatures
            .iter()
            .map(|value| {
                let bytes = igra_core::foundation::parse_hex_fixed::<65>(value).map_err(|err| err.to_string())?;
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&bytes[0..32]);
                s.copy_from_slice(&bytes[32..64]);
                Ok(Signature { r: U256::from_big_endian(&r), s: U256::from_big_endian(&s), v: u64::from(bytes[64]) })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(ProofMetadata { checkpoint, merkle_proof, signatures })
    }
}

fn format_h256(value: H256) -> String {
    format!("{:#x}", hx(value.as_bytes()))
}

fn pubkey_to_evm_address_h256(key: &PublicKey) -> [u8; 32] {
    let uncompressed = key.serialize_uncompressed();
    let digest = alloy::primitives::keccak256(&uncompressed[1..]);
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&digest.as_slice()[12..]);
    out
}

fn format_validator_address(key: &PublicKey) -> String {
    format!("{:#x}", hx(&pubkey_to_evm_address_h256(key)))
}

fn format_config_hash(set: &ValidatorSet) -> String {
    let mut hasher = Hasher::new();
    for pk in &set.validators {
        hasher.update(&pubkey_to_evm_address_h256(pk)[12..]);
    }
    hasher.update(&[set.threshold]);
    hasher.update(ism_mode_str(&set.mode).as_bytes());
    format!("{:#x}", hx(hasher.finalize().as_bytes()))
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
}

fn extract_signing_payload(message: &HyperlaneMessage) -> Result<SigningPayload, ThresholdError> {
    let body = &message.body;
    if body.len() > MAX_HYPERLANE_BODY_SIZE_BYTES {
        return Err(ThresholdError::HyperlaneBodyTooLarge { size: body.len(), max: MAX_HYPERLANE_BODY_SIZE_BYTES });
    }

    if body.len() < 8 {
        return Err(ThresholdError::HyperlaneMetadataParseError {
            details: "hyperlane message body too short".to_string(),
            source: None,
        });
    }
    let amount_bytes: [u8; 8] = body[0..8].try_into().map_err(|err| ThresholdError::HyperlaneMetadataParseError {
        details: format!("invalid amount bytes: {}", err),
        source: None,
    })?;
    let amount_sompi = u64::from_le_bytes(amount_bytes);

    let recipient_str = std::str::from_utf8(&body[8..])
        .map_err(|err| ThresholdError::HyperlaneInvalidUtf8 { position: err.valid_up_to(), source: Some(Box::new(err)) })?;
    let destination_address = recipient_str.to_string();

    Address::try_from(destination_address.as_str()).map_err(|err| ThresholdError::HyperlaneMetadataParseError {
        details: format!("invalid recipient address: {}", err),
        source: None,
    })?;

    // Enforce that Hyperlane `recipientAddress` (bytes32) matches our canonical tag-hash derivation
    // from the Kaspa address string carried in the message body.
    let mut preimage = Vec::with_capacity(HYPERLANE_RECIPIENT_TAG_V1.len() + destination_address.len());
    preimage.extend_from_slice(HYPERLANE_RECIPIENT_TAG_V1.as_bytes());
    preimage.extend_from_slice(destination_address.as_bytes());
    let digest = keccak256(preimage);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(digest.as_slice());
    let expected = H256::from(expected);
    if expected != message.recipient {
        return Err(ThresholdError::HyperlaneMetadataParseError {
            details: format!(
                "hyperlane recipientAddress mismatch expected={} got={}",
                format_h256(expected),
                format_h256(message.recipient)
            ),
            source: None,
        });
    }

    Ok(SigningPayload { destination_address, amount_sompi })
}

fn metadata_to_map(meta: &ProofMetadata, mode: &IsmMode) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(MetadataKey::HyperlaneMode.to_string(), ism_mode_str(mode).to_string());
    map.insert(MetadataKey::HyperlaneMailboxDomain.to_string(), meta.checkpoint.checkpoint.mailbox_domain.to_string());
    map.insert(
        MetadataKey::HyperlaneMerkleTreeHookAddress.to_string(),
        format_h256(meta.checkpoint.checkpoint.merkle_tree_hook_address),
    );
    map.insert(MetadataKey::HyperlaneRoot.to_string(), format_h256(meta.checkpoint.checkpoint.root));
    map.insert(MetadataKey::HyperlaneIndex.to_string(), meta.checkpoint.checkpoint.index.to_string());
    map.insert(MetadataKey::HyperlaneMessageId.to_string(), format_h256(meta.checkpoint.message_id));
    map
}

fn derive_session_id_hex(group_id_hex: Option<&str>, message_id: H256) -> String {
    let group_id_hex = match group_id_hex {
        Some(value) if !value.trim().is_empty() => value.trim(),
        _ => return String::new(),
    };
    let group_bytes = match igra_core::foundation::parse_hex_32bytes(group_id_hex) {
        Ok(bytes) => bytes,
        Err(_) => return String::new(),
    };
    let mut hasher = Hasher::new();
    hasher.update(&group_bytes);
    hasher.update(message_id.as_bytes());
    format!("{:#x}", hx(hasher.finalize().as_bytes()))
}

async fn submit_signing_from_hyperlane(
    ctx: &EventContext,
    message: &HyperlaneMessage,
    metadata: &ProofMetadata,
    session_id_hex: &str,
    set: &ValidatorSet,
    coordinator_peer_id: &str,
    session_expiry_seconds: u64,
    external_request_id: Option<String>,
) -> Result<SigningEventResult, ThresholdError> {
    let payload = extract_signing_payload(message)?;
    if payload.destination_address.trim().is_empty() || payload.amount_sompi == 0 {
        return Err(ThresholdError::MissingSigningPayload { message_id: format_h256(message.id()) });
    }
    let external_id = format_h256(message.id());
    let mut meta = metadata_to_map(metadata, &set.mode);
    meta.insert(MetadataKey::HyperlaneQuorum.to_string(), set.threshold.to_string());
    // Persist the canonical Hyperlane message fields so the core verifier can recompute `message_id`
    // (like a destination chain Mailbox would) and ensure it matches the signed checkpoint.
    meta.insert(MetadataKey::HyperlaneMsgVersion.to_string(), message.version.to_string());
    meta.insert(MetadataKey::HyperlaneMsgNonce.to_string(), message.nonce.to_string());
    meta.insert(MetadataKey::HyperlaneMsgOrigin.to_string(), message.origin.to_string());
    meta.insert(MetadataKey::HyperlaneMsgSender.to_string(), format_h256(message.sender));
    meta.insert(MetadataKey::HyperlaneMsgDestination.to_string(), message.destination.to_string());
    meta.insert(MetadataKey::HyperlaneMsgRecipient.to_string(), format_h256(message.recipient));
    meta.insert(MetadataKey::HyperlaneMsgBodyHex.to_string(), format!("{}", hx(&message.body)));

    // Forward Hyperlane ISM signatures to the core verifier. We strip the recovery id byte and
    // pass compact (r||s) signatures, concatenated, so the core verifier can validate them
    // against the checkpoint signing_hash.
    let signature = if metadata.signatures.is_empty() {
        None
    } else {
        let mut bytes = Vec::with_capacity(metadata.signatures.len().saturating_mul(64));
        for sig in &metadata.signatures {
            let sig_bytes: [u8; 65] = (*sig).into();
            bytes.extend_from_slice(&sig_bytes[0..64]);
        }
        Some(bytes)
    };

    let signing_event = SigningEventWire {
        external_id: external_id.clone(),
        source: SourceType::Hyperlane { origin_domain: message.origin },
        destination_address: payload.destination_address,
        amount_sompi: payload.amount_sompi,
        metadata: meta,
        proof_hex: None,
        proof: signature,
    };
    let params = SigningEventParams {
        session_id_hex: session_id_hex.to_string(),
        external_request_id,
        coordinator_peer_id: coordinator_peer_id.to_string(),
        expires_at_nanos: igra_core::foundation::now_nanos().saturating_add(session_expiry_seconds.saturating_mul(1_000_000_000)),
        event: signing_event,
    };
    submit_signing_event(ctx, params).await
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
    debug!(
        "resolved validators and threshold domain={} threshold={} validator_count={} mode={}",
        domain,
        set.threshold,
        set.validators.len(),
        ism_mode_str(&set.mode)
    );

    let result = ValidatorsAndThresholdResult {
        domain,
        validators: set.validators.iter().map(format_validator_address).collect(),
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
    debug!("selected ism mode mode={} threshold={} validator_count={}", ism_mode_str(&mode), set.threshold, set.validators.len());
    let message_id = message.id();
    let message_id = {
        let bytes = message_id.as_bytes();
        if bytes.len() != 32 {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            return json_ok(
                id,
                ProcessMessageResponse {
                    transaction_id: String::new(),
                    transaction_hash: String::new(),
                    gas_used: None,
                    success: false,
                    error: Some(format!("invalid message_id length {}", bytes.len())),
                },
            );
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        igra_core::foundation::ExternalId::from(out)
    };

    // Fast-path idempotency: if already delivered, return success with known tx id.
    match state.event_ctx.storage.hyperlane_get_delivery(&message_id) {
        Ok(Some(delivery)) => {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "ok");
            return json_ok(
                id,
                ProcessMessageResponse {
                    transaction_id: format!("0x{}", delivery.tx_id),
                    transaction_hash: format!("0x{}", delivery.tx_id),
                    gas_used: None,
                    success: true,
                    error: None,
                },
            );
        }
        Ok(None) => {}
        Err(err) => {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            return json_ok(
                id,
                ProcessMessageResponse {
                    transaction_id: String::new(),
                    transaction_hash: String::new(),
                    gas_used: None,
                    success: false,
                    error: Some(err.to_string()),
                },
            );
        }
    };

    let metadata = match params.metadata {
        MailboxMetadataParam::Hex(hex_value) => match decode_proof_metadata_hex(mode.clone(), &message, &hex_value) {
            Ok(meta) => meta,
            Err(err) => {
                state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
                debug!("invalid mailbox metadata hex error={}", err);
                return json_ok(
                    id,
                    ProcessMessageResponse {
                        transaction_id: String::new(),
                        transaction_hash: String::new(),
                        gas_used: None,
                        success: false,
                        error: Some(err.to_string()),
                    },
                );
            }
        },
        MailboxMetadataParam::Structured(params) => match params.into_core(message.id(), mode.clone()) {
            Ok(meta) => meta,
            Err(err) => {
                state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
                debug!("invalid mailbox metadata error={}", err);
                return json_err(id, RpcErrorCode::InvalidParams, err);
            }
        },
    };

    let message_id_h256 = message.id();
    let report = match ism.verify_proof(&message, &metadata, mode.clone()) {
        Ok(report) => report,
        Err(err) => {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            warn!(
                "hyperlane proof verification failed message_id={} origin_domain={} destination_domain={} error={}",
                format_h256(message_id_h256),
                message.origin,
                message.destination,
                err
            );
            return json_ok(
                id,
                ProcessMessageResponse {
                    transaction_id: String::new(),
                    transaction_hash: String::new(),
                    gas_used: None,
                    success: false,
                    error: Some(err),
                },
            );
        }
    };
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

    let submit_result = submit_signing_from_hyperlane(
        &state.event_ctx,
        &message,
        &metadata,
        &session_id,
        &set,
        &state.coordinator_peer_id,
        state.session_expiry_seconds,
        Some(format_h256(report.message_id)),
    )
    .await;

    match submit_result {
        Ok(signing_submitted) => {
            state.metrics.inc_submitted_event("hyperlane");
            info!(
                "hyperlane signing event submitted session_id={} event_id={} tx_template_hash={}",
                session_id, signing_submitted.event_id_hex, signing_submitted.tx_template_hash_hex
            );
        }
        Err(err) => {
            let err_string = err.to_string();
            let is_validation_error = err_string.contains("invalid recipient")
                || err_string.contains("destination_address")
                || err_string.contains("amount_sompi")
                || err_string.contains("body too short")
                || err_string.contains("event already processed");
            if is_validation_error {
                debug!("hyperlane signing event rejected message_id={} error={}", format_h256(message_id_h256), err_string);
            } else {
                warn!(
                    "failed to submit signing event from hyperlane message_id={} session_id={} error={}",
                    format_h256(message_id_h256),
                    session_id,
                    err_string
                );
            }
            // If already completed, we still might be able to return the tx id via the delivery index.
            if matches!(err, ThresholdError::EventReplayed(_)) {
                debug!(
                    "hyperlane mailbox_process observed EventReplayed; waiting for delivery index message_id={}",
                    format_h256(message_id_h256)
                );
            } else {
                state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
                return json_ok(
                    id,
                    ProcessMessageResponse {
                        transaction_id: String::new(),
                        transaction_hash: String::new(),
                        gas_used: None,
                        success: false,
                        error: Some(err_string),
                    },
                );
            }
        }
    }

    // Wait for CRDT completion to propagate and be indexed as a Hyperlane delivery record.
    const POLL_INTERVAL_MS: u64 = 250;
    let wait_seconds = state.hyperlane_mailbox_wait_seconds.max(1);
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    loop {
        match state.event_ctx.storage.hyperlane_get_delivery(&message_id) {
            Ok(Some(delivery)) => {
                state.metrics.inc_rpc_request("hyperlane.mailbox_process", "ok");
                return json_ok(
                    id,
                    ProcessMessageResponse {
                        transaction_id: format!("0x{}", delivery.tx_id),
                        transaction_hash: format!("0x{}", delivery.tx_id),
                        gas_used: Some(DEFAULT_PROCESS_GAS_USED.to_string()),
                        success: true,
                        error: None,
                    },
                );
            }
            Ok(None) => {}
            Err(err) => {
                state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
                return json_ok(
                    id,
                    ProcessMessageResponse {
                        transaction_id: String::new(),
                        transaction_hash: String::new(),
                        gas_used: None,
                        success: false,
                        error: Some(err.to_string()),
                    },
                );
            }
        }
        if Instant::now() >= deadline {
            state.metrics.inc_rpc_request("hyperlane.mailbox_process", "error");
            return json_ok(
                id,
                ProcessMessageResponse {
                    transaction_id: String::new(),
                    transaction_hash: String::new(),
                    gas_used: None,
                    success: false,
                    error: Some("pending: signing ceremony not completed yet".to_string()),
                },
            );
        }
        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::metrics::Metrics;
    use async_trait::async_trait;
    use futures_util::stream;
    use igra_core::application::validation::NoopVerifier;
    use igra_core::application::EventContext;
    use igra_core::application::{GroupPolicy, TwoPhaseConfig};
    use igra_core::foundation::{GroupId, PeerId, ThresholdError};
    use igra_core::infrastructure::config::ServiceConfig;
    use igra_core::infrastructure::keys::{LocalKeyManager, NoopAuditLogger, SecretBytes, SecretName, SecretStore};
    use igra_core::infrastructure::rpc::KaspaGrpcQueryClient;
    use igra_core::infrastructure::rpc::UnimplementedRpc;
    use igra_core::infrastructure::storage::phase::PhaseStorage;
    use igra_core::infrastructure::storage::RocksStorage;
    use igra_core::infrastructure::transport::iroh::traits::{StateSyncRequest, StateSyncResponse, Transport, TransportSubscription};
    use std::sync::Arc;
    use tempfile::TempDir;

    struct NoopTransport;
    struct EmptySecretStore;

    impl SecretStore for EmptySecretStore {
        fn backend(&self) -> &'static str {
            "empty"
        }

        fn get<'a>(
            &'a self,
            name: &'a SecretName,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
            Box::pin(async move { Err(ThresholdError::secret_not_found(name.as_str(), "empty")) })
        }

        fn list_secrets<'a>(
            &'a self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    #[async_trait]
    impl Transport for NoopTransport {
        async fn publish_event_state(
            &self,
            _broadcast: igra_core::infrastructure::transport::iroh::traits::EventStateBroadcast,
        ) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_proposal(&self, _proposal: igra_core::application::ProposalBroadcast) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_state_sync_request(&self, _request: StateSyncRequest) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn publish_state_sync_response(&self, _response: StateSyncResponse) -> Result<(), ThresholdError> {
            Ok(())
        }

        async fn subscribe_group(&self, _group_id: GroupId) -> Result<TransportSubscription, ThresholdError> {
            Ok(TransportSubscription::new(Box::pin(stream::empty())))
        }
    }

    fn dummy_state() -> RpcState {
        let temp_dir = TempDir::new().expect("temp dir");
        let dir_path = temp_dir.into_path();
        let storage = Arc::new(RocksStorage::open_in_dir(&dir_path).expect("storage"));
        let phase_storage: Arc<dyn PhaseStorage> = storage.clone();
        let key_audit_log = Arc::new(NoopAuditLogger);
        let key_manager = Arc::new(LocalKeyManager::new(Arc::new(EmptySecretStore), key_audit_log.clone()));
        let ctx = EventContext {
            config: ServiceConfig::default(),
            policy: GroupPolicy::default(),
            two_phase: TwoPhaseConfig::default(),
            local_peer_id: PeerId::from("test-peer"),
            message_verifier: Arc::new(NoopVerifier),
            storage,
            phase_storage,
            transport: Arc::new(NoopTransport),
            rpc: Arc::new(UnimplementedRpc::new()),
            key_manager,
            key_audit_log,
        };
        RpcState {
            event_ctx: ctx,
            rpc_token: None,
            node_rpc_url: "grpc://127.0.0.1:16110".to_string(),
            kaspa_query: Arc::new(KaspaGrpcQueryClient::unimplemented()),
            metrics: Arc::new(Metrics::new().expect("metrics")),
            rate_limiter: Arc::new(crate::api::RateLimiter::new()),
            hyperlane_ism: None,
            group_id_hex: None,
            coordinator_peer_id: "test-peer".to_string(),
            rate_limit_rps: 30,
            rate_limit_burst: 60,
            session_expiry_seconds: 600,
            hyperlane_mailbox_wait_seconds: 10,
        }
    }

    #[tokio::test]
    async fn hyperlane_methods_error_when_not_configured() {
        let state = dummy_state();
        let value = handle_validators_and_threshold(&state, serde_json::json!(1), Some(serde_json::json!({}))).await;
        assert_eq!(value["error"]["code"], RpcErrorCode::HyperlaneNotConfigured as i64);
    }

    #[test]
    fn extract_signing_payload_rejects_oversized_body() {
        let message = HyperlaneMessage {
            version: 0,
            nonce: 0,
            origin: 1,
            sender: H256::zero(),
            destination: 2,
            recipient: H256::zero(),
            body: vec![0u8; MAX_HYPERLANE_BODY_SIZE_BYTES.saturating_add(1)],
        };

        let err = extract_signing_payload(&message).expect_err("oversized body rejected");
        assert!(matches!(err, ThresholdError::HyperlaneBodyTooLarge { .. }));
    }
}
