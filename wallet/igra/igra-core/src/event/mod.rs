// Shared ingestion pipeline for event providers (JSON-RPC, file watcher, etc.).
use crate::audit::{audit, AuditEvent};
use crate::coordination::hashes::event_hash;
use crate::error::ThresholdError;
use crate::hd::derivation_path_from_index;
use crate::model::{EventSource, Hash32, SigningEvent};
use crate::storage::Storage;
use crate::types::{PeerId, RequestId, SessionId};
use crate::validation::{MessageVerifier, ValidationSource};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

#[async_trait]
pub trait EventProcessor: Send + Sync {
    async fn handle_signing_event(
        &self,
        config: &crate::config::ServiceConfig,
        session_id: SessionId,
        request_id: RequestId,
        signing_event: SigningEvent,
        expires_at_nanos: u64,
        coordinator_peer_id: PeerId,
    ) -> Result<Hash32, ThresholdError>;
}

#[derive(Clone)]
pub struct EventContext {
    pub processor: Arc<dyn EventProcessor>,
    pub config: crate::config::ServiceConfig,
    pub message_verifier: Arc<dyn MessageVerifier>,
    pub storage: Arc<dyn Storage>,
}

#[derive(Debug, Deserialize)]
pub struct SigningEventParams {
    pub session_id_hex: String,
    pub request_id: String,
    pub coordinator_peer_id: String,
    pub expires_at_nanos: u64,
    pub signing_event: SigningEventWire,
}

#[derive(Debug, Serialize)]
pub struct SigningEventResult {
    pub session_id_hex: String,
    pub event_hash_hex: String,
    pub validation_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct SigningEventWire {
    pub event_id: String,
    pub event_source: EventSource,
    pub derivation_path: String,
    pub derivation_index: Option<u32>,
    pub destination_address: String,
    pub amount_sompi: u64,
    pub metadata: std::collections::BTreeMap<String, String>,
    pub timestamp_nanos: u64,
    pub signature_hex: Option<String>,
    pub signature: Option<Vec<u8>>,
}

pub async fn submit_signing_event(ctx: &EventContext, params: SigningEventParams) -> Result<SigningEventResult, ThresholdError> {
    let session_id = SessionId::from(decode_hash32(&params.session_id_hex)?);
    let signing_event = params.signing_event.into_signing_event()?;
    let event_hash = event_hash(&signing_event)?;
    crate::audit_event_received!(event_hash, signing_event);
    info!(
        request_id = %params.request_id,
        event_id = %signing_event.event_id,
        "signing event received"
    );

    let report = ctx.message_verifier.report_for(&signing_event);
    if let Err(err) = ctx.message_verifier.verify(&signing_event) {
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
            audit(AuditEvent::EventSignatureValidated {
                event_hash: hex::encode(event_hash),
                validator_count: report.validator_count,
                valid: false,
                reason: Some(err.to_string()),
                timestamp_ns: crate::audit::now_nanos(),
            });
        }
        return Err(err);
    }
    if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
        audit(AuditEvent::EventSignatureValidated {
            event_hash: hex::encode(event_hash),
            validator_count: report.validator_count,
            valid: true,
            reason: None,
            timestamp_ns: crate::audit::now_nanos(),
        });
    }
    if ctx.storage.get_event(&event_hash)?.is_some() {
        return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
    }
    ctx.storage.insert_event(event_hash, signing_event.clone())?;
    debug!(event_hash = %hex::encode(event_hash), "signing event stored");
    let validation_hash = ctx
        .processor
        .handle_signing_event(
            &ctx.config,
            session_id,
            RequestId::from(params.request_id),
            signing_event.clone(),
            params.expires_at_nanos,
            PeerId::from(params.coordinator_peer_id),
        )
        .await?;
    Ok(SigningEventResult {
        session_id_hex: hex::encode(session_id.as_hash()),
        event_hash_hex: hex::encode(event_hash),
        validation_hash_hex: hex::encode(validation_hash),
    })
}

fn decode_hash32(value: &str) -> Result<Hash32, ThresholdError> {
    let bytes = hex::decode(value.trim()).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ThresholdError::Message("expected 32-byte hex value".to_string()))?;
    Ok(array)
}

impl SigningEventWire {
    fn into_signing_event(self) -> Result<SigningEvent, ThresholdError> {
        let derivation_path = resolve_derivation_path(&self.derivation_path, self.derivation_index)?;
        let signature = if let Some(hex_value) = self.signature_hex {
            let bytes = hex::decode(hex_value.trim()).map_err(|err| ThresholdError::Message(err.to_string()))?;
            Some(bytes)
        } else {
            self.signature
        };
        Ok(SigningEvent {
            event_id: self.event_id,
            event_source: self.event_source,
            derivation_path,
            derivation_index: self.derivation_index,
            destination_address: self.destination_address,
            amount_sompi: self.amount_sompi,
            metadata: self.metadata,
            timestamp_nanos: self.timestamp_nanos,
            signature,
        })
    }
}

fn resolve_derivation_path(path: &str, index: Option<u32>) -> Result<String, ThresholdError> {
    let trimmed = path.trim();
    if let Some(index) = index {
        let expected = derivation_path_from_index(index);
        if trimmed.is_empty() {
            return Ok(expected);
        }
        if trimmed != expected {
            return Err(ThresholdError::Message(
                "derivation_path does not match derivation_index".to_string(),
            ));
        }
        return Ok(expected);
    }
    if trimmed.is_empty() {
        return Err(ThresholdError::Message(
            "missing derivation_path (or derivation_index)".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}
