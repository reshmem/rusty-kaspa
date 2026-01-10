// Shared ingestion pipeline for event providers (JSON-RPC, file watcher, etc.).
use crate::domain::event::decode_session_and_request_ids;
use crate::domain::hashes::event_hash;
use crate::domain::validation::{MessageVerifier, ValidationSource};
use crate::foundation::{PeerId, RequestId, SessionId, ThresholdError};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::config::ServiceConfig;
use crate::infrastructure::storage::Storage;
use crate::domain::SigningEvent;
use crate::foundation::Hash32;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info};

pub use crate::domain::event::{SigningEventParams, SigningEventResult, SigningEventWire};

#[async_trait]
pub trait EventProcessor: Send + Sync {
    async fn handle_signing_event(
        &self,
        config: &ServiceConfig,
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
    pub config: ServiceConfig,
    pub message_verifier: Arc<dyn MessageVerifier>,
    pub storage: Arc<dyn Storage>,
}

pub async fn submit_signing_event(ctx: &EventContext, params: SigningEventParams) -> Result<SigningEventResult, ThresholdError> {
    let (session_id, request_id, coordinator_peer_id) = decode_session_and_request_ids(&params)?;
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
                timestamp_ns: crate::infrastructure::audit::now_nanos(),
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
            timestamp_ns: crate::infrastructure::audit::now_nanos(),
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
            request_id,
            signing_event,
            params.expires_at_nanos,
            coordinator_peer_id,
        )
        .await?;

    Ok(SigningEventResult {
        session_id_hex: params.session_id_hex,
        event_hash_hex: hex::encode(event_hash),
        validation_hash_hex: hex::encode(validation_hash),
    })
}
