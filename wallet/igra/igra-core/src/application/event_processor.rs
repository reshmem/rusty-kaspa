// Shared ingestion pipeline for event providers (JSON-RPC, file watcher, etc.).
use crate::domain::event::decode_session_and_request_ids;
use crate::domain::hashes::event_hash;
use crate::domain::validation::{MessageVerifier, ValidationSource};
use crate::domain::SigningEvent;
use crate::foundation::Hash32;
use crate::foundation::{PeerId, RequestId, SessionId, ThresholdError};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::config::ServiceConfig;
use crate::infrastructure::storage::Storage;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

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
    debug!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        coordinator_peer_id = %coordinator_peer_id,
        "decoded signing event ids"
    );
    let parsed = params.signing_event.into_signing_event()?;
    debug!(
        event_id = %parsed.event.event_id,
        derivation_source = ?parsed.derivation_path_source,
        signature_source = ?parsed.signature_source,
        "signing event parsed"
    );
    let signing_event = parsed.event;
    trace!(signing_event = ?signing_event, "signing event details");
    let event_hash = event_hash(&signing_event)?;
    debug!(event_hash = %hex::encode(event_hash), "computed signing event hash");
    crate::audit_event_received!(event_hash, signing_event);
    info!(
        request_id = %params.request_id,
        event_id = %signing_event.event_id,
        "signing event received"
    );

    let report = ctx.message_verifier.verify(&signing_event)?;
    if report.valid {
        info!(
            source = ?report.source,
            validator_count = report.validator_count,
            valid_signatures = report.valid_signatures,
            threshold = report.threshold_required,
            "message verification passed"
        );
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
            audit(AuditEvent::EventSignatureValidated {
                event_hash: hex::encode(event_hash),
                validator_count: report.validator_count,
                valid: true,
                reason: None,
                timestamp_ns: crate::infrastructure::audit::now_nanos(),
            });
        }
    } else {
        warn!(
            source = ?report.source,
            validator_count = report.validator_count,
            valid_signatures = report.valid_signatures,
            threshold = report.threshold_required,
            failure = ?report.failure_reason,
            "message verification failed"
        );
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) {
            audit(AuditEvent::EventSignatureValidated {
                event_hash: hex::encode(event_hash),
                validator_count: report.validator_count,
                valid: false,
                reason: report.failure_reason.clone(),
                timestamp_ns: crate::infrastructure::audit::now_nanos(),
            });
        }
        if matches!(report.source, ValidationSource::Hyperlane | ValidationSource::LayerZero) && report.validator_count == 0 {
            let message = match report.source {
                ValidationSource::Hyperlane => "no hyperlane validators configured",
                ValidationSource::LayerZero => "no layerzero endpoint pubkeys configured",
                ValidationSource::None => "no validators configured",
            };
            return Err(ThresholdError::ConfigError(message.to_string()));
        }
        return Err(ThresholdError::EventSignatureInvalid);
    }
    if ctx.storage.get_event(&event_hash)?.is_some() {
        warn!(event_hash = %hex::encode(event_hash), "event replayed");
        return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
    }
    ctx.storage.insert_event(event_hash, signing_event.clone())?;
    debug!(event_hash = %hex::encode(event_hash), "signing event stored");
    debug!(
        session_id = %hex::encode(session_id.as_hash()),
        request_id = %request_id,
        "dispatching to event processor"
    );
    let validation_hash = ctx
        .processor
        .handle_signing_event(&ctx.config, session_id, request_id, signing_event, params.expires_at_nanos, coordinator_peer_id)
        .await?;
    info!(validation_hash = %hex::encode(validation_hash), "signing event processed");

    Ok(SigningEventResult {
        session_id_hex: params.session_id_hex,
        event_hash_hex: hex::encode(event_hash),
        validation_hash_hex: hex::encode(validation_hash),
    })
}
