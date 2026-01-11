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
use log::{debug, info, trace, warn};
use std::sync::Arc;

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
        "decoded signing event ids session_id={} request_id={} coordinator_peer_id={}",
        hex::encode(session_id.as_hash()),
        request_id,
        coordinator_peer_id
    );
    let parsed = params.signing_event.into_signing_event()?;
    debug!(
        "signing event parsed event_id={} derivation_source={:?} signature_source={:?}",
        parsed.event.event_id, parsed.derivation_path_source, parsed.signature_source
    );
    let signing_event = parsed.event;
    trace!("signing event details signing_event={:?}", signing_event);
    let event_hash = event_hash(&signing_event)?;
    debug!("computed signing event hash event_hash={}", hex::encode(event_hash));
    crate::audit_event_received!(event_hash, signing_event);
    info!("signing event received request_id={} event_id={}", params.request_id, signing_event.event_id);

    let report = ctx.message_verifier.verify(&signing_event)?;
    if report.valid {
        info!(
            "message verification passed source={:?} validator_count={} valid_signatures={} threshold={}",
            report.source, report.validator_count, report.valid_signatures, report.threshold_required
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
            "message verification failed source={:?} validator_count={} valid_signatures={} threshold={} failure={:?}",
            report.source, report.validator_count, report.valid_signatures, report.threshold_required, report.failure_reason
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
        warn!("event replayed event_hash={}", hex::encode(event_hash));
        return Err(ThresholdError::EventReplayed(hex::encode(event_hash)));
    }
    ctx.storage.insert_event(event_hash, signing_event.clone())?;
    debug!("signing event stored event_hash={}", hex::encode(event_hash));
    debug!(
        "dispatching to event processor session_id={} request_id={}",
        hex::encode(session_id.as_hash()),
        request_id
    );
    let validation_hash = ctx
        .processor
        .handle_signing_event(&ctx.config, session_id, request_id, signing_event, params.expires_at_nanos, coordinator_peer_id)
        .await?;
    info!("signing event processed validation_hash={}", hex::encode(validation_hash));

    Ok(SigningEventResult {
        session_id_hex: params.session_id_hex,
        event_hash_hex: hex::encode(event_hash),
        validation_hash_hex: hex::encode(validation_hash),
    })
}
