use log::{debug, info, trace, warn};
use std::sync::{Arc, Mutex, OnceLock};

pub use crate::domain::audit::types::{AuditEvent, PolicyDecision};

pub trait AuditLogger: Send + Sync {
    fn log(&self, event: AuditEvent);
}

pub struct StructuredAuditLogger;

impl AuditLogger for StructuredAuditLogger {
    fn log(&self, event: AuditEvent) {
        let json = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(err) => {
                warn!("audit: failed to serialize audit event error={}", err);
                "{\"type\":\"serialize_failed\"}".to_string()
            }
        };
        debug!(target: "igra::audit::json", "audit event audit_event={}", json);
        info!(target: "igra::audit::human", "audit summary={}", human_summary(&event));
    }
}

pub struct FileAuditLogger {
    file: Arc<Mutex<std::fs::File>>,
}

impl FileAuditLogger {
    pub fn new(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Arc::new(Mutex::new(file)) })
    }
}

impl AuditLogger for FileAuditLogger {
    fn log(&self, event: AuditEvent) {
        use std::io::Write;

        let json = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(err) => {
                warn!("audit: failed to serialize audit event for file logger error={}", err);
                "{\"type\":\"serialize_failed\"}".to_string()
            }
        };
        match self.file.lock() {
            Ok(mut file) => {
                if let Err(err) = writeln!(file, "{}", json) {
                    warn!("audit: failed to write audit event to file error={}", err);
                    return;
                }
                if let Err(err) = file.flush() {
                    warn!("audit: failed to flush audit event to file error={}", err);
                }
            }
            Err(err) => {
                warn!("audit: failed to lock audit file mutex error={}", err);
            }
        }
    }
}

pub struct MultiAuditLogger {
    loggers: Vec<Box<dyn AuditLogger>>,
}

impl MultiAuditLogger {
    pub fn new() -> Self {
        Self { loggers: vec![] }
    }

    pub fn add_logger(&mut self, logger: Box<dyn AuditLogger>) {
        self.loggers.push(logger);
    }
}

impl Default for MultiAuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger for MultiAuditLogger {
    fn log(&self, event: AuditEvent) {
        for logger in &self.loggers {
            logger.log(event.clone());
        }
    }
}

static AUDIT_LOGGER: OnceLock<Box<dyn AuditLogger>> = OnceLock::new();

const SHORT_ID_DISPLAY_LENGTH: usize = 16;
const SOMPI_PER_KAS: f64 = 100_000_000.0;

pub fn init_audit_logger(logger: Box<dyn AuditLogger>) {
    if AUDIT_LOGGER.set(logger).is_err() {
        warn!("init_audit_logger called more than once; ignoring");
    }
}

pub fn audit(event: AuditEvent) {
    match AUDIT_LOGGER.get() {
        Some(logger) => logger.log(event),
        None => trace!("audit event dropped: no logger configured event={:?}", event),
    }
}

fn short_id(value: &str) -> String {
    let trimmed = value.trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.len() <= SHORT_ID_DISPLAY_LENGTH {
        trimmed.to_string()
    } else {
        format!("{}…", &trimmed[..SHORT_ID_DISPLAY_LENGTH])
    }
}

fn human_summary(event: &AuditEvent) -> String {
    match event {
        AuditEvent::EventReceived { event_id, source, recipient, amount_sompi, .. } => format!(
            "AUDIT: signing event received - {} KAS to {} (hash: {}, source: {})",
            *amount_sompi as f64 / SOMPI_PER_KAS,
            recipient,
            short_id(event_id),
            source
        ),
        AuditEvent::EventSignatureValidated { event_id, validator_count, valid, reason, .. } => format!(
            "AUDIT: event signature validated - valid={} validators={} (hash: {}, reason: {})",
            valid,
            validator_count,
            short_id(event_id),
            reason.clone().unwrap_or_else(|| "-".to_string())
        ),
        AuditEvent::PolicyEnforced { event_id, external_request_id, policy_type, decision, reason, .. } => format!(
            "AUDIT: policy enforced - decision={:?} policy={} reason={} (external_request: {}, event_id: {})",
            decision,
            policy_type,
            reason,
            external_request_id.as_deref().map(short_id).unwrap_or_else(|| "-".to_string()),
            short_id(event_id)
        ),
        AuditEvent::ProposalValidated { event_id, external_request_id, signer_peer_id, accepted, reason, validation_hash, .. } => {
            format!(
                "AUDIT: proposal validated - accepted={} signer={} (external_request: {}, event_id: {}, validation: {}, reason: {})",
                accepted,
                signer_peer_id,
                external_request_id.as_deref().map(short_id).unwrap_or_else(|| "-".to_string()),
                short_id(event_id),
                short_id(validation_hash),
                reason.clone().unwrap_or_else(|| "-".to_string())
            )
        }
        AuditEvent::ProposalEquivocationDetected {
            event_id,
            round,
            proposer_peer_id,
            existing_tx_template_hash,
            new_tx_template_hash,
            ..
        } => format!(
            "AUDIT: proposal equivocation detected - proposer={} round={} event_id={} existing_hash={} new_hash={}",
            proposer_peer_id,
            round,
            short_id(event_id),
            short_id(existing_tx_template_hash),
            short_id(new_tx_template_hash)
        ),
        AuditEvent::PartialSignatureCreated { event_id, external_request_id, signer_peer_id, input_count, .. } => format!(
            "AUDIT: partial signatures created - signer={} inputs={} (external_request: {}, event_id: {})",
            signer_peer_id,
            input_count,
            external_request_id.as_deref().map(short_id).unwrap_or_else(|| "-".to_string()),
            short_id(event_id)
        ),
        AuditEvent::TransactionFinalized { event_id, external_request_id, tx_id, signature_count, threshold_required, .. } => format!(
            "AUDIT: transaction finalized - tx={} sigs={}/{} (external_request: {}, event_id: {})",
            tx_id,
            signature_count,
            threshold_required,
            external_request_id.as_deref().map(short_id).unwrap_or_else(|| "-".to_string()),
            short_id(event_id)
        ),
        AuditEvent::TransactionSubmitted { event_id, external_request_id, tx_id, blue_score, .. } => {
            format!(
                "AUDIT: transaction submitted - tx={} blue_score={} (external_request: {}, event_id: {})",
                tx_id,
                blue_score,
                external_request_id.as_deref().map(short_id).unwrap_or_else(|| "-".to_string()),
                short_id(event_id)
            )
        }
        AuditEvent::SessionTimedOut {
            event_id, external_request_id, signature_count, threshold_required, duration_seconds, ..
        } => format!(
            "AUDIT: session timed out - sigs={}/{} duration_s={} (external_request: {}, event_id: {})",
            signature_count,
            threshold_required,
            duration_seconds,
            external_request_id.as_deref().map(short_id).unwrap_or_else(|| "-".to_string()),
            short_id(event_id)
        ),
        AuditEvent::ConfigurationChanged { change_type, changed_by, .. } => {
            format!("AUDIT: configuration changed - type={} by={}", change_type, changed_by)
        }
        AuditEvent::StorageMutated { operation, key_prefix, record_count, .. } => {
            format!("AUDIT: storage mutated - op={} key_prefix={} count={}", operation, key_prefix, record_count)
        }
        AuditEvent::RateLimitExceeded { peer_id, .. } => format!("AUDIT: rate limit exceeded - peer={}", peer_id),
    }
}

#[macro_export]
macro_rules! audit_event_received {
    ($event_id:expr, $event:expr) => {
        $crate::infrastructure::audit::audit($crate::infrastructure::audit::AuditEvent::EventReceived {
            event_id: format!("{}", $event_id),
            external_request_id: None,
            source: format!("{:?}", $event.event.source),
            recipient: $event.audit.destination_raw.clone(),
            amount_sompi: $event.event.amount_sompi,
            timestamp_nanos: $crate::foundation::now_nanos(),
        })
    };
}

#[macro_export]
macro_rules! audit_policy_enforced {
    ($external_request_id:expr, $event_id:expr, $policy_type:expr, $decision:expr, $reason:expr) => {
        $crate::infrastructure::audit::audit($crate::infrastructure::audit::AuditEvent::PolicyEnforced {
            event_id: format!("{}", $event_id),
            external_request_id: $external_request_id.clone(),
            policy_type: $policy_type.to_string(),
            decision: $decision,
            reason: $reason.to_string(),
            timestamp_nanos: $crate::foundation::now_nanos(),
        })
    };
}
