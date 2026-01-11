use std::sync::{Arc, Mutex, OnceLock};
use log::{debug, info, trace, warn};

pub use crate::domain::audit::types::{AuditEvent, PolicyDecision};

pub trait AuditLogger: Send + Sync {
    fn log(&self, event: AuditEvent);
}

pub struct StructuredAuditLogger;

impl AuditLogger for StructuredAuditLogger {
    fn log(&self, event: AuditEvent) {
        let json = serde_json::to_string(&event).unwrap_or_else(|_| "{\"type\":\"serialize_failed\"}".to_string());
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

        let json = serde_json::to_string(&event).unwrap_or_else(|_| "{\"type\":\"serialize_failed\"}".to_string());
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{}", json);
            let _ = file.flush();
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

pub fn now_nanos() -> u64 {
    current_timestamp_nanos_env(Some("KASPA_IGRA_TEST_NOW_NANOS")).unwrap_or(0)
}

fn short_id(value: &str) -> String {
    let trimmed = value.trim_start_matches("0x");
    if trimmed.len() <= 16 {
        trimmed.to_string()
    } else {
        format!("{}…", &trimmed[..16])
    }
}

fn human_summary(event: &AuditEvent) -> String {
    match event {
        AuditEvent::EventReceived { event_hash, source, recipient, amount_sompi, .. } => format!(
            "AUDIT: signing event received - {} KAS to {} (hash: {}, source: {})",
            *amount_sompi as f64 / 100_000_000.0,
            recipient,
            short_id(event_hash),
            source
        ),
        AuditEvent::EventSignatureValidated { event_hash, validator_count, valid, reason, .. } => format!(
            "AUDIT: event signature validated - valid={} validators={} (hash: {}, reason: {})",
            valid,
            validator_count,
            short_id(event_hash),
            reason.clone().unwrap_or_else(|| "-".to_string())
        ),
        AuditEvent::PolicyEnforced { request_id, event_hash, policy_type, decision, reason, .. } => format!(
            "AUDIT: policy enforced - decision={:?} policy={} reason={} (request: {}, hash: {})",
            decision,
            policy_type,
            reason,
            short_id(request_id),
            short_id(event_hash)
        ),
        AuditEvent::ProposalValidated { request_id, signer_peer_id, accepted, reason, validation_hash, .. } => format!(
            "AUDIT: proposal validated - accepted={} signer={} (request: {}, validation: {}, reason: {})",
            accepted,
            signer_peer_id,
            short_id(request_id),
            short_id(validation_hash),
            reason.clone().unwrap_or_else(|| "-".to_string())
        ),
        AuditEvent::PartialSignatureCreated { request_id, signer_peer_id, input_count, .. } => format!(
            "AUDIT: partial signatures created - signer={} inputs={} (request: {})",
            signer_peer_id,
            input_count,
            short_id(request_id)
        ),
        AuditEvent::TransactionFinalized { request_id, tx_id, signature_count, threshold_required, .. } => format!(
            "AUDIT: transaction finalized - tx={} sigs={}/{} (request: {})",
            tx_id,
            signature_count,
            threshold_required,
            short_id(request_id)
        ),
        AuditEvent::TransactionSubmitted { request_id, tx_id, blue_score, .. } => {
            format!("AUDIT: transaction submitted - tx={} blue_score={} (request: {})", tx_id, blue_score, short_id(request_id))
        }
        AuditEvent::SessionTimedOut { request_id, signature_count, threshold_required, duration_seconds, .. } => format!(
            "AUDIT: session timed out - sigs={}/{} duration_s={} (request: {})",
            signature_count,
            threshold_required,
            duration_seconds,
            short_id(request_id)
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
    ($event_hash:expr, $event:expr) => {
        $crate::infrastructure::audit::audit($crate::infrastructure::audit::AuditEvent::EventReceived {
            event_hash: hex::encode($event_hash),
            source: format!("{:?}", $event.event_source),
            recipient: $event.destination_address.clone(),
            amount_sompi: $event.amount_sompi,
            timestamp_ns: $crate::infrastructure::audit::now_nanos(),
        })
    };
}

#[macro_export]
macro_rules! audit_policy_enforced {
    ($request_id:expr, $event_hash:expr, $policy_type:expr, $decision:expr, $reason:expr) => {
        $crate::infrastructure::audit::audit($crate::infrastructure::audit::AuditEvent::PolicyEnforced {
            request_id: $request_id.to_string(),
            event_hash: hex::encode($event_hash),
            policy_type: $policy_type.to_string(),
            decision: $decision,
            reason: $reason.to_string(),
            timestamp_ns: $crate::infrastructure::audit::now_nanos(),
        })
    };
}

use crate::foundation::util::time::current_timestamp_nanos_env;
