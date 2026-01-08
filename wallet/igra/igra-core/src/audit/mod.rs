use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    EventReceived {
        event_hash: String,
        source: String,
        recipient: String,
        amount_sompi: u64,
        timestamp_ns: u64,
    },
    EventSignatureValidated {
        event_hash: String,
        validator_count: usize,
        valid: bool,
        reason: Option<String>,
        timestamp_ns: u64,
    },
    PolicyEnforced {
        request_id: String,
        event_hash: String,
        policy_type: String,
        decision: PolicyDecision,
        reason: String,
        timestamp_ns: u64,
    },
    ProposalValidated {
        request_id: String,
        signer_peer_id: String,
        accepted: bool,
        reason: Option<String>,
        validation_hash: String,
        timestamp_ns: u64,
    },
    PartialSignatureCreated {
        request_id: String,
        signer_peer_id: String,
        input_count: usize,
        timestamp_ns: u64,
    },
    TransactionFinalized {
        request_id: String,
        event_hash: String,
        tx_id: String,
        signature_count: usize,
        threshold_required: usize,
        timestamp_ns: u64,
    },
    TransactionSubmitted {
        request_id: String,
        tx_id: String,
        blue_score: u64,
        timestamp_ns: u64,
    },
    SessionTimedOut {
        request_id: String,
        event_hash: String,
        signature_count: usize,
        threshold_required: usize,
        duration_seconds: u64,
        timestamp_ns: u64,
    },
    ConfigurationChanged {
        change_type: String,
        old_value: Option<String>,
        new_value: String,
        changed_by: String,
        timestamp_ns: u64,
    },
    StorageMutated {
        operation: String,
        key_prefix: String,
        record_count: usize,
        timestamp_ns: u64,
    },
    RateLimitExceeded {
        peer_id: String,
        timestamp_ns: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Allowed,
    Rejected,
}

pub trait AuditLogger: Send + Sync {
    fn log(&self, event: AuditEvent);
}

pub struct StructuredAuditLogger;

impl AuditLogger for StructuredAuditLogger {
    fn log(&self, event: AuditEvent) {
        let json = serde_json::to_string(&event).unwrap_or_else(|_| "{\"type\":\"serialize_failed\"}".to_string());
        info!(target: "audit", "{}", json);
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

impl AuditLogger for MultiAuditLogger {
    fn log(&self, event: AuditEvent) {
        for logger in &self.loggers {
            logger.log(event.clone());
        }
    }
}

static AUDIT_LOGGER: OnceLock<Box<dyn AuditLogger>> = OnceLock::new();

pub fn init_audit_logger(logger: Box<dyn AuditLogger>) {
    let _ = AUDIT_LOGGER.set(logger);
}

pub fn audit(event: AuditEvent) {
    if let Some(logger) = AUDIT_LOGGER.get() {
        logger.log(event);
    }
}

pub fn now_nanos() -> u64 {
    current_timestamp_nanos_env(Some("KASPA_IGRA_TEST_NOW_NANOS")).unwrap_or(0)
}

#[macro_export]
macro_rules! audit_event_received {
    ($event_hash:expr, $event:expr) => {
        $crate::audit::audit($crate::audit::AuditEvent::EventReceived {
            event_hash: hex::encode($event_hash),
            source: format!("{:?}", $event.event_source),
            recipient: $event.destination_address.clone(),
            amount_sompi: $event.amount_sompi,
            timestamp_ns: $crate::audit::now_nanos(),
        })
    };
}

#[macro_export]
macro_rules! audit_policy_enforced {
    ($request_id:expr, $event_hash:expr, $policy_type:expr, $decision:expr, $reason:expr) => {
        $crate::audit::audit($crate::audit::AuditEvent::PolicyEnforced {
            request_id: $request_id.to_string(),
            event_hash: hex::encode($event_hash),
            policy_type: $policy_type.to_string(),
            decision: $decision,
            reason: $reason.to_string(),
            timestamp_ns: $crate::audit::now_nanos(),
        })
    };
}
use crate::util::time::current_timestamp_nanos_env;
