use std::sync::{Arc, Mutex, OnceLock};
use tracing::info;

pub use crate::domain::audit::types::{AuditEvent, PolicyDecision};

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
