use igra_core::foundation::ThresholdError;
use prometheus::{Encoder, IntCounter, IntCounterVec, Registry, TextEncoder};
use log::debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub uptime: Duration,
    pub sessions_proposal_received: u64,
    pub sessions_finalized: u64,
    pub sessions_timed_out: u64,
    pub signer_acks_accepted: u64,
    pub signer_acks_rejected: u64,
    pub partial_sigs_total: u64,
    pub rpc_ok: u64,
    pub rpc_error: u64,
}

pub struct Metrics {
    registry: Registry,
    signing_sessions_total: IntCounterVec,
    signer_acks_total: IntCounterVec,
    partial_sigs_total: IntCounter,
    rpc_requests_total: IntCounterVec,
    started_at: Instant,
    sessions_proposal_received: AtomicU64,
    sessions_finalized: AtomicU64,
    sessions_timed_out: AtomicU64,
    signer_acks_accepted: AtomicU64,
    signer_acks_rejected: AtomicU64,
    partial_sigs_seen: AtomicU64,
    rpc_ok: AtomicU64,
    rpc_error: AtomicU64,
}

impl Metrics {
    pub fn new() -> Result<Self, ThresholdError> {
        debug!("initializing prometheus metrics");
        let registry = Registry::new();
        let signing_sessions_total =
            IntCounterVec::new(prometheus::Opts::new("signing_sessions_total", "Signing sessions by stage"), &["stage"])
                .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let signer_acks_total =
            IntCounterVec::new(prometheus::Opts::new("signer_acks_total", "Signer acknowledgments"), &["accepted"])
                .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let partial_sigs_total = IntCounter::new("partial_sigs_total", "Partial signatures received")
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let rpc_requests_total = IntCounterVec::new(
            prometheus::Opts::new("rpc_requests_total", "RPC requests by method and status"),
            &["method", "status"],
        )
        .map_err(|err| ThresholdError::Message(err.to_string()))?;

        registry.register(Box::new(signing_sessions_total.clone())).map_err(|err| ThresholdError::Message(err.to_string()))?;
        registry.register(Box::new(signer_acks_total.clone())).map_err(|err| ThresholdError::Message(err.to_string()))?;
        registry.register(Box::new(partial_sigs_total.clone())).map_err(|err| ThresholdError::Message(err.to_string()))?;
        registry.register(Box::new(rpc_requests_total.clone())).map_err(|err| ThresholdError::Message(err.to_string()))?;

        let out = Self {
            registry,
            signing_sessions_total,
            signer_acks_total,
            partial_sigs_total,
            rpc_requests_total,
            started_at: Instant::now(),
            sessions_proposal_received: AtomicU64::new(0),
            sessions_finalized: AtomicU64::new(0),
            sessions_timed_out: AtomicU64::new(0),
            signer_acks_accepted: AtomicU64::new(0),
            signer_acks_rejected: AtomicU64::new(0),
            partial_sigs_seen: AtomicU64::new(0),
            rpc_ok: AtomicU64::new(0),
            rpc_error: AtomicU64::new(0),
        };
        debug!("prometheus metrics registered metric_count=4");
        Ok(out)
    }

    pub fn inc_session_stage(&self, stage: &str) {
        self.signing_sessions_total.with_label_values(&[stage]).inc();
        match stage {
            "proposal_received" => {
                self.sessions_proposal_received.fetch_add(1, Ordering::Relaxed);
            }
            "finalized" => {
                self.sessions_finalized.fetch_add(1, Ordering::Relaxed);
            }
            "timed_out" => {
                self.sessions_timed_out.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn inc_signer_ack(&self, accepted: bool) {
        let label = if accepted { "true" } else { "false" };
        self.signer_acks_total.with_label_values(&[label]).inc();
        if accepted {
            self.signer_acks_accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.signer_acks_rejected.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn inc_partial_sig(&self) {
        self.partial_sigs_total.inc();
        self.partial_sigs_seen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rpc_request(&self, method: &str, status: &str) {
        self.rpc_requests_total.with_label_values(&[method, status]).inc();
        match status {
            "ok" => {
                self.rpc_ok.fetch_add(1, Ordering::Relaxed);
            }
            "error" => {
                self.rpc_error.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime: self.started_at.elapsed(),
            sessions_proposal_received: self.sessions_proposal_received.load(Ordering::Relaxed),
            sessions_finalized: self.sessions_finalized.load(Ordering::Relaxed),
            sessions_timed_out: self.sessions_timed_out.load(Ordering::Relaxed),
            signer_acks_accepted: self.signer_acks_accepted.load(Ordering::Relaxed),
            signer_acks_rejected: self.signer_acks_rejected.load(Ordering::Relaxed),
            partial_sigs_total: self.partial_sigs_seen.load(Ordering::Relaxed),
            rpc_ok: self.rpc_ok.load(Ordering::Relaxed),
            rpc_error: self.rpc_error.load(Ordering::Relaxed),
        }
    }

    pub fn encode(&self) -> Result<String, ThresholdError> {
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut buffer).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let output = String::from_utf8(buffer).map_err(|err| ThresholdError::Message(err.to_string()))?;
        Ok(output)
    }
}
