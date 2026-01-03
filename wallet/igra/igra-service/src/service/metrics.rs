use igra_core::error::ThresholdError;
use prometheus::{Encoder, IntCounter, IntCounterVec, Registry, TextEncoder};

pub struct Metrics {
    registry: Registry,
    signing_sessions_total: IntCounterVec,
    signer_acks_total: IntCounterVec,
    partial_sigs_total: IntCounter,
    rpc_requests_total: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self, ThresholdError> {
        let registry = Registry::new();
        let signing_sessions_total = IntCounterVec::new(
            prometheus::Opts::new("signing_sessions_total", "Signing sessions by stage"),
            &["stage"],
        )
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let signer_acks_total = IntCounterVec::new(
            prometheus::Opts::new("signer_acks_total", "Signer acknowledgments"),
            &["accepted"],
        )
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let partial_sigs_total = IntCounter::new("partial_sigs_total", "Partial signatures received")
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let rpc_requests_total = IntCounterVec::new(
            prometheus::Opts::new("rpc_requests_total", "RPC requests by method and status"),
            &["method", "status"],
        )
        .map_err(|err| ThresholdError::Message(err.to_string()))?;

        registry
            .register(Box::new(signing_sessions_total.clone()))
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        registry
            .register(Box::new(signer_acks_total.clone()))
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        registry
            .register(Box::new(partial_sigs_total.clone()))
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        registry
            .register(Box::new(rpc_requests_total.clone()))
            .map_err(|err| ThresholdError::Message(err.to_string()))?;

        Ok(Self {
            registry,
            signing_sessions_total,
            signer_acks_total,
            partial_sigs_total,
            rpc_requests_total,
        })
    }

    pub fn inc_session_stage(&self, stage: &str) {
        self.signing_sessions_total.with_label_values(&[stage]).inc();
    }

    pub fn inc_signer_ack(&self, accepted: bool) {
        let label = if accepted { "true" } else { "false" };
        self.signer_acks_total.with_label_values(&[label]).inc();
    }

    pub fn inc_partial_sig(&self) {
        self.partial_sigs_total.inc();
    }

    pub fn inc_rpc_request(&self, method: &str, status: &str) {
        self.rpc_requests_total.with_label_values(&[method, status]).inc();
    }

    pub fn encode(&self) -> Result<String, ThresholdError> {
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&metric_families, &mut buffer)
            .map_err(|err| ThresholdError::Message(err.to_string()))?;
        let output = String::from_utf8(buffer).map_err(|err| ThresholdError::Message(err.to_string()))?;
        Ok(output)
    }
}
