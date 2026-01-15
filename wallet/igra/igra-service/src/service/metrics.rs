use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::storage::CrdtStorageStats;
use log::debug;
use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Registry, TextEncoder};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn metrics_err(operation: &str, err: impl std::fmt::Display) -> ThresholdError {
    ThresholdError::MetricsError { operation: operation.to_string(), details: err.to_string() }
}

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
    pub crdt_total: u64,
    pub crdt_pending: u64,
    pub crdt_completed: u64,
    pub crdt_cf_estimated_live_data_size_bytes: u64,
    pub crdt_gc_deleted_total: u64,
    pub tx_template_hash_mismatches_total: u64,
}

pub struct Metrics {
    registry: Registry,
    signing_sessions_total: IntCounterVec,
    signer_acks_total: IntCounterVec,
    partial_sigs_total: IntCounter,
    rpc_requests_total: IntCounterVec,
    crdt_event_crdts_total: IntGauge,
    crdt_event_crdts_pending: IntGauge,
    crdt_event_crdts_completed: IntGauge,
    crdt_cf_estimated_num_keys: IntGauge,
    crdt_cf_estimated_live_data_size_bytes: IntGauge,
    crdt_gc_deleted_total: IntCounter,
    tx_template_hash_mismatches_total: IntCounterVec,
    started_at: Instant,
    sessions_proposal_received: AtomicU64,
    sessions_finalized: AtomicU64,
    sessions_timed_out: AtomicU64,
    signer_acks_accepted: AtomicU64,
    signer_acks_rejected: AtomicU64,
    partial_sigs_seen: AtomicU64,
    rpc_ok: AtomicU64,
    rpc_error: AtomicU64,
    crdt_total: AtomicU64,
    crdt_pending: AtomicU64,
    crdt_completed: AtomicU64,
    crdt_cf_estimated_live_data_size_bytes_value: AtomicU64,
    crdt_gc_deleted_total_value: AtomicU64,
    tx_template_hash_mismatches_total_value: AtomicU64,
}

impl Metrics {
    pub fn new() -> Result<Self, ThresholdError> {
        debug!("initializing prometheus metrics");
        let registry = Registry::new();
        let signing_sessions_total =
            IntCounterVec::new(prometheus::Opts::new("signing_sessions_total", "Signing sessions by stage"), &["stage"])
                .map_err(|err| metrics_err("signing_sessions_total", err))?;
        let signer_acks_total =
            IntCounterVec::new(prometheus::Opts::new("signer_acks_total", "Signer acknowledgments"), &["accepted"])
                .map_err(|err| metrics_err("signer_acks_total", err))?;
        let partial_sigs_total = IntCounter::new("partial_sigs_total", "Partial signatures received")
            .map_err(|err| metrics_err("partial_sigs_total", err))?;
        let rpc_requests_total = IntCounterVec::new(
            prometheus::Opts::new("rpc_requests_total", "RPC requests by method and status"),
            &["method", "status"],
        )
        .map_err(|err| metrics_err("rpc_requests_total", err))?;

        let crdt_event_crdts_total = IntGauge::new("crdt_event_states_total", "Total CRDT event states (exact scan)") //
            .map_err(|err| metrics_err("crdt_event_states_total", err))?;
        let crdt_event_crdts_pending = IntGauge::new("crdt_event_states_pending", "Pending CRDT event states (exact scan)") //
            .map_err(|err| metrics_err("crdt_event_states_pending", err))?;
        let crdt_event_crdts_completed = IntGauge::new("crdt_event_states_completed", "Completed CRDT event states (exact scan)") //
            .map_err(|err| metrics_err("crdt_event_states_completed", err))?;
        let crdt_cf_estimated_num_keys =
            IntGauge::new("crdt_cf_estimated_num_keys", "RocksDB estimate-num-keys for CRDT CF (0 if unknown)") //
                .map_err(|err| metrics_err("crdt_cf_estimated_num_keys", err))?;
        let crdt_cf_estimated_live_data_size_bytes = IntGauge::new(
            "crdt_cf_estimated_live_data_size_bytes",
            "RocksDB estimate-live-data-size for CRDT CF in bytes (0 if unknown)",
        )
        .map_err(|err| metrics_err("crdt_cf_estimated_live_data_size_bytes", err))?;
        let crdt_gc_deleted_total = IntCounter::new("crdt_gc_deleted_total", "Total CRDT event states deleted by GC") //
            .map_err(|err| metrics_err("crdt_gc_deleted_total", err))?;
        let tx_template_hash_mismatches_total = IntCounterVec::new(
            prometheus::Opts::new("tx_template_hash_mismatches_total", "Tx template hash mismatches detected (by kind)"),
            &["kind"],
        )
        .map_err(|err| metrics_err("tx_template_hash_mismatches_total", err))?;

        registry.register(Box::new(signing_sessions_total.clone())).map_err(|err| metrics_err("register signing_sessions_total", err))?;
        registry.register(Box::new(signer_acks_total.clone())).map_err(|err| metrics_err("register signer_acks_total", err))?;
        registry.register(Box::new(partial_sigs_total.clone())).map_err(|err| metrics_err("register partial_sigs_total", err))?;
        registry.register(Box::new(rpc_requests_total.clone())).map_err(|err| metrics_err("register rpc_requests_total", err))?;
        registry.register(Box::new(crdt_event_crdts_total.clone())).map_err(|err| metrics_err("register crdt_event_crdts_total", err))?;
        registry.register(Box::new(crdt_event_crdts_pending.clone())).map_err(|err| metrics_err("register crdt_event_crdts_pending", err))?;
        registry
            .register(Box::new(crdt_event_crdts_completed.clone()))
            .map_err(|err| metrics_err("register crdt_event_crdts_completed", err))?;
        registry.register(Box::new(crdt_cf_estimated_num_keys.clone())).map_err(|err| metrics_err("register crdt_cf_estimated_num_keys", err))?;
        registry
            .register(Box::new(crdt_cf_estimated_live_data_size_bytes.clone()))
            .map_err(|err| metrics_err("register crdt_cf_estimated_live_data_size_bytes", err))?;
        registry.register(Box::new(crdt_gc_deleted_total.clone())).map_err(|err| metrics_err("register crdt_gc_deleted_total", err))?;
        registry
            .register(Box::new(tx_template_hash_mismatches_total.clone()))
            .map_err(|err| metrics_err("register tx_template_hash_mismatches_total", err))?;

        let out = Self {
            registry,
            signing_sessions_total,
            signer_acks_total,
            partial_sigs_total,
            rpc_requests_total,
            crdt_event_crdts_total,
            crdt_event_crdts_pending,
            crdt_event_crdts_completed,
            crdt_cf_estimated_num_keys,
            crdt_cf_estimated_live_data_size_bytes,
            crdt_gc_deleted_total,
            tx_template_hash_mismatches_total,
            started_at: Instant::now(),
            sessions_proposal_received: AtomicU64::new(0),
            sessions_finalized: AtomicU64::new(0),
            sessions_timed_out: AtomicU64::new(0),
            signer_acks_accepted: AtomicU64::new(0),
            signer_acks_rejected: AtomicU64::new(0),
            partial_sigs_seen: AtomicU64::new(0),
            rpc_ok: AtomicU64::new(0),
            rpc_error: AtomicU64::new(0),
            crdt_total: AtomicU64::new(0),
            crdt_pending: AtomicU64::new(0),
            crdt_completed: AtomicU64::new(0),
            crdt_cf_estimated_live_data_size_bytes_value: AtomicU64::new(0),
            crdt_gc_deleted_total_value: AtomicU64::new(0),
            tx_template_hash_mismatches_total_value: AtomicU64::new(0),
        };
        debug!("prometheus metrics registered");
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

    pub fn set_crdt_storage_stats(&self, stats: CrdtStorageStats) {
        let total = stats.total_event_crdts;
        let pending = stats.pending_event_crdts;
        let completed = stats.completed_event_crdts;

        self.crdt_event_crdts_total.set(total as i64);
        self.crdt_event_crdts_pending.set(pending as i64);
        self.crdt_event_crdts_completed.set(completed as i64);
        self.crdt_total.store(total, Ordering::Relaxed);
        self.crdt_pending.store(pending, Ordering::Relaxed);
        self.crdt_completed.store(completed, Ordering::Relaxed);

        let estimated_num_keys = stats.cf_estimated_num_keys.unwrap_or(0);
        let estimated_live_bytes = stats.cf_estimated_live_data_size_bytes.unwrap_or(0);
        self.crdt_cf_estimated_num_keys.set(estimated_num_keys as i64);
        self.crdt_cf_estimated_live_data_size_bytes.set(estimated_live_bytes as i64);
        self.crdt_cf_estimated_live_data_size_bytes_value.store(estimated_live_bytes, Ordering::Relaxed);
    }

    pub fn inc_crdt_gc_deleted_total(&self, deleted: u64) {
        self.crdt_gc_deleted_total.inc_by(deleted);
        self.crdt_gc_deleted_total_value.fetch_add(deleted, Ordering::Relaxed);
    }

    pub fn inc_tx_template_hash_mismatch(&self, kind: &str) {
        self.tx_template_hash_mismatches_total.with_label_values(&[kind]).inc();
        self.tx_template_hash_mismatches_total_value.fetch_add(1, Ordering::Relaxed);
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
            crdt_total: self.crdt_total.load(Ordering::Relaxed),
            crdt_pending: self.crdt_pending.load(Ordering::Relaxed),
            crdt_completed: self.crdt_completed.load(Ordering::Relaxed),
            crdt_cf_estimated_live_data_size_bytes: self.crdt_cf_estimated_live_data_size_bytes_value.load(Ordering::Relaxed),
            crdt_gc_deleted_total: self.crdt_gc_deleted_total_value.load(Ordering::Relaxed),
            tx_template_hash_mismatches_total: self.tx_template_hash_mismatches_total_value.load(Ordering::Relaxed),
        }
    }

    pub fn encode(&self) -> Result<String, ThresholdError> {
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut buffer).map_err(|err| metrics_err("encode metrics", err))?;
        let output = String::from_utf8(buffer).map_err(|err| ThresholdError::EncodingError(err.to_string()))?;
        Ok(output)
    }
}
