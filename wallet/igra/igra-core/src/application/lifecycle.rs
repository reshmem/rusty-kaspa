use crate::domain::{RequestDecision, SigningEvent, SigningRequest};
use crate::foundation::Hash32;
use crate::foundation::{PeerId, RequestId, TransactionId};
use crate::infrastructure::audit::{audit, now_nanos, AuditEvent};
use crate::infrastructure::storage::Storage;
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

pub trait LifecycleObserver: Send + Sync {
    fn on_event_received(&self, _event: &SigningEvent, _event_hash: &Hash32) {}
    fn on_request_created(&self, _request: &SigningRequest) {}
    fn on_status_changed(&self, _request_id: &RequestId, _old_status: &RequestDecision, _new_status: &RequestDecision) {}
    fn on_signature_added(&self, _request_id: &RequestId, _signer_peer_id: &PeerId, _input_index: u32) {}
    fn on_threshold_met(&self, _request_id: &RequestId, _signature_count: usize, _threshold: usize) {}
    fn on_finalized(&self, _request_id: &RequestId, _tx_id: &TransactionId) {}
    fn on_failed(&self, _request_id: &RequestId, _reason: &str) {}
}

pub struct NoopObserver;

impl LifecycleObserver for NoopObserver {}

pub struct CompositeObserver {
    observers: Vec<Arc<dyn LifecycleObserver>>,
}

impl CompositeObserver {
    pub fn new() -> Self {
        Self { observers: Vec::new() }
    }

    pub fn add_observer(&mut self, observer: Arc<dyn LifecycleObserver>) {
        self.observers.push(observer);
    }
}

impl Default for CompositeObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleObserver for CompositeObserver {
    fn on_event_received(&self, event: &SigningEvent, event_hash: &Hash32) {
        trace!(observer_count = self.observers.len(), event_hash = %hex::encode(event_hash), "on_event_received dispatch");
        for (idx, observer) in self.observers.iter().enumerate() {
            trace!(observer_index = idx, "on_event_received calling observer");
            observer.on_event_received(event, event_hash);
        }
    }

    fn on_request_created(&self, request: &SigningRequest) {
        trace!(observer_count = self.observers.len(), request_id = %request.request_id, "on_request_created dispatch");
        for (idx, observer) in self.observers.iter().enumerate() {
            trace!(observer_index = idx, "on_request_created calling observer");
            observer.on_request_created(request);
        }
    }

    fn on_status_changed(&self, request_id: &RequestId, old_status: &RequestDecision, new_status: &RequestDecision) {
        info!(
            request_id = %request_id,
            old_status = ?old_status,
            new_status = ?new_status,
            "request status changed"
        );
        for observer in &self.observers {
            observer.on_status_changed(request_id, old_status, new_status);
        }
    }

    fn on_signature_added(&self, request_id: &RequestId, signer_peer_id: &PeerId, input_index: u32) {
        debug!(
            request_id = %request_id,
            signer_peer_id = %signer_peer_id,
            input_index,
            "signature added"
        );
        for observer in &self.observers {
            observer.on_signature_added(request_id, signer_peer_id, input_index);
        }
    }

    fn on_threshold_met(&self, request_id: &RequestId, signature_count: usize, threshold: usize) {
        info!(
            request_id = %request_id,
            signature_count,
            threshold,
            "signature threshold met"
        );
        for observer in &self.observers {
            observer.on_threshold_met(request_id, signature_count, threshold);
        }
    }

    fn on_finalized(&self, request_id: &RequestId, tx_id: &TransactionId) {
        info!(
            request_id = %request_id,
            tx_id = %hex::encode(tx_id.as_hash()),
            "request finalized"
        );
        for observer in &self.observers {
            observer.on_finalized(request_id, tx_id);
        }
    }

    fn on_failed(&self, request_id: &RequestId, reason: &str) {
        warn!(request_id = %request_id, reason = %reason, "request failed");
        for observer in &self.observers {
            observer.on_failed(request_id, reason);
        }
    }
}

pub struct AuditLoggingObserver {
    storage: Option<Arc<dyn Storage>>,
    threshold_required: Option<usize>,
}

impl AuditLoggingObserver {
    pub fn new(storage: Option<Arc<dyn Storage>>, threshold_required: Option<usize>) -> Self {
        Self { storage, threshold_required }
    }
}

impl LifecycleObserver for AuditLoggingObserver {
    fn on_event_received(&self, event: &SigningEvent, event_hash: &Hash32) {
        trace!(event_hash = %hex::encode(event_hash), event_id = %event.event_id, "audit: event received");
        crate::audit_event_received!(event_hash, event);
    }

    fn on_finalized(&self, request_id: &RequestId, tx_id: &TransactionId) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        let Ok(Some(request)) = storage.get_request(request_id) else {
            return;
        };
        let signature_count = storage.list_partial_sigs(request_id).map(|entries| entries.len()).unwrap_or(0);
        let threshold_required = self.threshold_required.unwrap_or(0);
        info!(
            request_id = %request_id,
            tx_id = %hex::encode(tx_id.as_hash()),
            signature_count,
            threshold_required,
            "audit: finalized transaction"
        );
        audit(AuditEvent::TransactionFinalized {
            request_id: request_id.to_string(),
            event_hash: hex::encode(request.event_hash),
            tx_id: hex::encode(tx_id.as_hash()),
            signature_count,
            threshold_required,
            timestamp_ns: now_nanos(),
        });
    }
}
