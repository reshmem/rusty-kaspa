use crate::domain::{RequestDecision, SigningEvent, SigningRequest};
use crate::foundation::Hash32;
use crate::foundation::{PeerId, RequestId, TransactionId};
use crate::infrastructure::audit::{audit, now_nanos, AuditEvent};
use crate::infrastructure::storage::Storage;
use std::sync::Arc;
use log::{debug, info, trace, warn};

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
        trace!(
            "on_event_received dispatch observer_count={} event_hash={}",
            self.observers.len(),
            hex::encode(event_hash)
        );
        for (idx, observer) in self.observers.iter().enumerate() {
            trace!("on_event_received calling observer observer_index={}", idx);
            observer.on_event_received(event, event_hash);
        }
    }

    fn on_request_created(&self, request: &SigningRequest) {
        trace!(
            "on_request_created dispatch observer_count={} request_id={}",
            self.observers.len(),
            request.request_id
        );
        for (idx, observer) in self.observers.iter().enumerate() {
            trace!("on_request_created calling observer observer_index={}", idx);
            observer.on_request_created(request);
        }
    }

    fn on_status_changed(&self, request_id: &RequestId, old_status: &RequestDecision, new_status: &RequestDecision) {
        info!(
            "request status changed request_id={} old_status={:?} new_status={:?}",
            request_id, old_status, new_status
        );
        for observer in &self.observers {
            observer.on_status_changed(request_id, old_status, new_status);
        }
    }

    fn on_signature_added(&self, request_id: &RequestId, signer_peer_id: &PeerId, input_index: u32) {
        debug!(
            "signature added request_id={} signer_peer_id={} input_index={}",
            request_id, signer_peer_id, input_index
        );
        for observer in &self.observers {
            observer.on_signature_added(request_id, signer_peer_id, input_index);
        }
    }

    fn on_threshold_met(&self, request_id: &RequestId, signature_count: usize, threshold: usize) {
        info!(
            "signature threshold met request_id={} signature_count={} threshold={}",
            request_id, signature_count, threshold
        );
        for observer in &self.observers {
            observer.on_threshold_met(request_id, signature_count, threshold);
        }
    }

    fn on_finalized(&self, request_id: &RequestId, tx_id: &TransactionId) {
        info!(
            "request finalized request_id={} tx_id={}",
            request_id,
            hex::encode(tx_id.as_hash())
        );
        for observer in &self.observers {
            observer.on_finalized(request_id, tx_id);
        }
    }

    fn on_failed(&self, request_id: &RequestId, reason: &str) {
        warn!("request failed request_id={} reason={}", request_id, reason);
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
        trace!(
            "audit: event received event_hash={} event_id={}",
            hex::encode(event_hash),
            event.event_id
        );
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
            "audit: finalized transaction request_id={} tx_id={} signature_count={} threshold_required={}",
            request_id,
            hex::encode(tx_id.as_hash()),
            signature_count,
            threshold_required
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
