use crate::domain::StoredEvent;
use crate::foundation::Hash32;
use crate::foundation::{PeerId, TransactionId};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::storage::Storage;
use log::{debug, info, trace, warn};
use std::sync::Arc;

pub trait LifecycleObserver: Send + Sync {
    fn on_event_received(&self, _event: &StoredEvent, _event_id: &Hash32) {}
    fn on_signature_added(&self, _event_id: &Hash32, _tx_template_hash: &Hash32, _signer_peer_id: &PeerId, _input_index: u32) {}
    fn on_threshold_met(&self, _event_id: &Hash32, _tx_template_hash: &Hash32, _input_count: usize, _threshold: usize) {}
    fn on_completed(&self, _event_id: &Hash32, _tx_template_hash: &Hash32, _tx_id: &TransactionId) {}
    fn on_failed(&self, _event_id: &Hash32, _tx_template_hash: Option<&Hash32>, _reason: &str) {}
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
    fn on_event_received(&self, event: &StoredEvent, event_id: &Hash32) {
        trace!("on_event_received dispatch observer_count={} event_id={}", self.observers.len(), hex::encode(event_id));
        for (idx, observer) in self.observers.iter().enumerate() {
            trace!("on_event_received calling observer observer_index={}", idx);
            observer.on_event_received(event, event_id);
        }
    }

    fn on_signature_added(&self, event_id: &Hash32, tx_template_hash: &Hash32, signer_peer_id: &PeerId, input_index: u32) {
        debug!(
            "signature added event_id={} tx_template_hash={} signer_peer_id={} input_index={}",
            hex::encode(event_id),
            hex::encode(tx_template_hash),
            signer_peer_id,
            input_index
        );
        for observer in &self.observers {
            observer.on_signature_added(event_id, tx_template_hash, signer_peer_id, input_index);
        }
    }

    fn on_threshold_met(&self, event_id: &Hash32, tx_template_hash: &Hash32, input_count: usize, threshold: usize) {
        info!(
            "signature threshold met event_id={} tx_template_hash={} input_count={} threshold={}",
            hex::encode(event_id),
            hex::encode(tx_template_hash),
            input_count,
            threshold
        );
        for observer in &self.observers {
            observer.on_threshold_met(event_id, tx_template_hash, input_count, threshold);
        }
    }

    fn on_completed(&self, event_id: &Hash32, tx_template_hash: &Hash32, tx_id: &TransactionId) {
        info!(
            "event completed event_id={} tx_template_hash={} tx_id={}",
            hex::encode(event_id),
            hex::encode(tx_template_hash),
            hex::encode(tx_id.as_hash())
        );
        for observer in &self.observers {
            observer.on_completed(event_id, tx_template_hash, tx_id);
        }
    }

    fn on_failed(&self, event_id: &Hash32, tx_template_hash: Option<&Hash32>, reason: &str) {
        warn!(
            "event failed event_id={} tx_template_hash={} reason={}",
            hex::encode(event_id),
            tx_template_hash.map(hex::encode).unwrap_or_else(|| "-".to_string()),
            reason
        );
        for observer in &self.observers {
            observer.on_failed(event_id, tx_template_hash, reason);
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
    fn on_event_received(&self, event: &StoredEvent, event_id: &Hash32) {
        trace!("audit: event received event_id={} external_id={}", hex::encode(event_id), event.audit.external_id_raw);
        crate::audit_event_received!(event_id, event);
    }

    fn on_completed(&self, event_id: &Hash32, tx_template_hash: &Hash32, tx_id: &TransactionId) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        let signature_count =
            storage.get_event_crdt(event_id, tx_template_hash).ok().flatten().map(|state| state.signatures.len()).unwrap_or(0);
        let threshold_required = self.threshold_required.unwrap_or(0);
        info!(
            "audit: finalized transaction event_id={} tx_template_hash={} tx_id={} signature_count={} threshold_required={}",
            hex::encode(event_id),
            hex::encode(tx_template_hash),
            hex::encode(tx_id.as_hash()),
            signature_count,
            threshold_required
        );
        audit(AuditEvent::TransactionFinalized {
            event_id: hex::encode(event_id),
            external_request_id: None,
            tx_id: hex::encode(tx_id.as_hash()),
            signature_count,
            threshold_required,
            timestamp_nanos: crate::foundation::now_nanos(),
        });
    }
}
