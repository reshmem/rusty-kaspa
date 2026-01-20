use crate::domain::StoredEvent;
use crate::foundation::{EventId, PeerId, TransactionId, TxTemplateHash};
use crate::infrastructure::audit::{audit, AuditEvent};
use crate::infrastructure::storage::Storage;
use log::{debug, info, trace, warn};
use std::sync::Arc;

pub trait LifecycleObserver: Send + Sync {
    fn on_event_received(&self, _event: &StoredEvent, _event_id: &EventId) {}
    fn on_signature_added(
        &self,
        _event_id: &EventId,
        _tx_template_hash: &TxTemplateHash,
        _signer_peer_id: &PeerId,
        _input_index: u32,
    ) {
    }
    fn on_threshold_met(&self, _event_id: &EventId, _tx_template_hash: &TxTemplateHash, _input_count: usize, _threshold: usize) {}
    fn on_completed(&self, _event_id: &EventId, _tx_template_hash: &TxTemplateHash, _tx_id: &TransactionId) {}
    fn on_failed(&self, _event_id: &EventId, _tx_template_hash: Option<&TxTemplateHash>, _reason: &str) {}
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
    fn on_event_received(&self, event: &StoredEvent, event_id: &EventId) {
        trace!("on_event_received dispatch observer_count={} event_id={:#x}", self.observers.len(), event_id);
        for (idx, observer) in self.observers.iter().enumerate() {
            trace!("on_event_received calling observer observer_index={}", idx);
            observer.on_event_received(event, event_id);
        }
    }

    fn on_signature_added(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash, signer_peer_id: &PeerId, input_index: u32) {
        debug!(
            "signature added event_id={:#x} tx_template_hash={:#x} signer_peer_id={} input_index={}",
            event_id, tx_template_hash, signer_peer_id, input_index
        );
        for observer in &self.observers {
            observer.on_signature_added(event_id, tx_template_hash, signer_peer_id, input_index);
        }
    }

    fn on_threshold_met(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash, input_count: usize, threshold: usize) {
        info!(
            "signature threshold met event_id={:#x} tx_template_hash={:#x} input_count={} threshold={}",
            event_id, tx_template_hash, input_count, threshold
        );
        for observer in &self.observers {
            observer.on_threshold_met(event_id, tx_template_hash, input_count, threshold);
        }
    }

    fn on_completed(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash, tx_id: &TransactionId) {
        info!("event completed event_id={:#x} tx_template_hash={:#x} tx_id={:#x}", event_id, tx_template_hash, tx_id);
        for observer in &self.observers {
            observer.on_completed(event_id, tx_template_hash, tx_id);
        }
    }

    fn on_failed(&self, event_id: &EventId, tx_template_hash: Option<&TxTemplateHash>, reason: &str) {
        warn!(
            "event failed event_id={:#x} tx_template_hash={} reason={}",
            event_id,
            tx_template_hash.map(|h| h.to_string()).unwrap_or_else(|| "-".to_string()),
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
    fn on_event_received(&self, event: &StoredEvent, event_id: &EventId) {
        trace!("audit: event received event_id={:#x} external_id={}", event_id, event.audit.external_id_raw);
        crate::audit_event_received!(event_id, event);
    }

    fn on_completed(&self, event_id: &EventId, tx_template_hash: &TxTemplateHash, tx_id: &TransactionId) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        let signature_count = match storage.get_event_crdt(event_id, tx_template_hash) {
            Ok(Some(state)) => state.signatures.len(),
            _ => 0,
        };
        let threshold_required = match self.threshold_required {
            Some(value) => value,
            None => {
                warn!("audit: missing threshold_required configuration; using 0 event_id={:#x}", event_id);
                0
            }
        };
        info!(
            "audit: finalized transaction event_id={:#x} tx_template_hash={:#x} tx_id={:#x} signature_count={} threshold_required={}",
            event_id, tx_template_hash, tx_id, signature_count, threshold_required
        );
        audit(AuditEvent::TransactionFinalized {
            event_id: event_id.to_string(),
            external_request_id: None,
            tx_id: tx_id.to_string(),
            signature_count,
            threshold_required,
            timestamp_nanos: crate::foundation::now_nanos(),
        });
    }
}
