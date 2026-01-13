use crate::foundation::{Hash32, PeerId, ThresholdError};
use crate::infrastructure::storage::Storage;
use std::sync::Arc;

/// CRDT-based event coordinator.
///
/// This provides pure orchestration decisions for a given `(event_hash, tx_template_hash)` pair.
/// It does not perform transport I/O itself; callers can use the returned action to decide what to do.
pub struct CrdtCoordinator {
    storage: Arc<dyn Storage>,
    local_peer_id: PeerId,
}

impl CrdtCoordinator {
    pub fn new(storage: Arc<dyn Storage>, local_peer_id: PeerId) -> Self {
        Self { storage, local_peer_id }
    }

    pub fn process_event(&self, event_hash: &Hash32, tx_template_hash: &Hash32) -> Result<CrdtAction, ThresholdError> {
        let state = self.storage.get_event_crdt(event_hash, tx_template_hash)?;
        match state {
            Some(s) if s.completion.is_some() => Ok(CrdtAction::AlreadyComplete),
            Some(s) => {
                let has_my_sig = s.signatures.iter().any(|sig| sig.signer_peer_id == self.local_peer_id);
                if has_my_sig {
                    Ok(CrdtAction::WaitForThreshold)
                } else {
                    Ok(CrdtAction::SignAndBroadcast)
                }
            }
            None => Ok(CrdtAction::InitializeAndSign),
        }
    }

    pub fn check_threshold(
        &self,
        event_hash: &Hash32,
        tx_template_hash: &Hash32,
        input_count: usize,
        required: usize,
    ) -> Result<bool, ThresholdError> {
        self.storage.crdt_has_threshold(event_hash, tx_template_hash, input_count, required)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrdtAction {
    AlreadyComplete,
    WaitForThreshold,
    SignAndBroadcast,
    InitializeAndSign,
}

