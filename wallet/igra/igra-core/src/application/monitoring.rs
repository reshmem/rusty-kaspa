use crate::foundation::ThresholdError;
use crate::infrastructure::rpc::NodeRpc;
use std::sync::Arc;
use std::time::Duration;
use log::{debug, info, trace};

pub struct TransactionMonitor {
    rpc: Arc<dyn NodeRpc>,
    min_confirmations: u64,
    poll_interval: Duration,
}

impl TransactionMonitor {
    pub fn new(rpc: Arc<dyn NodeRpc>, min_confirmations: u64, poll_interval: Duration) -> Self {
        Self { rpc, min_confirmations, poll_interval }
    }

    pub async fn monitor_until_confirmed(&self, accepted_blue_score: u64) -> Result<u64, ThresholdError> {
        loop {
            let current = self.rpc.get_virtual_selected_parent_blue_score().await?;
            debug!(
                "checked blue score current_blue_score={} accepted_blue_score={} min_confirmations={}",
                current,
                accepted_blue_score,
                self.min_confirmations
            );
            trace!(
                "monitor loop tick current_blue_score={} accepted_blue_score={} min_confirmations={}",
                current,
                accepted_blue_score,
                self.min_confirmations
            );
            if current.saturating_sub(accepted_blue_score) >= self.min_confirmations {
                info!(
                    "confirmation threshold reached current_blue_score={} accepted_blue_score={} min_confirmations={}",
                    current,
                    accepted_blue_score,
                    self.min_confirmations
                );
                return Ok(current);
            }
            trace!(
                "sleeping before next blue score poll sleep_ms={}",
                self.poll_interval.as_millis()
            );
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}
