use crate::foundation::ThresholdError;
use crate::infrastructure::rpc::NodeRpc;
use std::sync::Arc;
use std::time::Duration;

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
            if current.saturating_sub(accepted_blue_score) >= self.min_confirmations {
                return Ok(current);
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

