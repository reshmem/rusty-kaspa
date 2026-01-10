use super::super::state::RpcState;
use igra_core::application::{submit_signing_event, SigningEventParams};
use igra_core::foundation::ThresholdError;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;

pub async fn run_hyperlane_watcher(state: Arc<RpcState>, dir: std::path::PathBuf, poll_interval: Duration) -> Result<(), ThresholdError> {
    loop {
        let mut entries = fs::read_dir(&dir).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
        while let Some(entry) = entries.next_entry().await.map_err(|err| ThresholdError::Message(err.to_string()))? {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path).await.map_err(|err| ThresholdError::Message(err.to_string()))?;
            let params: SigningEventParams = match serde_json::from_slice(&bytes) {
                Ok(params) => params,
                Err(err) => {
                    tracing::warn!(path = %path.display(), error = %err, "hyperlane watcher invalid event");
                    continue;
                }
            };
            if let Err(err) = submit_signing_event(&state.event_ctx, params).await {
                tracing::warn!(path = %path.display(), error = %err, "hyperlane watcher submit failed");
                continue;
            }
            let mut done_path = path.clone();
            done_path.set_extension("done");
            if let Err(err) = fs::rename(&path, &done_path).await {
                tracing::warn!(path = %path.display(), error = %err, "hyperlane watcher rename failed");
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}

