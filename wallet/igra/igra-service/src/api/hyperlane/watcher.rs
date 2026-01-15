use super::super::state::RpcState;
use igra_core::application::{submit_signing_event, SigningEventParams};
use igra_core::foundation::ThresholdError;
use log::{debug, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;

pub async fn run_hyperlane_watcher(
    state: Arc<RpcState>,
    dir: std::path::PathBuf,
    poll_interval: Duration,
) -> Result<(), ThresholdError> {
    info!("starting Hyperlane file watcher watch_dir={} poll_interval_ms={}", dir.display(), poll_interval.as_millis());
    let mut processed_count = 0u64;
    let mut error_count = 0u64;

    loop {
        let mut entries = match fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(err) => {
                error_count += 1;
                warn!("failed to read watch directory dir={} total_errors={} error={}", dir.display(), error_count, err);
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(err) => {
                    error_count += 1;
                    warn!("failed to read watch directory entry dir={} total_errors={} error={}", dir.display(), error_count, err);
                    break;
                }
            };

            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }

            debug!("processing Hyperlane message file file={}", path.display());
            let bytes = fs::read(&path).await.map_err(|err| ThresholdError::StorageError {
                operation: "hyperlane watcher read".to_string(),
                details: err.to_string(),
            })?;
            let params: SigningEventParams = match serde_json::from_slice(&bytes) {
                Ok(params) => params,
                Err(err) => {
                    error_count += 1;
                    warn!("hyperlane watcher invalid event path={} total_errors={} error={}", path.display(), error_count, err);
                    continue;
                }
            };
            if let Err(err) = submit_signing_event(&state.event_ctx, params).await {
                error_count += 1;
                warn!("hyperlane watcher submit failed path={} total_errors={} error={}", path.display(), error_count, err);
                continue;
            }

            let mut done_path = path.clone();
            done_path.set_extension("done");
            if let Err(err) = fs::rename(&path, &done_path).await {
                error_count += 1;
                warn!("hyperlane watcher rename failed path={} total_errors={} error={}", path.display(), error_count, err);
                continue;
            }

            processed_count += 1;
            info!(
                "Hyperlane message processed file={} total_processed={}",
                done_path.file_name().unwrap_or_default().to_string_lossy(),
                processed_count
            );
        }
        tokio::time::sleep(poll_interval).await;
    }
}
