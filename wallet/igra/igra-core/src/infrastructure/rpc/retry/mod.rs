use crate::foundation::ThresholdError;
use log::debug;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Retry an async operation with fixed delay/backoff.
pub async fn retry<F, Fut, T>(mut attempts: usize, delay: Duration, mut op: F) -> Result<T, ThresholdError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ThresholdError>>,
{
    let initial_attempts = attempts;
    let mut last_err = None;
    while attempts > 0 {
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) => {
                let attempt_no = initial_attempts.saturating_sub(attempts).saturating_add(1);
                debug!(
                    "retryable operation failed attempt={} remaining={} delay_ms={} error={}",
                    attempt_no,
                    attempts.saturating_sub(1),
                    delay.as_millis(),
                    err
                );
                last_err = Some(err);
                attempts -= 1;
                if attempts > 0 {
                    sleep(delay).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| ThresholdError::NodeRpcError(format!("retry exhausted after {} attempts", initial_attempts))))
}
