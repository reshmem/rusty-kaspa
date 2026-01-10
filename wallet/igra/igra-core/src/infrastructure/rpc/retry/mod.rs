use crate::foundation::ThresholdError;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Retry an async operation with fixed delay/backoff.
pub async fn retry<F, Fut, T>(mut attempts: usize, delay: Duration, mut op: F) -> Result<T, ThresholdError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ThresholdError>>,
{
    let mut last_err = None;
    while attempts > 0 {
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) => {
                last_err = Some(err);
                attempts -= 1;
                if attempts > 0 {
                    sleep(delay).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| ThresholdError::Message("retry exhausted".to_string())))
}
