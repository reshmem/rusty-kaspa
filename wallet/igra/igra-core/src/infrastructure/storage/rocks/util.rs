//! Utility helpers for RocksDB-backed storage.

use crate::foundation::{ThresholdError, STORAGE_LOCK_TIMEOUT_SECS};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

const DEFAULT_LOCK_POLL_INTERVAL_MS: u64 = 10;

pub fn acquire_with_timeout<'a, T>(lock: &'a Mutex<T>, operation: &'static str) -> Result<MutexGuard<'a, T>, ThresholdError> {
    acquire_with_timeout_for(lock, operation, Duration::from_secs(STORAGE_LOCK_TIMEOUT_SECS))
}

pub fn acquire_with_timeout_for<'a, T>(
    lock: &'a Mutex<T>,
    operation: &'static str,
    timeout: Duration,
) -> Result<MutexGuard<'a, T>, ThresholdError> {
    let start = Instant::now();
    loop {
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => {
                return Err(ThresholdError::StorageError { operation: operation.to_string(), details: "mutex poisoned".to_string() });
            }
            Err(TryLockError::WouldBlock) => {
                if start.elapsed() >= timeout {
                    return Err(ThresholdError::StorageLockTimeout {
                        operation: operation.to_string(),
                        timeout_secs: STORAGE_LOCK_TIMEOUT_SECS,
                    });
                }
                std::thread::sleep(Duration::from_millis(DEFAULT_LOCK_POLL_INTERVAL_MS));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn acquire_with_timeout_succeeds() {
        let lock = Mutex::new(());
        let guard = acquire_with_timeout_for(&lock, "test", Duration::from_millis(50));
        assert!(guard.is_ok());
    }

    #[test]
    fn acquire_with_timeout_times_out() {
        let lock = Arc::new(Mutex::new(()));
        let _held = lock.lock().expect("test setup: lock held");

        let err = acquire_with_timeout_for(&lock, "test", Duration::from_millis(25)).expect_err("times out");
        assert!(matches!(err, ThresholdError::StorageLockTimeout { .. }));
    }
}
