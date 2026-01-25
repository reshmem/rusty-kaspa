//! Result/Option helper traits.
//!
//! This module provides a small extension trait that makes it easier to work with
//! `Result<Option<T>>` values returned by storage layers.

use crate::foundation::ThresholdError;

/// Extension for converting `Result<Option<T>>` into `Result<T>`.
pub trait ResultExt<T> {
    /// Convert `Ok(None)` into an error.
    fn required(self, error: impl FnOnce() -> ThresholdError) -> Result<T, ThresholdError>;
}

impl<T> ResultExt<T> for Result<Option<T>, ThresholdError> {
    fn required(self, error: impl FnOnce() -> ThresholdError) -> Result<T, ThresholdError> {
        self?.ok_or_else(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_passes_through_some() {
        let result: Result<Option<u32>, ThresholdError> = Ok(Some(42));
        let value = result.required(|| ThresholdError::StorageError { operation: "test".into(), details: "missing".into() });
        assert_eq!(value.expect("some"), 42);
    }

    #[test]
    fn required_converts_none_to_error() {
        let result: Result<Option<u32>, ThresholdError> = Ok(None);
        let err = result
            .required(|| ThresholdError::StorageError { operation: "test".into(), details: "missing".into() })
            .expect_err("none -> err");
        assert!(matches!(err, ThresholdError::StorageError { .. }));
    }
}
