//! LWW-Register (Last-Writer-Wins Register) CRDT implementation.

use serde::{Deserialize, Serialize};

/// A Last-Writer-Wins Register CRDT.
///
/// Stores a single value with a timestamp. During merge, the value with the higher timestamp wins.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LWWRegister<T: Clone> {
    value: Option<T>,
    timestamp: u64,
}

impl<T: Clone> Default for LWWRegister<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> LWWRegister<T> {
    /// Create a new empty LWW-Register.
    pub fn new() -> Self {
        Self { value: None, timestamp: 0 }
    }

    /// Create a LWW-Register with an initial value.
    pub fn with_value(value: T, timestamp: u64) -> Self {
        Self { value: Some(value), timestamp }
    }

    /// Get the current value.
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Get the current timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Set a new value if timestamp is greater than current.
    /// Returns true if the value was updated.
    pub fn set(&mut self, value: T, timestamp: u64) -> bool {
        if timestamp > self.timestamp {
            self.value = Some(value);
            self.timestamp = timestamp;
            true
        } else {
            false
        }
    }

    /// Merge another register into this one.
    /// Returns true if this register was updated.
    pub fn merge(&mut self, other: &LWWRegister<T>) -> bool {
        if other.timestamp > self.timestamp {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_with_higher_timestamp() {
        let mut reg = LWWRegister::new();

        assert!(reg.set("first", 100));
        assert_eq!(reg.value(), Some(&"first"));

        assert!(reg.set("second", 200));
        assert_eq!(reg.value(), Some(&"second"));
    }

    #[test]
    fn test_set_with_lower_timestamp_ignored() {
        let mut reg = LWWRegister::with_value("initial", 200);

        assert!(!reg.set("older", 100));
        assert_eq!(reg.value(), Some(&"initial"));
    }

    #[test]
    fn test_merge() {
        let mut a = LWWRegister::with_value("a", 100);
        let b = LWWRegister::with_value("b", 200);

        assert!(a.merge(&b));
        assert_eq!(a.value(), Some(&"b"));
        assert_eq!(a.timestamp(), 200);
    }

    #[test]
    fn test_merge_older_ignored() {
        let mut a = LWWRegister::with_value("a", 200);
        let b = LWWRegister::with_value("b", 100);

        assert!(!a.merge(&b));
        assert_eq!(a.value(), Some(&"a"));
    }

    #[test]
    fn test_merge_is_commutative_idempotent() {
        let a = LWWRegister::with_value("a", 100);
        let b = LWWRegister::with_value("b", 200);

        let mut ab = a.clone();
        ab.merge(&b);

        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.value(), ba.value());
        assert_eq!(ab.value(), Some(&"b"));
    }
}
