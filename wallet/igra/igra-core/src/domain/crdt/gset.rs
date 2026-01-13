//! G-Set (Grow-only Set) CRDT implementation.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::Hash;

/// A Grow-only Set CRDT.
///
/// Elements can only be added, never removed.
/// Merge operation is set union.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GSet<T: Clone + Eq + Hash> {
    elements: HashSet<T>,
}

impl<T: Clone + Eq + Hash> GSet<T> {
    /// Create a new empty G-Set.
    pub fn new() -> Self {
        Self { elements: HashSet::new() }
    }

    /// Create a G-Set from an iterator.
    pub fn from_iter(iter: impl IntoIterator<Item = T>) -> Self {
        Self { elements: iter.into_iter().collect() }
    }

    /// Add an element to the set.
    /// Returns true if the element was newly inserted.
    pub fn add(&mut self, element: T) -> bool {
        self.elements.insert(element)
    }

    /// Check if the set contains an element.
    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains(element)
    }

    /// Get the number of elements.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Iterate over elements.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.elements.iter()
    }

    /// Merge another G-Set into this one (union operation).
    /// Returns the number of new elements added.
    pub fn merge(&mut self, other: &GSet<T>) -> usize {
        let before = self.elements.len();
        self.elements.extend(other.elements.iter().cloned());
        self.elements.len() - before
    }

    /// Create a merged G-Set without mutating either input.
    pub fn merged_with(&self, other: &GSet<T>) -> GSet<T> {
        let mut result = self.clone();
        result.merge(other);
        result
    }
}

impl<T: Clone + Eq + Hash> IntoIterator for GSet<T> {
    type Item = T;
    type IntoIter = std::collections::hash_set::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_contains() {
        let mut set = GSet::new();
        assert!(set.add(1));
        assert!(set.add(2));
        assert!(!set.add(1));

        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(!set.contains(&3));
    }

    #[test]
    fn test_merge_is_commutative() {
        let mut a = GSet::from_iter(vec![1, 2, 3]);
        let b = GSet::from_iter(vec![3, 4, 5]);

        let mut c = GSet::from_iter(vec![3, 4, 5]);
        let d = GSet::from_iter(vec![1, 2, 3]);

        a.merge(&b);
        c.merge(&d);

        assert_eq!(a.len(), c.len());
        for elem in a.iter() {
            assert!(c.contains(elem));
        }
    }

    #[test]
    fn test_merge_is_idempotent() {
        let mut a = GSet::from_iter(vec![1, 2, 3]);
        let b = a.clone();

        let added = a.merge(&b);

        assert_eq!(added, 0);
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn test_merge_is_associative() {
        let a = GSet::from_iter(vec![1, 2]);
        let b = GSet::from_iter(vec![2, 3]);
        let c = GSet::from_iter(vec![3, 4]);

        let mut ab = a.clone();
        ab.merge(&b);
        ab.merge(&c);

        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        assert_eq!(ab.len(), a_bc.len());
        for elem in ab.iter() {
            assert!(a_bc.contains(elem));
        }
    }
}

