//! Application-layer facade for CRDT-related domain logic and types.
//!
//! The goal is to keep `igra-service` depending on `igra-core::application` APIs, not directly
//! on `igra-core::domain` internals, while still delegating the pure logic to the domain layer.

use crate::foundation::{EventId, ThresholdError};
use std::collections::BTreeMap;

pub use crate::domain::{CrdtSigningMaterial, PartialSigRecord, StoredEvent};

pub struct CrdtOperations;

impl CrdtOperations {
    pub fn compute_event_id(event: &crate::domain::Event) -> EventId {
        crate::domain::hashes::compute_event_id(event)
    }

    pub fn validate_source_data(source_data: &BTreeMap<String, String>) -> Result<(), ThresholdError> {
        crate::domain::normalization::validate_source_data(source_data)
    }
}
