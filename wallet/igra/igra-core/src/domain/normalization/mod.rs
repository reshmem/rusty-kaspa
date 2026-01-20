//! Event normalization - converts external messages into canonical domain events.
//!
//! DESIGN PRINCIPLE: Normalization is pure and deterministic.
//! - No timestamps (caller adds those in StoredEvent)
//! - No I/O
//! - No local configuration except explicit parameters passed in

pub mod hyperlane;
mod shared;

pub use shared::validate_source_data;
pub use shared::{canonical_external_id_from_raw, parse_destination, parse_external_id, ExpectedNetwork};

use crate::domain::{Event, EventAuditData, SourceType, StoredEvent};
use crate::foundation::{EventId, ThresholdError};

pub struct NormalizationResult {
    pub event_id: EventId,
    pub event: Event,
    pub audit: EventAuditData,
    pub proof: Option<Vec<u8>>,
}

impl NormalizationResult {
    pub fn into_stored(self, received_at_nanos: u64) -> StoredEvent {
        StoredEvent { event: self.event, received_at_nanos, audit: self.audit, proof: self.proof }
    }
}

pub fn normalize_api(
    expected_network: ExpectedNetwork,
    external_id_raw: &str,
    destination_raw: &str,
    amount_sompi: u64,
    source_data: std::collections::BTreeMap<String, String>,
) -> Result<NormalizationResult, ThresholdError> {
    shared::validate_source_data(&source_data)?;
    let external_id = canonical_external_id_from_raw(external_id_raw)?;
    let destination = parse_destination(expected_network, destination_raw)?;

    let event = Event { external_id, source: SourceType::Api, destination, amount_sompi };
    let event_id = crate::domain::hashes::compute_event_id(&event);

    Ok(NormalizationResult {
        event_id,
        event,
        audit: EventAuditData {
            external_id_raw: external_id_raw.trim().to_string(),
            destination_raw: destination_raw.trim().to_string(),
            source_data,
        },
        proof: None,
    })
}

pub fn normalize_generic(
    expected_network: ExpectedNetwork,
    source: SourceType,
    external_id_raw: &str,
    destination_raw: &str,
    amount_sompi: u64,
    source_data: std::collections::BTreeMap<String, String>,
    proof: Option<Vec<u8>>,
) -> Result<NormalizationResult, ThresholdError> {
    shared::validate_source_data(&source_data)?;
    let external_id = canonical_external_id_from_raw(external_id_raw)?;
    let destination = parse_destination(expected_network, destination_raw)?;

    let event = Event { external_id, source, destination, amount_sompi };
    let event_id = crate::domain::hashes::compute_event_id(&event);

    Ok(NormalizationResult {
        event_id,
        event,
        audit: EventAuditData {
            external_id_raw: external_id_raw.trim().to_string(),
            destination_raw: destination_raw.trim().to_string(),
            source_data,
        },
        proof,
    })
}
