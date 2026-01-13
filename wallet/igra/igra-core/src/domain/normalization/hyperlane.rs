use super::shared::{parse_destination, parse_external_id, validate_source_data, ExpectedNetwork};
use super::NormalizationResult;
use crate::domain::{Event, EventAuditData, SourceType};
use crate::foundation::ThresholdError;
use std::collections::BTreeMap;

pub fn normalize_hyperlane(
    expected_network: ExpectedNetwork,
    message_id_raw: &str,
    origin_domain: u32,
    destination_raw: &str,
    amount_sompi: u64,
    source_data: BTreeMap<String, String>,
    proof: Option<Vec<u8>>,
) -> Result<NormalizationResult, ThresholdError> {
    validate_source_data(&source_data)?;
    let external_id = parse_external_id(message_id_raw)?;
    let destination = parse_destination(expected_network, destination_raw)?;

    let event = Event { external_id, source: SourceType::Hyperlane { origin_domain }, destination, amount_sompi };
    let event_id = crate::domain::hashes::compute_event_id(&event);

    Ok(NormalizationResult {
        event_id,
        event,
        audit: EventAuditData {
            external_id_raw: message_id_raw.trim().to_string(),
            destination_raw: destination_raw.trim().to_string(),
            source_data,
        },
        proof,
    })
}
