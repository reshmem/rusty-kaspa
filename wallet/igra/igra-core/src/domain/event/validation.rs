use crate::domain::hashes::event_hash;
use crate::domain::SigningEvent;
use crate::foundation::derivation_path_from_index;
use crate::foundation::error::ThresholdError;
use crate::foundation::{PeerId, RequestId, SessionId};

use super::types::{SigningEventParams, SigningEventWire};

pub fn decode_session_and_request_ids(params: &SigningEventParams) -> Result<(SessionId, RequestId, PeerId), ThresholdError> {
    let session_id = SessionId::from(decode_hash32(&params.session_id_hex)?);
    let request_id = validate_id("request_id", params.request_id.as_str())?;
    let coordinator_peer_id = validate_peer_id("coordinator_peer_id", params.coordinator_peer_id.as_str())?;
    Ok((session_id, request_id, coordinator_peer_id))
}

#[derive(Debug, Clone)]
pub struct EventParsingResult {
    pub event: SigningEvent,
    pub derivation_path_source: DerivationPathSource,
    pub signature_source: SignatureSource,
}

#[derive(Debug, Clone, Copy)]
pub enum DerivationPathSource {
    ExplicitPath,
    DerivedFromIndex { index: u32 },
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureSource {
    HexField,
    BinaryField,
    None,
}

pub fn into_signing_event(wire: SigningEventWire) -> Result<EventParsingResult, ThresholdError> {
    let SigningEventWire {
        event_id,
        event_source,
        derivation_path,
        derivation_index,
        destination_address,
        amount_sompi,
        metadata,
        timestamp_nanos,
        signature_hex,
        signature,
    } = wire;

    let (derivation_path_source, derivation_path) = resolve_derivation_path(&derivation_path, derivation_index)?;
    let (signature_source, signature) = if let Some(hex_value) = signature_hex {
        let bytes = hex::decode(hex_value.trim())?;
        (SignatureSource::HexField, Some(bytes))
    } else {
        match signature {
            Some(bytes) => (SignatureSource::BinaryField, Some(bytes)),
            None => (SignatureSource::None, None),
        }
    };
    let event = SigningEvent {
        event_id,
        event_source,
        derivation_path,
        derivation_index,
        destination_address,
        amount_sompi,
        metadata,
        timestamp_nanos,
        signature,
    };
    // ensure hashable without error
    event_hash(&event)?;
    Ok(EventParsingResult { event, derivation_path_source, signature_source })
}

fn decode_hash32(value: &str) -> Result<[u8; 32], ThresholdError> {
    let trimmed = value.trim();
    let stripped = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    let bytes = hex::decode(stripped).map_err(|e| ThresholdError::Message(format!("invalid hex '{trimmed}': {e}")))?;
    let array: [u8; 32] =
        bytes.as_slice().try_into().map_err(|_| ThresholdError::Message(format!("expected 32 bytes, got {}", bytes.len())))?;
    Ok(array)
}

fn resolve_derivation_path(path: &str, index: Option<u32>) -> Result<(DerivationPathSource, String), ThresholdError> {
    let trimmed = path.trim();
    if let Some(index) = index {
        let expected = derivation_path_from_index(index);
        if trimmed.is_empty() {
            return Ok((DerivationPathSource::DerivedFromIndex { index }, expected));
        }
        let normalized = normalize_derivation_path(trimmed)?;
        if normalized != expected {
            return Err(ThresholdError::InvalidDerivationPath(format!(
                "derivation_path '{}' does not match derivation_index {} (expected '{}')",
                trimmed, index, expected
            )));
        }
        return Ok((DerivationPathSource::DerivedFromIndex { index }, expected));
    }
    if trimmed.is_empty() {
        return Err(ThresholdError::Message("missing derivation_path (or derivation_index)".to_string()));
    }
    Ok((DerivationPathSource::ExplicitPath, normalize_derivation_path(trimmed)?))
}

fn validate_id(label: &str, value: &str) -> Result<RequestId, ThresholdError> {
    const MAX_LEN: usize = 256;
    if value.len() > MAX_LEN {
        return Err(ThresholdError::Message(format!("{label} too long: {} > {}", value.len(), MAX_LEN)));
    }
    Ok(RequestId::from(value))
}

fn validate_peer_id(label: &str, value: &str) -> Result<PeerId, ThresholdError> {
    const MAX_LEN: usize = 256;
    if value.len() > MAX_LEN {
        return Err(ThresholdError::Message(format!("{label} too long: {} > {}", value.len(), MAX_LEN)));
    }
    Ok(PeerId::from(value))
}

fn normalize_derivation_path(path: &str) -> Result<String, ThresholdError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    let mut parts = trimmed.split('/').map(str::trim);
    let root = parts.next().unwrap_or_default();
    if root != "m" {
        return Err(ThresholdError::InvalidDerivationPath(format!("invalid derivation path: '{trimmed}'")));
    }

    let mut normalized_parts = Vec::new();
    normalized_parts.push("m".to_string());

    for part in parts {
        if part.is_empty() {
            return Err(ThresholdError::InvalidDerivationPath(format!("invalid derivation path: '{trimmed}'")));
        }

        let (value, hardened) = if let Some(value) = part.strip_suffix('\'') {
            (value, true)
        } else if let Some(value) = part.strip_suffix('h') {
            (value, true)
        } else if let Some(value) = part.strip_suffix('H') {
            (value, true)
        } else {
            (part, false)
        };

        if value.parse::<u32>().is_err() {
            return Err(ThresholdError::InvalidDerivationPath(format!("invalid derivation path: '{trimmed}'")));
        }

        if hardened {
            normalized_parts.push(format!("{value}'"));
        } else {
            normalized_parts.push(value.to_string());
        }
    }

    if normalized_parts.len() == 1 {
        return Err(ThresholdError::InvalidDerivationPath("derivation path must include at least one segment".to_string()));
    }

    Ok(normalized_parts.join("/"))
}
