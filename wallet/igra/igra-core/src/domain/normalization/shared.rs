use crate::foundation::{ExternalId, ThresholdError};
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_address_script;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub enum ExpectedNetwork {
    Any,
    Prefix(Prefix),
}

impl ExpectedNetwork {
    pub fn from_network_id(network_id: u8) -> Self {
        // Keep mapping consistent with `igra-service/src/service/coordination/helpers.rs:17`.
        let prefix = match network_id {
            0 => Prefix::Mainnet,
            2 => Prefix::Devnet,
            3 => Prefix::Simnet,
            _ => Prefix::Testnet,
        };
        ExpectedNetwork::Prefix(prefix)
    }
}

pub fn parse_external_id(raw: &str) -> Result<ExternalId, ThresholdError> {
    let trimmed = raw.trim();
    if trimmed.len() > crate::foundation::constants::MAX_EXTERNAL_ID_RAW_LENGTH {
        return Err(ThresholdError::InvalidExternalId(format!(
            "external id too long: {} > {}",
            trimmed.len(),
            crate::foundation::constants::MAX_EXTERNAL_ID_RAW_LENGTH
        )));
    }
    let stripped = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if stripped.len() != 64 {
        return Err(ThresholdError::InvalidExternalId(format!("expected 32-byte hex, got len={}", stripped.len())));
    }
    let bytes = hex::decode(stripped).map_err(|e| ThresholdError::InvalidExternalId(format!("invalid hex: {e}")))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ThresholdError::InvalidExternalId(format!("expected 32 bytes, got {}", bytes.len())))?;
    Ok(ExternalId::from(array))
}

/// Canonicalize an external identifier that may not already be 32-byte hex.
///
/// - If it looks like 32-byte hex (with optional 0x prefix), use it as-is.
/// - Otherwise, hash the raw string under an explicit domain separator.
pub fn canonical_external_id_from_raw(raw: &str) -> Result<ExternalId, ThresholdError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ThresholdError::InvalidExternalId("external id is empty".to_string()));
    }
    if trimmed.len() > crate::foundation::constants::MAX_EXTERNAL_ID_RAW_LENGTH {
        return Err(ThresholdError::InvalidExternalId(format!(
            "external id too long: {} > {}",
            trimmed.len(),
            crate::foundation::constants::MAX_EXTERNAL_ID_RAW_LENGTH
        )));
    }
    if let Ok(id) = parse_external_id(trimmed) {
        return Ok(id);
    }
    const DOMAIN: &[u8] = b"igra:external_id:v1:";
    let mut buf = Vec::with_capacity(DOMAIN.len() + trimmed.len());
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(trimmed.as_bytes());
    Ok(ExternalId::from(*blake3::hash(&buf).as_bytes()))
}

pub fn parse_destination(expected: ExpectedNetwork, raw: &str) -> Result<ScriptPublicKey, ThresholdError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ThresholdError::InvalidDestination("destination address is empty".to_string()));
    }
    if trimmed.len() > crate::foundation::constants::MAX_ADDRESS_LENGTH {
        return Err(ThresholdError::InvalidDestination(format!(
            "destination address too long: {} > {}",
            trimmed.len(),
            crate::foundation::constants::MAX_ADDRESS_LENGTH
        )));
    }

    let addr = Address::constructor(trimmed);
    if let ExpectedNetwork::Prefix(prefix) = expected {
        if addr.prefix != prefix {
            return Err(ThresholdError::InvalidDestination(format!(
                "address prefix mismatch: expected {:?}, got {:?}",
                prefix, addr.prefix
            )));
        }
    }
    Ok(pay_to_address_script(&addr))
}

pub fn validate_source_data(source_data: &BTreeMap<String, String>) -> Result<(), ThresholdError> {
    if source_data.len() > crate::foundation::constants::MAX_EVENT_METADATA_KEYS {
        return Err(ThresholdError::MessageTooLarge {
            size: source_data.len(),
            max: crate::foundation::constants::MAX_EVENT_METADATA_KEYS,
        });
    }

    let mut total_bytes = 0usize;
    for (key, value) in source_data {
        if key.len() > crate::foundation::constants::MAX_EVENT_METADATA_KEY_LENGTH {
            return Err(ThresholdError::MessageTooLarge {
                size: key.len(),
                max: crate::foundation::constants::MAX_EVENT_METADATA_KEY_LENGTH,
            });
        }
        if value.len() > crate::foundation::constants::MAX_EVENT_METADATA_VALUE_LENGTH {
            return Err(ThresholdError::MessageTooLarge {
                size: value.len(),
                max: crate::foundation::constants::MAX_EVENT_METADATA_VALUE_LENGTH,
            });
        }
        total_bytes = total_bytes.saturating_add(key.len().saturating_add(value.len()));
        if total_bytes > crate::foundation::constants::MAX_EVENT_METADATA_SIZE {
            return Err(ThresholdError::MessageTooLarge {
                size: total_bytes,
                max: crate::foundation::constants::MAX_EVENT_METADATA_SIZE,
            });
        }
    }

    Ok(())
}
