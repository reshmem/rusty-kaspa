use crate::foundation::ThresholdError;
use std::str::FromStr;

/// Parse required config option (returns error if `None` or empty).
pub fn parse_required<T>(opt: &Option<String>, field: &str) -> Result<T, ThresholdError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    opt.as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ThresholdError::ConfigError(format!("missing {}", field)))?
        .parse()
        .map_err(|err| ThresholdError::ConfigError(format!("invalid {}: {}", field, err)))
}

/// Parse optional config (returns `Ok(None)` if `None` or empty).
pub fn parse_optional<T>(opt: &Option<String>) -> Result<Option<T>, ThresholdError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match opt.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(value) => Ok(Some(value.parse().map_err(|err| ThresholdError::ConfigError(format!("parse error: {}", err)))?)),
        None => Ok(None),
    }
}

/// Parse required config with default value.
pub fn parse_or_default<T>(opt: &Option<String>, default: T) -> T
where
    T: FromStr,
{
    opt.as_deref().and_then(|s| s.trim().parse().ok()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::EventId;

    #[test]
    fn parse_required_rejects_missing_and_empty() {
        assert!(parse_required::<EventId>(&None, "event_id").is_err());
        assert!(parse_required::<EventId>(&Some("".to_string()), "event_id").is_err());
        assert!(parse_required::<EventId>(&Some("   ".to_string()), "event_id").is_err());
    }

    #[test]
    fn parse_optional_treats_missing_and_empty_as_none() {
        assert!(matches!(parse_optional::<EventId>(&None).unwrap(), None));
        assert!(matches!(parse_optional::<EventId>(&Some("".to_string())).unwrap(), None));
        assert!(matches!(parse_optional::<EventId>(&Some("  ".to_string())).unwrap(), None));
    }

    #[test]
    fn parse_required_parses_hex_id() {
        let value = Some("0x0101010101010101010101010101010101010101010101010101010101010101".to_string());
        let parsed: EventId = parse_required(&value, "event_id").expect("parse");
        assert_eq!(format!("{:#x}", parsed), "0x0101010101010101010101010101010101010101010101010101010101010101");
    }
}
