mod loader;
mod types;
pub mod validation;

pub use loader::{load_config, load_config_from_file, load_config_from_file_with_profile, load_config_with_profile};
pub use types::*;

use crate::foundation::ThresholdError;
use crate::foundation::{derive_pubkeys, redeem_script_from_pubkeys, HdInputs};
use crate::infrastructure::network_mode::NetworkMode;
use kaspa_addresses::Prefix;
use kaspa_txscript::standard::{extract_script_pub_key_address, pay_to_script_hash_script};
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use std::path::{Path, PathBuf};

/// Validate a signer profile name in the canonical `signer-XX` format (01-99).
///
/// Returns the 1-based signer index (`signer-01` -> 1).
pub fn validate_signer_profile(profile: &str) -> Result<u8, ThresholdError> {
    let trimmed = profile.trim();
    let suffix = trimmed
        .strip_prefix("signer-")
        .ok_or_else(|| ThresholdError::ConfigError(format!("profile must match signer-XX (01-99): got '{trimmed}'")))?;
    if suffix.len() != 2 {
        return Err(ThresholdError::ConfigError(format!("profile must match signer-XX (01-99): got '{trimmed}'")));
    }
    let digits_ok = suffix.as_bytes().iter().all(|b| b.is_ascii_digit());
    if !digits_ok {
        return Err(ThresholdError::ConfigError(format!("profile must match signer-XX (01-99): got '{trimmed}'")));
    }
    let index: u8 =
        suffix.parse().map_err(|_| ThresholdError::ConfigError(format!("profile must match signer-XX (01-99): got '{trimmed}'")))?;
    if index == 0 || index > 99 {
        return Err(ThresholdError::ConfigError(format!("profile must match signer-XX (01-99): got '{trimmed}'")));
    }
    Ok(index)
}

pub fn signer_profile_name(index_1_based: u8) -> Result<String, ThresholdError> {
    if index_1_based == 0 || index_1_based > 99 {
        return Err(ThresholdError::ConfigError(format!("signer index out of range: {index_1_based}")));
    }
    Ok(format!("signer-{index_1_based:02}"))
}

pub fn load_app_config() -> Result<AppConfig, ThresholdError> {
    let data_dir = resolve_data_dir()?;
    let config_path = resolve_config_path(&data_dir)?;
    let config = load_config_from_file(&config_path, &data_dir)?;
    config.validate().map_err(|errors| ThresholdError::ConfigError(format!("validation failed: {:?}", errors)))?;
    Ok(config)
}

pub fn derive_redeem_script_hex(
    hd: &PsktHdConfig,
    key_data: &[PrvKeyData],
    derivation_path: Option<&str>,
    payment_secret: Option<&Secret>,
) -> Result<String, ThresholdError> {
    let inputs = HdInputs { key_data, xpubs: &hd.xpubs, derivation_path, payment_secret };
    let mut pubkeys = derive_pubkeys(inputs)?;
    if pubkeys.is_empty() {
        return Err(ThresholdError::ConfigError("no HD pubkeys configured".to_string()));
    }
    pubkeys.sort_by_key(|key| key.serialize());
    let redeem = redeem_script_from_pubkeys(&pubkeys, hd.required_sigs)?;
    Ok(hex::encode(redeem))
}

pub fn pskt_source_address_from_redeem_script_hex(mode: NetworkMode, redeem_script_hex: &str) -> Result<String, ThresholdError> {
    let redeem_hex = redeem_script_hex.trim();
    if redeem_hex.is_empty() {
        return Err(ThresholdError::ConfigError("missing service.pskt.redeem_script_hex".to_string()));
    }
    let redeem_script = hex::decode(redeem_hex)?;
    let spk = pay_to_script_hash_script(&redeem_script);

    let prefix = match mode {
        NetworkMode::Mainnet => Prefix::Mainnet,
        NetworkMode::Testnet => Prefix::Testnet,
        NetworkMode::Devnet => Prefix::Devnet,
    };
    let addr = extract_script_pub_key_address(&spk, prefix)
        .map_err(|err| ThresholdError::PsktError { operation: "pskt_source_address".to_string(), details: err.to_string() })?;
    Ok(addr.to_string())
}

pub fn load_app_config_from_path(path: &Path) -> Result<AppConfig, ThresholdError> {
    let data_dir = resolve_data_dir()?;
    let config = load_config_from_file(path, &data_dir)?;
    config.validate().map_err(|errors| ThresholdError::ConfigError(format!("validation failed: {:?}", errors)))?;
    Ok(config)
}

pub fn load_app_config_from_profile_path(path: &Path, profile: &str) -> Result<AppConfig, ThresholdError> {
    let data_dir = resolve_data_dir()?;
    let config = load_config_from_file_with_profile(path, &data_dir, profile)?;
    config.validate().map_err(|errors| ThresholdError::ConfigError(format!("validation failed: {:?}", errors)))?;
    Ok(config)
}

pub const CONFIG_PATH_ENV: &str = "KASPA_CONFIG_PATH";
pub const DATA_DIR_ENV: &str = "KASPA_DATA_DIR";
pub const TEST_NOW_NANOS_ENV: &str = "KASPA_IGRA_TEST_NOW_NANOS";
pub const FINALIZE_PSKT_JSON_ENV: &str = "KASPA_FINALIZE_PSKT_JSON";
pub const AUDIT_REQUEST_ID_ENV: &str = "KASPA_AUDIT_REQUEST_ID";

pub fn resolve_config_path(data_dir: &Path) -> Result<PathBuf, ThresholdError> {
    if let Ok(value) = std::env::var(CONFIG_PATH_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    Ok(data_dir.join("igra-config.toml"))
}

pub fn resolve_data_dir() -> Result<PathBuf, ThresholdError> {
    if let Ok(data_dir) = std::env::var(DATA_DIR_ENV) {
        let trimmed = data_dir.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let cwd = std::env::current_dir()
        .map_err(|err| ThresholdError::StorageError { operation: "env::current_dir".to_string(), details: err.to_string() })?;
    Ok(cwd.join(".igra"))
}

pub fn get_audit_request_id() -> Option<String> {
    std::env::var(AUDIT_REQUEST_ID_ENV).ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

pub fn get_finalize_pskt_json_path() -> Option<PathBuf> {
    std::env::var(FINALIZE_PSKT_JSON_ENV).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    })
}
