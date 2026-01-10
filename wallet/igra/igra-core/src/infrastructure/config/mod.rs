mod encryption;
mod loader;
mod types;
mod validation;

pub use loader::{load_config, load_config_from_file, load_config_from_file_with_profile, load_config_with_profile};
pub use types::*;

use crate::foundation::ThresholdError;
use crate::foundation::{derive_pubkeys, redeem_script_from_pubkeys, HdInputs};
use kaspa_wallet_core::prelude::Secret;
use std::path::{Path, PathBuf};

pub fn load_app_config() -> Result<AppConfig, ThresholdError> {
    let data_dir = resolve_data_dir()?;
    let config_path = resolve_config_path(&data_dir)?;
    let config = load_config_from_file(&config_path, &data_dir)?;
    config.validate().map_err(|errors| ThresholdError::ConfigError(format!("validation failed: {:?}", errors)))?;
    Ok(config)
}

pub fn derive_redeem_script_hex(hd: &PsktHdConfig, derivation_path: &str) -> Result<String, ThresholdError> {
    let key_data = hd.decrypt_mnemonics()?;
    let payment_secret = hd.passphrase.as_deref().map(Secret::from);
    let inputs = HdInputs { key_data: &key_data, xpubs: &hd.xpubs, derivation_path, payment_secret: payment_secret.as_ref() };
    let pubkeys = derive_pubkeys(inputs)?;
    if pubkeys.is_empty() {
        return Err(ThresholdError::Message("no HD pubkeys configured".to_string()));
    }
    let redeem = redeem_script_from_pubkeys(&pubkeys, hd.required_sigs)?;
    Ok(hex::encode(redeem))
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

pub const HD_WALLET_SECRET_ENV: &str = "KASPA_IGRA_WALLET_SECRET";
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
    let cwd = std::env::current_dir().map_err(|err| ThresholdError::Message(err.to_string()))?;
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
