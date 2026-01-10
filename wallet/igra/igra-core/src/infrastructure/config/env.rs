use crate::infrastructure::config::types::AppConfig;
use crate::foundation::ThresholdError;
use std::path::{Path, PathBuf};

pub const HD_WALLET_SECRET_ENV: &str = "KASPA_IGRA_WALLET_SECRET";
pub const CONFIG_PATH_ENV: &str = "KASPA_CONFIG_PATH";
pub const DATA_DIR_ENV: &str = "KASPA_DATA_DIR";
pub const TEST_NOW_NANOS_ENV: &str = "KASPA_IGRA_TEST_NOW_NANOS";
pub const NODE_URL_ENV: &str = "KASPA_NODE_URL";
pub const FINALIZE_PSKT_JSON_ENV: &str = "KASPA_FINALIZE_PSKT_JSON";
pub const AUDIT_REQUEST_ID_ENV: &str = "KASPA_AUDIT_REQUEST_ID";

pub fn resolve_config_path(data_dir: &Path) -> Result<PathBuf, ThresholdError> {
    if let Ok(value) = std::env::var(CONFIG_PATH_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let ini_path = data_dir.join("igra-config.ini");
    if ini_path.exists() {
        return Ok(ini_path);
    }
    let toml_path = data_dir.join("igra-config.toml");
    if toml_path.exists() {
        return Ok(toml_path);
    }
    Ok(ini_path)
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

pub fn apply_env_overrides(config: &mut AppConfig) -> Result<(), ThresholdError> {
    if let Ok(url) = std::env::var(NODE_URL_ENV) {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            config.service.node_rpc_url = trimmed.to_string();
        }
    }
    if let Ok(dir) = std::env::var(DATA_DIR_ENV) {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            config.service.data_dir = trimmed.to_string();
        }
    }
    Ok(())
}
