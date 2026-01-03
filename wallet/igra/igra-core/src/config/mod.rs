mod env;
mod encryption;
mod loader;
mod persistence;
mod types;
mod validation;

pub use env::{
    get_audit_request_id, get_finalize_pskt_json_path, AUDIT_REQUEST_ID_ENV, CONFIG_PATH_ENV, DATA_DIR_ENV,
    FINALIZE_PSKT_JSON_ENV, HD_WALLET_SECRET_ENV, NODE_URL_ENV, TEST_NOW_NANOS_ENV,
};
pub use types::*;

use crate::error::ThresholdError;
use crate::hd::{derive_pubkeys, redeem_script_from_pubkeys, HdInputs};
use kaspa_wallet_core::prelude::Secret;
use std::path::Path;

pub fn load_app_config() -> Result<AppConfig, ThresholdError> {
    let data_dir = env::resolve_data_dir()?;
    if let Some(config) = persistence::load_config_from_db(&data_dir)? {
        let mut config = config;
        env::apply_env_overrides(&mut config)?;
        return Ok(config);
    }

    let path = env::resolve_config_path(&data_dir)?;
    let mut config = load_from_path(&path, &data_dir)?;
    env::apply_env_overrides(&mut config)?;
    persistence::store_config_in_db(&data_dir, &config)?;
    Ok(config)
}

pub fn derive_redeem_script_hex(hd: &PsktHdConfig, derivation_path: &str) -> Result<String, ThresholdError> {
    let key_data = hd.decrypt_mnemonics()?;
    let payment_secret = hd.passphrase.as_deref().map(Secret::from);
    let inputs = HdInputs {
        key_data: &key_data,
        xpubs: &hd.xpubs,
        derivation_path,
        payment_secret: payment_secret.as_ref(),
    };
    let pubkeys = derive_pubkeys(inputs)?;
    if pubkeys.is_empty() {
        return Err(ThresholdError::Message("no HD pubkeys configured".to_string()));
    }
    let redeem = redeem_script_from_pubkeys(&pubkeys, hd.required_sigs)?;
    Ok(hex::encode(redeem))
}

pub fn load_app_config_from_path(path: &Path) -> Result<AppConfig, ThresholdError> {
    let data_dir = env::resolve_data_dir()?;
    let mut config = load_from_path(path, &data_dir)?;
    env::apply_env_overrides(&mut config)?;
    Ok(config)
}

pub fn load_app_config_from_profile_path(path: &Path, profile: &str) -> Result<AppConfig, ThresholdError> {
    let data_dir = env::resolve_data_dir()?;
    if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
        return Err(ThresholdError::Message(
            "profiled config loading is only supported for INI files".to_string(),
        ));
    }
    let mut config = loader::load_from_ini_profile(path, &data_dir, profile)?;
    env::apply_env_overrides(&mut config)?;
    Ok(config)
}

fn load_from_path(path: &Path, data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("toml") => loader::load_from_toml(path, data_dir),
        _ => loader::load_from_ini(path, data_dir),
    }
}
