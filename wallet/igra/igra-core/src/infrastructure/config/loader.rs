//! Configuration loader using Figment for layered config management.
//!
//! Precedence (lowest to highest):
//! 1. Compiled defaults
//! 2. TOML config file
//! 3. Profile overrides from `[profiles.<name>]`
//! 4. Environment variables (IGRA_* prefix)

use crate::domain::{GroupConfig, GroupMetadata, GroupPolicy};
use crate::foundation::ThresholdError;
use crate::infrastructure::config::encryption::encrypt_mnemonics;
use crate::infrastructure::config::types::AppConfig;
use figment::providers::{Env, Format, Serialized, Toml};
use figment::value::{Dict, Map, Value};
use figment::{Figment, Profile};
use kaspa_wallet_core::prelude::Secret;
use serde::Deserialize;
use std::path::Path;
use tracing::{debug, info};

const DEFAULT_NODE_RPC_URL: &str = "grpc://127.0.0.1:16110";
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8088";
const DEFAULT_POLL_SECS: u64 = 5;
const DEFAULT_SIG_OP_COUNT: u8 = 2;
const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 60;
const DEFAULT_SESSION_EXPIRY_SECS: u64 = 600;

/// Environment variable prefix for config overrides.
///
/// Example: `IGRA_SERVICE__NODE_RPC_URL` -> `service.node_rpc_url`
const ENV_PREFIX: &str = "IGRA_";

#[derive(Clone, Debug, Default, Deserialize)]
struct AppConfigRaw {
    #[serde(default)]
    pub service: crate::infrastructure::config::types::ServiceConfig,
    #[serde(default)]
    pub runtime: crate::infrastructure::config::types::RuntimeConfig,
    #[serde(default)]
    pub signing: crate::infrastructure::config::types::SigningConfig,
    #[serde(default)]
    pub rpc: crate::infrastructure::config::types::RpcConfig,
    #[serde(default)]
    pub policy: GroupPolicy,
    #[serde(default)]
    pub group: Option<GroupConfigRaw>,
    #[serde(default)]
    pub hyperlane: crate::infrastructure::config::types::HyperlaneConfig,
    #[serde(default)]
    pub layerzero: crate::infrastructure::config::types::LayerZeroConfig,
    #[serde(default)]
    pub iroh: crate::infrastructure::config::types::IrohRuntimeConfig,
    #[serde(default, skip_serializing)]
    pub profiles: Option<Map<String, Dict>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct GroupConfigRaw {
    #[serde(default)]
    pub network_id: u8,
    #[serde(default)]
    pub threshold_m: u16,
    #[serde(default)]
    pub threshold_n: u16,
    #[serde(default)]
    pub member_pubkeys: Vec<String>,
    #[serde(default)]
    pub fee_rate_sompi_per_gram: u64,
    #[serde(default)]
    pub finality_blue_score_threshold: u64,
    #[serde(default)]
    pub dust_threshold_sompi: u64,
    #[serde(default)]
    pub min_recipient_amount_sompi: u64,
    #[serde(default)]
    pub session_timeout_seconds: u64,
    #[serde(default)]
    pub group_metadata: GroupMetadata,
}

/// Load configuration from the default file in `data_dir` (`igra-config.toml`).
pub fn load_config(data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    let config_path = data_dir.join("igra-config.toml");
    load_config_from_file(&config_path, data_dir)
}

/// Load configuration from the default file in `data_dir` (`igra-config.toml`) with a profile.
pub fn load_config_with_profile(data_dir: &Path, profile: &str) -> Result<AppConfig, ThresholdError> {
    let config_path = data_dir.join("igra-config.toml");
    load_config_from_file_with_profile(&config_path, data_dir, profile)
}

/// Load configuration from a specific file path.
pub fn load_config_from_file(path: &Path, data_dir: &Path) -> Result<AppConfig, ThresholdError> {
    info!(path = %path.display(), data_dir = %data_dir.display(), "loading configuration");
    let figment = figment_base(path, data_dir).merge(Env::prefixed(ENV_PREFIX).split("__"));
    let raw: AppConfigRaw = figment.extract().map_err(|e| ThresholdError::ConfigError(format!("config extraction failed: {e}")))?;
    let mut config = convert_raw(raw)?;
    postprocess(&mut config, data_dir)?;
    debug!(
        node_rpc_url = %redact_url(&config.service.node_rpc_url),
        rpc_addr = %config.rpc.addr,
        rpc_enabled = config.rpc.enabled,
        "configuration loaded"
    );
    Ok(config)
}

/// Load configuration from a specific file path with profile overrides.
pub fn load_config_from_file_with_profile(path: &Path, data_dir: &Path, profile: &str) -> Result<AppConfig, ThresholdError> {
    info!(
        path = %path.display(),
        data_dir = %data_dir.display(),
        profile = %profile,
        "loading configuration with profile"
    );

    // Extract once to access `profiles.<name>` overrides from the file.
    let base_config: AppConfigRaw =
        figment_base(path, data_dir).extract().map_err(|e| ThresholdError::ConfigError(format!("config extraction failed: {e}")))?;

    let overrides = profile_overrides(&base_config, profile)?;

    // Full extraction with overrides + env.
    let figment =
        figment_base(path, data_dir).merge(Serialized::from(overrides, Profile::Default)).merge(Env::prefixed(ENV_PREFIX).split("__"));

    let raw: AppConfigRaw = figment
        .extract()
        .map_err(|e| ThresholdError::ConfigError(format!("config extraction failed for profile '{profile}': {e}")))?;
    let mut config = convert_raw(raw)?;

    postprocess(&mut config, data_dir)?;

    debug!(
        profile = %profile,
        node_rpc_url = %redact_url(&config.service.node_rpc_url),
        rpc_addr = %config.rpc.addr,
        "configuration loaded with profile"
    );

    Ok(config)
}

fn figment_base(path: &Path, data_dir: &Path) -> Figment {
    let mut figment = Figment::new().merge(Serialized::defaults(AppConfig::default()));
    if path.exists() {
        figment = figment.merge(Toml::file(path));
    } else {
        debug!(path = %path.display(), "configuration file missing; using defaults and env only");
    }
    // Always seed data_dir into service.data_dir if the config doesn't set it.
    // (Done post-extraction to keep the figment pipeline simple.)
    let _ = data_dir;
    figment
}

fn profile_overrides(config: &AppConfigRaw, profile: &str) -> Result<Dict, ThresholdError> {
    let profiles = config.profiles.as_ref().ok_or_else(|| ThresholdError::ConfigError("no profiles section in config".to_string()))?;

    let overrides = profiles
        .get(profile)
        .cloned()
        .ok_or_else(|| ThresholdError::ConfigError(format!("profile '{profile}' not found in config")))?;

    Ok(normalize_profile_overrides(overrides)?)
}

/// Normalizes `[profiles.<name>.*]` sections into the shape expected by `AppConfig`.
///
/// Compatibility mapping (from legacy INI profile sections):
/// - `profiles.<name>.hd` -> `service.hd`
/// - `profiles.<name>.pskt` -> `service.pskt`
fn normalize_profile_overrides(mut overrides: Dict) -> Result<Dict, ThresholdError> {
    move_into_service(&mut overrides, "hd", "hd")?;
    move_into_service(&mut overrides, "pskt", "pskt")?;
    Ok(overrides)
}

fn move_into_service(overrides: &mut Dict, key: &str, service_key: &str) -> Result<(), ThresholdError> {
    let Some(value) = overrides.remove(key) else {
        return Ok(());
    };

    let entry = overrides.entry("service".to_string()).or_insert_with(|| Value::from(Dict::new()));
    match entry {
        Value::Dict(_, service) => {
            service.insert(service_key.to_string(), value);
            Ok(())
        }
        _ => Err(ThresholdError::ConfigError("invalid profiles.<name>.service shape (expected a table)".to_string())),
    }
}

fn postprocess(config: &mut AppConfig, data_dir: &Path) -> Result<(), ThresholdError> {
    if config.service.data_dir.trim().is_empty() {
        config.service.data_dir = data_dir.to_string_lossy().to_string();
    }

    if config.service.node_rpc_url.trim().is_empty() {
        config.service.node_rpc_url = DEFAULT_NODE_RPC_URL.to_string();
    }

    if config.service.pskt.node_rpc_url.trim().is_empty() {
        config.service.pskt.node_rpc_url = config.service.node_rpc_url.clone();
    }

    if config.service.pskt.sig_op_count == 0 {
        config.service.pskt.sig_op_count = DEFAULT_SIG_OP_COUNT;
    }

    if config.rpc.addr.trim().is_empty() {
        config.rpc.addr = DEFAULT_RPC_ADDR.to_string();
    }

    if config.hyperlane.poll_secs == 0 {
        config.hyperlane.poll_secs = DEFAULT_POLL_SECS;
    }

    if config.runtime.session_timeout_seconds == 0 {
        config.runtime.session_timeout_seconds = DEFAULT_SESSION_TIMEOUT_SECS;
    }

    if config.runtime.session_expiry_seconds.is_none() {
        config.runtime.session_expiry_seconds = Some(DEFAULT_SESSION_EXPIRY_SECS);
    }

    encrypt_hd_config(config)?;
    normalize_group_config(config);

    Ok(())
}

fn normalize_group_config(config: &mut AppConfig) {
    let Some(group) = config.group.as_mut() else {
        return;
    };

    // Keep a single source of truth for the policy used in group_id derivation.
    group.policy = config.policy.clone();

    // Match `devnet-keygen` defaults to keep group_id stable unless explicitly overridden.
    if group.group_metadata.policy_version == 0 {
        group.group_metadata.policy_version = 1;
    }
}

fn convert_raw(raw: AppConfigRaw) -> Result<AppConfig, ThresholdError> {
    let policy = raw.policy.clone();
    let group = match raw.group {
        Some(group) => Some(convert_group_config(raw.iroh.network_id, &policy, group)?),
        None => None,
    };

    Ok(AppConfig {
        service: raw.service,
        runtime: raw.runtime,
        signing: raw.signing,
        rpc: raw.rpc,
        policy,
        group,
        hyperlane: raw.hyperlane,
        layerzero: raw.layerzero,
        iroh: raw.iroh,
        profiles: raw.profiles,
    })
}

fn convert_group_config(iroh_network_id: u8, policy: &GroupPolicy, group: GroupConfigRaw) -> Result<GroupConfig, ThresholdError> {
    let network_id = if group.network_id != 0 { group.network_id } else { iroh_network_id };
    let member_pubkeys = group
        .member_pubkeys
        .into_iter()
        .map(|s| {
            let trimmed = s.trim().strip_prefix("0x").unwrap_or(s.trim());
            hex::decode(trimmed).map_err(|e| ThresholdError::ConfigError(format!("invalid group.member_pubkeys entry: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(GroupConfig {
        network_id,
        threshold_m: group.threshold_m,
        threshold_n: group.threshold_n,
        member_pubkeys,
        fee_rate_sompi_per_gram: group.fee_rate_sompi_per_gram,
        finality_blue_score_threshold: group.finality_blue_score_threshold,
        dust_threshold_sompi: group.dust_threshold_sompi,
        min_recipient_amount_sompi: group.min_recipient_amount_sompi,
        session_timeout_seconds: group.session_timeout_seconds,
        group_metadata: group.group_metadata,
        policy: policy.clone(),
    })
}

fn encrypt_hd_config(config: &mut AppConfig) -> Result<(), ThresholdError> {
    let Some(hd) = config.service.hd.as_mut() else {
        return Ok(());
    };

    if hd.mnemonics.is_empty() {
        return Ok(());
    }

    let value = std::env::var(crate::infrastructure::config::HD_WALLET_SECRET_ENV).unwrap_or_default();
    if value.trim().is_empty() {
        return Err(ThresholdError::ConfigError(format!(
            "{} is required to encrypt hd.mnemonics",
            crate::infrastructure::config::HD_WALLET_SECRET_ENV
        )));
    }
    let wallet_secret = Secret::from(value);
    let payment_secret = hd.passphrase.as_deref().map(Secret::from);
    let encrypted = encrypt_mnemonics(std::mem::take(&mut hd.mnemonics), payment_secret.as_ref(), &wallet_secret)?;
    hd.encrypted_mnemonics = Some(encrypted);
    Ok(())
}

fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let Some(at) = rest.find('@') else {
        return url.to_string();
    };
    format!("{scheme}<redacted>@{}", &rest[at + 1..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_minimal_toml() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(
            &config_path,
            r#"
            [service]
            node_rpc_url = "grpc://127.0.0.1:16110"
        "#,
        )
        .unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.service.node_rpc_url, "grpc://127.0.0.1:16110");
    }

    #[test]
    fn test_load_with_arrays() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(
            &config_path,
            r#"
            [service.pskt]
            source_addresses = ["addr1", "addr2"]
        "#,
        )
        .unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.service.pskt.source_addresses, vec!["addr1", "addr2"]);
    }

    #[test]
    fn test_load_hyperlane_domains() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(
            &config_path,
            r#"
            [[hyperlane.domains]]
            domain = 42
            validators = ["0xabc"]
            threshold = 1
        "#,
        )
        .unwrap();

        let config = load_config(dir.path()).unwrap();
        assert_eq!(config.hyperlane.domains.len(), 1);
        assert_eq!(config.hyperlane.domains[0].domain, 42);
    }

    #[test]
    fn test_load_with_profile() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("igra-config.toml");
        std::fs::write(
            &config_path,
            r#"
            [service]
            data_dir = "/base"

            [profiles.signer-1.service]
            data_dir = "/signer-1"
        "#,
        )
        .unwrap();

        let config = load_config_with_profile(dir.path(), "signer-1").unwrap();
        assert_eq!(config.service.data_dir, "/signer-1");
    }

    #[test]
    fn test_load_from_specific_file() {
        let dir = tempdir().unwrap();
        let custom_path = dir.path().join("custom-config.toml");
        std::fs::write(
            &custom_path,
            r#"
            [service]
            node_rpc_url = "grpc://custom:16110"
        "#,
        )
        .unwrap();

        let config = load_config_from_file(&custom_path, dir.path()).unwrap();
        assert_eq!(config.service.node_rpc_url, "grpc://custom:16110");
    }
}
