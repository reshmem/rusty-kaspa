use super::super::report::{ErrorCategory, ValidationReport};
use super::super::{NetworkMode, ValidationStrictness};
use crate::infrastructure::config::{AppConfig, KeyType};

pub fn validate_network_confirmation(
    app_config: &AppConfig,
    mode: NetworkMode,
    level: ValidationStrictness,
    report: &mut ValidationReport,
) {
    let configured = app_config.service.network.as_deref().map(str::trim).unwrap_or("");
    if configured.is_empty() {
        match (mode, level) {
            (NetworkMode::Mainnet, ValidationStrictness::Error) => report.add_error(
                ErrorCategory::Network,
                "mainnet requires explicit confirmation: set `service.network = \"mainnet\"` in the config file",
            ),
            (NetworkMode::Testnet, _) => report.add_warning(
                ErrorCategory::Network,
                "testnet recommended: set `service.network = \"testnet\"` in the config file to prevent drift",
            ),
            _ => {}
        }
        return;
    }

    if configured != mode.to_string() {
        match (mode, level) {
            (NetworkMode::Mainnet, ValidationStrictness::Error) => report.add_error(
                ErrorCategory::Network,
                format!("network mismatch: CLI mode is '{mode}', but config has service.network='{configured}'"),
            ),
            _ => report.add_warning(
                ErrorCategory::Network,
                format!("network mismatch: CLI mode is '{mode}', but config has service.network='{configured}'"),
            ),
        }
    }
}

pub fn validate_addresses_and_threshold(
    app_config: &AppConfig,
    mode: NetworkMode,
    level: ValidationStrictness,
    report: &mut ValidationReport,
) {
    if mode != NetworkMode::Devnet {
        let data_dir = app_config.service.data_dir.to_lowercase();
        if data_dir.contains("devnet") || data_dir.contains("test") {
            let msg = format!(
                "data_dir path suggests non-production config: data_dir='{}' (contains 'devnet'/'test')",
                app_config.service.data_dir
            );
            match mode {
                NetworkMode::Mainnet => report.add_error(ErrorCategory::Configuration, msg),
                NetworkMode::Testnet => report.add_warning(ErrorCategory::Configuration, msg),
                NetworkMode::Devnet => {}
            }
        }
    }

    let expected_prefix = mode.address_prefix();

    let redeem_script_hex = app_config.service.pskt.redeem_script_hex.trim();
    let provided_sources =
        app_config.service.pskt.source_addresses.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
    if !redeem_script_hex.is_empty() && !provided_sources.is_empty() {
        match crate::infrastructure::config::pskt_source_address_from_redeem_script_hex(mode, redeem_script_hex) {
            Ok(expected_source) => {
                for addr in &provided_sources {
                    if *addr != expected_source {
                        report.add_error(
                            ErrorCategory::Configuration,
                            format!(
                                "pskt.source_addresses mismatch: expected '{}' (derived from redeem_script_hex), got '{}'",
                                expected_source, addr
                            ),
                        );
                    }
                }
            }
            Err(err) => report.add_error(
                ErrorCategory::Configuration,
                format!("invalid pskt.redeem_script_hex (cannot derive source address): {}", err),
            ),
        }
    }

    if mode != NetworkMode::Devnet {
        for addr in &app_config.service.pskt.source_addresses {
            let trimmed = addr.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !trimmed.starts_with(expected_prefix) {
                report.add_error(
                    ErrorCategory::Configuration,
                    format!("address prefix mismatch: '{}' must start with '{}'", trimmed, expected_prefix),
                );
            }
        }
    }

    if let Some(group) = app_config.group.as_ref() {
        if group.threshold_m == 0 || group.threshold_n == 0 || group.threshold_m > group.threshold_n {
            report.add_error(ErrorCategory::Configuration, "invalid group threshold m/n".to_string());
        }

        if group.threshold_m < 2 {
            match mode {
                NetworkMode::Mainnet => report
                    .add_error(ErrorCategory::Configuration, "mainnet requires group.threshold_m >= 2 (single-signer is insecure)"),
                NetworkMode::Testnet => {
                    report.add_warning(ErrorCategory::Configuration, "threshold_m < 2 is insecure; recommended m>=2")
                }
                NetworkMode::Devnet => {}
            }
        }
    } else if mode == NetworkMode::Mainnet {
        report.add_error(ErrorCategory::Configuration, "mainnet requires [group] configuration (threshold + member_pubkeys)");
    }

    if let (Some(hd), ValidationStrictness::Error | ValidationStrictness::Warning) = (app_config.service.hd.as_ref(), level) {
        if mode == NetworkMode::Mainnet && hd.key_type == KeyType::HdMnemonic {
            report.add_error(
                ErrorCategory::Configuration,
                "mainnet forbids service.hd.key_type=hd_mnemonic; use raw_private_key + secrets.bin",
            );
        }

        if let Some(path) = hd.derivation_path.as_deref().map(str::trim).filter(|p| !p.is_empty() && *p != "m") {
            let expected_coin = mode.coin_type();
            if (mode == NetworkMode::Mainnet || mode == NetworkMode::Testnet) && !path.contains(expected_coin) {
                report.add_error(
                    ErrorCategory::Configuration,
                    format!("derivation_path coin type mismatch: derivation_path='{path}' must contain coin_type={expected_coin} for {mode}"),
                );
            }
        }
    }
}
