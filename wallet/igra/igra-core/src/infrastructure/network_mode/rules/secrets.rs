use super::super::report::{ErrorCategory, ValidationReport};
use super::super::{NetworkMode, ValidationContext, ValidationStrictness};
use crate::infrastructure::config::AppConfig;
use crate::infrastructure::keys::backends::file_format::SecretFile;
use std::path::PathBuf;

const LEGACY_WALLET_SECRET_ENV: &str = "KASPA_IGRA_WALLET_SECRET";

pub fn key_audit_log_path(service: &crate::infrastructure::config::ServiceConfig) -> PathBuf {
    match service.key_audit_log_path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(&service.data_dir).join("key-audit.log"),
    }
}

pub fn validate_secrets(
    app_config: &AppConfig,
    mode: NetworkMode,
    _ctx: &ValidationContext,
    level: ValidationStrictness,
    report: &mut ValidationReport,
) {
    let service = &app_config.service;
    let has_legacy_env = match std::env::var(LEGACY_WALLET_SECRET_ENV) {
        Ok(v) => !v.trim().is_empty(),
        Err(std::env::VarError::NotPresent) => false,
        Err(err) => {
            report.add_warning(
                ErrorCategory::Secrets,
                format!("failed to read legacy env secret {}: {}", LEGACY_WALLET_SECRET_ENV, err),
            );
            false
        }
    };

    if has_legacy_env {
        match mode {
            NetworkMode::Mainnet => report.add_error(
                ErrorCategory::Secrets,
                format!("mainnet forbids legacy env secret {} - use encrypted secrets file instead", LEGACY_WALLET_SECRET_ENV),
            ),
            NetworkMode::Testnet => report.add_warning(
                ErrorCategory::Secrets,
                format!("legacy env secret {} is discouraged outside devnet", LEGACY_WALLET_SECRET_ENV),
            ),
            NetworkMode::Devnet => {}
        }
    }

    if mode == NetworkMode::Mainnet && !service.use_encrypted_secrets {
        report.add_error(ErrorCategory::Secrets, "mainnet requires service.use_encrypted_secrets=true");
    } else if mode == NetworkMode::Testnet && !service.use_encrypted_secrets {
        report.add_warning(ErrorCategory::Secrets, "testnet recommended: use encrypted secrets (service.use_encrypted_secrets=true)");
    }

    if let Some(raw) = service.key_audit_log_path.as_deref() {
        if raw.trim().is_empty() {
            report.add_error(ErrorCategory::Secrets, "invalid service.key_audit_log_path: empty string");
        }
    }

    let audit_path = key_audit_log_path(service);
    if let Some(parent) = audit_path.parent() {
        if !parent.exists() {
            match mode {
                NetworkMode::Mainnet => report.add_error(
                    ErrorCategory::Secrets,
                    format!("key audit log directory does not exist: {} (create it before starting)", parent.display()),
                ),
                NetworkMode::Testnet => report.add_warning(
                    ErrorCategory::Secrets,
                    format!("key audit log directory does not exist: {} (create it before starting)", parent.display()),
                ),
                NetworkMode::Devnet => {}
            }
        }
    }

    if service.use_encrypted_secrets {
        let secrets_path = secrets_file_path(service);
        if !secrets_path.exists() {
            report.add_error(
                ErrorCategory::Secrets,
                format!(
                    "encrypted secrets enabled but secrets file not found: {} (set service.secrets_file or create it)",
                    secrets_path.display()
                ),
            );
        }

        let passphrase = match std::env::var("IGRA_SECRETS_PASSPHRASE") {
            Ok(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            Err(std::env::VarError::NotPresent) => None,
            Err(err) => {
                report.add_warning(ErrorCategory::Secrets, format!("failed to read IGRA_SECRETS_PASSPHRASE env var: {}", err));
                None
            }
        };

        if mode == NetworkMode::Mainnet {
            if passphrase.is_none() {
                report
                    .add_error(ErrorCategory::Secrets, "mainnet forbids interactive passphrase; set IGRA_SECRETS_PASSPHRASE env var");
            }
        } else if mode == NetworkMode::Testnet {
            if passphrase.is_none() {
                report.add_warning(
                    ErrorCategory::Secrets,
                    "testnet: consider setting IGRA_SECRETS_PASSPHRASE to avoid interactive passphrase prompts",
                );
            }
        }

        validate_passphrase_rotation_policy(service, mode, report);
    } else if matches!(level, ValidationStrictness::Error | ValidationStrictness::Warning) {
        if mode != NetworkMode::Devnet {
            report.add_warning(ErrorCategory::Secrets, "using environment-based secrets is intended for devnet/CI");
        }
    }
}

fn validate_passphrase_rotation_policy(
    service: &crate::infrastructure::config::ServiceConfig,
    mode: NetworkMode,
    report: &mut ValidationReport,
) {
    let enabled = service.passphrase_rotation_enabled.unwrap_or(match mode {
        NetworkMode::Mainnet => true,
        NetworkMode::Testnet => true,
        NetworkMode::Devnet => false,
    });

    if mode == NetworkMode::Mainnet && service.passphrase_rotation_enabled == Some(false) {
        report.add_warning(
            ErrorCategory::Secrets,
            "passphrase rotation enforcement disabled in mainnet (service.passphrase_rotation_enabled=false)",
        );
    }

    if !enabled {
        return;
    }

    let warn_days = service.passphrase_rotation_warn_days.unwrap_or(match mode {
        NetworkMode::Mainnet => 60,
        NetworkMode::Testnet => 90,
        NetworkMode::Devnet => 0,
    });
    let error_days = service.passphrase_rotation_error_days.unwrap_or(match mode {
        NetworkMode::Mainnet => 90,
        NetworkMode::Testnet => 0,
        NetworkMode::Devnet => 0,
    });

    if warn_days == 0 && error_days == 0 {
        return;
    }

    let secrets_path = secrets_file_path(service);
    if !secrets_path.exists() {
        return;
    }

    let data = match std::fs::read(&secrets_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            report.add_error(
                ErrorCategory::Secrets,
                format!("failed to read secrets file for passphrase rotation checks path={} error={}", secrets_path.display(), err),
            );
            return;
        }
    };

    let file = match SecretFile::from_bytes(&data) {
        Ok(file) => file,
        Err(err) => {
            match mode {
                NetworkMode::Mainnet => report.add_error(
                    ErrorCategory::Secrets,
                    format!(
                        "failed to parse secrets file for passphrase rotation checks path={} error={} (regenerate with secrets-admin init)",
                        secrets_path.display(),
                        err
                    ),
                ),
                NetworkMode::Testnet => report.add_warning(
                    ErrorCategory::Secrets,
                    format!(
                        "failed to parse secrets file for passphrase rotation checks path={} error={} (regenerate with secrets-admin init)",
                        secrets_path.display(),
                        err
                    ),
                ),
                NetworkMode::Devnet => {}
            }
            return;
        }
    };

    let age_days = file.rotation_metadata().age_days(crate::foundation::now_nanos());

    if warn_days > 0 && age_days >= warn_days {
        report.add_warning(
            ErrorCategory::Secrets,
            format!(
                "passphrase age {} days exceeds warn threshold {} days (rotation recommended). See docs/dev/passphrase-rotation.md",
                age_days, warn_days
            ),
        );
    }

    if error_days > 0 && age_days >= error_days {
        let msg = format!(
            "passphrase age {} days exceeds max allowed {} days (rotation required). Override (not recommended): IGRA_SERVICE__PASSPHRASE_ROTATION_ENABLED=false. See docs/dev/passphrase-rotation.md",
            age_days, error_days
        );
        match mode {
            NetworkMode::Mainnet => report.add_error(ErrorCategory::Secrets, msg),
            NetworkMode::Testnet => report.add_warning(ErrorCategory::Secrets, msg),
            NetworkMode::Devnet => {}
        }
    }
}

pub fn secrets_file_path(service: &crate::infrastructure::config::ServiceConfig) -> PathBuf {
    match service.secrets_file.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(&service.data_dir).join("secrets.bin"),
    }
}
