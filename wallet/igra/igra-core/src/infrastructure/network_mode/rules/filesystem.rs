use super::super::report::{ErrorCategory, ValidationReport};
use super::super::{NetworkMode, ValidationContext, ValidationStrictness};
use crate::infrastructure::config::AppConfig;
use crate::infrastructure::network_mode::rules::secrets::{key_audit_log_path, secrets_file_path};
use std::fs;
use std::path::Path;

#[cfg(unix)]
fn mode_bits(path: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

pub fn validate_filesystem(
    app_config: &AppConfig,
    mode: NetworkMode,
    ctx: &ValidationContext,
    level: ValidationStrictness,
    report: &mut ValidationReport,
) {
    if matches!(level, ValidationStrictness::Ignore) {
        return;
    }

    let data_dir = Path::new(&app_config.service.data_dir);
    if !data_dir.exists() {
        if mode == NetworkMode::Mainnet {
            report.add_error(ErrorCategory::FilePermissions, format!("data dir does not exist: {}", data_dir.display()));
        } else {
            report.add_warning(ErrorCategory::FilePermissions, format!("data dir does not exist yet: {}", data_dir.display()));
        }
        return;
    }

    if mode == NetworkMode::Mainnet {
        #[cfg(unix)]
        {
            if let Ok(bits) = mode_bits(data_dir) {
                if bits != 0o700 {
                    report.add_error(
                        ErrorCategory::FilePermissions,
                        format!("mainnet data dir must be 0700, got {:o} ({})", bits, data_dir.display()),
                    );
                }
            }
        }
    }

    if let Some(config_path) = ctx.config_path.as_deref() {
        if config_path.exists() {
            #[cfg(unix)]
            {
                if let Ok(bits) = mode_bits(config_path) {
                    if mode == NetworkMode::Mainnet && bits != 0o600 {
                        report.add_error(
                            ErrorCategory::FilePermissions,
                            format!("mainnet config file must be 0600, got {:o} ({})", bits, config_path.display()),
                        );
                    } else if mode == NetworkMode::Testnet && bits & 0o077 != 0 {
                        report.add_warning(
                            ErrorCategory::FilePermissions,
                            format!("testnet config file has group/world perms {:o} ({})", bits, config_path.display()),
                        );
                    }
                }
            }
        }
    }

    if app_config.service.use_encrypted_secrets {
        let secrets_path = secrets_file_path(&app_config.service);
        if secrets_path.exists() {
            #[cfg(unix)]
            {
                if let Ok(bits) = mode_bits(&secrets_path) {
                    if mode == NetworkMode::Mainnet && bits != 0o600 {
                        report.add_error(
                            ErrorCategory::FilePermissions,
                            format!("mainnet secrets file must be 0600, got {:o} ({})", bits, secrets_path.display()),
                        );
                    } else if mode == NetworkMode::Testnet && bits & 0o077 != 0 {
                        report.add_warning(
                            ErrorCategory::FilePermissions,
                            format!("testnet secrets file has group/world perms {:o} ({})", bits, secrets_path.display()),
                        );
                    }
                }
            }
        }
    }

    let audit_path = key_audit_log_path(&app_config.service);
    if audit_path.exists() {
        #[cfg(unix)]
        {
            if let Ok(bits) = mode_bits(&audit_path) {
                if mode == NetworkMode::Mainnet && bits != 0o600 {
                    report.add_error(
                        ErrorCategory::FilePermissions,
                        format!("mainnet key audit log file must be 0600, got {:o} ({})", bits, audit_path.display()),
                    );
                } else if mode == NetworkMode::Testnet && bits & 0o077 != 0 {
                    report.add_warning(
                        ErrorCategory::FilePermissions,
                        format!("testnet key audit log file has group/world perms {:o} ({})", bits, audit_path.display()),
                    );
                }
            }
        }
    }

    if mode == NetworkMode::Mainnet {
        if let Some(log_dir) = ctx.log_dir.as_deref() {
            #[cfg(unix)]
            {
                if log_dir.exists() {
                    if let Ok(bits) = mode_bits(log_dir) {
                        if bits & 0o077 != 0 {
                            report.add_error(
                                ErrorCategory::FilePermissions,
                                format!("mainnet log dir must be 0700, got {:o} ({})", bits, log_dir.display()),
                            );
                        }
                    }
                }
            }
        }
    }
}
