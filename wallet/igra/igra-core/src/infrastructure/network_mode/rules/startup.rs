use super::super::report::{ErrorCategory, ValidationReport};
use super::super::{NetworkMode, ValidationStrictness};
use crate::foundation::{ThresholdError, MIN_DISK_SPACE_BYTES, MIN_OPEN_FILE_LIMIT};
use crate::infrastructure::config::AppConfig;
use crate::infrastructure::keys::{KeyManagerContext, SecretName};
use crate::infrastructure::rpc::KaspaGrpcQueryClient;
use kaspa_bip32::{Language, Mnemonic};
use kaspa_wallet_core::encryption::EncryptionKind;
use kaspa_wallet_core::prelude::Secret;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use log::warn;
use std::path::Path;

const SIGNER_MNEMONIC_SECRET_PREFIX: &str = "igra.signer.mnemonic_";
const SIGNER_PRIVATE_KEY_SECRET_PREFIX: &str = "igra.signer.private_key_";
const SIGNER_PAYMENT_SECRET_PREFIX: &str = "igra.signer.payment_secret_";

pub fn validate_runtime_environment(
    mode: NetworkMode,
    app_config: &AppConfig,
    level: ValidationStrictness,
    report: &mut ValidationReport,
) {
    if mode == NetworkMode::Devnet || matches!(level, ValidationStrictness::Ignore) {
        return;
    }

    // Disk space.
    let data_dir = Path::new(&app_config.service.data_dir);
    if let Ok(space) = available_space_bytes(data_dir) {
        if space < MIN_DISK_SPACE_BYTES {
            let msg = format!(
                "insufficient disk space: {} GB available, need at least {} GB",
                space / (1024 * 1024 * 1024),
                MIN_DISK_SPACE_BYTES / (1024 * 1024 * 1024)
            );
            if mode == NetworkMode::Mainnet {
                report.add_error(ErrorCategory::Startup, msg);
            } else {
                report.add_warning(ErrorCategory::Startup, msg);
            }
        }
    }

    // Memory.
    if let Ok(mem) = available_memory_bytes() {
        let min = 1024_u64 * 1024 * 1024;
        if mem < min {
            let msg = format!("insufficient available memory: {} MB available, need at least 1024 MB", mem / (1024 * 1024));
            if mode == NetworkMode::Mainnet {
                report.add_error(ErrorCategory::Startup, msg);
            } else {
                report.add_warning(ErrorCategory::Startup, msg);
            }
        }
    }

    // File limits + core dumps + root.
    #[cfg(unix)]
    {
        if let Ok((soft, _hard)) = open_file_limits() {
            if soft < MIN_OPEN_FILE_LIMIT {
                let msg = format!("open file soft limit too low: {soft} (need at least {MIN_OPEN_FILE_LIMIT})");
                if mode == NetworkMode::Mainnet {
                    report.add_error(ErrorCategory::Startup, msg);
                } else {
                    report.add_warning(ErrorCategory::Startup, msg);
                }
            }
        }

        if let Ok(core) = core_dump_limit() {
            if core != 0 {
                let msg = "core dumps should be disabled (ulimit -c 0)".to_string();
                if mode == NetworkMode::Mainnet {
                    report.add_error(ErrorCategory::Startup, msg);
                } else {
                    report.add_warning(ErrorCategory::Startup, msg);
                }
            }
        }

        let uid = unsafe { libc::getuid() };
        if uid == 0 && mode == NetworkMode::Mainnet {
            report.add_error(ErrorCategory::Startup, "mainnet must not run as root; create a dedicated service user");
        }
    }
}

pub async fn validate_kaspa_node(mode: NetworkMode, kaspa_query: &KaspaGrpcQueryClient, report: &mut ValidationReport) {
    if mode == NetworkMode::Devnet {
        return;
    }

    match kaspa_query.get_server_info().await {
        Ok(info) => {
            let net = info.network_id.to_string().to_lowercase();
            let expected = mode.kaspa_network_id_hint();
            if !net.contains(expected) {
                let msg = format!("kaspa node network mismatch: reported='{}' expected contains '{}'", info.network_id, expected);
                if mode == NetworkMode::Mainnet {
                    report.add_error(ErrorCategory::Startup, msg);
                } else {
                    report.add_warning(ErrorCategory::Startup, msg);
                }
            }
        }
        Err(err) => {
            let msg = format!("failed to connect to kaspa node for server_info: {}", err);
            if mode == NetworkMode::Mainnet {
                report.add_error(ErrorCategory::Startup, msg);
            } else {
                report.add_warning(ErrorCategory::Startup, msg);
            }
        }
    }
}

pub async fn validate_required_secrets(
    mode: NetworkMode,
    app_config: &AppConfig,
    key_ctx: &KeyManagerContext,
    report: &mut ValidationReport,
) -> Result<(), ThresholdError> {
    let Some(hd) = app_config.service.hd.as_ref() else {
        return Ok(());
    };

    let profile = match app_config.service.active_profile.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(profile) => profile,
        None => {
            report.add_error(
                ErrorCategory::Secrets,
                "missing active profile: set CLI --profile signer-XX or service.active_profile in config".to_string(),
            );
            return Ok(());
        }
    };
    let expected_index_1based = match crate::infrastructure::config::validate_signer_profile(profile) {
        Ok(idx) => idx as usize,
        Err(err) => {
            report.add_error(ErrorCategory::Secrets, format!("invalid active profile {}: {}", profile, err));
            return Ok(());
        }
    };

    if mode == NetworkMode::Mainnet && matches!(hd.key_type, crate::infrastructure::config::KeyType::HdMnemonic) {
        report.add_error(
            ErrorCategory::Secrets,
            "mainnet forbids service.hd.key_type=hd_mnemonic; use raw_private_key + secrets.bin".to_string(),
        );
        return Ok(());
    }

    match hd.key_type {
        crate::infrastructure::config::KeyType::HdMnemonic => {
            let (derived_pubkey, redeem_pubkeys) = match validate_signer_alignment_hdmnemonic(app_config, key_ctx, profile).await {
                Ok(v) => v,
                Err(err) => {
                    report.add_error(
                        ErrorCategory::Secrets,
                        format!("invalid mnemonic signer secrets for profile {}: {}", profile, err),
                    );
                    return Ok(());
                }
            };
            validate_signer_index_alignment(report, profile, expected_index_1based, &derived_pubkey, &redeem_pubkeys);
        }
        crate::infrastructure::config::KeyType::RawPrivateKey => {
            let (derived_pubkey, redeem_pubkeys) = match validate_signer_alignment_raw_private_key(app_config, key_ctx, profile).await
            {
                Ok(v) => v,
                Err(err) => {
                    report.add_error(
                        ErrorCategory::Secrets,
                        format!("invalid raw_private_key signer secrets for profile {}: {}", profile, err),
                    );
                    return Ok(());
                }
            };
            validate_signer_index_alignment(report, profile, expected_index_1based, &derived_pubkey, &redeem_pubkeys);
        }
    }

    if report.has_errors() && mode == NetworkMode::Testnet {
        warn!("testnet missing required secrets; service will fail when signing");
    }

    Ok(())
}

fn signer_secret_name(key_ctx: &KeyManagerContext, prefix: &str, profile: &str) -> Result<SecretName, ThresholdError> {
    let store = key_ctx
        .key_manager()
        .secret_store()
        .ok_or_else(|| ThresholdError::secret_store_unavailable("none", "KeyManager has no SecretStore"))?;
    let suffix = if store.backend() == "env" { profile.replace('-', "_") } else { profile.to_string() };
    Ok(SecretName::new(format!("{prefix}{suffix}")))
}

async fn load_utf8_secret(key_ctx: &KeyManagerContext, name: &SecretName) -> Result<String, ThresholdError> {
    let secret_bytes = key_ctx.get_secret_with_audit(name).await?;
    String::from_utf8(secret_bytes.expose_owned())
        .map_err(|err| ThresholdError::secret_decode_failed(name.to_string(), "utf8", format!("invalid UTF-8: {}", err)))
}

async fn load_payment_secret_optional(key_ctx: &KeyManagerContext, profile: &str) -> Result<Option<Secret>, ThresholdError> {
    let name = signer_secret_name(key_ctx, SIGNER_PAYMENT_SECRET_PREFIX, profile)?;
    let secret_bytes = match key_ctx.get_secret_with_audit(&name).await {
        Ok(bytes) => bytes,
        Err(ThresholdError::SecretNotFound { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };
    if secret_bytes.expose_secret().is_empty() {
        return Ok(None);
    }
    let value = String::from_utf8(secret_bytes.expose_owned())
        .map_err(|err| ThresholdError::secret_decode_failed(name.to_string(), "utf8", format!("invalid UTF-8: {}", err)))?;
    Ok(Some(Secret::from(value)))
}

async fn validate_signer_alignment_hdmnemonic(
    app_config: &AppConfig,
    key_ctx: &KeyManagerContext,
    profile: &str,
) -> Result<(secp256k1::PublicKey, Vec<secp256k1::PublicKey>), ThresholdError> {
    let mnemonic_name = signer_secret_name(key_ctx, SIGNER_MNEMONIC_SECRET_PREFIX, profile)?;
    let phrase = load_utf8_secret(key_ctx, &mnemonic_name).await?;
    let mnemonic = Mnemonic::new(phrase.trim(), Language::English)
        .map_err(|err| ThresholdError::ConfigError(format!("invalid mnemonic in secret {}: {}", mnemonic_name, err)))?;
    let payment_secret = load_payment_secret_optional(key_ctx, profile).await?;
    let key_data =
        PrvKeyData::try_from_mnemonic(mnemonic, payment_secret.as_ref(), EncryptionKind::XChaCha20Poly1305, None).map_err(|err| {
            ThresholdError::ConfigError(format!("failed to create key data from mnemonic secret {}: {}", mnemonic_name, err))
        })?;
    let signing_keypair = crate::foundation::hd::derive_keypair_from_key_data(
        &key_data,
        app_config.service.hd.as_ref().and_then(|h| h.derivation_path.as_deref()),
        payment_secret.as_ref(),
    )?;
    let keypair = signing_keypair.to_secp256k1()?;
    let derived_pubkey = crate::domain::pskt::multisig::canonical_schnorr_pubkey_for_keypair(&keypair);

    let redeem_pubkeys = redeem_pubkeys_for_validation(app_config, key_ctx, profile, Some((key_data, payment_secret))).await?;
    Ok((derived_pubkey, redeem_pubkeys))
}

async fn validate_signer_alignment_raw_private_key(
    app_config: &AppConfig,
    key_ctx: &KeyManagerContext,
    profile: &str,
) -> Result<(secp256k1::PublicKey, Vec<secp256k1::PublicKey>), ThresholdError> {
    let name = signer_secret_name(key_ctx, SIGNER_PRIVATE_KEY_SECRET_PREFIX, profile)?;
    let secret_bytes = key_ctx.get_secret_with_audit(&name).await?;
    let signing_keypair = crate::foundation::hd::keypair_from_bytes(secret_bytes.expose_secret())?;
    let keypair = signing_keypair.to_secp256k1()?;
    let derived_pubkey = crate::domain::pskt::multisig::canonical_schnorr_pubkey_for_keypair(&keypair);
    let redeem_pubkeys = redeem_pubkeys_for_validation(app_config, key_ctx, profile, None).await?;
    Ok((derived_pubkey, redeem_pubkeys))
}

async fn redeem_pubkeys_for_validation(
    app_config: &AppConfig,
    key_ctx: &KeyManagerContext,
    profile: &str,
    mnemonic_material: Option<(PrvKeyData, Option<Secret>)>,
) -> Result<Vec<secp256k1::PublicKey>, ThresholdError> {
    let redeem_hex = app_config.service.pskt.redeem_script_hex.trim().to_string();
    let redeem_hex = if !redeem_hex.is_empty() {
        redeem_hex
    } else {
        let Some(hd) = app_config.service.hd.as_ref() else {
            return Err(ThresholdError::ConfigError("missing service.hd".to_string()));
        };
        if !matches!(hd.key_type, crate::infrastructure::config::KeyType::HdMnemonic) {
            return Err(ThresholdError::ConfigError("missing service.pskt.redeem_script_hex".to_string()));
        }

        let (key_data, payment_secret) = match mnemonic_material {
            Some(v) => v,
            None => {
                let mnemonic_name = signer_secret_name(key_ctx, SIGNER_MNEMONIC_SECRET_PREFIX, profile)?;
                let phrase = load_utf8_secret(key_ctx, &mnemonic_name).await?;
                let mnemonic = Mnemonic::new(phrase.trim(), Language::English)
                    .map_err(|err| ThresholdError::ConfigError(format!("invalid mnemonic in secret {}: {}", mnemonic_name, err)))?;
                let payment_secret = load_payment_secret_optional(key_ctx, profile).await?;
                let key_data =
                    PrvKeyData::try_from_mnemonic(mnemonic, payment_secret.as_ref(), EncryptionKind::XChaCha20Poly1305, None)
                        .map_err(|err| {
                            ThresholdError::ConfigError(format!(
                                "failed to create key data from mnemonic secret {}: {}",
                                mnemonic_name, err
                            ))
                        })?;
                (key_data, payment_secret)
            }
        };

        crate::infrastructure::config::derive_redeem_script_hex(
            hd,
            std::slice::from_ref(&key_data),
            hd.derivation_path.as_deref(),
            payment_secret.as_ref(),
        )?
    };

    let redeem_script = hex::decode(redeem_hex.trim())?;
    crate::domain::pskt::multisig::ordered_pubkeys_from_redeem_script(&redeem_script)
}

fn validate_signer_index_alignment(
    report: &mut ValidationReport,
    profile: &str,
    expected_index_1based: usize,
    derived_pubkey: &secp256k1::PublicKey,
    redeem_pubkeys: &[secp256k1::PublicKey],
) {
    if redeem_pubkeys.is_empty() {
        report.add_error(ErrorCategory::Secrets, "redeem script pubkey list is empty".to_string());
        return;
    }
    if expected_index_1based == 0 || expected_index_1based > redeem_pubkeys.len() {
        report.add_error(
            ErrorCategory::Secrets,
            format!(
                "signer index alignment invalid: profile={} expects position {} but redeem script has {} pubkeys",
                profile,
                expected_index_1based,
                redeem_pubkeys.len()
            ),
        );
        return;
    }

    let expected_pubkey = &redeem_pubkeys[expected_index_1based - 1];
    if derived_pubkey == expected_pubkey {
        return;
    }

    let actual_index = redeem_pubkeys.iter().position(|pk| pk == derived_pubkey).map(|idx| idx + 1);
    match actual_index {
        Some(actual) => report.add_error(
            ErrorCategory::Secrets,
            format!(
                "signer index alignment mismatch: profile={} expects redeem-script pubkey position {} but derived key matches position {}",
                profile, expected_index_1based, actual
            ),
        ),
        None => report.add_error(
            ErrorCategory::Secrets,
            format!(
                "signer index alignment mismatch: profile={} expects redeem-script pubkey position {} but derived key not found in redeem script",
                profile, expected_index_1based
            ),
        ),
    }
}

fn available_space_bytes(_path: &Path) -> Result<u64, ThresholdError> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;
        let c_path = CString::new(_path.to_string_lossy().to_string())
            .map_err(|_| ThresholdError::StorageError { operation: "statvfs".into(), details: "invalid path".into() })?;
        let mut stat = MaybeUninit::<libc::statvfs>::uninit();
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
        if rc != 0 {
            return Err(ThresholdError::StorageError { operation: "statvfs".into(), details: "statvfs failed".into() });
        }
        let stat = unsafe { stat.assume_init() };
        let bytes = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        Ok(u64::MAX)
    }
}

fn available_memory_bytes() -> Result<u64, ThresholdError> {
    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        #[cfg(not(target_os = "macos"))]
        let pages = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if pages <= 0 || page_size <= 0 {
            return Err(ThresholdError::StorageError { operation: "sysconf".into(), details: "unavailable".into() });
        }
        Ok((pages as u64).saturating_mul(page_size as u64))
    }
    #[cfg(not(unix))]
    {
        Err(ThresholdError::Unimplemented("available_memory_bytes unsupported platform".to_string()))
    }
}

#[cfg(unix)]
fn open_file_limits() -> Result<(u64, u64), ThresholdError> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    if rc != 0 {
        return Err(ThresholdError::StorageError { operation: "getrlimit".into(), details: "RLIMIT_NOFILE failed".into() });
    }
    Ok((lim.rlim_cur as u64, lim.rlim_max as u64))
}

#[cfg(unix)]
fn core_dump_limit() -> Result<u64, ThresholdError> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
    if rc != 0 {
        return Err(ThresholdError::StorageError { operation: "getrlimit".into(), details: "RLIMIT_CORE failed".into() });
    }
    Ok(lim.rlim_cur as u64)
}
