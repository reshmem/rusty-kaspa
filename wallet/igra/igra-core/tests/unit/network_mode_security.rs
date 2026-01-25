use igra_core::domain::{GroupConfig, GroupMetadata, GroupPolicy};
use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::config::{AppConfig, KeyType, PsktHdConfig};
use igra_core::infrastructure::keys::backends::file_format::{Argon2Params, SecretFile, SecretMap};
use igra_core::infrastructure::keys::{KeyManagerContext, LocalKeyManager, NoopAuditLogger, SecretBytes, SecretName, SecretStore};
use igra_core::infrastructure::network_mode::{NetworkMode, SecurityValidator, ValidationContext};
use igra_core::infrastructure::rpc::KaspaGrpcQueryClient;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;

fn make_group_config() -> GroupConfig {
    GroupConfig {
        network_id: 1,
        threshold_m: 2,
        threshold_n: 3,
        member_pubkeys: vec![vec![1u8; 33], vec![2u8; 33], vec![3u8; 33]],
        fee_rate_sompi_per_gram: 1,
        finality_blue_score_threshold: 100,
        dust_threshold_sompi: 1000,
        min_recipient_amount_sompi: 1000,
        session_timeout_seconds: 600,
        group_metadata: GroupMetadata::default(),
        policy: GroupPolicy::default(),
    }
}

fn make_mainnet_ready_config(tmp: &TempDir) -> (AppConfig, ValidationContext) {
    std::env::remove_var("KASPA_IGRA_WALLET_SECRET");

    let data_dir = tmp.path().to_string_lossy().to_string();
    let secrets_path = tmp.path().join("secrets.bin");
    let secrets = SecretMap { secrets: HashMap::new() };
    let file = SecretFile::encrypt(&secrets, "test-passphrase", Argon2Params::default()).expect("test setup: encrypt secrets");
    let bytes = file.to_bytes().expect("test setup: serialize secrets file");
    std::fs::write(&secrets_path, bytes).expect("test setup: secrets file write");
    let log_dir = tmp.path().join("logs");
    std::fs::create_dir_all(&log_dir).expect("test setup: log dir");

    std::env::set_var("IGRA_SECRETS_PASSPHRASE", "test-passphrase");

    let mut app_config = AppConfig::default();
    app_config.service.network = Some("mainnet".to_string());
    app_config.service.node_rpc_url = "grpc://127.0.0.1:16110".to_string();
    app_config.service.data_dir = data_dir;
    app_config.service.use_encrypted_secrets = true;
    app_config.service.secrets_file = Some(secrets_path.to_string_lossy().to_string());
    app_config.service.key_audit_log_path = Some(tmp.path().join("key-audit.log").to_string_lossy().to_string());
    app_config.service.pskt.source_addresses = vec!["kaspa:source".to_string()];
    app_config.service.hd = Some(PsktHdConfig {
        key_type: KeyType::RawPrivateKey,
        required_sigs: 2,
        derivation_path: Some("m/45'/111110'/0'/0/0".to_string()),
        ..Default::default()
    });
    app_config.group = Some(make_group_config());

    let ctx = ValidationContext {
        config_path: None,
        allow_remote_rpc: false,
        log_filters: Some("info".to_string()),
        log_dir: Some(log_dir),
    };

    (app_config, ctx)
}

#[test]
fn mainnet_rejects_hd_mnemonic_key_type() {
    let tmp = TempDir::new().expect("test setup: tempdir");
    let (mut app_config, ctx) = make_mainnet_ready_config(&tmp);
    app_config.service.hd = Some(PsktHdConfig { key_type: KeyType::HdMnemonic, required_sigs: 2, ..Default::default() });

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_static(&app_config, &ctx);

    assert!(report.has_errors());
    assert!(report.errors.iter().any(|e| e.message.contains("mainnet forbids service.hd.key_type=hd_mnemonic")));
}

#[test]
fn mainnet_rejects_legacy_env_secrets() {
    let tmp = TempDir::new().expect("test setup: tempdir");
    let (app_config, ctx) = make_mainnet_ready_config(&tmp);
    std::env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-test-secret-please-change");

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_static(&app_config, &ctx);

    assert!(report.has_errors());
    assert!(report.errors.iter().any(|e| e.message.contains("forbids legacy env secret")));

    std::env::remove_var("KASPA_IGRA_WALLET_SECRET");
}

#[test]
fn mainnet_rejects_remote_rpc_without_flag() {
    let tmp = TempDir::new().expect("test setup: tempdir");
    let (mut app_config, ctx) = make_mainnet_ready_config(&tmp);
    app_config.service.node_rpc_url = "grpcs://token@remote-node.example.com:16110".to_string();

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_static(&app_config, &ctx);

    assert!(report.has_errors());
    assert!(report.errors.iter().any(|e| e.message.contains("requires local RPC")));
}

#[test]
fn mainnet_allows_remote_rpc_with_flag_and_tls_and_auth() {
    let tmp = TempDir::new().expect("test setup: tempdir");
    let (mut app_config, mut ctx) = make_mainnet_ready_config(&tmp);
    app_config.service.node_rpc_url = "grpcs://token@remote-node.example.com:16110".to_string();
    ctx.allow_remote_rpc = true;

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_static(&app_config, &ctx);

    assert!(!report.errors.iter().any(|e| e.category == igra_core::infrastructure::network_mode::ErrorCategory::RpcEndpoint));
    assert!(report.warnings.iter().any(|w| w.category == igra_core::infrastructure::network_mode::ErrorCategory::RpcEndpoint));
}

#[test]
fn mainnet_remote_rpc_requires_auth() {
    let tmp = TempDir::new().expect("test setup: tempdir");
    let (mut app_config, mut ctx) = make_mainnet_ready_config(&tmp);
    app_config.service.node_rpc_url = "grpcs://remote-node.example.com:16110".to_string();
    ctx.allow_remote_rpc = true;

    let validator = SecurityValidator::new(NetworkMode::Mainnet);
    let report = validator.validate_static(&app_config, &ctx);

    assert!(report.has_errors());
    assert!(report.errors.iter().any(|e| e.message.contains("must include authentication")));
}

#[test]
fn devnet_allows_env_secrets() {
    std::env::set_var("KASPA_IGRA_WALLET_SECRET", "devnet-secret");
    let tmp = TempDir::new().expect("test setup: tempdir");
    let data_dir = tmp.path().to_string_lossy().to_string();

    let mut app_config = AppConfig::default();
    app_config.service.node_rpc_url = "grpc://127.0.0.1:16110".to_string();
    app_config.service.data_dir = data_dir;
    app_config.service.use_encrypted_secrets = false;
    app_config.service.pskt.source_addresses = vec!["kaspadev:source".to_string()];

    let ctx = ValidationContext::default();
    let validator = SecurityValidator::new(NetworkMode::Devnet);
    let report = validator.validate_static(&app_config, &ctx);

    assert!(!report.has_errors());

    std::env::remove_var("KASPA_IGRA_WALLET_SECRET");
}

#[tokio::test]
async fn startup_requires_secrets_even_in_devnet() {
    std::env::remove_var("KASPA_IGRA_WALLET_SECRET");
    let tmp = TempDir::new().expect("test setup: tempdir");
    let data_dir = tmp.path().to_string_lossy().to_string();

    let mut app_config = AppConfig::default();
    app_config.service.node_rpc_url = "grpc://127.0.0.1:16110".to_string();
    app_config.service.data_dir = data_dir;
    app_config.service.use_encrypted_secrets = false;
    app_config.service.hd = Some(PsktHdConfig { key_type: KeyType::HdMnemonic, ..Default::default() });

    struct EmptySecretStore;

    impl SecretStore for EmptySecretStore {
        fn backend(&self) -> &'static str {
            "empty"
        }

        fn get<'a>(
            &'a self,
            name: &'a SecretName,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<SecretBytes, ThresholdError>> + Send + 'a>> {
            Box::pin(async move { Err(ThresholdError::secret_not_found(name.as_str(), "empty")) })
        }

        fn list_secrets<'a>(
            &'a self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<SecretName>, ThresholdError>> + Send + 'a>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    let secret_store = Arc::new(EmptySecretStore);
    let audit_log = Arc::new(NoopAuditLogger);
    let key_manager = Arc::new(LocalKeyManager::new(secret_store, audit_log.clone()));
    let key_ctx = KeyManagerContext::with_new_request_id(key_manager, audit_log);

    let validator = SecurityValidator::new(NetworkMode::Devnet);
    let kaspa_query = KaspaGrpcQueryClient::unimplemented();
    let result = validator.validate_startup(&app_config, &kaspa_query, &key_ctx).await;
    assert!(result.is_err());
}
