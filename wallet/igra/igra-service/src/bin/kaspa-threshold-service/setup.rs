use ed25519_dalek::VerifyingKey;
use igra_core::domain::group_id::verify_group_id;
use igra_core::foundation::{parse_hex_32bytes, parse_required, GroupId, PeerId, ThresholdError};
use igra_core::infrastructure::config::AppConfig;
use igra_core::infrastructure::keys::{
    EnvSecretStore, FileAuditLogger, FileSecretStore, KeyAuditLogger, KeyManager, KeyManagerContext, LocalKeyManager, SecretName,
    SecretStore,
};
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
use log::{info, warn};
use rand::RngCore;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use iroh_base::{EndpointAddr, EndpointId, SecretKey as IrohSecretKey, TransportAddr};

pub fn init_logging(level: &str) -> Result<(), ThresholdError> {
    let log_dir = std::env::var("KASPA_IGRA_LOG_DIR").ok().filter(|s| !s.trim().is_empty());
    igra_core::infrastructure::logging::init_logger(log_dir.as_deref(), level);
    igra_core::infrastructure::audit::init_audit_logger(Box::new(igra_core::infrastructure::audit::StructuredAuditLogger));
    info!("logging initialized level={}", level);
    Ok(())
}

pub fn load_app_config() -> Result<Arc<AppConfig>, ThresholdError> {
    info!("loading application config");
    let app_config = Arc::new(igra_core::infrastructure::config::load_app_config()?);
    if let Err(errors) = app_config.validate() {
        for err in errors {
            warn!("config validation error: {}", err);
        }
    }
    Ok(app_config)
}

pub fn load_app_config_profile(path: &std::path::Path, profile: &str) -> Result<Arc<AppConfig>, ThresholdError> {
    info!("loading application config profile path={} profile={}", path.display(), profile);
    let app_config = Arc::new(igra_core::infrastructure::config::load_app_config_from_profile_path(path, profile)?);
    if let Err(errors) = app_config.validate() {
        for err in errors {
            warn!("config validation error: {}", err);
        }
    }
    Ok(app_config)
}

pub fn validate_startup_config(app_config: &AppConfig) -> bool {
    let missing_source_addresses = app_config.service.pskt.source_addresses.is_empty();
    let missing_redeem_script = app_config.service.pskt.redeem_script_hex.trim().is_empty();
    let missing_hd = app_config.service.hd.is_none();
    if missing_source_addresses || (missing_redeem_script && missing_hd) {
        warn!(
            "startup config missing required PSKT fields missing_source_addresses={} missing_redeem_script={} missing_hd={}",
            missing_source_addresses, missing_redeem_script, missing_hd
        );
        return false;
    }
    true
}

pub fn warn_test_mode(app_config: &AppConfig) {
    let runtime = &app_config.runtime;
    let recipient = runtime.test_recipient.clone().unwrap_or_default();
    let amount_sompi = runtime.test_amount_sompi.unwrap_or(0);
    if !runtime.test_mode && (recipient.is_empty() || amount_sompi == 0) {
        warn!("service expects signing events to supply recipient+amount; enable runtime.test_mode in the TOML config to use test overrides");
    }
}

pub fn init_storage(data_dir: &str, allow_schema_wipe: bool) -> Result<Arc<RocksStorage>, ThresholdError> {
    info!("initializing storage data_dir={} allow_schema_wipe={}", data_dir, allow_schema_wipe);
    RocksStorage::open_in_dir_with_options(data_dir, allow_schema_wipe)
        .map(Arc::new)
        .map_err(|err| ThresholdError::Message(format!("rocksdb open error: {}", err)))
}

pub async fn setup_key_manager(
    service_config: &igra_core::infrastructure::config::ServiceConfig,
) -> Result<(Arc<dyn KeyManager>, Arc<dyn KeyAuditLogger>), ThresholdError> {
    let secret_store: Arc<dyn SecretStore> = if service_config.use_encrypted_secrets {
        let secrets_path = match service_config.secrets_file.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(&service_config.data_dir).join("secrets.bin"),
        };
        if !secrets_path.exists() {
            return Err(ThresholdError::secret_store_unavailable(
                "file",
                format!("secrets file not found: {} (set service.secrets_file or create the file first)", secrets_path.display()),
            ));
        }
        let passphrase = prompt_secrets_passphrase()?;
        Arc::new(FileSecretStore::open(&secrets_path, &passphrase).await?)
    } else {
        warn!("using environment-based secrets (devnet/CI only)");
        Arc::new(EnvSecretStore::new())
    };

    let audit_path = match service_config.key_audit_log_path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(&service_config.data_dir).join("key-audit.log"),
    };
    let audit_log: Arc<dyn KeyAuditLogger> = Arc::new(FileAuditLogger::new(&audit_path)?);

    let key_manager: Arc<dyn KeyManager> = Arc::new(LocalKeyManager::new(secret_store, audit_log.clone()));
    Ok((key_manager, audit_log))
}

fn prompt_secrets_passphrase() -> Result<String, ThresholdError> {
    use std::io::{self, Write};

    if let Ok(pass) = std::env::var("IGRA_SECRETS_PASSPHRASE") {
        let trimmed = pass.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    print!("Enter secrets file passphrase: ");
    io::stdout().flush().map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to flush stdout: {}", e)))?;

    let mut passphrase = String::new();
    io::stdin()
        .read_line(&mut passphrase)
        .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("Failed to read passphrase: {}", e)))?;

    Ok(passphrase.trim().to_string())
}

pub struct SignerIdentity {
    pub peer_id: PeerId,
    pub signer: Arc<Ed25519Signer>,
    pub verifier: Arc<StaticEd25519Verifier>,
    pub seed: [u8; 32],
}

pub async fn init_signer_identity(
    app_config: &AppConfig,
    key_manager: &Arc<dyn KeyManager>,
    audit_log: &Arc<dyn KeyAuditLogger>,
) -> Result<SignerIdentity, ThresholdError> {
    let key_ctx = KeyManagerContext::with_new_request_id(key_manager.clone(), audit_log.clone());

    let peer_id_config = app_config.iroh.peer_id.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let seed_config = app_config.iroh.signer_seed_hex.as_deref().map(parse_hex_32bytes).transpose()?;

    let profile_suffix = std::env::var("KASPA_IGRA_PROFILE")
        .ok()
        .map(|s| s.trim().replace('-', "_"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    let secret_name = SecretName::new(format!("igra.iroh.signer_seed_{}", profile_suffix));
    let seed_from_store: Option<[u8; 32]> =
        match key_ctx.get_secret_with_audit(&secret_name).await {
            Ok(bytes) => Some(bytes.expose_secret().try_into().map_err(|_| {
                ThresholdError::key_operation_failed("parse_iroh_seed", secret_name.to_string(), "seed must be 32 bytes")
            })?),
            Err(ThresholdError::SecretNotFound { .. }) => None,
            Err(err) => return Err(err),
        };

    let (peer_id, seed) = if let Some(seed) = seed_from_store {
        if let Some(peer_id) = peer_id_config {
            info!("using iroh identity from secret store + config peer_id={} secret_name={}", peer_id, secret_name);
            (PeerId::from(peer_id), seed)
        } else {
            let digest = blake3::hash(&seed);
            let prefix = &digest.as_bytes()[..8];
            let peer_id = PeerId::from(format!("peer-{}", hex::encode(prefix)));
            info!("using iroh identity derived from secret store peer_id={} secret_name={}", peer_id, secret_name);
            (peer_id, seed)
        }
    } else if let Some(seed) = seed_config {
        if let Some(peer_id) = peer_id_config {
            info!("using iroh identity from config peer_id={}", peer_id);
            (PeerId::from(peer_id), seed)
        } else {
            let digest = blake3::hash(&seed);
            let prefix = &digest.as_bytes()[..8];
            let peer_id = PeerId::from(format!("peer-{}", hex::encode(prefix)));
            info!("using iroh identity derived from config seed peer_id={}", peer_id);
            (peer_id, seed)
        }
    } else {
        info!("loading or creating iroh identity");
        let (peer_id, seed_hex) = load_or_create_iroh_identity(&app_config.service.data_dir)?;
        let seed = parse_hex_32bytes(&seed_hex)?;
        (peer_id, seed)
    };
    let signer = Arc::new(Ed25519Signer::from_seed(peer_id.clone(), seed));

    let mut keys = parse_verifier_keys(&app_config.iroh.verifier_keys)?;
    keys.entry(peer_id.clone()).or_insert_with(|| signer.verifying_key());
    let verifier = Arc::new(StaticEd25519Verifier::new(keys));

    Ok(SignerIdentity { peer_id, signer, verifier, seed })
}

pub fn resolve_group_id(app_config: &AppConfig) -> Result<GroupId, ThresholdError> {
    let group_id: GroupId = parse_required(&app_config.iroh.group_id, "iroh.group_id")?;
    if let Some(group_config) = app_config.group.as_ref() {
        let verification = verify_group_id(group_config, &group_id)?;
        if !verification.matches {
            let computed = GroupId::from(verification.computed);
            return Err(ThresholdError::ConfigError(format!(
                "group_id mismatch: computed={:#x} configured={:#x}",
                computed, group_id
            )));
        }
        info!("group_id validated against group config group_id={:#x}", group_id);
    } else {
        info!("group_id loaded group_id={:#x}", group_id);
    }
    Ok(group_id)
}

pub fn log_startup_banner(app_config: &AppConfig, peer_id: &PeerId, group_id: &GroupId) {
    let (threshold_m, threshold_n, finality_blue_score) = match app_config.group.as_ref() {
        Some(group) => (group.threshold_m, group.threshold_n, group.finality_blue_score_threshold),
        None => (0, 0, 0),
    };
    let rpc_enabled = app_config.rpc.enabled;
    let rpc_addr = app_config.rpc.addr.as_str();

    info!("╔════════════════════════════════════════════════════════════╗");
    info!("║              IGRA Threshold Signing Service                ║");
    info!("╠════════════════════════════════════════════════════════════╣");
    info!("║ Peer ID:    {:<45} ║", peer_id.to_string());
    info!("║ Group ID:   {:<45} ║", format!("{group_id:#x}"));
    info!("║ Threshold:  {:<45} ║", format!("{}/{} signers", threshold_m, threshold_n));
    info!("║ Network ID: {:<45} ║", app_config.iroh.network_id);
    info!("║ RPC:        {:<45} ║", if rpc_enabled { rpc_addr } else { "disabled" });
    info!("║ Finality:   {:<45} ║", format!("blue_score +{}", finality_blue_score));
    info!("╚════════════════════════════════════════════════════════════╝");
}

pub async fn init_iroh_gossip(
    bind_port: Option<u16>,
    static_addrs: Vec<EndpointAddr>,
    secret_key: IrohSecretKey,
) -> Result<(iroh_gossip::net::Gossip, iroh::protocol::Router), ThresholdError> {
    info!("initializing iroh gossip bind_port={:?} static_addr_count={}", bind_port, static_addrs.len());
    let mut builder = iroh::Endpoint::empty_builder(iroh::endpoint::RelayMode::Disabled).secret_key(secret_key);
    let static_provider = iroh::discovery::static_provider::StaticProvider::new();
    if !static_addrs.is_empty() {
        for addr in &static_addrs {
            static_provider.add_endpoint_info(addr.clone());
        }
        builder = builder.discovery(static_provider);
    }
    if let Some(port) = bind_port {
        builder = builder.bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
    }
    let endpoint = builder.bind().await.map_err(|err| ThresholdError::Message(err.to_string()))?;
    let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
    let router = iroh::protocol::Router::builder(endpoint).accept(iroh_gossip::net::GOSSIP_ALPN, gossip.clone()).spawn();
    info!("iroh gossip initialized");
    Ok((gossip, router))
}

pub fn parse_bootstrap_addrs(addrs: &[String]) -> Result<Vec<EndpointAddr>, ThresholdError> {
    let mut out = Vec::new();
    for entry in addrs.iter().filter(|s| !s.trim().is_empty()) {
        let mut parts = entry.splitn(2, '@');
        let id_str = parts.next().unwrap_or_default().trim();
        let addr_str = parts.next().unwrap_or_default().trim();
        if id_str.is_empty() || addr_str.is_empty() {
            return Err(ThresholdError::ConfigError("iroh.bootstrap_addrs entries must be EndpointId@host:port".to_string()));
        }
        let id = EndpointId::from_str(id_str).map_err(|err| ThresholdError::Message(format!("invalid EndpointId {id_str}: {err}")))?;
        let sock: SocketAddr =
            addr_str.parse().map_err(|err| ThresholdError::Message(format!("invalid socket address {addr_str}: {err}")))?;
        out.push(EndpointAddr::from_parts(id, [TransportAddr::Ip(sock)]));
    }
    Ok(out)
}

pub fn derive_iroh_secret(seed: [u8; 32]) -> IrohSecretKey {
    IrohSecretKey::from(seed)
}

fn parse_verifier_keys(values: &[String]) -> Result<HashMap<PeerId, VerifyingKey>, ThresholdError> {
    let mut keys = HashMap::new();
    for entry in values.iter().filter(|s| !s.trim().is_empty()) {
        let mut parts = entry.splitn(2, ':');
        let peer_id = parts.next().unwrap_or_default().trim();
        let key_hex = parts.next().unwrap_or_default().trim();
        if peer_id.is_empty() || key_hex.is_empty() {
            return Err(ThresholdError::Message("expected verifier entry as peer_id:hex_pubkey".to_string()));
        }
        let array =
            parse_hex_32bytes(key_hex).map_err(|err| ThresholdError::ConfigError(format!("invalid verifier key hex: {}", err)))?;
        let key = VerifyingKey::from_bytes(&array).map_err(|err| ThresholdError::ConfigError(err.to_string()))?;
        keys.insert(PeerId::from(peer_id), key);
    }
    Ok(keys)
}

fn load_or_create_iroh_identity(data_dir: &str) -> Result<(PeerId, String), ThresholdError> {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct IdentityRecord {
        peer_id: String,
        seed_hex: String,
    }

    let base_dir = if data_dir.trim().is_empty() {
        let cwd = std::env::current_dir().map_err(|err| ThresholdError::Message(err.to_string()))?;
        cwd.join(".igra")
    } else {
        PathBuf::from(data_dir)
    };
    let identity_dir = base_dir.join("iroh");
    let identity_path = identity_dir.join("identity.json");
    if identity_path.exists() {
        let bytes = std::fs::read(&identity_path).map_err(|err| ThresholdError::Message(err.to_string()))?;
        let record: IdentityRecord = serde_json::from_slice(&bytes)?;
        if record.peer_id.trim().is_empty() || record.seed_hex.trim().is_empty() {
            return Err(ThresholdError::Message("identity.json is missing peer_id or seed_hex".to_string()));
        }
        return Ok((PeerId::from(record.peer_id), record.seed_hex));
    }

    std::fs::create_dir_all(&identity_dir).map_err(|err| ThresholdError::Message(err.to_string()))?;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut peer_id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut peer_id_bytes);
    let record = IdentityRecord { peer_id: format!("peer-{}", hex::encode(peer_id_bytes)), seed_hex: hex::encode(seed) };
    let json = serde_json::to_vec_pretty(&record)?;
    std::fs::write(&identity_path, json).map_err(|err| ThresholdError::Message(err.to_string()))?;
    info!("created iroh identity at {}", identity_path.display());
    Ok((PeerId::from(record.peer_id), record.seed_hex))
}
