use ed25519_dalek::VerifyingKey;
use igra_core::infrastructure::config::AppConfig;
use igra_core::foundation::ThresholdError;
use igra_core::domain::group_id::compute_group_id;
use igra_core::foundation::Hash32;
use igra_core::infrastructure::storage::rocks::RocksStorage;
use igra_core::infrastructure::transport::identity::{Ed25519Signer, StaticEd25519Verifier};
use igra_core::foundation::PeerId;
use rand::RngCore;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};

use iroh_base::{EndpointAddr, EndpointId, SecretKey as IrohSecretKey, TransportAddr};

pub fn init_logging(level: &str) -> Result<(), ThresholdError> {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
        .map_err(|err| ThresholdError::Message(err.to_string()))?;
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(true).with_thread_ids(true).try_init();
    igra_core::infrastructure::audit::init_audit_logger(Box::new(igra_core::infrastructure::audit::StructuredAuditLogger));
    Ok(())
}

pub fn load_app_config() -> Result<Arc<AppConfig>, ThresholdError> {
    let app_config = Arc::new(igra_core::infrastructure::config::load_app_config()?);
    if let Err(errors) = app_config.validate() {
        for err in errors {
            warn!("config validation error: {}", err);
        }
    }
    Ok(app_config)
}

pub fn load_app_config_profile(path: &std::path::Path, profile: &str) -> Result<Arc<AppConfig>, ThresholdError> {
    let app_config = Arc::new(igra_core::infrastructure::config::load_app_config_from_profile_path(path, profile)?);
    if let Err(errors) = app_config.validate() {
        for err in errors {
            warn!("config validation error: {}", err);
        }
    }
    Ok(app_config)
}

pub fn validate_startup_config(app_config: &AppConfig) -> bool {
    if app_config.service.pskt.source_addresses.is_empty()
        || (app_config.service.pskt.redeem_script_hex.is_empty() && app_config.service.hd.is_none())
    {
        warn!("missing source_addresses or redeem script/HD config");
        return false;
    }
    true
}

pub fn warn_test_mode(app_config: &AppConfig) {
    let runtime = &app_config.runtime;
    let recipient = runtime.test_recipient.clone().unwrap_or_default();
    let amount_sompi = runtime.test_amount_sompi.unwrap_or(0);
    if !runtime.test_mode && (recipient.is_empty() || amount_sompi == 0) {
        warn!("service expects signing events to supply recipient+amount; enable runtime.test_mode in the INI config to use test overrides");
    }
}

pub fn init_storage(data_dir: &str) -> Result<Arc<RocksStorage>, ThresholdError> {
    RocksStorage::open_in_dir(data_dir).map(Arc::new).map_err(|err| ThresholdError::Message(format!("rocksdb open error: {}", err)))
}

pub struct SignerIdentity {
    pub peer_id: PeerId,
    pub signer: Arc<Ed25519Signer>,
    pub verifier: Arc<StaticEd25519Verifier>,
}

pub fn init_signer_identity(app_config: &AppConfig) -> Result<SignerIdentity, ThresholdError> {
    let peer_id_env = app_config.iroh.peer_id.clone().unwrap_or_default();
    let seed_hex_env = app_config.iroh.signer_seed_hex.clone().unwrap_or_default();
    let (peer_id, seed_hex) = if !peer_id_env.is_empty() && !seed_hex_env.is_empty() {
        (PeerId::from(peer_id_env), seed_hex_env)
    } else {
        load_or_create_iroh_identity(&app_config.service.data_dir)?
    };

    let seed = parse_seed_hex(&seed_hex)?;
    let signer = Arc::new(Ed25519Signer::from_seed(peer_id.clone(), seed));

    let mut keys = parse_verifier_keys(&app_config.iroh.verifier_keys)?;
    keys.entry(peer_id.clone()).or_insert_with(|| signer.verifying_key());
    let verifier = Arc::new(StaticEd25519Verifier::new(keys));

    Ok(SignerIdentity { peer_id, signer, verifier })
}

pub fn resolve_group_id(app_config: &AppConfig) -> Result<Hash32, ThresholdError> {
    let group_id_hex = app_config.iroh.group_id.clone().unwrap_or_default();
    if group_id_hex.is_empty() {
        return Err(ThresholdError::ConfigError("missing group_id".to_string()));
    }
    let group_id = parse_hash32_hex(&group_id_hex)?;
    if let Some(group_config) = app_config.group.as_ref() {
        let computed = compute_group_id(group_config)?;
        if computed != group_id {
            return Err(ThresholdError::ConfigError(format!(
                "group_id mismatch: computed={} configured={}",
                hex::encode(computed),
                group_id_hex
            )));
        }
    }
    Ok(group_id)
}

pub async fn init_iroh_gossip(
    bind_port: Option<u16>,
    static_addrs: Vec<EndpointAddr>,
    secret_key: IrohSecretKey,
) -> Result<(iroh_gossip::net::Gossip, iroh::protocol::Router), ThresholdError> {
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

fn parse_seed_hex(value: &str) -> Result<[u8; 32], ThresholdError> {
    let bytes = hex::decode(value.trim())?;
    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| ThresholdError::Message("expected 32-byte hex seed".to_string()))?;
    Ok(array)
}

pub fn derive_iroh_secret(seed_hex: &str) -> Result<IrohSecretKey, ThresholdError> {
    let seed = parse_seed_hex(seed_hex)?;
    Ok(IrohSecretKey::from(seed))
}

fn parse_hash32_hex(value: &str) -> Result<Hash32, ThresholdError> {
    let bytes = hex::decode(value.trim())?;
    let array: [u8; 32] =
        bytes.as_slice().try_into().map_err(|_| ThresholdError::Message("expected 32-byte hex value".to_string()))?;
    Ok(array)
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
        let bytes = hex::decode(key_hex)?;
        let array: [u8; 32] =
            bytes.as_slice().try_into().map_err(|_| ThresholdError::Message("expected 32-byte ed25519 public key".to_string()))?;
        let key = VerifyingKey::from_bytes(&array).map_err(|err| ThresholdError::Message(err.to_string()))?;
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
